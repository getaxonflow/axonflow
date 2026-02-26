//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cloudstorage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
)

// azureBlobClient is the subset of the Azure blob client API we use, enabling mock injection.
type azureBlobClient interface {
	UploadBuffer(ctx context.Context, containerName string, blobName string, buffer []byte, o *azblob.UploadBufferOptions) (azblob.UploadBufferResponse, error)
	DownloadBlob(ctx context.Context, containerName string, blobName string) (io.ReadCloser, error)
	DeleteBlob(ctx context.Context, containerName string, blobName string, o *azblob.DeleteBlobOptions) (azblob.DeleteBlobResponse, error)
	NewListBlobsFlatPager(containerName string, o *azblob.ListBlobsFlatOptions) azureListPager
}

// azureListPager abstracts the Azure pager for listing blobs.
type azureListPager interface {
	More() bool
	NextPage(ctx context.Context) (azblob.ListBlobsFlatResponse, error)
}

// azureSASGenerator generates SAS URLs for Azure blobs.
type azureSASGenerator interface {
	GenerateSASURL(containerName, blobName string, expiry time.Time) (string, error)
}

// AzureBackend implements StorageBackend for Azure Blob Storage.
type AzureBackend struct {
	client    azureBlobClient
	sasGen    azureSASGenerator
	cfg       AzureConfig
	rawClient *azblob.Client // for health checks and SAS
}

// NewAzureBackend creates a new Azure Blob storage backend.
func NewAzureBackend(cfg AzureConfig) (*AzureBackend, error) {
	if cfg.ContainerName == "" {
		return nil, fmt.Errorf("azure: container name is required")
	}

	var client *azblob.Client
	var err error

	if cfg.ConnectionString != "" {
		client, err = azblob.NewClientFromConnectionString(cfg.ConnectionString, nil)
		// Extract account name and key from connection string for SAS generation
		if cfg.AccountName == "" || cfg.AccountKey == "" {
			parsedName, parsedKey := parseConnectionString(cfg.ConnectionString)
			if cfg.AccountName == "" {
				cfg.AccountName = parsedName
			}
			if cfg.AccountKey == "" {
				cfg.AccountKey = parsedKey
			}
		}
	} else if cfg.AccountName != "" && cfg.AccountKey != "" {
		cred, credErr := azblob.NewSharedKeyCredential(cfg.AccountName, cfg.AccountKey)
		if credErr != nil {
			return nil, fmt.Errorf("azure: create shared key credential: %w", credErr)
		}
		serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", cfg.AccountName)
		client, err = azblob.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
	} else {
		return nil, fmt.Errorf("azure: either connection_string or account_name+account_key is required")
	}

	if err != nil {
		return nil, fmt.Errorf("azure: create client: %w", err)
	}

	backend := &AzureBackend{
		rawClient: client,
		cfg:       cfg,
	}
	backend.client = &azureClientAdapter{client: client}
	backend.sasGen = &azureSASAdapter{client: client, cfg: cfg}

	return backend, nil
}

// newAzureBackendWithClient creates an AzureBackend with injected clients (for testing).
func newAzureBackendWithClient(client azureBlobClient, sasGen azureSASGenerator, cfg AzureConfig) *AzureBackend {
	return &AzureBackend{client: client, sasGen: sasGen, cfg: cfg}
}

// Upload stores a blob in Azure Blob Storage.
func (b *AzureBackend) Upload(ctx context.Context, req *UploadRequest) (*UploadResult, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, req.Body)
	if err != nil {
		return nil, fmt.Errorf("azure upload: read body: %w", err)
	}

	opts := &azblob.UploadBufferOptions{}
	if req.ContentType != "" {
		opts.HTTPHeaders = &blob.HTTPHeaders{
			BlobContentType: &req.ContentType,
		}
	}
	if len(req.Metadata) > 0 {
		m := make(map[string]*string, len(req.Metadata))
		for k, v := range req.Metadata {
			v := v
			m[k] = &v
		}
		opts.Metadata = m
	}

	_, err = b.client.UploadBuffer(ctx, b.cfg.ContainerName, req.Key, buf.Bytes(), opts)
	if err != nil {
		return nil, fmt.Errorf("azure upload: %w", err)
	}

	return &UploadResult{
		Key:       req.Key,
		SizeBytes: n,
	}, nil
}

// Download retrieves a blob from Azure Blob Storage.
func (b *AzureBackend) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	reader, err := b.client.DownloadBlob(ctx, b.cfg.ContainerName, key)
	if err != nil {
		return nil, fmt.Errorf("azure download: %w", err)
	}
	return reader, nil
}

// GeneratePresignedURL creates a SAS URL for the blob.
func (b *AzureBackend) GeneratePresignedURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	expiryTime := time.Now().UTC().Add(expiry)
	url, err := b.sasGen.GenerateSASURL(b.cfg.ContainerName, key, expiryTime)
	if err != nil {
		return "", fmt.Errorf("azure presign: %w", err)
	}
	return url, nil
}

// Delete removes a blob from Azure Blob Storage.
func (b *AzureBackend) Delete(ctx context.Context, key string) error {
	_, err := b.client.DeleteBlob(ctx, b.cfg.ContainerName, key, nil)
	if err != nil {
		return fmt.Errorf("azure delete: %w", err)
	}
	return nil
}

// List returns blobs with the given prefix.
func (b *AzureBackend) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	pager := b.client.NewListBlobsFlatPager(b.cfg.ContainerName, &azblob.ListBlobsFlatOptions{
		Prefix: &prefix,
	})

	var objects []ObjectInfo
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure list: %w", err)
		}
		for _, item := range page.Segment.BlobItems {
			info := ObjectInfo{}
			if item.Name != nil {
				info.Key = *item.Name
			}
			if item.Properties != nil {
				if item.Properties.ContentLength != nil {
					info.SizeBytes = *item.Properties.ContentLength
				}
				if item.Properties.LastModified != nil {
					info.LastModified = *item.Properties.LastModified
				}
				if item.Properties.ETag != nil {
					info.ETag = string(*item.Properties.ETag)
				}
			}
			objects = append(objects, info)
		}
	}
	return objects, nil
}

// Type returns the storage backend type.
func (b *AzureBackend) Type() string { return string(StorageTypeAzure) }

// HealthCheck verifies the container is accessible.
func (b *AzureBackend) HealthCheck(ctx context.Context) error {
	// List with max results 1 to verify access
	pager := b.client.NewListBlobsFlatPager(b.cfg.ContainerName, &azblob.ListBlobsFlatOptions{
		MaxResults: ptrInt32(1),
	})
	if pager.More() {
		_, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("azure health check: %w", err)
		}
	}
	return nil
}

func ptrInt32(v int32) *int32 { return &v }

// azureClientAdapter wraps the real azblob.Client to satisfy our interface.
type azureClientAdapter struct {
	client *azblob.Client
}

func (a *azureClientAdapter) UploadBuffer(ctx context.Context, containerName, blobName string, buffer []byte, o *azblob.UploadBufferOptions) (azblob.UploadBufferResponse, error) {
	return a.client.UploadBuffer(ctx, containerName, blobName, buffer, o)
}

func (a *azureClientAdapter) DownloadBlob(ctx context.Context, containerName, blobName string) (io.ReadCloser, error) {
	resp, err := a.client.DownloadStream(ctx, containerName, blobName, nil)
	if err != nil {
		return nil, err
	}
	return resp.NewRetryReader(ctx, nil), nil
}

func (a *azureClientAdapter) DeleteBlob(ctx context.Context, containerName, blobName string, o *azblob.DeleteBlobOptions) (azblob.DeleteBlobResponse, error) {
	return a.client.DeleteBlob(ctx, containerName, blobName, o)
}

func (a *azureClientAdapter) NewListBlobsFlatPager(containerName string, o *azblob.ListBlobsFlatOptions) azureListPager {
	return a.client.NewListBlobsFlatPager(containerName, o)
}

// azureSASAdapter generates SAS URLs using the shared-key credential.
type azureSASAdapter struct {
	client *azblob.Client
	cfg    AzureConfig
}

// parseConnectionString extracts AccountName and AccountKey from an Azure connection string.
// Connection string format: "AccountName=...;AccountKey=...;EndpointSuffix=..."
// Uses strings.SplitN to robustly handle '=' characters within values (e.g. base64 account keys).
func parseConnectionString(connStr string) (accountName, accountKey string) {
	for _, part := range strings.Split(connStr, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "AccountName":
			accountName = kv[1]
		case "AccountKey":
			accountKey = kv[1]
		}
	}
	return
}

func (a *azureSASAdapter) GenerateSASURL(containerName, blobName string, expiry time.Time) (string, error) {
	if a.cfg.AccountName == "" || a.cfg.AccountKey == "" {
		return "", fmt.Errorf("SAS generation requires account name and key")
	}
	cred, err := azblob.NewSharedKeyCredential(a.cfg.AccountName, a.cfg.AccountKey)
	if err != nil {
		return "", fmt.Errorf("create sas credential: %w", err)
	}

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", a.cfg.AccountName)
	sasURL, err := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		ExpiryTime:    expiry,
		Permissions:   (&sas.BlobPermissions{Read: true}).String(),
		ContainerName: containerName,
		BlobName:      blobName,
	}.SignWithSharedKey(cred)
	if err != nil {
		return "", fmt.Errorf("sign sas: %w", err)
	}

	return serviceURL + containerName + "/" + blobName + "?" + sasURL.Encode(), nil
}
