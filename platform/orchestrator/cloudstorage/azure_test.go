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
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

// mockAzureClient implements azureBlobClient for testing.
type mockAzureClient struct {
	objects     map[string][]byte
	uploadErr   error
	downloadErr error
	deleteErr   error
	listErr     error
}

func newMockAzureClient() *mockAzureClient {
	return &mockAzureClient{objects: make(map[string][]byte)}
}

func (m *mockAzureClient) UploadBuffer(ctx context.Context, containerName, blobName string, buffer []byte, o *azblob.UploadBufferOptions) (azblob.UploadBufferResponse, error) {
	if m.uploadErr != nil {
		return azblob.UploadBufferResponse{}, m.uploadErr
	}
	m.objects[blobName] = make([]byte, len(buffer))
	copy(m.objects[blobName], buffer)
	return azblob.UploadBufferResponse{}, nil
}

func (m *mockAzureClient) DownloadBlob(ctx context.Context, containerName, blobName string) (io.ReadCloser, error) {
	if m.downloadErr != nil {
		return nil, m.downloadErr
	}
	data, ok := m.objects[blobName]
	if !ok {
		return nil, fmt.Errorf("blob not found: %s", blobName)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *mockAzureClient) DeleteBlob(ctx context.Context, containerName, blobName string, o *azblob.DeleteBlobOptions) (azblob.DeleteBlobResponse, error) {
	if m.deleteErr != nil {
		return azblob.DeleteBlobResponse{}, m.deleteErr
	}
	delete(m.objects, blobName)
	return azblob.DeleteBlobResponse{}, nil
}

func (m *mockAzureClient) NewListBlobsFlatPager(containerName string, o *azblob.ListBlobsFlatOptions) azureListPager {
	prefix := ""
	if o != nil && o.Prefix != nil {
		prefix = *o.Prefix
	}

	var items []*container.BlobItem
	for key, data := range m.objects {
		if strings.HasPrefix(key, prefix) {
			name := key
			size := int64(len(data))
			now := time.Now()
			etag := azcore.ETag("etag123")
			items = append(items, &container.BlobItem{
				Name: &name,
				Properties: &container.BlobProperties{
					ContentLength: &size,
					LastModified:  &now,
					ETag:          &etag,
				},
			})
		}
	}
	return &mockAzureListPager{items: items, hasMore: len(items) > 0}
}

// mockAzureListPager implements azureListPager for testing.
type mockAzureListPager struct {
	items   []*container.BlobItem
	hasMore bool
}

func (p *mockAzureListPager) More() bool {
	return p.hasMore
}

func (p *mockAzureListPager) NextPage(ctx context.Context) (azblob.ListBlobsFlatResponse, error) {
	p.hasMore = false
	return azblob.ListBlobsFlatResponse{
		ListBlobsFlatSegmentResponse: container.ListBlobsFlatSegmentResponse{
			Segment: &container.BlobFlatListSegment{
				BlobItems: p.items,
			},
		},
	}, nil
}

// mockAzureSASGen implements azureSASGenerator for testing.
type mockAzureSASGen struct {
	url string
	err error
}

func (m *mockAzureSASGen) GenerateSASURL(containerName, blobName string, expiry time.Time) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if m.url != "" {
		return m.url, nil
	}
	return fmt.Sprintf("https://account.blob.core.windows.net/%s/%s?sig=abc", containerName, blobName), nil
}

func TestAzureBackend_Upload(t *testing.T) {
	mock := newMockAzureClient()
	backend := newAzureBackendWithClient(mock, &mockAzureSASGen{}, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	result, err := backend.Upload(ctx, &UploadRequest{
		Key:         "org1/export.json",
		Body:        strings.NewReader(`{"data": true}`),
		ContentType: "application/json",
		Metadata:    map[string]string{"org_id": "org1"},
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if result.Key != "org1/export.json" {
		t.Errorf("key = %q", result.Key)
	}
	if _, ok := mock.objects["org1/export.json"]; !ok {
		t.Error("blob not stored")
	}
}

func TestAzureBackend_UploadError(t *testing.T) {
	mock := newMockAzureClient()
	mock.uploadErr = fmt.Errorf("access denied")
	backend := newAzureBackendWithClient(mock, &mockAzureSASGen{}, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	_, err := backend.Upload(ctx, &UploadRequest{
		Key:  "test.json",
		Body: strings.NewReader("data"),
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureBackend_Download(t *testing.T) {
	mock := newMockAzureClient()
	mock.objects["test.json"] = []byte("hello")
	backend := newAzureBackendWithClient(mock, &mockAzureSASGen{}, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	reader, err := backend.Download(ctx, "test.json")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer reader.Close()
	data, _ := io.ReadAll(reader)
	if string(data) != "hello" {
		t.Errorf("data = %q", data)
	}
}

func TestAzureBackend_DownloadNotFound(t *testing.T) {
	mock := newMockAzureClient()
	backend := newAzureBackendWithClient(mock, &mockAzureSASGen{}, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	_, err := backend.Download(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureBackend_GeneratePresignedURL(t *testing.T) {
	sasGen := &mockAzureSASGen{}
	backend := newAzureBackendWithClient(newMockAzureClient(), sasGen, AzureConfig{ContainerName: "audit"})
	ctx := context.Background()

	url, err := backend.GeneratePresignedURL(ctx, "export.json", time.Hour)
	if err != nil {
		t.Fatalf("Presign: %v", err)
	}
	if !strings.Contains(url, "sig=abc") {
		t.Errorf("url = %q", url)
	}
}

func TestAzureBackend_PresignError(t *testing.T) {
	sasGen := &mockAzureSASGen{err: fmt.Errorf("sas failed")}
	backend := newAzureBackendWithClient(newMockAzureClient(), sasGen, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	_, err := backend.GeneratePresignedURL(ctx, "key", time.Hour)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureBackend_Delete(t *testing.T) {
	mock := newMockAzureClient()
	mock.objects["test.json"] = []byte("data")
	backend := newAzureBackendWithClient(mock, &mockAzureSASGen{}, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	if err := backend.Delete(ctx, "test.json"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := mock.objects["test.json"]; ok {
		t.Error("blob still exists")
	}
}

func TestAzureBackend_DeleteError(t *testing.T) {
	mock := newMockAzureClient()
	mock.deleteErr = fmt.Errorf("delete failed")
	backend := newAzureBackendWithClient(mock, &mockAzureSASGen{}, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	err := backend.Delete(ctx, "test.json")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAzureBackend_List(t *testing.T) {
	mock := newMockAzureClient()
	mock.objects["org1/a.json"] = []byte("a")
	mock.objects["org1/b.json"] = []byte("bb")
	mock.objects["org2/c.json"] = []byte("ccc")
	backend := newAzureBackendWithClient(mock, &mockAzureSASGen{}, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	objects, err := backend.List(ctx, "org1/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(objects) != 2 {
		t.Errorf("List returned %d, want 2", len(objects))
	}
}

func TestAzureBackend_HealthCheck(t *testing.T) {
	mock := newMockAzureClient()
	backend := newAzureBackendWithClient(mock, &mockAzureSASGen{}, AzureConfig{ContainerName: "test"})
	ctx := context.Background()

	if err := backend.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
}
