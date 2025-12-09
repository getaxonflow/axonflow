// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package azureblob provides an Azure Blob Storage connector for the AxonFlow platform.
// It implements the base.Connector interface for Azure Blob and container operations
// including listing, reading, writing, and SAS URL generation.
// This connector supports Azure Blob Storage, Azure Data Lake Storage Gen2,
// and various authentication methods including Account Key, Connection String,
// and Managed Identity.
package azureblob

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/sdk"
)

// AzureBlobConnector implements the MCP Connector interface for Azure Blob Storage
type AzureBlobConnector struct {
	sdk.BaseConnector
	client           *azblob.Client
	serviceClient    *service.Client
	accountName      string
	defaultContainer string
}

// NewAzureBlobConnector creates a new Azure Blob connector instance
func NewAzureBlobConnector() *AzureBlobConnector {
	conn := &AzureBlobConnector{}
	conn.BaseConnector = *sdk.NewBaseConnector("azureblob")
	conn.SetVersion("1.0.0")
	conn.SetCapabilities([]string{
		"query",      // List blobs
		"execute",    // Upload/Delete blobs
		"presign",    // Generate SAS URLs
		"streaming",  // Streaming support
	})

	// Set up configuration validator
	conn.SetValidator(sdk.NewDefaultConfigValidator(
		[]string{"account_name"}, // Account name is required
		map[string]interface{}{
			"sas_expiry":  3600, // 1 hour in seconds
		},
	))

	return conn
}

// Connect establishes connection to Azure Blob Storage
func (c *AzureBlobConnector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error {
	// Call base connect for validation and hooks
	if err := c.BaseConnector.Connect(ctx, cfg); err != nil {
		return err
	}

	// Get configuration options
	c.accountName = c.GetStringOption("account_name", "")
	c.defaultContainer = c.GetStringOption("default_container", "")

	// Get credentials
	accountKey := c.GetCredential("account_key")
	connectionString := c.GetCredential("connection_string")
	useManagedIdentity := c.GetBoolOption("use_managed_identity", false)

	var err error

	// Build Azure client based on authentication method
	if connectionString != "" {
		// Use connection string
		c.client, err = azblob.NewClientFromConnectionString(connectionString, nil)
		if err != nil {
			return base.NewConnectorError(cfg.Name, "Connect", "failed to create client from connection string", err)
		}
		c.serviceClient, err = service.NewClientFromConnectionString(connectionString, nil)
		if err != nil {
			return base.NewConnectorError(cfg.Name, "Connect", "failed to create service client from connection string", err)
		}
	} else if accountKey != "" {
		// Use shared key authentication
		serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", c.accountName)
		cred, err := azblob.NewSharedKeyCredential(c.accountName, accountKey)
		if err != nil {
			return base.NewConnectorError(cfg.Name, "Connect", "failed to create shared key credential", err)
		}
		c.client, err = azblob.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
		if err != nil {
			return base.NewConnectorError(cfg.Name, "Connect", "failed to create client", err)
		}
		c.serviceClient, err = service.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
		if err != nil {
			return base.NewConnectorError(cfg.Name, "Connect", "failed to create service client", err)
		}
	} else if useManagedIdentity {
		// Use Azure AD authentication (Managed Identity or DefaultAzureCredential)
		serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", c.accountName)
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return base.NewConnectorError(cfg.Name, "Connect", "failed to create Azure credential", err)
		}
		c.client, err = azblob.NewClient(serviceURL, cred, nil)
		if err != nil {
			return base.NewConnectorError(cfg.Name, "Connect", "failed to create client", err)
		}
		c.serviceClient, err = service.NewClient(serviceURL, cred, nil)
		if err != nil {
			return base.NewConnectorError(cfg.Name, "Connect", "failed to create service client", err)
		}
	} else {
		return base.NewConnectorError(cfg.Name, "Connect", "no authentication method provided", nil)
	}

	// Verify connectivity
	_, err = c.serviceClient.GetProperties(ctx, nil)
	if err != nil {
		return base.NewConnectorError(cfg.Name, "Connect", "failed to verify Azure Blob connectivity", err)
	}

	c.GetMetrics().RecordConnect()
	c.Log("Connected to Azure Blob Storage (account: %s, container: %s)", c.accountName, c.defaultContainer)

	return nil
}

// Disconnect closes the Azure Blob connection
func (c *AzureBlobConnector) Disconnect(ctx context.Context) error {
	c.GetMetrics().RecordDisconnect()
	c.client = nil
	c.serviceClient = nil
	return c.BaseConnector.Disconnect(ctx)
}

// HealthCheck verifies Azure Blob connectivity
func (c *AzureBlobConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.serviceClient == nil {
		return &base.HealthStatus{
			Healthy:   false,
			Error:     "Azure Blob client not initialized",
			Timestamp: time.Now(),
		}, nil
	}

	start := time.Now()
	_, err := c.serviceClient.GetProperties(ctx, nil)
	latency := time.Since(start)

	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Error:     err.Error(),
			Latency:   latency,
			Timestamp: time.Now(),
		}, nil
	}

	details := map[string]string{
		"account_name":      c.accountName,
		"default_container": c.defaultContainer,
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query lists blobs or retrieves blob content
func (c *AzureBlobConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "Azure Blob client not initialized", nil)
	}

	timer := sdk.NewTimer()
	defer timer.RecordTo(c.GetMetrics().RecordQuery, nil)

	action := query.Statement
	if action == "" {
		action = "list_blobs"
	}

	switch strings.ToLower(action) {
	case "list_containers":
		return c.listContainers(ctx)
	case "list_blobs", "list":
		return c.listBlobs(ctx, query)
	case "get_blob", "get":
		return c.getBlob(ctx, query)
	case "get_properties", "head":
		return c.getBlobProperties(ctx, query)
	case "generate_sas":
		return c.generateSAS(ctx, query)
	default:
		return nil, base.NewConnectorError(c.Name(), "Query", fmt.Sprintf("unknown action: %s", action), nil)
	}
}

// Execute performs write operations on Azure Blob
func (c *AzureBlobConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "Azure Blob client not initialized", nil)
	}

	timer := sdk.NewTimer()
	defer timer.RecordTo(c.GetMetrics().RecordExecute, nil)

	switch strings.ToLower(cmd.Action) {
	case "upload_blob", "put", "upload":
		return c.uploadBlob(ctx, cmd)
	case "delete_blob", "delete":
		return c.deleteBlob(ctx, cmd)
	case "copy_blob", "copy":
		return c.copyBlob(ctx, cmd)
	case "create_container":
		return c.createContainer(ctx, cmd)
	case "delete_container":
		return c.deleteContainer(ctx, cmd)
	default:
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("unknown action: %s", cmd.Action), nil)
	}
}

// listContainers returns all containers in the storage account
func (c *AzureBlobConnector) listContainers(ctx context.Context) (*base.QueryResult, error) {
	start := time.Now()

	pager := c.serviceClient.NewListContainersPager(nil)

	rows := make([]map[string]interface{}, 0)
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, base.NewConnectorError(c.Name(), "Query", "failed to list containers", err)
		}

		for _, container := range resp.ContainerItems {
			rows = append(rows, map[string]interface{}{
				"name":          *container.Name,
				"last_modified": container.Properties.LastModified,
			})
		}
	}

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// listBlobs lists blobs in a container
func (c *AzureBlobConnector) listBlobs(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	containerName := c.getContainer(query.Parameters)
	prefix := getStringParam(query.Parameters, "prefix", "")
	maxResults := int32(getIntParam(query.Parameters, "max_results", 1000))

	containerClient := c.serviceClient.NewContainerClient(containerName)

	listOptions := &container.ListBlobsFlatOptions{
		Prefix:     &prefix,
		MaxResults: &maxResults,
	}

	pager := containerClient.NewListBlobsFlatPager(listOptions)

	rows := make([]map[string]interface{}, 0)
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, base.NewConnectorError(c.Name(), "Query", "failed to list blobs", err)
		}

		for _, blob := range resp.Segment.BlobItems {
			rows = append(rows, map[string]interface{}{
				"name":          *blob.Name,
				"size":          *blob.Properties.ContentLength,
				"last_modified": blob.Properties.LastModified,
				"content_type":  getStringPtrValue(blob.Properties.ContentType),
				"etag":          getStringPtrValue((*string)(blob.Properties.ETag)),
			})
		}
	}

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// getBlob retrieves blob content
func (c *AzureBlobConnector) getBlob(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	containerName := c.getContainer(query.Parameters)
	blobName := getStringParam(query.Parameters, "blob", "")

	if blobName == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "blob name is required", nil)
	}

	blobClient := c.client.ServiceClient().NewContainerClient(containerName).NewBlobClient(blobName)

	downloadResponse, err := blobClient.DownloadStream(ctx, nil)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", fmt.Sprintf("failed to download blob: %s", blobName), err)
	}

	content, err := io.ReadAll(downloadResponse.Body)
	downloadResponse.Body.Close()
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to read blob content", err)
	}

	row := map[string]interface{}{
		"blob":           blobName,
		"content":        string(content),
		"content_length": *downloadResponse.ContentLength,
		"content_type":   getStringPtrValue(downloadResponse.ContentType),
		"last_modified":  downloadResponse.LastModified,
	}

	return &base.QueryResult{
		Rows:      []map[string]interface{}{row},
		RowCount:  1,
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// getBlobProperties retrieves blob metadata without content
func (c *AzureBlobConnector) getBlobProperties(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	containerName := c.getContainer(query.Parameters)
	blobName := getStringParam(query.Parameters, "blob", "")

	if blobName == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "blob name is required", nil)
	}

	blobClient := c.client.ServiceClient().NewContainerClient(containerName).NewBlobClient(blobName)

	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", fmt.Sprintf("failed to get blob properties: %s", blobName), err)
	}

	row := map[string]interface{}{
		"blob":           blobName,
		"content_length": *props.ContentLength,
		"content_type":   getStringPtrValue(props.ContentType),
		"last_modified":  props.LastModified,
		"etag":           getStringPtrValue((*string)(props.ETag)),
	}

	if props.Metadata != nil {
		row["metadata"] = props.Metadata
	}

	return &base.QueryResult{
		Rows:      []map[string]interface{}{row},
		RowCount:  1,
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// generateSAS generates a SAS URL for blob access
func (c *AzureBlobConnector) generateSAS(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	containerName := c.getContainer(query.Parameters)
	blobName := getStringParam(query.Parameters, "blob", "")
	permissions := getStringParam(query.Parameters, "permissions", "r") // r=read, w=write, d=delete
	expiry := getIntParam(query.Parameters, "expiry", c.GetIntOption("sas_expiry", 3600))

	if blobName == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "blob name is required", nil)
	}

	// We need the account key to generate SAS
	accountKey := c.GetCredential("account_key")
	if accountKey == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "account key required for SAS generation", nil)
	}

	// Create SAS permissions
	sasPerms := sas.BlobPermissions{}
	for _, p := range permissions {
		switch p {
		case 'r':
			sasPerms.Read = true
		case 'w':
			sasPerms.Write = true
		case 'd':
			sasPerms.Delete = true
		case 'c':
			sasPerms.Create = true
		}
	}

	expiryTime := time.Now().Add(time.Duration(expiry) * time.Second)

	cred, err := azblob.NewSharedKeyCredential(c.accountName, accountKey)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to create credential for SAS", err)
	}

	signatureValues := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		StartTime:     time.Now().Add(-10 * time.Minute),
		ExpiryTime:    expiryTime,
		Permissions:   sasPerms.String(),
		ContainerName: containerName,
		BlobName:      blobName,
	}

	sasQueryParams, err := signatureValues.SignWithSharedKey(cred)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to generate SAS token", err)
	}

	fullURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s?%s",
		c.accountName, containerName, blobName, sasQueryParams.Encode())

	row := map[string]interface{}{
		"url":         fullURL,
		"expires_at":  expiryTime,
		"permissions": permissions,
	}

	return &base.QueryResult{
		Rows:      []map[string]interface{}{row},
		RowCount:  1,
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// uploadBlob uploads content to a blob
func (c *AzureBlobConnector) uploadBlob(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	containerName := c.getContainer(cmd.Parameters)
	blobName := getStringParam(cmd.Parameters, "blob", "")
	content := getStringParam(cmd.Parameters, "content", "")
	contentType := getStringParam(cmd.Parameters, "content_type", "application/octet-stream")

	if blobName == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "blob name is required", nil)
	}

	_, err := c.client.UploadBuffer(ctx, containerName, blobName, []byte(content), &azblob.UploadBufferOptions{
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType: &contentType,
		},
	})
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("failed to upload blob: %s", blobName), err)
	}

	return &base.CommandResult{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("Blob uploaded successfully: %s", blobName),
		Connector: c.Name(),
	}, nil
}

// deleteBlob deletes a blob
func (c *AzureBlobConnector) deleteBlob(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	containerName := c.getContainer(cmd.Parameters)
	blobName := getStringParam(cmd.Parameters, "blob", "")

	if blobName == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "blob name is required", nil)
	}

	_, err := c.client.DeleteBlob(ctx, containerName, blobName, nil)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("failed to delete blob: %s", blobName), err)
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Duration:     time.Since(start),
		Message:      fmt.Sprintf("Blob deleted: %s", blobName),
		Connector:    c.Name(),
	}, nil
}

// copyBlob copies a blob
func (c *AzureBlobConnector) copyBlob(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	sourceContainer := getStringParam(cmd.Parameters, "source_container", c.defaultContainer)
	sourceBlob := getStringParam(cmd.Parameters, "source_blob", "")
	destContainer := getStringParam(cmd.Parameters, "dest_container", c.defaultContainer)
	destBlob := getStringParam(cmd.Parameters, "dest_blob", "")

	if sourceBlob == "" || destBlob == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "source_blob and dest_blob are required", nil)
	}

	sourceURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s",
		c.accountName, sourceContainer, sourceBlob)

	destClient := c.client.ServiceClient().NewContainerClient(destContainer).NewBlobClient(destBlob)

	_, err := destClient.StartCopyFromURL(ctx, sourceURL, nil)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to copy blob", err)
	}

	return &base.CommandResult{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("Blob copy started from %s to %s/%s", sourceURL, destContainer, destBlob),
		Connector: c.Name(),
	}, nil
}

// createContainer creates a new container
func (c *AzureBlobConnector) createContainer(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	containerName := getStringParam(cmd.Parameters, "container", "")

	if containerName == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "container name is required", nil)
	}

	_, err := c.client.CreateContainer(ctx, containerName, nil)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("failed to create container: %s", containerName), err)
	}

	return &base.CommandResult{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("Container created: %s", containerName),
		Connector: c.Name(),
	}, nil
}

// deleteContainer deletes a container
func (c *AzureBlobConnector) deleteContainer(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	containerName := getStringParam(cmd.Parameters, "container", "")

	if containerName == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "container name is required", nil)
	}

	_, err := c.client.DeleteContainer(ctx, containerName, nil)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("failed to delete container: %s", containerName), err)
	}

	return &base.CommandResult{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("Container deleted: %s", containerName),
		Connector: c.Name(),
	}, nil
}

// getContainer returns the container from parameters or default
func (c *AzureBlobConnector) getContainer(params map[string]interface{}) string {
	if container := getStringParam(params, "container", ""); container != "" {
		return container
	}
	return c.defaultContainer
}

// Helper functions
func getStringParam(params map[string]interface{}, key, defaultValue string) string {
	if params == nil {
		return defaultValue
	}
	if v, ok := params[key].(string); ok {
		return v
	}
	return defaultValue
}

func getIntParam(params map[string]interface{}, key string, defaultValue int) int {
	if params == nil {
		return defaultValue
	}
	switch v := params[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return defaultValue
}

func getStringPtrValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Verify AzureBlobConnector implements base.Connector
var _ base.Connector = (*AzureBlobConnector)(nil)
