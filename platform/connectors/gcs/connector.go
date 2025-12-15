// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gcs provides a Google Cloud Storage connector for the AxonFlow platform.
// It implements the base.Connector interface for GCS bucket and object operations.
package gcs

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/sdk"
)

// GCSConnector implements the Connector interface for Google Cloud Storage
type GCSConnector struct {
	sdk.BaseConnector
	client        *storage.Client
	defaultBucket string
	projectID     string
}

// NewGCSConnector creates a new GCS connector instance
func NewGCSConnector() *GCSConnector {
	conn := &GCSConnector{}
	conn.BaseConnector = *sdk.NewBaseConnector("gcs")
	conn.SetVersion("1.0.0")
	conn.SetCapabilities([]string{
		"query",     // List objects, get object, etc.
		"execute",   // Put/Delete objects
		"presign",   // Generate signed URLs
		"streaming", // Streaming support
	})

	// Set up configuration validator
	conn.SetValidator(sdk.NewDefaultConfigValidator(
		[]string{}, // No strictly required fields - can use ADC
		map[string]interface{}{
			"signed_url_expiry": 900, // 15 minutes in seconds
		},
	))

	return conn
}

// Connect establishes connection to GCS
func (c *GCSConnector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error {
	// Call base connect for validation and hooks
	if err := c.BaseConnector.Connect(ctx, cfg); err != nil {
		return err
	}

	// Get configuration options
	c.defaultBucket = c.GetStringOption("default_bucket", "")
	c.projectID = c.GetStringOption("project_id", "")

	// Build client options
	var opts []option.ClientOption

	// Check for credentials file path
	if credFile := c.GetCredential("credentials_file"); credFile != "" {
		opts = append(opts, option.WithCredentialsFile(credFile))
	} else if credJSON := c.GetCredential("credentials_json"); credJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(credJSON)))
	}

	// Check for custom endpoint (useful for emulator)
	if endpoint := c.GetStringOption("endpoint", ""); endpoint != "" {
		opts = append(opts, option.WithEndpoint(endpoint))
	}

	// Create the GCS client
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return base.NewConnectorError(cfg.Name, "Connect", "failed to create GCS client", err)
	}

	c.client = client

	// Verify connectivity
	if c.defaultBucket != "" {
		// Check if default bucket exists
		_, err = c.client.Bucket(c.defaultBucket).Attrs(ctx)
	} else if c.projectID != "" {
		// Try to list one bucket
		it := c.client.Buckets(ctx, c.projectID)
		_, err = it.Next()
		if err == iterator.Done {
			err = nil // No buckets is fine
		}
	}

	if err != nil {
		return base.NewConnectorError(cfg.Name, "Connect", "failed to verify GCS connectivity", err)
	}

	c.GetMetrics().RecordConnect()
	c.Log("Connected to GCS (project: %s, bucket: %s)", c.projectID, c.defaultBucket)

	return nil
}

// Disconnect closes the GCS client
func (c *GCSConnector) Disconnect(ctx context.Context) error {
	c.GetMetrics().RecordDisconnect()
	if c.client != nil {
		if err := c.client.Close(); err != nil {
			c.Log("Warning: error closing GCS client: %v", err)
		}
		c.client = nil
	}
	return c.BaseConnector.Disconnect(ctx)
}

// HealthCheck verifies GCS connectivity
func (c *GCSConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.client == nil {
		return &base.HealthStatus{
			Healthy:   false,
			Error:     "GCS client not initialized",
			Timestamp: time.Now(),
		}, nil
	}

	start := time.Now()
	var err error

	// Try to access default bucket or list buckets
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if c.defaultBucket != "" {
		_, err = c.client.Bucket(c.defaultBucket).Attrs(ctx)
	} else if c.projectID != "" {
		it := c.client.Buckets(ctx, c.projectID)
		_, err = it.Next()
		if err == iterator.Done {
			err = nil
		}
	}

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
		"project_id":     c.projectID,
		"default_bucket": c.defaultBucket,
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes read operations on GCS
func (c *GCSConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "not connected", nil)
	}

	timer := sdk.NewTimer()
	timeout := c.GetTimeout()
	if query.Timeout > 0 {
		timeout = query.Timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var result *base.QueryResult
	var err error

	switch query.Statement {
	case "list_objects":
		result, err = c.listObjects(ctx, query.Parameters)
	case "get_object":
		result, err = c.getObject(ctx, query.Parameters)
	case "get_object_metadata":
		result, err = c.getObjectMetadata(ctx, query.Parameters)
	case "list_buckets":
		result, err = c.listBuckets(ctx, query.Parameters)
	case "get_bucket_metadata":
		result, err = c.getBucketMetadata(ctx, query.Parameters)
	default:
		err = base.NewConnectorError(c.Name(), "Query", fmt.Sprintf("unsupported query: %s", query.Statement), nil)
	}

	c.GetMetrics().RecordQuery(timer.Duration(), err)

	if err != nil {
		return nil, err
	}

	result.Duration = timer.Duration()
	result.Connector = c.Name()
	return result, nil
}

// Execute performs write operations on GCS
func (c *GCSConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "not connected", nil)
	}

	timer := sdk.NewTimer()
	timeout := c.GetTimeout()
	if cmd.Timeout > 0 {
		timeout = cmd.Timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var result *base.CommandResult
	var err error

	switch cmd.Action {
	case "put_object":
		result, err = c.putObject(ctx, cmd.Parameters)
	case "delete_object":
		result, err = c.deleteObject(ctx, cmd.Parameters)
	case "copy_object":
		result, err = c.copyObject(ctx, cmd.Parameters)
	case "create_bucket":
		result, err = c.createBucket(ctx, cmd.Parameters)
	case "delete_bucket":
		result, err = c.deleteBucket(ctx, cmd.Parameters)
	case "generate_signed_url", "presign":
		result, err = c.generateSignedURL(ctx, cmd.Parameters)
	default:
		err = base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("unsupported action: %s", cmd.Action), nil)
	}

	c.GetMetrics().RecordExecute(timer.Duration(), err)

	if err != nil {
		return nil, err
	}

	result.Duration = timer.Duration()
	result.Connector = c.Name()
	return result, nil
}

// listObjects lists objects in a GCS bucket
func (c *GCSConnector) listObjects(ctx context.Context, params map[string]interface{}) (*base.QueryResult, error) {
	bucket := c.getBucket(params)
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "bucket is required", nil)
	}

	prefix := getStringParam(params, "prefix", "")
	delimiter := getStringParam(params, "delimiter", "")
	maxResults := getIntParam(params, "max_results", 1000)

	query := &storage.Query{
		Prefix:    prefix,
		Delimiter: delimiter,
	}

	it := c.client.Bucket(bucket).Objects(ctx, query)

	var rows []map[string]interface{}
	count := 0

	for count < maxResults {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, base.NewConnectorError(c.Name(), "Query", "failed to list objects", err)
		}

		row := map[string]interface{}{
			"name":          attrs.Name,
			"bucket":        attrs.Bucket,
			"size":          attrs.Size,
			"content_type":  attrs.ContentType,
			"updated":       attrs.Updated,
			"created":       attrs.Created,
			"generation":    attrs.Generation,
			"storage_class": attrs.StorageClass,
			"etag":          attrs.Etag,
			"md5":           attrs.MD5,
		}

		if attrs.Prefix != "" {
			row["prefix"] = attrs.Prefix
		}

		rows = append(rows, row)
		count++
	}

	return &base.QueryResult{
		Rows:     rows,
		RowCount: len(rows),
		Metadata: map[string]interface{}{
			"bucket": bucket,
			"prefix": prefix,
		},
	}, nil
}

// getObject retrieves an object from GCS
func (c *GCSConnector) getObject(ctx context.Context, params map[string]interface{}) (*base.QueryResult, error) {
	bucket := c.getBucket(params)
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "bucket is required", nil)
	}

	key := getStringParam(params, "key", "")
	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "key is required", nil)
	}

	obj := c.client.Bucket(bucket).Object(key)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", fmt.Sprintf("failed to read object: %s", key), err)
	}
	defer func() {
		_ = reader.Close()
	}()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to read object content", err)
	}

	attrs := reader.Attrs

	row := map[string]interface{}{
		"key":          key,
		"bucket":       bucket,
		"content":      string(content),
		"content_type": attrs.ContentType,
		"size":         attrs.Size,
		"generation":   attrs.Generation,
	}

	return &base.QueryResult{
		Rows:     []map[string]interface{}{row},
		RowCount: 1,
	}, nil
}

// getObjectMetadata retrieves object metadata without content
func (c *GCSConnector) getObjectMetadata(ctx context.Context, params map[string]interface{}) (*base.QueryResult, error) {
	bucket := c.getBucket(params)
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "bucket is required", nil)
	}

	key := getStringParam(params, "key", "")
	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "key is required", nil)
	}

	attrs, err := c.client.Bucket(bucket).Object(key).Attrs(ctx)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to get object attributes", err)
	}

	row := map[string]interface{}{
		"name":                      attrs.Name,
		"bucket":                    attrs.Bucket,
		"size":                      attrs.Size,
		"content_type":              attrs.ContentType,
		"content_encoding":          attrs.ContentEncoding,
		"content_language":          attrs.ContentLanguage,
		"cache_control":             attrs.CacheControl,
		"updated":                   attrs.Updated,
		"created":                   attrs.Created,
		"generation":                attrs.Generation,
		"metageneration":            attrs.Metageneration,
		"storage_class":             attrs.StorageClass,
		"etag":                      attrs.Etag,
		"md5":                       attrs.MD5,
		"crc32c":                    attrs.CRC32C,
		"metadata":                  attrs.Metadata,
		"owner":                     attrs.Owner,
		"retention_expires":         attrs.RetentionExpirationTime,
	}

	return &base.QueryResult{
		Rows:     []map[string]interface{}{row},
		RowCount: 1,
	}, nil
}

// listBuckets lists all buckets in the project
func (c *GCSConnector) listBuckets(ctx context.Context, params map[string]interface{}) (*base.QueryResult, error) {
	projectID := getStringParam(params, "project_id", c.projectID)
	if projectID == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "project_id is required", nil)
	}

	it := c.client.Buckets(ctx, projectID)

	var rows []map[string]interface{}

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, base.NewConnectorError(c.Name(), "Query", "failed to list buckets", err)
		}

		row := map[string]interface{}{
			"name":                      attrs.Name,
			"location":                  attrs.Location,
			"location_type":             attrs.LocationType,
			"storage_class":             attrs.StorageClass,
			"created":                   attrs.Created,
			"versioning":                attrs.VersioningEnabled,
			"requester_pays":            attrs.RequesterPays,
			"default_event_based_hold":  attrs.DefaultEventBasedHold,
		}

		rows = append(rows, row)
	}

	return &base.QueryResult{
		Rows:     rows,
		RowCount: len(rows),
		Metadata: map[string]interface{}{
			"project_id": projectID,
		},
	}, nil
}

// getBucketMetadata retrieves bucket metadata
func (c *GCSConnector) getBucketMetadata(ctx context.Context, params map[string]interface{}) (*base.QueryResult, error) {
	bucket := c.getBucket(params)
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "bucket is required", nil)
	}

	attrs, err := c.client.Bucket(bucket).Attrs(ctx)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to get bucket attributes", err)
	}

	row := map[string]interface{}{
		"name":                      attrs.Name,
		"location":                  attrs.Location,
		"location_type":             attrs.LocationType,
		"storage_class":             attrs.StorageClass,
		"created":                   attrs.Created,
		"metageneration":            attrs.MetaGeneration,
		"versioning":                attrs.VersioningEnabled,
		"requester_pays":            attrs.RequesterPays,
		"labels":                    attrs.Labels,
		"default_event_based_hold":  attrs.DefaultEventBasedHold,
		"etag":                      attrs.Etag,
	}

	return &base.QueryResult{
		Rows:     []map[string]interface{}{row},
		RowCount: 1,
	}, nil
}

// putObject uploads an object to GCS
func (c *GCSConnector) putObject(ctx context.Context, params map[string]interface{}) (*base.CommandResult, error) {
	bucket := c.getBucket(params)
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "bucket is required", nil)
	}

	key := getStringParam(params, "key", "")
	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "key is required", nil)
	}

	content := getStringParam(params, "content", "")
	contentType := getStringParam(params, "content_type", "application/octet-stream")

	obj := c.client.Bucket(bucket).Object(key)
	writer := obj.NewWriter(ctx)
	writer.ContentType = contentType

	// Set optional metadata
	if metadata, ok := params["metadata"].(map[string]string); ok {
		writer.Metadata = metadata
	}

	// Set cache control if provided
	if cacheControl := getStringParam(params, "cache_control", ""); cacheControl != "" {
		writer.CacheControl = cacheControl
	}

	// Set content encoding if provided
	if contentEncoding := getStringParam(params, "content_encoding", ""); contentEncoding != "" {
		writer.ContentEncoding = contentEncoding
	}

	// Write content
	if _, err := writer.Write([]byte(content)); err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to write object", err)
	}

	if err := writer.Close(); err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to close writer", err)
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Message:      fmt.Sprintf("uploaded object %s to bucket %s", key, bucket),
		Metadata: map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		},
	}, nil
}

// deleteObject removes an object from GCS
func (c *GCSConnector) deleteObject(ctx context.Context, params map[string]interface{}) (*base.CommandResult, error) {
	bucket := c.getBucket(params)
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "bucket is required", nil)
	}

	key := getStringParam(params, "key", "")
	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "key is required", nil)
	}

	obj := c.client.Bucket(bucket).Object(key)

	// Check for generation (for versioned deletes)
	if gen := getIntParam(params, "generation", 0); gen > 0 {
		obj = obj.Generation(int64(gen))
	}

	if err := obj.Delete(ctx); err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to delete object", err)
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Message:      fmt.Sprintf("deleted object %s from bucket %s", key, bucket),
	}, nil
}

// copyObject copies an object within GCS
func (c *GCSConnector) copyObject(ctx context.Context, params map[string]interface{}) (*base.CommandResult, error) {
	srcBucket := getStringParam(params, "source_bucket", c.defaultBucket)
	if srcBucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "source_bucket is required", nil)
	}

	srcKey := getStringParam(params, "source_key", "")
	if srcKey == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "source_key is required", nil)
	}

	dstBucket := getStringParam(params, "destination_bucket", srcBucket)
	dstKey := getStringParam(params, "destination_key", "")
	if dstKey == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "destination_key is required", nil)
	}

	src := c.client.Bucket(srcBucket).Object(srcKey)
	dst := c.client.Bucket(dstBucket).Object(dstKey)

	copier := dst.CopierFrom(src)

	// Set content type if provided
	if contentType := getStringParam(params, "content_type", ""); contentType != "" {
		copier.ContentType = contentType
	}

	attrs, err := copier.Run(ctx)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to copy object", err)
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Message:      fmt.Sprintf("copied %s/%s to %s/%s", srcBucket, srcKey, dstBucket, dstKey),
		Metadata: map[string]interface{}{
			"generation": attrs.Generation,
			"size":       attrs.Size,
		},
	}, nil
}

// createBucket creates a new GCS bucket
func (c *GCSConnector) createBucket(ctx context.Context, params map[string]interface{}) (*base.CommandResult, error) {
	bucket := getStringParam(params, "bucket", "")
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "bucket name is required", nil)
	}

	projectID := getStringParam(params, "project_id", c.projectID)
	if projectID == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "project_id is required", nil)
	}

	attrs := &storage.BucketAttrs{
		Location:     getStringParam(params, "location", "US"),
		StorageClass: getStringParam(params, "storage_class", "STANDARD"),
	}

	// Enable versioning if requested
	if versioning, ok := params["versioning"].(bool); ok && versioning {
		attrs.VersioningEnabled = true
	}

	// Set labels if provided
	if labels, ok := params["labels"].(map[string]string); ok {
		attrs.Labels = labels
	}

	if err := c.client.Bucket(bucket).Create(ctx, projectID, attrs); err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to create bucket", err)
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Message:      fmt.Sprintf("created bucket %s in project %s", bucket, projectID),
		Metadata: map[string]interface{}{
			"bucket":        bucket,
			"location":      attrs.Location,
			"storage_class": attrs.StorageClass,
		},
	}, nil
}

// deleteBucket deletes a GCS bucket
func (c *GCSConnector) deleteBucket(ctx context.Context, params map[string]interface{}) (*base.CommandResult, error) {
	bucket := getStringParam(params, "bucket", "")
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "bucket name is required", nil)
	}

	if err := c.client.Bucket(bucket).Delete(ctx); err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to delete bucket", err)
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Message:      fmt.Sprintf("deleted bucket %s", bucket),
	}, nil
}

// generateSignedURL generates a signed URL for object access
func (c *GCSConnector) generateSignedURL(ctx context.Context, params map[string]interface{}) (*base.CommandResult, error) {
	bucket := c.getBucket(params)
	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "bucket is required", nil)
	}

	key := getStringParam(params, "key", "")
	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "key is required", nil)
	}

	// Get expiration (default 15 minutes)
	expiresIn := c.GetIntOption("signed_url_expiry", 900)
	if paramExpiry := getIntParam(params, "expires_in", 0); paramExpiry > 0 {
		expiresIn = paramExpiry
	}
	expiration := time.Now().Add(time.Duration(expiresIn) * time.Second)

	// Determine HTTP method
	method := strings.ToUpper(getStringParam(params, "method", "GET"))

	opts := &storage.SignedURLOptions{
		Method:  method,
		Expires: expiration,
	}

	// Set content type for PUT requests
	if method == "PUT" {
		if contentType := getStringParam(params, "content_type", ""); contentType != "" {
			opts.ContentType = contentType
		}
	}

	signedURL, err := c.client.Bucket(bucket).SignedURL(key, opts)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to generate signed URL", err)
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Message:      "generated signed URL",
		Metadata: map[string]interface{}{
			"url":        signedURL,
			"bucket":     bucket,
			"key":        key,
			"method":     method,
			"expires_at": expiration,
		},
	}, nil
}

// getBucket returns the bucket from params or the default bucket
func (c *GCSConnector) getBucket(params map[string]interface{}) string {
	if bucket := getStringParam(params, "bucket", ""); bucket != "" {
		return bucket
	}
	return c.defaultBucket
}

// Helper functions (kept for backward compatibility with existing tests)

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

// Ensure GCSConnector implements the Connector interface
var _ base.Connector = (*GCSConnector)(nil)
