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

// Package s3 provides an Amazon S3 connector for the AxonFlow platform.
// It implements the base.Connector interface for S3 bucket and object operations
// including listing, reading, writing, and presigned URL generation.
// This connector also supports S3-compatible storage services like MinIO,
// DigitalOcean Spaces, and Cloudflare R2.
package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/sdk"
)

// S3Connector implements the MCP Connector interface for Amazon S3
type S3Connector struct {
	sdk.BaseConnector
	client       *s3.Client
	defaultBucket string
	presignClient *s3.PresignClient
}

// NewS3Connector creates a new S3 connector instance
func NewS3Connector() *S3Connector {
	conn := &S3Connector{}
	conn.BaseConnector = *sdk.NewBaseConnector("s3")
	conn.SetVersion("1.0.0")
	conn.SetCapabilities([]string{
		"query",        // List objects
		"execute",      // Put/Delete objects
		"presign",      // Generate presigned URLs
		"multipart",    // Multipart upload support
		"streaming",    // Streaming support
	})

	// Set up configuration validator
	conn.SetValidator(sdk.NewDefaultConfigValidator(
		[]string{}, // No strictly required fields - can use IAM roles
		map[string]interface{}{
			"region":           "us-east-1",
			"max_retries":      3,
			"presign_expiry":   3600, // 1 hour in seconds
		},
	))

	return conn
}

// Connect establishes connection to S3
func (c *S3Connector) Connect(ctx context.Context, cfg *base.ConnectorConfig) error {
	// Call base connect for validation and hooks
	if err := c.BaseConnector.Connect(ctx, cfg); err != nil {
		return err
	}

	// Get configuration options
	region := c.GetStringOption("region", "us-east-1")
	endpoint := c.GetStringOption("endpoint", "")
	forcePathStyle := c.GetBoolOption("force_path_style", false)

	// Get credentials
	accessKeyID := c.GetCredential("access_key_id")
	secretAccessKey := c.GetCredential("secret_access_key")
	sessionToken := c.GetCredential("session_token")

	// Build AWS config
	var awsCfg aws.Config
	var err error

	optFns := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}

	// Use explicit credentials if provided, otherwise use default credential chain
	if accessKeyID != "" && secretAccessKey != "" {
		creds := credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)
		optFns = append(optFns, config.WithCredentialsProvider(creds))
	}

	awsCfg, err = config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return base.NewConnectorError(cfg.Name, "Connect", "failed to load AWS config", err)
	}

	// Create S3 client options
	s3Options := []func(*s3.Options){}

	if endpoint != "" {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	if forcePathStyle {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	// Create S3 client
	c.client = s3.NewFromConfig(awsCfg, s3Options...)
	c.presignClient = s3.NewPresignClient(c.client)

	// Get default bucket if specified
	c.defaultBucket = c.GetStringOption("default_bucket", "")

	// Verify connectivity by listing buckets (unless bucket is specified)
	if c.defaultBucket == "" {
		_, err = c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	} else {
		_, err = c.client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: aws.String(c.defaultBucket),
		})
	}

	if err != nil {
		return base.NewConnectorError(cfg.Name, "Connect", "failed to verify S3 connectivity", err)
	}

	c.GetMetrics().RecordConnect()
	c.Log("Connected to S3 (region: %s, bucket: %s)", region, c.defaultBucket)

	return nil
}

// Disconnect closes the S3 connection
func (c *S3Connector) Disconnect(ctx context.Context) error {
	c.GetMetrics().RecordDisconnect()
	c.client = nil
	c.presignClient = nil
	return c.BaseConnector.Disconnect(ctx)
}

// HealthCheck verifies S3 connectivity
func (c *S3Connector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.client == nil {
		return &base.HealthStatus{
			Healthy:   false,
			Error:     "S3 client not initialized",
			Timestamp: time.Now(),
		}, nil
	}

	start := time.Now()
	var err error

	if c.defaultBucket != "" {
		_, err = c.client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: aws.String(c.defaultBucket),
		})
	} else {
		_, err = c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
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
		"default_bucket": c.defaultBucket,
		"region":         c.GetStringOption("region", "us-east-1"),
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query lists objects or retrieves object content from S3
func (c *S3Connector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "S3 client not initialized", nil)
	}

	timer := sdk.NewTimer()
	defer timer.RecordTo(c.GetMetrics().RecordQuery, nil)

	// Parse query parameters
	action := query.Statement
	if action == "" {
		action = "list_objects"
	}

	switch strings.ToLower(action) {
	case "list_buckets":
		return c.listBuckets(ctx)
	case "list_objects", "list":
		return c.listObjects(ctx, query)
	case "get_object", "get":
		return c.getObject(ctx, query)
	case "head_object", "head":
		return c.headObject(ctx, query)
	case "presign_get":
		return c.presignGetObject(ctx, query)
	case "presign_put":
		return c.presignPutObject(ctx, query)
	default:
		return nil, base.NewConnectorError(c.Name(), "Query", fmt.Sprintf("unknown action: %s", action), nil)
	}
}

// Execute performs write operations on S3
func (c *S3Connector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "S3 client not initialized", nil)
	}

	timer := sdk.NewTimer()
	defer timer.RecordTo(c.GetMetrics().RecordExecute, nil)

	switch strings.ToLower(cmd.Action) {
	case "put_object", "put", "upload":
		return c.putObject(ctx, cmd)
	case "delete_object", "delete":
		return c.deleteObject(ctx, cmd)
	case "delete_objects", "delete_many":
		return c.deleteObjects(ctx, cmd)
	case "copy_object", "copy":
		return c.copyObject(ctx, cmd)
	case "create_bucket":
		return c.createBucket(ctx, cmd)
	case "delete_bucket":
		return c.deleteBucket(ctx, cmd)
	default:
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("unknown action: %s", cmd.Action), nil)
	}
}

// listBuckets returns all accessible S3 buckets
func (c *S3Connector) listBuckets(ctx context.Context) (*base.QueryResult, error) {
	start := time.Now()

	output, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to list buckets", err)
	}

	rows := make([]map[string]interface{}, 0, len(output.Buckets))
	for _, bucket := range output.Buckets {
		rows = append(rows, map[string]interface{}{
			"name":         aws.ToString(bucket.Name),
			"creation_date": bucket.CreationDate,
		})
	}

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// listObjects lists objects in a bucket
func (c *S3Connector) listObjects(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	bucket := c.getBucket(query.Parameters)
	prefix := getStringParam(query.Parameters, "prefix", "")
	delimiter := getStringParam(query.Parameters, "delimiter", "")
	maxKeys := int32(getIntParam(query.Parameters, "max_keys", 1000))
	continuationToken := getStringParam(query.Parameters, "continuation_token", "")

	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(maxKeys),
	}

	if delimiter != "" {
		input.Delimiter = aws.String(delimiter)
	}

	if continuationToken != "" {
		input.ContinuationToken = aws.String(continuationToken)
	}

	output, err := c.client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to list objects", err)
	}

	rows := make([]map[string]interface{}, 0, len(output.Contents))
	for _, obj := range output.Contents {
		rows = append(rows, map[string]interface{}{
			"key":           aws.ToString(obj.Key),
			"size":          obj.Size,
			"last_modified": obj.LastModified,
			"etag":          strings.Trim(aws.ToString(obj.ETag), "\""),
			"storage_class": string(obj.StorageClass),
		})
	}

	// Add common prefixes for directory-like listing
	metadata := map[string]interface{}{
		"is_truncated":        output.IsTruncated,
		"key_count":           output.KeyCount,
	}

	if output.NextContinuationToken != nil {
		metadata["next_continuation_token"] = aws.ToString(output.NextContinuationToken)
	}

	if len(output.CommonPrefixes) > 0 {
		prefixes := make([]string, 0, len(output.CommonPrefixes))
		for _, p := range output.CommonPrefixes {
			prefixes = append(prefixes, aws.ToString(p.Prefix))
		}
		metadata["common_prefixes"] = prefixes
	}

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  time.Since(start),
		Connector: c.Name(),
		Metadata:  metadata,
	}, nil
}

// getObject retrieves object content
func (c *S3Connector) getObject(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	bucket := c.getBucket(query.Parameters)
	key := getStringParam(query.Parameters, "key", "")

	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "key is required", nil)
	}

	output, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", fmt.Sprintf("failed to get object: %s", key), err)
	}
	defer output.Body.Close()

	// Read content
	content, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to read object content", err)
	}

	row := map[string]interface{}{
		"key":            key,
		"content":        string(content),
		"content_length": output.ContentLength,
		"content_type":   aws.ToString(output.ContentType),
		"etag":           strings.Trim(aws.ToString(output.ETag), "\""),
		"last_modified":  output.LastModified,
	}

	if output.Metadata != nil {
		row["metadata"] = output.Metadata
	}

	return &base.QueryResult{
		Rows:      []map[string]interface{}{row},
		RowCount:  1,
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// headObject retrieves object metadata without content
func (c *S3Connector) headObject(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	bucket := c.getBucket(query.Parameters)
	key := getStringParam(query.Parameters, "key", "")

	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "key is required", nil)
	}

	output, err := c.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", fmt.Sprintf("failed to head object: %s", key), err)
	}

	row := map[string]interface{}{
		"key":            key,
		"content_length": output.ContentLength,
		"content_type":   aws.ToString(output.ContentType),
		"etag":           strings.Trim(aws.ToString(output.ETag), "\""),
		"last_modified":  output.LastModified,
		"storage_class":  string(output.StorageClass),
	}

	if output.Metadata != nil {
		row["metadata"] = output.Metadata
	}

	return &base.QueryResult{
		Rows:      []map[string]interface{}{row},
		RowCount:  1,
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// presignGetObject generates a presigned URL for downloading an object
func (c *S3Connector) presignGetObject(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	bucket := c.getBucket(query.Parameters)
	key := getStringParam(query.Parameters, "key", "")
	expiry := getIntParam(query.Parameters, "expiry", c.GetIntOption("presign_expiry", 3600))

	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "key is required", nil)
	}

	presigned, err := c.presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(time.Duration(expiry)*time.Second))

	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to presign get object", err)
	}

	row := map[string]interface{}{
		"url":        presigned.URL,
		"method":     presigned.Method,
		"expires_at": time.Now().Add(time.Duration(expiry) * time.Second),
	}

	return &base.QueryResult{
		Rows:      []map[string]interface{}{row},
		RowCount:  1,
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// presignPutObject generates a presigned URL for uploading an object
func (c *S3Connector) presignPutObject(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	start := time.Now()

	bucket := c.getBucket(query.Parameters)
	key := getStringParam(query.Parameters, "key", "")
	contentType := getStringParam(query.Parameters, "content_type", "application/octet-stream")
	expiry := getIntParam(query.Parameters, "expiry", c.GetIntOption("presign_expiry", 3600))

	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Query", "key is required", nil)
	}

	presigned, err := c.presignClient.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	}, s3.WithPresignExpires(time.Duration(expiry)*time.Second))

	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to presign put object", err)
	}

	row := map[string]interface{}{
		"url":          presigned.URL,
		"method":       presigned.Method,
		"content_type": contentType,
		"expires_at":   time.Now().Add(time.Duration(expiry) * time.Second),
	}

	return &base.QueryResult{
		Rows:      []map[string]interface{}{row},
		RowCount:  1,
		Duration:  time.Since(start),
		Connector: c.Name(),
	}, nil
}

// putObject uploads an object to S3
func (c *S3Connector) putObject(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	bucket := c.getBucket(cmd.Parameters)
	key := getStringParam(cmd.Parameters, "key", "")
	content := getStringParam(cmd.Parameters, "content", "")
	contentType := getStringParam(cmd.Parameters, "content_type", "application/octet-stream")

	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "key is required", nil)
	}

	// Get metadata if provided
	var metadata map[string]string
	if m, ok := cmd.Parameters["metadata"].(map[string]string); ok {
		metadata = m
	} else if m, ok := cmd.Parameters["metadata"].(map[string]interface{}); ok {
		metadata = make(map[string]string)
		for k, v := range m {
			if s, ok := v.(string); ok {
				metadata[k] = s
			}
		}
	}

	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader([]byte(content)),
		ContentType: aws.String(contentType),
	}

	if len(metadata) > 0 {
		input.Metadata = metadata
	}

	output, err := c.client.PutObject(ctx, input)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("failed to put object: %s", key), err)
	}

	return &base.CommandResult{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("Object uploaded successfully: %s", key),
		Connector: c.Name(),
		Metadata: map[string]interface{}{
			"etag":       strings.Trim(aws.ToString(output.ETag), "\""),
			"version_id": aws.ToString(output.VersionId),
		},
	}, nil
}

// deleteObject deletes a single object from S3
func (c *S3Connector) deleteObject(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	bucket := c.getBucket(cmd.Parameters)
	key := getStringParam(cmd.Parameters, "key", "")
	versionId := getStringParam(cmd.Parameters, "version_id", "")

	if key == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "key is required", nil)
	}

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	if versionId != "" {
		input.VersionId = aws.String(versionId)
	}

	_, err := c.client.DeleteObject(ctx, input)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("failed to delete object: %s", key), err)
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1,
		Duration:     time.Since(start),
		Message:      fmt.Sprintf("Object deleted: %s", key),
		Connector:    c.Name(),
	}, nil
}

// deleteObjects deletes multiple objects from S3
func (c *S3Connector) deleteObjects(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	bucket := c.getBucket(cmd.Parameters)
	keys := getStringSliceParam(cmd.Parameters, "keys")

	if len(keys) == 0 {
		return nil, base.NewConnectorError(c.Name(), "Execute", "keys is required", nil)
	}

	objects := make([]types.ObjectIdentifier, 0, len(keys))
	for _, key := range keys {
		objects = append(objects, types.ObjectIdentifier{
			Key: aws.String(key),
		})
	}

	output, err := c.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   aws.Bool(true),
		},
	})
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to delete objects", err)
	}

	deletedCount := len(keys) - len(output.Errors)

	return &base.CommandResult{
		Success:      true,
		RowsAffected: deletedCount,
		Duration:     time.Since(start),
		Message:      fmt.Sprintf("Deleted %d objects", deletedCount),
		Connector:    c.Name(),
	}, nil
}

// copyObject copies an object within S3
func (c *S3Connector) copyObject(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	sourceBucket := getStringParam(cmd.Parameters, "source_bucket", c.defaultBucket)
	sourceKey := getStringParam(cmd.Parameters, "source_key", "")
	destBucket := getStringParam(cmd.Parameters, "dest_bucket", c.defaultBucket)
	destKey := getStringParam(cmd.Parameters, "dest_key", "")

	if sourceKey == "" || destKey == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "source_key and dest_key are required", nil)
	}

	copySource := fmt.Sprintf("%s/%s", sourceBucket, sourceKey)

	_, err := c.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(destBucket),
		Key:        aws.String(destKey),
		CopySource: aws.String(copySource),
	})
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to copy object", err)
	}

	return &base.CommandResult{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("Object copied from %s to %s/%s", copySource, destBucket, destKey),
		Connector: c.Name(),
	}, nil
}

// createBucket creates a new S3 bucket
func (c *S3Connector) createBucket(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	bucket := getStringParam(cmd.Parameters, "bucket", "")
	region := c.GetStringOption("region", "us-east-1")

	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "bucket name is required", nil)
	}

	input := &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}

	// Only set location constraint for non us-east-1 regions
	if region != "us-east-1" {
		input.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(region),
		}
	}

	_, err := c.client.CreateBucket(ctx, input)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("failed to create bucket: %s", bucket), err)
	}

	return &base.CommandResult{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("Bucket created: %s", bucket),
		Connector: c.Name(),
	}, nil
}

// deleteBucket deletes an S3 bucket (must be empty)
func (c *S3Connector) deleteBucket(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	start := time.Now()

	bucket := getStringParam(cmd.Parameters, "bucket", "")

	if bucket == "" {
		return nil, base.NewConnectorError(c.Name(), "Execute", "bucket name is required", nil)
	}

	_, err := c.client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", fmt.Sprintf("failed to delete bucket: %s", bucket), err)
	}

	return &base.CommandResult{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("Bucket deleted: %s", bucket),
		Connector: c.Name(),
	}, nil
}

// getBucket returns the bucket from parameters or default
func (c *S3Connector) getBucket(params map[string]interface{}) string {
	if bucket := getStringParam(params, "bucket", ""); bucket != "" {
		return bucket
	}
	return c.defaultBucket
}

// Helper functions for parameter extraction
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

func getStringSliceParam(params map[string]interface{}, key string) []string {
	if params == nil {
		return nil
	}
	switch v := params[key].(type) {
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// Verify S3Connector implements base.Connector
var _ base.Connector = (*S3Connector)(nil)
