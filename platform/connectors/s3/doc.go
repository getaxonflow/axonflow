// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0

/*
Package s3 provides an Amazon S3 connector for the AxonFlow MCP (Model Context Protocol) system.

# Overview

The S3 connector enables AI agents to interact with Amazon S3 and S3-compatible storage
services. It supports listing buckets and objects, reading and writing object content,
and generating presigned URLs for secure, time-limited access.

# Supported Storage Services

  - Amazon S3
  - MinIO (self-hosted)
  - DigitalOcean Spaces
  - Cloudflare R2
  - Any S3-compatible service

# Authentication

The connector supports multiple authentication methods:

  - AWS Access Keys (access_key_id + secret_access_key)
  - IAM Roles (when running on AWS infrastructure)
  - Session Tokens (for temporary credentials)

# Configuration

Required credentials:

  - access_key_id: AWS access key (optional if using IAM roles)
  - secret_access_key: AWS secret key (optional if using IAM roles)

Optional configuration:

  - region: AWS region (default: us-east-1)
  - endpoint: Custom endpoint URL for S3-compatible services
  - force_path_style: Use path-style URLs (required for some S3-compatible services)
  - default_bucket: Default bucket for operations

# Query Operations

The connector supports the following query operations:

  - list_buckets: List all accessible buckets
  - list_objects: List objects in a bucket with optional prefix filtering
  - get_object: Retrieve object content
  - head_object: Get object metadata without content
  - presign_get: Generate a presigned URL for downloading
  - presign_put: Generate a presigned URL for uploading

# Execute Operations

The connector supports the following write operations:

  - put_object: Upload object content
  - delete_object: Delete a single object
  - delete_objects: Delete multiple objects
  - copy_object: Copy object within or between buckets

# Usage Example

	conn := s3.NewS3Connector()
	err := conn.Connect(ctx, &base.ConnectorConfig{
		Name: "my-s3",
		Credentials: map[string]string{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
		Options: map[string]interface{}{
			"region":         "us-west-2",
			"default_bucket": "my-bucket",
		},
	})

	// List objects
	result, err := conn.Query(ctx, &base.Query{
		Statement: "list_objects",
		Parameters: map[string]interface{}{
			"prefix": "data/",
			"limit":  100,
		},
	})

# Thread Safety

The S3Connector is safe for concurrent use by multiple goroutines.

# Metrics

The connector records the following metrics:

  - s3_queries_total: Total number of query operations
  - s3_executes_total: Total number of execute operations
  - s3_query_duration_seconds: Query operation latency
  - s3_execute_duration_seconds: Execute operation latency
  - s3_errors_total: Total number of errors by operation type
*/
package s3
