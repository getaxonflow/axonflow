// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0

/*
Package gcs provides a Google Cloud Storage connector for the AxonFlow MCP
(Model Context Protocol) system.

# Overview

The GCS connector enables AI agents to interact with Google Cloud Storage.
It supports listing buckets and objects, reading and writing object content,
and generating signed URLs for secure, time-limited access.

# Supported Services

  - Google Cloud Storage
  - GCS Emulator (for local development)

# Authentication

The connector supports multiple authentication methods:

  - Service Account: JSON key file or inline JSON credentials
  - Application Default Credentials (ADC): Automatic credential discovery
  - Workload Identity: For GKE workloads

# Configuration

Optional credentials:

  - credentials_file: Path to service account JSON key file
  - credentials_json: Inline service account JSON credentials

Optional configuration:

  - project_id: GCP project ID (required for listing buckets)
  - default_bucket: Default bucket for operations
  - endpoint: Custom endpoint URL (for emulator)
  - signed_url_expiry: Default signed URL expiry in seconds (default: 900)

# Query Operations

The connector supports the following query operations:

  - list_buckets: List all buckets in the project
  - list_objects: List objects in a bucket with optional prefix filtering
  - get_object: Download object content
  - get_object_attrs: Get object metadata without content
  - generate_signed_url: Generate a signed URL for object access

# Execute Operations

The connector supports the following write operations:

  - upload_object: Upload object content
  - delete_object: Delete a single object
  - copy_object: Copy object within or between buckets
  - update_metadata: Update object metadata

# Usage Example

	conn := gcs.NewGCSConnector()
	err := conn.Connect(ctx, &base.ConnectorConfig{
		Name: "my-gcs",
		Credentials: map[string]string{
			"credentials_file": "/path/to/service-account.json",
		},
		Options: map[string]interface{}{
			"project_id":     "my-gcp-project",
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

# Using Application Default Credentials

When running on Google Cloud infrastructure (GCE, GKE, Cloud Run), the connector
can use Application Default Credentials automatically:

	conn := gcs.NewGCSConnector()
	err := conn.Connect(ctx, &base.ConnectorConfig{
		Name: "my-gcs",
		Options: map[string]interface{}{
			"project_id":     "my-gcp-project",
			"default_bucket": "my-bucket",
		},
	})

# Local Development with Emulator

For local development, you can use the GCS emulator:

	conn := gcs.NewGCSConnector()
	err := conn.Connect(ctx, &base.ConnectorConfig{
		Name: "local-gcs",
		Options: map[string]interface{}{
			"endpoint":       "http://localhost:4443/storage/v1/",
			"project_id":     "test-project",
			"default_bucket": "test-bucket",
		},
	})

# Thread Safety

The GCSConnector is safe for concurrent use by multiple goroutines.

# Metrics

The connector records the following metrics:

  - gcs_queries_total: Total number of query operations
  - gcs_executes_total: Total number of execute operations
  - gcs_query_duration_seconds: Query operation latency
  - gcs_execute_duration_seconds: Execute operation latency
  - gcs_errors_total: Total number of errors by operation type
*/
package gcs
