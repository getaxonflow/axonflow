// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0

/*
Package azureblob provides an Azure Blob Storage connector for the AxonFlow MCP
(Model Context Protocol) system.

# Overview

The Azure Blob connector enables AI agents to interact with Azure Blob Storage and
Azure Data Lake Storage Gen2. It supports listing containers and blobs, reading
and writing blob content, and generating SAS (Shared Access Signature) URLs.

# Supported Services

  - Azure Blob Storage
  - Azure Data Lake Storage Gen2 (ADLS Gen2)
  - Azurite (local emulator)

# Authentication

The connector supports multiple authentication methods:

  - Account Key: Storage account name + access key
  - Connection String: Full Azure storage connection string
  - Managed Identity: Azure AD authentication for VMs/containers
  - SAS Token: Time-limited shared access signatures

# Configuration

Required configuration:

  - account_name: Azure storage account name

Credentials (choose one method):

  - account_key: Storage account access key
  - connection_string: Azure storage connection string
  - use_managed_identity: Set to true for Azure AD auth

Optional configuration:

  - default_container: Default container for operations
  - sas_expiry: Default SAS URL expiry in seconds (default: 3600)

# Query Operations

The connector supports the following query operations:

  - list_containers: List all containers in the storage account
  - list_blobs: List blobs in a container with optional prefix filtering
  - get_blob: Download blob content
  - get_blob_properties: Get blob metadata without content
  - generate_sas: Generate a SAS URL for blob access

# Execute Operations

The connector supports the following write operations:

  - upload_blob: Upload blob content
  - delete_blob: Delete a single blob
  - delete_container: Delete an empty container
  - copy_blob: Copy blob within or between containers
  - set_blob_metadata: Update blob metadata

# Usage Example

	conn := azureblob.NewAzureBlobConnector()
	err := conn.Connect(ctx, &base.ConnectorConfig{
		Name: "my-azure-storage",
		Credentials: map[string]string{
			"account_key": "your-account-key",
		},
		Options: map[string]interface{}{
			"account_name":      "mystorageaccount",
			"default_container": "my-container",
		},
	})

	// List blobs
	result, err := conn.Query(ctx, &base.Query{
		Statement: "list_blobs",
		Parameters: map[string]interface{}{
			"prefix": "data/",
			"limit":  100,
		},
	})

# ADLS Gen2 Support

For Azure Data Lake Storage Gen2, the connector automatically handles hierarchical
namespace operations. Use the same API but with path-based addressing:

	result, err := conn.Query(ctx, &base.Query{
		Statement: "list_blobs",
		Parameters: map[string]interface{}{
			"prefix": "folder1/subfolder/",
		},
	})

# Thread Safety

The AzureBlobConnector is safe for concurrent use by multiple goroutines.

# Metrics

The connector records the following metrics:

  - azureblob_queries_total: Total number of query operations
  - azureblob_executes_total: Total number of execute operations
  - azureblob_query_duration_seconds: Query operation latency
  - azureblob_execute_duration_seconds: Execute operation latency
  - azureblob_errors_total: Total number of errors by operation type
*/
package azureblob
