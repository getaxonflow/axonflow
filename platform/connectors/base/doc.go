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

/*
Package base provides the core interfaces and types for MCP (Model Context
Protocol) connectors in AxonFlow.

# Overview

The base package defines the Connector interface that all MCP connectors
must implement. This interface follows the Model Context Protocol pattern
for Resources (read operations) and Tools (write operations).

# Connector Interface

All connectors implement the Connector interface:

	type Connector interface {
	    // Lifecycle
	    Connect(ctx context.Context, config *ConnectorConfig) error
	    Disconnect(ctx context.Context) error
	    HealthCheck(ctx context.Context) (*HealthStatus, error)

	    // Data Operations (MCP Resources)
	    Query(ctx context.Context, query *Query) (*QueryResult, error)

	    // Action Operations (MCP Tools)
	    Execute(ctx context.Context, cmd *Command) (*CommandResult, error)

	    // Metadata
	    Name() string
	    Type() string
	    Version() string
	    Capabilities() []string
	}

# Supported Connector Types

AxonFlow includes connectors for:

  - PostgreSQL - Relational database queries
  - Cassandra - Wide-column NoSQL queries
  - Redis - Key-value operations
  - HTTP API - REST API integrations
  - Salesforce - CRM data access
  - Slack - Messaging operations
  - Amadeus - Travel API integration
  - Snowflake - Data warehouse queries

# Query Operations

Query operations follow the MCP Resources pattern (read-only):

	query := &Query{
	    Statement:  "SELECT * FROM users WHERE department = $1",
	    Parameters: map[string]interface{}{"1": "engineering"},
	    Timeout:    5 * time.Second,
	    Limit:      100,
	}

	result, err := connector.Query(ctx, query)
	if err != nil {
	    return err
	}

	for _, row := range result.Rows {
	    fmt.Println(row["name"])
	}

Note: Parameters are passed positionally to the database driver. Map keys
are for documentation purposes; values are extracted in iteration order.

# Command Operations

Command operations follow the MCP Tools pattern (write operations):

	cmd := &Command{
	    Action:     "INSERT",
	    Statement:  "INSERT INTO audit_log (event, timestamp) VALUES ($1, $2)",
	    Parameters: map[string]interface{}{"1": "user_login", "2": time.Now()},
	    Timeout:    5 * time.Second,
	}

	result, err := connector.Execute(ctx, cmd)
	if err != nil {
	    return err
	}

	fmt.Printf("Rows affected: %d\n", result.RowsAffected)

# Configuration

Connectors are configured via ConnectorConfig:

	config := &ConnectorConfig{
	    Name:          "main-postgres",
	    Type:          "postgres",
	    ConnectionURL: "postgres://user:pass@host:5432/db",
	    Credentials:   map[string]string{"ssl_mode": "require"},
	    Options:       map[string]interface{}{"max_open_conns": 25},
	    Timeout:       5 * time.Second,
	    MaxRetries:    3,
	    TenantID:      "tenant-123",
	}

# Error Handling

All connector errors are wrapped in ConnectorError for consistent handling:

	err := connector.Query(ctx, query)
	if connErr, ok := err.(*ConnectorError); ok {
	    log.Printf("Connector: %s, Operation: %s, Message: %s",
	        connErr.ConnectorName, connErr.Operation, connErr.Message)
	}

# Thread Safety

All Connector implementations must be safe for concurrent use.
The interface methods can be called from multiple goroutines simultaneously.

# Security Utilities

The base package provides security utilities to protect against common
vulnerabilities in connector implementations:

## SSRF Protection (ValidateURL)

Use ValidateURL to protect against Server-Side Request Forgery attacks:

	opts := URLValidationOptions{
	    AllowPrivateIPs:     false, // Block private/internal IPs
	    AllowedSchemes:      []string{"https"},
	    AllowedHostSuffixes: []string{".salesforce.com", ".service-now.com"},
	}

	if err := ValidateURL(userProvidedURL, opts); err != nil {
	    return fmt.Errorf("invalid URL: %w", err)
	}

The function validates:
  - URL scheme (default: https, http)
  - Hostname is not blocked
  - Hostname matches allowed list/suffixes (if specified)
  - Resolved IP addresses are not private (unless AllowPrivateIPs=true)

## allow_private_ips Configuration Option

For connectors that support self-hosted deployments (Jira Server, GitLab
self-hosted, etc.), the `allow_private_ips` option enables connections to
internal network addresses:

	config := &ConnectorConfig{
	    Name: "jira-server",
	    Type: "jira",
	    Options: map[string]interface{}{
	        "base_url":          "https://jira.internal.company.com",
	        "allow_private_ips": true, // Required for self-hosted
	    },
	}

Security Warning: Only enable allow_private_ips when connecting to
trusted internal services. This disables SSRF protection and allows
the connector to make requests to internal network addresses.

## Path Traversal Protection (ValidateFilePath)

Use ValidateFilePath to protect against path traversal attacks:

	if err := ValidateFilePath(userProvidedPath); err != nil {
	    return fmt.Errorf("invalid path: %w", err)
	}

	data, err := os.ReadFile(userProvidedPath)

## Log Injection Protection (SanitizeLogString)

Use SanitizeLogString to prevent log injection attacks:

	log.Printf("User input: %s", SanitizeLogString(userInput))

## SQL Identifier Validation (ValidateSQLIdentifier)

Use ValidateSQLIdentifier for dynamic column/table names:

	if err := ValidateSQLIdentifier(columnName); err != nil {
	    return fmt.Errorf("invalid column: %w", err)
	}

	// Safe to use in query (still prefer prepared statements for values)
	query := fmt.Sprintf("SELECT %s FROM users", columnName)
*/
package base
