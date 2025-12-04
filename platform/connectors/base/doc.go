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
*/
package base
