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

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"axonflow/platform/connectors/base"
)

// PostgresConnector implements the MCP Connector interface for PostgreSQL
type PostgresConnector struct {
	config *base.ConnectorConfig
	db     *sql.DB
	logger *log.Logger
}

// NewPostgresConnector creates a new PostgreSQL connector instance
func NewPostgresConnector() *PostgresConnector {
	return &PostgresConnector{
		logger: log.New(os.Stdout, "[MCP_POSTGRES] ", log.LstdFlags),
	}
}

// Connect establishes a connection to PostgreSQL
func (c *PostgresConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config

	// Open database connection
	db, err := sql.Open("postgres", config.ConnectionURL)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to open connection", err)
	}

	// Configure connection pool
	maxOpenConns := 25
	maxIdleConns := 5
	connMaxLifetime := 5 * time.Minute

	if val, ok := config.Options["max_open_conns"].(int); ok {
		maxOpenConns = val
	}
	if val, ok := config.Options["max_idle_conns"].(int); ok {
		maxIdleConns = val
	}
	if val, ok := config.Options["conn_max_lifetime"].(string); ok {
		if duration, err := time.ParseDuration(val); err == nil {
			connMaxLifetime = duration
		}
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	// Test connection
	if err := db.PingContext(ctx); err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to ping database", err)
	}

	c.db = db
	c.logger.Printf("Connected to PostgreSQL: %s (max_conns=%d)", config.Name, maxOpenConns)

	return nil
}

// Disconnect closes the database connection
func (c *PostgresConnector) Disconnect(ctx context.Context) error {
	if c.db == nil {
		return nil
	}

	if err := c.db.Close(); err != nil {
		return base.NewConnectorError(c.config.Name, "Disconnect", "failed to close connection", err)
	}

	c.logger.Printf("Disconnected from PostgreSQL: %s", c.config.Name)
	return nil
}

// HealthCheck verifies the database connection is healthy
func (c *PostgresConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.db == nil {
		return &base.HealthStatus{
			Healthy: false,
			Error:   "database not connected",
		}, nil
	}

	start := time.Now()
	err := c.db.PingContext(ctx)
	latency := time.Since(start)

	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Latency:   latency,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}

	// Get connection stats
	stats := c.db.Stats()
	details := map[string]string{
		"open_connections": fmt.Sprintf("%d", stats.OpenConnections),
		"in_use":           fmt.Sprintf("%d", stats.InUse),
		"idle":             fmt.Sprintf("%d", stats.Idle),
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes a SELECT query and returns results
func (c *PostgresConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.db == nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "database not connected", nil)
	}

	// Apply timeout
	timeout := query.Timeout
	if timeout == 0 {
		timeout = c.config.Timeout
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Convert parameters map to slice for PostgreSQL positional parameters
	args, err := c.buildArgs(query.Parameters)
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "failed to build query parameters", err)
	}

	// Execute query
	start := time.Now()
	rows, err := c.db.QueryContext(queryCtx, query.Statement, args...)
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "query execution failed", err)
	}
	defer func() { _ = rows.Close() }()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "failed to get columns", err)
	}

	// Scan rows
	results := make([]map[string]interface{}, 0)
	for rows.Next() {
		// Check limit
		if query.Limit > 0 && len(results) >= query.Limit {
			break
		}

		// Create slice for scanning
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan row
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, base.NewConnectorError(c.config.Name, "Query", "failed to scan row", err)
		}

		// Build result map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			// Convert []byte to string for text/varchar fields
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	// Check for errors during iteration
	if err := rows.Err(); err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "error during row iteration", err)
	}

	duration := time.Since(start)

	c.logger.Printf("Query executed: %d rows in %v", len(results), duration)

	return &base.QueryResult{
		Rows:      results,
		RowCount:  len(results),
		Duration:  duration,
		Cached:    false,
		Connector: c.config.Name,
	}, nil
}

// Execute runs INSERT, UPDATE, DELETE, or other write operations
func (c *PostgresConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.db == nil {
		return nil, base.NewConnectorError(c.config.Name, "Execute", "database not connected", nil)
	}

	// Apply timeout
	timeout := cmd.Timeout
	if timeout == 0 {
		timeout = c.config.Timeout
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Convert parameters
	args, err := c.buildArgs(cmd.Parameters)
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Execute", "failed to build command parameters", err)
	}

	// Execute command
	start := time.Now()
	result, err := c.db.ExecContext(execCtx, cmd.Statement, args...)
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Execute", "command execution failed", err)
	}

	duration := time.Since(start)

	// Get rows affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.logger.Printf("Warning: Could not get rows affected: %v", err)
		rowsAffected = 0
	}

	c.logger.Printf("Command executed: %d rows affected in %v", rowsAffected, duration)

	return &base.CommandResult{
		Success:      true,
		RowsAffected: int(rowsAffected),
		Duration:     duration,
		Message:      fmt.Sprintf("%s executed successfully", cmd.Action),
		Connector:    c.config.Name,
	}, nil
}

// Name returns the connector name
func (c *PostgresConnector) Name() string {
	if c.config == nil {
		return "postgres"
	}
	return c.config.Name
}

// Type returns the connector type
func (c *PostgresConnector) Type() string {
	return "postgres"
}

// Version returns the connector version
func (c *PostgresConnector) Version() string {
	return "1.0.0"
}

// Capabilities returns the list of supported capabilities
func (c *PostgresConnector) Capabilities() []string {
	return []string{
		"query",
		"execute",
		"transactions",
		"prepared_statements",
		"connection_pooling",
	}
}

// buildArgs converts parameter map to positional argument slice
// PostgreSQL uses $1, $2, etc. for positional parameters
func (c *PostgresConnector) buildArgs(params map[string]interface{}) ([]interface{}, error) {
	if len(params) == 0 {
		return nil, nil
	}

	// For now, assume parameters are already in correct order
	// In production, this should parse the SQL and match parameter names
	args := make([]interface{}, 0, len(params))
	for _, v := range params {
		args = append(args, v)
	}

	return args, nil
}
