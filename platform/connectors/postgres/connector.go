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

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/sdk"
)

// PostgresConnector implements the MCP Connector interface for PostgreSQL
type PostgresConnector struct {
	sdk.BaseConnector
	config *base.ConnectorConfig
	db     *sql.DB
	logger *log.Logger
}

// NewPostgresConnector creates a new PostgreSQL connector instance
func NewPostgresConnector() *PostgresConnector {
	conn := &PostgresConnector{}
	conn.BaseConnector = *sdk.NewBaseConnector("postgres")
	conn.SetVersion("1.0.0")
	conn.SetCapabilities([]string{
		"query",
		"execute",
		"transactions",
		"prepared_statements",
		"connection_pooling",
	})
	conn.SetValidator(sdk.NewDefaultConfigValidator(
		[]string{},
		map[string]interface{}{
			"max_open_conns":    25,
			"max_idle_conns":    5,
			"conn_max_lifetime": "5m",
			"timeout_seconds":   30,
		},
	))
	conn.logger = conn.GetLogger()
	return conn
}

// Connect establishes a connection to PostgreSQL
func (c *PostgresConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	if config == nil {
		return base.NewConnectorError("postgres", "Connect", "config is required", nil)
	}
	c.config = config
	if config.Type == "" {
		config.Type = "postgres"
	}
	if config.ConnectionURL == "" {
		return base.NewConnectorError(config.Name, "Connect", "connection URL is required", nil)
	}
	if err := c.BaseConnector.Connect(ctx, config); err != nil {
		return err
	}

	// Open database connection
	db, err := sql.Open("postgres", config.ConnectionURL)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to open connection", err)
	}

	// Configure connection pool
	maxOpenConns := 25
	maxIdleConns := 5
	connMaxLifetime := 5 * time.Minute

	if val := c.GetIntOption("max_open_conns", maxOpenConns); val > 0 {
		maxOpenConns = val
	}
	if val := c.GetIntOption("max_idle_conns", maxIdleConns); val >= 0 {
		maxIdleConns = val
	}
	if val := c.GetStringOption("conn_max_lifetime", ""); val != "" {
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
	c.GetMetrics().RecordConnect()
	c.Log("Connected to PostgreSQL: %s (max_conns=%d)", config.Name, maxOpenConns)

	return nil
}

// Disconnect closes the database connection
func (c *PostgresConnector) Disconnect(ctx context.Context) error {
	if c.db == nil {
		return nil
	}

	if err := c.db.Close(); err != nil {
		return base.NewConnectorError(c.Name(), "Disconnect", "failed to close connection", err)
	}

	c.GetMetrics().RecordDisconnect()
	c.Log("Disconnected from PostgreSQL: %s", c.Name())
	return c.BaseConnector.Disconnect(ctx)
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
		return nil, base.NewConnectorError(c.Name(), "Query", "database not connected", nil)
	}

	// Apply timeout
	timeout := query.Timeout
	if timeout == 0 {
		timeout = c.GetTimeout()
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Convert parameters map to slice for PostgreSQL positional parameters
	args, err := c.buildArgs(query.Parameters)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to build query parameters", err)
	}

	// Execute query
	start := time.Now()
	rows, err := c.db.QueryContext(queryCtx, query.Statement, args...)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "query execution failed", err)
	}
	defer func() { _ = rows.Close() }()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to get columns", err)
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
			return nil, base.NewConnectorError(c.Name(), "Query", "failed to scan row", err)
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
		return nil, base.NewConnectorError(c.Name(), "Query", "error during row iteration", err)
	}

	duration := time.Since(start)

	c.Log("Query executed: %d rows in %v", len(results), duration)

	return &base.QueryResult{
		Rows:      results,
		RowCount:  len(results),
		Duration:  duration,
		Cached:    false,
		Connector: c.Name(),
	}, nil
}

// Execute runs INSERT, UPDATE, DELETE, or other write operations
func (c *PostgresConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.db == nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "database not connected", nil)
	}

	// Apply timeout
	timeout := cmd.Timeout
	if timeout == 0 {
		timeout = c.GetTimeout()
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Convert parameters
	args, err := c.buildArgs(cmd.Parameters)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to build command parameters", err)
	}

	// Execute command
	start := time.Now()
	result, err := c.db.ExecContext(execCtx, cmd.Statement, args...)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "command execution failed", err)
	}

	duration := time.Since(start)

	// Get rows affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.Log("Warning: Could not get rows affected: %v", err)
		rowsAffected = 0
	}

	c.Log("Command executed: %d rows affected in %v", rowsAffected, duration)

	return &base.CommandResult{
		Success:      true,
		RowsAffected: int(rowsAffected),
		Duration:     duration,
		Message:      fmt.Sprintf("%s executed successfully", cmd.Action),
		Connector:    c.Name(),
	}, nil
}

// Name returns the connector name.
// Preserves legacy behavior used by tests and callers that set c.config directly.
func (c *PostgresConnector) Name() string {
	if c.config == nil {
		return "postgres"
	}
	return c.config.Name
}

// buildArgs converts parameter map to positional argument slice.
// PostgreSQL uses $1, $2, etc. for positional parameters.
// Keys are sorted alphabetically to ensure deterministic ordering,
// since Go map iteration order is non-deterministic.
func (c *PostgresConnector) buildArgs(params map[string]interface{}) ([]interface{}, error) {
	if len(params) == 0 {
		return nil, nil
	}

	// Extract and sort keys for deterministic ordering
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build args slice in sorted key order
	args := make([]interface{}, 0, len(params))
	for _, k := range keys {
		args = append(args, params[k])
	}

	return args, nil
}
