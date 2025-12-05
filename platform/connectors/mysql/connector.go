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

package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL driver

	"axonflow/platform/connectors/base"
)

const (
	// DefaultMaxOpenConns is the default maximum number of open connections
	DefaultMaxOpenConns = 25
	// DefaultMaxIdleConns is the default maximum number of idle connections
	DefaultMaxIdleConns = 5
	// DefaultConnMaxLifetime is the default maximum connection lifetime
	DefaultConnMaxLifetime = 5 * time.Minute
	// DefaultConnMaxIdleTime is the default maximum idle time for connections
	DefaultConnMaxIdleTime = 5 * time.Minute
	// DefaultTimeout is the default query timeout
	DefaultTimeout = 30 * time.Second
)

// namedParamRegex matches named parameters like :name in SQL statements
var namedParamRegex = regexp.MustCompile(`:(\w+)`)

// MySQLConnector implements the MCP Connector interface for MySQL databases.
// It provides connection pooling, parameterized queries, and production-ready
// error handling for MySQL 5.7+ and MySQL 8.0+ databases.
type MySQLConnector struct {
	config *base.ConnectorConfig
	db     *sql.DB
	logger *log.Logger
}

// NewMySQLConnector creates a new MySQL connector instance
func NewMySQLConnector() *MySQLConnector {
	return &MySQLConnector{
		logger: log.New(os.Stdout, "[MCP_MYSQL] ", log.LstdFlags),
	}
}

// Connect establishes a connection to MySQL with connection pooling
func (c *MySQLConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config

	// Build DSN from connection URL or options
	dsn, err := c.buildDSN(config)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to build DSN", err)
	}

	// Open database connection
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to open connection", err)
	}

	// Configure connection pool
	maxOpenConns := DefaultMaxOpenConns
	maxIdleConns := DefaultMaxIdleConns
	connMaxLifetime := DefaultConnMaxLifetime
	connMaxIdleTime := DefaultConnMaxIdleTime

	if val, ok := config.Options["max_open_conns"].(float64); ok {
		maxOpenConns = int(val)
	}
	if val, ok := config.Options["max_idle_conns"].(float64); ok {
		maxIdleConns = int(val)
	}
	if val, ok := config.Options["conn_max_lifetime"].(string); ok {
		if duration, err := time.ParseDuration(val); err == nil {
			connMaxLifetime = duration
		}
	}
	if val, ok := config.Options["conn_max_idle_time"].(string); ok {
		if duration, err := time.ParseDuration(val); err == nil {
			connMaxIdleTime = duration
		}
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)

	// Test connection with context
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return base.NewConnectorError(config.Name, "Connect", "failed to ping database", err)
	}

	c.db = db
	c.logger.Printf("Connected to MySQL: %s (max_open=%d, max_idle=%d)",
		config.Name, maxOpenConns, maxIdleConns)

	return nil
}

// buildDSN constructs MySQL Data Source Name from config
func (c *MySQLConnector) buildDSN(config *base.ConnectorConfig) (string, error) {
	// If ConnectionURL is provided, use it directly (after validation)
	if config.ConnectionURL != "" {
		// Parse and validate the DSN
		return c.validateAndEnhanceDSN(config.ConnectionURL, config)
	}

	// Build DSN from options
	host := "localhost"
	port := 3306
	database := ""

	if h, ok := config.Options["host"].(string); ok {
		host = h
	}
	if p, ok := config.Options["port"].(float64); ok {
		port = int(p)
	}
	if d, ok := config.Options["database"].(string); ok {
		database = d
	}

	username := config.Credentials["username"]
	password := config.Credentials["password"]

	if database == "" {
		return "", fmt.Errorf("database name is required")
	}

	// Build DSN: username:password@tcp(host:port)/database?params
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
		username, password, host, port, database)

	// Add default parameters for production use
	params := []string{
		"parseTime=true",           // Parse TIME/DATE/DATETIME to time.Time
		"loc=UTC",                  // Use UTC timezone
		"charset=utf8mb4",          // Full UTF-8 support
		"collation=utf8mb4_unicode_ci",
		"timeout=10s",              // Connection timeout
		"readTimeout=30s",          // Read timeout
		"writeTimeout=30s",         // Write timeout
		"multiStatements=false",    // Disable multi-statements (SQL injection prevention)
		"interpolateParams=false",  // Use server-side prepared statements
	}

	// TLS configuration
	if tls, ok := config.Options["tls"].(string); ok {
		params = append(params, fmt.Sprintf("tls=%s", tls))
	}

	// Custom parameters from config
	if customParams, ok := config.Options["params"].(map[string]interface{}); ok {
		for key, val := range customParams {
			params = append(params, fmt.Sprintf("%s=%v", key, val))
		}
	}

	dsn += "?" + strings.Join(params, "&")

	return dsn, nil
}

// validateAndEnhanceDSN validates and adds default parameters to a DSN
func (c *MySQLConnector) validateAndEnhanceDSN(dsn string, config *base.ConnectorConfig) (string, error) {
	// Ensure parseTime is enabled for proper time handling
	if !strings.Contains(dsn, "parseTime") {
		if strings.Contains(dsn, "?") {
			dsn += "&parseTime=true"
		} else {
			dsn += "?parseTime=true"
		}
	}

	// Add credentials if not in DSN but provided in config
	if config.Credentials["username"] != "" && !strings.Contains(dsn, "@") {
		username := config.Credentials["username"]
		password := config.Credentials["password"]
		// Insert credentials before the host part
		dsn = fmt.Sprintf("%s:%s@%s", username, password, dsn)
	}

	return dsn, nil
}

// Disconnect closes the database connection pool
func (c *MySQLConnector) Disconnect(ctx context.Context) error {
	if c.db == nil {
		return nil
	}

	if err := c.db.Close(); err != nil {
		return base.NewConnectorError(c.Name(), "Disconnect", "failed to close connection", err)
	}

	c.logger.Printf("Disconnected from MySQL: %s", c.Name())
	return nil
}

// HealthCheck verifies the database connection is healthy
func (c *MySQLConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.db == nil {
		return &base.HealthStatus{
			Healthy:   false,
			Error:     "database not connected",
			Timestamp: time.Now(),
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

	// Get connection pool stats
	stats := c.db.Stats()

	// Get MySQL version
	var version string
	row := c.db.QueryRowContext(ctx, "SELECT VERSION()")
	_ = row.Scan(&version)

	details := map[string]string{
		"open_connections":  strconv.Itoa(stats.OpenConnections),
		"in_use":            strconv.Itoa(stats.InUse),
		"idle":              strconv.Itoa(stats.Idle),
		"wait_count":        strconv.FormatInt(stats.WaitCount, 10),
		"wait_duration":     stats.WaitDuration.String(),
		"max_idle_closed":   strconv.FormatInt(stats.MaxIdleClosed, 10),
		"max_lifetime_closed": strconv.FormatInt(stats.MaxLifetimeClosed, 10),
		"mysql_version":     version,
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes a SELECT query and returns results
func (c *MySQLConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.db == nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "database not connected", nil)
	}

	// Apply timeout
	timeout := query.Timeout
	if timeout == 0 && c.config != nil {
		timeout = c.config.Timeout
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Convert parameters to positional arguments
	// MySQL uses ? placeholders
	stmt, args, err := c.buildArgs(query.Statement, query.Parameters)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to build query parameters", err)
	}

	// Execute query
	start := time.Now()
	rows, err := c.db.QueryContext(queryCtx, stmt, args...)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "query execution failed", err)
	}
	defer func() { _ = rows.Close() }()

	// Get column names and types
	columns, err := rows.Columns()
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to get columns", err)
	}

	columnTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to get column types", err)
	}

	// Scan rows
	results := make([]map[string]interface{}, 0)
	for rows.Next() {
		// Check limit
		if query.Limit > 0 && len(results) >= query.Limit {
			break
		}

		// Create slice for scanning with proper types
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		// Scan row
		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, base.NewConnectorError(c.Name(), "Query", "failed to scan row", err)
		}

		// Build result map with proper type conversion
		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = c.convertValue(values[i], columnTypes[i])
		}
		results = append(results, row)
	}

	// Check for errors during iteration
	if err := rows.Err(); err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "error during row iteration", err)
	}

	duration := time.Since(start)

	c.logger.Printf("Query executed: %d rows in %v", len(results), duration)

	return &base.QueryResult{
		Rows:      results,
		RowCount:  len(results),
		Duration:  duration,
		Cached:    false,
		Connector: c.Name(),
	}, nil
}

// Execute runs INSERT, UPDATE, DELETE, or other write operations
func (c *MySQLConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.db == nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "database not connected", nil)
	}

	// Apply timeout
	timeout := cmd.Timeout
	if timeout == 0 && c.config != nil {
		timeout = c.config.Timeout
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Convert parameters
	stmt, args, err := c.buildArgs(cmd.Statement, cmd.Parameters)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "failed to build command parameters", err)
	}

	// Execute command
	start := time.Now()
	result, err := c.db.ExecContext(execCtx, stmt, args...)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Execute", "command execution failed", err)
	}

	duration := time.Since(start)

	// Get rows affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		c.logger.Printf("Warning: Could not get rows affected: %v", err)
		rowsAffected = 0
	}

	// Get last insert ID for INSERT operations
	var message string
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(cmd.Statement)), "INSERT") {
		lastID, err := result.LastInsertId()
		if err == nil && lastID > 0 {
			message = fmt.Sprintf("%s executed successfully (last_insert_id=%d)", cmd.Action, lastID)
		} else {
			message = fmt.Sprintf("%s executed successfully", cmd.Action)
		}
	} else {
		message = fmt.Sprintf("%s executed successfully", cmd.Action)
	}

	c.logger.Printf("Command executed: %d rows affected in %v", rowsAffected, duration)

	return &base.CommandResult{
		Success:      true,
		RowsAffected: int(rowsAffected),
		Duration:     duration,
		Message:      message,
		Connector:    c.Name(),
	}, nil
}

// Name returns the connector name
func (c *MySQLConnector) Name() string {
	if c.config == nil {
		return "mysql"
	}
	return c.config.Name
}

// Type returns the connector type
func (c *MySQLConnector) Type() string {
	return "mysql"
}

// Version returns the connector version
func (c *MySQLConnector) Version() string {
	return "1.0.0"
}

// Capabilities returns the list of supported capabilities
func (c *MySQLConnector) Capabilities() []string {
	return []string{
		"query",
		"execute",
		"transactions",
		"prepared_statements",
		"connection_pooling",
		"last_insert_id",
	}
}

// buildArgs converts parameter map to positional argument slice for MySQL
// Supports both named parameters (:name) and positional (?)
// Returns the modified statement (with :name replaced by ?) and the args slice
func (c *MySQLConnector) buildArgs(statement string, params map[string]interface{}) (string, []interface{}, error) {
	if len(params) == 0 {
		return statement, nil, nil
	}

	// Check if statement uses named parameters (:name)
	matches := namedParamRegex.FindAllStringSubmatch(statement, -1)

	if len(matches) > 0 {
		// Named parameters - extract values in order they appear and replace with ?
		args := make([]interface{}, 0, len(matches))
		for _, match := range matches {
			paramName := match[1]
			if val, ok := params[paramName]; ok {
				args = append(args, val)
			} else {
				return "", nil, fmt.Errorf("missing parameter: %s", paramName)
			}
		}
		// Replace all :name with ? for MySQL
		modifiedStatement := namedParamRegex.ReplaceAllString(statement, "?")
		return modifiedStatement, args, nil
	}

	// Positional parameters (?) - use ordered keys or indexed parameters
	// Try to use numeric keys first (0, 1, 2, etc.)
	args := make([]interface{}, 0, len(params))

	// Check for numeric keys
	numericKeys := true
	for key := range params {
		if _, err := strconv.Atoi(key); err != nil {
			numericKeys = false
			break
		}
	}

	if numericKeys {
		// Sort by numeric key
		keys := make([]int, 0, len(params))
		for key := range params {
			k, _ := strconv.Atoi(key)
			keys = append(keys, k)
		}
		sort.Ints(keys)

		for _, k := range keys {
			args = append(args, params[strconv.Itoa(k)])
		}
	} else {
		// Use alphabetical order as fallback
		keys := make([]string, 0, len(params))
		for key := range params {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			args = append(args, params[key])
		}
	}

	return statement, args, nil
}

// convertValue converts database values to appropriate Go types
func (c *MySQLConnector) convertValue(val interface{}, colType *sql.ColumnType) interface{} {
	if val == nil {
		return nil
	}

	switch v := val.(type) {
	case []byte:
		// Convert []byte to string for text types
		typeName := strings.ToUpper(colType.DatabaseTypeName())
		switch {
		case strings.Contains(typeName, "CHAR"),
			strings.Contains(typeName, "TEXT"),
			strings.Contains(typeName, "ENUM"),
			strings.Contains(typeName, "SET"),
			typeName == "JSON":
			return string(v)
		case strings.Contains(typeName, "DECIMAL"),
			strings.Contains(typeName, "NUMERIC"):
			// Keep decimal as string to preserve precision
			return string(v)
		default:
			// For BLOB and other binary types, keep as []byte
			return v
		}
	case time.Time:
		return v
	case int64:
		return v
	case float64:
		return v
	case bool:
		return v
	default:
		return v
	}
}

// Transaction support methods

// BeginTx starts a new transaction
func (c *MySQLConnector) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	if c.db == nil {
		return nil, base.NewConnectorError(c.Name(), "BeginTx", "database not connected", nil)
	}
	return c.db.BeginTx(ctx, opts)
}

// Prepare creates a prepared statement for later queries or executions
func (c *MySQLConnector) Prepare(ctx context.Context, query string) (*sql.Stmt, error) {
	if c.db == nil {
		return nil, base.NewConnectorError(c.Name(), "Prepare", "database not connected", nil)
	}
	return c.db.PrepareContext(ctx, query)
}
