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

package cassandra

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gocql/gocql" // Cassandra/Scylla driver

	"axonflow/platform/connectors/base"
)

// CassandraConnector implements the MCP Connector interface for Apache Cassandra / ScyllaDB
type CassandraConnector struct {
	config  *base.ConnectorConfig
	cluster *gocql.ClusterConfig
	session *gocql.Session
	logger  *log.Logger
}

// NewCassandraConnector creates a new Cassandra connector instance
func NewCassandraConnector() *CassandraConnector {
	return &CassandraConnector{
		logger: log.New(os.Stdout, "[MCP_CASSANDRA] ", log.LstdFlags),
	}
}

// Connect establishes a connection to Cassandra cluster
func (c *CassandraConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config

	// Parse connection URL (format: cassandra://host1,host2:port/keyspace)
	hosts, keyspace, err := parseConnectionURL(config.ConnectionURL)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "invalid connection URL", err)
	}

	// Create cluster configuration
	cluster := gocql.NewCluster(hosts...)
	cluster.Keyspace = keyspace

	// Set consistency level
	consistency := "QUORUM"
	if val, ok := config.Options["consistency"].(string); ok {
		consistency = val
	}
	cluster.Consistency = parseConsistency(consistency)

	// Set timeout
	if config.Timeout > 0 {
		cluster.Timeout = config.Timeout
	} else {
		cluster.Timeout = 5 * time.Second
	}

	// Set credentials if provided
	if username, ok := config.Credentials["username"]; ok {
		if password, ok := config.Credentials["password"]; ok {
			cluster.Authenticator = gocql.PasswordAuthenticator{
				Username: username,
				Password: password,
			}
		}
	}

	// Connection pool settings
	cluster.NumConns = 2
	if val, ok := config.Options["num_conns"].(int); ok {
		cluster.NumConns = val
	}

	// Create session
	session, err := cluster.CreateSession()
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to create session", err)
	}

	c.cluster = cluster
	c.session = session
	c.logger.Printf("Connected to Cassandra: %s (keyspace=%s, consistency=%s)", config.Name, keyspace, consistency)

	return nil
}

// Disconnect closes the Cassandra session
func (c *CassandraConnector) Disconnect(ctx context.Context) error {
	if c.session == nil {
		return nil
	}

	c.session.Close()
	c.logger.Printf("Disconnected from Cassandra: %s", c.config.Name)

	return nil
}

// HealthCheck verifies the Cassandra connection is healthy
func (c *CassandraConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.session == nil {
		return &base.HealthStatus{
			Healthy: false,
			Error:   "session not connected",
		}, nil
	}

	// Execute simple query to test connection
	start := time.Now()
	var releaseVersion string
	err := c.session.Query("SELECT release_version FROM system.local").Scan(&releaseVersion)
	latency := time.Since(start)

	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Latency:   latency,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}

	details := map[string]string{
		"release_version": releaseVersion,
		"keyspace":        c.cluster.Keyspace,
		"consistency":     c.cluster.Consistency.String(),
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes a CQL SELECT query and returns results
func (c *CassandraConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.session == nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "session not connected", nil)
	}

	// Build CQL query with parameters
	cqlQuery := c.session.Query(query.Statement)

	// Bind parameters (CQL uses positional parameters)
	if len(query.Parameters) > 0 {
		args := make([]interface{}, 0, len(query.Parameters))
		for _, v := range query.Parameters {
			args = append(args, v)
		}
		cqlQuery = cqlQuery.Bind(args...)
	}

	// Apply timeout (currently unused, context handles timeout)
	_ = query.Timeout // TODO: Apply timeout to query if needed
	cqlQuery = cqlQuery.WithContext(ctx)

	// Set consistency level if specified
	if consistency, ok := query.Parameters["_consistency"].(string); ok {
		cqlQuery = cqlQuery.Consistency(parseConsistency(consistency))
	}

	// Execute query
	start := time.Now()
	iter := cqlQuery.Iter()

	// Get column names
	columns := iter.Columns()
	columnNames := make([]string, len(columns))
	for i, col := range columns {
		columnNames[i] = col.Name
	}

	// Scan results
	results := make([]map[string]interface{}, 0)
	for query.Limit == 0 || len(results) < query.Limit {
		// Scan next row
		row := make(map[string]interface{})
		if !iter.MapScan(row) {
			break
		}

		results = append(results, row)
	}

	// Check for errors
	if err := iter.Close(); err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "query execution failed", err)
	}

	duration := time.Since(start)

	c.logger.Printf("CQL Query executed: %d rows in %v", len(results), duration)

	return &base.QueryResult{
		Rows:      results,
		RowCount:  len(results),
		Duration:  duration,
		Cached:    false,
		Connector: c.config.Name,
	}, nil
}

// Execute runs INSERT, UPDATE, DELETE, or other write operations
func (c *CassandraConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.session == nil {
		return nil, base.NewConnectorError(c.config.Name, "Execute", "session not connected", nil)
	}

	// Build CQL command
	cqlCmd := c.session.Query(cmd.Statement)

	// Bind parameters
	if len(cmd.Parameters) > 0 {
		args := make([]interface{}, 0, len(cmd.Parameters))
		for _, v := range cmd.Parameters {
			args = append(args, v)
		}
		cqlCmd = cqlCmd.Bind(args...)
	}

	// Apply timeout (currently unused, context handles timeout)
	_ = cmd.Timeout // TODO: Apply timeout to command if needed
	cqlCmd = cqlCmd.WithContext(ctx)

	// Execute command
	start := time.Now()
	err := cqlCmd.Exec()
	duration := time.Since(start)

	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Execute", "command execution failed", err)
	}

	c.logger.Printf("CQL Command executed in %v", duration)

	return &base.CommandResult{
		Success:      true,
		RowsAffected: 1, // Cassandra doesn't return affected rows
		Duration:     duration,
		Message:      fmt.Sprintf("%s executed successfully", cmd.Action),
		Connector:    c.config.Name,
	}, nil
}

// Name returns the connector name
func (c *CassandraConnector) Name() string {
	if c.config == nil {
		return "cassandra"
	}
	return c.config.Name
}

// Type returns the connector type
func (c *CassandraConnector) Type() string {
	return "cassandra"
}

// Version returns the connector version
func (c *CassandraConnector) Version() string {
	return "1.0.0"
}

// Capabilities returns the list of supported capabilities
func (c *CassandraConnector) Capabilities() []string {
	return []string{
		"query",
		"execute",
		"batch_operations",
		"consistency_levels",
		"token_aware_routing",
	}
}

// parseConnectionURL parses Cassandra connection URL
// Format: cassandra://host1:port,host2:port/keyspace
// Example: cassandra://10.0.1.50:9042,10.0.1.51:9042/bookings
func parseConnectionURL(url string) ([]string, string, error) {
	// Remove scheme
	url = strings.TrimPrefix(url, "cassandra://")

	// Split hosts and keyspace
	parts := strings.Split(url, "/")
	if len(parts) != 2 {
		return nil, "", fmt.Errorf("invalid connection URL format (expected: cassandra://host:port/keyspace)")
	}

	// Parse hosts
	hosts := strings.Split(parts[0], ",")
	keyspace := parts[1]

	if len(hosts) == 0 || keyspace == "" {
		return nil, "", fmt.Errorf("invalid connection URL: missing hosts or keyspace")
	}

	return hosts, keyspace, nil
}

// parseConsistency converts string to gocql.Consistency
func parseConsistency(level string) gocql.Consistency {
	switch strings.ToUpper(level) {
	case "ANY":
		return gocql.Any
	case "ONE":
		return gocql.One
	case "TWO":
		return gocql.Two
	case "THREE":
		return gocql.Three
	case "QUORUM":
		return gocql.Quorum
	case "ALL":
		return gocql.All
	case "LOCAL_QUORUM":
		return gocql.LocalQuorum
	case "EACH_QUORUM":
		return gocql.EachQuorum
	case "LOCAL_ONE":
		return gocql.LocalOne
	default:
		return gocql.Quorum // Default to QUORUM
	}
}
