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

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"

	"axonflow/platform/connectors/base"
)

// RedisConnector implements the MCP Connector interface for Redis
type RedisConnector struct {
	config *base.ConnectorConfig
	client *redis.Client
	logger *log.Logger
}

// NewRedisConnector creates a new Redis connector instance
func NewRedisConnector() *RedisConnector {
	return &RedisConnector{
		logger: log.New(os.Stdout, "[MCP_REDIS] ", log.LstdFlags),
	}
}

// Connect establishes a connection to Redis
func (c *RedisConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config

	// Parse Redis connection options
	host := config.Options["host"].(string)
	port := 6379
	if p, ok := config.Options["port"].(float64); ok {
		port = int(p)
	}
	password := ""
	if pw, ok := config.Credentials["password"]; ok {
		password = pw
	}
	db := 0
	if d, ok := config.Options["db"].(float64); ok {
		db = int(d)
	}

	// Create Redis client
	c.client = redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		Password:     password,
		DB:           db,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     100,
		MinIdleConns: 10,
	})

	// Test connection
	if err := c.client.Ping(ctx).Err(); err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to ping Redis", err)
	}

	c.logger.Printf("Connected to Redis: %s (db=%d, pool_size=100)", config.Name, db)

	return nil
}

// Disconnect closes the Redis connection
func (c *RedisConnector) Disconnect(ctx context.Context) error {
	if c.client == nil {
		return nil
	}

	if err := c.client.Close(); err != nil {
		return base.NewConnectorError(c.config.Name, "Disconnect", "failed to close connection", err)
	}

	c.logger.Printf("Disconnected from Redis: %s", c.config.Name)
	return nil
}

// HealthCheck verifies the Redis connection is healthy
func (c *RedisConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.client == nil {
		return &base.HealthStatus{
			Healthy: false,
			Error:   "client not connected",
		}, nil
	}

	start := time.Now()
	err := c.client.Ping(ctx).Err()
	latency := time.Since(start)

	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Latency:   latency,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}

	// Get Redis info
	_ = c.client.Info(ctx, "stats").Val() // Get stats (unused for now)
	dbSize := c.client.DBSize(ctx).Val()

	details := map[string]string{
		"db_size":    fmt.Sprintf("%d", dbSize),
		"connected":  "true",
		"pool_stats": fmt.Sprintf("%+v", c.client.PoolStats()),
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes a read operation (GET, EXISTS, TTL, KEYS)
func (c *RedisConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "client not connected", nil)
	}

	operation := query.Statement
	start := time.Now()
	var rows []map[string]interface{}
	var err error

	switch operation {
	case "GET":
		rows, err = c.get(ctx, query.Parameters)
	case "EXISTS":
		rows, err = c.exists(ctx, query.Parameters)
	case "TTL":
		rows, err = c.ttl(ctx, query.Parameters)
	case "KEYS":
		rows, err = c.keys(ctx, query.Parameters)
	case "STATS":
		rows, err = c.stats(ctx)
	default:
		return nil, base.NewConnectorError(c.config.Name, "Query",
			fmt.Sprintf("unsupported operation: %s", operation), nil)
	}

	duration := time.Since(start)

	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "query execution failed", err)
	}

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  duration,
		Cached:    false,
		Connector: c.config.Name,
	}, nil
}

// Execute executes a write operation (SET, DELETE, EXPIRE)
func (c *RedisConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.config.Name, "Execute", "client not connected", nil)
	}

	action := cmd.Action
	start := time.Now()
	var rowsAffected int
	var err error
	var message string

	switch action {
	case "SET":
		rowsAffected, message, err = c.set(ctx, cmd.Parameters)
	case "DELETE":
		rowsAffected, message, err = c.delete(ctx, cmd.Parameters)
	case "EXPIRE":
		rowsAffected, message, err = c.expire(ctx, cmd.Parameters)
	default:
		return nil, base.NewConnectorError(c.config.Name, "Execute",
			fmt.Sprintf("unsupported action: %s", action), nil)
	}

	duration := time.Since(start)

	if err != nil {
		return &base.CommandResult{
			Success:      false,
			RowsAffected: 0,
			Duration:     duration,
			Message:      err.Error(),
			Connector:    c.config.Name,
		}, nil
	}

	return &base.CommandResult{
		Success:      true,
		RowsAffected: rowsAffected,
		Duration:     duration,
		Message:      message,
		Connector:    c.config.Name,
	}, nil
}

// Name returns the connector instance name
func (c *RedisConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "redis-connector"
}

// Type returns the connector type
func (c *RedisConnector) Type() string {
	return "redis"
}

// Version returns the connector version
func (c *RedisConnector) Version() string {
	return "0.2.0"
}

// Capabilities returns the list of connector capabilities
func (c *RedisConnector) Capabilities() []string {
	return []string{"query", "execute", "cache", "kv-store"}
}

// get retrieves a value from Redis
func (c *RedisConnector) get(ctx context.Context, params map[string]interface{}) ([]map[string]interface{}, error) {
	key, ok := params["key"].(string)
	if !ok {
		return nil, fmt.Errorf("key parameter required")
	}

	val, err := c.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return []map[string]interface{}{
			{"key": key, "exists": false, "value": nil},
		}, nil
	}
	if err != nil {
		return nil, err
	}

	ttl, _ := c.client.TTL(ctx, key).Result()

	return []map[string]interface{}{
		{
			"key":    key,
			"exists": true,
			"value":  val,
			"ttl":    int(ttl.Seconds()),
		},
	}, nil
}

// exists checks if a key exists
func (c *RedisConnector) exists(ctx context.Context, params map[string]interface{}) ([]map[string]interface{}, error) {
	key, ok := params["key"].(string)
	if !ok {
		return nil, fmt.Errorf("key parameter required")
	}

	count, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	return []map[string]interface{}{
		{"key": key, "exists": count > 0},
	}, nil
}

// ttl gets the TTL of a key
func (c *RedisConnector) ttl(ctx context.Context, params map[string]interface{}) ([]map[string]interface{}, error) {
	key, ok := params["key"].(string)
	if !ok {
		return nil, fmt.Errorf("key parameter required")
	}

	ttl, err := c.client.TTL(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	return []map[string]interface{}{
		{"key": key, "ttl": int(ttl.Seconds())},
	}, nil
}

// keys lists keys matching a pattern
func (c *RedisConnector) keys(ctx context.Context, params map[string]interface{}) ([]map[string]interface{}, error) {
	pattern := "*"
	if p, ok := params["pattern"].(string); ok {
		pattern = p
	}

	limit := 100
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
	}

	var cursor uint64
	var keys []string
	for len(keys) < limit {
		var batch []string
		var err error
		batch, cursor, err = c.client.Scan(ctx, cursor, pattern, 10).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		if cursor == 0 {
			break
		}
	}

	if len(keys) > limit {
		keys = keys[:limit]
	}

	rows := make([]map[string]interface{}, len(keys))
	for i, key := range keys {
		rows[i] = map[string]interface{}{"key": key}
	}

	return rows, nil
}

// stats returns cache statistics
func (c *RedisConnector) stats(ctx context.Context) ([]map[string]interface{}, error) {
	info, err := c.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, err
	}

	dbSize, _ := c.client.DBSize(ctx).Result()
	poolStats := c.client.PoolStats()

	return []map[string]interface{}{
		{
			"db_size":         dbSize,
			"pool_hits":       poolStats.Hits,
			"pool_misses":     poolStats.Misses,
			"pool_timeouts":   poolStats.Timeouts,
			"pool_total_conn": poolStats.TotalConns,
			"pool_idle_conn":  poolStats.IdleConns,
			"info":            info,
		},
	}, nil
}

// set stores a value in Redis
func (c *RedisConnector) set(ctx context.Context, params map[string]interface{}) (int, string, error) {
	key, ok := params["key"].(string)
	if !ok {
		return 0, "", fmt.Errorf("key parameter required")
	}

	value, ok := params["value"]
	if !ok {
		return 0, "", fmt.Errorf("value parameter required")
	}

	// Convert value to string if needed
	var valueStr string
	switch v := value.(type) {
	case string:
		valueStr = v
	case []byte:
		valueStr = string(v)
	default:
		// Marshal to JSON for complex types
		b, err := json.Marshal(v)
		if err != nil {
			return 0, "", err
		}
		valueStr = string(b)
	}

	ttl := time.Duration(0)
	if ttlVal, ok := params["ttl"]; ok {
		switch t := ttlVal.(type) {
		case float64:
			ttl = time.Duration(int(t)) * time.Second
		case int:
			ttl = time.Duration(t) * time.Second
		case string:
			parsed, err := time.ParseDuration(t)
			if err == nil {
				ttl = parsed
			}
		}
	}

	err := c.client.Set(ctx, key, valueStr, ttl).Err()
	if err != nil {
		return 0, "", err
	}

	return 1, fmt.Sprintf("SET %s (ttl=%v)", key, ttl), nil
}

// delete removes a key from Redis
func (c *RedisConnector) delete(ctx context.Context, params map[string]interface{}) (int, string, error) {
	key, ok := params["key"].(string)
	if !ok {
		return 0, "", fmt.Errorf("key parameter required")
	}

	count, err := c.client.Del(ctx, key).Result()
	if err != nil {
		return 0, "", err
	}

	return int(count), fmt.Sprintf("DELETE %s", key), nil
}

// expire sets TTL on a key
func (c *RedisConnector) expire(ctx context.Context, params map[string]interface{}) (int, string, error) {
	key, ok := params["key"].(string)
	if !ok {
		return 0, "", fmt.Errorf("key parameter required")
	}

	ttl := time.Duration(0)
	if ttlVal, ok := params["ttl"]; ok {
		switch t := ttlVal.(type) {
		case float64:
			ttl = time.Duration(int(t)) * time.Second
		case int:
			ttl = time.Duration(t) * time.Second
		case string:
			parsed, err := strconv.Atoi(t)
			if err == nil {
				ttl = time.Duration(parsed) * time.Second
			}
		}
	}

	if ttl == 0 {
		return 0, "", fmt.Errorf("ttl parameter required")
	}

	success, err := c.client.Expire(ctx, key, ttl).Result()
	if err != nil {
		return 0, "", err
	}

	rowsAffected := 0
	if success {
		rowsAffected = 1
	}

	return rowsAffected, fmt.Sprintf("EXPIRE %s %v", key, ttl), nil
}
