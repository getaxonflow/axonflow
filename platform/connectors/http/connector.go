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

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"axonflow/platform/connectors/base"
)

// HTTPConnector implements the MCP Connector interface for HTTP REST APIs
type HTTPConnector struct {
	config     *base.ConnectorConfig
	httpClient *http.Client
	logger     *log.Logger
	baseURL    string
	authType   string
	authConfig map[string]string
	headers    map[string]string
}

// NewHTTPConnector creates a new HTTP connector instance
func NewHTTPConnector() *HTTPConnector {
	return &HTTPConnector{
		logger: log.New(os.Stdout, "[MCP_HTTP] ", log.LstdFlags),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		headers: make(map[string]string),
	}
}

// Connect initializes the HTTP connector
func (c *HTTPConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config

	// Extract configuration
	if url, ok := config.Options["base_url"].(string); ok {
		c.baseURL = strings.TrimSuffix(url, "/")
	} else {
		return base.NewConnectorError(config.Name, "Connect", "base_url required", nil)
	}

	// Auth type
	if authType, ok := config.Options["auth_type"].(string); ok {
		c.authType = authType
	} else {
		c.authType = "none"
	}

	// Auth credentials
	c.authConfig = make(map[string]string)
	for key, val := range config.Credentials {
		c.authConfig[key] = val
	}

	// Custom headers
	if headers, ok := config.Options["headers"].(map[string]interface{}); ok {
		for key, val := range headers {
			if strVal, ok := val.(string); ok {
				c.headers[key] = strVal
			}
		}
	}

	// Timeout
	if timeout, ok := config.Options["timeout"].(float64); ok {
		c.httpClient.Timeout = time.Duration(int(timeout)) * time.Second
	}

	c.logger.Printf("Connected to HTTP API: %s (auth=%s)", config.Name, c.authType)

	return nil
}

// Disconnect closes the connection (no-op for HTTP)
func (c *HTTPConnector) Disconnect(ctx context.Context) error {
	c.logger.Printf("Disconnected from HTTP API: %s", c.config.Name)
	return nil
}

// HealthCheck verifies the API is accessible
func (c *HTTPConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.baseURL == "" {
		return &base.HealthStatus{
			Healthy: false,
			Error:   "base_url not configured",
		}, nil
	}

	// Try to hit a health endpoint or root
	healthPath := "/"
	if hp, ok := c.config.Options["health_path"].(string); ok {
		healthPath = hp
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+healthPath, nil)
	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}

	c.applyAuth(req)
	c.applyHeaders(req)

	resp, err := c.httpClient.Do(req)
	latency := time.Since(start)

	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Latency:   latency,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	healthy := resp.StatusCode >= 200 && resp.StatusCode < 400

	details := map[string]string{
		"base_url":    c.baseURL,
		"status_code": fmt.Sprintf("%d", resp.StatusCode),
		"auth_type":   c.authType,
	}

	return &base.HealthStatus{
		Healthy:   healthy,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes a GET request (read operation)
func (c *HTTPConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	// query.Statement should be the URL path (e.g., "/api/users")
	path := query.Statement
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	url := c.baseURL + path

	// Add query parameters
	if len(query.Parameters) > 0 {
		queryParams := make([]string, 0)
		for key, val := range query.Parameters {
			queryParams = append(queryParams, fmt.Sprintf("%s=%v", key, val))
		}
		url += "?" + strings.Join(queryParams, "&")
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "failed to create request", err)
	}

	c.applyAuth(req)
	c.applyHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "request failed", err)
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(start)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "failed to read response", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, base.NewConnectorError(c.config.Name, "Query",
			fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)), nil)
	}

	// Parse JSON response
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		// If not JSON, return as string
		rows := []map[string]interface{}{
			{"response": string(body)},
		}
		return &base.QueryResult{
			Rows:      rows,
			RowCount:  1,
			Duration:  duration,
			Connector: c.config.Name,
		}, nil
	}

	// Convert result to rows
	rows := c.convertToRows(result)

	c.logger.Printf("HTTP GET %s: %d rows, %v", path, len(rows), duration)

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  duration,
		Connector: c.config.Name,
	}, nil
}

// Execute executes a POST/PUT/DELETE request (write operation)
func (c *HTTPConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	// cmd.Action should be the HTTP method (POST, PUT, DELETE, PATCH)
	method := strings.ToUpper(cmd.Action)
	path := cmd.Statement
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	url := c.baseURL + path

	// Prepare request body
	var bodyReader io.Reader
	if len(cmd.Parameters) > 0 {
		bodyBytes, err := json.Marshal(cmd.Parameters)
		if err != nil {
			return nil, base.NewConnectorError(c.config.Name, "Execute", "failed to marshal body", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Execute", "failed to create request", err)
	}

	c.applyAuth(req)
	c.applyHeaders(req)

	// Ensure JSON content type for body requests
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &base.CommandResult{
			Success:   false,
			Duration:  time.Since(start),
			Message:   err.Error(),
			Connector: c.config.Name,
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(start)

	// Read response body
	body, _ := io.ReadAll(resp.Body)

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	message := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
	if len(body) > 200 {
		message = fmt.Sprintf("HTTP %d: %s...", resp.StatusCode, string(body[:200]))
	}

	rowsAffected := 0
	if success {
		rowsAffected = 1
	}

	c.logger.Printf("HTTP %s %s: status=%d, %v", method, path, resp.StatusCode, duration)

	return &base.CommandResult{
		Success:      success,
		RowsAffected: rowsAffected,
		Duration:     duration,
		Message:      message,
		Connector:    c.config.Name,
	}, nil
}

// Name returns the connector instance name
func (c *HTTPConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "http-connector"
}

// Type returns the connector type
func (c *HTTPConnector) Type() string {
	return "http"
}

// Version returns the connector version
func (c *HTTPConnector) Version() string {
	return "0.2.0"
}

// Capabilities returns the list of connector capabilities
func (c *HTTPConnector) Capabilities() []string {
	return []string{"query", "execute", "rest-api"}
}

// applyAuth applies authentication to the request
func (c *HTTPConnector) applyAuth(req *http.Request) {
	switch c.authType {
	case "bearer":
		if token, ok := c.authConfig["token"]; ok {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	case "basic":
		if username, ok := c.authConfig["username"]; ok {
			password := c.authConfig["password"]
			req.SetBasicAuth(username, password)
		}
	case "api-key":
		if key, ok := c.authConfig["api_key"]; ok {
			headerName := c.authConfig["header_name"]
			if headerName == "" {
				headerName = "X-API-Key"
			}
			req.Header.Set(headerName, key)
		}
	case "none":
		// No authentication
	}
}

// applyHeaders applies custom headers to the request
func (c *HTTPConnector) applyHeaders(req *http.Request) {
	for key, val := range c.headers {
		req.Header.Set(key, val)
	}
}

// convertToRows converts API response to rows format
func (c *HTTPConnector) convertToRows(result interface{}) []map[string]interface{} {
	switch v := result.(type) {
	case []interface{}:
		// Array response - convert each item to a row
		rows := make([]map[string]interface{}, 0, len(v))
		for _, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				rows = append(rows, itemMap)
			} else {
				// Wrap non-map items
				rows = append(rows, map[string]interface{}{"value": item})
			}
		}
		return rows
	case map[string]interface{}:
		// Single object response - return as single row
		return []map[string]interface{}{v}
	default:
		// Primitive or unknown type - wrap it
		return []map[string]interface{}{
			{"value": v},
		}
	}
}
