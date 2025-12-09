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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"axonflow/platform/connectors/base"
)

const (
	// DefaultTimeout is the default HTTP request timeout
	DefaultTimeout = 30 * time.Second
	// DefaultMaxResponseSize is the maximum response body size (10MB)
	DefaultMaxResponseSize = 10 * 1024 * 1024
	// DefaultMaxRetries is the default number of retry attempts
	DefaultMaxRetries = 3
	// DefaultRetryDelay is the initial delay between retries
	DefaultRetryDelay = 100 * time.Millisecond
	// MaxRetryDelay is the maximum delay between retries
	MaxRetryDelay = 5 * time.Second
)

// HTTPConnector implements the MCP Connector interface for HTTP REST APIs
// with production-ready security hardening and reliability features.
type HTTPConnector struct {
	config          *base.ConnectorConfig
	httpClient      *http.Client
	logger          *log.Logger
	baseURL         string
	authType        string
	authConfig      map[string]string
	headers         map[string]string
	maxResponseSize int64
	maxRetries      int
	retryDelay      time.Duration
	allowPrivateIPs bool
}

// NewHTTPConnector creates a new HTTP connector instance with secure defaults
func NewHTTPConnector() *HTTPConnector {
	return &HTTPConnector{
		logger:          log.New(os.Stdout, "[MCP_HTTP] ", log.LstdFlags),
		headers:         make(map[string]string),
		maxResponseSize: DefaultMaxResponseSize,
		maxRetries:      DefaultMaxRetries,
		retryDelay:      DefaultRetryDelay,
		allowPrivateIPs: false, // SSRF protection enabled by default
	}
}

// Connect initializes the HTTP connector with security validations
func (c *HTTPConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config

	// Extract and validate base URL
	baseURLStr, ok := config.Options["base_url"].(string)
	if !ok || baseURLStr == "" {
		return base.NewConnectorError(config.Name, "Connect", "base_url is required", nil)
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(baseURLStr)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "invalid base_url format", err)
	}

	// Validate URL scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return base.NewConnectorError(config.Name, "Connect", "base_url must use http or https scheme", nil)
	}

	// SSRF protection: validate host is not a private IP unless explicitly allowed
	if allowPrivate, ok := config.Options["allow_private_ips"].(bool); ok {
		c.allowPrivateIPs = allowPrivate
	}

	if !c.allowPrivateIPs {
		if err := c.validateHost(parsedURL.Hostname()); err != nil {
			return base.NewConnectorError(config.Name, "Connect", "SSRF protection", err)
		}
	}

	c.baseURL = strings.TrimSuffix(baseURLStr, "/")

	// Configure authentication
	if authType, ok := config.Options["auth_type"].(string); ok {
		c.authType = authType
	} else {
		c.authType = "none"
	}

	c.authConfig = make(map[string]string)
	for key, val := range config.Credentials {
		c.authConfig[key] = val
	}

	// Configure custom headers
	if headers, ok := config.Options["headers"].(map[string]interface{}); ok {
		for key, val := range headers {
			if strVal, ok := val.(string); ok {
				c.headers[key] = strVal
			}
		}
	}

	// Configure timeout
	timeout := DefaultTimeout
	if t, ok := config.Options["timeout"].(float64); ok && t > 0 {
		timeout = time.Duration(int(t)) * time.Second
	}
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	// Configure max response size
	if maxSize, ok := config.Options["max_response_size"].(float64); ok && maxSize > 0 {
		c.maxResponseSize = int64(maxSize)
	}

	// Configure retries
	if retries, ok := config.Options["max_retries"].(float64); ok {
		c.maxRetries = int(retries)
	}
	if config.MaxRetries > 0 {
		c.maxRetries = config.MaxRetries
	}

	if delay, ok := config.Options["retry_delay"].(string); ok {
		if parsed, err := time.ParseDuration(delay); err == nil {
			c.retryDelay = parsed
		}
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if skipVerify, ok := config.Options["tls_skip_verify"].(bool); ok && skipVerify {
		tlsConfig.InsecureSkipVerify = true
		c.logger.Printf("WARNING: TLS verification disabled for %s", config.Name)
	}

	// Create HTTP transport with connection pooling
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    100,
		MaxConnsPerHost: 10,
		IdleConnTimeout: 90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	// Create HTTP client
	c.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	// Disable redirects if configured
	if noRedirect, ok := config.Options["disable_redirects"].(bool); ok && noRedirect {
		c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	c.logger.Printf("Connected to HTTP API: %s (auth=%s, timeout=%v, max_retries=%d)",
		config.Name, c.authType, timeout, c.maxRetries)

	return nil
}

// validateHost checks if the host is safe to connect to (SSRF protection)
func (c *HTTPConnector) validateHost(host string) error {
	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve host %s: %w", host, err)
	}

	for _, ip := range ips {
		if c.isPrivateIP(ip) {
			return fmt.Errorf("connection to private IP %s is not allowed (host: %s)", ip, host)
		}
	}

	return nil
}

// isPrivateIP checks if an IP address is private/reserved
func (c *HTTPConnector) isPrivateIP(ip net.IP) bool {
	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for private ranges
	if ip.IsPrivate() {
		return true
	}

	// Check for unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}

	// Additional checks for IPv4
	if ip4 := ip.To4(); ip4 != nil {
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if ip4[0] == 127 {
			return true
		}
	}

	return false
}

// Disconnect closes the connection (cleans up transport)
func (c *HTTPConnector) Disconnect(ctx context.Context) error {
	if c.httpClient != nil && c.httpClient.Transport != nil {
		if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	c.logger.Printf("Disconnected from HTTP API: %s", c.Name())
	return nil
}

// HealthCheck verifies the API is accessible
func (c *HTTPConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.baseURL == "" {
		return &base.HealthStatus{
			Healthy:   false,
			Error:     "base_url not configured",
			Timestamp: time.Now(),
		}, nil
	}

	healthPath := "/"
	if c.config != nil && c.config.Options != nil {
		if hp, ok := c.config.Options["health_path"].(string); ok {
			healthPath = hp
		}
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

	// Drain body to allow connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	healthy := resp.StatusCode >= 200 && resp.StatusCode < 400

	details := map[string]string{
		"base_url":    c.baseURL,
		"status_code": strconv.Itoa(resp.StatusCode),
		"auth_type":   c.authType,
	}

	return &base.HealthStatus{
		Healthy:   healthy,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes a GET request (read operation) with retry support
func (c *HTTPConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	path := query.Statement
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Build URL with properly encoded query parameters
	reqURL, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "invalid URL path", err)
	}

	// Add query parameters with proper encoding
	if len(query.Parameters) > 0 {
		params := url.Values{}
		for key, val := range query.Parameters {
			// Skip internal parameters
			if strings.HasPrefix(key, "_") {
				continue
			}
			params.Set(key, fmt.Sprintf("%v", val))
		}
		reqURL.RawQuery = params.Encode()
	}

	start := time.Now()
	var lastErr error
	var resp *http.Response

	// Retry loop with exponential backoff
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.calculateBackoff(attempt)
			c.logger.Printf("Retry attempt %d/%d after %v", attempt, c.maxRetries, delay)

			select {
			case <-ctx.Done():
				return nil, base.NewConnectorError(c.Name(), "Query", "context cancelled during retry", ctx.Err())
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
		if err != nil {
			return nil, base.NewConnectorError(c.Name(), "Query", "failed to create request", err)
		}

		c.applyAuth(req)
		c.applyHeaders(req)

		resp, lastErr = c.httpClient.Do(req)
		if lastErr == nil && !c.isRetryableStatusCode(resp.StatusCode) {
			break
		}

		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
		}

		if lastErr == nil {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}

	if lastErr != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "request failed after retries", lastErr)
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(start)

	// Read response with size limit
	limitedReader := io.LimitReader(resp.Body, c.maxResponseSize+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, base.NewConnectorError(c.Name(), "Query", "failed to read response", err)
	}

	if int64(len(body)) > c.maxResponseSize {
		return nil, base.NewConnectorError(c.Name(), "Query",
			fmt.Sprintf("response size exceeds limit of %d bytes", c.maxResponseSize), nil)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := string(body)
		if len(errMsg) > 200 {
			errMsg = errMsg[:200] + "..."
		}
		return nil, base.NewConnectorError(c.Name(), "Query",
			fmt.Sprintf("HTTP %d: %s", resp.StatusCode, errMsg), nil)
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
			Connector: c.Name(),
		}, nil
	}

	rows := c.convertToRows(result)

	c.logger.Printf("HTTP GET %s: %d rows, %v", path, len(rows), duration)

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  duration,
		Connector: c.Name(),
	}, nil
}

// Execute executes a POST/PUT/DELETE request (write operation) with retry support
func (c *HTTPConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	method := strings.ToUpper(cmd.Action)
	if method == "" {
		method = "POST"
	}

	// Validate HTTP method
	validMethods := map[string]bool{
		"POST": true, "PUT": true, "DELETE": true, "PATCH": true,
	}
	if !validMethods[method] {
		return nil, base.NewConnectorError(c.Name(), "Execute",
			fmt.Sprintf("unsupported HTTP method: %s", method), nil)
	}

	path := cmd.Statement
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	reqURL := c.baseURL + path

	// Prepare request body
	var bodyReader io.Reader
	var bodyBytes []byte
	if len(cmd.Parameters) > 0 {
		var err error
		bodyBytes, err = json.Marshal(cmd.Parameters)
		if err != nil {
			return nil, base.NewConnectorError(c.Name(), "Execute", "failed to marshal body", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	start := time.Now()
	var lastErr error
	var resp *http.Response

	// Retry loop for idempotent methods or specific errors
	maxRetries := c.maxRetries
	if method != "PUT" && method != "DELETE" {
		// Only retry POST/PATCH on connection errors, not on HTTP errors
		maxRetries = 1
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.calculateBackoff(attempt)
			c.logger.Printf("Retry attempt %d/%d after %v", attempt, maxRetries, delay)

			select {
			case <-ctx.Done():
				return nil, base.NewConnectorError(c.Name(), "Execute", "context cancelled during retry", ctx.Err())
			case <-time.After(delay):
			}

			// Reset body reader for retry
			if bodyBytes != nil {
				bodyReader = bytes.NewReader(bodyBytes)
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
		if err != nil {
			return nil, base.NewConnectorError(c.Name(), "Execute", "failed to create request", err)
		}

		c.applyAuth(req)
		c.applyHeaders(req)

		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, lastErr = c.httpClient.Do(req)
		if lastErr == nil {
			break // Success, exit retry loop
		}

		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
		}
	}

	if lastErr != nil {
		return &base.CommandResult{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("request failed after retries: %v", lastErr),
			Connector: c.Name(),
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(start)

	// Read response with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseSize))
	if err != nil {
		c.logger.Printf("Warning: failed to read response body: %v", err)
	}

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	message := fmt.Sprintf("HTTP %d", resp.StatusCode)
	if len(body) > 0 {
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		message = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, bodyStr)
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
		Connector:    c.Name(),
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
	return "1.0.0"
}

// Capabilities returns the list of connector capabilities
func (c *HTTPConnector) Capabilities() []string {
	return []string{
		"query",
		"execute",
		"rest-api",
		"retry",
		"ssrf-protection",
	}
}

// applyAuth applies authentication to the request
func (c *HTTPConnector) applyAuth(req *http.Request) {
	switch c.authType {
	case "bearer":
		if token, ok := c.authConfig["token"]; ok && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	case "basic":
		if username, ok := c.authConfig["username"]; ok {
			password := c.authConfig["password"]
			req.SetBasicAuth(username, password)
		}
	case "api-key":
		if key, ok := c.authConfig["api_key"]; ok && key != "" {
			headerName := c.authConfig["header_name"]
			if headerName == "" {
				headerName = "X-API-Key"
			}
			req.Header.Set(headerName, key)
		}
	case "oauth2":
		if token, ok := c.authConfig["access_token"]; ok && token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	case "none", "":
		// No authentication
	}
}

// applyHeaders applies custom headers to the request
func (c *HTTPConnector) applyHeaders(req *http.Request) {
	// Set default headers
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "AxonFlow-HTTP-Connector/1.0")
	}

	// Apply custom headers
	for key, val := range c.headers {
		req.Header.Set(key, val)
	}
}

// convertToRows converts API response to rows format
func (c *HTTPConnector) convertToRows(result interface{}) []map[string]interface{} {
	switch v := result.(type) {
	case []interface{}:
		rows := make([]map[string]interface{}, 0, len(v))
		for _, item := range v {
			if itemMap, ok := item.(map[string]interface{}); ok {
				rows = append(rows, itemMap)
			} else {
				rows = append(rows, map[string]interface{}{"value": item})
			}
		}
		return rows
	case map[string]interface{}:
		return []map[string]interface{}{v}
	default:
		return []map[string]interface{}{
			{"value": v},
		}
	}
}

// calculateBackoff calculates exponential backoff delay
func (c *HTTPConnector) calculateBackoff(attempt int) time.Duration {
	delay := c.retryDelay * time.Duration(1<<uint(attempt-1))
	if delay > MaxRetryDelay {
		delay = MaxRetryDelay
	}
	return delay
}

// isRetryableStatusCode returns true if the status code indicates a retryable error
func (c *HTTPConnector) isRetryableStatusCode(statusCode int) bool {
	switch statusCode {
	case 408, // Request Timeout
		429, // Too Many Requests
		500, // Internal Server Error
		502, // Bad Gateway
		503, // Service Unavailable
		504: // Gateway Timeout
		return true
	default:
		return false
	}
}
