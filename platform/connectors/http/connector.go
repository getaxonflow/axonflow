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

package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/sdk"
	"axonflow/platform/shared/egress"
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
	sdk.BaseConnector
	httpClient      *http.Client
	baseURL         string
	authType        string
	authProvider    sdk.AuthProvider
	headers         map[string]string
	maxResponseSize int64
	maxRetries      int
	retryDelay      time.Duration
	allowPrivateIPs bool
}

// NewHTTPConnector creates a new HTTP connector instance with secure defaults
func NewHTTPConnector() *HTTPConnector {
	conn := &HTTPConnector{
		headers:         make(map[string]string),
		maxResponseSize: DefaultMaxResponseSize,
		maxRetries:      DefaultMaxRetries,
		retryDelay:      DefaultRetryDelay,
		allowPrivateIPs: false, // SSRF protection enabled by default
	}
	conn.BaseConnector = *sdk.NewBaseConnector("http")
	conn.SetVersion("1.0.0")
	conn.SetCapabilities([]string{
		"query",
		"execute",
		"rest-api",
		"retry",
		"ssrf-protection",
	})
	conn.SetValidator(sdk.NewDefaultConfigValidator(
		[]string{"base_url"},
		map[string]interface{}{
			"allow_private_ips": false,
			"max_response_size": DefaultMaxResponseSize,
			"max_retries":       DefaultMaxRetries,
			"retry_delay":       DefaultRetryDelay.String(),
			"disable_redirects": false,
			"tls_skip_verify":   false,
			"timeout":           float64(DefaultTimeout / time.Second),
		},
	))

	return conn
}

// Connect initializes the HTTP connector with security validations
func (c *HTTPConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	if config == nil {
		return base.NewConnectorError("http", "Connect", "config is required", nil)
	}

	if config.Type == "" {
		config.Type = "http"
	}

	// Preserve current precedence: config.Timeout overrides option timeout.
	timeout := DefaultTimeout
	if t, ok := config.Options["timeout"].(float64); ok && t > 0 {
		timeout = time.Duration(int(t)) * time.Second
	}
	if config.Timeout > 0 {
		timeout = config.Timeout
	}
	config.Timeout = timeout

	// Configure retries early so base connector stores it.
	maxRetries := DefaultMaxRetries
	if retries, ok := config.Options["max_retries"].(float64); ok {
		maxRetries = int(retries)
	}
	if config.MaxRetries > 0 {
		maxRetries = config.MaxRetries
	}
	config.MaxRetries = maxRetries

	// Call base connect for validation and hooks
	if err := c.BaseConnector.Connect(ctx, config); err != nil {
		return err
	}

	// Extract and validate base URL
	baseURLStr := c.GetStringOption("base_url", "")
	if baseURLStr == "" {
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
	c.allowPrivateIPs = c.GetBoolOption("allow_private_ips", false)

	if !c.allowPrivateIPs {
		if err := c.validateHost(parsedURL.Hostname()); err != nil {
			return base.NewConnectorError(config.Name, "Connect", "SSRF protection", err)
		}
	}

	c.baseURL = strings.TrimSuffix(baseURLStr, "/")

	// Configure authentication
	c.authType = c.GetStringOption("auth_type", "none")
	authProvider, err := c.buildAuthProvider(c.authType)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "invalid auth configuration", err)
	}
	if authProvider == nil && c.authType != "" && c.authType != "none" {
		c.Log("Warning: auth_type %s configured but credentials are missing; requests will be unauthenticated", c.authType)
	}
	c.authProvider = authProvider
	c.SetAuthProvider(authProvider)

	// Configure custom headers
	c.headers = make(map[string]string)
	if headers, ok := c.GetOption("headers", nil).(map[string]interface{}); ok {
		for key, val := range headers {
			if strVal, ok := val.(string); ok {
				c.headers[key] = strVal
			}
		}
	}

	// Configure max response size
	if maxSize := c.GetIntOption("max_response_size", DefaultMaxResponseSize); maxSize > 0 {
		c.maxResponseSize = int64(maxSize)
	}

	c.maxRetries = config.MaxRetries

	retryDelay := c.GetStringOption("retry_delay", "")
	if retryDelay != "" {
		if parsed, err := time.ParseDuration(retryDelay); err == nil {
			c.retryDelay = parsed
		}
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if c.GetBoolOption("tls_skip_verify", false) {
		tlsConfig.InsecureSkipVerify = true
		c.Log("WARNING: TLS verification disabled for %s", config.Name)
	}

	// Create HTTP transport with connection pooling.
	//
	// The dialer is egress-guarded, not bare (#3104 R3 round 2, finding 1).
	// validateHost above runs ONCE, inside Connect. Every request after that
	// re-resolves base_url's host, and until now nothing checked the answer —
	// so a host that resolved public at Connect and into a reserved range
	// afterwards was dialled. That is the same DNS-rebinding shape #3104 closed
	// on the three callback dialers, sitting on the surface this file's own
	// comment calls "the weakest and most general-purpose egress path in the
	// codebase". egress.NewSafeDialContext resolves once per dial, refuses if
	// any answer is blocked, and connects to the literal it validated.
	//
	// allow_private_ips bypasses it exactly as it bypasses validateHost, so the
	// documented escape hatch keeps its existing meaning.
	baseDialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	dialContext := baseDialer.DialContext
	if !c.allowPrivateIPs {
		dialContext = egress.NewSafeDialContext(egress.ConnectorEgress, baseDialer, nil, func(ip net.IP) error {
			return fmt.Errorf("SSRF protection: connection to private IP %s is not allowed (%s; set allow_private_ips=true on this connector to permit it)",
				ip, egress.ConnectorEgress.Reason(ip))
		})
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    100,
		MaxConnsPerHost: 10,
		IdleConnTimeout: 90 * time.Second,
		DialContext:     dialContext,
	}

	// Create HTTP client
	c.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	// Disable redirects if configured
	if c.GetBoolOption("disable_redirects", false) {
		c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	c.GetMetrics().RecordConnect()
	c.Log("Connected to HTTP API: %s (auth=%s, timeout=%v, max_retries=%d)",
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
		// Use the canonical connector egress classifier. This connector
		// deliberately does NOT keep a local copy: it previously did, that copy
		// was a strict subset of base.IsPrivateIP, and since the HTTP connector
		// takes an arbitrary operator-supplied base_url it was the weakest and
		// most general-purpose egress path in the codebase (#3095).
		if base.IsPrivateIP(ip) {
			return fmt.Errorf("connection to private IP %s is not allowed (host: %s)", ip, host)
		}
	}

	return nil
}

// Disconnect closes the connection (cleans up transport)
func (c *HTTPConnector) Disconnect(ctx context.Context) error {
	if c.httpClient != nil && c.httpClient.Transport != nil {
		if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	c.GetMetrics().RecordDisconnect()
	c.Log("Disconnected from HTTP API: %s", c.Name())
	return c.BaseConnector.Disconnect(ctx)
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

	healthPath := c.GetStringOption("health_path", "/")

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+healthPath, nil)
	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}

	if err := c.applyAuth(ctx, req); err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Latency:   time.Since(start),
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}
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
func (c *HTTPConnector) Query(ctx context.Context, query *base.Query) (result *base.QueryResult, err error) {
	start := time.Now()
	defer func() {
		c.GetMetrics().RecordQuery(time.Since(start), err)
	}()

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

	var lastErr error
	var resp *http.Response

	// Retry loop with exponential backoff
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			delay := c.calculateBackoff(attempt)
			c.Log("Retry attempt %d/%d after %v", attempt, c.maxRetries, delay)

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

		if err := c.applyAuth(ctx, req); err != nil {
			return nil, base.NewConnectorError(c.Name(), "Query", "authentication failed", err)
		}
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
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
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

	rows := c.convertToRows(parsed)

	c.Log("HTTP GET %s: %d rows, %v", path, len(rows), duration)

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  duration,
		Connector: c.Name(),
	}, nil
}

// Execute executes a POST/PUT/DELETE request (write operation) with retry support
func (c *HTTPConnector) Execute(ctx context.Context, cmd *base.Command) (result *base.CommandResult, err error) {
	start := time.Now()
	defer func() {
		c.GetMetrics().RecordExecute(time.Since(start), err)
	}()

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
			c.Log("Retry attempt %d/%d after %v", attempt, maxRetries, delay)

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

		if err := c.applyAuth(ctx, req); err != nil {
			return nil, base.NewConnectorError(c.Name(), "Execute", "authentication failed", err)
		}
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
		c.Log("Warning: failed to read response body: %v", err)
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

	c.Log("HTTP %s %s: status=%d, %v", method, path, resp.StatusCode, duration)

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
	if cfg := c.GetConfig(); cfg != nil && cfg.Name != "" {
		return cfg.Name
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

func (c *HTTPConnector) buildAuthProvider(authType string) (sdk.AuthProvider, error) {
	switch strings.ToLower(authType) {
	case "bearer":
		token := c.GetCredential("token")
		if token == "" {
			return nil, nil
		}
		return sdk.NewBearerTokenAuth(token, time.Time{}), nil
	case "basic":
		username := c.GetCredential("username")
		if username == "" {
			return nil, nil
		}
		password := c.GetCredential("password")
		return sdk.NewBasicAuth(username, password), nil
	case "api-key":
		key := c.GetCredential("api_key")
		if key == "" {
			return nil, nil
		}
		headerName := c.GetCredential("header_name")
		if headerName == "" {
			headerName = "X-API-Key"
		}
		return sdk.NewAPIKeyAuth(key, sdk.APIKeyInHeader, headerName), nil
	case "oauth2":
		accessToken := c.GetCredential("access_token")
		if accessToken != "" {
			return sdk.NewBearerTokenAuth(accessToken, time.Time{}), nil
		}
		tokenURL := c.GetStringOption("token_url", "")
		clientID := c.GetCredential("client_id")
		clientSecret := c.GetCredential("client_secret")
		if tokenURL == "" || clientID == "" || clientSecret == "" {
			return nil, nil
		}
		scopes := c.getScopeList()
		return sdk.NewOAuthAuth(&sdk.OAuthConfig{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
			Scopes:       scopes,
		}), nil
	case "none", "":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported auth_type %q", authType)
	}
}

func (c *HTTPConnector) getScopeList() []string {
	rawScopes := c.GetOption("scopes", nil)
	switch scopes := rawScopes.(type) {
	case []string:
		return scopes
	case []interface{}:
		list := make([]string, 0, len(scopes))
		for _, scope := range scopes {
			if s, ok := scope.(string); ok && s != "" {
				list = append(list, s)
			}
		}
		return list
	case string:
		if scopes == "" {
			return nil
		}
		return []string{scopes}
	default:
		return nil
	}
}

// applyAuth applies authentication to the request
func (c *HTTPConnector) applyAuth(ctx context.Context, req *http.Request) error {
	if c.authProvider == nil {
		return nil
	}

	if c.authProvider.IsExpired() {
		if err := c.authProvider.Refresh(ctx); err != nil {
			return err
		}
	}

	return c.authProvider.Authenticate(ctx, req)
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
