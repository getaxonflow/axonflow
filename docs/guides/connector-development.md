# AxonFlow Connector Development Guide

This guide explains how to develop new MCP connectors for AxonFlow. Connectors enable AI agents to safely interact with external data sources like databases and APIs.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                           AxonFlow Agent                            │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐ │
│  │  MCP Registry   │──│ Policy Engine   │──│ Connector Manager   │ │
│  └────────┬────────┘  └─────────────────┘  └──────────┬──────────┘ │
│           │                                           │            │
│  ┌────────┴──────────────────────────────────────────┴──────────┐ │
│  │                    Connector Interface                        │ │
│  └──────────────────────────────────────────────────────────────┘ │
│           │           │           │           │           │       │
│  ┌────────┴───┐┌──────┴──┐┌──────┴───┐┌──────┴──┐┌──────┴──────┐ │
│  │ PostgreSQL ││Cassandra││Snowflake ││Salesforce││ Your New   │ │
│  │ Connector  ││Connector││Connector ││Connector ││ Connector  │ │
│  └────────────┘└─────────┘└──────────┘└──────────┘└─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow
```

### 2. Create Connector Structure

```bash
# Create connector directory
mkdir -p platform/connectors/myconnector

# Create files
touch platform/connectors/myconnector/connector.go
touch platform/connectors/myconnector/connector_test.go
```

### 3. Implement the Connector Interface

```go
// platform/connectors/myconnector/connector.go
package myconnector

import (
    "context"
    "axonflow/platform/connectors/base"
)

type MyConnector struct {
    config *base.ConnectorConfig
    client *MyClient  // Your SDK client
}

func NewMyConnector() *MyConnector {
    return &MyConnector{}
}

// Required interface methods...
```

## Connector Interface

All connectors must implement the `base.Connector` interface:

```go
// platform/connectors/base/connector.go
type Connector interface {
    // Lifecycle Management
    Connect(ctx context.Context, config *ConnectorConfig) error
    Disconnect(ctx context.Context) error
    HealthCheck(ctx context.Context) (*HealthStatus, error)

    // Data Operations (MCP Resources - read-only)
    Query(ctx context.Context, query *Query) (*QueryResult, error)

    // Action Operations (MCP Tools - write operations)
    Execute(ctx context.Context, cmd *Command) (*CommandResult, error)

    // Metadata
    Name() string           // Unique connector instance name
    Type() string           // Connector type (postgres, cassandra, http_api)
    Version() string        // Connector version
    Capabilities() []string // List of capabilities (query, execute, transactions)
}
```

### Required Methods

#### Connect

Initialize the connection using the provided configuration:

```go
func (c *MyConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
    c.config = config

    // Parse credentials
    apiKey := config.Credentials["api_key"]
    endpoint := config.ConnectionURL

    // Initialize client
    client, err := NewMyClient(endpoint, apiKey)
    if err != nil {
        return fmt.Errorf("failed to create client: %w", err)
    }

    c.client = client
    return nil
}
```

#### Disconnect

Clean up resources:

```go
func (c *MyConnector) Disconnect(ctx context.Context) error {
    if c.client != nil {
        return c.client.Close()
    }
    return nil
}
```

#### HealthCheck

Health check the connection:

```go
func (c *MyConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
    start := time.Now()
    if err := c.client.Ping(ctx); err != nil {
        return &base.HealthStatus{
            Healthy:   false,
            Error:     err.Error(),
            Timestamp: time.Now(),
        }, err
    }
    return &base.HealthStatus{
        Healthy:   true,
        Latency:   time.Since(start),
        Timestamp: time.Now(),
    }, nil
}
```

#### Name, Type, Version, Capabilities

Return connector metadata:

```go
func (c *MyConnector) Name() string {
    return c.config.Name // Unique instance name from configuration
}

func (c *MyConnector) Type() string {
    return "myconnector"
}

func (c *MyConnector) Version() string {
    return "1.0.0"
}

func (c *MyConnector) Capabilities() []string {
    return []string{
        "query",          // Supports read operations
        "execute",        // Supports write operations
        "transactions",   // Supports transactions
    }
}
```

#### Query

Execute read operations:

```go
func (c *MyConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
    start := time.Now()

    // Apply timeout
    if query.Timeout > 0 {
        var cancel context.CancelFunc
        ctx, cancel = context.WithTimeout(ctx, query.Timeout)
        defer cancel()
    }

    // Execute query
    results, err := c.client.Query(ctx, query.Statement, query.Parameters)
    if err != nil {
        return nil, fmt.Errorf("query failed: %w", err)
    }

    // Apply limit
    if query.Limit > 0 && len(results) > query.Limit {
        results = results[:query.Limit]
    }

    return &base.QueryResult{
        Rows:     results,
        RowCount: len(results),
        Duration: time.Since(start),
    }, nil
}
```

#### Execute

Execute write operations:

```go
func (c *MyConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
    start := time.Now()

    // Validate action is allowed
    switch strings.ToUpper(cmd.Action) {
    case "INSERT", "UPDATE":
        // Allowed
    case "DELETE":
        // May be blocked by policy
        return nil, fmt.Errorf("DELETE operations require explicit approval")
    default:
        return nil, fmt.Errorf("unsupported action: %s", cmd.Action)
    }

    // Execute command
    affected, err := c.client.Execute(ctx, cmd.Statement, cmd.Parameters)
    if err != nil {
        return nil, fmt.Errorf("execute failed: %w", err)
    }

    return &base.CommandResult{
        RowsAffected: affected,
        Duration:     time.Since(start),
        Message:      fmt.Sprintf("%d rows affected", affected),
    }, nil
}
```

## Data Types

### ConnectorConfig

```go
type ConnectorConfig struct {
    Name          string                 // Unique connector name
    Type          string                 // Connector type (e.g., "myconnector")
    ConnectionURL string                 // Connection string
    Credentials   map[string]string      // Authentication credentials
    Options       map[string]interface{} // Type-specific options
    Timeout       time.Duration          // Default timeout
    MaxRetries    int                    // Retry attempts
    TenantID      string                 // Tenant filter
}
```

### Query

```go
type Query struct {
    Statement  string                 // Query statement (SQL, API operation, etc.)
    Parameters map[string]interface{} // Query parameters
    Timeout    time.Duration          // Query timeout
    Limit      int                    // Result limit
}
```

### QueryResult

```go
type QueryResult struct {
    Rows     []map[string]interface{} // Result rows
    RowCount int                      // Number of rows
    Duration time.Duration            // Execution time
    Metadata map[string]interface{}   // Optional metadata
}
```

### Command

```go
type Command struct {
    Action     string                 // Action type (INSERT, UPDATE, DELETE)
    Statement  string                 // Command statement
    Parameters map[string]interface{} // Command parameters
    Timeout    time.Duration          // Command timeout
}
```

### CommandResult

```go
type CommandResult struct {
    RowsAffected int64                  // Rows affected
    LastInsertID int64                  // Last insert ID (if applicable)
    Duration     time.Duration          // Execution time
    Message      string                 // Status message
    Metadata     map[string]interface{} // Optional metadata
}
```

## Complete Example: HTTP API Connector

Here's a complete example of an HTTP API connector:

```go
// platform/connectors/httpapi/connector.go
package httpapi

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "axonflow/platform/connectors/base"
)

type HTTPAPIConnector struct {
    config     *base.ConnectorConfig
    httpClient *http.Client
    baseURL    string
    apiKey     string
}

func NewHTTPAPIConnector() *HTTPAPIConnector {
    return &HTTPAPIConnector{
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

func (c *HTTPAPIConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
    c.config = config
    c.baseURL = config.ConnectionURL
    c.apiKey = config.Credentials["api_key"]

    if c.baseURL == "" {
        return fmt.Errorf("connection_url is required")
    }

    // Set custom timeout if provided
    if config.Timeout > 0 {
        c.httpClient.Timeout = config.Timeout
    }

    return nil
}

func (c *HTTPAPIConnector) Disconnect(ctx context.Context) error {
    c.httpClient.CloseIdleConnections()
    return nil
}

func (c *HTTPAPIConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
    start := time.Now()

    req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
    if err != nil {
        return nil, err
    }

    c.addAuthHeaders(req)

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return &base.HealthStatus{
            Healthy:   false,
            Error:     err.Error(),
            Timestamp: time.Now(),
        }, fmt.Errorf("health check failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return &base.HealthStatus{
            Healthy:   false,
            Error:     fmt.Sprintf("health check returned status %d", resp.StatusCode),
            Timestamp: time.Now(),
        }, fmt.Errorf("health check returned status %d", resp.StatusCode)
    }

    return &base.HealthStatus{
        Healthy:   true,
        Latency:   time.Since(start),
        Timestamp: time.Now(),
    }, nil
}

func (c *HTTPAPIConnector) Name() string {
    return c.config.Name
}

func (c *HTTPAPIConnector) Type() string {
    return "httpapi"
}

func (c *HTTPAPIConnector) Version() string {
    return "1.0.0"
}

func (c *HTTPAPIConnector) Capabilities() []string {
    return []string{"query", "execute"}
}

func (c *HTTPAPIConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
    start := time.Now()

    // Build request URL
    endpoint := c.baseURL + "/" + query.Statement

    req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
    if err != nil {
        return nil, err
    }

    c.addAuthHeaders(req)

    // Add query parameters
    q := req.URL.Query()
    for key, value := range query.Parameters {
        q.Add(key, fmt.Sprintf("%v", value))
    }
    if query.Limit > 0 {
        q.Add("limit", fmt.Sprintf("%d", query.Limit))
    }
    req.URL.RawQuery = q.Encode()

    // Execute request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
    }

    // Parse response
    var results []map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
        return nil, fmt.Errorf("failed to parse response: %w", err)
    }

    return &base.QueryResult{
        Rows:     results,
        RowCount: len(results),
        Duration: time.Since(start),
    }, nil
}

func (c *HTTPAPIConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
    start := time.Now()

    // Build request
    endpoint := c.baseURL + "/" + cmd.Statement

    var method string
    switch cmd.Action {
    case "INSERT", "CREATE":
        method = "POST"
    case "UPDATE":
        method = "PUT"
    case "DELETE":
        method = "DELETE"
    default:
        method = "POST"
    }

    body, err := json.Marshal(cmd.Parameters)
    if err != nil {
        return nil, fmt.Errorf("failed to encode parameters: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
    if err != nil {
        return nil, err
    }

    c.addAuthHeaders(req)
    req.Header.Set("Content-Type", "application/json")

    // Execute request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
    }

    return &base.CommandResult{
        RowsAffected: 1,
        Duration:     time.Since(start),
        Message:      fmt.Sprintf("Request completed with status %d", resp.StatusCode),
    }, nil
}

func (c *HTTPAPIConnector) addAuthHeaders(req *http.Request) {
    if c.apiKey != "" {
        req.Header.Set("Authorization", "Bearer "+c.apiKey)
    }
}
```

## Testing Your Connector

### Unit Tests

```go
// platform/connectors/httpapi/connector_test.go
package httpapi

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "axonflow/platform/connectors/base"
)

func TestHTTPAPIConnector_Connect(t *testing.T) {
    connector := NewHTTPAPIConnector()

    config := &base.ConnectorConfig{
        Name:          "test_api",
        Type:          "httpapi",
        ConnectionURL: "https://api.example.com",
        Credentials: map[string]string{
            "api_key": "test-key",
        },
    }

    err := connector.Connect(context.Background(), config)
    if err != nil {
        t.Errorf("Connect failed: %v", err)
    }

    if connector.baseURL != "https://api.example.com" {
        t.Errorf("Expected baseURL 'https://api.example.com', got '%s'", connector.baseURL)
    }
}

func TestHTTPAPIConnector_Query(t *testing.T) {
    // Create mock server
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`[{"id": 1, "name": "test"}]`))
    }))
    defer server.Close()

    connector := NewHTTPAPIConnector()
    connector.Connect(context.Background(), &base.ConnectorConfig{
        ConnectionURL: server.URL,
    })

    result, err := connector.Query(context.Background(), &base.Query{
        Statement: "users",
    })

    if err != nil {
        t.Errorf("Query failed: %v", err)
    }

    if result.RowCount != 1 {
        t.Errorf("Expected 1 row, got %d", result.RowCount)
    }
}

func TestHTTPAPIConnector_Type(t *testing.T) {
    connector := NewHTTPAPIConnector()
    if connector.Type() != "httpapi" {
        t.Errorf("Expected type 'httpapi', got '%s'", connector.Type())
    }
}
```

### Integration Tests

```go
// +build integration

func TestHTTPAPIConnector_Integration(t *testing.T) {
    apiURL := os.Getenv("TEST_API_URL")
    apiKey := os.Getenv("TEST_API_KEY")

    if apiURL == "" {
        t.Skip("TEST_API_URL not set")
    }

    connector := NewHTTPAPIConnector()
    err := connector.Connect(context.Background(), &base.ConnectorConfig{
        ConnectionURL: apiURL,
        Credentials:   map[string]string{"api_key": apiKey},
    })

    if err != nil {
        t.Fatalf("Connect failed: %v", err)
    }
    defer connector.Disconnect(context.Background())

    // Test health check
    if status, err := connector.HealthCheck(context.Background()); err != nil || !status.Healthy {
        t.Errorf("HealthCheck failed: %v", err)
    }
}
```

## Registering Your Connector

### 1. Add Config Loader

```go
// platform/connectors/config/config.go

func LoadHTTPAPIConfig(name string) (*base.ConnectorConfig, error) {
    url := os.Getenv("HTTPAPI_" + strings.ToUpper(name) + "_URL")
    if url == "" {
        return nil, fmt.Errorf("HTTPAPI_%s_URL not set", strings.ToUpper(name))
    }

    return &base.ConnectorConfig{
        Name:          name,
        Type:          "httpapi",
        ConnectionURL: url,
        Credentials: map[string]string{
            "api_key": os.Getenv("HTTPAPI_" + strings.ToUpper(name) + "_API_KEY"),
        },
    }, nil
}
```

### 2. Register in MCP Handler

```go
// platform/agent/mcp_handler.go

func registerConnectorFromConfig(cfg *base.ConnectorConfig) error {
    var connector base.Connector

    switch cfg.Type {
    // ... existing cases ...
    case "httpapi":
        connector = httpapi.NewHTTPAPIConnector()
    default:
        return fmt.Errorf("unsupported connector type: %s", cfg.Type)
    }

    return mcpRegistry.Register(cfg.Name, connector, cfg)
}
```

### 3. Add to Config File Schema

```go
// platform/connectors/config/file_loader.go

func ValidateConfigFile(config *ConfigFile) error {
    // ... existing validation ...

    validTypes := map[string]bool{
        "postgres":   true,
        "cassandra":  true,
        // ... existing types ...
        "httpapi":    true,  // Add your type
    }

    // ...
}
```

## Best Practices

### Error Handling

```go
// Wrap errors with context
if err != nil {
    return nil, fmt.Errorf("failed to execute query: %w", err)
}

// Use specific error types for common cases
var ErrConnectionFailed = errors.New("connection failed")
var ErrAuthenticationFailed = errors.New("authentication failed")
var ErrTimeout = errors.New("operation timed out")
```

### Context Handling

```go
// Always respect context cancellation
select {
case <-ctx.Done():
    return nil, ctx.Err()
default:
}

// Use context for timeouts
ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
defer cancel()
```

### Logging

```go
import "log"

// Use structured logging
log.Printf("[%s] Query executed: statement=%s, rows=%d, duration=%v",
    c.Type(), query.Statement, result.RowCount, result.Duration)
```

### Security

- Never log credentials
- Validate all input parameters
- Use parameterized queries for SQL
- Implement rate limiting if needed
- Handle sensitive data carefully

## Policy Enforcement

As of Issue #963, all MCP connector requests go through phase-aware policy enforcement:

### Request Phase

Before `connector.Query()` is called, the policy engine evaluates the query:
- SQL injection patterns are blocked
- Dangerous operations (DROP, TRUNCATE) are blocked
- Admin-only tables require authorization

If a policy blocks the request, your connector's `Query()` method is never called.

### Response Phase

After your connector returns data, the policy engine scans for sensitive data:
- PII (SSN, credit cards, Aadhaar, etc.) is automatically redacted
- The response includes `redacted: true` and `redacted_fields` metadata
- `policy_info` provides evaluation details

### Response Schema

Connector responses now include policy metadata:

```json
{
  "success": true,
  "data": [...],
  "redacted": true,
  "redacted_fields": ["data[0].ssn"],
  "policy_info": {
    "policies_evaluated": 15,
    "blocked": false,
    "redactions_applied": 1,
    "processing_time_ms": 3
  }
}
```

### SDK Integration

SDK consumers should handle the new fields:

```go
resp, err := client.MCPQuery(ctx, req)
if resp.Redacted {
    log.Printf("Fields redacted: %v", resp.RedactedFields)
}
```

See the [MCP Audit Logging & Policy Enforcement Guide](mcp-audit-logging.md) for details.

## Existing Connectors (Reference)

Study these connectors as implementation references:

| Connector | Type | Directory | Good Example For |
|-----------|------|-----------|------------------|
| `postgres` | Database | `platform/connectors/postgres/` | SQL queries, connection pooling |
| `redis` | Cache | `platform/connectors/redis/` | Simple operations |
| `http` | API | `platform/connectors/http/` | REST calls |
| `amadeus` | Travel API | `ee/connectors/amadeus/` | OAuth, complex external API |
| `salesforce` | CRM | `ee/connectors/salesforce/` | Enterprise auth |

Community connectors live under `platform/connectors/`; Enterprise connector implementations live under `ee/connectors/`.

## Connector SDK

The AxonFlow Connector SDK (`platform/connectors/sdk`) provides production-ready utilities so you don't have to build them per connector:

### Authentication Providers

```go
import "axonflow/platform/connectors/sdk"

// API Key, Basic, Bearer, OAuth 2.0, AWS IAM, chained providers
auth := sdk.NewAPIKeyAuth("key", sdk.APIKeyInHeader, "X-API-Key")
auth := sdk.NewBasicAuth(username, password)
auth := sdk.NewOAuthAuth(&sdk.OAuthConfig{ /* token URL, client creds, scopes */ })
auth := sdk.NewIAMAuth(&sdk.IAMCredentials{ /* access key, secret, region */ })
```

### Rate Limiting

```go
// Token bucket rate limiter
limiter := sdk.NewRateLimiter(100, 100) // 100 requests/sec, burst 100
limiter.Wait(ctx)

// Adaptive rate limiter (adjusts between a min and max rate)
adaptive := sdk.NewAdaptiveRateLimiter(10, 100, 100)

// Sliding window and multi-tenant variants
sw := sdk.NewSlidingWindowRateLimiter(time.Minute, 600)
mt := sdk.NewMultiTenantRateLimiter(100, 100)
mt.Wait(ctx, tenantID)
```

### Metrics Collection

```go
metrics := sdk.NewConnectorMetrics("myconnector")
metrics.RecordQuery(latency)
metrics.RecordQueryError()

// Prometheus export
exporter := sdk.NewPrometheusExporter("axonflow")
```

### BaseConnector

`sdk.NewBaseConnector(connType)` provides a reusable base with the metadata methods pre-wired, so your connector only implements the operations that differ.

Full SDK documentation: `platform/connectors/sdk/README.md` in the repository.

## Contributing

1. Fork the repository
2. Create your connector in `platform/connectors/yourconnector/`
3. Add tests (minimum 80% coverage)
4. Update documentation
5. Submit a pull request

### PR Checklist

- [ ] Implements all `base.Connector` interface methods
- [ ] Includes unit tests
- [ ] Includes integration tests (with skip for CI)
- [ ] Documented in this guide
- [ ] Added to `ValidateConfigFile` valid types
- [ ] Added config loader function
- [ ] Updated `registerConnectorFromConfig` switch

## Support

- GitHub Issues: [github.com/getaxonflow/axonflow/issues](https://github.com/getaxonflow/axonflow/issues)
- Discussions: [github.com/getaxonflow/axonflow/discussions](https://github.com/getaxonflow/axonflow/discussions)
- Documentation: [docs.getaxonflow.com](https://docs.getaxonflow.com)
