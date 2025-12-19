# AxonFlow Connector SDK

The AxonFlow Connector SDK provides a comprehensive framework for building MCP (Model Context Protocol) connectors. It includes authentication providers, rate limiting, retry logic, metrics collection, and testing utilities.

## Installation

```go
import "axonflow/platform/connectors/sdk"
```

## Quick Start

```go
package main

import (
    "context"
    "axonflow/platform/connectors/sdk"
    "axonflow/platform/connectors/base"
)

// Create a custom connector
type MyConnector struct {
    sdk.BaseConnector
    client *http.Client
}

func NewMyConnector() *MyConnector {
    return &MyConnector{
        BaseConnector: sdk.BaseConnector{
            ConnectorType:    "myconnector",
            ConnectorVersion: "1.0.0",
            ConnectorCaps:    []string{"query", "execute"},
        },
        client: &http.Client{},
    }
}
```

## Features

### Authentication Providers

The SDK includes multiple authentication providers:

```go
// API Key authentication
apiKeyAuth := sdk.NewAPIKeyAuth("your-api-key", "X-API-Key", sdk.APIKeyHeader)

// Basic authentication
basicAuth := sdk.NewBasicAuth("username", "password")

// Bearer token authentication
bearerAuth := sdk.NewBearerTokenAuth("your-token")

// OAuth 2.0 with auto-refresh
oauthAuth := sdk.NewOAuthAuth(tokenEndpoint, clientID, clientSecret, scopes)

// AWS IAM Signature V4
iamAuth := sdk.NewIAMAuth(accessKey, secretKey, region, service)

// Chained authentication (try multiple providers)
chainedAuth := sdk.NewChainedAuth(apiKeyAuth, bearerAuth)
```

### Rate Limiting

```go
// Token bucket rate limiter (100 requests per second)
limiter := sdk.NewRateLimiter(100, 100)

// Wait for permission
if err := limiter.Wait(ctx); err != nil {
    return err
}

// Adaptive rate limiter (adjusts based on response headers)
adaptive := sdk.NewAdaptiveRateLimiter(100, 100)
adaptive.UpdateFromHeaders(resp.Header)

// Multi-tenant rate limiting
mtLimiter := sdk.NewMultiTenantRateLimiter(func() *sdk.RateLimiter {
    return sdk.NewRateLimiter(10, 10)
})
mtLimiter.Wait(ctx, "tenant-123")
```

### Retry with Backoff

```go
// Default retry configuration
config := sdk.DefaultRetryConfig()

// Custom configuration
config := sdk.RetryConfig{
    MaxRetries:     5,
    InitialBackoff: 100 * time.Millisecond,
    MaxBackoff:     30 * time.Second,
    BackoffFactor:  2.0,
    Jitter:         0.1,
    RetryIf:        sdk.DefaultRetryable,
}

// Execute with retry
result, err := sdk.RetryWithBackoff(ctx, config, func(ctx context.Context) (string, error) {
    return callAPI()
})

// Circuit breaker pattern
cb := sdk.NewCircuitBreaker(5, 30*time.Second)
if cb.Allow() {
    result, err := callAPI()
    if err != nil {
        cb.RecordFailure()
    } else {
        cb.RecordSuccess()
    }
}
```

### Metrics Collection

```go
// Create metrics collector
metrics := sdk.NewConnectorMetrics("my-connector")

// Record operations
metrics.RecordQuery(150 * time.Millisecond)
metrics.RecordQueryError()
metrics.RecordExecute(50 * time.Millisecond)
metrics.RecordExecuteError()
metrics.RecordHealthCheck(10 * time.Millisecond, true)
metrics.RecordConnect()
metrics.RecordDisconnect()

// Get stats
stats := metrics.Stats()
fmt.Printf("Query count: %d\n", stats["query_count"])
fmt.Printf("Error rate: %.2f%%\n", stats["query_error_rate"].(float64)*100)

// Export to Prometheus
exporter := sdk.NewPrometheusExporter()
exporter.RegisterConnector("my-connector", metrics)
output := exporter.Export()
```

### Testing Framework

```go
// Mock connector for testing
mock := sdk.NewMockConnector()
mock.SetQueryResult(&base.QueryResult{
    Rows: []map[string]interface{}{{"id": 1}},
})
mock.SetExecuteResult(&base.CommandResult{
    Success: true,
})

// Test harness for integration testing
harness := sdk.NewTestHarness(realConnector)
harness.TestConnection(t, config)
harness.TestQuery(t, &base.Query{Statement: "SELECT 1"})
harness.TestExecute(t, &base.Command{Action: "INSERT"})

// Benchmark harness
benchHarness := sdk.NewBenchmarkHarness(connector)
results := benchHarness.BenchmarkQuery(b, &base.Query{Statement: "SELECT 1"})
```

## Available Connectors

### Community Connectors (platform/connectors/)

| Connector | Type | Description |
|-----------|------|-------------|
| S3 | `s3` | AWS S3 object storage |
| Azure Blob | `azureblob` | Azure Blob Storage |
| GCS | `gcs` | Google Cloud Storage |
| PostgreSQL | `postgres` | PostgreSQL database |
| MySQL | `mysql` | MySQL database |
| MongoDB | `mongodb` | MongoDB database |
| Redis | `redis` | Redis cache/database |
| HTTP | `http` | Generic HTTP/REST API |
| Cassandra | `cassandra` | Apache Cassandra |

### Enterprise Connectors (ee/platform/connectors/)

| Connector | Type | Description |
|-----------|------|-------------|
| HubSpot | `hubspot` | HubSpot CRM |
| Jira | `jira` | Atlassian Jira |
| ServiceNow | `servicenow` | ServiceNow ITSM |
| Salesforce | `salesforce` | Salesforce CRM |
| Snowflake | `snowflake` | Snowflake Data Cloud |
| Slack | `slack` | Slack messaging |
| Amadeus | `amadeus` | Amadeus travel API |

## Creating a New Connector

1. Create a new package under `platform/connectors/` (Community) or `ee/platform/connectors/` (Enterprise)

2. Implement the `base.Connector` interface:

```go
type Connector interface {
    Connect(ctx context.Context, config *ConnectorConfig) error
    Disconnect(ctx context.Context) error
    HealthCheck(ctx context.Context) (*HealthStatus, error)
    Query(ctx context.Context, query *Query) (*QueryResult, error)
    Execute(ctx context.Context, cmd *Command) (*CommandResult, error)
    Name() string
    Type() string
    Version() string
    Capabilities() []string
}
```

3. Use the SDK utilities:

```go
type MyConnector struct {
    config   *base.ConnectorConfig
    auth     sdk.AuthProvider
    limiter  *sdk.RateLimiter
    metrics  *sdk.ConnectorMetrics
}

func (c *MyConnector) Query(ctx context.Context, q *base.Query) (*base.QueryResult, error) {
    start := time.Now()

    // Rate limiting
    if err := c.limiter.Wait(ctx); err != nil {
        return nil, err
    }

    // Execute with retry
    result, err := sdk.RetryWithBackoff(ctx, sdk.DefaultRetryConfig(), func(ctx context.Context) (*base.QueryResult, error) {
        // Create and authenticate request
        req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
        if err := c.auth.Apply(req); err != nil {
            return nil, err
        }

        // Make request...
        return parseResponse(resp)
    })

    // Record metrics
    if err != nil {
        c.metrics.RecordQueryError()
    } else {
        c.metrics.RecordQuery(time.Since(start))
    }

    return result, err
}
```

4. Add tests using the testing framework:

```go
func TestMyConnector(t *testing.T) {
    conn := NewMyConnector()
    harness := sdk.NewTestHarness(conn)

    config := &base.ConnectorConfig{
        Name: "test",
        Credentials: map[string]string{"api_key": "test"},
    }

    harness.TestConnection(t, config)
    harness.TestQuery(t, &base.Query{Statement: "test"})
}
```

## License

Copyright 2025 AxonFlow. Licensed under the Apache License, Version 2.0.
