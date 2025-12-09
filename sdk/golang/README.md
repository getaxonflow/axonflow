# AxonFlow SDK for Go

Enterprise-grade Go SDK for AxonFlow AI governance platform. Add invisible AI governance to your applications with production-ready features including retry logic, caching, fail-open strategy, and debug mode.

## Installation

```bash
go get github.com/axonflow/sdk-go
```

Or copy the `client-sdk` directory into your project.

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    client_sdk "your-project/client-sdk"
)

func main() {
    // Simple initialization (backward compatible)
    client := client_sdk.NewAxonFlowClient(
        "http://10.0.2.67:8080",  // Agent URL
        "your-client-id",          // Client ID
        "your-client-secret",      // Client Secret
    )

    // Execute a governed query
    resp, err := client.ExecuteQuery(
        "user-token",
        "What is the capital of France?",
        "chat",
        map[string]interface{}{},
    )

    if err != nil {
        log.Fatalf("Query failed: %v", err)
    }

    if resp.Blocked {
        log.Printf("Request blocked: %s", resp.BlockReason)
        return
    }

    fmt.Printf("Result: %s\n", resp.Data)
}
```

### Advanced Configuration

```go
import client_sdk "your-project/client-sdk"

// Full configuration with all features
client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
    AgentURL:     "http://10.0.2.67:8080",
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    Mode:         "production",  // or "sandbox"
    Debug:        true,           // Enable debug logging
    Timeout:      60 * time.Second,

    // Retry configuration (exponential backoff)
    Retry: client_sdk.RetryConfig{
        Enabled:      true,
        MaxAttempts:  3,
        InitialDelay: 1 * time.Second,
    },

    // Cache configuration (in-memory with TTL)
    Cache: client_sdk.CacheConfig{
        Enabled: true,
        TTL:     60 * time.Second,
    },
})
```

### Sandbox Mode (Testing)

```go
// Quick sandbox client for testing
client := client_sdk.Sandbox("demo-key")

resp, err := client.ExecuteQuery(
    "",
    "Test query with sensitive data: SSN 123-45-6789",
    "chat",
    map[string]interface{}{},
)

// In sandbox, this will be blocked/redacted
if resp.Blocked {
    fmt.Printf("Blocked: %s\n", resp.BlockReason)
}
```

## Features

### ✅ Retry Logic with Exponential Backoff

Automatic retry on transient failures with exponential backoff:

```go
client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
    AgentURL: "http://10.0.2.67:8080",
    ClientID: "your-client-id",
    ClientSecret: "your-secret",
    Retry: client_sdk.RetryConfig{
        Enabled:      true,
        MaxAttempts:  3,           // Retry up to 3 times
        InitialDelay: 1 * time.Second,  // 1s, 2s, 4s backoff
    },
})

// Automatically retries on 5xx errors or network failures
resp, err := client.ExecuteQuery(...)
```

### ✅ In-Memory Caching with TTL

Reduce latency and load with intelligent caching:

```go
client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
    AgentURL: "http://10.0.2.67:8080",
    ClientID: "your-client-id",
    ClientSecret: "your-secret",
    Cache: client_sdk.CacheConfig{
        Enabled: true,
        TTL:     60 * time.Second,  // Cache for 60 seconds
    },
})

// First call: hits AxonFlow
resp1, _ := client.ExecuteQuery("token", "query", "chat", nil)

// Second call (within 60s): served from cache
resp2, _ := client.ExecuteQuery("token", "query", "chat", nil)
```

### ✅ Fail-Open Strategy (Production Mode)

Never block your users if AxonFlow is unavailable:

```go
client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
    AgentURL: "http://10.0.2.67:8080",
    ClientID: "your-client-id",
    ClientSecret: "your-secret",
    Mode:     "production",  // Fail-open in production
    Debug:    true,
})

// If AxonFlow is unavailable, request proceeds with warning
resp, err := client.ExecuteQuery(...)
// err == nil, resp.Success == true, resp.Error contains warning
```

### ✅ Debug Mode with Structured Logging

Detailed logging for development and troubleshooting:

```go
client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
    AgentURL: "http://10.0.2.67:8080",
    ClientID: "your-client-id",
    ClientSecret: "your-secret",
    Debug:    true,  // Enable debug logging
})

// Logs:
// [AxonFlow] Client initialized - Mode: production, Endpoint: http://10.0.2.67:8080
// [AxonFlow] Sending request - Type: chat, Query: What is the capital...
// [AxonFlow] Response received - Success: true, Duration: 45ms
```

## Gateway Mode (Direct LLM Calls with Governance)

Gateway Mode allows you to make LLM calls directly to your provider while still using AxonFlow for policy enforcement and audit logging. This is ideal when you need:
- Maximum control over LLM calls
- Use of your own API keys
- Lower latency by avoiding proxy overhead

### Pre-Check Before LLM Call

```go
// Step 1: Get policy approval before making LLM call
ctx, err := client.GetPolicyApprovedContext(
    userToken,                      // User JWT token
    []string{"postgres"},           // MCP connectors for data
    "Find patients with diabetes",  // Query/prompt
    nil,                            // Additional context
)
if err != nil {
    log.Fatalf("Pre-check failed: %v", err)
}

if !ctx.Approved {
    log.Printf("Request blocked: %s", ctx.BlockReason)
    return
}

// Use ctx.ApprovedData to build your LLM prompt
prompt := buildPromptWithData(ctx.ApprovedData, query)
```

### Make LLM Call and Audit

```go
// Step 2: Make LLM call directly (using your API keys)
startTime := time.Now()
response, err := openai.Chat(prompt)
latencyMs := time.Since(startTime).Milliseconds()

// Step 3: Report back for audit
audit, err := client.AuditLLMCall(
    ctx.ContextID,                  // From pre-check
    summarize(response),            // Brief summary (not full response)
    "openai",                       // Provider
    "gpt-4",                        // Model
    axonflow.TokenUsage{
        PromptTokens:     response.Usage.PromptTokens,
        CompletionTokens: response.Usage.CompletionTokens,
        TotalTokens:      response.Usage.TotalTokens,
    },
    latencyMs,
    map[string]interface{}{         // Optional metadata
        "session_id": sessionID,
    },
)
```

### Complete Gateway Mode Example

```go
func handleQuery(userToken, query string) (string, error) {
    // Pre-check
    ctx, err := client.GetPolicyApprovedContext(userToken, nil, query, nil)
    if err != nil {
        return "", err
    }
    if !ctx.Approved {
        return "", fmt.Errorf("blocked: %s", ctx.BlockReason)
    }

    // LLM call
    startTime := time.Now()
    resp, err := openai.Chat(query)
    if err != nil {
        return "", err
    }

    // Audit
    client.AuditLLMCall(
        ctx.ContextID,
        resp.Content[:100],
        "openai", "gpt-4",
        axonflow.TokenUsage{TotalTokens: resp.Usage.Total},
        time.Since(startTime).Milliseconds(),
        nil,
    )

    return resp.Content, nil
}
```

## MCP Connector Marketplace

Integrate with external data sources using AxonFlow's MCP (Model Context Protocol) connectors:

### List Available Connectors

```go
connectors, err := client.ListConnectors()
if err != nil {
    log.Fatalf("Failed to list connectors: %v", err)
}

for _, conn := range connectors {
    fmt.Printf("Connector: %s (%s)\n", conn.Name, conn.Type)
    fmt.Printf("  Description: %s\n", conn.Description)
    fmt.Printf("  Installed: %v\n", conn.Installed)
    fmt.Printf("  Capabilities: %v\n", conn.Capabilities)
}
```

### Install a Connector

```go
err := client.InstallConnector(client_sdk.ConnectorInstallRequest{
    ConnectorID: "amadeus-travel",
    Name:        "amadeus-prod",
    TenantID:    "your-tenant-id",
    Options: map[string]interface{}{
        "environment": "production",
    },
    Credentials: map[string]string{
        "api_key":    "your-amadeus-key",
        "api_secret": "your-amadeus-secret",
    },
})

if err != nil {
    log.Fatalf("Failed to install connector: %v", err)
}

fmt.Println("Connector installed successfully!")
```

### Query a Connector

```go
// Query the Amadeus connector for flight information
resp, err := client.QueryConnector(
    "amadeus-prod",
    "Find flights from Paris to Amsterdam on Dec 15",
    map[string]interface{}{
        "origin":      "CDG",
        "destination": "AMS",
        "date":        "2025-12-15",
    },
)

if err != nil {
    log.Fatalf("Connector query failed: %v", err)
}

if resp.Success {
    fmt.Printf("Flight data: %v\n", resp.Data)
} else {
    fmt.Printf("Query failed: %s\n", resp.Error)
}
```

## Multi-Agent Planning (MAP)

Generate and execute complex multi-step plans using AI agent orchestration:

### Generate a Plan

```go
// Generate a travel planning workflow
plan, err := client.GeneratePlan(
    "Plan a 3-day trip to Paris with moderate budget",
    "travel",  // Domain hint (optional)
)

if err != nil {
    log.Fatalf("Plan generation failed: %v", err)
}

fmt.Printf("Generated plan %s with %d steps\n", plan.PlanID, len(plan.Steps))
fmt.Printf("Complexity: %d, Parallel: %v\n", plan.Complexity, plan.Parallel)

for i, step := range plan.Steps {
    fmt.Printf("  Step %d: %s (%s)\n", i+1, step.Name, step.Type)
    fmt.Printf("    Description: %s\n", step.Description)
    fmt.Printf("    Agent: %s\n", step.Agent)
    if len(step.DependsOn) > 0 {
        fmt.Printf("    Depends on: %v\n", step.DependsOn)
    }
}
```

### Execute a Plan

```go
// Execute the generated plan
execResp, err := client.ExecutePlan(plan.PlanID)
if err != nil {
    log.Fatalf("Plan execution failed: %v", err)
}

fmt.Printf("Plan Status: %s\n", execResp.Status)
fmt.Printf("Duration: %s\n", execResp.Duration)

if execResp.Status == "completed" {
    fmt.Printf("Result:\n%s\n", execResp.Result)

    // Access individual step results
    for stepID, result := range execResp.StepResults {
        fmt.Printf("  %s: %v\n", stepID, result)
    }
} else if execResp.Status == "failed" {
    fmt.Printf("Error: %s\n", execResp.Error)
}
```

### Check Plan Status

```go
// For long-running plans, check status periodically
status, err := client.GetPlanStatus(plan.PlanID)
if err != nil {
    log.Fatalf("Failed to get plan status: %v", err)
}

fmt.Printf("Plan Status: %s\n", status.Status)
if status.Status == "running" {
    fmt.Println("Plan is still executing...")
}
```

### Complete Example: Trip Planning with MAP

```go
package main

import (
    "fmt"
    "log"
    client_sdk "your-project/client-sdk"
)

func main() {
    // Initialize client
    client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
        AgentURL:     "http://10.0.2.67:8080",
        ClientID:     "travel-demo",
        ClientSecret: "travel-secret-key",
        Debug:        true,
    })

    // 1. Generate multi-agent plan
    plan, err := client.GeneratePlan(
        "Plan a 3-day trip to Paris for 2 people with moderate budget",
        "travel",
    )
    if err != nil {
        log.Fatalf("Plan generation failed: %v", err)
    }

    fmt.Printf("✅ Generated plan with %d steps (parallel: %v)\n",
        len(plan.Steps), plan.Parallel)

    // 2. Execute the plan
    fmt.Println("\n🚀 Executing plan...")
    execResp, err := client.ExecutePlan(plan.PlanID)
    if err != nil {
        log.Fatalf("Plan execution failed: %v", err)
    }

    // 3. Display results
    if execResp.Status == "completed" {
        fmt.Printf("\n✅ Plan completed in %s\n", execResp.Duration)
        fmt.Printf("\n📋 Complete Itinerary:\n%s\n", execResp.Result)
    } else {
        fmt.Printf("\n❌ Plan failed: %s\n", execResp.Error)
    }
}
```

## Health Check

Check if AxonFlow Agent is available:

```go
err := client.HealthCheck()
if err != nil {
    log.Printf("AxonFlow Agent is unhealthy: %v", err)
} else {
    log.Println("AxonFlow Agent is healthy")
}
```

## VPC Private Endpoint (Low-Latency)

For applications running in AWS VPC, use the private endpoint for sub-10ms latency:

```go
client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
    AgentURL:     "https://10.0.2.67:8443",  // VPC private endpoint
    ClientID:     "your-client-id",
    ClientSecret: "your-secret",
    Mode:         "production",
})

// Enjoy sub-10ms P99 latency vs ~100ms over public internet
```

**Performance:**
- Public endpoint: ~100ms (internet routing)
- VPC private endpoint: <10ms P99 (intra-VPC routing)

**Note:** VPC endpoints require AWS VPC peering setup with AxonFlow infrastructure.

## Error Handling

```go
resp, err := client.ExecuteQuery(...)
if err != nil {
    // Network errors, timeouts, or AxonFlow unavailability
    log.Printf("Request failed: %v", err)
    return
}

if resp.Blocked {
    // Policy violation - request blocked by governance rules
    log.Printf("Request blocked: %s", resp.BlockReason)
    log.Printf("Policies evaluated: %v", resp.PolicyInfo.PoliciesEvaluated)
    return
}

if !resp.Success {
    // Request succeeded but returned error from downstream
    log.Printf("Query failed: %s", resp.Error)
    return
}

// Success - use resp.Data or resp.Result
fmt.Printf("Result: %v\n", resp.Data)
```

## Production Best Practices

1. **Environment Variables**: Never hardcode credentials
   ```go
   client := client_sdk.NewAxonFlowClient(
       os.Getenv("AXONFLOW_AGENT_URL"),
       os.Getenv("AXONFLOW_CLIENT_ID"),
       os.Getenv("AXONFLOW_CLIENT_SECRET"),
   )
   ```

2. **Fail-Open in Production**: Use `Mode: "production"` to fail-open if AxonFlow is unavailable

3. **Enable Caching**: Reduce latency for repeated queries

4. **Enable Retry**: Handle transient failures automatically

5. **Debug in Development**: Use `Debug: true` during development, disable in production

6. **Health Checks**: Monitor AxonFlow availability with periodic health checks

## Configuration Reference

### AxonFlowConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `AgentURL` | `string` | Required | AxonFlow Agent endpoint URL |
| `ClientID` | `string` | Required | Client ID for authentication |
| `ClientSecret` | `string` | Required | Client secret for authentication |
| `Mode` | `string` | `"production"` | `"production"` or `"sandbox"` |
| `Debug` | `bool` | `false` | Enable debug logging |
| `Timeout` | `time.Duration` | `60s` | Request timeout |
| `Retry.Enabled` | `bool` | `true` | Enable retry logic |
| `Retry.MaxAttempts` | `int` | `3` | Maximum retry attempts |
| `Retry.InitialDelay` | `time.Duration` | `1s` | Initial retry delay (exponential backoff) |
| `Cache.Enabled` | `bool` | `true` | Enable caching |
| `Cache.TTL` | `time.Duration` | `60s` | Cache time-to-live |

## Support

- Documentation: https://docs.axonflow.com
- Email: support@axonflow.com
- GitHub: https://github.com/axonflow/sdk-go

## License

MIT
