# AxonFlow LLM Provider SDK

The AxonFlow LLM Provider SDK provides a comprehensive framework for building custom LLM providers. It includes authentication providers, rate limiting, retry logic with exponential backoff, and circuit breaker patterns.

## Installation

```go
import "axonflow/platform/orchestrator/llm/sdk"
```

## Quick Start

### Using the Fluent Builder

```go
package main

import (
    "context"
    "os"

    "axonflow/platform/orchestrator/llm"
    "axonflow/platform/orchestrator/llm/sdk"
)

func main() {
    // Create a custom provider using the fluent builder
    provider := sdk.NewProviderBuilder("my-provider", llm.ProviderTypeCustom).
        WithModel("my-model-v1").
        WithEndpoint("https://api.myprovider.com/v1").
        WithAuth(sdk.NewAPIKeyAuth(os.Getenv("MY_API_KEY"))).
        WithRateLimiter(sdk.NewRateLimiter(100, 100)).
        WithRetry(sdk.DefaultRetryConfig()).
        WithCompleteFunc(myCompletionHandler).
        Build()

    // Use the provider
    ctx := context.Background()
    resp, err := provider.Complete(ctx, llm.CompletionRequest{
        Prompt:    "Hello, world!",
        MaxTokens: 100,
    })
}

func myCompletionHandler(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
    // Your implementation here
    return &llm.CompletionResponse{
        Content: "Response from custom provider",
        Model:   req.Model,
        Usage: llm.UsageStats{
            PromptTokens:     10,
            CompletionTokens: 20,
            TotalTokens:      30,
        },
    }, nil
}
```

### Implementing Provider Interface Directly

For complex providers, implement the `llm.Provider` interface:

```go
type MyProvider struct {
    name      string
    client    *http.Client
    auth      sdk.AuthProvider
    limiter   *sdk.RateLimiter
    endpoint  string
}

func (p *MyProvider) Name() string { return p.name }
func (p *MyProvider) Type() llm.ProviderType { return llm.ProviderTypeCustom }

func (p *MyProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
    // Apply rate limiting
    if err := p.limiter.Wait(ctx); err != nil {
        return nil, err
    }

    // Build HTTP request
    body := buildRequestBody(req)
    httpReq, _ := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/completions", body)
    p.auth.Apply(httpReq)
    httpReq.Header.Set("Content-Type", "application/json")

    // Execute with retry
    return sdk.RetryWithBackoff(ctx, *sdk.DefaultRetryConfig(), func(ctx context.Context) (*llm.CompletionResponse, error) {
        resp, err := p.client.Do(httpReq)
        if err != nil {
            return nil, err
        }
        defer resp.Body.Close()

        return parseResponse(resp)
    })
}

func (p *MyProvider) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
    // Implement health check
}

func (p *MyProvider) Capabilities() []llm.Capability {
    return []llm.Capability{llm.CapabilityChat, llm.CapabilityCompletion}
}

func (p *MyProvider) SupportsStreaming() bool { return false }

func (p *MyProvider) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
    // Implement cost estimation
}
```

## Features

### Authentication Providers

The SDK supports multiple authentication methods:

```go
// API Key in Authorization header (Bearer token) - most common for LLMs
auth := sdk.NewAPIKeyAuth("sk-your-api-key")

// API Key in custom header
auth := sdk.NewAPIKeyAuthWithHeader("sk-xxx", "X-API-Key")

// API Key as query parameter
auth := sdk.NewAPIKeyAuthWithQuery("sk-xxx", "api_key")

// Basic authentication
auth := sdk.NewBasicAuth("username", "password")

// Bearer token
auth := sdk.NewBearerTokenAuth("your-token")

// No authentication (for local/internal providers like Ollama)
auth := sdk.NewNoAuth()

// Chain multiple auth providers
auth := sdk.NewChainedAuth(apiKeyAuth, customHeaderAuth)
```

### Rate Limiting

Token bucket rate limiting to respect API quotas:

```go
// 100 requests per second with burst of 100
limiter := sdk.NewRateLimiter(100, 100)

// Wait for permission (blocks until available)
if err := limiter.Wait(ctx); err != nil {
    return err // Context cancelled
}

// Try without blocking
if !limiter.TryAcquire() {
    return errors.New("rate limited")
}

// Check available tokens
available := limiter.Available()

// Dynamically adjust rate
limiter.SetRate(50)    // Reduce to 50 rps
limiter.SetBurst(200)  // Increase burst capacity
```

For multi-tenant applications:

```go
// Create per-tenant rate limiters
mtLimiter := sdk.NewMultiTenantRateLimiter(func() *sdk.RateLimiter {
    return sdk.NewRateLimiter(10, 10) // 10 rps per tenant
})

// Wait for specific tenant
err := mtLimiter.Wait(ctx, "tenant-123")

// Or try without blocking
if mtLimiter.TryAcquire("tenant-456") {
    // Proceed with request
}

// Clean up inactive tenants
mtLimiter.RemoveTenant("tenant-123")
```

### Retry with Exponential Backoff

Automatic retry with configurable backoff:

```go
// Use default configuration
config := sdk.DefaultRetryConfig()

// Or customize
config := sdk.RetryConfig{
    MaxRetries:     5,
    InitialBackoff: 100 * time.Millisecond,
    MaxBackoff:     30 * time.Second,
    BackoffFactor:  2.0,
    Jitter:         0.1,  // 10% jitter to avoid thundering herd
    RetryIf:        sdk.DefaultRetryable,
}

// Execute with retry
result, err := sdk.RetryWithBackoff(ctx, config, func(ctx context.Context) (*Response, error) {
    return callAPI(ctx)
})

// Custom retry conditions
config.RetryIf = func(err error) bool {
    // Only retry rate limit errors
    if apiErr, ok := err.(*sdk.APIError); ok {
        return apiErr.StatusCode == 429
    }
    return false
}
```

### Circuit Breaker

Prevent cascading failures:

```go
// Open circuit after 5 failures, reset after 30 seconds
cb := sdk.NewCircuitBreaker(5, 30*time.Second)

if cb.Allow() {
    resp, err := callAPI()
    if err != nil {
        cb.RecordFailure()
        // Circuit opens after threshold
    } else {
        cb.RecordSuccess()
        // Circuit resets to closed
    }
} else {
    // Circuit is open, fail fast
    return errors.New("service unavailable")
}

// Check circuit state
switch cb.State() {
case sdk.CircuitClosed:
    // Normal operation
case sdk.CircuitOpen:
    // Blocking requests
case sdk.CircuitHalfOpen:
    // Testing with a single request
}

// Manual reset if needed
cb.Reset()
```

## Registering with the Factory

Register your custom provider with the factory system:

```go
// Register the factory function
llm.RegisterFactory(llm.ProviderTypeCustom, func(config llm.ProviderConfig) (llm.Provider, error) {
    return sdk.NewProviderBuilder(config.Name, llm.ProviderTypeCustom).
        WithModel(config.Model).
        WithEndpoint(config.Endpoint).
        WithAuth(sdk.NewAPIKeyAuth(config.APIKey)).
        WithRateLimiter(sdk.NewRateLimiter(100, 100)).
        WithRetry(sdk.DefaultRetryConfig()).
        WithCompleteFunc(myHandler).
        Build(), nil
})

// Now it can be used via the registry
registry := llm.NewRegistry()
registry.Register(ctx, &llm.ProviderConfig{
    Name:     "my-custom-llm",
    Type:     llm.ProviderTypeCustom,
    APIKey:   os.Getenv("MY_API_KEY"),
    Model:    "my-model-v1",
    Endpoint: "https://api.myprovider.com",
    Enabled:  true,
})

provider, _ := registry.Get(ctx, "my-custom-llm")
```

## Configuration via YAML

Providers can be configured via YAML file with environment variable expansion:

```yaml
# axonflow.yaml
version: "1.0"

llm_providers:
  my_custom_provider:
    enabled: true
    display_name: "My Custom LLM"
    config:
      model: "my-model-v1"
      endpoint: "https://api.myprovider.com/v1"
      max_tokens: 4096
    credentials:
      api_key: ${MY_PROVIDER_API_KEY}
    priority: 10
    weight: 0.5

  ollama_local:
    enabled: true
    display_name: "Ollama (Local)"
    config:
      endpoint: ${OLLAMA_ENDPOINT:-http://localhost:11434}
      model: ${OLLAMA_MODEL:-llama3.1:70b}
    priority: 5
    weight: 0.3
```

## Built-in Provider Support

| Provider | Type | Edition | Description |
|----------|------|---------|-------------|
| OpenAI | `openai` | Community | GPT-4, GPT-3.5-turbo |
| Anthropic | `anthropic` | Community | Claude 3.5 Sonnet, Claude 3 Opus |
| Ollama | `ollama` | Community | Self-hosted models |
| AWS Bedrock | `bedrock` | Enterprise | Claude on AWS, Llama, Titan |
| Google Gemini | `gemini` | Enterprise | Gemini Pro, Gemini Ultra |
| Custom | `custom` | Enterprise | Your own implementations |

> **Note:** Community edition includes OpenAI, Anthropic, and Ollama providers. Enterprise providers (Bedrock, Gemini, Custom) require a license.

## Best Practices

1. **Always use rate limiting** to respect API quotas
2. **Implement retries** for transient failures (rate limits, 5xx errors)
3. **Use circuit breakers** for production deployments
4. **Set appropriate timeouts** - LLM calls can be slow
5. **Implement health checks** to enable automatic failover
6. **Log errors** but don't expose API keys in logs

## Testing

Use the test utilities for unit testing:

```go
func TestMyProvider(t *testing.T) {
    // Create a mock completion function
    provider := sdk.NewProviderBuilder("test", llm.ProviderTypeCustom).
        WithCompleteFunc(func(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
            return &llm.CompletionResponse{
                Content: "mock response",
                Model:   req.Model,
            }, nil
        }).
        Build()

    ctx := context.Background()
    resp, err := provider.Complete(ctx, llm.CompletionRequest{
        Prompt: "test",
    })

    require.NoError(t, err)
    assert.Equal(t, "mock response", resp.Content)
}
```

## Related Documentation

- [LLM Provider Architecture Guide](../../docs/LLM_PROVIDER_ARCHITECTURE.md) - Deep dive into internals
- [LLM Provider Configuration](../../docs/LLM_PROVIDER_CONFIGURATION.md) - User configuration guide
- [SDK Integration Guide](../../docs/sdk/LLM_SDK_GUIDE.md) - Complete SDK usage examples

## License

Copyright 2025 AxonFlow. Licensed under the Apache License, Version 2.0.
