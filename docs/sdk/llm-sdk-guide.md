# LLM Provider SDK Integration Guide

This guide shows how to integrate AxonFlow's LLM provider system into your Go applications.

## Installation

```bash
go get github.com/getaxonflow/axonflow/platform/orchestrator/llm
```

## Quick Start

### Basic Usage (Single Provider)

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/getaxonflow/axonflow/platform/orchestrator/llm"
)

func main() {
    ctx := context.Background()

    // Create a registry
    registry := llm.NewRegistry()

    // Register the OpenAI factory (built-in)
    llm.RegisterFactory(llm.ProviderTypeOpenAI, llm.DefaultOpenAIFactory)

    // Register provider configuration
    config := &llm.ProviderConfig{
        Name:    "openai-primary",
        Type:    llm.ProviderTypeOpenAI,
        APIKey:  "sk-...", // From environment or secret manager
        Model:   "gpt-4",
        Enabled: true,
    }

    if err := registry.Register(ctx, config); err != nil {
        log.Fatal(err)
    }

    // Get provider and make a request
    provider, err := registry.Get(ctx, "openai-primary")
    if err != nil {
        log.Fatal(err)
    }

    response, err := provider.Complete(ctx, llm.CompletionRequest{
        Prompt:    "What is the capital of France?",
        MaxTokens: 100,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Response: %s\n", response.Content)
    fmt.Printf("Tokens used: %d\n", response.Usage.TotalTokens)
}
```

### Multi-Provider Setup

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/getaxonflow/axonflow/platform/orchestrator/llm"
)

func main() {
    ctx := context.Background()

    // Create factory manager
    fm := llm.NewFactoryManager()
    fm.Register(llm.ProviderTypeOpenAI, llm.DefaultOpenAIFactory)
    fm.Register(llm.ProviderTypeAnthropic, llm.DefaultAnthropicFactory)
    fm.Register(llm.ProviderTypeOllama, llm.DefaultOllamaFactory)

    // Create registry with factory manager
    registry := llm.NewRegistry(llm.WithFactoryManager(fm))

    // Register multiple providers
    providers := []llm.ProviderConfig{
        {
            Name:    "openai-prod",
            Type:    llm.ProviderTypeOpenAI,
            APIKey:  os.Getenv("OPENAI_API_KEY"),
            Model:   "gpt-4",
            Enabled: true,
        },
        {
            Name:    "anthropic-prod",
            Type:    llm.ProviderTypeAnthropic,
            APIKey:  os.Getenv("ANTHROPIC_API_KEY"),
            Model:   "claude-3-5-sonnet-20241022",
            Enabled: true,
        },
        {
            Name:    "ollama-local",
            Type:    llm.ProviderTypeOllama,
            BaseURL: "http://localhost:11434",
            Model:   "llama3.1",
            Enabled: true,
        },
    }

    for _, cfg := range providers {
        if err := registry.Register(ctx, &cfg); err != nil {
            log.Printf("Warning: failed to register %s: %v", cfg.Name, err)
        }
    }

    // Create router for intelligent routing
    router := llm.NewRouter(
        llm.WithRouterRegistry(registry),
        llm.WithDefaultWeights(map[string]float64{
            "openai-prod":    0.5,
            "anthropic-prod": 0.3,
            "ollama-local":   0.2,
        }),
    )

    // Route request with automatic load balancing
    response, info, err := router.RouteRequest(ctx, llm.CompletionRequest{
        Prompt:    "Explain quantum computing in simple terms",
        MaxTokens: 500,
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Provider: %s, Model: %s, Latency: %dms",
        info.ProviderName, info.Model, info.ResponseTimeMs)
    log.Printf("Response: %s", response.Content)
}
```

## Provider Configuration

### ProviderConfig Fields

```go
type ProviderConfig struct {
    // Required
    Name    string       // Unique identifier
    Type    ProviderType // Provider type (openai, anthropic, etc.)

    // Authentication (one of these required for most providers)
    APIKey          string // Direct API key
    APIKeySecretARN string // AWS Secrets Manager ARN

    // Connection
    BaseURL string // Custom API endpoint (for Ollama, proxies)
    Model   string // Default model
    Region  string // AWS region (for Bedrock)

    // Behavior
    Enabled        bool // Enable/disable provider
    Priority       int  // Routing priority (higher = preferred)
    Weight         int  // Routing weight (0-100)
    RateLimit      int  // Requests per minute (0 = unlimited)
    TimeoutSeconds int  // Request timeout

    // Custom settings
    Settings map[string]any // Provider-specific settings
}
```

### Provider-Specific Configuration

#### OpenAI

```go
config := &llm.ProviderConfig{
    Name:   "openai",
    Type:   llm.ProviderTypeOpenAI,
    APIKey: os.Getenv("OPENAI_API_KEY"),
    Model:  "gpt-4-turbo", // or gpt-4, gpt-3.5-turbo
    Settings: map[string]any{
        "organization": "org-xxx", // Optional org ID
    },
}
```

#### Anthropic

```go
config := &llm.ProviderConfig{
    Name:   "anthropic",
    Type:   llm.ProviderTypeAnthropic,
    APIKey: os.Getenv("ANTHROPIC_API_KEY"),
    Model:  "claude-3-5-sonnet-20241022",
}
```

#### AWS Bedrock

```go
config := &llm.ProviderConfig{
    Name:   "bedrock",
    Type:   llm.ProviderTypeBedrock,
    Region: "us-east-1",
    Model:  "anthropic.claude-3-5-sonnet-20240620-v1:0",
    // Authentication via IAM role (no API key needed)
}
```

#### Ollama (Self-Hosted)

```go
config := &llm.ProviderConfig{
    Name:    "ollama",
    Type:    llm.ProviderTypeOllama,
    BaseURL: "http://localhost:11434",
    Model:   "llama3.1",
    // No API key needed for local Ollama
}
```

## Router Features

### Weighted Load Balancing

```go
router := llm.NewRouter(
    llm.WithRouterRegistry(registry),
    llm.WithDefaultWeights(map[string]float64{
        "openai":    0.6, // 60% of traffic
        "anthropic": 0.3, // 30% of traffic
        "ollama":    0.1, // 10% of traffic
    }),
)
```

### Preferred Provider

```go
response, info, err := router.RouteRequest(ctx, req,
    llm.WithPreferredProvider("anthropic"),
)
// Will use anthropic if healthy, otherwise fails over
```

### Request-Specific Weights

```go
response, info, err := router.RouteRequest(ctx, req,
    llm.WithRouteWeights(map[string]float64{
        "ollama": 1.0, // Force ollama for this request
    }),
)
```

### Disable Failover

```go
response, info, err := router.RouteRequest(ctx, req,
    llm.WithPreferredProvider("openai"),
    llm.WithDisableFailover(), // Error if openai fails
)
```

## Health Monitoring

### Start Periodic Health Checks

```go
// Check provider health every 30 seconds
registry.StartPeriodicHealthCheck(ctx, 30*time.Second)
```

### Manual Health Check

```go
// Check all providers
registry.HealthCheck(ctx)

// Get health status for specific provider
result := registry.GetHealthResult("openai")
switch result.Status {
case llm.HealthStatusHealthy:
    log.Println("Provider is healthy")
case llm.HealthStatusDegraded:
    log.Println("Provider is degraded, consider failover")
case llm.HealthStatusUnhealthy:
    log.Println("Provider is unhealthy, excluded from routing")
}
```

### Provider Status Dashboard

```go
status := router.GetProviderStatus(ctx)
for name, ps := range status {
    fmt.Printf("%-20s | %-10s | Requests: %5d | Errors: %3d | Latency: %.0fms\n",
        name,
        ps.Health.Status,
        ps.Metrics.RequestCount,
        ps.Metrics.ErrorCount,
        ps.Metrics.AvgResponseTime,
    )
}
```

## Database Persistence

### Setup PostgreSQL Storage

```go
import (
    "database/sql"
    _ "github.com/lib/pq"
)

db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
if err != nil {
    log.Fatal(err)
}
defer db.Close()

storage := llm.NewPostgresStorage(db)
registry := llm.NewRegistry(llm.WithStorage(storage))
```

### Set Tenant Context (Multi-Tenant)

```go
// Set tenant ID for RLS (Row Level Security)
_, err := db.Exec("SELECT set_config('app.current_org_id', $1, false)", tenantID)
if err != nil {
    log.Fatal(err)
}

// Now all operations are scoped to this tenant
registry.Register(ctx, config)
```

## Error Handling

### Registry Errors

```go
err := registry.Register(ctx, config)
if err != nil {
    var regErr *llm.RegistryError
    if errors.As(err, &regErr) {
        switch regErr.Code {
        case llm.ErrRegistryNotFound:
            log.Printf("Provider not found: %s", regErr.ProviderName)
        case llm.ErrRegistryDuplicate:
            log.Printf("Provider already exists: %s", regErr.ProviderName)
        case llm.ErrRegistryInvalidConfig:
            log.Printf("Invalid config: %s", regErr.Message)
        case llm.ErrRegistryLicenseRequired:
            log.Printf("License upgrade required: %s", regErr.Message)
        default:
            log.Printf("Registry error: %v", err)
        }
    }
}
```

### License Errors

```go
err := registry.Register(ctx, &llm.ProviderConfig{
    Name: "bedrock",
    Type: llm.ProviderTypeBedrock,
    // ... Bedrock requires Enterprise license
})

var licErr *llm.LicenseError
if errors.As(err, &licErr) {
    log.Printf("Provider %s requires %s tier (you have: %s)",
        licErr.ProviderType,
        licErr.RequiredTier,
        licErr.CurrentTier,
    )
    log.Println("Upgrade at https://getaxonflow.com/enterprise")
}
```

## Custom Provider Implementation

### Implement Provider Interface

```go
type MyCustomProvider struct {
    name   string
    client *http.Client
    apiKey string
}

func (p *MyCustomProvider) Name() string {
    return p.name
}

func (p *MyCustomProvider) Type() llm.ProviderType {
    return llm.ProviderTypeCustom
}

func (p *MyCustomProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
    // Implement your completion logic
    return &llm.CompletionResponse{
        Content: "response from custom provider",
        Model:   "custom-model",
        Usage: llm.UsageStats{
            PromptTokens:     10,
            CompletionTokens: 20,
            TotalTokens:      30,
        },
    }, nil
}

func (p *MyCustomProvider) HealthCheck(ctx context.Context) (*llm.HealthCheckResult, error) {
    // Implement health check (e.g., ping API)
    return &llm.HealthCheckResult{
        Status:      llm.HealthStatusHealthy,
        LastChecked: time.Now(),
    }, nil
}

func (p *MyCustomProvider) Capabilities() []llm.Capability {
    return []llm.Capability{llm.CapabilityChat, llm.CapabilityCompletion}
}

func (p *MyCustomProvider) SupportsStreaming() bool {
    return false
}

func (p *MyCustomProvider) EstimateCost(req llm.CompletionRequest) *llm.CostEstimate {
    return &llm.CostEstimate{
        InputCostPer1K:   0.001,
        OutputCostPer1K:  0.002,
        TotalEstimate:    0.003,
        Currency:         "USD",
    }
}
```

### Register Custom Factory

```go
llm.RegisterFactory(llm.ProviderTypeCustom, func(config llm.ProviderConfig) (llm.Provider, error) {
    return &MyCustomProvider{
        name:   config.Name,
        apiKey: config.APIKey,
        client: &http.Client{Timeout: 30 * time.Second},
    }, nil
})
```

## License Tiers

### Check Provider Availability

```go
// Check if provider is available in OSS
if llm.IsOSSProvider(llm.ProviderTypeOpenAI) {
    fmt.Println("OpenAI is available in OSS")
}

// Get all OSS providers
ossProviders := llm.GetOSSProviders()
// Returns: [ollama, openai, anthropic]

// Get enterprise-only providers
entProviders := llm.GetEnterpriseProviders()
// Returns: [bedrock, gemini, custom]
```

### Validate Provider Access

```go
err := llm.ValidateProviderAccess(ctx, llm.ProviderTypeBedrock)
if err != nil {
    log.Printf("Cannot use Bedrock: %v", err)
    // Fall back to OSS provider
}
```

## Best Practices

### 1. Use Environment Variables

```go
config := &llm.ProviderConfig{
    Name:   "openai",
    Type:   llm.ProviderTypeOpenAI,
    APIKey: os.Getenv("OPENAI_API_KEY"), // Never hardcode
}
```

### 2. Enable Health Checks in Production

```go
registry.StartPeriodicHealthCheck(ctx, 30*time.Second)
```

### 3. Configure Appropriate Timeouts

```go
config := &llm.ProviderConfig{
    // ...
    TimeoutSeconds: 60, // Generous timeout for LLM calls
}
```

### 4. Use Failover for High Availability

```go
router := llm.NewRouter(
    llm.WithRouterRegistry(registry),
    // Failover is enabled by default
)

// Request will automatically try next provider on failure
response, _, err := router.RouteRequest(ctx, req)
```

### 5. Monitor Provider Metrics

```go
status := router.GetProviderStatus(ctx)
for name, ps := range status {
    if ps.Metrics.ErrorCount > 100 {
        log.Printf("WARNING: High error rate for %s", name)
    }
}
```

## Related Documentation

- [LLM Provider Architecture](../reference/llm-architecture.md) - Deep dive into internals
- [LLM Provider Configuration](../guides/llm-providers.md) - User configuration guide
- [TypeScript SDK Guide](./typescript-quickstart.md) - TypeScript SDK usage
