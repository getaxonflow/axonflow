# LLM Provider Architecture Guide

## Overview

AxonFlow's LLM provider system is designed to be pluggable, extensible, and enterprise-ready. This document describes the architecture for developers who want to:

- Understand how providers work internally
- Add custom provider implementations
- Integrate with the provider registry
- Implement license-gated features

## Architecture Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Router                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐  │
│  │ Load        │  │ Metrics     │  │ Route Options               │  │
│  │ Balancer    │  │ Tracker     │  │ - Preferred Provider        │  │
│  │ (weighted)  │  │ (latency,   │  │ - Custom Weights            │  │
│  │             │  │  errors)    │  │ - Disable Failover          │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Registry                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────────┐    │
│  │ Provider        │  │ Health          │  │ License           │    │
│  │ Configs         │  │ Monitoring      │  │ Validator         │    │
│  │ (name→config)   │  │ (periodic       │  │ (Community vs ENT)│    │
│  │                 │  │  health checks) │  │                   │    │
│  └─────────────────┘  └─────────────────┘  └───────────────────┘    │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐                           │
│  │ Factory         │  │ Storage         │                           │
│  │ Manager         │  │ (PostgreSQL)    │                           │
│  │ (type→factory)  │  │                 │                           │
│  └─────────────────┘  └─────────────────┘                           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Providers                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────┐  │
│  │ OpenAI   │  │ Anthropic│  │ Bedrock  │  │ Ollama   │  │ Custom│  │
│  │ (Comm)   │  │ (Comm)   │  │ (ENT)    │  │ (Comm)   │  │ (ENT) │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └───────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Bootstrap System

The bootstrap system initializes LLM providers from environment variables at startup, ensuring backward compatibility with existing deployments.

### Environment Variable Configuration

```bash
# Enable specific providers
export LLM_OPENAI_ENABLED=true
export LLM_ANTHROPIC_ENABLED=true
export LLM_BEDROCK_ENABLED=true
export LLM_OLLAMA_ENABLED=true

# OpenAI configuration
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4

# Anthropic configuration
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_MODEL=claude-3-sonnet-20240229

# AWS Bedrock configuration
export AWS_REGION=us-east-1
export LLM_BEDROCK_MODEL=anthropic.claude-3-5-sonnet-20240620-v1:0

# Ollama configuration
export LLM_OLLAMA_ENDPOINT=http://localhost:11434
export LLM_OLLAMA_MODEL=llama3
```

### Bootstrap Process

At startup, the orchestrator:

1. **Scans environment variables** for provider configurations
2. **Creates provider configs** with auto-generated names (`openai-default`, `anthropic-default`, etc.)
3. **Registers providers** in the in-memory registry
4. **Performs health checks** to validate connectivity
5. **Logs initialized providers** for debugging

### Using Bootstrap in Code

```go
import "axonflow/platform/orchestrator/llm"

// Quick bootstrap - creates router from environment variables
router, err := llm.QuickBootstrap()
if err != nil {
    log.Fatal(err)
}

// Or use MustBootstrap which panics on error (for main())
router := llm.MustBootstrap()

// Route a request (automatic provider selection with failover)
response, info, err := router.RouteRequest(ctx, llm.CompletionRequest{
    Prompt:    "Hello",
    MaxTokens: 100,
})
if err != nil {
    log.Printf("Request failed: %v", err)
}
log.Printf("Response from %s: %s", info.ProviderName, response.Content)

// Access the registry from the router
registry := router.Registry()
providers := registry.ListEnabled()
for _, name := range providers {
    provider, _ := registry.Get(ctx, name)
    log.Printf("Provider: %s (type: %s)", provider.Name(), provider.Type())
}
```

### Full Bootstrap with Custom Configuration

```go
import "axonflow/platform/orchestrator/llm"

// Create custom bootstrap config
cfg := &llm.BootstrapConfig{
    EnableOpenAI:    true,
    EnableAnthropic: true,
    EnableBedrock:   false,
    EnableOllama:    false,
}

// Bootstrap with custom config
result, err := llm.BootstrapFromEnv(cfg)
if err != nil {
    log.Fatal(err)
}

log.Printf("Bootstrapped %d providers", len(result.ProvidersBootstrapped))
for _, name := range result.ProvidersBootstrapped {
    log.Printf("  - %s", name)
}

// Check for any failures
for name, err := range result.ProvidersFailed {
    log.Printf("  - %s failed: %v", name, err)
}

// Create a router with the bootstrapped registry
router := llm.NewRouter(llm.WithRouterRegistry(result.Registry))
```

### Priority and Weights

Bootstrap providers are assigned default priorities:

| Provider | Default Priority | Default Weight |
|----------|-----------------|----------------|
| OpenAI | 1 | 100 |
| Anthropic | 2 | 100 |
| Bedrock | 3 | 100 |
| Ollama | 4 | 100 |

Lower priority numbers are preferred. Weights are used for load balancing among providers with the same priority.

## Core Interfaces

### Provider Interface

Every LLM provider must implement the `Provider` interface:

```go
// Provider defines the interface for LLM providers.
type Provider interface {
    // Name returns the provider's unique identifier.
    Name() string

    // Type returns the provider type (openai, anthropic, bedrock, etc.)
    Type() ProviderType

    // Complete sends a completion request to the LLM.
    Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)

    // HealthCheck verifies the provider is operational.
    HealthCheck(ctx context.Context) (*HealthCheckResult, error)

    // Capabilities returns the provider's capabilities.
    Capabilities() []Capability

    // SupportsStreaming returns true if the provider supports streaming.
    SupportsStreaming() bool

    // EstimateCost estimates the cost for a completion request.
    EstimateCost(req CompletionRequest) *CostEstimate
}
```

### Provider Types

| Type | Constant | License | Description |
|------|----------|---------|-------------|
| OpenAI | `ProviderTypeOpenAI` | Community | OpenAI GPT models |
| Anthropic | `ProviderTypeAnthropic` | Community | Anthropic Claude models |
| Ollama | `ProviderTypeOllama` | Community | Self-hosted open-source models |
| Bedrock | `ProviderTypeBedrock` | Enterprise | AWS Bedrock managed models |
| Gemini | `ProviderTypeGemini` | Enterprise | Google Gemini models |
| Custom | `ProviderTypeCustom` | Enterprise | Third-party or custom providers |

## Factory Pattern

### Registering a Factory

Factories create provider instances from configuration:

```go
// Register factory for your provider type
RegisterFactory(ProviderTypeMyProvider, func(config ProviderConfig) (Provider, error) {
    return NewMyProvider(
        config.Name,
        config.APIKey,
        config.Settings,
    ), nil
})
```

### Factory Manager

For isolated testing, use `FactoryManager`:

```go
fm := NewFactoryManager()
fm.Register(ProviderTypeOpenAI, myOpenAIFactory)
fm.Register(ProviderTypeCustom, myCustomFactory)

registry := NewRegistry(WithFactoryManager(fm))
```

## Registry

### Creating a Registry

```go
// Basic registry (in-memory only)
registry := NewRegistry()

// With PostgreSQL storage
db, _ := sql.Open("postgres", databaseURL)
storage := NewPostgresStorage(db)
registry := NewRegistry(WithStorage(storage))

// With custom license validator
validator := myEnterpriseLicenseValidator()
registry := NewRegistry(WithLicenseValidator(validator))
```

### Registering Providers

```go
ctx := context.Background()

// Register via configuration (lazy instantiation)
config := &ProviderConfig{
    Name:    "my-openai",
    Type:    ProviderTypeOpenAI,
    APIKey:  "sk-...",
    Model:   "gpt-4",
    Enabled: true,
}
err := registry.Register(ctx, config)

// Register pre-instantiated provider
provider := NewOpenAIProvider("my-openai", apiKey)
err := registry.RegisterProvider("my-openai", provider, config)
```

### Getting Providers

```go
// Get by name (lazy instantiation)
provider, err := registry.Get(ctx, "my-openai")

// List all providers
names := registry.List()

// List enabled providers only
enabled := registry.ListEnabled()

// List healthy providers
healthy := registry.GetHealthyProviders()
```

## Router

### Creating a Router

```go
registry := NewRegistry()
router := NewRouter(
    WithRouterRegistry(registry),
    WithDefaultWeights(map[string]float64{
        "openai-1": 0.6,
        "anthropic-1": 0.4,
    }),
)
```

### Routing Requests

```go
req := CompletionRequest{
    Prompt:    "Hello, world!",
    MaxTokens: 100,
}

// Route with automatic load balancing
response, info, err := router.RouteRequest(ctx, req)

// Route to specific provider
response, info, err := router.RouteRequest(ctx, req,
    WithPreferredProvider("anthropic-1"),
)

// Route with custom weights
response, info, err := router.RouteRequest(ctx, req,
    WithRouteWeights(map[string]float64{
        "openai-1": 0.9,
        "anthropic-1": 0.1,
    }),
)

// Route without failover
response, info, err := router.RouteRequest(ctx, req,
    WithDisableFailover(),
)
```

### Route Info

```go
type RouteInfo struct {
    ProviderName   string       // Provider that handled the request
    ProviderType   ProviderType // Type of provider
    Model          string       // Model used
    ResponseTimeMs int64        // Response time in milliseconds
    TokensUsed     int          // Total tokens consumed
    EstimatedCost  float64      // Estimated cost in USD
}
```

## License Gating

### Provider Tiers

| Tier | Providers | Features |
|------|-----------|----------|
| Community | Ollama, OpenAI, Anthropic | Basic routing, health checks |
| PRO | + Bedrock, Gemini, Custom | Advanced routing, priority support |
| ENT | All providers | All features, SLA guarantee |
| PLUS | All providers | Dedicated support, custom development |

### Checking Access

```go
// Check if provider is allowed
err := ValidateProviderAccess(ctx, ProviderTypeBedrock)
if err != nil {
    // Provider requires license upgrade
    log.Printf("License error: %v", err)
}

// Get available providers for current tier
communityProviders := GetCommunityProviders() // [ollama, openai, anthropic, gemini]
entProviders := GetEnterpriseProviders()       // [bedrock, custom]
```

### Implementing Custom Validator

```go
type MyLicenseValidator struct {
    tier LicenseTier
}

func (v *MyLicenseValidator) GetCurrentTier(ctx context.Context) LicenseTier {
    // Check license from context, database, or external service
    return v.tier
}

func (v *MyLicenseValidator) IsProviderAllowed(ctx context.Context, pt ProviderType) bool {
    requiredTier := GetTierForProvider(pt)
    return TierSatisfiesRequirement(v.tier, requiredTier)
}

func (v *MyLicenseValidator) ValidateLicense(ctx context.Context, key string) error {
    // Validate license key against license server
    return nil
}

func (v *MyLicenseValidator) GetFeatures() map[string]bool {
    return map[string]bool{
        "multi_provider": true,
        "load_balancing": true,
        // ...
    }
}
```

## Database Storage

### Schema

The provider configuration is stored in PostgreSQL with Row Level Security (RLS):

```sql
-- Provider configuration table
CREATE TABLE llm_providers (
    id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    api_key_encrypted TEXT,
    api_key_secret_arn VARCHAR(500),
    base_url VARCHAR(500),
    model VARCHAR(100),
    region VARCHAR(50),
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 100,
    weight INTEGER DEFAULT 100,
    rate_limit INTEGER DEFAULT 0,
    timeout_seconds INTEGER DEFAULT 30,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Usage tracking table
CREATE TABLE llm_provider_usage (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider_name VARCHAR(100) NOT NULL,
    request_id VARCHAR(100),
    model VARCHAR(100),
    input_tokens INTEGER,
    output_tokens INTEGER,
    total_tokens INTEGER,
    estimated_cost_usd DECIMAL(10, 6),
    latency_ms INTEGER,
    status VARCHAR(20),
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Health status table
CREATE TABLE llm_provider_health (
    provider_name VARCHAR(100) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL,
    latency_ms INTEGER,
    message TEXT,
    consecutive_failures INTEGER DEFAULT 0,
    last_checked TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Using PostgreSQL Storage

```go
import (
    "database/sql"
    _ "github.com/lib/pq"
)

db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
if err != nil {
    log.Fatal(err)
}

storage := NewPostgresStorage(db)
registry := NewRegistry(WithStorage(storage))

// Providers are now persisted to PostgreSQL
err = registry.Register(ctx, config)
```

## Adapters (Backward Compatibility)

### Using Legacy Providers

If you have providers implementing the old `LegacyProvider` interface:

```go
// Old interface
type LegacyProvider interface {
    Name() string
    Query(ctx context.Context, prompt string, options LegacyQueryOptions) (*LegacyResponse, error)
    IsHealthy() bool
    GetCapabilities() []string
    EstimateCost(tokens int) float64
}

// Adapt to new interface
legacyProvider := myOldProvider()
adapter := NewLegacyAdapter(legacyProvider, ProviderTypeCustom)

// Use with registry
registry.RegisterProvider("legacy-provider", adapter, config)
```

### Exposing New Providers as Legacy

```go
// New provider implementing Provider interface
newProvider := NewMyProvider(config)

// Adapt to legacy interface
legacyAdapter := NewProviderAdapter(newProvider)

// Use with old code that expects LegacyProvider
oldRouter.AddProvider(legacyAdapter)
```

## Health Monitoring

### Automatic Health Checks

```go
// Start periodic health checks
registry.StartPeriodicHealthCheck(ctx, 30*time.Second)

// Manual health check
registry.HealthCheck(ctx)

// Get health result for specific provider
result := registry.GetHealthResult("my-provider")
// result.Status: HealthStatusHealthy, HealthStatusDegraded, HealthStatusUnhealthy
```

### Health States

| Status | Description | Routing Behavior |
|--------|-------------|------------------|
| Healthy | 0-2 consecutive failures | Full traffic |
| Degraded | 3-4 consecutive failures | Deprioritized |
| Unhealthy | 5+ consecutive failures | Excluded from routing |

## Error Handling

### Registry Errors

```go
var regErr *RegistryError
if errors.As(err, &regErr) {
    switch regErr.Code {
    case ErrRegistryNotFound:
        // Provider not found
    case ErrRegistryDuplicate:
        // Provider already registered
    case ErrRegistryInvalidConfig:
        // Invalid configuration
    case ErrRegistryCreationFailed:
        // Factory failed to create provider
    case ErrRegistryStorageError:
        // Database error
    case ErrRegistryLicenseRequired:
        // Provider requires license upgrade
    }
}
```

### License Errors

```go
var licErr *LicenseError
if errors.As(err, &licErr) {
    log.Printf("Provider %s requires %s tier (current: %s)",
        licErr.ProviderType,
        licErr.RequiredTier,
        licErr.CurrentTier,
    )
}
```

## Best Practices

### 1. Use Lazy Loading

Register configurations first, providers are instantiated on first use:

```go
// Good: Register config, instantiate lazily
registry.Register(ctx, config)
provider, _ := registry.Get(ctx, "my-provider") // Instantiated here

// Avoid: Pre-instantiating all providers at startup
for _, config := range configs {
    provider := factory(config) // Unnecessary if provider never used
    registry.RegisterProvider(config.Name, provider, &config)
}
```

### 2. Handle Failover

Always check for failover in production:

```go
response, info, err := router.RouteRequest(ctx, req)
if err != nil {
    // All providers failed
    log.Printf("All providers failed, last error: %v", err)
    return nil, err
}

// Check if failover occurred
if info.ProviderName != preferredProvider {
    log.Printf("Failover occurred from %s to %s", preferredProvider, info.ProviderName)
}
```

### 3. Monitor Metrics

Track provider performance:

```go
status := router.GetProviderStatus(ctx)
for name, ps := range status {
    log.Printf("Provider %s: health=%s, requests=%d, errors=%d, avg_latency=%.2fms",
        name,
        ps.Health.Status,
        ps.Metrics.RequestCount,
        ps.Metrics.ErrorCount,
        ps.Metrics.AvgResponseTime,
    )
}
```

### 4. Test License Gating

Ensure enterprise features are properly gated:

```go
func TestEnterpriseProviderRequiresLicense(t *testing.T) {
    registry := NewRegistry(WithLicenseValidator(NewCommunityLicenseValidator()))

    err := registry.Register(ctx, &ProviderConfig{
        Name: "bedrock-test",
        Type: ProviderTypeBedrock,
    })

    if err == nil {
        t.Fatal("Expected license error for enterprise provider in Community mode")
    }
}
```

## Migration Guide

### From Legacy Router

1. Create a new Registry with your factory implementations
2. Register your existing providers using `RegisterProvider`
3. Create a Router with the Registry
4. Update routing calls to use `router.RouteRequest`
5. Use adapters for code that still expects `LegacyProvider`

### Adding New Provider Types

1. Define a new `ProviderType` constant
2. Implement the `Provider` interface
3. Register a factory function
4. Add to license tier requirements (if enterprise)
5. Add tests for all interface methods

## REST API Reference

The orchestrator exposes REST API endpoints for provider management. All endpoints require authentication and are tenant-scoped.

### List Providers

```
GET /api/v1/llm-providers
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by provider type (openai, anthropic, bedrock, ollama, custom) |
| `enabled` | boolean | Filter by enabled status |
| `page` | integer | Page number (default: 1) |
| `page_size` | integer | Items per page (default: 20, max: 100) |

**Response:**

```json
{
  "providers": [
    {
      "name": "my-anthropic",
      "type": "anthropic",
      "model": "claude-3-sonnet-20240229",
      "enabled": true,
      "priority": 1,
      "weight": 100,
      "has_api_key": true,
      "health": {
        "status": "healthy",
        "last_checked": "2025-01-15T10:30:00Z"
      }
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### Get Provider

```
GET /api/v1/llm-providers/{name}
```

**Response:**

```json
{
  "provider": {
    "name": "my-anthropic",
    "type": "anthropic",
    "endpoint": "https://api.anthropic.com",
    "model": "claude-3-sonnet-20240229",
    "enabled": true,
    "priority": 1,
    "weight": 100,
    "rate_limit": 60,
    "timeout_seconds": 30,
    "has_api_key": true,
    "settings": {},
    "health": {
      "status": "healthy",
      "message": "Provider is responsive",
      "last_checked": "2025-01-15T10:30:00Z"
    }
  }
}
```

### Create Provider

```
POST /api/v1/llm-providers
```

**Request Body:**

```json
{
  "name": "my-anthropic",
  "type": "anthropic",
  "api_key": "sk-ant-...",
  "model": "claude-3-sonnet-20240229",
  "enabled": true,
  "priority": 1,
  "weight": 100,
  "rate_limit": 60,
  "timeout_seconds": 30
}
```

**Alternative with AWS Secrets Manager:**

```json
{
  "name": "my-bedrock",
  "type": "bedrock",
  "api_key_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789:secret:llm/bedrock",
  "region": "us-east-1",
  "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
  "enabled": true,
  "priority": 1
}
```

### Update Provider

```
PUT /api/v1/llm-providers/{name}
```

**Request Body (partial updates supported):**

```json
{
  "enabled": false,
  "priority": 2,
  "weight": 50
}
```

### Delete Provider

```
DELETE /api/v1/llm-providers/{name}
```

**Response:** 204 No Content

### Get Provider Health

```
GET /api/v1/llm-providers/{name}/health
```

**Response:**

```json
{
  "name": "my-anthropic",
  "health": {
    "status": "healthy",
    "latency_ms": 245,
    "message": "Provider is responsive",
    "last_checked": "2025-01-15T10:30:00Z"
  }
}
```

### Get All Providers Health

```
GET /api/v1/llm-providers/health
```

**Response:**

```json
{
  "providers": {
    "my-anthropic": {
      "status": "healthy",
      "latency_ms": 245,
      "message": "Provider is responsive",
      "last_checked": "2025-01-15T10:30:00Z"
    },
    "my-openai": {
      "status": "unhealthy",
      "latency_ms": 0,
      "message": "Connection timeout",
      "last_checked": "2025-01-15T10:30:00Z"
    }
  }
}
```

### Update Routing Weights

```
PUT /api/v1/llm-providers/routing
```

**Request Body:**

```json
{
  "weights": {
    "my-anthropic": 70,
    "my-openai": 30
  }
}
```

### Error Responses

All endpoints return errors in this format:

```json
{
  "error": {
    "code": "PROVIDER_NOT_FOUND",
    "message": "Provider 'my-provider' not found"
  }
}
```

**Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `PROVIDER_NOT_FOUND` | 404 | Provider with given name not found |
| `PROVIDER_EXISTS` | 409 | Provider with given name already exists |
| `INVALID_REQUEST` | 400 | Request body validation failed |
| `LICENSE_REQUIRED` | 402 | Enterprise license required for provider type |
| `INTERNAL_ERROR` | 500 | Internal server error |

## Related Documentation

- [LLM Provider Configuration Guide](../guides/llm-providers.md) - User-facing configuration
- [SDK Integration Guide](../sdk/llm-sdk-guide.md) - SDK usage examples
- [Getting Started](../getting-started.md) - Quick start guide
