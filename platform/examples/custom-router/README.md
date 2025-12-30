# Custom LLM Router Example

This example demonstrates how to implement a custom LLM router using the `LLMRouterInterface`. Custom routers enable advanced routing logic, caching strategies, or integration with proprietary LLM systems.

## LLMRouterInterface

The `LLMRouterInterface` is the core abstraction for LLM routing in AxonFlow:

```go
type LLMRouterInterface interface {
    RouteRequest(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error)
    IsHealthy() bool
    GetProviderStatus() map[string]ProviderStatus
    UpdateProviderWeights(weights map[string]float64) error
}
```

## Use Cases

| Pattern | Description |
|---------|-------------|
| **Caching Router** | Cache responses to reduce API costs and latency |
| **Rate Limiting Router** | Implement custom rate limiting logic |
| **A/B Testing Router** | Route requests to different providers for comparison |
| **Fallback Router** | Custom fallback chains with specific retry logic |
| **Logging Router** | Add detailed logging/tracing to requests |

## Example: CachingRouter

This example implements a `CachingRouter` that wraps another router and caches responses:

```go
type CachingRouter struct {
    upstream LLMRouterInterface
    cache    sync.Map
    ttl      time.Duration
}

func (r *CachingRouter) RouteRequest(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
    // Check cache first
    if cached := r.getFromCache(req.Query); cached != nil {
        return cached.response, cached.info, nil
    }

    // Forward to upstream
    response, info, err := r.upstream.RouteRequest(ctx, req)
    if err != nil {
        return nil, nil, err
    }

    // Cache the response
    r.cache(req.Query, response, info)
    return response, info, nil
}
```

## Running the Example

```bash
cd platform/examples/custom-router
go run main.go
```

Expected output:

```
=== Custom LLM Router Example ===

1. Created MockRouter implementing LLMRouterInterface
   Health: true
   Providers: 2

2. Created CachingRouter wrapper

3. Making requests through CachingRouter:
   [0] Query: What is the weather today?
       Provider: openai, Response: Mock response for: What is the weather today?
   [1] Query: How does machine learning work?
       Provider: openai, Response: Mock response for: How does machine learning w...
   [2] Query: What is the weather today?  <-- Cache hit!
       Provider: openai, Response: Mock response for: What is the weather today?
   ...

4. Cache Statistics:
   Hits: 2, Misses: 3
   Hit Rate: 40.0%
```

## Integration with AxonFlow

To use a custom router with AxonFlow orchestrator:

```go
// Create your custom router
customRouter := NewCachingRouter(existingRouter, 5*time.Minute)

// Use with workflow engine
engine := orchestrator.NewWorkflowEngine()
engine.InitializeWithDependencies(customRouter, nil)
```

## Built-in Implementations

AxonFlow provides these built-in implementations:

| Implementation | Package | Description |
|----------------|---------|-------------|
| `UnifiedRouter` | `orchestrator/llm` | Multi-provider router with strategies |
| `UnifiedRouterWrapper` | `orchestrator` | Wrapper implementing interface |
| `MockLLMRouter` | `orchestrator` | Testing mock |

## See Also

- [LLM Provider Routing](../../../examples/llm-routing/) - SDK-based routing examples
- [ADR-007](../../../technical-docs/architecture-decisions/adr-007-llm-router-interface.md) - Architecture decision
