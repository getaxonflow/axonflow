# AxonFlow SDK Comparison: Go vs TypeScript

Complete feature parity achieved between Go and TypeScript SDKs. Both SDKs now support all AxonFlow platform features including retry logic, caching, fail-open strategy, MCP connectors, and Multi-Agent Planning (MAP).

## Quick Decision Guide

**Use TypeScript SDK if:**
- Building web applications (React, Next.js, Vue)
- Need "invisible" governance with `protect()` wrapper
- Want OpenAI/Anthropic interceptors
- Prefer NPM package distribution

**Use Go SDK if:**
- Building backend services or microservices
- Already using Go in your stack
- Need explicit control over governance calls
- Building internal tools or agents

## Feature Comparison Matrix

| Feature | Go SDK | TypeScript SDK | Notes |
|---------|--------|----------------|-------|
| **Core Features** ||||
| Request/Response | ✅ | ✅ | Both fully supported |
| Policy enforcement | ✅ | ✅ | Both fully supported |
| Health checks | ✅ | ✅ | Both fully supported |
| TLS configuration | ✅ | ✅ | Go has more granular control |
| **Gateway Mode (Nov 2025)** ||||
| `getPolicyApprovedContext()` | ✅ | ✅ | Pre-check before LLM calls |
| `auditLLMCall()` | ✅ | ✅ | Audit after LLM calls |
| Context expiration (5min TTL) | ✅ | ✅ | Context IDs expire after 5 minutes |
| LLM cost estimation | ✅ | ✅ | OpenAI, Anthropic, Bedrock, Ollama |
| **Resilience** ||||
| Retry with exponential backoff | ✅ | ✅ | Both support configurable retry |
| In-memory caching with TTL | ✅ | ✅ | Both support configurable TTL |
| Fail-open in production | ✅ | ✅ | Both support production mode |
| Debug logging | ✅ | ✅ | Both support structured logging |
| **MCP Connectors** ||||
| List connectors | ✅ | ✅ | Browse marketplace |
| Install connectors | ✅ | ✅ | Install from marketplace |
| Query connectors | ✅ | ✅ | Execute connector queries |
| **Multi-Agent Planning (MAP)** ||||
| Generate plans | ✅ | ✅ | Natural language to workflow |
| Execute plans | ✅ | ✅ | Run multi-step workflows |
| Get plan status | ✅ | ✅ | Monitor long-running plans |
| **Developer Experience** ||||
| Package manager | Embedded | NPM | TypeScript: `@axonflow/sdk` |
| Documentation | ✅ README | ✅ README | Both comprehensive |
| Code examples | ✅ | ✅ | Both include examples |
| Type safety | ✅ | ✅ | Go: structs, TS: interfaces |
| **Advanced** ||||
| Provider interceptors | ❌ | ✅ | TypeScript: OpenAI, Anthropic |
| Client wrapping | ❌ | ✅ | TypeScript: `wrapOpenAIClient()` |
| Invisible governance | ❌ | ✅ | TypeScript: `protect()` wrapper |

## Lines of Code

| SDK | Lines | Complexity |
|-----|-------|------------|
| **Go SDK** | 663 | Medium (explicit) |
| **TypeScript SDK** | 424 | Medium-High (interceptors) |

Both SDKs are production-ready with comprehensive feature sets.

## Installation

### Go SDK

```bash
# Copy client-sdk directory into your project
cp -r platform/clients/travel-demo/client-sdk ./

# Or use as Go module (future)
go get github.com/axonflow/sdk-go
```

### TypeScript SDK

```bash
npm install @axonflow/sdk
```

## Code Comparison

### Basic Usage

**Go:**
```go
import client_sdk "your-project/client-sdk"

client := client_sdk.NewAxonFlowClient(
    "http://10.0.2.67:8080",
    "client-id",
    "client-secret",
)

resp, err := client.ExecuteQuery(
    "user-token",
    "What is the capital of France?",
    "chat",
    map[string]interface{}{},
)
```

**TypeScript:**
```typescript
import { AxonFlow } from '@axonflow/sdk';

const axonflow = new AxonFlow({
  apiKey: process.env.AXONFLOW_API_KEY
});

const response = await axonflow.protect(async () => {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'What is the capital of France?' }]
  });
});
```

### Advanced Configuration

**Go:**
```go
client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
    AgentURL:     "http://10.0.2.67:8080",
    ClientID:     "client-id",
    ClientSecret: "client-secret",
    Mode:         "production",
    Debug:        true,
    Timeout:      60 * time.Second,
    Retry: client_sdk.RetryConfig{
        Enabled:      true,
        MaxAttempts:  3,
        InitialDelay: 1 * time.Second,
    },
    Cache: client_sdk.CacheConfig{
        Enabled: true,
        TTL:     60 * time.Second,
    },
})
```

**TypeScript:**
```typescript
const axonflow = new AxonFlow({
  apiKey: process.env.AXONFLOW_API_KEY,
  endpoint: 'https://staging-eu.getaxonflow.com',
  mode: 'production',
  debug: true,
  timeout: 30000,
  retry: {
    enabled: true,
    maxAttempts: 3,
    delay: 1000
  },
  cache: {
    enabled: true,
    ttl: 60000
  }
});
```

### MCP Connector Usage

**Go:**
```go
// List connectors
connectors, err := client.ListConnectors()

// Install connector
err = client.InstallConnector(client_sdk.ConnectorInstallRequest{
    ConnectorID: "amadeus-travel",
    Name:        "amadeus-prod",
    TenantID:    "tenant-id",
    Options:     map[string]interface{}{"environment": "production"},
    Credentials: map[string]string{
        "api_key": "key",
        "api_secret": "secret",
    },
})

// Query connector
resp, err := client.QueryConnector(
    "amadeus-prod",
    "Find flights from Paris to Amsterdam",
    map[string]interface{}{
        "origin": "CDG",
        "destination": "AMS",
    },
)
```

**TypeScript:**
```typescript
// List connectors
const connectors = await axonflow.listConnectors();

// Install connector
await axonflow.installConnector({
  connector_id: 'amadeus-travel',
  name: 'amadeus-prod',
  tenant_id: 'tenant-id',
  options: { environment: 'production' },
  credentials: {
    api_key: process.env.AMADEUS_KEY,
    api_secret: process.env.AMADEUS_SECRET
  }
});

// Query connector
const resp = await axonflow.queryConnector(
  'amadeus-prod',
  'Find flights from Paris to Amsterdam',
  { origin: 'CDG', destination: 'AMS' }
);
```

### Multi-Agent Planning (MAP)

**Go:**
```go
// Generate plan
plan, err := client.GeneratePlan(
    "Plan a 3-day trip to Paris",
    "travel",
)

// Execute plan
execResp, err := client.ExecutePlan(plan.PlanID)

// Check status
status, err := client.GetPlanStatus(plan.PlanID)
```

**TypeScript:**
```typescript
// Generate plan
const plan = await axonflow.generatePlan(
  'Plan a 3-day trip to Paris',
  'travel'
);

// Execute plan
const execResp = await axonflow.executePlan(plan.planId);

// Check status
const status = await axonflow.getPlanStatus(plan.planId);
```

### Gateway Mode (Nov 2025)

Gateway Mode allows clients to make LLM calls directly while using AxonFlow for policy enforcement and audit logging.

**Go:**
```go
// 1. Pre-check: Get policy-approved context
ctx, err := client.GetPolicyApprovedContext(
    userToken,
    []string{"postgres", "salesforce"},  // Data sources
    "Show me customer orders",            // Query
    nil,                                  // Additional context
)
if err != nil || !ctx.Approved {
    log.Printf("Blocked: %s", ctx.BlockReason)
    return
}

// 2. Client makes LLM call with approved data
startTime := time.Now()
llmResponse, _ := openai.Chat(buildPrompt(ctx.ApprovedData))
latencyMs := time.Since(startTime).Milliseconds()

// 3. Audit the LLM call
result, err := client.AuditLLMCall(
    ctx.ContextID,
    summarize(llmResponse),
    "openai",
    "gpt-4",
    axonflow.TokenUsage{
        PromptTokens:     100,
        CompletionTokens: 50,
        TotalTokens:      150,
    },
    latencyMs,
    map[string]interface{}{"user_id": user.ID},
)
```

**TypeScript:**
```typescript
// 1. Pre-check: Get policy-approved context
const ctx = await axonflow.getPolicyApprovedContext({
  userToken,
  dataSources: ['postgres', 'salesforce'],
  query: 'Show me customer orders'
});

if (!ctx.approved) {
  throw new Error(`Blocked: ${ctx.blockReason}`);
}

// 2. Client makes LLM call with approved data
const startTime = Date.now();
const llmResponse = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: buildPrompt(ctx.approvedData) }]
});
const latencyMs = Date.now() - startTime;

// 3. Audit the LLM call
await axonflow.auditLLMCall(
  ctx.contextId,
  summarize(llmResponse),
  'openai',
  'gpt-4',
  {
    promptTokens: llmResponse.usage.prompt_tokens,
    completionTokens: llmResponse.usage.completion_tokens,
    totalTokens: llmResponse.usage.total_tokens
  },
  latencyMs,
  { userId: user.id }
);
```

See `docs/GATEWAY_MODE_MIGRATION_GUIDE.md` for the full migration guide.

## Performance

| Metric | Go SDK | TypeScript SDK |
|--------|--------|----------------|
| **Latency Overhead** | ~1-2ms | ~1-2ms |
| **Memory Footprint** | ~5MB | ~10MB (Node.js) |
| **Throughput** | 10,000+ RPS | 5,000+ RPS |
| **Cache Performance** | Goroutine cleanup | Periodic cleanup |
| **Retry Strategy** | Exponential backoff | Exponential backoff |

Both SDKs have negligible latency overhead (<2ms) for governance checks.

## Error Handling

### Go

```go
resp, err := client.ExecuteQuery(...)
if err != nil {
    // Network error or AxonFlow unavailable
    log.Printf("Request failed: %v", err)
    return
}

if resp.Blocked {
    // Policy violation
    log.Printf("Blocked: %s", resp.BlockReason)
    return
}

if !resp.Success {
    // Downstream error
    log.Printf("Query failed: %s", resp.Error)
    return
}

// Success
fmt.Printf("Result: %v\n", resp.Data)
```

### TypeScript

```typescript
try {
  const response = await axonflow.protect(() => aiCall());
  // Success
  console.log('Result:', response);
} catch (error) {
  if (error.message.includes('blocked by AxonFlow')) {
    // Policy violation
    console.error('Request blocked:', error.message);
  } else {
    // Network or downstream error
    console.error('Request failed:', error);
  }
}
```

## Production Best Practices

### Both SDKs

1. **Environment Variables**: Never hardcode credentials
2. **Fail-Open**: Use `Mode: "production"` (Go) or `mode: 'production'` (TypeScript)
3. **Enable Caching**: Reduce latency for repeated queries
4. **Enable Retry**: Handle transient failures automatically
5. **Debug in Development**: Enable debug mode during development, disable in production
6. **Health Checks**: Monitor AxonFlow availability

### Go-Specific

- Use `NewAxonFlowClientWithConfig()` for full configuration
- Leverage goroutines for concurrent requests
- Consider connection pooling for high-throughput scenarios

### TypeScript-Specific

- Use `protect()` wrapper for invisible governance
- Leverage interceptors for OpenAI/Anthropic
- Use `wrapOpenAIClient()` for seamless integration

## Migration Guide

### From Old Go SDK to Enhanced

```go
// Old (still works - backward compatible)
client := client_sdk.NewAxonFlowClient(url, id, secret)

// New (recommended - with all features)
client := client_sdk.NewAxonFlowClientWithConfig(client_sdk.AxonFlowConfig{
    AgentURL:     url,
    ClientID:     id,
    ClientSecret: secret,
    Mode:         "production",  // Enable fail-open
    Retry: client_sdk.RetryConfig{Enabled: true, MaxAttempts: 3},
    Cache: client_sdk.CacheConfig{Enabled: true, TTL: 60 * time.Second},
})
```

### From TypeScript v0.1 to v0.2 (MCP+MAP)

```typescript
// Old (still works)
const axonflow = new AxonFlow({ apiKey: 'key' });
const response = await axonflow.protect(() => aiCall());

// New features available
const connectors = await axonflow.listConnectors();  // MCP
const plan = await axonflow.generatePlan(query, domain);  // MAP
```

## When to Use Which SDK?

### Use Go SDK For:

- **Backend services** (REST APIs, gRPC services)
- **Microservices architecture**
- **Internal tools and CLIs**
- **Agent orchestration services**
- **High-throughput scenarios** (10,000+ RPS)
- **Explicit governance control**

### Use TypeScript SDK For:

- **Web applications** (React, Vue, Svelte)
- **Next.js / Vercel deployments**
- **Server-side rendering (SSR)**
- **Serverless functions (Lambda, Cloudflare Workers)**
- **Invisible governance** (no app changes)
- **OpenAI/Anthropic direct integration**

### Use Both:

- **Full-stack applications**: TypeScript frontend + Go backend
- **Microservices**: Different services use appropriate SDK
- **Multi-platform products**: Web (TypeScript) + Mobile backend (Go)

## Support & Resources

- **Documentation**: https://docs.axonflow.com
- **Go SDK**: `/sdk/golang/README.md`
- **TypeScript SDK**: `/sdk/typescript/README.md`
- **Examples**: See READMEs for complete examples
- **Email**: support@axonflow.com

## Changelog

### v0.3.0 (November 2025) - Gateway Mode

**Both SDKs:**
- ✅ Added Gateway Mode support (`getPolicyApprovedContext()`, `auditLLMCall()`)
- ✅ LLM cost estimation for OpenAI, Anthropic, Bedrock, Ollama
- ✅ Context expiration (5-minute TTL)
- ✅ Prometheus metrics for gateway operations

**Agent:**
- ✅ `POST /api/policy/pre-check` endpoint
- ✅ `POST /api/audit/llm-call` endpoint
- ✅ PostgreSQL tables: `gateway_contexts`, `llm_call_audits`
- ✅ EFS volume mount for Fargate audit persistence

**Test Coverage:**
- Agent: 65.2%
- TypeScript SDK: 65.64%

### v0.2.0 (October 2025)

**Both SDKs:**
- ✅ Added MCP Connector Marketplace support
- ✅ Added Multi-Agent Planning (MAP) support
- ✅ Added retry logic with exponential backoff
- ✅ Added in-memory caching with TTL
- ✅ Added fail-open strategy for production
- ✅ Added debug mode with structured logging
- ✅ Complete feature parity achieved

**Go SDK:**
- ✅ Backward compatible with existing code
- ✅ New `NewAxonFlowClientWithConfig()` for advanced features
- ✅ Comprehensive README with examples

**TypeScript SDK:**
- ✅ New connector types and methods
- ✅ New planning types and methods
- ✅ Enhanced error handling

### v0.1.0 (October 2025)

- Initial release with basic governance features

## License

MIT
