# TypeScript SDK Technical Specification

**Version:** 1.0.0
**Last Updated:** September 30, 2025
**Status:** Production Ready

## Architecture Overview

The SDK implements an invisible governance layer for AI applications, providing real-time policy enforcement with minimal latency overhead.

### Core Design Principles

1. **Zero Dependencies**: No external packages for security and size
2. **Isomorphic**: Works in Node.js and browsers
3. **Non-Invasive**: 3-line integration without code restructuring
4. **Fail-Open**: Gracefully degrades if service unavailable
5. **Performance First**: Minimal overhead on AI calls (typically single-digit ms)

## Component Architecture

```
┌─────────────────────────────────────────┐
│           Application Code              │
├─────────────────────────────────────────┤
│         TypeScript SDK Layer            │
│  ┌────────────────────────────────┐    │
│  │      Client (client.ts)        │    │
│  │  - Configuration management    │    │
│  │  - Request interception        │    │
│  │  - Response processing         │    │
│  └────────────────────────────────┘    │
│  ┌────────────────────────────────┐    │
│  │    Interceptors (interceptors/)│    │
│  │  - OpenAI wrapper              │    │
│  │  - Anthropic wrapper           │    │
│  │  - Generic HTTP interceptor    │    │
│  └────────────────────────────────┘    │
│  ┌────────────────────────────────┐    │
│  │      Policies (policies/)      │    │
│  │  - PII detection engine        │    │
│  │  - Content filtering           │    │
│  │  - Rate limiting               │    │
│  └────────────────────────────────┘    │
├─────────────────────────────────────────┤
│         Control Plane API               │
│    (Agent + Orchestrator Services)      │
└─────────────────────────────────────────┘
```

## API Specification

### Client Initialization

```typescript
interface Config {
  apiKey: string;                    // Required: Authentication key
  endpoint?: string;                 // Optional: API endpoint (default: production)
  environment?: 'production' | 'sandbox'; // Optional: Environment mode
  timeout?: number;                  // Optional: Request timeout in ms (default: 5000)
  failOpen?: boolean;               // Optional: Fail open on errors (default: true in prod)
  debug?: boolean;                  // Optional: Enable debug logging (default: false)
  cache?: {
    enabled: boolean;               // Enable response caching
    ttl: number;                    // Cache TTL in seconds
    maxSize: number;                // Max cache entries
  };
}
```

### Core Methods

#### protect()
Primary method for wrapping AI operations with governance.

```typescript
async protect<T>(
  operation: () => Promise<T>,
  options?: ProtectOptions
): Promise<T>

interface ProtectOptions {
  metadata?: Record<string, any>;   // Additional context
  policies?: string[];              // Specific policies to apply
  mode?: 'enforce' | 'monitor';    // Enforcement mode
}
```

#### wrapClient()
Helper for wrapping entire AI client instances.

```typescript
function wrapOpenAIClient(
  client: OpenAI,
  axonflow: AxonFlowClient
): OpenAI

function wrapAnthropicClient(
  client: Anthropic,
  axonflow: AxonFlowClient
): Anthropic
```

## Request Flow

### 1. Request Interception
```
Application → SDK.protect() → Validate → Extract Content
```

### 2. Policy Evaluation
```
Content → PII Detection → Policy Check → Transformation
```

### 3. Service Communication
```
Transformed Request → Control Plane API → Response
```

### 4. Response Processing
```
API Response → Validation → Reverse Transform → Application
```

## Policy Engine

### PII Detection Patterns

| Type | Pattern | Replacement |
|------|---------|-------------|
| SSN | `\d{3}-?\d{2}-?\d{4}` | `[SSN_REDACTED]` |
| Credit Card | `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` | `[CARD_REDACTED]` |
| Passport | `[A-Z]{1,2}\d{6,9}` | `[PASSPORT_REDACTED]` |
| Email | `[\w.-]+@[\w.-]+\.\w+` | `[EMAIL_REDACTED]` |
| Phone | `\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}` | `[PHONE_REDACTED]` |

### Policy Types

1. **Static Policies** (Cached locally)
   - PII patterns
   - Blocked keywords
   - Rate limits
   - Content filters

2. **Dynamic Policies** (Evaluated server-side)
   - User-specific rules
   - Context-aware decisions
   - Real-time threat detection
   - Cost optimization routing

## Performance Characteristics

### Latency Budget

| Component | P50 | P95 | P99 | Target |
|-----------|-----|-----|-----|--------|
| SDK Overhead | 2ms | 5ms | 9ms | <10ms |
| Network (Local) | 1ms | 2ms | 3ms | <5ms |
| Policy Evaluation | 1ms | 3ms | 5ms | <5ms |
| **Total** | **4ms** | **10ms** | **17ms** | **<20ms** |

### Memory Usage

- Initial load: <1MB
- Runtime (idle): <5MB
- Runtime (active): <10MB
- Cache (max): Configurable, default 50MB

### Bundle Size

- Uncompressed: 45KB
- Minified: 28KB
- Gzipped: 9.2KB
- Brotli: 7.8KB

## Security Considerations

### API Key Management
- Never exposed in client-side code
- Transmitted only via Authorization header
- Rotatable without code changes
- Environment-specific keys supported

### Data Privacy
- No data persistence in SDK
- PII never logged
- Secure erasure of sensitive data
- No telemetry or tracking

### Network Security
- HTTPS only
- Certificate pinning available
- Request signing for integrity
- Replay attack prevention

## Error Handling

### Error Types

```typescript
enum ErrorCode {
  UNAUTHORIZED = 'UNAUTHORIZED',
  RATE_LIMITED = 'RATE_LIMITED',
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  NETWORK_ERROR = 'NETWORK_ERROR',
  TIMEOUT = 'TIMEOUT',
  INVALID_CONFIG = 'INVALID_CONFIG'
}

class SDKError extends Error {
  code: ErrorCode;
  details: Record<string, any>;
  retryable: boolean;
  fallbackAction?: () => any;
}
```

### Retry Strategy

```typescript
interface RetryConfig {
  maxAttempts: 3;
  backoffMultiplier: 2;
  initialDelay: 100;      // ms
  maxDelay: 5000;        // ms
  retryableErrors: [
    'NETWORK_ERROR',
    'TIMEOUT'
  ];
}
```

## Deployment Modes

### Production Mode
- Fail open on service unavailable
- Async policy updates
- Response caching enabled
- Minimal logging

### Sandbox Mode
- Fail closed for testing
- Synchronous policy evaluation
- No caching
- Verbose logging

### Development Mode
- Mock responses available
- Debug inspector enabled
- Performance profiling
- Request replay

## Monitoring & Observability

### Metrics Collected

| Metric | Type | Purpose |
|--------|------|---------|
| request_count | Counter | Total requests processed |
| request_duration | Histogram | Latency distribution |
| policy_violations | Counter | Violations by type |
| pii_redactions | Counter | PII items redacted |
| cache_hit_rate | Gauge | Cache effectiveness |
| error_rate | Gauge | Error percentage |

### Health Checks

```typescript
interface HealthStatus {
  sdk_version: string;
  api_reachable: boolean;
  cache_enabled: boolean;
  policies_loaded: boolean;
  last_sync: Date;
  latency_ms: number;
}
```

## Integration Patterns

### Pattern 1: Wrapper Approach
```typescript
import { wrapOpenAIClient } from '@axonflow/sdk';

const protectedClient = wrapOpenAIClient(openai, axonflow);
// Use normally, protection is invisible
```

### Pattern 2: Decorator Approach
```typescript
class AIService {
  @protect()
  async generateResponse(prompt: string) {
    return this.openai.complete(prompt);
  }
}
```

### Pattern 3: Middleware Approach
```typescript
app.use(axonflowMiddleware({
  apiKey: process.env.AXONFLOW_KEY,
  routes: ['/api/ai/*']
}));
```

## Testing Support

### Mock Mode
```typescript
const axonflow = AxonFlow.mock({
  responses: {
    '/protect': { status: 'allowed' }
  }
});
```

### Test Utilities
```typescript
import { testUtils } from '@axonflow/sdk';

testUtils.assertPIIRedacted(response);
testUtils.assertPolicyApplied(response, 'rate_limit');
testUtils.measureLatency(operation);
```

## Migration Guide

### From Direct AI Calls
```typescript
// Before
const response = await openai.complete(prompt);

// After (Option 1: Minimal change)
const response = await axonflow.protect(() =>
  openai.complete(prompt)
);

// After (Option 2: Full wrapper)
const protectedOpenAI = wrapOpenAIClient(openai, axonflow);
const response = await protectedOpenAI.complete(prompt);
```

## Compatibility Matrix

| Environment | Version | Support |
|-------------|---------|---------|
| Node.js | 14+ | ✅ Full |
| Chrome | 90+ | ✅ Full |
| Firefox | 88+ | ✅ Full |
| Safari | 14+ | ✅ Full |
| Edge | 90+ | ✅ Full |
| React | 16.8+ | ✅ Full |
| Next.js | 12+ | ✅ Full |
| Vue | 3+ | ✅ Full |
| Angular | 12+ | ✅ Full |

## Performance Benchmarks

### Operation Benchmarks (1M operations)

| Operation | Ops/sec | Memory | CPU |
|-----------|---------|--------|-----|
| protect() call | 125,000 | 8MB | 12% |
| PII detection | 85,000 | 12MB | 25% |
| Policy evaluation | 95,000 | 10MB | 18% |
| Cache lookup | 450,000 | 15MB | 5% |

### Real-world Scenarios

| Scenario | Requests/sec | P99 Latency | Error Rate |
|----------|--------------|-------------|------------|
| Chat application | 1,000 | 9.5ms | 0.01% |
| Batch processing | 5,000 | 12ms | 0.02% |
| Real-time API | 10,000 | 15ms | 0.03% |

## Roadmap

### v1.1 (Q4 2025)
- WebSocket support
- Streaming response handling
- Additional AI provider wrappers
- GraphQL interceptor

### v1.2 (Q1 2026)
- Edge runtime optimization
- WebAssembly build
- Offline policy sync
- Request batching

### v2.0 (Q2 2026)
- Multi-tenant isolation
- Custom policy DSL
- Advanced caching strategies
- Distributed tracing

---

*This specification serves as the authoritative reference for SDK implementation and integration.*