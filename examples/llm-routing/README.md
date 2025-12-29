# LLM Provider Routing Examples

These examples demonstrate how to work with AxonFlow's LLM provider routing capabilities.

## Overview

AxonFlow supports flexible LLM provider routing through server-side configuration. This allows operators to:

- **Optimize costs** by preferring cheaper providers
- **Meet compliance requirements** (e.g., HIPAA with Bedrock-only routing)
- **Improve performance** by favoring faster providers
- **Configure failover** for high availability

## Server Configuration

Configure routing via environment variables on the AxonFlow Orchestrator:

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `LLM_ROUTING_STRATEGY` | `weighted`, `round_robin`, `failover`, `cost_optimized`* | `weighted` | Routing strategy |
| `PROVIDER_WEIGHTS` | `openai:50,anthropic:30,bedrock:20` | Equal weights | Provider distribution |
| `DEFAULT_LLM_PROVIDER` | `bedrock`, `openai`, etc. | None | Primary provider for failover |
| `PROVIDER_COSTS`* | `ollama:0,bedrock:0.02,openai:0.03` | See defaults | Cost per 1K tokens |

\* Enterprise only

## Routing Strategies

### Weighted (Default)

Distributes requests based on configured weights:

```bash
PROVIDER_WEIGHTS=openai:50,anthropic:30,bedrock:20
# ~50% to OpenAI, ~30% to Anthropic, ~20% to Bedrock
```

### Round Robin

Cycles through healthy providers equally:

```bash
LLM_ROUTING_STRATEGY=round_robin
# openai -> anthropic -> bedrock -> openai -> ...
```

### Failover

Uses primary provider, falls back on failure:

```bash
LLM_ROUTING_STRATEGY=failover
DEFAULT_LLM_PROVIDER=bedrock
# Always uses Bedrock, falls back to others if unhealthy
```

### Cost Optimized (Enterprise)

Automatically routes to the cheapest healthy provider:

```bash
LLM_ROUTING_STRATEGY=cost_optimized
PROVIDER_COSTS=ollama:0,bedrock:0.02,anthropic:0.025,openai:0.03
# Selects cheapest healthy provider automatically
```

Default costs (if `PROVIDER_COSTS` not set):
- ollama: $0.00 (self-hosted)
- bedrock: $0.02
- anthropic/gemini: $0.025
- openai: $0.03

## Examples

Each example demonstrates:

1. **Default routing** - Let the server decide based on configuration
2. **Provider preference** - Request a specific provider
3. **Model override** - Specify exact model to use
4. **Health checking** - Query provider availability

### HTTP (curl)

No SDK required - direct HTTP calls:

```bash
cd http
chmod +x provider-routing.sh
AXONFLOW_ENDPOINT=http://localhost:8080 ./provider-routing.sh
```

### TypeScript

```bash
cd typescript
npm install
AXONFLOW_ENDPOINT=http://localhost:8080 npx ts-node provider-routing.ts
```

### Python

```bash
cd python
pip install axonflow
AXONFLOW_ENDPOINT=http://localhost:8080 python provider_routing.py
```

### Go

```bash
cd go
go mod init example
go get github.com/getaxonflow/axonflow-sdk-go
AXONFLOW_ENDPOINT=http://localhost:8080 go run provider_routing.go
```

### Java

```bash
cd java
# Add axonflow-sdk dependency to pom.xml
mvn compile exec:java -Dexec.mainClass="com.example.llmrouting.ProviderRouting"
```

## Client-Side Provider Hints

While routing is server-controlled, clients can provide hints:

```typescript
// Request specific provider (server may override based on health/policy)
const response = await client.proxy({
  query: "Hello",
  requestType: "chat",
  context: {
    provider: "anthropic",  // Provider hint
    model: "claude-3-haiku" // Model hint
  }
});
```

**Note:** Provider hints are suggestions. The server makes final routing decisions based on:
- Provider health status
- Configured routing strategy
- License/compliance constraints

## Use Cases

### HIPAA Compliance (Healthcare)

Force all traffic through AWS Bedrock:

```bash
LLM_ROUTING_STRATEGY=failover
DEFAULT_LLM_PROVIDER=bedrock
PROVIDER_WEIGHTS=bedrock:100
```

### Cost Optimization (Community)

Prefer cheaper providers via weights:

```bash
PROVIDER_WEIGHTS=bedrock:60,anthropic:30,openai:10
```

### Cost Optimization (Enterprise)

Automatic cheapest provider selection:

```bash
LLM_ROUTING_STRATEGY=cost_optimized
PROVIDER_COSTS=ollama:0,bedrock:0.02,anthropic:0.025,openai:0.03
```

### High Availability

Round-robin with automatic failover:

```bash
LLM_ROUTING_STRATEGY=round_robin
# Unhealthy providers automatically skipped
```
