# Community LLM Routing E2E Tests

End-to-end tests for Community LLM provider routing functionality.

## Prerequisites

1. Start the orchestrator:
   ```bash
   docker compose up -d
   ```

2. Configure API keys via environment variables:
   ```bash
   export OPENAI_API_KEY=sk-...
   export ANTHROPIC_API_KEY=sk-ant-...
   export GEMINI_API_KEY=...
   ```

## Available Tests

### HTTP/curl Tests

```bash
# Test all 3 Community providers (OpenAI, Anthropic, Gemini)
./http/test-community-providers.sh

# Test routing strategies (weighted, round-robin, failover)
./http/test-routing-strategies.sh

# Test health check monitoring and failover recovery
./http/test-health-recovery.sh

# Test concurrent requests and load handling
./http/test-concurrent-requests.sh
# Or with custom concurrency: CONCURRENT=20 TOTAL=100 ./http/test-concurrent-requests.sh
```

### Go SDK Tests

```bash
cd go
# Basic SDK test
go run main.go

# Load test with concurrent requests
go run loadtest.go
# Or with custom settings: CONCURRENT=20 TOTAL=100 go run loadtest.go
```

### Python SDK Tests

```bash
cd python
pip install axonflow
python main.py
```

### TypeScript SDK Tests

```bash
cd typescript
npm install @axonflow/sdk
npx ts-node main.ts
```

### Java SDK Tests

```bash
cd java
mvn compile exec:java -Dexec.mainClass="com.example.LLMProviderTests"
```

## Test Coverage

| Test | Description |
|------|-------------|
| Provider listing | List all 3 Community providers |
| Per-request selection | Select specific provider per request |
| Weighted routing | Verify weighted distribution |
| Routing strategies | Test weighted, round-robin, failover |
| Response times | Compare provider latencies |
| Health monitoring | Verify health checks and failover recovery |
| Concurrent requests | Test parallel request handling |
| Load testing | Measure throughput and percentiles under load |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ORCHESTRATOR_URL` | Orchestrator endpoint | `http://localhost:8081` |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `GOOGLE_API_KEY` | Google Gemini API key | - |
| `LLM_ROUTING_STRATEGY` | Routing strategy | `weighted` |

## Routing Strategies

Test different routing strategies:

```bash
# Weighted routing (default)
LLM_ROUTING_STRATEGY=weighted docker compose up -d

# Round-robin routing
LLM_ROUTING_STRATEGY=round_robin docker compose up -d

# Failover routing
LLM_ROUTING_STRATEGY=failover docker compose up -d
```
