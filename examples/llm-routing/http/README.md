# LLM Provider Routing - HTTP Examples

Direct HTTP/curl examples for LLM provider routing without requiring an SDK.

## Prerequisites

- AxonFlow Agent running at `http://localhost:8080`
- Valid license key (or `DEPLOYMENT_MODE=community` for testing)
- LLM provider configured (OpenAI, Anthropic, Ollama, or Gemini)

## Quick Start

```bash
# Make the script executable
chmod +x provider-routing.sh

# Run all examples
./provider-routing.sh

# Or run individual curl commands from the script
```

## Examples

### 1. Default Routing (Server Decides Provider)

```bash
curl -X POST http://localhost:8080/api/request \
  -H "Content-Type: application/json" \
  -H "X-License-Key: ${AXONFLOW_LICENSE_KEY}" \
  -d '{
    "query": "What is 2 + 2?",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat"
  }'
```

### 2. Request Specific Provider

```bash
curl -X POST http://localhost:8080/api/request \
  -H "Content-Type: application/json" \
  -H "X-License-Key: ${AXONFLOW_LICENSE_KEY}" \
  -d '{
    "query": "What is the capital of France?",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat",
    "context": {
      "provider": "anthropic"
    }
  }'
```

### 3. Request with Specific Model

```bash
curl -X POST http://localhost:8080/api/request \
  -H "Content-Type: application/json" \
  -H "X-License-Key: ${AXONFLOW_LICENSE_KEY}" \
  -d '{
    "query": "Explain machine learning in one sentence",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat",
    "context": {
      "provider": "openai",
      "model": "gpt-4o-mini"
    }
  }'
```

### 4. Health Check

```bash
curl http://localhost:8080/health
```

### 5. Gateway Mode (Pre-check + Audit)

For SDK-managed LLM calls where you make direct calls to providers:

```bash
# Step 1: Pre-check
PRECHECK=$(curl -s -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -H "X-License-Key: ${AXONFLOW_LICENSE_KEY}" \
  -d '{
    "query": "What is AI?",
    "user_token": "demo-user",
    "client_id": "http-example"
  }')

CONTEXT_ID=$(echo $PRECHECK | jq -r '.context_id')
echo "Context ID: $CONTEXT_ID"

# Step 2: Make your LLM call directly to OpenAI/Anthropic/etc.
# ... your direct API call ...

# Step 3: Audit the result
curl -X POST http://localhost:8080/api/policy/audit \
  -H "Content-Type: application/json" \
  -H "X-License-Key: ${AXONFLOW_LICENSE_KEY}" \
  -d "{
    \"context_id\": \"$CONTEXT_ID\",
    \"response_metadata\": {
      \"provider\": \"openai\",
      \"model\": \"gpt-4o\",
      \"tokens_used\": 150,
      \"latency_ms\": 500
    }
  }"
```

## Server-Side Configuration

LLM routing is configured server-side via environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `LLM_ROUTING_STRATEGY` | Routing strategy | `weighted`, `round_robin`, `failover` |
| `PROVIDER_WEIGHTS` | Provider weights for weighted strategy | `openai:50,anthropic:30,ollama:20` |
| `DEFAULT_LLM_PROVIDER` | Default provider | `openai` |
| `OPENAI_API_KEY` | OpenAI API key | `sk-...` |
| `ANTHROPIC_API_KEY` | Anthropic API key | `sk-ant-...` |
| `GOOGLE_API_KEY` | Google Gemini API key | `AIza...` |
| `OLLAMA_BASE_URL` | Ollama base URL | `http://localhost:11434` |

## Supported Providers

| Provider | Community | Enterprise |
|----------|:---------:|:----------:|
| OpenAI | Yes | Yes |
| Anthropic | Yes | Yes |
| Google Gemini | Yes | Yes |
| Ollama (local) | Yes | Yes |
| AWS Bedrock | No | Yes |

## Response Format

```json
{
  "success": true,
  "data": {
    "response": "The answer is 4."
  },
  "policy_info": {
    "policies_evaluated": ["pii-detection"],
    "static_checks": ["ssn_pattern", "credit_card"],
    "processing_time": "12.5ms"
  }
}
```

## Error Handling

### Policy Blocked Response

```json
{
  "success": false,
  "blocked": true,
  "block_reason": "Query contains PII (SSN detected)",
  "policy_info": {
    "policies_evaluated": ["pii-ssn"],
    "processing_time": "2.1ms"
  }
}
```

### Provider Unavailable

```json
{
  "success": false,
  "error": "All LLM providers are unavailable",
  "error_code": "PROVIDER_UNAVAILABLE"
}
```

## See Also

- [LLM Provider Configuration](https://docs.getaxonflow.com/docs/llm/overview)
- [SDK Examples](../go/) for language-specific SDKs
- [Gateway Mode Guide](https://docs.getaxonflow.com/docs/concepts/gateway-mode)
