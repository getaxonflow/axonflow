# Mistral AI Provider

**Last Updated:** April 2026

**Platform Version:** v6.0.0 | **SDKs:** Python v6.1.0, Go/TypeScript/Java v5.1.0

AxonFlow supports Mistral AI models for LLM routing and orchestration. Mistral is a leading European AI company based in France, offering high-performance models with competitive pricing and EU data residency options.

## Quick Start

### 1. Get API Key

1. Go to [Mistral Console](https://console.mistral.ai/)
2. Sign up or sign in
3. Navigate to **API Keys** in the left sidebar
4. Click **Create new key**
5. Copy the generated key

### 2. Configure Environment

```bash
# Required
export MISTRAL_API_KEY=your-api-key-here

# Optional: Specify model (default: mistral-small-latest)
export MISTRAL_MODEL=mistral-large-latest
```

### 3. Start AxonFlow

```bash
docker compose up -d
```

### 4. Test

```bash
curl -s http://localhost:8080/api/request \
  -H "Content-Type: application/json" \
  -d '{"query": "Hello from Mistral!", "context": {"provider": "mistral"}}'
```

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISTRAL_API_KEY` | Yes | — | Mistral API key from console.mistral.ai |
| `MISTRAL_MODEL` | No | `mistral-small-latest` | Default model for completions |
| `MISTRAL_ENDPOINT` | No | `https://api.mistral.ai` | Custom API endpoint (for self-hosted or EU-specific deployments) |
| `MISTRAL_TIMEOUT_SECONDS` | No | `120` | HTTP request timeout |

### Supported Models

| Model | Context | Pricing (per 1M tokens) | Use Case |
|-------|---------|------------------------|----------|
| `mistral-small-latest` | 32K | $0.10 input / $0.30 output | Fast, cost-effective. Best for most use cases. |
| `mistral-medium-latest` | 32K | $0.40 input / $1.20 output | Balanced capability and cost |
| `mistral-large-latest` | 128K | $2 input / $6 output | Most capable. Complex reasoning, analysis. |
| `codestral-latest` | 32K | $0.30 input / $0.90 output | Code generation and review |
| `open-mistral-nemo` | 128K | $0.15 input / $0.15 output | Open-weight, self-hostable |
| `ministral-8b-latest` | 128K | $0.10 input / $0.10 output | Lightweight, low latency |
| `pixtral-large-latest` | 128K | $2 input / $6 output | Vision + text multimodal |

### Capabilities

- Chat completions
- Streaming (SSE)
- Code generation (Codestral)
- EU data residency (Mistral's infrastructure is EU-based)

**Planned (not yet implemented):**
- Function calling / tool use (requires tools/tool_choice request fields)
- Vision / Pixtral (requires multimodal message content blocks)
- JSON mode (requires response_format field)

## Usage Examples

### Proxy Mode (Recommended)

Route requests through AxonFlow with automatic policy enforcement:

```bash
curl -X POST http://localhost:8080/api/request \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Explain EU AI Act compliance requirements.",
    "context": {"provider": "mistral"}
  }'
```

### Gateway Mode

Pre-check policies, call Mistral directly, then audit:

```bash
# Step 1: Pre-check
PRECHECK=$(curl -s -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -d '{"query": "Analyze customer data", "context": {"provider": "mistral"}}')

CONTEXT_ID=$(echo "$PRECHECK" | jq -r '.context_id')

# Step 2: Call Mistral directly
RESPONSE=$(curl -s https://api.mistral.ai/v1/chat/completions \
  -H "Authorization: Bearer $MISTRAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "mistral-small-latest", "messages": [{"role": "user", "content": "Analyze customer data"}]}')

# Step 3: Audit
curl -X POST http://localhost:8080/api/audit/llm-call \
  -H "Content-Type: application/json" \
  -d "{\"context_id\": \"$CONTEXT_ID\", \"provider\": \"mistral\", \"model\": \"mistral-small-latest\", \"latency_ms\": 500, \"token_usage\": {\"prompt_tokens\": 10, \"completion_tokens\": 50, \"total_tokens\": 60}}"
```

### Multi-Provider Routing

Use Mistral alongside other providers with weighted routing:

```bash
# Set provider weights in environment
export LLM_ROUTING_STRATEGY=weighted
export MISTRAL_API_KEY=your-key
export OPENAI_API_KEY=your-key

# AxonFlow routes based on configured weights
docker compose up -d
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `401 Unauthorized` | Invalid or expired API key | Regenerate key at console.mistral.ai |
| `429 Too Many Requests` | Rate limit exceeded | Reduce request frequency or upgrade plan |
| Provider not appearing in health check | `MISTRAL_API_KEY` not set | Set the environment variable before starting |
| Timeout errors | Model overloaded | Increase `MISTRAL_TIMEOUT_SECONDS` or use `mistral-small-latest` |

## Examples

- [Hello World](/examples/llm-providers/mistral/hello-world/) — Gateway + Proxy mode (HTTP, Go, Python, TypeScript, Java)
- [PII Detection](/examples/llm-providers/mistral/pii-detection/) — PII policy enforcement through Mistral
- [Proxy Mode](/examples/llm-providers/mistral/proxy-mode/) — Proxy mode with SQLi blocking and audit trails
