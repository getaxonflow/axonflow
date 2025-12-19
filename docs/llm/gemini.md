# Google Gemini Provider

AxonFlow supports Google's Gemini models for LLM routing and orchestration. This guide covers configuration, supported models, and usage.

## Quick Start

### 1. Get API Key

1. Go to [Google AI Studio](https://aistudio.google.com/apikey)
2. Create or select a Google Cloud project
3. Click "Create API Key"
4. Copy the generated key

### 2. Configure Environment

```bash
# Required
export GOOGLE_API_KEY=your-api-key-here

# Optional: Specify model (default: gemini-2.0-flash)
export GOOGLE_MODEL=gemini-2.5-flash
```

### 3. Start AxonFlow

```bash
docker-compose up -d
```

## Supported Models

| Model | Context Window | Best For |
|-------|---------------|----------|
| `gemini-2.5-flash` | 1M tokens | Latest, fastest model |
| `gemini-2.5-pro` | 2M tokens | Latest, highest quality |
| `gemini-2.0-flash` | 1M tokens | Fast, general-purpose tasks (default) |
| `gemini-2.0-flash-lite` | 1M tokens | Cost-optimized, simple tasks |
| `gemini-1.5-pro` | 2M tokens | Complex reasoning, long context (legacy) |
| `gemini-1.5-flash` | 1M tokens | Balanced speed/quality (legacy) |

## Configuration Options

### Provider Configuration

```yaml
# In your provider configuration
providers:
  - name: gemini-primary
    type: gemini
    api_key: ${GOOGLE_API_KEY}
    model: gemini-2.0-flash
    timeout_seconds: 120
    enabled: true
    priority: 100
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GOOGLE_API_KEY` | Yes | - | Google AI API key |
| `GOOGLE_MODEL` | No | `gemini-2.0-flash` | Default model |
| `GOOGLE_ENDPOINT` | No | `https://generativelanguage.googleapis.com` | API endpoint |
| `GOOGLE_TIMEOUT_SECONDS` | No | `120` | Request timeout (seconds) |

## Capabilities

The Gemini provider supports:

- **Chat completions** - Conversational AI
- **Streaming responses** - Real-time token streaming
- **Long context** - Up to 2M tokens (Gemini 2.5 Pro)
- **Vision** - Image understanding
- **Function calling** - Tool use
- **Code generation** - Programming assistance

## Usage Examples

### Proxy Mode (Python SDK)

Proxy mode routes requests through AxonFlow for simple integration:

```python
from axonflow import AxonFlow

async with AxonFlow(agent_url="http://localhost:8080") as client:
    # Execute query through AxonFlow (routes to configured Gemini provider)
    response = await client.execute_query(
        user_token="user-123",
        query="Explain quantum computing",
        request_type="chat",
        context={"provider": "gemini", "model": "gemini-2.0-flash"}
    )
    print(response.content)
```

### Proxy Mode (cURL)

```bash
curl -X POST http://localhost:8080/api/request \
  -H "Content-Type: application/json" \
  -H "X-User-Token: user-123" \
  -d '{
    "query": "What is machine learning?",
    "provider": "gemini",
    "model": "gemini-2.0-flash",
    "max_tokens": 500
  }'
```

### Gateway Mode (TypeScript SDK)

Gateway mode gives you full control over the LLM call while AxonFlow handles policy enforcement and audit logging:

```typescript
import { AxonFlow } from '@axonflow/sdk';
import { GoogleGenerativeAI } from '@google/generative-ai';

const axonflow = new AxonFlow({
  endpoint: 'http://localhost:8080',
  apiKey: 'your-axonflow-key'
});

// 1. Pre-check: Get policy approval
const ctx = await axonflow.getPolicyApprovedContext({
  userToken: 'user-123',
  query: 'Explain quantum computing'
});

if (!ctx.approved) {
  throw new Error(`Blocked: ${ctx.blockReason}`);
}

// 2. Call Gemini directly
const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
const result = await model.generateContent(ctx.approvedData.query);
const response = result.response.text();

// 3. Audit the call
await axonflow.auditLLMCall(
  ctx.contextId,
  response.substring(0, 100),  // Summary
  'gemini',
  'gemini-2.0-flash',
  { promptTokens: 50, completionTokens: 100, totalTokens: 150 },
  250  // latency ms
);
```

## Streaming

Gemini supports server-sent events (SSE) for streaming responses. Use the Gemini SDK directly:

```typescript
import { GoogleGenerativeAI } from '@google/generative-ai';

const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

const result = await model.generateContentStream('Write a long story');

for await (const chunk of result.stream) {
  const text = chunk.text();
  process.stdout.write(text);
}
```

## Pricing

Gemini pricing (as of January 2025):

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|-------|----------------------|------------------------|
| Gemini 2.0 Flash | $0.10 | $0.40 |
| Gemini 1.5 Pro (≤128K) | $1.25 | $5.00 |
| Gemini 1.5 Pro (>128K) | $2.50 | $10.00 |
| Gemini 1.5 Flash | $0.075 | $0.30 |

AxonFlow provides cost estimation via the `/api/cost/estimate` endpoint.

## Error Handling

Common error codes from Gemini:

| Status | Reason | Action |
|--------|--------|--------|
| 400 | Invalid request | Check request format |
| 401 | Invalid API key | Verify `GOOGLE_API_KEY` |
| 403 | Permission denied | Check API key permissions |
| 429 | Rate limit | Implement backoff/retry |
| 500 | Server error | Retry with exponential backoff |

AxonFlow automatically handles retries for transient errors (429, 500, 503).

## Health Checks

The Gemini provider reports health status at:

```bash
curl http://localhost:8081/health
```

Response includes Gemini provider status:

```json
{
  "status": "healthy",
  "providers": {
    "gemini": {
      "status": "healthy",
      "latency_ms": 45
    }
  }
}
```

## Multi-Provider Routing

Configure Gemini alongside other providers for intelligent routing:

```yaml
providers:
  - name: gemini-primary
    type: gemini
    priority: 100
    enabled: true

  - name: openai-fallback
    type: openai
    priority: 50
    enabled: true

routing:
  strategy: priority
  fallback_enabled: true
```

## Best Practices

1. **Use appropriate models** - Gemini Flash for speed, Pro for quality
2. **Set reasonable timeouts** - 120s default is good for most use cases
3. **Enable fallback providers** - Configure OpenAI/Anthropic as backup
4. **Monitor costs** - Use AxonFlow's cost dashboard to track usage
5. **Handle rate limits** - Implement client-side retry logic for high-volume apps

## Troubleshooting

### "API key not valid"
- Verify the key at [Google AI Studio](https://aistudio.google.com/apikey)
- Ensure the key has Generative Language API enabled

### "Model not found"
- Check model name spelling
- Verify model availability in your region

### "Quota exceeded"
- Check usage at [Google Cloud Console](https://console.cloud.google.com)
- Consider upgrading to a paid plan

## See Also

- [LLM Provider Overview](./overview.md)
- [Multi-Model Routing](./routing.md)
- [Cost Optimization](../guides/cost-optimization.md)
