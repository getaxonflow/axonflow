# Azure OpenAI Provider

**Last Updated:** February 2026

**Platform Version:** v4.5.0 | **SDKs:** v3.7.0

AxonFlow supports Azure OpenAI Service as a Community LLM provider, available without an enterprise license.

## Quick Start

### 1. Get Azure OpenAI Credentials

1. Create an Azure OpenAI resource in [Azure Portal](https://portal.azure.com)
2. Deploy a model (e.g., `gpt-4o-mini`)
3. Copy your endpoint and API key

### 2. Configure Environment

```bash
# Required
export AZURE_OPENAI_ENDPOINT="https://your-resource.cognitiveservices.azure.com"
export AZURE_OPENAI_API_KEY="your-api-key"
export AZURE_OPENAI_DEPLOYMENT_NAME="gpt-4o-mini"

# Optional
export AZURE_OPENAI_API_VERSION="2024-08-01-preview"
```

### 3. Use with AxonFlow

```bash
# Start AxonFlow
docker compose up -d

# Test with Proxy Mode
curl -X POST http://localhost:8080/api/v1/query/execute \
  -H "Content-Type: application/json" \
  -H "X-Client-Id: demo-org" \
  -H "X-Client-Secret: your-license-key" \
  -d '{
    "user_token": "user-123",
    "query": "Hello!",
    "request_type": "chat",
    "context": {"provider": "azure-openai"}
  }'
```

> **Authentication:** All AxonFlow API requests require `X-Client-Id` and `X-Client-Secret` headers. Alternatively, use `Authorization: Basic` with Base64-encoded `clientId:clientSecret`.

## Authentication Patterns

AxonFlow auto-detects the authentication method from your endpoint URL:

| Endpoint Pattern | Auth Method | Header |
|------------------|-------------|--------|
| `*.cognitiveservices.azure.com` | Bearer Token | `Authorization: Bearer <key>` |
| `*.openai.azure.com` | API Key | `api-key: <key>` |

> **Note:** Microsoft is transitioning to Azure AI Foundry. New Azure OpenAI resources typically use the `cognitiveservices.azure.com` endpoint pattern.

## Configuration Reference

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `AZURE_OPENAI_ENDPOINT` | Yes | - | Azure OpenAI endpoint URL |
| `AZURE_OPENAI_API_KEY` | Yes | - | API key or bearer token |
| `AZURE_OPENAI_DEPLOYMENT_NAME` | Yes | - | Model deployment name |
| `AZURE_OPENAI_API_VERSION` | No | `2024-08-01-preview` | API version |
| `AZURE_OPENAI_TIMEOUT_SECONDS` | No | `120` | Request timeout |

## Supported Models

Azure OpenAI supports various OpenAI models. Common deployments include:

- `gpt-4o` - Latest GPT-4 Omni model
- `gpt-4o-mini` - Cost-effective GPT-4o variant
- `gpt-4` - Standard GPT-4

> **Note:** In Azure OpenAI, the "model" is your deployment name, which can be any string you choose when deploying.

## Gateway Mode Example

Gateway Mode gives you full control over the LLM interaction:

```python
import requests
import os

AXONFLOW_URL = "http://localhost:8080"
AZURE_ENDPOINT = os.environ["AZURE_OPENAI_ENDPOINT"]
AZURE_KEY = os.environ["AZURE_OPENAI_API_KEY"]
DEPLOYMENT = os.environ["AZURE_OPENAI_DEPLOYMENT_NAME"]

# Step 1: Pre-check with AxonFlow
pre_check = requests.post(f"{AXONFLOW_URL}/api/v1/pre-check", json={
    "query": "What is Azure?",
    "context": {"provider": "azure-openai", "model": DEPLOYMENT}
}).json()

if pre_check.get("blocked"):
    print(f"Blocked: {pre_check['reason']}")
    exit(1)

context_id = pre_check["context_id"]

# Step 2: Call Azure OpenAI directly
headers = {"Content-Type": "application/json"}
if "cognitiveservices.azure.com" in AZURE_ENDPOINT:
    headers["Authorization"] = f"Bearer {AZURE_KEY}"
else:
    headers["api-key"] = AZURE_KEY

response = requests.post(
    f"{AZURE_ENDPOINT}/openai/deployments/{DEPLOYMENT}/chat/completions?api-version=2024-08-01-preview",
    headers=headers,
    json={"messages": [{"role": "user", "content": "What is Azure?"}], "max_tokens": 500}
).json()

content = response["choices"][0]["message"]["content"]
print(f"Response: {content}")

# Step 3: Audit with AxonFlow
requests.post(f"{AXONFLOW_URL}/api/v1/audit", json={
    "context_id": context_id,
    "response": content,
    "usage": response["usage"]
})
```

## Proxy Mode SDK Examples

Proxy Mode is simpler -- AxonFlow handles the Azure OpenAI call for you, applying policies and audit logging automatically.

### Python SDK

```python
from axonflow import AxonFlow

client = AxonFlow(
    endpoint="http://localhost:8080",
    client_id="demo-org",
    client_secret="your-license-key",
)

response = client.proxy_llm_call(
    user_token="user-123",
    query="Explain Azure OpenAI in one sentence.",
    request_type="chat",
    context={"provider": "azure-openai"},
)
print(response.content)
```

### Go SDK

```go
client, err := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "http://localhost:8080",
    ClientID:     "demo-org",
    ClientSecret: "your-license-key",
})
if err != nil {
    log.Fatal(err)
}

resp, err := client.ProxyLLMCall(
    "user-123",
    "Explain Azure OpenAI in one sentence.",
    "chat",
    map[string]interface{}{"provider": "azure-openai"},
)
if err != nil {
    log.Fatal(err)
}
fmt.Println(resp.Content)
```

### TypeScript SDK

```typescript
const client = new AxonFlow({
  endpoint: 'http://localhost:8080',
  clientId: 'demo-org',
  clientSecret: 'your-license-key',
});

const response = await client.proxyLLMCall({
  userToken: 'user-123',
  query: 'Explain Azure OpenAI in one sentence.',
  requestType: 'chat',
  context: { provider: 'azure-openai' },
});
console.log(response.content);
```

### Java SDK

```java
AxonFlowClient client = AxonFlowClient.builder()
    .endpoint("http://localhost:8080")
    .clientId("demo-org")
    .clientSecret("your-license-key")
    .build();

var response = client.proxyLlmCall(
    "user-123",
    "Explain Azure OpenAI in one sentence.",
    "chat",
    Map.of("provider", "azure-openai")
);
System.out.println(response.getContent());
```

## Troubleshooting

### 404 DeploymentNotFound

- Verify `AZURE_OPENAI_DEPLOYMENT_NAME` matches your Azure deployment exactly
- Check the deployment status in Azure Portal (must be "Succeeded")

### 401 Unauthorized

- For Foundry endpoints: Ensure your API key is valid
- For Classic endpoints: Check the API key in Azure Portal → Keys and Endpoint

### No Quota Available

Azure OpenAI requires quota allocation. If you can't deploy models:
1. Check your subscription type (some free tiers have no quota)
2. Request quota increase in Azure Portal → Quotas
3. Consider using Azure AI Foundry which may have different quota policies

## Examples

Complete code examples are available:

### Community Examples
- [Hello World (Go, Python, TypeScript, Java, HTTP)](../../examples/llm-providers/azure-openai/hello-world/)
- [PII Detection (Python)](../../examples/llm-providers/azure-openai/pii-detection/python/)
- [SQL Injection Scanning (TypeScript)](../../examples/llm-providers/azure-openai/sqli-scanning/typescript/)
- [Proxy Mode (Go)](../../examples/llm-providers/azure-openai/proxy-mode/go/)

### Enterprise Examples
- [HITL Approval (Go)](../../ee/examples/llm-providers/azure-openai/hitl-approval/go/)
- [Cost Attribution (Go)](../../ee/examples/llm-providers/azure-openai/cost-attribution/go/)
- [Multi-Tenant (Python)](../../ee/examples/llm-providers/azure-openai/multi-tenant/python/)
- [Compliance Audit (TypeScript)](../../ee/examples/llm-providers/azure-openai/compliance-audit/typescript/)

## See Also

- [LLM Providers Guide](../guides/llm-providers.md) - Configure provider routing
- [Azure OpenAI Documentation](https://learn.microsoft.com/azure/ai-services/openai/)
