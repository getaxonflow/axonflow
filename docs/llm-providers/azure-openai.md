# Azure OpenAI Provider

Azure OpenAI Service provides REST API access to OpenAI's GPT models through Microsoft Azure infrastructure.

## Quick Start

### 1. Set Environment Variables

```bash
export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
export AZURE_OPENAI_API_KEY=your-api-key
export AZURE_OPENAI_DEPLOYMENT_NAME=gpt-4o-mini
export AZURE_OPENAI_API_VERSION=2024-08-01-preview
```

### 2. Start AxonFlow

```bash
docker compose up -d
```

### 3. Test

```bash
curl -X POST http://localhost:8080/api/request \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Hello from Azure OpenAI!",
    "context": {"provider": "azure-openai"}
  }'
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_OPENAI_ENDPOINT` | Yes | Azure OpenAI resource URL |
| `AZURE_OPENAI_API_KEY` | Yes | API key or access token |
| `AZURE_OPENAI_DEPLOYMENT_NAME` | Yes | Model deployment name |
| `AZURE_OPENAI_API_VERSION` | No | API version (default: `2024-08-01-preview`) |

## Endpoint Patterns

Azure OpenAI supports two endpoint patterns that AxonFlow auto-detects:

| Pattern | Domain | Use Case |
|---------|--------|----------|
| **Foundry** | `*.cognitiveservices.azure.com` | New deployments, AI Foundry |
| **Classic** | `*.openai.azure.com` | Legacy deployments |

Both use `Authorization: Bearer <key>` authentication.

## Supported Models

| Model | Deployment Name | Use Case |
|-------|-----------------|----------|
| GPT-4o | `gpt-4o` | Latest, multimodal |
| GPT-4o Mini | `gpt-4o-mini` | Cost-effective |
| GPT-4 Turbo | `gpt-4-turbo` | Fast GPT-4 |
| GPT-4 | `gpt-4` | Standard GPT-4 |
| GPT-3.5 Turbo | `gpt-35-turbo` | Budget-friendly |

## Integration Modes

### Gateway Mode (Recommended)

Your application calls Azure OpenAI directly. AxonFlow provides policy enforcement and audit logging.

```
[Your App] → [AxonFlow Pre-check] → [Azure OpenAI] → [AxonFlow Audit] → [Response]
```

**Benefits:**
- Full control over Azure OpenAI parameters
- Lowest latency
- Use existing Azure credentials

### Proxy Mode

AxonFlow handles all Azure OpenAI communication. Your app just sends queries.

```
[Your App] → [AxonFlow] → [Azure OpenAI] → [Response]
```

**Benefits:**
- Simplest integration
- Centralized credential management
- Automatic policy enforcement

## Examples

### Community Examples

| Example | Language | Location |
|---------|----------|----------|
| Hello World | Go | `examples/llm-providers/azure-openai/hello-world/go/` |
| Hello World | Python | `examples/llm-providers/azure-openai/hello-world/python/` |
| Hello World | TypeScript | `examples/llm-providers/azure-openai/hello-world/typescript/` |
| Hello World | Java | `examples/llm-providers/azure-openai/hello-world/java/` |
| Hello World | HTTP/curl | `examples/llm-providers/azure-openai/hello-world/http/` |
| Proxy Mode | Go | `examples/llm-providers/azure-openai/proxy-mode/go/` |
| PII Detection | Python | `examples/llm-providers/azure-openai/pii-detection/python/` |
| SQL Injection | TypeScript | `examples/llm-providers/azure-openai/sqli-scanning/typescript/` |

### Enterprise Examples

| Example | Language | Location |
|---------|----------|----------|
| HITL Approval | Go | `ee/examples/llm-providers/azure-openai/hitl-approval/go/` |
| Multi-Tenant | Python | `ee/examples/llm-providers/azure-openai/multi-tenant/python/` |
| Compliance Audit | TypeScript | `ee/examples/llm-providers/azure-openai/compliance-audit/typescript/` |
| Policy Override | Java | `ee/examples/llm-providers/azure-openai/policy-override/java/` |
| Cost Attribution | Go | `ee/examples/llm-providers/azure-openai/cost-attribution/go/` |

## Troubleshooting

### 404 DeploymentNotFound

**Cause:** Wrong API version for your endpoint pattern.

**Solution:**
- Foundry endpoints: Use `2024-08-01-preview` or later
- Classic endpoints: Use `2024-02-15-preview` or later

### 401 Unauthorized

**Cause:** Invalid API key or wrong auth header.

**Solution:** Verify your API key is correct and the endpoint URL matches your Azure resource.

### Connection Refused

**Cause:** Azure OpenAI resource not accessible.

**Solution:**
1. Verify endpoint URL is correct
2. Check Azure network security settings
3. Verify your IP is allowed (if using firewall)

## Azure-Specific Features

### Data Residency

Azure OpenAI keeps data within your Azure region. Configure AxonFlow with region-specific endpoints for compliance.

### Private Endpoints

For VNet integration, configure Azure Private Link and update `AZURE_OPENAI_ENDPOINT` to use your private endpoint.

### Azure Active Directory

For AAD authentication (instead of API keys), obtain a Bearer token from AAD and set it as `AZURE_OPENAI_API_KEY`.

## Related Documentation

- [LLM Provider Guide](../guides/llm-providers.md)
- [Getting Started](../getting-started.md)
- [Azure OpenAI Service Docs](https://learn.microsoft.com/azure/cognitive-services/openai/)
