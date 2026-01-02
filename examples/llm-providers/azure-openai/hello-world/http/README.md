# Azure OpenAI HTTP/curl Example

Demonstrates Azure OpenAI integration with AxonFlow using raw HTTP requests.

## Prerequisites

- AxonFlow running locally on port 8080
- Azure OpenAI credentials set in environment

## Environment Variables

```bash
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
export AZURE_OPENAI_API_KEY="your-api-key"
export AZURE_OPENAI_DEPLOYMENT_NAME="gpt-4o-mini"
export AZURE_OPENAI_API_VERSION="2024-08-01-preview"  # optional
```

## Run

```bash
./test.sh
```

## Endpoints Used

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/policy/pre-check` | POST | Pre-check request with policy engine |
| `/api/audit/llm-call` | POST | Audit LLM call for compliance |
| `/api/request` | POST | Proxy mode - AxonFlow calls LLM |
