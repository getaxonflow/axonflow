# Mistral LLM Provider - Hello World

Demonstrates Mistral AI integration with AxonFlow in Gateway Mode and Proxy Mode.

## Prerequisites

- AxonFlow running (`docker compose up -d`)
- Mistral API key ([console.mistral.ai](https://console.mistral.ai/))

## Quick Start

```bash
# Set your Mistral API key
export MISTRAL_API_KEY=your-api-key

# HTTP (cURL)
cd http && ./mistral.sh

# Go
cd go && go run main.go

# Python
cd python && pip install -r requirements.txt && python main.py

# TypeScript
cd typescript && npm install && npx tsx index.ts

# Java
cd java && mvn exec:java -q
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISTRAL_API_KEY` | Yes | — | Mistral API key |
| `MISTRAL_MODEL` | No | `mistral-small-latest` | Default model |
| `AXONFLOW_ENDPOINT` | No | `http://localhost:8080` | AxonFlow agent URL |
| `AXONFLOW_CLIENT_ID` | No | `community` | OAuth2 client ID |
| `AXONFLOW_CLIENT_SECRET` | No | — | OAuth2 client secret |

## Supported Models

| Model | Use Case | Context Window |
|-------|----------|---------------|
| `mistral-small-latest` | Fast, cost-effective (default) | 32K |
| `mistral-medium-latest` | Balanced capability | 32K |
| `mistral-large-latest` | Most capable | 128K |
| `codestral-latest` | Code generation | 32K |
| `open-mistral-nemo` | Open-weight, self-hostable | 128K |
| `ministral-8b-latest` | Lightweight, low latency | 128K |
| `pixtral-large-latest` | Vision + text multimodal (vision not yet supported in AxonFlow) | 128K |

## What This Tests

- **Gateway Mode**: Pre-check policy evaluation, direct Mistral API call, audit logging
- **Proxy Mode**: Request routed through AxonFlow with LLM response
- **Streaming**: SSE streaming from Mistral API
- **Policy Enforcement**: SQL injection blocked, dangerous commands blocked

## Additional Mistral Examples

| Example | Description |
|---------|-------------|
| [PII Detection](../pii-detection/) | SSN + Aadhaar detection through Mistral |
| [Proxy Mode](../proxy-mode/) | Full proxy mode with SQLi + dangerous command blocking + audit |
| [MAP Basic](../map-basic/) | Multi-Agent Plan generation — Mistral decomposes tasks into agent steps |
| [MAP Lifecycle](../map-lifecycle/) | Full MAP lifecycle: generate, execute, cancel, versioning |
| [MAP Confirm Mode](../map-confirm-mode/) | HITL approval before execution (Enterprise) |
