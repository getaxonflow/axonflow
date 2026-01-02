# Azure OpenAI Examples

This directory contains examples demonstrating how to use AxonFlow with Azure OpenAI Service.

## Overview

Azure OpenAI Service provides access to OpenAI models through Azure infrastructure. AxonFlow supports **two authentication patterns**:

| Pattern | Endpoint | Auth Header | Use Case |
|---------|----------|-------------|----------|
| **Foundry** (Recommended) | `*.cognitiveservices.azure.com` | `Authorization: Bearer <token>` | Azure AI Foundry deployments |
| **Classic** | `*.openai.azure.com` | `api-key: <key>` | Traditional Azure OpenAI resources |

> **Note:** Microsoft is transitioning to Azure AI Foundry. New users will typically get Foundry-style endpoints. Classic endpoints require specific subscription types and quota allocations.

AxonFlow auto-detects the correct authentication method from your endpoint URL.

## Prerequisites

1. An Azure account with Azure OpenAI access
2. A deployed model in Azure OpenAI (e.g., gpt-4o-mini)
3. Docker and Docker Compose installed

## Environment Variables

Set these in your `.env` file or docker-compose environment:

```bash
# Required
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com  # or *.cognitiveservices.azure.com
AZURE_OPENAI_API_KEY=your-api-key-or-bearer-token
AZURE_OPENAI_DEPLOYMENT_NAME=your-deployment-name

# Optional
AZURE_OPENAI_API_VERSION=2024-08-01-preview  # default
AZURE_OPENAI_TIMEOUT_SECONDS=120             # default
```

## Examples

| Language | Description | Files |
|----------|-------------|-------|
| [Go](./go) | Gateway and Proxy mode examples | `main.go` |
| [Python](./python) | Gateway and Proxy mode examples | `main.py` |
| [TypeScript](./typescript) | Gateway and Proxy mode examples | `src/index.ts` |
| [Java](./java) | Gateway and Proxy mode examples | `src/main/java/.../Main.java` |
| [HTTP](./http) | Raw HTTP/cURL examples | `azure-openai.http` |

## Quick Start

1. Copy `.env.example` to `.env` and fill in your Azure OpenAI credentials:

```bash
cp .env.example .env
# Edit .env with your credentials
```

2. Start AxonFlow:

```bash
docker compose up -d
```

3. Run an example:

```bash
# Go
cd go && go run main.go

# Python
cd python && pip install -r requirements.txt && python main.py

# TypeScript
cd typescript && npm install && npm start

# HTTP (using curl)
cd http && ./test.sh
```

## Gateway vs Proxy Mode

### Gateway Mode (Recommended)
- **Pre-check only**: AxonFlow validates the request before your LLM call
- **You call Azure OpenAI directly**: Full control over the LLM interaction
- **Audit after**: Report back the response for logging

```
Client -> AxonFlow (pre-check) -> Azure OpenAI -> AxonFlow (audit)
```

### Proxy Mode
- **Full proxy**: AxonFlow handles the entire LLM call
- **Simpler integration**: Just send your prompt to AxonFlow
- **Less control**: AxonFlow manages the Azure OpenAI connection

```
Client -> AxonFlow -> Azure OpenAI -> AxonFlow -> Client
```

## Troubleshooting

### 404 DeploymentNotFound
- Verify your `AZURE_OPENAI_DEPLOYMENT_NAME` matches exactly
- Check that the deployment is in "Succeeded" state in Azure Portal

### 401 Unauthorized
- For Classic: Check your API key is correct
- For Foundry: Ensure you're using a valid bearer token

### Auth Pattern Detection
AxonFlow detects the pattern from your endpoint:
- `*.openai.azure.com` -> Uses `api-key` header
- `*.cognitiveservices.azure.com` -> Uses `Authorization: Bearer` header
