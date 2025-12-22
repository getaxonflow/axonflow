# AxonFlow Examples

Comprehensive examples for integrating AxonFlow into your applications.

## Quick Start

```bash
# Start AxonFlow locally
docker compose up -d

# Choose an example and run it
cd integrations/gateway-mode/python
pip install -r requirements.txt
python main.py
```

## Examples Overview

### Hello World

The simplest integration - check if queries pass policy evaluation.

| Language | Path | Description |
|----------|------|-------------|
| Go | `hello-world/go/` | Basic Go SDK usage |
| TypeScript | `hello-world/typescript/` | Basic TypeScript SDK usage |
| Python | `hello-world/python/` | Basic Python SDK usage |

### Integration Modes

Two ways to integrate AxonFlow:

#### Gateway Mode (Lowest Latency)

You make LLM calls directly; AxonFlow handles policy pre-check and audit.

```
Your App → AxonFlow Pre-check → Your LLM Call → AxonFlow Audit
```

| Language | Path |
|----------|------|
| TypeScript | `integrations/gateway-mode/typescript/` |
| Go | `integrations/gateway-mode/go/` |
| Python | `integrations/gateway-mode/python/` |

#### Proxy Mode (Simplest)

AxonFlow handles everything - policy enforcement AND LLM routing.

```
Your App → AxonFlow (Policy + LLM) → Response
```

| Language | Path |
|----------|------|
| TypeScript | `integrations/proxy-mode/typescript/` |
| Go | `integrations/proxy-mode/go/` |
| Python | `integrations/proxy-mode/python/` |

### Framework Integrations

Use AxonFlow with popular AI frameworks.

| Framework | Path | Description |
|-----------|------|-------------|
| LangChain | `integrations/langchain/` | Chains, RAG with governance |
| CrewAI | `integrations/crewai/` | Multi-agent governance |

### Policy Management

Programmatic policy CRUD operations.

| Example | Path | Description |
|---------|------|-------------|
| CRUD | `policies/crud/` | Create, read, update, delete policies |

## SDK Versions

All examples use the latest SDK versions:

| SDK | Package | Version |
|-----|---------|---------|
| TypeScript | `@axonflow/sdk` | ^1.4.1 |
| Go | `github.com/getaxonflow/axonflow-sdk-go` | v1.5.0 |
| Python | `axonflow-sdk` | ^0.3.0 |

## Environment Configuration

Each example includes a `.env.example` file. Copy and configure:

```bash
cp .env.example .env
# Edit .env with your configuration
```

Common environment variables:

```bash
AXONFLOW_AGENT_URL=http://localhost:8080
AXONFLOW_CLIENT_ID=demo
AXONFLOW_CLIENT_SECRET=demo-secret
AXONFLOW_LICENSE_KEY=your-license-key  # Enterprise only
```

## Running with Docker

```bash
# Start AxonFlow stack
docker compose up -d

# Verify services are healthy
curl http://localhost:8080/health
```

## Enterprise Examples

Enterprise-only examples are in `ee/examples/`:

- AWS Bedrock LLM provider
- Amadeus travel connector
- Salesforce CRM connector
- EU AI Act compliance
- RBI/SEBI compliance (India)

See [ee/examples/README.md](../ee/examples/README.md) for details.

## Documentation

- [AxonFlow Docs](https://docs.getaxonflow.com)
- [Gateway Mode Guide](https://docs.getaxonflow.com/docs/integrations/gateway-mode)
- [Proxy Mode Guide](https://docs.getaxonflow.com/docs/integrations/proxy-mode)
- [SDK Reference](https://docs.getaxonflow.com/docs/sdk/overview)
