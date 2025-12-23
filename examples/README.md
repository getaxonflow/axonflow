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
| Python | `hello-world/python/` | Basic Python SDK usage |
| TypeScript | `hello-world/typescript/` | Basic TypeScript SDK usage |
| Go | `hello-world/go/` | Basic Go SDK usage |
| Java | `hello-world/java/` | Basic Java SDK usage |

### Integration Modes

Two ways to integrate AxonFlow:

#### Gateway Mode (Lowest Latency)

You make LLM calls directly; AxonFlow handles policy pre-check and audit.

```
Your App → AxonFlow Pre-check → Your LLM Call → AxonFlow Audit
```

| Language | Path |
|----------|------|
| Python | `integrations/gateway-mode/python/` |
| TypeScript | `integrations/gateway-mode/typescript/` |
| Go | `integrations/gateway-mode/go/` |
| Java | `integrations/gateway-mode/java/` |

#### Proxy Mode (Simplest)

AxonFlow handles everything - policy enforcement AND LLM routing.

```
Your App → AxonFlow (Policy + LLM) → Response
```

| Language | Path |
|----------|------|
| Python | `integrations/proxy-mode/python/` |
| TypeScript | `integrations/proxy-mode/typescript/` |
| Go | `integrations/proxy-mode/go/` |
| Java | `integrations/proxy-mode/java/` |

### Multi-Agent Planning (MAP)

Orchestrate multi-step AI workflows with governance.

| Language | Path | Description |
|----------|------|-------------|
| Python | `map/python/` | Generate and execute multi-agent plans |
| TypeScript | `map/typescript/` | Generate and execute multi-agent plans |
| Go | `map/go/` | Generate and execute multi-agent plans |
| Java | `map/java/` | Generate and execute multi-agent plans |

### LLM Interceptors

Wrap LLM provider clients with transparent governance - no code changes required.

```
Your App → Wrapped LLM Client → AxonFlow Pre-check → LLM API → AxonFlow Audit
```

| Language | Path | Description |
|----------|------|-------------|
| Python | `interceptors/python/` | OpenAI/Anthropic interceptors |
| Go | `interceptors/go/` | OpenAI-compatible interceptors |
| Java | `interceptors/java/` | OpenAI/Anthropic interceptors |

### MCP Connectors

Query external systems through MCP (Model Context Protocol) connectors with policy governance.

| Language | Path | Description |
|----------|------|-------------|
| TypeScript | `mcp-connectors/typescript/` | Query MCP connectors |
| Go | `mcp-connectors/go/` | Query MCP connectors |
| Java | `mcp-connectors/java/` | Query MCP connectors |

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
| Python | `axonflow` | ^0.3.1 |
| TypeScript | `@axonflow/sdk` | ^1.4.2 |
| Go | `github.com/getaxonflow/axonflow-sdk-go` | v1.5.1 |
| Java | `com.getaxonflow:axonflow-sdk` | 1.1.1 |

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
- [Gateway Mode Guide](https://docs.getaxonflow.com/docs/sdk/gateway-mode)
- [Proxy Mode Guide](https://docs.getaxonflow.com/docs/sdk/proxy-mode)
- [SDK Reference](https://docs.getaxonflow.com/docs/sdk/choosing-a-mode)
