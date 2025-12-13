# AxonFlow Documentation

Public documentation for AxonFlow - synced to the open source repository.

## Quick Start

- [Getting Started](./getting-started.md) - First steps with AxonFlow
- [Local Development](./guides/local-development.md) - Run AxonFlow locally
- [Tutorials](./tutorials/) - Step-by-step tutorials

## Guides

Configuration and how-to guides for common tasks.

| Guide | Description |
|-------|-------------|
| [Community Configuration](./guides/community-configuration.md) | Configure AxonFlow Community edition |
| [LLM Providers](./guides/llm-providers.md) | Configure LLM providers (OpenAI, Anthropic) |
| [Choosing a Mode](./guides/choosing-a-mode.md) | Gateway vs Proxy mode comparison |
| [Gateway Mode](./guides/gateway-mode.md) | Migrate to Gateway Mode SDK |
| [Proxy Mode](./guides/proxy-mode.md) | Configure Proxy Mode deployment |
| [PII Detection](./guides/pii-detection.md) | Configure PII detection and redaction |
| [Connector Development](./guides/connector-development.md) | Build custom MCP connectors |

## SDK Documentation

| Document | Description |
|----------|-------------|
| [SDK Comparison](./reference/sdk-comparison.md) | Compare Go vs TypeScript SDKs |
| [TypeScript Quickstart](./sdk/typescript-quickstart.md) | Get started with TypeScript SDK |
| [TypeScript Architecture](./sdk/typescript-architecture.md) | SDK architecture and design |
| [TypeScript Specification](./sdk/typescript-specification.md) | Full API specification |
| [LLM SDK Guide](./sdk/llm-sdk-guide.md) | Using LLM providers with SDK |

## Reference

Technical specifications and architecture documentation.

| Document | Description |
|----------|-------------|
| [Agent Definition](./reference/agent-definition.md) | Agent architecture and configuration |
| [Configurable Agents](./reference/configurable-agents.md) | Configure agents via YAML (MAP 0.5) |
| [LLM Architecture](./reference/llm-architecture.md) | LLM provider system architecture |
| [Policy Templates](./reference/policy-templates.md) | Policy templates API |
| [MCP v0.2 Release](./reference/mcp-v02-release.md) | MCP protocol v0.2 changes |
| [Secrets & Logging](./reference/secrets-logging-checklist.md) | Security checklist |
| [License Migration](./reference/license-migration.md) | License key migration guide |

## Compliance

Regulatory compliance documentation.

| Document | Description |
|----------|-------------|
| [EU AI Act](./compliance/eu-ai-act.md) | EU AI Act compliance features |
| [SEBI Compliance](./compliance/sebi-compliance.md) | SEBI regulatory compliance (India) |

## API Documentation

| Document | Description |
|----------|-------------|
| [api/](./api/) | OpenAPI specifications |
| [api/error-codes.md](./api/error-codes.md) | API error codes reference |

## Security

| Document | Description |
|----------|-------------|
| [Row-Level Security](./security/row-level-security.md) | Database-level tenant isolation |

## Directory Structure

```
docs/
├── guides/          # How-to guides and configuration
├── reference/       # Technical specifications
├── compliance/      # Regulatory compliance docs
├── sdk/             # SDK documentation
├── api/             # API specifications
├── security/        # Security documentation
└── tutorials/       # Step-by-step tutorials
```

## Enterprise Documentation

Enterprise-only features are documented in `/ee/docs/`:
- AWS Bedrock and Ollama LLM providers
- AWS Marketplace metering
- Internal deployment guides
- Dashboard configuration

## Internal Documentation

For internal architecture and technical decisions, see `/technical-docs/` (not synced to Community edition).
