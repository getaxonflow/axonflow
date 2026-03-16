# AxonFlow Documentation

**Last Updated: March 2026** | **Platform: v5.3.0** | **SDKs: v4.2.0**

Public documentation for AxonFlow - synced to the Community Edition repository.

## Quick Start

- [Getting Started](./getting-started.md) - First steps with AxonFlow
- [Local Development](./guides/local-development.md) - Run AxonFlow locally
- [Tutorials](./tutorials/) - Step-by-step tutorials

## Guides

Configuration and how-to guides for common tasks.

| Guide | Description |
|-------|-------------|
| [Community Configuration](./guides/community-configuration.md) | Configure AxonFlow Community Edition |
| [LLM Providers](./guides/llm-providers.md) | Configure LLM providers (OpenAI, Anthropic) |
| [Choosing a Mode](./guides/choosing-a-mode.md) | Gateway vs Proxy mode comparison |
| [Gateway Mode](./guides/gateway-mode.md) | Migrate to Gateway Mode SDK |
| [Proxy Mode](./guides/proxy-mode.md) | Configure Proxy Mode deployment |
| [PII Detection](./guides/pii-detection.md) | Configure PII detection and redaction |
| [Connector Development](./guides/connector-development.md) | Build custom MCP connectors |
| [Workflow Control Plane](./guides/workflow-control-plane.md) | WCP step gates, policy enforcement, SDK integration |
| [Audit Logging](./guides/audit-logging.md) | Audit logging configuration and compliance |
| [MCP Audit Logging](./guides/mcp-audit-logging.md) | Three-phase MCP policy enforcement and audit |
| [Execution Tracking](./guides/execution-tracking.md) | Unified execution history for MAP and WCP |
| [Grafana Dashboard](./guides/grafana-dashboard.md) | Monitoring with Grafana dashboards |

## SDK Documentation

AxonFlow provides official SDKs for Go, Python, Java, and TypeScript. All SDKs are at v4.2.0.

| Document | Description |
|----------|-------------|
| [SDK Feature Coverage](./SDK_FEATURE_COVERAGE.md) | Method coverage matrix across all SDKs |
| [LLM SDK Guide](./sdk/llm-sdk-guide.md) | Using LLM providers with SDK |

### Go SDK

- **Repository:** [github.com/getaxonflow/axonflow-sdk-go](https://github.com/getaxonflow/axonflow-sdk-go)
- **Install:** `go get github.com/getaxonflow/axonflow-sdk-go/v4`

### Python SDK

- **Repository:** [github.com/getaxonflow/axonflow-sdk-python](https://github.com/getaxonflow/axonflow-sdk-python)
- **Install:** `pip install axonflow-sdk`

### Java SDK

- **Repository:** [github.com/getaxonflow/axonflow-sdk-java](https://github.com/getaxonflow/axonflow-sdk-java)
- **Install:** Maven `com.getaxonflow:axonflow-sdk:3.5.0`

### TypeScript SDK

- **Repository:** [github.com/getaxonflow/axonflow-sdk-typescript](https://github.com/getaxonflow/axonflow-sdk-typescript)
- **Install:** `npm install @axonflow/sdk`
- [TypeScript Quickstart](./sdk/typescript-quickstart.md) - Get started with TypeScript SDK
- [TypeScript Architecture](./sdk/typescript-architecture.md) - SDK architecture and design
- [TypeScript Specification](./sdk/typescript-specification.md) - Full API specification

## Reference

Technical specifications and architecture documentation.

| Document | Description |
|----------|-------------|
| [Configurable Agents](./reference/configurable-agents.md) | Configure agents via YAML (MAP 0.5) |
| [LLM Architecture](./reference/llm-architecture.md) | LLM provider system architecture |
| [Policy Templates](./reference/policy-templates.md) | Policy templates API |
| [Secrets & Logging](./reference/secrets-logging-checklist.md) | Security checklist |
| [License Migration](./reference/license-migration.md) | License key migration guide |

## Compliance

Regulatory compliance documentation.

| Document | Description |
|----------|-------------|
| [EU AI Act](./compliance/eu-ai-act.md) | EU AI Act compliance features |
| [SEBI Compliance](./compliance/sebi-compliance.md) | SEBI regulatory compliance (India) |
| [SEBI AI/ML Framework](./compliance/sebi-ai-ml.md) | SEBI AI/ML circular compliance |
| [RBI Free AI](./compliance/rbi-free-ai.md) | RBI guidelines for AI in banking (India) |

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

For internal architecture and technical decisions, see `/technical-docs/` (not synced to Community Edition).
