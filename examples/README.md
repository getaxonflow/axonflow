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

### MCP Server Decision Mode (PEP / PDP pattern)

A runnable Python MCP server that uses AxonFlow Decision Mode as its Policy
Decision Point — the recognizable starting point for governing an MCP server.

| Example | Path | Description |
|---------|------|-------------|
| mcp-decision-mode | `mcp-decision-mode/` | Python MCP server with AxonFlow Decision Mode integration (PEP / PDP pattern; Indonesia PII handling) |

### v9 Identity Forwarding

Shows how `X-Org-ID`, `X-Client-ID`, and `X-Tenant-ID` flow agent → orchestrator
under the v9 identity model (ADR-052), including the anti-spoofing overwrite
rule applied at every auth boundary.

| Example | Path | Description |
|---------|------|-------------|
| Go | `v9_identity/go/` | Self-contained mock agent + orchestrator demo |

### Governance, Compliance & Security

| Example | Path | Description |
|---------|------|-------------|
| Audit Logging | `audit-logging/` | Audit logging for compliance and monitoring |
| Code Governance | `code-governance/` | Automatic detection and auditing of LLM-generated code |
| Governance Profiles | `governance-profiles/` | `AXONFLOW_PROFILE` environment profiles (v6.2.0) |
| Indonesia Compliance | `indonesia-compliance/` | Indonesia PII detection (OJK / UU PDP) compliance |
| Singapore PII | `singapore-pii/` | Singapore PII detection for MAS FEAT compliance |
| PII Detection | `pii-detection/` | Built-in PII detection capabilities |
| SQL Injection Detection | `sqli-detection/` | SQL injection detection for queries and responses |
| Media Governance | `media-governance/` | Multimodal media governance for images |
| Media Governance Policies | `media-governance-policies/` | Media governance policy management |

### Policy Configuration & Cost

| Example | Path | Description |
|---------|------|-------------|
| Dynamic Policies | `dynamic-policies/` | CRUD for LLM-powered dynamic policies |
| Static Policies | `static-policies/` | All static policy SDK methods |
| Policy Configuration | `policy-configuration/` | Per-mode MCP policy configuration |
| Gateway Policy Config | `gateway-policy-config/` | Gateway-mode policy configuration via environment variables |
| MCP Policies | `mcp-policies/` | MCP policy enforcement with phase-aware blocking and redaction |
| Feature Limits | `feature-limits/` | Tier-based feature limits |
| Cost Controls | `cost-controls/` | All Cost Controls SDK methods and HTTP endpoints |
| Cost Estimation | `cost-estimation/` | Cost estimation examples |
| Risk-Tiered Approvals | `risk-tiered-approvals/` | Risk-tiered approval workflows |

### Workflows & Execution

| Example | Path | Description |
|---------|------|-------------|
| Workflows | `workflows/` | Example workflows (sequential and parallel) |
| Workflow Control | `workflow-control/` | Workflow Control Plane examples |
| Workflow Policy | `workflow-policy/` | Workflow policy enforcement |
| Workflow Fail | `workflow-fail/` | Workflow failure handling |
| MAP Confirm Mode | `map-confirm-mode/` | Multi-agent planning with confirm-mode governance |
| MAP Lifecycle | `map-lifecycle/` | Multi-agent planning lifecycle management |
| Checkpoint Resume | `checkpoint-resume/` | Checkpoint and resume of workflow execution |
| WCP Retry + Idempotency | `wcp-retry-idempotency/` | Workflow Control Plane retry and idempotency validators |
| Retry Semantics | `retry-semantics/` | Execution boundary retry semantics |
| Execution Replay | `execution-replay/` | Decision & execution replay API |
| Execution Tracking | `execution-tracking/` | Unified execution tracking for MAP and WCP |

### Human-in-the-Loop

| Example | Path | Description |
|---------|------|-------------|
| HITL | `hitl/` | `require_approval` policy action and HITL workflows |
| HITL Queue | `hitl-queue/` | HITL approval queue handling |
| HITL Response Parity | `hitl-response-parity/` | Unified approve/reject response shape (v7.4.0) |

### LLM Providers & Routing

| Example | Path | Description |
|---------|------|-------------|
| LLM Providers | `llm-providers/` | Alternate LLM providers (Azure OpenAI, Mistral) |
| LLM Routing | `llm-routing/` | LLM provider routing capabilities |
| Evaluation Tier | `evaluation-tier/` | Three-tier licensing model tests |
| Version Check | `version-check/` | SDK-platform version compatibility and capability discovery |

### Operations

| Example | Path | Description |
|---------|------|-------------|
| Health Check | `health-check/` | Health check examples |
| Config | `config/` | Example configuration files |
| SDK Audit | `sdk-audit/` | Validates all SDK methods against live services |
| MCP Audit | `mcp-audit/` | MCP audit logging examples |
| Webhooks | `webhooks/` | Webhook subscription CRUD operations |
| Demo | `demo/` | Community demo snippets |
| Support Demo | `support-demo/` | Customer support AI governance demo application |

### Additional Integration Modes

| Example | Path | Description |
|---------|------|-------------|
| AutoGen | `integrations/autogen/` | AutoGen + AxonFlow integration |
| Claude Agent SDK | `integrations/claude-agent-sdk/` | Claude Agent SDK integration |
| Claude Code | `integrations/claude-code/` | Claude Code integration |

## SDK Versions

All examples use the latest SDK versions:

| SDK | Package | Version |
|-----|---------|---------|
| Python | `axonflow` | >=9.0.0 |
| TypeScript | `@axonflow/sdk` | >=9.0.0 |
| Go | `github.com/getaxonflow/axonflow-sdk-go/v9` | v9.0.0 |
| Java | `com.getaxonflow:axonflow-sdk` | 9.0.0 |
| Rust _(preview)_ | `axonflow-sdk-rust` | 0.8.1 |

## Environment Configuration

Each example includes a `.env.example` file. Copy and configure:

```bash
cp .env.example .env
# Edit .env with your configuration
```

Common environment variables:

```bash
AXONFLOW_AGENT_URL=http://localhost:8080
AXONFLOW_CLIENT_ID=your-client-id
AXONFLOW_CLIENT_SECRET=your-client-secret
```

## Python prerequisites

The Python examples target the **current** `axonflow` PyPI release, which requires
**Python 3.10 or newer**. A few examples (notably `retry-semantics/python` and
`map-lifecycle/python`) use SDK methods, types, or async patterns that were added
after `axonflow==4.1.0` and won't import on Python 3.9 with that version pinned.

If you see a `Traceback` immediately on import or a missing-attribute error like
`AttributeError: 'AxonFlow' object has no attribute '...'` when running an example,
you are likely on Python 3.9 with an old SDK. Either:

- **Recommended:** Use Python 3.11+ and `pip install -U axonflow` to pull the latest
  SDK release, or
- Build the SDK from source against your local checkout:
  `pip install -e /path/to/axonflow-sdk-python`

The system `python3` on macOS Big Sur / Monterey defaults to 3.9 — create a venv on
a newer interpreter (`python3.11 -m venv .venv && source .venv/bin/activate`) before
running these examples.

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

See the hosted documentation at https://docs.getaxonflow.com for details.

## Documentation

- [AxonFlow Docs](https://docs.getaxonflow.com)
- [Gateway Mode Guide](https://docs.getaxonflow.com/docs/sdk/gateway-mode)
- [Proxy Mode Guide](https://docs.getaxonflow.com/docs/sdk/proxy-mode)
- [SDK Reference](https://docs.getaxonflow.com/docs/sdk/choosing-a-mode)
