# AxonFlow

**AxonFlow is the execution authority and system of record for AI decisions in production workflows.**

It operates inside the execution path between your workflow logic and model or tool calls. Gateways can help at the request boundary and observability tools can tell you what happened later. AxonFlow records why an action was allowed, blocked, paused, or resumed while the workflow is running.

It runs self-hosted (Docker or Kubernetes), with SDKs for **Python**, **TypeScript**, **Go**, **Java**, and **Rust** (preview), plus governance plugins for **OpenClaw**, **Claude Code**, **Claude Desktop**, **Cursor**, **Codex**, **Google ADK**, **n8n**, and **LiteLLM**.

> **Upgrade strongly recommended.** AxonFlow ships substantial monthly security and quality hardening; staying on the latest major is the security-supported release line. [Latest release](https://github.com/getaxonflow/axonflow/releases/latest) · [Security advisories](https://github.com/getaxonflow/axonflow/security/advisories)

## Why AxonFlow Exists

Production AI systems are multi-step, non-deterministic, and increasingly regulated. In practice:

- Prompt filters alone do not control downstream tool execution.
- Orchestration frameworks coordinate steps, but do not decide whether a risky step should execute.
- Routing gateways improve connectivity, but do not give you workflow-level approvals or safe resume semantics.
- Logs show that something happened, but not always why it was allowed or who owned the decision path.

AxonFlow addresses this with a runtime execution layer that enforces policy at the step boundary and records decision context at execution time.

## What AxonFlow Is

AxonFlow is composed of:

- **Agent runtime** for inline policy evaluation and execution checks (`:8080`)
- **Orchestrator runtime** for workflow execution state and routing (`:8081`)
- **Policy engine** for tenant and org governance policies
- **Workflow Control Plane (WCP)** for gated, step-level workflow execution
- **Decision record and evidence layer** for replay, export, and compliance workflows

Execution modes:

- **Gateway Mode**: Pre-check + your own LLM call + audit
- **Proxy Mode**: AxonFlow enforces and proxies model/tool execution
- **WCP Mode**: Governed multi-step workflow execution with step gates

AxonFlow is not a workflow engine, observability dashboard, or prompt gateway. Your application or orchestrator still decides what to do next. AxonFlow decides whether the next model or tool action can run and records that decision.

## What AxonFlow Does

**Policy Enforcement** — 100+ pre-populated policies across multiple categories:
- **Security**: SQL injection detection (37 patterns), unsafe admin access, schema exposure
- **Sensitive Data**: PII detection (SSN, credit cards, PAN, Aadhaar, email, phone), salary, medical records
- **Compliance**: GDPR, PCI-DSS, HIPAA basic constraints (Community); EU AI Act, SEBI/RBI, MAS FEAT, DORA frameworks with retention and exports (Enterprise)
- **Runtime Controls**: Tenant isolation, environment restrictions, approval gates
- **Cost & Abuse**: Per-user/team limits, anomalous usage detection, token budgets

All policies are configurable. Teams typically start in observe-only mode and enable blocking once they trust the signal.

> **[Full policy documentation](https://docs.getaxonflow.com/docs/policies/overview/)** · **[Community vs Enterprise](https://docs.getaxonflow.com/docs/features/community-vs-enterprise/?utm_source=readme_eval)**

**Human-in-the-Loop Approval Gates** — Require explicit approvals for high-risk workflow steps. Configurable expiry, pending limits by tier, and automatic workflow abort on expiration.

**Policy Simulation & Impact Reporting** — Dry-run policy changes against historical traffic before deploying. See which requests would be blocked, allowed, or changed.

**Evidence Export** — Generate compliance-ready audit evidence packs with configurable retention windows. Designed for internal governance reviews and regulatory audits.

**Workflow Control Plane (WCP)** — Govern long-running, multi-step AI workflows with step-level gate checks, a durable step ledger, cancellation, and SSE streaming. WCP works with any orchestration framework — your code controls execution, AxonFlow controls governance and visibility.

**Multi-Agent Planning (MAP)** — Define agents in YAML, let AxonFlow turn natural language requests into executable workflows with automatic plan generation and execution tracking.

**SQL Injection Response Scanning** — Detect SQLi payloads in MCP connector responses. Protects against data exfiltration when compromised data is returned from databases.

**Media Governance** — Governance pipeline for image inputs, including content classification and policy enforcement on multimodal requests.

**Code Governance** — Detect LLM-generated code, identify language and security issues (secrets, eval, shell injection). Logged for compliance.

**Decision Records & Audit Trails** — Every request and governed step is recorded with decision context. Know what was blocked, why it was blocked, and which policy or approval path applied. Token usage tracked for cost analysis.

**Decision & Execution Replay** — Debug governed workflows with step-by-step state and policy decisions. Timeline view and compliance exports included.

**Cost Controls** — Set budgets at org, team, agent, or user level. Track LLM spend across providers with configurable alerts and enforcement actions.

**Multi-Model Routing** — Route requests across OpenAI, Anthropic, Bedrock, Ollama based on cost, capability, or compliance requirements. Failover included.

**Circuit Breaker** — Emergency kill switch wired into the request pipeline. Instantly halt all LLM traffic when something goes wrong in production.

**Proxy Mode** — Full request lifecycle: policy, planning, routing, audit. Recommended for new projects.

**Gateway Mode** — Request-boundary governance for existing stacks. Pre-check → your call → audit.

> **[Choosing a mode](https://docs.getaxonflow.com/docs/sdk/choosing-a-mode/)** · **[Architecture deep-dive](https://docs.getaxonflow.com/docs/architecture/overview/)**

## Who This Is For

**Good fit:**
- Production AI teams needing governance before shipping
- Platform teams building internal AI infrastructure
- Regulated industries (healthcare, finance, legal) with compliance requirements
- Teams wanting audit trails and policy enforcement without building it themselves
- Teams running multi-step agent workflows that need execution control, retries, and step-level visibility

**Not a good fit:**
- Single-prompt experiments or notebooks
- Prototypes where governance isn't a concern yet
- Projects where adding a service layer is overkill

**[Full Documentation](https://docs.getaxonflow.com)** · **[Getting Started Guide](https://docs.getaxonflow.com/docs/getting-started/)** · **[API Reference](./docs/api/)**

**Product demos (Platform + Fraud & Risk):** See runtime enforcement, HITL approvals, audit evidence, cost visibility, and agentic payment controls: [Watch the demos](https://getaxonflow.com/demo/?utm_source=github&utm_medium=readme&utm_campaign=product_demo&utm_content=axonflow)

**Community Quickstart walkthrough (2 min):** See governed calls, PII blocking, Gateway Mode with LangChain/CrewAI, and MAP from YAML: [Watch on YouTube](https://youtu.be/BSqU1z0xxCo)

**Architecture deep dive (12 min):** How the control plane works, policy enforcement flow, and multi-agent planning: [Watch on YouTube](https://youtu.be/Q2CZ1qnquhg)

---

## Pick Your First 10-Minute Path

If you're adding governance to an existing AI stack (LangChain, CrewAI, direct API calls), start with Path A. If you're building new multi-step agent workflows that need execution control, start with Path B.

### Path A: Govern Existing LLM Calls

Add policy enforcement, PII detection, and audit trails to your current AI stack — without changing your orchestration logic.

```bash
# Gateway Mode: Pre-check → Your LLM call → Audit
curl -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -d '{"user_token": "demo-user", "client_id": "demo-client", "query": "Look up customer with SSN 123-45-6789"}'
# Returns: {"approved": true, "requires_redaction": true, "pii_detected": ["ssn"]}
```

Works with LangChain, CrewAI, or any framework — AxonFlow acts as a governance sidecar.

> **[Choosing a mode guide](https://docs.getaxonflow.com/docs/sdk/choosing-a-mode/)** — covers Gateway Mode, Proxy Mode, and when to use each.

### Path B: Execution Control for Long-Running Workflows

Use the Workflow Control Plane (WCP) to manage multi-step AI workflows with step-level gates, a durable ledger, cancellation, and SSE streaming.

```bash
# Run the execution tracking demo (requires Docker services running)
./examples/execution-tracking/http/example.sh
```

This creates a WCP workflow, runs step-level gate checks, records a step ledger, demonstrates cancellation, and shows unified execution status.

> **[Execution tracking guide](https://docs.getaxonflow.com/docs/orchestration/wcp/overview/)** — WCP workflow creation, step gates, SSE streaming, and unified execution status.

---

## Quick Start

If you want to see how this looks before setting it up, watch the [Community Quickstart walkthrough (2 min)](https://youtu.be/BSqU1z0xxCo).

**Prerequisites:** [Docker Desktop](https://docs.docker.com/get-docker/) installed and running.

```bash
# Clone and start
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow

# Set your API key (at least one LLM provider required for AI features)
echo "OPENAI_API_KEY=sk-your-key-here" > .env   # or ANTHROPIC_API_KEY

# Start services
docker compose up -d

# Wait for services to be healthy (~30 seconds)
docker compose ps   # All services should show "healthy"

# Verify it's running
curl http://localhost:8080/health
curl http://localhost:8081/health
```

**That's it.** Services are now running:

| Service | URL | Purpose |
|---------|-----|---------|
| Agent | http://localhost:8080 | Policy enforcement, PII detection |
| Orchestrator | http://localhost:8081 | LLM routing, WCP, tenant policies |
| Grafana | http://localhost:3000 | Dashboards (admin / grafana_localdev456) |
| Prometheus | http://localhost:9090 | Metrics |

> **Note:** All commands in this README assume you're in the repository root directory (`cd axonflow`).

### Execution Control Demo (60 seconds)

With services running, try the execution control workflow:

```bash
./examples/execution-tracking/http/example.sh
```

This demonstrates:
1. **MAP plan creation** via `/api/request`
2. **WCP workflow** with step-level gate checks and completion
3. **Cancellation** via the unified execution API
4. **SSE streaming** for real-time execution events
5. **Workflow listing** and status queries

### Supported LLM Providers

| Provider | Community | Enterprise | Notes |
|----------|:---------:|:----------:|-------|
| **OpenAI** | ✅ | ✅ | GPT-5.x, GPT-4o, GPT-4 |
| **Anthropic** | ✅ | ✅ | Claude Opus 4.6, Claude Sonnet 4.6 |
| **Azure OpenAI** | ✅ | ✅ | Azure AI Foundry & Classic endpoints |
| **Google Gemini** | ✅ | ✅ | Gemini 3.x (Pro, Flash, Flash-Lite) |
| **Ollama** | ✅ | ✅ | Local/air-gapped deployments |
| **AWS Bedrock** | ❌ | ✅ | HIPAA-compliant, data residency |

> LLM provider configuration applies to Proxy Mode and MAP, where AxonFlow routes requests to the provider.
> In Gateway Mode and WCP, your application calls the LLM directly, including via frameworks like LangChain or CrewAI, so any provider works.

> **[Provider configuration guide](https://docs.getaxonflow.com/docs/llm/overview/)**

### See Governance in Action (30 seconds)

```bash
# Example: Send a request containing an SSN — AxonFlow detects and flags it for redaction
curl -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -d '{"user_token": "demo-user", "client_id": "demo-client", "query": "Look up customer with SSN 123-45-6789"}'
```

```json
{"approved": true, "requires_redaction": true, "pii_detected": ["ssn"], "policies": ["pii_ssn_detection"]}
```

### Full Interactive Demo (10 min)

Experience the complete governance suite: PII detection, SQL injection blocking,
proxy and gateway modes, MCP connectors, multi-agent planning, and observability.

**Requires:** Python 3.10+ (for demo scripts)

```bash
# Ensure your .env has a valid API key
cat .env   # Should show OPENAI_API_KEY=sk-... or ANTHROPIC_API_KEY=sk-ant-...

# Restart services if you just added the key
docker compose up -d --force-recreate

# Run the interactive demo
./examples/demo/demo.sh
```

The demo walks through a realistic customer support scenario with live LLM calls.
See [`examples/demo/README.md`](examples/demo/README.md) for options (`--quick`, `--part N`).

---

AxonFlow runs inline with LLM traffic, enforcing policies and routing decisions in single-digit milliseconds — fast enough to prevent failures rather than observe them after the fact.

---

### Integration Options

For Go, Java, Python, TypeScript, and Rust (preview) applications, we recommend using the **[AxonFlow SDKs](https://docs.getaxonflow.com/docs/sdk/overview/)**. All SDKs are thin wrappers over the same REST APIs, which remain fully supported for custom integrations.

| Integration | Recommended For |
|-------------|-----------------|
| **SDKs** | Application code, services, strongly typed environments |
| **HTTP APIs** | Agents, automation, CLI tools, CI pipelines, languages without SDKs |

All features—policy enforcement, audit logging, MCP connectors, WCP workflows—are available via both SDKs and HTTP.

AxonFlow ships official plugins for AI agent runtimes, coding assistants, and developer tools. All plugins enforce the same policy surface and share a single audit trail via your self-hosted AxonFlow stack.

**OpenClaw** ships a source-available governance policy bundle covering shell injection, secret exfiltration, PII redaction, and tool-result risk classification. The same policy set ports across all four hook plugins below (OpenClaw, Claude Code, Cursor, Codex); the install path is the only thing that changes. Claude Desktop has no hooks, so it applies the same policies at the MCP-proxy layer (a different interception point — see its row below).

| Plugin | Platform | Install | Docs | Repo |
|--------|----------|---------|------|------|
| **OpenClaw** | OpenClaw | `openclaw plugins install @axonflow/openclaw` | [Docs](https://docs.getaxonflow.com/docs/integration/openclaw/) | [GitHub](https://github.com/getaxonflow/axonflow-openclaw-plugin) |
| **Claude Code** | Claude Code CLI | Marketplace or manual hooks | [Docs](https://docs.getaxonflow.com/docs/integration/claude-code/) | [GitHub](https://github.com/getaxonflow/axonflow-claude-plugin) |
| **Cursor** | Cursor IDE | Pre-/post-tool hooks | [Docs](https://docs.getaxonflow.com/docs/integration/cursor/) | [GitHub](https://github.com/getaxonflow/axonflow-cursor-plugin) |
| **Codex** | OpenAI Codex CLI | Bash hooks and advisory skills | [Docs](https://docs.getaxonflow.com/docs/integration/codex/) | [GitHub](https://github.com/getaxonflow/axonflow-codex-plugin) |
| **Claude Desktop** | Claude Desktop app (Chat/Cowork/Code) | One-click `.mcpb` Desktop Extension (MCP governance proxy — no hooks) | [Docs](https://docs.getaxonflow.com/docs/integration/claude-desktop/) | [GitHub](https://github.com/getaxonflow/axonflow-claude-desktop-plugin) |
| **Google ADK** | Google Agent Development Kit | `pip install axonflow-google-adk-plugin` | [Docs](https://docs.getaxonflow.com/docs/integration/google-adk/) | [GitHub](https://github.com/getaxonflow/axonflow-google-adk-plugin) |
| **n8n** | n8n workflow automation | `npm install @axonflow/n8n-nodes-axonflow` | [Docs](https://docs.getaxonflow.com/docs/integration/n8n/) | [GitHub](https://github.com/getaxonflow/axonflow-n8n-node) |
| **LiteLLM** | LiteLLM Python SDK | `pip install axonflow-litellm` | [Docs](https://docs.getaxonflow.com/docs/integration/litellm/) | [GitHub](https://github.com/getaxonflow/axonflow-litellm) |

For AI agent framework integration patterns, see:
- [**Anthropic Computer Use**](https://docs.getaxonflow.com/docs/integration/computer-use/) — governed desktop and tool actions
- [**Claude Agent SDK**](https://docs.getaxonflow.com/docs/integration/claude-agent-sdk/) — MCP tool governance patterns

> **[SDK Documentation](https://docs.getaxonflow.com/docs/sdk/overview/)** · **[API Reference](./docs/api/)**

### vs LangChain / LangSmith

| Feature | AxonFlow | LangChain/LangSmith |
|---------|----------|---------------------|
| **Governance** | Inline policy enforcement | Post-hoc monitoring |
| **Architecture** | Active prevention | Passive detection (observability) |
| **Workflow Execution Control** | Step-level gates, durable ledger, cancellation | Chain sequencing only |
| **Evidence & Replay** | Compliance exports, decision replay, audit retention | Trace logging |
| **Enterprise Focus** | Built for compliance & security first | Developer-first framework |
| **Multi-Tenant** | Production-ready isolation | DIY multi-tenancy |
| **Self-Hosted** | Full core available | Partial (monitoring requires cloud) |

**The Key Difference:** LangChain/LangSmith focus on observability and post-hoc analysis, while AxonFlow enforces policies inline during request execution.

**Best of Both Worlds:** Many teams use LangChain for orchestration logic with AxonFlow as the governance layer on top.

---

## Architecture

```
┌─────────────┐    ┌──────────────────────────────────────────────────┐
│  Your App   │───▶│                Agent (:8080)                     │
│   (SDK)     │    │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
└─────────────┘    │  │  Policy  │ │   MCP    │ │  Media / Code    │ │
                   │  │  Engine  │ │Connectors│ │  Governance      │ │
                   │  │  (60+)   │ │          │ │                  │ │
                   │  └──────────┘ └──────────┘ └──────────────────┘ │
                   │  ┌──────────────────┐ ┌─────────────────────┐   │
                   │  │ PII / SQLi       │ │ Circuit Breaker     │   │
                   │  │ Detection        │ │ (Kill Switch)       │   │
                   │  └──────────────────┘ └─────────────────────┘   │
                   └────────────────────┬─────────────────────────────┘
                                        │
                                        ▼
                   ┌──────────────────────────────────────────────────┐
                   │             Orchestrator (:8081)                 │
                   │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
                   │  │   WCP    │ │  MAP     │ │  Cost Controls   │ │
                   │  │  Step    │ │  Plan +  │ │  & Multi-Model   │ │
                   │  │  Gates   │ │  Execute │ │  Routing         │ │
                   │  └──────────┘ └──────────┘ └──────────────────┘ │
                   │  ┌──────────────────┐ ┌─────────────────────┐   │
                   │  │ HITL Approval    │ │ Evidence Export      │   │
                   │  │ Gates            │ │ & Decision Replay    │   │
                   │  └──────────────────┘ └─────────────────────┘   │
                   └────────────────────┬─────────────────────────────┘
                                        │
                                        ▼
                   ┌──────────────────────────────────────────────────┐
                   │                 LLM Providers                    │
                   │   (OpenAI, Anthropic, Gemini, Bedrock, Ollama)   │
                   └──────────────────────────────────────────────────┘

           PostgreSQL (policies, audit, evidence) • Redis (cache)
```

- **Agent** (:8080): Policy enforcement, PII detection, SQLi response scanning, media/code governance, MCP connectors, circuit breaker
- **Orchestrator** (:8081): WCP step gates, multi-agent planning, LLM routing, cost controls, HITL approval gates, evidence export, decision replay

### Why AxonFlow often becomes the default control plane

Teams typically start by placing AxonFlow in front of a single workflow or agent to evaluate policy enforcement, auditability, and execution control. As usage grows, running some AI workflows through AxonFlow and others outside it tends to create fragmented audit logs, inconsistent policies, and duplicated observability. For this reason, teams that continue using AxonFlow often standardize on it as a single control plane for AI workflows, while retaining their existing orchestration frameworks and execution logic.

### What evaluators are saying

> *"So many teams are just making the first steps, which work quite easily in a localhost environment, but then when they try to move this to production they find that they have to build so much core infrastructure. I am happy to see this solution looking so much more mature and feature rich."*
> — Principal Technical Product Manager · Global travel marketplace

> *"Most failures aren't model quality issues. The idea of a lightweight, inline control plane that doesn't replace the orchestrator but governs execution step-by-step feels like a pragmatic way to tackle that."*
> — Staff Software Engineer · Global travel marketplace

> *"This is massively needed. Large corporations are building their own frameworks but a new business looking to go agentic can't do it without this."*
> — Principal Product Manager, AI/ML · Global payments platform

> *"Your product gives a no-fluff approach to bolt the security early on and not as an afterthought."*
> — Principal Engineer · Global travel marketplace

*Quotes are anonymized and lightly edited for clarity.*

---

## Three-Tier Licensing

AxonFlow offers three tiers. Community is free with no license key. Evaluation is free with a license key and unlocks governance features designed for teams taking AI to production:

| Feature | Community | Evaluation (Free) | Enterprise |
|---------|-----------|-------------------|------------|
| Tenant policies | 20 | 50 | Unlimited |
| Org-wide policies | 0 | 5 | Unlimited |
| Audit retention | 3 days | 14 days | 3650 days |
| Concurrent executions | 5 | 25 | Unlimited |
| HITL Approval Gates | — | 100 pending, 24h expiry | Unlimited, configurable expiry |
| Policy Simulation | — | 300/day | Unlimited |
| Evidence Export | — | 14-day window, 3/day | Unlimited |

[Get a free Evaluation license](https://getaxonflow.com/evaluation-license?utm_source=readme_eval) · [Run a paid production program](https://getaxonflow.com/design-partner?utm_source=readme_eval) · [Full feature matrix](https://docs.getaxonflow.com/docs/features/community-vs-enterprise/?utm_source=readme_eval)

### Stay on Community if:
- Single team prototyping AI features
- Development and local evaluation
- Your limits fit in Community capacity (20 tenant policies, 5 concurrent executions)

### Upgrade to Evaluation (Free) when:
- Taking AI to production with a small team
- Need Human-in-the-Loop approval gates for governed workflows
- Want to simulate policy changes before deploying them (dry-run)
- Need evidence exports for compliance proof or audit prep
- Need organization-wide policies (up to 5) and 14-day audit retention

**Get your free Evaluation license:** https://getaxonflow.com/evaluation-license

### Need a sponsored production decision?

If you have one real workflow, a dated security or business requirement, written controls, and an executive sponsor, use the paid [Design Partner Program](https://getaxonflow.com/design-partner?utm_source=readme_eval). It is a bounded production path rather than another open-ended evaluation:

- **Core:** 60 days, $2,000 public track or $4,000 confidential track
- **Core + Fraud & Risk:** 75 days, $3,000 public track or $6,000 confidential track
- Enterprise access for the single workflow and footprint agreed in the signed program plan
- Weekly founder session, next-business-day acknowledgment and triage for production-impacting issues, and a fixed evidence readout
- Expected production footprint, indicative conversion price, and procurement path established before the program begins
- 100% of the fee credited against the first quarterly invoice when a commercial licence is signed within 30 days of program end

The public track includes deployment-story collaboration subject to mutual written approval. The confidential paid pilot has no marketing obligations. All prices are subject to eligibility and a signed agreement.

### You need Enterprise when:

**Identity & Organization Controls**
- SSO + SAML authentication
- SCIM user lifecycle management
- Multi-tenant isolation

**Compliance & Risk**
- EU AI Act conformity workflows + 10-year retention
- SEBI/RBI compliance exports + 5-year retention
- Unlimited HITL approval queues with configurable expiry
- Emergency circuit breaker (kill switch)

**Platform & Operations**
- One-click AWS CloudFormation deployment
- Usage analytics and cost attribution
- Priority support with SLA
- Customer Portal UI for runtime management

See the full **[Community vs Evaluation vs Enterprise feature matrix](https://docs.getaxonflow.com/docs/features/community-vs-enterprise/?utm_source=readme_eval)**
*(designed for security reviews, procurement, and platform evaluations)*

**Enterprise:** [AWS Marketplace](https://aws.amazon.com/marketplace) or [sales@getaxonflow.com](mailto:sales@getaxonflow.com)

---

## Try AxonFlow Online

Skip local setup — try AxonFlow instantly at [**try.getaxonflow.com**](https://docs.getaxonflow.com/docs/deployment/community-saas/). No Docker, no installation required.

```bash
# Register a free trial tenant (30 seconds)
curl -X POST https://try.getaxonflow.com/api/v1/register \
  -H "Content-Type: application/json" -d '{"label":"my-trial"}'
```

Set `AXONFLOW_TRY=1` in your environment and any SDK will auto-connect. Rate-limited (20 req/min, 500 req/day). No SLA — for production, deploy self-hosted with `docker compose up -d` or [reach out](mailto:hello@getaxonflow.com) for enterprise SaaS and in-VPC options with enterprise grade SLOs, production guarantees and many additional capabilities.

## SDKs

```bash
pip install axonflow              # Python
npm install @axonflow/sdk         # TypeScript
go get github.com/getaxonflow/axonflow-sdk-go/v9  # Go
cargo add axonflow-sdk-rust       # Rust (preview, v0.8.1)
```

```xml
<!-- Java (Maven) -->
<dependency>
    <groupId>com.getaxonflow</groupId>
    <artifactId>axonflow-sdk</artifactId>
    <version>9.0.0</version>
</dependency>
```

### Python

```python
from axonflow import AxonFlow

async with AxonFlow(endpoint="http://localhost:8080") as ax:
    response = await ax.proxy_llm_call(
        user_token="user-123",
        query="Analyze customer sentiment",
        request_type="chat"
    )
```

### TypeScript

```typescript
import { AxonFlow } from '@axonflow/sdk';

const axonflow = new AxonFlow({
  endpoint: 'http://localhost:8080',
  clientId: 'my-app',
  clientSecret: 'my-secret'
});

const response = await axonflow.proxyLLMCall({
  userToken: 'user-123',
  query: 'Analyze customer sentiment',
  requestType: 'chat'
});
```

### Go

```go
import axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"

client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint:     "http://localhost:8080",
    ClientID:     "my-app",
    ClientSecret: "my-secret",
})

response, err := client.ProxyLLMCall(
    "user-123",                          // userToken
    "Analyze customer sentiment",        // query
    "chat",                              // requestType
    map[string]interface{}{},            // context
)
```

### Java

```java
import com.getaxonflow.sdk.AxonFlowClient;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.*;

AxonFlowClient client = AxonFlowClient.builder()
    .endpoint("http://localhost:8080")
    .clientId("my-app")
    .clientSecret("my-secret")
    .build();

// Gateway Mode: Pre-check → Your LLM call → Audit
PolicyApprovalResult approval = client.getPolicyApprovedContext(
    PolicyApprovalRequest.builder()
        .query("Analyze customer sentiment")
        .clientId("my-app")
        .userToken("user-123")
        .build());

if (approval.isApproved()) {
    // Make your LLM call here...
    client.auditLLMCall(AuditOptions.builder()
        .contextId(approval.getContextId())
        .clientId("my-app")
        .model("gpt-4")
        .success(true)
        .build());
}
```

### Rust (preview)

```rust
use axonflow_sdk_rust::{AxonFlowClient, AxonFlowConfig};

let config = AxonFlowConfig::new("http://localhost:8080")
    .with_auth("my-app", "my-secret");
let client = AxonFlowClient::new(config)?;

let response = client.proxy_llm_call(
    "user-123",
    "Analyze customer sentiment",
    "chat",
    serde_json::json!({}),
).await?;
```

The Rust SDK is at v0.8.1 preview on [crates.io](https://crates.io/crates/axonflow-sdk-rust). Repo: [axonflow-sdk-rust](https://github.com/getaxonflow/axonflow-sdk-rust).

> **[SDK Documentation](https://docs.getaxonflow.com/docs/sdk/overview/)**

---

## Examples

| Example | Description |
|---------|-------------|
| **[Execution Tracking](examples/execution-tracking/)** | WCP workflows, step ledger, MAP plans, cancellation |
| **[Support Demo](examples/support-demo/)** | Customer support with PII redaction and RBAC |
| **[Code Governance](examples/code-governance/)** | Detect and audit LLM-generated code |
| **[Hello World](examples/hello-world/)** | Minimal SDK example (30 lines) |

> **[Browse all examples](examples/)**

---

## Development

```bash
docker compose up -d              # Start services
docker compose logs -f            # View logs
go test ./platform/... -cover     # Run tests
```

For a full development environment with health checks and automatic waits, use:
```bash
./scripts/local-dev/start.sh      # Recommended for development
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete development guide.

| Package | Coverage | Threshold |
|---------|----------|-----------|
| Orchestrator | 76.8% | 76% |
| Agent | 76.6% | 76% |
| Connectors | 77.1% | 76% |
| Shared Policy | 82.4% | 80% |

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- 76% minimum test coverage required
- Tests must be fast (<5s), deterministic
- Security-first: validate inputs, no secrets in logs

---

## Telemetry

AxonFlow SDKs, plugins, and platform binaries (agent + orchestrator) emit an anonymous startup heartbeat — version, OS/architecture, environment class, license tier — at most once per machine every 7 days. No prompts, payloads, API keys, or tenant identifiers. Opt out with `export AXONFLOW_TELEMETRY=off`. On Community SaaS (`try.getaxonflow.com`) the hosted service also processes operational data governed by the [Privacy Policy](https://getaxonflow.com/privacy/), not by this env var. Full schema and per-surface details: [Telemetry docs](https://docs.getaxonflow.com/docs/telemetry/).

---

## Links

- **Docs:** https://docs.getaxonflow.com
- **Performance:** [Load testing — Measured Results](https://docs.getaxonflow.com/docs/development/load-testing/#measured-results) for published P50/P95/P99 numbers and test conditions
- **License:** [BSL 1.1](LICENSE) (converts to Apache 2.0 after 4 years)
- **Issues:** https://github.com/getaxonflow/axonflow/issues
- **Enterprise:** [sales@getaxonflow.com](mailto:sales@getaxonflow.com)

---

> **Evaluating AxonFlow for a real deployment?**
>
> Choose the path that fits:
> - **Self-serve:** free 90-day [Evaluation License](https://getaxonflow.com/evaluation-license?utm_source=readme_platform_eval)
> - **Sponsored production decision:** paid [Design Partner Program](https://getaxonflow.com/design-partner?utm_source=readme_platform)  -  one scoped workflow over 60 or 75 days, founder-led rollout support, upfront conversion pricing, and a fixed decision date; public track from $2,000 or confidential track from $4,000
>
> Programs require a dated forcing event, written control requirements, a named executive sponsor, and a technical owner. Prices are subject to eligibility and a signed agreement. We reply within two business days.

> **Questions or feedback?**
>
> Comment in [GitHub Discussions](https://github.com/getaxonflow/axonflow/discussions/239) or email [hello@getaxonflow.com](mailto:hello@getaxonflow.com) for private feedback.

### Public Issues (Technical Questions Welcome)

If you are evaluating AxonFlow and encounter unclear behavior, edge cases, or questions about guarantees such as policy enforcement, audit semantics, or failure modes, opening a GitHub issue or discussion is welcome. This includes situations where you are unsure whether something is expected behavior, a limitation, or a mismatch with your use case.

For private or sensitive questions, you can also reach us at hello@getaxonflow.com.

### Evaluating AxonFlow or Exploring Internally?

If you looked at AxonFlow in any capacity — reading code, cloning SDKs, testing locally, or mapping it to an internal use case — we would value your perspective.

This includes cases where you:

- paused evaluation
- decided not to proceed
- are still exploring
- are borrowing ideas for internal work

[Anonymous evaluation feedback (30 seconds)](https://getaxonflow.com/feedback)

No attribution. No tracking. No follow-up unless you explicitly opt in.

---

_Quick Start verified locally: Mar 2026_
