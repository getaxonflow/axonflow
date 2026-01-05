# AxonFlow

> Self-hosted governance and orchestration for production AI systems.

## TL;DR

- **What:** A control plane that sits between your app and LLM providers, applying real-time policy enforcement and orchestration
- **How it works:** Runs AI workflows end-to-end as a control plane, with an optional gateway mode for incremental adoption
- **How it runs:** Docker Compose locally, no signup, no license key required
- **Core features:** Policy enforcement (PII, injection attacks), audit trails, multi-model routing, multi-agent planning
- **License:** BSL 1.1 (source-available) — converts to Apache 2.0 after 4 years
- **Not for:** Hobby scripts or single-prompt experiments — built for teams taking AI to production

📘 **[Full Documentation](https://docs.getaxonflow.com)** · 🚀 **[Getting Started Guide](https://docs.getaxonflow.com/docs/getting-started)** · 🔌 **[API Reference](./docs/api/)**

*AxonFlow is implemented in Go as a long-running control plane, with client SDKs for **Python**, **TypeScript**, **Go**, and **Java**.*

---

## Why This Exists

Most agent frameworks optimize for authoring workflows, not operating them.
Once agents touch real systems, teams run into familiar problems: partial failures, retries with side effects, missing permissions, and no runtime visibility.

AxonFlow treats agents as long-running, stateful systems that require governance, observability, and control at runtime — not just good prompts.

---

## Quick Start

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
| Orchestrator | http://localhost:8081 | LLM routing, dynamic policies |
| Grafana | http://localhost:3000 | Dashboards (admin / grafana_localdev456) |
| Prometheus | http://localhost:9090 | Metrics |

> **Note:** All commands in this README assume you're in the repository root directory (`cd axonflow`).

### Supported LLM Providers

| Provider | Community | Enterprise | Notes |
|----------|:---------:|:----------:|-------|
| **OpenAI** | ✅ | ✅ | GPT-5.2, GPT-4o, GPT-4 |
| **Anthropic** | ✅ | ✅ | Claude Sonnet 4, Claude Opus 4.5 |
| **Azure OpenAI** | ✅ | ✅ | Azure AI Foundry & Classic endpoints |
| **Google Gemini** | ✅ | ✅ | Gemini 3 Flash, Gemini 3 Pro |
| **Ollama** | ✅ | ✅ | Local/air-gapped deployments |
| **AWS Bedrock** | ❌ | ✅ | HIPAA-compliant, data residency |

→ **[Provider configuration guide](https://docs.getaxonflow.com/docs/llm/overview)**

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

**Requires:** Python 3.9+ (for demo scripts)

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

## Who This Is For

**Good fit:**
- Production AI teams needing governance before shipping
- Platform teams building internal AI infrastructure
- Regulated industries (healthcare, finance, legal) with compliance requirements
- Teams wanting audit trails and policy enforcement without building it themselves

**Not a good fit:**
- Single-prompt experiments or notebooks
- Prototypes where governance isn't a concern yet
- Projects where adding a service layer is overkill

---

## What AxonFlow Does

**Policy Enforcement** — Block SQL injection, detect PII (SSN, credit cards, PAN/Aadhaar), enforce rate limits. Policies apply before requests reach LLMs.

**SQL Injection Response Scanning** — Detect SQLi payloads in MCP connector responses. Protects against data exfiltration when compromised data is returned from databases.

**Code Governance** — Detect LLM-generated code, identify language and security issues (secrets, eval, shell injection). Logged for compliance.

**Audit Trails** — Every request logged with full context. Know what was blocked, why, and by which policy. Token usage tracked for cost analysis.

**Decision & Execution Replay** — Debug governed workflows with step-by-step state and policy decisions. Timeline view and compliance exports included.

**Cost Controls** — Set budgets at org, team, agent, or user level. Track LLM spend across providers with configurable alerts and enforcement actions.

**Multi-Model Routing** — Route requests across OpenAI, Anthropic, Bedrock, Ollama based on cost, capability, or compliance requirements. Failover included.

**Multi-Agent Planning** — Define agents in YAML, let AxonFlow turn natural language requests into executable workflows.

**Proxy Mode** — Full request lifecycle: policy, planning, routing, audit. Recommended for new projects.

**Gateway Mode** — Governance for existing stacks (LangChain, CrewAI, and similar frameworks). Pre-check → your call → audit.

→ **[Choosing a mode](https://docs.getaxonflow.com/docs/sdk/choosing-a-mode)** · **[Architecture deep-dive](https://docs.getaxonflow.com/docs/architecture/overview)**

### vs LangChain / LangSmith

| Feature | AxonFlow | LangChain/LangSmith |
|---------|----------|---------------------|
| **Governance** | Inline policy enforcement | Post-hoc monitoring |
| **Architecture** | Active prevention | Passive detection (observability) |
| **Enterprise Focus** | Built for compliance & security first | Developer-first framework |
| **Multi-Tenant** | Production-ready isolation | DIY multi-tenancy |
| **Self-Hosted** | Full core available | Partial (monitoring requires cloud) |

**The Key Difference:** LangChain/LangSmith focus on observability and post-hoc analysis, while AxonFlow enforces policies inline during request execution.

**Best of Both Worlds:** Many teams use LangChain for orchestration logic with AxonFlow as the governance layer on top.

---

## Architecture

```
┌─────────────┐    ┌─────────────────────────────────────┐
│  Your App   │───▶│            Agent (:8080)            │
│   (SDK)     │    │  ┌───────────┐ ┌─────────────┐      │
└─────────────┘    │  │  Policy   │ │    MCP      │      │
                   │  │  Engine   │ │ Connectors  │      │
                   │  └───────────┘ └─────────────┘      │
                   └───────────────┬─────────────────────┘
                                   │
                                   ▼
                   ┌─────────────────────────────────────┐
                   │        Orchestrator (:8081)         │
                   │  ┌───────────┐ ┌─────────────┐      │
                   │  │  Dynamic  │ │ Multi-Agent │      │
                   │  │  Policies │ │  Planning   │      │
                   │  └───────────┘ └─────────────┘      │
                   └───────────────┬─────────────────────┘
                                   │
                                   ▼
                   ┌─────────────────────────────────────┐
                   │            LLM Providers            │
                   │  (OpenAI, Anthropic, Bedrock, etc.) │
                   └─────────────────────────────────────┘

        PostgreSQL (policies, audit) • Redis (cache)
```

- **Agent** (:8080): Policy enforcement, PII detection, SQLi response scanning, MCP connectors
- **Orchestrator** (:8081): LLM routing, dynamic policies, multi-agent planning

---

## Community vs Enterprise

Community is for experimentation and validation. Enterprise is what IT, security, and compliance require for production rollout.

### Stay on Community if:
- Single team prototyping AI features
- No centralized identity or IT controls required
- No regulatory or audit requirements

### You need Enterprise when:

**Identity & Organization Controls**
- SSO + SAML authentication
- SCIM user lifecycle management
- Multi-tenant isolation

**Compliance & Risk**
- EU AI Act conformity workflows + 10-year retention
- SEBI/RBI compliance exports + 5-year retention
- Human-in-the-Loop approval queues
- Emergency circuit breaker (kill switch)

**Platform & Operations**
- One-click AWS CloudFormation deployment
- Usage analytics and cost attribution
- Priority support with SLA
- Customer Portal UI for runtime management

See the full **[Community vs Enterprise feature matrix](https://docs.getaxonflow.com/docs/features/community-vs-enterprise)**
*(designed for security reviews, procurement, and platform evaluations)*

**Enterprise:** [AWS Marketplace](https://aws.amazon.com/marketplace) or [sales@getaxonflow.com](mailto:sales@getaxonflow.com)

---

## SDKs

```bash
pip install axonflow          # Python
npm install @axonflow/sdk     # TypeScript
go get github.com/getaxonflow/axonflow-sdk-go  # Go
```

```xml
<!-- Java (Maven) -->
<dependency>
    <groupId>com.getaxonflow</groupId>
    <artifactId>axonflow-sdk</artifactId>
    <version>2.1.0</version>
</dependency>
```

### Python

```python
from axonflow import AxonFlow

async with AxonFlow(endpoint="http://localhost:8080") as ax:
    response = await ax.execute_query(
        user_token="user-123",
        query="Analyze customer sentiment",
        request_type="chat"
    )
```

### TypeScript

```typescript
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const axonflow = new AxonFlow({ endpoint: 'http://localhost:8080' });

// Wrap any AI call with AxonFlow protection
const response = await axonflow.protect(async () => {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'Analyze customer sentiment' }]
  });
});
```

### Go

```go
import "github.com/getaxonflow/axonflow-sdk-go"

client := axonflow.NewClient("http://localhost:8080")
response, err := client.ExecuteQuery(ctx, axonflow.QueryRequest{
    UserToken:   "user-123",
    Query:       "Analyze customer sentiment",
    RequestType: "chat",
})
```

### Java

```java
import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.*;

AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
    .endpoint("http://localhost:8080")
    .build());

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

→ **[SDK Documentation](https://docs.getaxonflow.com/docs/sdk/overview)**

---

## Examples

| Example | Description |
|---------|-------------|
| **[Support Demo](examples/support-demo/)** | Customer support with PII redaction and RBAC |
| **[Code Governance](examples/code-governance/)** | Detect and audit LLM-generated code |
| **[Hello World](examples/hello-world/)** | Minimal SDK example (30 lines) |

→ **[Browse all examples](examples/)**

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

| Package | Coverage |
|---------|----------|
| Agent | 78.7% |
| Orchestrator | 73.9% |
| Connectors | 63.4% |

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- 70% minimum test coverage required
- Tests must be fast (<5s), deterministic
- Security-first: validate inputs, no secrets in logs

---

## Links

- **Docs:** https://docs.getaxonflow.com
- **License:** [BSL 1.1](LICENSE) (converts to Apache 2.0 after 4 years)
- **Issues:** https://github.com/getaxonflow/axonflow/issues
- **Enterprise:** [sales@getaxonflow.com](mailto:sales@getaxonflow.com)

---

### Public Issues (Technical Questions Welcome)

If you're evaluating AxonFlow and encounter unclear behavior, edge cases, or questions around guarantees (e.g. policy enforcement, audit semantics, failure modes), opening a GitHub issue is welcome.

We're especially interested in questions that surface ambiguous semantics or runtime edge cases rather than general feedback.

### Private Evaluation Questions

If you're evaluating AxonFlow internally and prefer not to open a public issue, you can reach us at hello@getaxonflow.com.

This channel is intended for technical questions about semantics, guarantees, or runtime behavior. We treat these as engineering discussions, not sales conversations.

---

_Quick Start verified locally: Jan 2026_
