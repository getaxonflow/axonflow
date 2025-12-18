# AxonFlow

> Self-hosted governance and orchestration for production AI systems.

## TL;DR

- **What:** A control plane that sits between your app and LLM providers, applying real-time policy enforcement and orchestration
- **How it runs:** Docker Compose locally, no signup, no license key required
- **Core features:** Policy enforcement (PII, injection attacks), audit trails, multi-model routing, multi-agent planning
- **License:** BSL 1.1 (source-available) — converts to Apache 2.0 after 4 years
- **Not for:** Hobby scripts or single-prompt experiments — built for teams taking AI to production

📘 **[Full Documentation](https://docs.getaxonflow.com)** · 🚀 **[Getting Started Guide](https://docs.getaxonflow.com/docs/getting-started)** · 🔌 **[API Reference](./docs/api/)**

*AxonFlow is implemented in Go as a long-running control plane, with client SDKs for **Python**, **TypeScript**, **Go**, and **Java**.*

---

## Quick Start

```bash
# Clone and start
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow
export OPENAI_API_KEY=sk-your-key-here  # or ANTHROPIC_API_KEY
docker-compose up -d

# Verify it's running
curl http://localhost:8080/health
curl http://localhost:8081/health
```

**That's it.** Agent runs on `:8080`, Orchestrator on `:8081`.

### Supported LLM Providers

| Provider | Community | Enterprise | Notes |
|----------|:---------:|:----------:|-------|
| **OpenAI** | ✅ | ✅ | GPT-4, GPT-4o, GPT-3.5 |
| **Anthropic** | ✅ | ✅ | Claude 3.5 Sonnet, Claude 3 Opus |
| **Ollama** | ✅ | ✅ | Local/air-gapped deployments |
| **AWS Bedrock** | ❌ | ✅ | HIPAA-compliant, data residency |
| **Google Gemini** | ❌ | ✅ | Gemini Pro, Gemini Ultra |

→ **[Provider configuration guide](https://docs.getaxonflow.com/docs/llm/overview)**

### See Governance in Action (30 seconds)

```bash
# Example: Send a request containing an SSN — AxonFlow blocks it before it reaches an LLM
curl -X POST http://localhost:8080/api/policy/pre-check \
  -H "Content-Type: application/json" \
  -d '{"user_token": "demo-user", "client_id": "demo-client", "query": "Look up customer with SSN 123-45-6789"}'
```

```json
{"approved": false, "block_reason": "PII detected: ssn", "policies": ["pii_ssn_detection"]}
```

For a full end-to-end demo (gateway mode, policy enforcement, multi-agent planning), see `./examples/demo/demo.sh`.

Policy checks add single-digit millisecond overhead.

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

**Audit Trails** — Every request logged with full context. Know what was blocked, why, and by which policy. Token usage tracked for cost analysis.

**Multi-Model Routing** — Route requests across OpenAI, Anthropic, Bedrock, Ollama based on cost, capability, or compliance requirements. Failover included.

**Multi-Agent Planning** — Define agents in YAML, let AxonFlow turn natural language requests into executable workflows.

**Gateway Mode** — Wrap existing LLM calls with governance. Pre-check → your LLM call → audit. Incremental adoption path.

→ **[Architecture deep-dive](https://docs.getaxonflow.com/docs/architecture/overview)**

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

| Feature | Community (Free) | Enterprise |
|---------|------------|------------|
| **Core Platform** | | |
| Policy enforcement engine | ✅ | ✅ |
| Single-digit ms inline governance | ✅ | ✅ |
| PII detection (SSN, credit cards, PAN, Aadhaar) | ✅ | ✅ |
| SQLi response scanning (basic) | ✅ | ✅ |
| SQLi response scanning (ML-based) | ❌ | ✅ |
| Audit logging | ✅ | ✅ |
| Static Policy API (list, get) | ✅ | ✅ |
| **LLM Providers** | | |
| OpenAI | ✅ | ✅ |
| Anthropic (Claude) | ✅ | ✅ |
| Ollama (local/air-gapped) | ✅ | ✅ |
| AWS Bedrock | ❌ | ✅ |
| Google Gemini | ❌ | ✅ |
| Multi-provider routing & failover | ✅ | ✅ |
| Customer Portal provider UI | ❌ | ✅ |
| **MCP Connectors** | | |
| PostgreSQL, MySQL, MongoDB | ✅ | ✅ |
| Redis, HTTP/REST, Cassandra | ✅ | ✅ |
| S3, Azure Blob, GCS (cloud storage) | ✅ | ✅ |
| Amadeus (Travel API) | ❌ | ✅ |
| Salesforce | ❌ | ✅ |
| Slack | ❌ | ✅ |
| Snowflake | ❌ | ✅ |
| HubSpot | ❌ | ✅ |
| Jira | ❌ | ✅ |
| ServiceNow | ❌ | ✅ |
| Customer Portal Connector UI | ❌ | ✅ |
| **Multi-Agent Planning (MAP)** | | |
| YAML agent configuration | ✅ | ✅ |
| Parallel task execution | ✅ | ✅ |
| Conditional logic & branching | ✅ | ✅ |
| Agent registry with hot reload | ✅ | ✅ |
| REST API (list, get, validate) | ✅ | ✅ |
| REST API (CRUD, versions, sandbox) | ❌ | ✅ |
| Database-backed agent storage | ❌ | ✅ |
| **Policy Management** | | |
| Static policies (SQL injection, PII) | ✅ | ✅ |
| Dynamic policy CRUD API | ✅ | ✅ |
| Policy versioning | ✅ | ✅ |
| Policy templates library | Basic | Full (EU AI Act, HIPAA, PCI-DSS, SEBI) |
| Customer Portal Policy UI | ❌ | ✅ |
| **EU AI Act Compliance** | | |
| Decision chain tracing | ✅ | ✅ |
| Transparency headers (X-AI-*) | ✅ | ✅ |
| Human-in-the-Loop (HITL) queue | ❌ | ✅ |
| Emergency circuit breaker | ❌ | ✅ |
| Conformity assessment workflow | ❌ | ✅ |
| Accuracy metrics & bias detection | ❌ | ✅ |
| 10-year audit retention | ❌ | ✅ |
| EU AI Act export format | ❌ | ✅ |
| **India Compliance (SEBI/RBI)** | | |
| India PII detection (Aadhaar, PAN, UPI) | ✅ Pattern-based | ✅ With checksum |
| SEBI AI/ML Guidelines - basic detection | ✅ | ✅ |
| SEBI compliance module (export, 5-year retention) | ❌ | ✅ |
| RBI FREE-AI Framework (kill switch, board reports) | ❌ | ✅ |
| Compliance dashboard | ❌ | ✅ |
| **Platform Features** | | |
| Customer dashboard UI | ❌ | ✅ |
| Usage analytics & reporting | ❌ | ✅ |
| AWS Marketplace integration | ❌ | ✅ |
| **Deployment** | | |
| Docker Compose (local) | ✅ | ✅ |
| AWS ECS/Fargate | Manual | One-click CloudFormation |
| Multi-tenant isolation | ❌ | ✅ |
| **Support** | | |
| Community (GitHub Issues) | ✅ | ✅ |
| Priority support & SLA | ❌ | ✅ |

→ **[Full feature comparison](https://docs.getaxonflow.com/docs/features/community-vs-enterprise)**

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
    <version>1.0.0</version>
</dependency>
```

### Python

```python
from axonflow import AxonFlow

async with AxonFlow(agent_url="http://localhost:8080") as ax:
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
    .agentUrl("http://localhost:8080")
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

→ **[SDK Documentation](https://docs.getaxonflow.com/docs/sdk/choosing-a-mode)**

---

## Examples

| Example | Description |
|---------|-------------|
| **[Support Demo](examples/support-demo/)** | Customer support with PII redaction and RBAC |
| **[Hello World](examples/hello-world/)** | Minimal SDK example (30 lines) |

→ **[More examples](https://docs.getaxonflow.com/docs/examples/overview)**

---

## Development

```bash
docker-compose up -d              # Start services
docker-compose logs -f            # View logs
go test ./platform/... -cover     # Run tests
```

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
- **Issues:** https://github.com/getaxonflow/axonflow/issues
- **License:** [BSL 1.1](LICENSE) (converts to Apache 2.0 after 4 years)
- **Enterprise:** [sales@getaxonflow.com](mailto:sales@getaxonflow.com)
