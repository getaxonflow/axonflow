# AxonFlow - The NewRelic of AI Orchestration

> **The NewRelic of AI Orchestration** — Prevent AI failures before they happen with 9.5ms inline governance. Unlike passive monitoring that detects issues after damage, AxonFlow provides active prevention in real-time.
>
> **9.5ms inline governance • active prevention not passive detection • 420% ROI • EU AI Act ready • multi-model routing • audit-grade observability**

## 🚀 Quick Start

### Self-Hosted (OSS - No License Required)

Get AxonFlow running locally in under 5 minutes with docker-compose:

```bash
# 1. Clone the repository
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow

# 2. Set your LLM provider credentials (see table below for OSS vs Enterprise providers)
export OPENAI_API_KEY=sk-your-key-here
# OR: export ANTHROPIC_API_KEY=sk-ant-your-key-here

# 3. Start all services (agent + orchestrator + postgres + redis)
docker-compose up -d

# 4. Check service health
docker-compose ps

# Services available at:
# - Agent:        http://localhost:8080
# - Orchestrator: http://localhost:8081
# - PostgreSQL:   localhost:5432
# - Redis:        localhost:6379
```

**Self-hosted mode runs without license validation** - no license server or account needed!

**What you get:**
- ✅ Full AxonFlow platform (agent + orchestrator)
- ✅ PostgreSQL database with automatic migrations
- ✅ Redis for rate limiting and caching
- ✅ No license validation required
- ✅ Same core features as production
- ✅ Perfect for local development and evaluation

### Supported LLM Providers

| Provider | OSS | Enterprise | Notes |
|----------|:---:|:----------:|-------|
| **OpenAI** | ✅ | ✅ | GPT-4, GPT-4o, GPT-3.5 |
| **Anthropic** | ✅ | ✅ | Claude 3.5 Sonnet, Claude 3 Opus |
| **Ollama** | ✅ | ✅ | Local/air-gapped deployments |
| **AWS Bedrock** | ❌ | ✅ | HIPAA-compliant, data residency |
| **Google Gemini** | ❌ | ✅ | Gemini Pro, Gemini Ultra |

> **Note:** OSS users can use OpenAI, Anthropic, or Ollama. Enterprise providers (Bedrock, Gemini) require a license. Setting an unsupported provider in OSS will show a helpful error message.

**Test it's working:**
```bash
# Check agent health
curl http://localhost:8080/health

# Check orchestrator health
curl http://localhost:8081/health
```

## 🎯 Try It Now - See AxonFlow in Action

**Services running? Let's see what AxonFlow can do!** Run the interactive demo:

```bash
./platform/examples/demo/demo.sh
```

**Expected output:**
```
╔═══════════════════════════════════════════════════════════════╗
║               AxonFlow Interactive Demo                       ║
║          Real-time AI Governance in Action                    ║
╚═══════════════════════════════════════════════════════════════╝

Demo 1: SQL Injection Blocking
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Sending: "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"
🛡️  BLOCKED - SQL Injection Detected

Demo 2: Safe Query (Allowed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Sending: "What is the weather forecast for tomorrow?"
✓ ALLOWED - No policy violations

Demo 3: Credit Card Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Sending: "Charge my card 4111-1111-1111-1111 for the order"
🛡️  POLICY TRIGGERED - Credit Card Detected

Demo 4: Sub-10ms Policy Evaluation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡ Average latency: 3ms (Sub-10ms inline governance achieved!)
```

**That's AxonFlow** - blocking malicious queries and detecting sensitive data in real-time, under 10ms.

### Want More? Try These Examples

| Example | Description | Command |
|---------|-------------|---------|
| **[Support Demo](platform/examples/support-demo/)** | Full customer support app with PII redaction, RBAC, audit logs | `cd platform/examples/support-demo && docker-compose up` |
| **[Hello World](examples/hello-world/)** | Minimal SDK example (30 lines) | `cd examples/hello-world/go && go run main.go` |
| **[Workflows](examples/workflows/)** | 10 production-ready workflow patterns | See [examples/workflows/README.md](examples/workflows/README.md) |

### Quick SDK Test

Want to try from code? Here's the Python equivalent of the demo:

```python
# pip install requests
import requests

# Test SQL injection detection using the Gateway Mode pre-check endpoint
response = requests.post("http://localhost:8080/api/policy/pre-check", json={
    "client_id": "demo",
    "user_token": "demo-user",
    "query": "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
    "context": {"user_role": "agent"}
})

print(response.json())  # Shows approved: false, block_reason: "SQL injection detected"
```

---

## 🆕 What's New (December 2025)

- **EU AI Act Compliance**: Full Article 43 conformity assessment APIs, HITL workflows, accuracy metrics, bias detection, and emergency circuit breaker
- **MAP 0.8**: REST API for agent management - list, get, validate agents via `/api/v1/agents` (Enterprise: full CRUD, version history, sandbox testing)
- **MAP 0.5**: User-configurable agents via YAML - define your own agent workflows without code changes
- **Python SDK**: First-class Python support (`pip install axonflow`) alongside TypeScript and Go
- **Anthropic Provider**: Claude support in OSS core (OpenAI + Anthropic)
- **OSS Connectors**: 6 connectors in OSS (PostgreSQL, MySQL, MongoDB, Redis, HTTP, Cassandra)
- **Test Coverage**: 70%+ across all modules (Agent: 74.9%, Orchestrator: 73.7%, Connectors: 68.6%)
- **OpenAPI Spec**: Full API documented at `docs/api/orchestrator-api.yaml`

### 🇪🇺 EU AI Act Compliance (Enterprise)

AxonFlow Enterprise provides comprehensive EU AI Act compliance features:

| Feature | Article | Description |
|---------|---------|-------------|
| Decision Chain Tracing | 12, 13 | Full audit trail with transparency headers |
| Human-in-the-Loop (HITL) | 14 | Workflow queues for human oversight |
| Conformity Assessment | 43 | Self-assessment and third-party assessment APIs |
| Accuracy Metrics | 9, 15 | Performance tracking and threshold alerts |
| Bias Detection | 9, 10 | Category-based bias scoring and monitoring |
| Emergency Circuit Breaker | 15 | Immediate halt on critical issues |
| Audit Export | 11, 12 | EU AI Act compliant export format |

See [EU AI Act Compliance Guide](docs/EU_AI_ACT_COMPLIANCE.md) for complete documentation.

**Authentication for SDK calls:**

In self-hosted mode, use any non-empty credentials:
- **Client ID:** Any string (e.g., `my-app`)
- **User Token:** Any string (e.g., `dev-user`)

```python
from axonflow import AxonFlow

async with AxonFlow(
    agent_url="http://localhost:8080",
    client_id="my-app",
    client_secret="any-secret"
) as ax:
    response = await ax.execute_query(
        user_token="dev-user",
        query="Hello!",
        request_type="chat"
    )
```

### Production Deployment (AWS)

For production deployments on AWS, we provide:

**Option 1: AWS Marketplace (Easiest)**
- One-click CloudFormation deployment
- Auto-scaling ECS Fargate setup
- Multi-AZ RDS PostgreSQL
- Application Load Balancer
- Production-grade security groups

**Option 2: Manual ECS Deployment**
```bash
# Build and push images to ECR
bash scripts/deployment/build-and-push.sh --component agent --version latest
bash scripts/deployment/build-and-push.sh --component orchestrator --version latest

# Deploy using your environment config
bash scripts/deployment/deploy.sh --environment production
```

See `technical-docs/DEPLOYMENT_GUIDE.md` for detailed deployment guides and `technical-docs/DECOUPLED_DEPLOYMENTS_GUIDE.md` for decoupled deployment strategies.

## 🤔 Why AxonFlow?

### vs LangChain / LangSmith

| Feature | AxonFlow | LangChain/LangSmith |
|---------|----------|---------------------|
| **Governance** | ✅ Real-time policy enforcement (9.5ms) | ❌ Post-hoc monitoring only |
| **Architecture** | Active prevention (inline) | Passive detection (observability) |
| **Enterprise Focus** | Built for compliance & security first | Developer-first framework |
| **Multi-Tenant** | ✅ Production-ready isolation | ❌ DIY multi-tenancy |
| **Policy-as-Code** | ✅ RBAC, ABAC, data redaction | ❌ Basic guardrails |
| **Self-Hosted** | ✅ OSS core available | Partial (monitoring requires cloud) |

**The Key Difference:**
LangChain/LangSmith **detect** problems after they happen (read-only monitoring).
AxonFlow **prevents** problems before they happen (read-write governance).

**When to Use AxonFlow:**
- You need EU AI Act compliance
- You're in a regulated industry (healthcare, finance, legal)
- You need real-time data redaction and PII protection
- You want policy-as-code enforcement, not just logging
- You need multi-tenant enterprise deployments

**When to Use LangChain:**
- You're building prototypes and MVPs
- Compliance isn't critical yet
- You need maximum flexibility in implementation
- You prefer framework over platform

**Best of Both Worlds:** Many teams use LangChain for orchestration logic with AxonFlow as the governance layer on top.

## 🆓 OSS vs Enterprise Features

AxonFlow is available in two editions:

| Feature | OSS (Free) | Enterprise |
|---------|------------|------------|
| **Core Platform** | | |
| Policy enforcement engine | ✅ | ✅ |
| Sub-10ms inline governance | ✅ | ✅ |
| PII detection (10 types) | ✅ | ✅ |
| Audit logging | ✅ | ✅ |
| **LLM Providers** | | |
| OpenAI | ✅ | ✅ |
| Anthropic (Claude) | ✅ | ✅ |
| Ollama (local/air-gapped) | ✅ | ✅ |
| AWS Bedrock | ❌ | ✅ |
| Google Gemini | ❌ | ✅ |
| **MCP Connectors** | | |
| PostgreSQL | ✅ | ✅ |
| MySQL | ✅ | ✅ |
| MongoDB | ✅ | ✅ |
| Redis | ✅ | ✅ |
| HTTP/REST | ✅ | ✅ |
| Cassandra | ✅ | ✅ |
| Amadeus (Travel API) | ❌ | ✅ |
| Salesforce | ❌ | ✅ |
| Slack | ❌ | ✅ |
| Snowflake | ❌ | ✅ |
| **Multi-Agent Planning (MAP)** | | |
| YAML agent configuration | ✅ | ✅ |
| Agent registry with hot reload | ✅ | ✅ |
| REST API (list, get, validate) | ✅ | ✅ |
| REST API (CRUD, versions, test) | ❌ | ✅ |
| Database-backed storage | ❌ | ✅ |
| **EU AI Act Compliance** | | |
| Decision chain tracing | ✅ | ✅ |
| Transparency headers (X-AI-*) | ✅ | ✅ |
| Human-in-the-Loop (HITL) | ❌ | ✅ |
| Conformity assessment APIs | ❌ | ✅ |
| Accuracy metrics & bias detection | ❌ | ✅ |
| Emergency circuit breaker | ❌ | ✅ |
| EU AI Act export format | ❌ | ✅ |
| **Advanced Features** | | |
| Policy templates library | Basic | Full (EU AI Act, HIPAA, PCI-DSS) |
| Customer dashboard UI | ❌ | ✅ |
| Usage analytics | ❌ | ✅ |
| AWS Marketplace integration | ❌ | ✅ |
| **Deployment** | | |
| Docker Compose (local) | ✅ | ✅ |
| AWS ECS/Fargate | Manual | One-click CloudFormation |
| Multi-tenant isolation | ❌ | ✅ |
| **Support** | | |
| Community (GitHub Issues) | ✅ | ✅ |
| Priority support | ❌ | ✅ |
| SLA guarantees | ❌ | ✅ |

**Get Enterprise:** Contact [sales@getaxonflow.com](mailto:sales@getaxonflow.com) or deploy via [AWS Marketplace](https://aws.amazon.com/marketplace).

## 📦 SDK Integration

Add AxonFlow governance to your existing applications in 3 lines of code:

### Python (Primary)

```bash
pip install axonflow
```

```python
from axonflow import AxonFlow

async with AxonFlow(
    agent_url="http://localhost:8080",
    client_id="demo",
    client_secret="demo"
) as ax:
    response = await ax.execute_query(
        user_token="user-123",
        query="Analyze customer sentiment",
        request_type="chat"
    )
```

### TypeScript

```bash
npm install @axonflow/sdk
```

```typescript
import { AxonFlow } from '@axonflow/sdk';
import OpenAI from 'openai';

// Initialize your AI client
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const axonflow = new AxonFlow({
  endpoint: 'http://localhost:8080'  // Points to AxonFlow agent
});

// Wrap any AI call with AxonFlow protection
const response = await axonflow.protect(async () => {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'Analyze customer sentiment' }]
  });
});
```

### Go

```bash
go get github.com/getaxonflow/axonflow-sdk-go
```

**SDK Features:**
- ✅ Drop-in protection for OpenAI, Anthropic, and other LLM providers
- ✅ MCP connector integration (Amadeus, Redis, PostgreSQL, HTTP, and more)
- ✅ Multi-Agent Planning (MAP) with user-configurable agents via YAML
- ✅ Python, TypeScript, and Go SDKs available
- ✅ Zero UI changes required

**Documentation:**
- Python SDK: https://github.com/getaxonflow/axonflow-sdk-python
- TypeScript SDK: https://github.com/getaxonflow/axonflow-sdk-typescript
- Go SDK: https://github.com/getaxonflow/axonflow-sdk-go
- Full docs: https://docs.getaxonflow.com

## 🎯 Vision: The NewRelic of AI Orchestration

**AxonFlow is the NewRelic of AI Orchestration** — preventing AI failures before they happen with industry-leading 9.5ms inline governance. While monitoring tools detect problems after damage is done, AxonFlow actively prevents hallucinations, data leaks, and compliance violations in real-time.

**Key Differentiator:** Active prevention (read-write) vs passive monitoring (read-only). Our architectural DNA enables real-time intervention that incumbents can't match without rebuilding from scratch.

### The Problem We Solve
- **Prevention Gap:** Current tools detect AI failures after damage is done
- **70%** of pilots stall without real-time governance
- **9.5ms** performance makes inline prevention possible (industry first)
- **420%** ROI through prevented incidents and operational efficiency
- **11-month window** - EU AI Act enforcement creates urgency

### Why Now?
- **EU AI Act enforcement** → 11-month first-mover window (August 2025)
- **$45B precedent** → Observability market proves the model
- **Performance breakthrough** → 9.5ms enables real-time prevention
- **Innovator's Dilemma** → Monitoring companies can't pivot to prevention
- **Next 12 months** = category-defining window

## 🎯 Solution: Active AI Governance Platform

The NewRelic of AI — prevent failures before they happen with real-time governance:

### 🔄 **Agentic Workflow Orchestration**
- Visualise and deploy multi-step AI workflows across internal systems
- Visual editor + code-first config (YAML/JSON/DSL)
- Decision logic, retries, approvals, fallbacks
- Multi-agent flows (LLM + human-in-the-loop)
- Versioned rollouts & rollback support

### 🔗 **Internal System Integration (via MCP)**
- Connect codebases, databases, services via Model Context Protocol
- Secure authentication and fine-grained IAM
- Service account support with secrets management

### 🌐 **Multi-Model Vendor-Neutral Routing**
**Supported Providers:**
- ✅ **OpenAI** - GPT-4, GPT-3.5
- ✅ **Anthropic** - Claude 3.5 Sonnet, Claude 3 Opus
- ✅ **AWS Bedrock** - HIPAA-compliant, data residency support
- ✅ **Ollama** - Local/air-gapped deployments

**Key Features:**
- 🔒 **No Vendor Lock-in** - Switch providers with environment variables only
- 💰 **Cost Optimization** - Route based on cost/performance requirements
- 📍 **Data Residency** - Keep data in specific regions for compliance
- 🧪 **Shadow Mode** - Test new providers safely before migration
- 🔐 **Air-Gap Support** - Deploy without internet connectivity

**Configuration Example:**
```bash
# Use AWS Bedrock for HIPAA compliance
export LLM_PRIMARY_PROVIDER=bedrock
export BEDROCK_REGION=us-east-1
export BEDROCK_MODEL=anthropic.claude-3-sonnet-20240229-v1:0

# Or use Ollama for air-gapped environments
export LLM_PRIMARY_PROVIDER=ollama
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=llama2
```

See [LLM Provider Configuration Guide](docs/LLM_PROVIDER_CONFIGURATION.md) for detailed setup and Shadow Mode migration strategies.

### 🛡 **Policy-as-Code Enforcement**
- Role-based (RBAC) and attribute-based (ABAC) access control
- Data redaction, DLP policy enforcement
- Deny-by-default with policy violation alerts

### 🔎 **Audit-Grade Observability**
- Every action, prompt, and output logged and traceable
- Export logs to SIEM or BI tools
- Alerts on anomalies and compliance violations

### 🏢 **Enterprise Deployment Flexibility**
- **SaaS**: Fast onboarding, multi-tenant isolation
- **On-premises**: Customer infrastructure, air-gapped support
- **In-VPC**: Hybrid deployments for enhanced security

## 🏗️ Architecture

```
┌─────────────┐    ┌─────────────────────────────────┐    ┌─────────────┐
│  Your App   │───▶│          Agent (:8080)          │◀──▶│   Database  │
│   (SDK)     │    │  ┌───────────┐ ┌─────────────┐  │    │ (PostgreSQL)│
└─────────────┘    │  │  Policy   │ │    MCP      │  │    │   (Redis)   │
                   │  │  Engine   │ │ Connectors  │  │    └─────────────┘
                   │  └───────────┘ └─────────────┘  │
                   └───────────────┬─────────────────┘
                                   │
                                   ▼
                   ┌─────────────────────────────────┐    ┌─────────────┐
                   │      Orchestrator (:8081)       │───▶│LLM Providers│
                   │  ┌───────────┐ ┌─────────────┐  │    │(OpenAI,     │
                   │  │  Dynamic  │ │  Multi-Agent│  │    │ Anthropic,  │
                   │  │  Policies │ │  Planning   │  │    │ Bedrock,    │
                   │  └───────────┘ └─────────────┘  │    │ Ollama)     │
                   └─────────────────────────────────┘    └─────────────┘
```

**Key Components:**
- **Agent** (port 8080): Policy enforcement, PII detection, MCP connectors, audit logging
- **Orchestrator** (port 8081): LLM routing, dynamic policies, multi-agent planning
- **PostgreSQL**: Policy storage, audit logs, configuration
- **Redis**: Rate limiting, caching, session management

## 🛠️ Development

### Prerequisites
- Docker & Docker Compose
- (Optional) Go 1.21+ for running tests locally

### Local Development
```bash
# Start all services
docker-compose up -d

# Rebuild after code changes
docker-compose up -d --build axonflow-agent

# Run tests
go test ./platform/...

# View logs
docker-compose logs -f axonflow-agent
```

### Key Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | - |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `DATABASE_HOST` | PostgreSQL host | `postgres` |
| `LOG_LEVEL` | Logging level | `info` |

## 🤝 Contributing

We welcome contributions to AxonFlow! To maintain high quality standards:

- **Test Coverage Required:** All code must meet 70% minimum test coverage (see CONTRIBUTING.md)
- **Zero Flaky Tests:** Tests must be fast (<5s), deterministic, and independent
- **Security First:** All inputs validated, no sensitive data in logs
- **Documentation:** Update docs for all user-facing changes

**Getting Started:**
1. Read `CONTRIBUTING.md` for detailed guidelines
2. Check `technical-docs/` for architecture and testing standards
3. Run `go test -cover` to verify coverage before submitting PRs

**Current Quality Status (Dec 5, 2025):**
- Agent Package: 74.9% test coverage ✅ (threshold: 74%)
- Orchestrator Package: 73.0% test coverage ✅ (threshold: 72%)
- Connectors Package: 68.6% test coverage ✅ (threshold: 66%)
- All tests passing, zero flaky tests
- CI/CD pipeline enforces coverage thresholds per module

## 📚 Documentation

**Technical Documentation:**
- `technical-docs/MAINTENANCE.md` - Automated cleanup & maintenance system
- `technical-docs/DEPLOYMENT_SCRIPTS_REFERENCE.md` - All deployment scripts
- `technical-docs/INSTANCE_ARCHITECTURE.md` - Infrastructure details
- `.claude/QUICK_REFERENCE.md` - 1-page maintenance cheat sheet

**Development:**
- `.claude/principles.md` - Development principles and standards
- `CONTRIBUTING.md` - Contribution guidelines

**Public Docs:**
- https://docs.getaxonflow.com - Customer documentation

## 🔄 Workflow Orchestration

**Built-in workflow engine** supports complex AI workflows with governance at every step:

- **YAML Configuration:** Declarative workflow definitions with step dependencies
- **LLM Integration:** Multi-provider routing (OpenAI, Anthropic, local models)
- **External Connectors:** Database, API, and service integrations
- **Human-in-the-Loop:** Approval workflows and escalation handling
- **Policy Enforcement:** Governance applied to every workflow step
- **Audit Trails:** Complete execution logging for compliance

**Example workflows included:**
- Customer support with conditional escalation
- Data analysis with privacy protection
- Content moderation with appeals process

## 📝 Development Roadmap

### Phase 0: Foundation ✅ Complete
- [x] Policy enforcement platform complete
- [x] Basic workflow orchestration engine
- [x] Multi-tenant deployment to production (5 environments)
- [x] Python, TypeScript, Go SDKs released
- [x] Multi-Agent Planning (MAP) with YAML agent configs

### Phase 1: Workflow Engine (Q4 2025)
- [ ] DAG-style workflow orchestration
- [ ] MCP connector framework
- [ ] Visual workflow builder
- [ ] Enterprise authentication

### Phase 2: Enterprise Platform (2026)
- [ ] Advanced compliance features
- [ ] Multi-client demonstrations
- [ ] SOC2 certification

---

**Built for Enterprise Scale - The Control Plane for Enterprise AI**

*AxonFlow: Like Kubernetes for containers, but for enterprise AI workflows*
