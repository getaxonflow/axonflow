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

# 2. Set your LLM provider credentials (OpenAI example, see docs for Bedrock/Ollama/Anthropic)
export OPENAI_API_KEY=sk-your-key-here
# OR use AWS Bedrock: export LLM_PRIMARY_PROVIDER=bedrock BEDROCK_REGION=us-east-1
# OR use Ollama: export LLM_PRIMARY_PROVIDER=ollama OLLAMA_BASE_URL=http://localhost:11434

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

**Test it's working:**
```bash
# Check agent health
curl http://localhost:8080/health

# Check orchestrator health
curl http://localhost:8081/health

# View logs
docker-compose logs -f axonflow-agent
docker-compose logs -f axonflow-orchestrator
```

## 🆕 What's New (December 2025)

- **MAP 0.8**: REST API for agent management - list, get, validate agents via `/api/v1/agents` (Enterprise: full CRUD, version history, sandbox testing)
- **MAP 0.5**: User-configurable agents via YAML - define your own agent workflows without code changes
- **Python SDK**: First-class Python support (`pip install axonflow`) alongside TypeScript and Go
- **Anthropic Provider**: Claude support in OSS core (OpenAI + Anthropic)
- **OSS Connectors**: 6 connectors in OSS (PostgreSQL, MySQL, MongoDB, Redis, HTTP, Cassandra)
- **Test Coverage**: 70%+ across all modules (Agent: 74.9%, Orchestrator: 73.7%, Connectors: 68.6%)
- **OpenAPI Spec**: Full API documented at `docs/api/orchestrator-api.yaml`

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
| AWS Bedrock | ❌ | ✅ |
| Ollama (local/air-gapped) | ❌ | ✅ |
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

### Demo Users & Permissions

| User | Role | Region | Permissions | Use Case |
|------|------|--------|-------------|----------|
| `john.doe@company.com` | Support Agent | US West | Limited PII | Day-to-day support queries |
| `sarah.manager@company.com` | Manager | US West | Full PII | Escalated support cases |
| `admin@company.com` | Admin | Global | All Access | System administration |
| `eu.agent@company.com` | EU Agent | EU West | EU Data Only | GDPR compliance demo |

**Password for all users:** `demo123`

## 🔐 Security Features Demonstrated

### 1. **Row-Level Security**
- Users only see data from their assigned region
- Automatic query filtering based on permissions
- Zero-trust data access model

### 2. **PII Detection & Redaction**
- Automatic detection of SSNs, credit cards, phone numbers
- Permission-based redaction (users without `read_pii` see `[REDACTED_SSN]`)
- Real-time PII flagging in results

### 3. **Audit Logging**
- Every query logged with user, timestamp, results count
- PII detection events tracked
- Immutable audit trail for compliance

### 4. **Permission-Based Access**
- Role-based permissions (`read_customers`, `read_pii`, `admin`)
- Fine-grained access control
- Dynamic query modification

## 📊 Sample Data

The demo includes realistic customer support data:
- **10 customers** across US and EU regions with real PII
- **10 support tickets** with embedded sensitive information
- **4 users** with different permission levels
- **Audit logs** showing all historical queries

## 🧪 Demo Queries to Try

### Support Agent (john.doe@company.com)
```sql
SELECT * FROM customers WHERE region = 'us-west' LIMIT 10
SELECT * FROM support_tickets WHERE status = 'open' LIMIT 5
SELECT name, email FROM customers WHERE support_tier = 'premium'
```
*PII will be automatically redacted*

### Manager (sarah.manager@company.com)
```sql
SELECT * FROM customers WHERE support_tier = 'enterprise'
SELECT * FROM support_tickets WHERE priority = 'high'
SELECT customer_id, title, description FROM support_tickets WHERE assigned_to LIKE '%manager%'
```
*Full PII access granted*

### Admin (admin@company.com)
```sql
SELECT * FROM customers LIMIT 10
SELECT * FROM support_tickets WHERE created_at > CURRENT_DATE - INTERVAL '7 days'
SELECT user_email, COUNT(*) as query_count FROM audit_log GROUP BY user_email
```
*Global access to all data*

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  React Frontend │───▶│   Go API        │───▶│  PostgreSQL     │
│  (Port 3000)    │    │  (Port 8080)    │    │  (Port 5432)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        │              ┌─────────────────┐             │
        └─────────────▶│  Security Layer │◀────────────┘
                       │  - JWT Auth     │
                       │  - Row Filters  │
                       │  - PII Detection│
                       │  - Audit Log    │
                       └─────────────────┘
```

## 🔧 Technical Stack

- **Backend:** Go with PostgreSQL
- **Frontend:** React with modern UI
- **Database:** PostgreSQL with realistic demo data
- **Auth:** JWT tokens with permission-based access
- **Security:** Row-level security, PII detection, audit logging
- **Deployment:** Docker Compose for one-command setup

## 📈 Key Metrics Dashboard

The demo shows real-time compliance metrics:
- Total queries executed
- PII detections and redactions
- Compliance score calculation
- System health status

## 🚨 What This Demonstrates

### For Investors:
1. **Clear Value Prop:** "Connect ANY database to ANY LLM with ZERO security compromises"
2. **Large Market:** Every enterprise needs AI governance for sensitive data
3. **Technical Differentiation:** Real-time PII detection + row-level security
4. **Compliance Focus:** Built for regulated industries (healthcare, finance, etc.)

### Enterprise Selling Points:
- **Instant compliance** - SOC2, GDPR, HIPAA ready
- **Zero security compromises** - Fine-grained access control
- **Audit-ready** - Complete trail of all AI data access
- **Easy integration** - Works with existing databases and LLMs

## 🛠️ Development

### Prerequisites
- Docker & Docker Compose
- (Optional) Go 1.21+ and Node.js 18+ for local development

### Local Development
```bash
# Backend only
cd backend
go run main.go

# Frontend only  
cd frontend
npm install
npm start
```

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET`: Secret for JWT token signing
- `PORT`: API server port (default: 8080)

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

Built with support from Claude and other AI tools to accelerate development.