# Getting Started with AxonFlow

**Build your first AI agent in 10 minutes** - No ML experience required.

---

## Table of Contents

1. [What is AxonFlow?](#what-is-axonflow)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Your First Agent (10 Minutes)](#your-first-agent-10-minutes)
5. [Understanding the Architecture](#understanding-the-architecture)
6. [Next Steps](#next-steps)
7. [Troubleshooting](#troubleshooting)

---

## What is AxonFlow?

AxonFlow is an **AI governance platform** that makes it easy to:

- ✅ Deploy production-ready AI agents with built-in governance
- ✅ Connect to your data sources (databases, APIs, file systems)
- ✅ Route requests to the right LLM models (GPT-4, Claude, Bedrock, etc.)
- ✅ Enforce policies, rate limits, and permissions automatically
- ✅ Monitor usage, costs, and performance in real-time

**Think of it as a "control plane" for AI agents** - you focus on defining what your agent should do, AxonFlow handles the infrastructure, security, and governance.

---

## Prerequisites

### Required

1. **AWS Account** - AxonFlow runs on AWS infrastructure
2. **Basic Command Line Skills** - Ability to run bash commands
3. **Docker Installed** (for local development) - [Install Docker](https://docs.docker.com/get-docker/)

### Optional (for production)

- **Domain Name** - For custom URLs like `https://ai.yourcompany.com`
- **SSL Certificate** - Automatically provided via Let's Encrypt
- **AWS CLI** - For advanced deployments

---

## Quick Start

### Option 1: AWS Marketplace (Recommended for Production)

Deploy AxonFlow in one click from AWS Marketplace:

1. **Subscribe to AxonFlow** on AWS Marketplace
   - Visit: [AWS Marketplace - AxonFlow](https://aws.amazon.com/marketplace)
   - Click "Continue to Subscribe"
   - Accept terms (pay-as-you-go, hourly billing)

2. **Launch CloudFormation Stack**
   - Click "Continue to Configuration"
   - Select your AWS region (e.g., `us-east-1`, `eu-central-1`)
   - Click "Continue to Launch"
   - Choose "Launch CloudFormation"

3. **Configure Your Deployment**
   ```yaml
   Stack Name: axonflow-production
   VPC: vpc-12345678 (select existing or create new)
   Subnets: subnet-abc, subnet-def (2 availability zones)
   Database Password: (generate strong password)
   Pricing Tier: Professional ($0.10/node-hour)
   ```

4. **Wait 10-15 Minutes**
   - CloudFormation creates all infrastructure
   - Agents, orchestrators, database, load balancer
   - Automatic SSL certificate generation

5. **Access Your Dashboard**
   - Get ALB URL from CloudFormation Outputs tab
   - Example: `http://axonfl-AxonF-ABC123.us-east-1.elb.amazonaws.com`
   - First login creates admin account

**Total Cost:**
- 2 agents × 24 hours × 30 days × $0.10 = **$144/month** (Professional tier)
- Plus AWS infrastructure (EC2, RDS, ALB) ~$150/month
- **Total: ~$300/month** for production-ready AI infrastructure

### Option 2: Local Development (Docker Compose)

Run AxonFlow locally for testing and development:

```bash
# Clone the repository
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow

# Copy environment template
cp .env.example .env

# Add your LLM API keys (at least one required)
vim .env
```

Add your API keys to `.env`:
```bash
# OpenAI (GPT-4)
OPENAI_API_KEY=sk-proj-...

# Anthropic (Claude)
ANTHROPIC_API_KEY=sk-ant-...

# AWS Bedrock (if using Bedrock models)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
```

Start AxonFlow:
```bash
# Start all services (agent, orchestrator, database, portal)
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f agent
```

**Access locally:**
- Agent API: http://localhost:8081
- Customer Portal: http://localhost:8090
- Database: localhost:5432

---

## Your First Agent (10 Minutes)

Let's build a **Customer Support Agent** that answers questions about your product using RAG (Retrieval-Augmented Generation).

### Step 1: Create Your License Key (2 minutes)

Every AxonFlow deployment includes a license key generation tool:

```bash
# Generate a license key for your organization
docker exec -it axonflow-agent /app/keygen \
  --tier PLUS \
  --org my-company \
  --expires-at 20261231 \
  --output /tmp/license.key

# View your license key
cat /tmp/license.key
```

You'll get a license key like:
```
AXON-PLUS-my-company-20261231-a7f3b2c9
```

**Save this key** - you'll need it to authenticate your application.

### Step 2: Install the AxonFlow SDK (2 minutes)

Choose your language:

**Go:**
```bash
go get github.com/getaxonflow/axonflow-sdk-go
```

**Python (coming Q1 2026):**
```bash
pip install axonflow-sdk
```

**JavaScript/TypeScript (coming Q1 2026):**
```bash
npm install axonflow-sdk
```

### Step 3: Write Your First Agent (3 minutes)

Create `customer-support-agent.go`:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
    // Initialize AxonFlow client
    client := axonflow.NewClient(axonflow.Config{
        BaseURL:    "https://your-axonflow-url.com",  // From CloudFormation or localhost:8081
        LicenseKey: os.Getenv("AXONFLOW_LICENSE_KEY"), // Your license key
    })

    // Define your query
    query := "How do I reset my password?"

    // Execute query through AxonFlow
    ctx := context.Background()
    response, err := client.ExecuteQuery(ctx, axonflow.QueryRequest{
        Query: query,
        Context: map[string]interface{}{
            "customer_id":   "cust_12345",
            "product":       "SaaS Platform",
            "intent":        "support",
        },
    })

    if err != nil {
        log.Fatalf("Query failed: %v", err)
    }

    // Print the AI response
    fmt.Printf("Customer Question: %s\n\n", query)
    fmt.Printf("AI Response:\n%s\n", response.Result)
    fmt.Printf("\nResponse Time: %.2fs\n", response.Metadata.Duration.Seconds())
    fmt.Printf("Tokens Used: %d\n", response.Metadata.TokensUsed)
    fmt.Printf("Cost: $%.4f\n", response.Metadata.Cost)
}
```

### Step 4: Run Your Agent (1 minute)

```bash
# Set your license key
export AXONFLOW_LICENSE_KEY="AXON-PLUS-my-company-20261231-a7f3b2c9"

# Run your agent
go run customer-support-agent.go
```

**Expected Output:**
```
Customer Question: How do I reset my password?

AI Response:
To reset your password, follow these steps:

1. Go to the login page at https://app.yourcompany.com/login
2. Click "Forgot Password?" below the login button
3. Enter your email address
4. Check your email for a password reset link (arrives within 2 minutes)
5. Click the link and create a new password
6. Password must be at least 12 characters with uppercase, lowercase, and numbers

If you don't receive the email within 5 minutes:
- Check your spam/junk folder
- Verify the email address is correct
- Contact support@yourcompany.com for assistance

Is there anything else I can help you with?

Response Time: 2.3s
Tokens Used: 156
Cost: $0.0047
```

**That's it!** You've built your first AI agent with:
- ✅ Automatic LLM routing (AxonFlow picks the best model)
- ✅ Built-in governance (rate limits, policies, cost tracking)
- ✅ Production-ready infrastructure (high availability, monitoring)
- ✅ Audit trails (every query logged for compliance)

### Step 5: Customize Your Agent (2 minutes)

Let's make the agent smarter by connecting it to your knowledge base:

```go
// Add RAG (Retrieval-Augmented Generation)
response, err := client.ExecuteQuery(ctx, axonflow.QueryRequest{
    Query: "How do I reset my password?",
    Context: map[string]interface{}{
        "customer_id": "cust_12345",
        "product":     "SaaS Platform",
        "intent":      "support",

        // NEW: Add knowledge base context
        "knowledge_sources": []string{
            "postgresql://docs_db/support_articles",  // Your FAQ database
            "s3://company-docs/help-center/",         // Your help center docs
        },

        // NEW: Add custom instructions
        "system_prompt": "You are a helpful customer support agent for Acme Corp. " +
                        "Always be friendly, concise, and provide specific steps. " +
                        "If you don't know the answer, direct customers to support@acme.com.",
    },
})
```

**AxonFlow will automatically:**
1. Query your knowledge sources for relevant information
2. Combine query + context + knowledge into a prompt
3. Route to the best LLM model for your use case
4. Return a contextually-aware response

---

## Understanding the Architecture

### How AxonFlow Works

```
┌─────────────────┐
│  Your App       │  (Go, Python, JS, etc.)
└────────┬────────┘
         │
         │ 1. ExecuteQuery(query, context)
         ▼
┌─────────────────────────┐
│  AxonFlow Agent         │  (Your VPC)
│  - License validation   │
│  - Policy enforcement   │
│  - Rate limiting        │
└────────┬────────────────┘
         │
         │ 2. Routed query with governance
         ▼
┌─────────────────────────┐
│  AxonFlow Orchestrator  │  (Your VPC)
│  - LLM routing          │
│  - Knowledge retrieval  │
│  - Multi-step reasoning │
└────────┬────────────────┘
         │
         │ 3. API calls (multiple if needed)
         ▼
┌─────────────────────────┐
│  LLM Providers          │  (External APIs)
│  - OpenAI (GPT-4)       │
│  - Anthropic (Claude)   │
│  - AWS Bedrock          │
│  - Azure OpenAI         │
└─────────────────────────┘
```

**Key Components:**

1. **Agent** - Entry point for your queries
   - License key validation
   - Policy enforcement (who can query what)
   - Rate limiting (prevent abuse)
   - Audit logging (every query tracked)

2. **Orchestrator** - Brain of the system
   - Picks the best LLM model for your query
   - Retrieves knowledge from your data sources
   - Handles multi-step reasoning (agents calling agents)
   - Caches responses for performance

3. **MCP Connectors** (Model Context Protocol)
   - Connect to your data: PostgreSQL, MySQL, S3, APIs
   - Query connectors from LLMs using natural language
   - Example: "Show me sales data for Q3" → PostgreSQL query

4. **Customer Portal** (Optional)
   - Web UI for managing agents, policies, and usage
   - Real-time dashboards (queries/sec, costs, errors)
   - User management (invite team members)

### Data Flow Example

**Query:** "What were our top 3 customers last quarter?"

1. **Your App** → Agent
   ```go
   client.ExecuteQuery(ctx, "What were our top 3 customers last quarter?")
   ```

2. **Agent** validates license, checks policies, applies rate limits

3. **Orchestrator** decides:
   - "This needs data from PostgreSQL"
   - Calls MCP connector: `mcp:postgresql:query`
   - SQL executed: `SELECT customer_name, SUM(revenue) FROM sales WHERE quarter='Q3-2025' GROUP BY customer_name ORDER BY SUM(revenue) DESC LIMIT 3`

4. **LLM** (GPT-4) receives:
   - Original query: "What were our top 3 customers last quarter?"
   - SQL results: `[{customer: "Acme Corp", revenue: $1.2M}, ...]`
   - Generates natural language response

5. **Response** returned to your app:
   ```
   Your top 3 customers last quarter were:

   1. Acme Corp - $1.2M in revenue
   2. TechStart Inc - $980K in revenue
   3. Global Solutions - $750K in revenue

   These three customers accounted for 42% of your Q3 revenue.
   ```

**Total time:** 2-3 seconds (database query + LLM generation)

---

## Next Steps

### 1. Connect Your Data Sources

AxonFlow supports multiple data connectors out of the box:

**Databases:**
- PostgreSQL
- MySQL
- Snowflake
- BigQuery
- Redshift

**APIs:**
- Salesforce (CRM data)
- Slack (messages, channels)
- Jira (issues, projects)
- Custom REST APIs

**File Storage:**
- AWS S3
- Google Cloud Storage
- Azure Blob Storage

**Example: Connect PostgreSQL**

```bash
# Add PostgreSQL connector to your .env
POSTGRESQL_URL=postgresql://user:pass@host:5432/dbname

# Restart agent to load connector
docker-compose restart agent
```

Now you can query your database with natural language:
```go
response, err := client.ExecuteQuery(ctx, axonflow.QueryRequest{
    Query: "How many users signed up last week?",
    Context: map[string]interface{}{
        "mcp_connector": "postgresql",
        "database":      "production",
    },
})
```

### 2. Define Custom Agents

Instead of one-off queries, define reusable agents with specific behaviors:

Create `agents/customer-support.yaml`:
```yaml
name: customer-support-agent
description: Handles customer support questions for Acme Corp

# Allowed operations
permissions:
  - mcp:postgresql:query  # Read customer data
  - mcp:salesforce:read   # Read CRM data
  - llm:gpt4:query        # Use GPT-4 for responses

# System instructions
system_prompt: |
  You are a helpful customer support agent for Acme Corp.

  Guidelines:
  - Always be friendly and empathetic
  - Provide specific steps, not generic advice
  - If you need to look up customer data, use the PostgreSQL connector
  - If the issue requires human support, escalate to support@acme.com
  - Never share sensitive data (passwords, credit cards, SSNs)

# Knowledge sources
knowledge_sources:
  - postgresql://production/support_articles
  - s3://acme-docs/help-center/
  - https://docs.acme.com/api/knowledge-base

# Rate limits
rate_limits:
  requests_per_minute: 60
  requests_per_hour: 1000
  cost_per_day_usd: 50.00

# Response settings
response:
  max_tokens: 500
  temperature: 0.7
  model: gpt-4-turbo
```

Load your agent:
```go
agent, err := client.LoadAgent("customer-support")

response, err := agent.Query(ctx, "How do I reset my password?")
```

**See full guide:** [Agent Definition Reference](./agent-definition.md)

### 3. Deploy to Production

When you're ready to go live:

```bash
# 1. Deploy via AWS Marketplace CloudFormation (recommended)
# See "Option 1: AWS Marketplace" above

# 2. Configure your domain
# - Point your DNS to the ALB URL
# - SSL certificate automatically generated via Let's Encrypt

# 3. Set up monitoring
# - CloudWatch dashboards created automatically
# - Optional: Grafana for advanced metrics
# - Optional: Datadog/New Relic integration

# 4. Configure backups
# - RDS automated backups (7-day retention)
# - Optional: Cross-region replication

# 5. Test load
bash scripts/load-testing/run-load-test.sh --target production --duration 10m
```

**Production checklist:**
- ✅ High Availability (Multi-AZ RDS + multiple agents)
- ✅ SSL/TLS (Let's Encrypt automatic renewal)
- ✅ Monitoring (CloudWatch + optional Grafana)
- ✅ Backups (RDS automated, 7-day retention)
- ✅ Rate Limiting (per-tenant, per-API key)
- ✅ Audit Logging (90-day retention in CloudWatch)
- ✅ Cost Tracking (AWS Marketplace metering)

### 4. Explore Example Applications

AxonFlow includes 3 complete example applications:

**1. Healthcare AI Assistant** (`examples/healthcare/`)
- HIPAA-compliant patient data queries
- Integration with Epic/Cerner EHR systems
- Natural language medication lookup
- Appointment scheduling

**2. E-commerce Recommendation Engine** (`examples/ecommerce/`)
- Product recommendations based on browsing history
- Inventory queries ("Do you have size M in blue?")
- Order tracking ("Where is my order?")
- Returns and refunds automation

**3. Trip Planning Assistant** (`examples/travel/`)
- Flight and hotel search (Amadeus API)
- Multi-city itinerary planning
- Budget optimization
- Real-time booking integration

**Run examples:**
```bash
# Healthcare
cd examples/healthcare
docker-compose up -d
open http://localhost:3000

# E-commerce
cd examples/ecommerce
docker-compose up -d
open http://localhost:3001

# Travel
cd examples/travel
docker-compose up -d
open http://localhost:3002
```

Each example includes:
- Complete source code (Go backend + React frontend)
- Docker Compose setup
- Sample data and test cases
- Production deployment guide

---

## Troubleshooting

### Common Issues

#### 1. "License key invalid" error

**Problem:** Agent rejects your license key.

**Solution:**
```bash
# Verify your license key format
echo $AXONFLOW_LICENSE_KEY
# Should be: AXON-PLUS-org-20261231-signature

# Regenerate if needed
docker exec -it axonflow-agent /app/keygen \
  --tier PLUS \
  --org my-company \
  --expires-at 20261231
```

#### 2. "Connection refused" when calling agent

**Problem:** Agent not reachable on port 8081.

**Solution:**
```bash
# Check if agent is running
docker ps | grep axonflow-agent

# If not running, check logs
docker-compose logs agent

# Common issues:
# - Database not ready (wait 30 seconds and retry)
# - Port 8081 already in use (change in docker-compose.yml)
# - Firewall blocking port (add firewall rule)
```

#### 3. "Database connection failed"

**Problem:** Agent can't connect to PostgreSQL.

**Solution:**
```bash
# Check database is running
docker ps | grep postgres

# Test connection manually
docker exec -it axonflow-db psql -U axonflow -d axonflow

# If connection fails:
# 1. Check DATABASE_URL in .env
# 2. Verify credentials
# 3. Restart database: docker-compose restart db
```

#### 4. "Rate limit exceeded"

**Problem:** Too many requests in short time.

**Solution:**
```bash
# Check your rate limits
curl -H "Authorization: Bearer $AXONFLOW_LICENSE_KEY" \
  https://your-agent-url/health

# Response includes rate limit info:
# {
#   "status": "healthy",
#   "rate_limits": {
#     "requests_per_minute": 60,
#     "requests_per_hour": 1000,
#     "current_usage": 45
#   }
# }

# To increase limits:
# 1. Upgrade tier (PLUS → ENTERPRISE)
# 2. Or contact sales@getaxonflow.com for custom limits
```

#### 5. High costs / unexpected billing

**Problem:** AWS Marketplace bill higher than expected.

**Solution:**
```bash
# Check current node count
aws ecs describe-service \
  --cluster axonflow \
  --service axonflow-agent-service \
  --query 'service.desiredCount'

# View usage this month
# See: docs/MARKETPLACE_METERING_FAQ.md

# Reduce costs:
# 1. Scale down nodes during off-hours
# 2. Use Professional tier ($0.10/hr) instead of Enterprise
# 3. Set max nodes in CloudFormation template
```

### Getting Help

**Documentation:**
- Technical Docs: `technical-docs/`
- API Reference: `docs/api-reference.md`
- Agent Definition: `docs/agent-definition.md`
- Marketplace FAQ: `docs/MARKETPLACE_METERING_FAQ.md`

**Community:**
- Slack: https://getaxonflow.com/slack
- GitHub Issues: https://github.com/getaxonflow/axonflow/issues
- Email Support: support@getaxonflow.com (< 24hr response)

**Sales & Enterprise:**
- Enterprise inquiries: sales@getaxonflow.com
- Custom pricing: Contact sales for volume discounts
- Phone: +1 (555) 123-4567

---

## What's Next?

You've built your first AI agent with AxonFlow! Here's what to explore next:

1. **[Agent Definition Guide](./agent-definition.md)** - Define custom agents with YAML
2. **[API Reference](./api-reference.md)** - Complete SDK documentation
3. **[Example Applications](../examples/)** - Healthcare, E-commerce, Trip Planning
4. **[Production Deployment](../technical-docs/DEPLOYMENT_GUIDE.md)** - Deploy to AWS
5. **[MCP Connectors](../technical-docs/MCP_CONNECTORS.md)** - Connect to your data sources

**Questions?** Join our Slack community: https://getaxonflow.com/slack

**Ready to deploy?** Subscribe on AWS Marketplace: https://aws.amazon.com/marketplace/pp/B0XXXXXX

---

*Last Updated: November 11, 2025*
*Version: 1.0.0*
