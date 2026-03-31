# Getting Started with AxonFlow

**Last Updated: March 2026** | **Platform: v5.4.1** | **SDKs: Python v5.3.0, Go/TypeScript/Java v4.3.0**

**Get AxonFlow running locally in about 10 minutes.**

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

AxonFlow is the **execution authority and system of record for AI decisions in production workflows**. It sits in the execution path between your application logic and LLM or tool calls.

It helps you:

- ✅ Deploy production-ready AI agents with built-in governance
- ✅ Connect to your data sources (databases, APIs, file systems)
- ✅ Route requests to the right LLM models (GPT-4, Claude, Bedrock, etc.)
- ✅ Enforce policies, rate limits, and permissions automatically
- ✅ Monitor usage, costs, and performance in real-time

Logs can tell you that a call happened. AxonFlow records why a step was allowed, blocked, paused, or resumed.

**AxonFlow is not a workflow engine.** Your code or orchestrator still decides what to do next. AxonFlow enforces execution policy and records the decision at runtime.

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
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f agent
```

**Access locally:**
- Agent API: http://localhost:8080 (Single Entry Point)
- Customer Portal: http://localhost:8090
- Database: localhost:5432

---

## Your First Agent (10 Minutes)

Let's build a **Customer Support Agent** that answers questions about your product using RAG (Retrieval-Augmented Generation).

### Step 1: Choose Your Tier (2 minutes)

AxonFlow offers three licensing tiers:

| Tier | License | Policies | Connectors with Custom Policies | Best For |
|------|---------|----------|---------------------------|----------|
| **Community** | None needed | 20 | 2 | Development, evaluation |
| **Evaluation** | Free | 50 | 5 | Small teams, production |
| **Enterprise** | Paid | Unlimited | Unlimited | Large organizations |

All connectors can be registered in all tiers. Connectors with custom policies are those with tenant-level policies (rate limiting, budgets, time/role access).

**For most users, start with Community** - no license needed!

**Ready for production?** Get a free Evaluation license at: https://getaxonflow.com/evaluation-license

**Need Enterprise features?** Contact sales@getaxonflow.com

If you have an Evaluation or Enterprise license, set it:

```bash
# Set your license key (optional - not needed for Community tier)
export AXONFLOW_LICENSE_KEY="AXON-V2-eyJ0aWVyIjoiRVZBTC...}-8d084b59"
```

### Step 2: Install the AxonFlow SDK (2 minutes)

Choose your language:

**Go:**
```bash
go get github.com/getaxonflow/axonflow-sdk-go/v4
```

**Python:**
```bash
pip install axonflow-sdk
```

**Java:**
```xml
<dependency>
    <groupId>com.getaxonflow</groupId>
    <artifactId>axonflow-sdk</artifactId>
    <version>3.5.0</version>
</dependency>
```

**TypeScript:**
```bash
npm install @axonflow/sdk
```

### Step 3: Write Your First Agent (3 minutes)

Choose your language below. All four SDKs are fully supported at v4.2.0.

#### Go

Create `customer-support-agent.go`:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    axonflow "github.com/getaxonflow/axonflow-sdk-go/v4"
)

func main() {
    // Initialize AxonFlow client
    client := axonflow.NewClient(axonflow.AxonFlowConfig{
        Endpoint:     "https://your-axonflow.example.com",      // From CloudFormation or localhost:8080
        ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),          // Your organization ID
        ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),      // License key
    })

    // Define your query
    query := "How do I reset my password?"
    userToken := "cust_12345"
    requestType := "support"
    queryContext := map[string]interface{}{
        "product": "SaaS Platform",
    }

    // Execute query through AxonFlow
    ctx := context.Background()
    response, err := client.ProxyLLMCall(ctx, userToken, query, requestType, queryContext)
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

#### Python

Create `customer_support_agent.py`:

```python
import os
from axonflow import AxonFlow

# Initialize AxonFlow client
client = AxonFlow(
    endpoint="https://your-axonflow.example.com",       # From CloudFormation or localhost:8080
    client_id=os.environ["AXONFLOW_CLIENT_ID"],         # Your organization ID
    client_secret=os.environ["AXONFLOW_CLIENT_SECRET"], # License key
)

# Execute query through AxonFlow
query = "How do I reset my password?"
response = client.proxy_llm_call(
    user_token="cust_12345",
    query=query,
    request_type="support",
    context={"product": "SaaS Platform"},
)

# Print the AI response
print(f"Customer Question: {query}\n")
print(f"AI Response:\n{response.result}")
print(f"\nResponse Time: {response.metadata.duration:.2f}s")
print(f"Tokens Used: {response.metadata.tokens_used}")
print(f"Cost: ${response.metadata.cost:.4f}")
```

#### TypeScript

Create `customer-support-agent.ts`:

```typescript
import { AxonFlow } from "@axonflow/sdk";

// Initialize AxonFlow client
const client = new AxonFlow({
  endpoint: "https://your-axonflow.example.com",        // From CloudFormation or localhost:8080
  clientId: process.env.AXONFLOW_CLIENT_ID!,            // Your organization ID
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET!,    // License key
});

// Execute query through AxonFlow
const query = "How do I reset my password?";
const response = await client.proxyLLMCall({
  query,
  userToken: "cust_12345",
  requestType: "support",
  context: { product: "SaaS Platform" },
});

// Print the AI response
console.log(`Customer Question: ${query}\n`);
console.log(`AI Response:\n${response.result}`);
console.log(`\nResponse Time: ${response.metadata.duration.toFixed(2)}s`);
console.log(`Tokens Used: ${response.metadata.tokensUsed}`);
console.log(`Cost: $${response.metadata.cost.toFixed(4)}`);
```

#### Java

Create `CustomerSupportAgent.java`:

```java
import com.getaxonflow.sdk.AxonFlowClient;

public class CustomerSupportAgent {
    public static void main(String[] args) {
        // Initialize AxonFlow client
        var client = AxonFlowClient.builder()
            .endpoint("https://your-axonflow.example.com")  // From CloudFormation or localhost:8080
            .clientId(System.getenv("AXONFLOW_CLIENT_ID"))
            .clientSecret(System.getenv("AXONFLOW_CLIENT_SECRET"))
            .build();

        // Execute query through AxonFlow
        String query = "How do I reset my password?";
        var response = client.proxyLlmCall(
            "cust_12345",   // userToken
            query,
            "support",      // requestType
            Map.of("product", "SaaS Platform")
        );

        // Print the AI response
        System.out.printf("Customer Question: %s%n%n", query);
        System.out.printf("AI Response:%n%s%n", response.getResult());
        System.out.printf("%nResponse Time: %.2fs%n", response.getMetadata().getDuration());
        System.out.printf("Tokens Used: %d%n", response.getMetadata().getTokensUsed());
        System.out.printf("Cost: $%.4f%n", response.getMetadata().getCost());
    }
}
```

### Step 4: Run Your Agent (1 minute)

```bash
# Set your OAuth2-style credentials
export AXONFLOW_CLIENT_ID="my-company"
export AXONFLOW_CLIENT_SECRET="AXON-PLUS-my-company-20261231-a7f3b2c9"  # Optional for community

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
query := "How do I reset my password?"
userToken := "cust_12345"
requestType := "support"
queryContext := map[string]interface{}{
    "product": "SaaS Platform",

    // NEW: Add knowledge base context
    "knowledge_sources": []string{
        "postgresql://docs_db/support_articles",  // Your FAQ database
        "s3://company-docs/help-center/",         // Your help center docs
    },

    // NEW: Add custom instructions
    "system_prompt": "You are a helpful customer support agent for Acme Corp. " +
                    "Always be friendly, concise, and provide specific steps. " +
                    "If you don't know the answer, direct customers to support@acme.com.",
}

response, err := client.ProxyLLMCall(ctx, userToken, query, requestType, queryContext)
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
         │ 1. ProxyLLMCall(token, query, type, ctx)
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
   - Client authentication (OAuth2-style credentials)
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
   client.ProxyLLMCall(ctx, userToken, "What were our top 3 customers last quarter?", "analytics", nil)
   ```

2. **Agent** validates credentials, checks policies, applies rate limits

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
docker compose restart agent
```

Now you can query your database with natural language:
```go
response, err := client.ProxyLLMCall(ctx, userToken, "How many users signed up last week?", "analytics",
    map[string]interface{}{
        "mcp_connector": "postgresql",
        "database":      "production",
    },
)
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
  model: gpt-4o
```

Load your agent:
```go
agent, err := client.LoadAgent("customer-support")

response, err := agent.Query(ctx, "How do I reset my password?")
```

**See full guide:** [Configurable Agents Reference](./reference/configurable-agents.md)

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

AxonFlow includes example applications covering common use cases. See the full list in [`examples/README.md`](../examples/README.md).

**Key examples:**

| Example | Description |
|---------|-------------|
| [`hello-world/`](../examples/hello-world/) | Basic SDK usage in Go, Python, TypeScript, and Java |
| [`llm-providers/`](../examples/llm-providers/) | LLM integration with OpenAI, Bedrock, Anthropic, Ollama |
| [`execution-tracking/`](../examples/execution-tracking/) | Workflow execution control and step ledger |
| [`mcp-connectors/`](../examples/mcp-connectors/) | Connect to Salesforce, Snowflake, and other data sources |
| [`pii-detection/`](../examples/pii-detection/) | PII detection and redaction |
| [`cost-controls/`](../examples/cost-controls/) | Budget management and usage tracking |

**Run the hello-world example:**
```bash
cd examples/hello-world/http
./example.sh
```

---

## Troubleshooting

### Common Issues

#### 1. "Authentication failed" error

**Problem:** Agent rejects your credentials.

**Solution:**
```bash
# Verify your credentials are set
echo $AXONFLOW_CLIENT_ID
# Should be: my-company (your organization identifier)

echo $AXONFLOW_LICENSE_KEY
# Should be: AXON-V2-... (optional for Community tier)

# Community tier: No license needed
# Evaluation tier: Get free license at https://getaxonflow.com/evaluation-license
# Enterprise tier: Contact sales@getaxonflow.com
```

#### 1b. "Policy limit exceeded" error

**Problem:** You've reached the policy limit for your tier.

**Tier Limits:**
| Tier | Tenant Policies | Org Policies | Connectors with Custom Policies |
|------|-----------------|--------------|---------------------------|
| Community | 20 | 0 | 2 |
| Evaluation | 50 | 5 | 5 |
| Enterprise | Unlimited | Unlimited | Unlimited |

**Solution:**
```bash
# Check your current tier
curl -H "Authorization: Basic $(echo -n $AXONFLOW_CLIENT_ID: | base64)" \
  http://localhost:8080/health

# Upgrade options:
# - Community → Evaluation (free): https://getaxonflow.com/evaluation-license
# - Evaluation → Enterprise: Contact sales@getaxonflow.com
```

#### 2. "Connection refused" when calling agent

**Problem:** Agent not reachable on port 8080.

**Solution:**
```bash
# Check if agent is running
docker ps | grep axonflow-agent

# If not running, check logs
docker compose logs agent

# Common issues:
# - Database not ready (wait 30 seconds and retry)
# - Port 8080 already in use (change in docker-compose.yml)
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
# 3. Restart database: docker compose restart db
```

#### 4. "Rate limit exceeded"

**Problem:** Too many requests in short time.

**Solution:**
```bash
# Check your rate limits
curl -H "Authorization: Basic $(echo -n $AXONFLOW_CLIENT_ID:$AXONFLOW_CLIENT_SECRET | base64)" \
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
# 1. Upgrade tier (Plus → Enterprise)
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
- API Reference: `docs/api/`
- Configurable Agents: `docs/reference/configurable-agents.md`
- SDK Documentation: `docs/sdk/README.md`

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

1. **[Configurable Agents Guide](./reference/configurable-agents.md)** - Configure agent behavior and routing
2. **[API Reference](./api/)** - API specifications and error codes
3. **[Example Applications](../examples/)** - Healthcare, E-commerce, Trip Planning
4. **[Production Deployment](../technical-docs/DEPLOYMENT_GUIDE.md)** - Deploy to AWS
5. **[MCP Connectors](../technical-docs/MCP_CONNECTORS.md)** - Connect to your data sources

**Questions?** Join our Slack community: https://getaxonflow.com/slack

**Ready to deploy?** Subscribe on AWS Marketplace: https://aws.amazon.com/marketplace/pp/B0XXXXXX

---

*Last Updated: March 2026*
*Platform Version: v5.0.0 | SDK Version: v4.2.0*
