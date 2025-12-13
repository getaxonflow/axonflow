# Agent Definition Reference

**Define custom AI agents using YAML configuration** - No code required.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Example](#quick-example)
3. [Agent Definition Format](#agent-definition-format)
4. [Configuration Reference](#configuration-reference)
5. [Advanced Features](#advanced-features)
6. [Best Practices](#best-practices)
7. [Examples](#examples)
8. [Troubleshooting](#troubleshooting)

---

## Overview

### What is an Agent Definition?

An **agent definition** is a YAML file that describes:

- **What** your agent does (purpose, capabilities)
- **Who** can use it (permissions, access control)
- **How** it behaves (system prompts, response settings)
- **Where** it gets data (knowledge sources, connectors)
- **When** to apply limits (rate limits, cost caps)

**Think of it as a "recipe" for your AI agent** - you define the ingredients (data sources, models, prompts), and AxonFlow handles the cooking (inference, governance, monitoring).

### Why Use Agent Definitions?

**Without Agent Definitions (code):**
```go
// Scattered configuration in code
client.ExecuteQuery(ctx, axonflow.QueryRequest{
    Query: "How do I reset my password?",
    Context: map[string]interface{}{
        "system_prompt": "You are a helpful support agent...",
        "model": "gpt-4-turbo",
        "temperature": 0.7,
        "max_tokens": 500,
        "knowledge_sources": []string{"postgresql://..."},
        // ... 50 more configuration options
    },
})
```

**With Agent Definitions (YAML):**
```go
// Clean, declarative configuration
agent, _ := client.LoadAgent("customer-support")
response, _ := agent.Query(ctx, "How do I reset my password?")
```

**Benefits:**
- ✅ **Declarative** - What you want, not how to get it
- ✅ **Reusable** - Define once, use everywhere
- ✅ **Version Controlled** - Track changes with Git
- ✅ **No Code Changes** - Update agent behavior without redeploying
- ✅ **Governance** - Centralized policies and permissions
- ✅ **Testable** - Validate configurations before deployment

---

## Quick Example

Let's create a **Customer Support Agent** in 5 minutes.

### Step 1: Create Agent Definition

Create `agents/customer-support.yaml`:

```yaml
# Agent identity
name: customer-support-agent
version: 1.0.0
description: Handles customer support questions for Acme Corp
owner: support-team@acme.com

# Who can use this agent
permissions:
  allowed_users:
    - support-team@acme.com
    - agents@acme.com
  allowed_roles:
    - support_agent
    - admin

  # What this agent can access
  mcp_connectors:
    - postgresql:read      # Read customer data
    - salesforce:read      # Read CRM data
    - slack:write          # Send Slack notifications

  llm_models:
    - gpt-4-turbo         # Primary model
    - claude-3-sonnet     # Fallback model

# How the agent behaves
behavior:
  system_prompt: |
    You are a helpful customer support agent for Acme Corp.

    Your responsibilities:
    - Answer customer questions accurately and empathetically
    - Look up customer data when needed (use PostgreSQL connector)
    - Escalate complex issues to human agents
    - Never share sensitive data (passwords, credit cards, SSNs)

    Guidelines:
    - Be friendly and professional
    - Provide specific steps, not generic advice
    - If you don't know, say "I don't know" and escalate
    - Always end with "Is there anything else I can help you with?"

  response:
    max_tokens: 500
    temperature: 0.7
    model: gpt-4-turbo
    fallback_model: claude-3-sonnet

  # Knowledge sources for RAG
  knowledge_sources:
    - postgresql://production/support_articles
    - s3://acme-docs/help-center/
    - https://docs.acme.com/api/knowledge-base

# Rate limits and cost controls
limits:
  rate_limits:
    requests_per_minute: 60
    requests_per_hour: 1000
    requests_per_day: 10000

  cost_controls:
    max_cost_per_query_usd: 0.50
    max_cost_per_day_usd: 50.00
    max_cost_per_month_usd: 1500.00

# Monitoring and alerting
monitoring:
  log_level: info
  alert_on_error: true
  alert_channels:
    - slack://support-alerts
    - email://support-team@acme.com

  metrics:
    track_response_time: true
    track_token_usage: true
    track_cost: true
    track_user_satisfaction: true

# Metadata
metadata:
  created_at: "2025-11-11T10:00:00Z"
  updated_at: "2025-11-11T10:00:00Z"
  tags:
    - customer-support
    - production
    - gpt-4
```

### Step 2: Validate Your Agent

```bash
# Validate agent definition syntax
axonflow agent validate agents/customer-support.yaml

# Expected output:
# ✅ Agent definition is valid
# ✅ All required fields present
# ✅ Permissions are valid
# ✅ Knowledge sources are reachable
# ✅ Rate limits are reasonable
```

### Step 3: Deploy Your Agent

```bash
# Deploy to production
axonflow agent deploy agents/customer-support.yaml --env production

# Expected output:
# ✅ Agent deployed: customer-support-agent
# ✅ Version: 1.0.0
# ✅ URL: https://api.acme.com/agents/customer-support-agent
# ✅ Health check: PASSING
```

### Step 4: Use Your Agent

```go
package main

import (
    "context"
    "fmt"
    axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
    client := axonflow.NewClient(axonflow.Config{
        BaseURL:    "https://api.acme.com",
        LicenseKey: "AXON-PLUS-acme-20261231-abc123",
    })

    // Load your agent
    agent, err := client.LoadAgent("customer-support-agent")
    if err != nil {
        panic(err)
    }

    // Query your agent
    ctx := context.Background()
    response, err := agent.Query(ctx, "How do I reset my password?")
    if err != nil {
        panic(err)
    }

    fmt.Println(response.Result)
}
```

**That's it!** Your agent is live with:
- ✅ Authentication (license key)
- ✅ Authorization (allowed users/roles)
- ✅ Rate limiting (60/min, 1000/hr)
- ✅ Cost controls ($50/day cap)
- ✅ Knowledge retrieval (3 sources)
- ✅ Monitoring (Slack + email alerts)

---

## Agent Definition Format

### File Structure

Every agent definition follows this structure:

```yaml
# IDENTITY - Who is this agent?
name: string (required)
version: string (required, semver)
description: string (required)
owner: string (required, email)

# PERMISSIONS - Who can use this agent and what can it access?
permissions:
  allowed_users: []string
  allowed_roles: []string
  mcp_connectors: []string
  llm_models: []string

# BEHAVIOR - How does this agent act?
behavior:
  system_prompt: string (required)
  response: object
  knowledge_sources: []string
  tools: []object

# LIMITS - What are the guardrails?
limits:
  rate_limits: object
  cost_controls: object

# MONITORING - How do we track this agent?
monitoring:
  log_level: string
  alert_on_error: bool
  alert_channels: []string
  metrics: object

# METADATA - Additional information
metadata:
  created_at: string (ISO 8601)
  updated_at: string (ISO 8601)
  tags: []string
```

### Naming Conventions

**Agent Names:**
- Use lowercase with hyphens: `customer-support-agent`
- Be descriptive: `healthcare-ehr-assistant` not `agent1`
- Include purpose: `order-tracking-bot`

**File Names:**
- Match agent name: `customer-support-agent.yaml`
- Store in `agents/` directory
- Use Git for version control

**Versions:**
- Follow semantic versioning: `1.0.0`, `1.2.3`, `2.0.0`
- Increment major version for breaking changes
- Increment minor version for new features
- Increment patch version for bug fixes

---

## Configuration Reference

### 1. Identity Section

```yaml
name: customer-support-agent
version: 1.0.0
description: Handles customer support questions for Acme Corp
owner: support-team@acme.com
```

**Fields:**
- `name` (required) - Unique identifier for your agent
  - Must be lowercase with hyphens
  - Example: `customer-support-agent`, `order-tracking-bot`

- `version` (required) - Semantic version
  - Format: `MAJOR.MINOR.PATCH`
  - Example: `1.0.0`, `2.1.3`

- `description` (required) - One-sentence description
  - Shown in UI and documentation
  - Keep under 100 characters

- `owner` (required) - Email of responsible team/person
  - Used for alerts and notifications
  - Must be valid email format

### 2. Permissions Section

```yaml
permissions:
  # Who can use this agent
  allowed_users:
    - support-team@acme.com
    - agents@acme.com
    - "*@acme.com"  # Wildcard: all Acme Corp users

  allowed_roles:
    - support_agent
    - admin
    - power_user

  # What this agent can access
  mcp_connectors:
    - postgresql:read           # Read-only database access
    - postgresql:write          # Write access
    - salesforce:read           # Read CRM data
    - salesforce:write          # Update CRM data
    - slack:write               # Send Slack messages
    - s3:read                   # Read S3 files
    - amadeus:search_flights    # Search flights (Amadeus API)

  llm_models:
    - gpt-4-turbo              # OpenAI GPT-4 Turbo
    - gpt-4                    # OpenAI GPT-4
    - claude-3-opus            # Anthropic Claude 3 Opus
    - claude-3-sonnet          # Anthropic Claude 3 Sonnet
    - bedrock:claude-v2        # AWS Bedrock Claude v2
```

**Permission Levels:**

| Level | Description | Example |
|-------|-------------|---------|
| `read` | View data only | `postgresql:read` |
| `write` | Create/update data | `postgresql:write` |
| `delete` | Remove data | `postgresql:delete` |
| `admin` | Full access | `postgresql:admin` |
| `*` | All operations | `postgresql:*` |

**Wildcard Support:**
```yaml
allowed_users:
  - "*@acme.com"              # All users in acme.com domain
  - "eng-*@acme.com"          # All engineering emails
  - "support*@acme.com"       # All support emails

mcp_connectors:
  - "postgresql:*"            # All PostgreSQL operations
  - "salesforce:*"            # All Salesforce operations
  - "mcp:*"                   # All MCP connectors (dangerous!)
```

### 3. Behavior Section

```yaml
behavior:
  # System prompt (instructions for the LLM)
  system_prompt: |
    You are a helpful customer support agent for Acme Corp.

    Your responsibilities:
    - Answer customer questions accurately and empathetically
    - Look up customer data when needed
    - Escalate complex issues to human agents
    - Never share sensitive data

    Guidelines:
    - Be friendly and professional
    - Provide specific steps, not generic advice
    - If you don't know, say "I don't know"
    - Always end with "Is there anything else I can help you with?"

  # Response settings
  response:
    model: gpt-4-turbo
    fallback_model: claude-3-sonnet
    max_tokens: 500
    temperature: 0.7
    top_p: 0.9
    frequency_penalty: 0.0
    presence_penalty: 0.0
    stop_sequences: ["END", "STOP"]

  # Knowledge sources for RAG (Retrieval-Augmented Generation)
  knowledge_sources:
    # Database tables
    - postgresql://production/support_articles
    - postgresql://production/customer_data

    # File storage
    - s3://acme-docs/help-center/
    - s3://acme-docs/product-manuals/

    # Web APIs
    - https://docs.acme.com/api/knowledge-base
    - https://status.acme.com/api/incidents

  # Tools the agent can call
  tools:
    - name: escalate_to_human
      description: Escalate issue to human support agent
      connector: slack
      action: send_message
      parameters:
        channel: "#support-escalations"
        template: "Customer {{customer_id}} needs help: {{issue}}"

    - name: create_ticket
      description: Create Jira ticket for bug reports
      connector: jira
      action: create_issue
      parameters:
        project: "SUPPORT"
        issue_type: "Bug"

    - name: check_order_status
      description: Look up order status in database
      connector: postgresql
      action: query
      parameters:
        database: "production"
        table: "orders"
```

**Response Settings Explained:**

- `model` - Primary LLM model to use
  - Options: `gpt-4-turbo`, `gpt-4`, `claude-3-opus`, `claude-3-sonnet`, `bedrock:claude-v2`
  - Default: `gpt-4-turbo`

- `fallback_model` - Use if primary model fails
  - Ensures high availability
  - Example: If GPT-4 is down, use Claude

- `max_tokens` - Maximum response length
  - Range: 1 to 4096 (GPT-4), 1 to 100000 (Claude)
  - Recommend: 500 for support, 2000 for long-form

- `temperature` - Creativity vs consistency
  - Range: 0.0 to 2.0
  - 0.0 = Deterministic (same input = same output)
  - 0.7 = Balanced (default)
  - 1.5 = Creative (varies widely)

- `top_p` - Nucleus sampling
  - Range: 0.0 to 1.0
  - 0.9 = Consider top 90% probable tokens
  - Lower = More focused, Higher = More diverse

- `frequency_penalty` - Reduce repetition
  - Range: 0.0 to 2.0
  - 0.0 = No penalty (default)
  - 1.0 = Moderate penalty
  - 2.0 = Strong penalty (avoid repeated words)

- `presence_penalty` - Encourage new topics
  - Range: 0.0 to 2.0
  - 0.0 = No penalty (default)
  - 1.0 = Moderate penalty
  - 2.0 = Strong penalty (favor new topics)

### 4. Limits Section

```yaml
limits:
  # Rate limits (prevent abuse)
  rate_limits:
    requests_per_minute: 60
    requests_per_hour: 1000
    requests_per_day: 10000
    concurrent_requests: 10

  # Cost controls (prevent budget overruns)
  cost_controls:
    max_cost_per_query_usd: 0.50
    max_cost_per_day_usd: 50.00
    max_cost_per_month_usd: 1500.00
    alert_threshold_usd: 40.00   # Alert when reaching 80% of daily limit

  # Timeout controls
  timeouts:
    query_timeout_seconds: 30
    tool_call_timeout_seconds: 10
    total_timeout_seconds: 60
```

**Why Rate Limits Matter:**

**Without rate limits:**
```
User makes 10,000 requests in 1 minute
↓
LLM API costs: $500 (10,000 × $0.05/query)
↓
Monthly bill: $15,000 for a single user!
```

**With rate limits:**
```
User makes 10,000 requests in 1 minute
↓
First 60 accepted, rest rejected (60/minute limit)
↓
LLM API costs: $3 (60 × $0.05/query)
↓
User gets clear error: "Rate limit exceeded. Try again in 60 seconds."
```

**Recommended Limits by Use Case:**

| Use Case | Requests/Min | Requests/Day | Max Cost/Day |
|----------|--------------|--------------|--------------|
| **Internal Tools** | 60 | 10,000 | $50 |
| **Customer Support** | 100 | 50,000 | $250 |
| **Public API** | 10 | 1,000 | $10 |
| **Batch Processing** | 600 | 500,000 | $2,500 |

### 5. Monitoring Section

```yaml
monitoring:
  # Logging
  log_level: info   # debug, info, warning, error, critical
  log_retention_days: 90

  # Alerting
  alert_on_error: true
  alert_on_slow_response: true
  slow_response_threshold_seconds: 5

  alert_channels:
    - slack://support-alerts
    - email://support-team@acme.com
    - pagerduty://on-call

  # Metrics to track
  metrics:
    track_response_time: true
    track_token_usage: true
    track_cost: true
    track_user_satisfaction: true
    track_error_rate: true

  # Custom dashboards
  dashboards:
    - grafana://customer-support-metrics
    - datadog://agent-performance
```

**Alert Examples:**

**Slack Alert (Error):**
```
🚨 Agent Error: customer-support-agent

Error: Rate limit exceeded on OpenAI API
User: support-agent-001@acme.com
Time: 2025-11-11 10:23:45 UTC
Query: "Show me all orders for customer ABC123"

Action Required: Check OpenAI API status or increase rate limits
```

**Email Alert (Slow Response):**
```
Subject: ⚠️  Slow Response Detected: customer-support-agent

Agent: customer-support-agent
Response Time: 12.3 seconds (threshold: 5 seconds)
User: support-agent-002@acme.com
Query: "Search for all customers in California with orders > $1000"

Possible Causes:
- Large database query
- High LLM API latency
- Network congestion

Recommendation: Review query complexity or add database indexes
```

### 6. Metadata Section

```yaml
metadata:
  created_at: "2025-11-11T10:00:00Z"
  updated_at: "2025-11-11T14:30:00Z"
  created_by: john.doe@acme.com

  # Tags for organization
  tags:
    - customer-support
    - production
    - gpt-4
    - high-priority

  # Custom fields
  custom:
    department: Customer Success
    cost_center: CS-001
    compliance: HIPAA, SOC2
    sla_tier: platinum
```

---

## Advanced Features

### 1. Multi-Step Workflows

Define agents that perform multi-step tasks:

```yaml
name: order-processing-agent
behavior:
  workflow:
    - step: validate_order
      description: Check if order is valid
      connector: postgresql
      query: "SELECT * FROM orders WHERE order_id = {{order_id}}"
      conditions:
        - field: status
          operator: equals
          value: "pending"
      on_failure: reject_order

    - step: check_inventory
      description: Verify items are in stock
      connector: postgresql
      query: "SELECT stock FROM inventory WHERE sku = {{sku}}"
      conditions:
        - field: stock
          operator: greater_than
          value: 0
      on_failure: notify_out_of_stock

    - step: charge_payment
      description: Process payment
      connector: stripe
      action: create_charge
      parameters:
        amount: "{{order_total}}"
        currency: "usd"
        customer: "{{customer_id}}"
      on_failure: refund_and_notify

    - step: update_order_status
      description: Mark order as processed
      connector: postgresql
      query: "UPDATE orders SET status = 'processed' WHERE order_id = {{order_id}}"

    - step: send_confirmation
      description: Email customer
      connector: sendgrid
      action: send_email
      parameters:
        to: "{{customer_email}}"
        template: "order_confirmation"
        data:
          order_id: "{{order_id}}"
          items: "{{order_items}}"
```

### 2. Conditional Routing

Route queries to different models based on complexity:

```yaml
name: smart-routing-agent
behavior:
  routing:
    - condition:
        query_complexity: simple
        max_tokens: 100
      route_to: gpt-3.5-turbo
      reason: "Fast and cheap for simple queries"

    - condition:
        query_complexity: medium
        max_tokens: 500
      route_to: gpt-4-turbo
      reason: "Balanced performance for medium queries"

    - condition:
        query_complexity: complex
        requires_reasoning: true
      route_to: claude-3-opus
      reason: "Best reasoning for complex queries"

    - condition:
        query_type: code_generation
      route_to: gpt-4-turbo
      reason: "Best for code generation"

    - condition:
        query_type: creative_writing
      route_to: claude-3-opus
      reason: "Best for creative tasks"
```

### 3. Caching and Performance

Optimize response times with caching:

```yaml
name: high-performance-agent
behavior:
  caching:
    enabled: true
    ttl_seconds: 3600  # Cache for 1 hour
    cache_key_fields:
      - query
      - user_id
      - context.product_id

    # Cache only certain types of queries
    cache_conditions:
      - query_type: faq
      - query_type: documentation_lookup

    # Don't cache sensitive queries
    exclude_patterns:
      - contains: password
      - contains: credit_card
      - contains: ssn
```

### 4. A/B Testing

Test different prompts or models:

```yaml
name: ab-test-agent
behavior:
  experiments:
    - name: prompt_comparison
      enabled: true
      traffic_split:
        variant_a: 50%  # Original prompt
        variant_b: 50%  # New prompt

      variant_a:
        system_prompt: "You are a helpful assistant."
        model: gpt-4-turbo

      variant_b:
        system_prompt: "You are an expert support agent with 10 years of experience."
        model: claude-3-opus

      metrics:
        - user_satisfaction
        - response_time
        - cost_per_query

      duration_days: 7
      min_samples: 1000
```

### 5. Multi-Tenant Support

Define tenant-specific behavior:

```yaml
name: multi-tenant-agent
behavior:
  tenants:
    - tenant_id: acme-corp
      system_prompt: "You are Acme Corp's support agent."
      knowledge_sources:
        - postgresql://acme-corp-db/support_articles
      branding:
        company_name: "Acme Corp"
        support_email: "support@acme.com"

    - tenant_id: tech-start
      system_prompt: "You are TechStart's support agent."
      knowledge_sources:
        - postgresql://techstart-db/support_articles
      branding:
        company_name: "TechStart Inc"
        support_email: "help@techstart.io"
```

---

## Best Practices

### 1. System Prompt Guidelines

**DO:**
```yaml
system_prompt: |
  You are a customer support agent for Acme Corp.

  Your role:
  - Answer questions about our SaaS platform
  - Look up customer data when needed
  - Escalate complex issues to human agents

  Guidelines:
  - Be friendly and professional
  - Provide specific steps
  - If uncertain, say "I don't know" and escalate

  Examples:
  User: "How do I reset my password?"
  You: "To reset your password, follow these steps:
  1. Go to https://app.acme.com/login
  2. Click 'Forgot Password'
  3. Enter your email address
  4. Check your email for the reset link"
```

**DON'T:**
```yaml
system_prompt: "You are a helpful assistant."  # Too vague
system_prompt: "Answer questions."             # No context
system_prompt: "Be nice."                      # Not actionable
```

**Why Specific Prompts Matter:**

Bad prompt → Vague response:
```
User: "How do I reset my password?"
Agent: "You can reset your password through the settings page."
```

Good prompt → Actionable response:
```
User: "How do I reset my password?"
Agent: "To reset your password, follow these steps:
1. Go to https://app.acme.com/login
2. Click 'Forgot Password?' below the login button
3. Enter your email address
4. Check your email for a reset link (arrives within 2 minutes)
5. Click the link and create a new password (min 12 characters)"
```

### 2. Knowledge Source Organization

**Organize by type:**
```yaml
knowledge_sources:
  # Structured data (databases)
  databases:
    - postgresql://production/customers
    - postgresql://production/orders
    - postgresql://production/support_tickets

  # Unstructured data (documents)
  documents:
    - s3://company-docs/help-center/
    - s3://company-docs/product-manuals/
    - s3://company-docs/api-docs/

  # Real-time data (APIs)
  apis:
    - https://status.acme.com/api/incidents
    - https://docs.acme.com/api/knowledge-base
```

**Prioritize sources:**
```yaml
knowledge_sources:
  - source: postgresql://production/support_articles
    priority: 1  # Check first (most accurate)

  - source: s3://company-docs/help-center/
    priority: 2  # Check second (comprehensive)

  - source: https://docs.acme.com/api/knowledge-base
    priority: 3  # Check last (public docs)
```

### 3. Rate Limit Tuning

**Start conservative, then increase:**

**Week 1: Test limits**
```yaml
rate_limits:
  requests_per_minute: 10
  requests_per_day: 500
  max_cost_per_day_usd: 10.00
```

**Week 2: Measure actual usage**
```bash
# Check usage
axonflow metrics customer-support-agent --days 7

# Output:
# Average: 3 requests/minute (30% of limit)
# Peak: 8 requests/minute (80% of limit)
# Cost: $5/day (50% of limit)
```

**Week 3: Increase based on data**
```yaml
rate_limits:
  requests_per_minute: 20  # 2.5x peak usage
  requests_per_day: 2000   # 4x average
  max_cost_per_day_usd: 25.00  # 5x average
```

### 4. Error Handling

**Define fallback behavior:**
```yaml
behavior:
  error_handling:
    # If LLM fails
    on_llm_error:
      action: retry
      max_retries: 3
      backoff_seconds: [1, 2, 4]  # Exponential backoff
      fallback_response: "I'm experiencing technical difficulties. Please try again in a moment."

    # If knowledge source fails
    on_knowledge_source_error:
      action: skip
      fallback_to_general_knowledge: true

    # If rate limit exceeded
    on_rate_limit:
      response: "You've reached the rate limit. Please wait {{retry_after_seconds}} seconds."
      http_status: 429

    # If cost limit exceeded
    on_cost_limit:
      response: "Daily cost limit reached. Service will resume tomorrow."
      notify: [email://support-team@acme.com, slack://alerts]
```

### 5. Versioning Strategy

**Use semantic versioning:**

```yaml
# v1.0.0 - Initial release
name: customer-support-agent
version: 1.0.0
```

```yaml
# v1.1.0 - Added new knowledge source (backward compatible)
name: customer-support-agent
version: 1.1.0
behavior:
  knowledge_sources:
    - postgresql://production/support_articles  # Existing
    - s3://company-docs/help-center/            # NEW
```

```yaml
# v2.0.0 - Changed system prompt (breaking change)
name: customer-support-agent
version: 2.0.0
behavior:
  system_prompt: |
    # Completely new prompt format
    # Not compatible with v1.x
```

**Deployment strategy:**
```bash
# Deploy v2.0.0 alongside v1.0.0
axonflow agent deploy customer-support-agent-v2.yaml

# Route 10% traffic to v2.0.0 (canary deployment)
axonflow agent traffic customer-support-agent --v1: 90% --v2: 10%

# Monitor for 24 hours
axonflow metrics customer-support-agent --version 2.0.0 --days 1

# If metrics good, increase to 100%
axonflow agent traffic customer-support-agent --v1: 0% --v2: 100%

# Deprecate v1.0.0
axonflow agent deprecate customer-support-agent --version 1.0.0
```

---

## Examples

### Example 1: Customer Support Agent

**Use case:** Answer customer questions about a SaaS product

**Full definition:** [examples/customer-support-agent.yaml](../examples/agents/customer-support-agent.yaml)

**Highlights:**
- Uses GPT-4 for accurate responses
- Queries PostgreSQL for customer data
- Escalates to Slack for complex issues
- Rate limited: 60/min, 1000/hour
- Cost capped: $50/day

### Example 2: Order Tracking Agent

**Use case:** Let customers check order status via natural language

**Full definition:** [examples/order-tracking-agent.yaml](../examples/agents/order-tracking-agent.yaml)

**Highlights:**
- Multi-step workflow (validate order → check status → return info)
- Conditional logic (if order not found, suggest alternatives)
- Integrates with Stripe, Shippo, SendGrid
- Cost optimized: Uses GPT-3.5 for simple queries

### Example 3: Code Review Agent

**Use case:** Automated code review for pull requests

**Full definition:** [examples/code-review-agent.yaml](../examples/agents/code-review-agent.yaml)

**Highlights:**
- Specialized for code review tasks
- Checks for: bugs, security issues, performance problems
- Integrates with GitHub, Jira
- Uses Claude 3 Opus (best reasoning)
- Comments directly on pull requests

### Example 4: Healthcare EHR Agent (HIPAA-compliant)

**Use case:** Query electronic health records with natural language

**Full definition:** [examples/healthcare-ehr-agent.yaml](../examples/agents/healthcare-ehr-agent.yaml)

**Highlights:**
- HIPAA-compliant configuration
- Strict access controls (role-based)
- Audit logging (90-day retention)
- Integrates with Epic/Cerner APIs
- Cost capped: $200/day

---

## Troubleshooting

### Issue 1: "Permission denied" when deploying agent

**Error:**
```
❌ Permission denied: user john.doe@acme.com cannot deploy agent customer-support-agent
```

**Solution:**
```bash
# Check your user role
axonflow user info

# Add deploy permission
axonflow user grant --email john.doe@acme.com --permission deploy:agent

# Or add to deployment role
axonflow role add-member deployer john.doe@acme.com
```

### Issue 2: "Knowledge source unreachable"

**Error:**
```
❌ Knowledge source unreachable: postgresql://production/support_articles
Connection refused on postgresql://production:5432
```

**Solution:**
```bash
# Check network connectivity
ping production.rds.amazonaws.com

# Check credentials
psql -h production -U axonflow -d axonflow -c "SELECT 1"

# Update agent definition with correct URL
vim agents/customer-support-agent.yaml
# Change: postgresql://production/support_articles
# To: postgresql://production.rds.amazonaws.com/support_articles
```

### Issue 3: "Rate limit too high"

**Error:**
```
⚠️  Warning: Rate limit 10,000 requests/minute exceeds recommended limit (1,000)
This could result in high costs. Proceed? (y/n)
```

**Solution:**
```yaml
# Reduce to reasonable limits
rate_limits:
  requests_per_minute: 100   # Was: 10000
  requests_per_day: 50000    # Was: 1000000
```

### Issue 4: "System prompt too long"

**Error:**
```
❌ Validation failed: system_prompt exceeds 4000 characters (current: 5200)
```

**Solution:**
```yaml
# Move long instructions to knowledge sources
system_prompt: |
  You are a customer support agent for Acme Corp.
  Follow the guidelines in: s3://company-docs/agent-guidelines.md

knowledge_sources:
  - s3://company-docs/agent-guidelines.md  # Contains detailed instructions
```

---

## Next Steps

1. **Browse Examples** - [examples/agents/](../examples/agents/)
2. **Read API Reference** - [API Documentation](../api/)
3. **Deploy Your First Agent** - Follow Quick Example above
4. **Join Community** - https://getaxonflow.com/slack

**Questions?** Email support@getaxonflow.com or visit https://docs.getaxonflow.com

---

*Last Updated: November 11, 2025*
*Version: 1.0.0*
