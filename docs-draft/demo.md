---
sidebar_position: 5
title: Interactive Demo
description: Try AxonFlow's AI governance features with our hands-on demo
---

# Interactive Demo

Experience AxonFlow's AI governance capabilities firsthand with our interactive demo.

## What You'll See

The demo showcases a realistic **AI Customer Support Assistant** scenario where AxonFlow governs AI interactions with customer data.

### Features Demonstrated

| Feature | Description |
|---------|-------------|
| **PII Detection** | Block SSN, credit cards, PAN, Aadhaar |
| **SQL Injection Blocking** | Prevent UNION, DROP TABLE attacks |
| **Two Integration Modes** | Proxy (simple) and Gateway (low latency) |
| **MCP Connectors** | AI safely querying PostgreSQL |
| **Multi-Agent Planning** | Orchestrated workflows with governance |
| **Complete Audit Trail** | Every request logged and queryable |
| **Multi-Model Routing** | OpenAI, Anthropic, and more |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/getaxonflow/axonflow.git
cd axonflow

# Start services
docker-compose up -d

# Run the demo
./examples/demo/demo.sh
```

**Requirements:**
- Docker & Docker Compose
- Python 3.8+ (for example scripts)
- Optional: OpenAI or Anthropic API key

## Demo Structure

### Part 1: The Problem

See what happens when AI calls are unprotected:
- No audit trail
- PII sent to external LLMs
- No protection against prompt injection

### Part 2: Core Governance

Watch AxonFlow block dangerous content automatically:

```python
# PII Detection - Blocked
"Customer SSN is 123-45-6789"  # Detected and blocked

# SQL Injection - Blocked
"SELECT * FROM users; DROP TABLE secrets;"  # Attack prevented

# Safe Query - Allowed
"What are my open support tickets?"  # Passes through
```

### Part 3: Integration Modes

**Proxy Mode** - Simplest integration:
```
App → AxonFlow → LLM → Response
```
AxonFlow handles everything with one API call.

**Gateway Mode** - Lowest latency:
```
Pre-check → Your LLM Call → Audit
```
You control the LLM, AxonFlow governs. ~5ms overhead per step.

### Part 4: MCP Connectors

Connect AI to your databases safely:
```
"Show me tickets from this week"
  ↓
AxonFlow converts to SQL, enforces policies
  ↓
Results returned with PII redacted
```

### Part 5: Multi-Agent Planning

Orchestrate complex workflows:
```yaml
steps:
  - name: gather-data
    type: connector-call
  - name: analyze
    type: llm-call
  - name: report
    type: llm-call
```
Governance applied at every step.

### Part 6: Observability

Query audit logs and view metrics in Grafana:
- Request rate and blocked requests
- Latency percentiles (P50, P95, P99)
- Policy enforcement breakdown
- Token usage and costs

### Part 7: Multi-Model

Same governance, any provider:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude 3)
- Self-hosted (Ollama)

## Run Individual Examples

Each part has a Python script you can run directly:

```bash
# PII Detection
python3 examples/demo/02_pii_detection.py

# SQL Injection Blocking
python3 examples/demo/03_sql_injection.py

# Gateway Mode
python3 examples/demo/05_gateway_mode.py
```

## View in Grafana

After running the demo, open Grafana to see the metrics:

**URL:** http://localhost:3000
**Login:** admin / grafana_localdev456

The "AxonFlow Community" dashboard shows:
- Real-time request rates
- Policy violation breakdown
- Latency distributions
- Token usage tracking

## Next Steps

After the demo:

1. [Quick Start Guide](/docs/getting-started) - Set up your own instance
2. [SDK Documentation](/docs/sdk) - Integrate with your application
3. [Policy Configuration](/docs/policies) - Customize detection rules
4. [Enterprise Features](/docs/enterprise) - HITL, compliance modules

## Get Help

- **GitHub Issues:** [Report bugs or request features](https://github.com/getaxonflow/axonflow/issues)
- **Documentation:** Browse the full docs
- **Community:** Join our Discord

---

Ready to govern your AI? [Get Started →](/docs/getting-started)
