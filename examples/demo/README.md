# AxonFlow Community Demo

Interactive demonstration of AxonFlow's AI governance capabilities.

**Scenario:** AI Customer Support Assistant
An AI agent helps support teams query customer data while AxonFlow ensures security, compliance, and complete audit trails.

## Quick Start

```bash
# 1. Start services
docker-compose up -d

# 2. Wait for services to be healthy (~30 seconds)
docker-compose ps

# 3. Run the demo
./examples/demo/demo.sh
```

## Prerequisites

- **Docker & Docker Compose** - For running AxonFlow services
- **Python 3.8+** - For running demo examples
- **AxonFlow Python SDK** - Installed automatically if missing

Optional (for full demo):
- **OpenAI API Key** - Set `OPENAI_API_KEY` for LLM calls
- **Anthropic API Key** - Set `ANTHROPIC_API_KEY` for multi-model demo

## Demo Structure

The demo covers 7 parts, showcasing all major Community features:

| Part | Name | Duration | What You'll See |
|------|------|----------|-----------------|
| 1 | The Problem | 1 min | Risks of unprotected AI |
| 2 | Core Governance | 2 min | PII detection, SQL injection blocking |
| 3 | Integration Modes | 2 min | Proxy mode vs Gateway mode |
| 4 | MCP Connectors | 2 min | AI querying PostgreSQL safely |
| 5 | Multi-Agent Planning | 2 min | Orchestrated workflows |
| 6 | Observability | 1 min | Audit logs, Grafana dashboard |
| 7 | Multi-Model | 1 min | Vendor-neutral LLM routing |

**Total runtime:** ~10 minutes (full) or ~3 minutes (quick mode)

## Running the Demo

### Full Demo

```bash
./examples/demo/demo.sh
```

Interactive mode - press Enter between sections.

### Quick Demo

```bash
./examples/demo/demo.sh --quick
```

Runs Parts 2, 3, and 6 without pauses (~3 minutes).

### Specific Part

```bash
./examples/demo/demo.sh --part 2    # Just Core Governance
./examples/demo/demo.sh --part 4    # Just MCP Connectors
```

## Python Examples

Each part has a corresponding Python file you can run individually:

| File | Description |
|------|-------------|
| `01_the_problem.py` | Unprotected LLM call (shows the risk) |
| `02_pii_detection.py` | PII detection (SSN, CC, PAN, Aadhaar) |
| `03_sql_injection.py` | SQL injection blocking |
| `04_proxy_mode.py` | Proxy mode integration |
| `05_gateway_mode.py` | Gateway mode (3-step flow) |
| `06_mcp_connector.py` | PostgreSQL connector demo |
| `07_multi_agent_planning.py` | MAP workflow execution |
| `08_audit_trail.py` | Query audit logs |
| `09_multi_model.py` | Multi-provider routing |

Run any example directly:

```bash
python3 examples/demo/02_pii_detection.py
```

## Seeding Demo Data

For the PostgreSQL connector demo (Part 4), seed the database with sample tickets:

```bash
./config/seed-data/seed.sh
```

This creates:
- `support_tickets` table with 20 realistic tickets
- Sample audit logs for Grafana visualization

## Grafana Dashboard

A pre-built dashboard visualizes AxonFlow metrics:

**URL:** http://localhost:3000
**Login:** admin / grafana_localdev456
**Dashboard:** AxonFlow Community (auto-provisioned)

**Panels:**
- Request rate and blocked requests
- Latency percentiles (P50, P95, P99)
- Policy enforcement breakdown
- LLM token usage and costs
- MCP connector metrics

## What's Demonstrated

### Policy Enforcement

| Policy | Detection |
|--------|-----------|
| PII - SSN | `123-45-6789` patterns |
| PII - Credit Card | Luhn-valid card numbers |
| PII - PAN (India) | `ABCDE1234F` format |
| PII - Aadhaar (India) | 12-digit with spaces |
| SQL Injection | UNION, DROP, TRUNCATE, etc. |

### Integration Modes

**Proxy Mode** (simplest):
```
App -> AxonFlow -> LLM -> Response
```
- Single API call
- AxonFlow handles policy + LLM routing

**Gateway Mode** (lowest latency):
```
Pre-check -> Your LLM Call -> Audit
```
- You control the LLM
- ~5ms overhead per step

### MCP Connectors

Connect AI to your data with built-in governance:
- Natural language to SQL conversion
- Policy enforcement on queries
- Response scanning for data leaks

### Multi-Agent Planning (MAP)

Orchestrate complex workflows:
- Define steps declaratively
- Governance at every step
- Supports: `llm-call`, `api-call`, `connector-call`, `conditional`

## Troubleshooting

### Services not starting

```bash
# Check status
docker-compose ps

# View logs
docker-compose logs axonflow-agent
docker-compose logs axonflow-orchestrator
```

### Python SDK not found

```bash
pip install axonflow
```

### No LLM responses

Set your API key:
```bash
export OPENAI_API_KEY=sk-your-key
# or
export ANTHROPIC_API_KEY=sk-ant-your-key
```

### Grafana shows no data

1. Run some demo queries first
2. Check Prometheus is scraping: http://localhost:9090/targets
3. Dashboard auto-refreshes every 5 seconds

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_AGENT_URL` | `http://localhost:8080` | Agent endpoint |
| `AXONFLOW_ORCHESTRATOR_URL` | `http://localhost:8081` | Orchestrator endpoint |
| `AXONFLOW_CLIENT_ID` | `demo-client` | Client identifier |
| `AXONFLOW_CLIENT_SECRET` | `demo-secret` | Client secret |
| `OPENAI_API_KEY` | - | For LLM calls |
| `ANTHROPIC_API_KEY` | - | For multi-model demo |

## Next Steps

After the demo:

1. **Read the docs:** https://docs.getaxonflow.com
2. **Explore SDK examples:** `examples/hello-world/`
3. **Try your own policies:** Create custom detection rules
4. **Check Enterprise features:** HITL, Circuit Breaker, Compliance

## Support

- **Documentation:** https://docs.getaxonflow.com
- **GitHub Issues:** https://github.com/getaxonflow/axonflow/issues
