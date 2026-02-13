# Grafana Dashboard Guide

**Last Updated:** February 2026

**Platform Version:** v4.3.0

The AxonFlow Community Dashboard provides real-time visibility into your AI governance platform's security, performance, and policy enforcement metrics.

## Quick Start

The dashboard is automatically loaded when you start AxonFlow with docker-compose:

```bash
docker compose up -d

# Access Grafana
open http://localhost:3000
# Login: admin / grafana_localdev456
```

> **Port note:** Grafana runs on port **3000** in the main `docker-compose.yaml` (standard for local development). The `support-demo` compose profile uses port 3001 to avoid conflicts. If you see references to port 3001 elsewhere, that applies only to the support-demo environment.

Navigate to **Dashboards → AxonFlow → AxonFlow Community** to view the dashboard.

## Dashboard Sections

### Overview

Key metrics at a glance:

| Metric | Description |
|--------|-------------|
| Total Requests | Total API requests processed |
| Blocked Requests | Requests blocked by security policies |
| Policy Evaluations | Number of policy evaluations performed |
| Success Rate | Percentage of allowed requests |
| P95 Pre-check Latency | 95th percentile gateway pre-check time |
| LLM Tokens Tracked | Total LLM tokens processed |

### Security & Compliance

Real-time security monitoring panels:

| Panel | Type | Description |
|-------|------|-------------|
| **PII Detections by Type** | Bar Chart | Breakdown of detected PII by type (Aadhaar, PAN, UPI, bank accounts, etc.) |
| **Security Threats Blocked** | Stat | Total blocked requests including SQL injection, PII leaks, and dangerous queries |
| **Provider Distribution** | Pie Chart | Distribution of LLM API calls across providers (OpenAI, Anthropic, Google, Azure, Ollama) |
| **Active Policies Summary** | Bar Chart | Policy enforcement activity - evaluations vs blocks vs PII detections |

**Prometheus Metrics Used:**
- `axonflow_gateway_rbi_pii_detected_total{pii_type, blocked}` - PII detection by type
- `axonflow_agent_blocked_requests_total` - Agent blocked requests
- `axonflow_orchestrator_blocked_requests_total` - Orchestrator blocked requests
- `axonflow_orchestrator_llm_calls_total{provider, status}` - LLM calls by provider
- `axonflow_agent_policy_evaluations_total` - Policy evaluations

### Request Throughput

Traffic analysis panels:

- **Request Rate**: Requests per second by status
- **Blocked Requests Rate**: Blocked requests over time

### Latency

Performance monitoring panels:

- **Gateway Pre-check Latency**: P50/P95/P99 for pre-check operations
- **Agent Request Latency**: P50/P95/P99 for agent processing
- **Orchestrator Request Latency**: P50/P95/P99 for orchestrator operations

### Policy Enforcement

Policy activity panels:

- **Policy Activity (Hourly)**: Policy evaluations and blocked requests over time
- **Gateway Pre-check Results**: Pie chart showing approved vs blocked ratio

### LLM Usage

LLM monitoring panels:

- **LLM Tokens (5m)**: Token usage by type (input/output)
- **LLM Cost (Hourly)**: Cost tracking by provider and model
- **LLM API Calls (5m)**: API calls by provider and status

### MCP Connectors

Connector monitoring panels:

- **Connector Calls (5m)**: Requests by connector type
- **Connector Latency**: P50/P95 latency by connector
- **Connector Errors (5m)**: Error tracking by connector and type

## Auto-Provisioning

The dashboard is automatically provisioned when Grafana starts:

1. **Datasource**: Prometheus is auto-configured at `http://prometheus:9090`
2. **Dashboard**: The JSON dashboard is loaded from `/var/lib/grafana/dashboards`

Configuration files:
- `config/grafana/provisioning/datasources/prometheus.yml` - Prometheus datasource
- `config/grafana/provisioning/dashboards/dashboards.yml` - Dashboard provisioning
- `config/grafana/dashboards/axonflow-community.json` - Dashboard definition

## Customization

### Adding Custom Panels

1. Open the dashboard in Grafana
2. Click **Add → Visualization**
3. Configure your query using available Prometheus metrics
4. Save the dashboard

### Exporting Changes

To persist dashboard changes:

1. Click **Dashboard settings** (gear icon)
2. Click **JSON Model**
3. Copy the JSON
4. Update `config/grafana/dashboards/axonflow-community.json`

### Available Metrics

Common Prometheus metrics for custom panels:

**Agent Metrics:**
- `axonflow_agent_requests_total{status}` - Total requests by status
- `axonflow_agent_blocked_requests_total` - Blocked requests
- `axonflow_agent_policy_evaluations_total` - Policy evaluations
- `axonflow_agent_request_duration_milliseconds_bucket` - Request latency histogram

**Gateway Metrics:**
- `axonflow_gateway_precheck_requests_total{approved}` - Pre-check requests
- `axonflow_gateway_precheck_duration_milliseconds_bucket` - Pre-check latency
- `axonflow_gateway_rbi_pii_detected_total{pii_type, blocked}` - PII detections
- `axonflow_gateway_llm_tokens_total{type}` - LLM token tracking
- `axonflow_gateway_llm_cost_usd_total{provider, model}` - LLM cost tracking

**Orchestrator Metrics:**
- `axonflow_orchestrator_requests_total{status}` - Total requests
- `axonflow_orchestrator_blocked_requests_total` - Blocked requests
- `axonflow_orchestrator_policy_evaluations_total` - Policy evaluations
- `axonflow_orchestrator_llm_calls_total{provider, status}` - LLM calls

**Connector Metrics:**
- `axonflow_connector_calls_total{connector}` - Connector calls
- `axonflow_connector_duration_milliseconds_bucket{connector}` - Connector latency
- `axonflow_connector_errors_total{connector, error_type}` - Connector errors

## Troubleshooting

### Dashboard Not Loading

```bash
# Check Grafana is running
docker compose ps grafana

# Check Grafana logs
docker compose logs grafana

# Verify provisioning files
ls -la config/grafana/provisioning/
```

### No Data Showing

```bash
# Check Prometheus is scraping targets
open http://localhost:9090/targets

# Verify Agent is exposing metrics
curl http://localhost:8080/metrics

# Check Prometheus for data
curl http://localhost:9090/api/v1/query?query=axonflow_agent_requests_total
```

### Dashboard Shows "No Data"

1. Ensure you've made some API requests to generate metrics
2. Check the time range selector (default: Last 1 hour)
3. Verify Prometheus datasource is configured correctly

## Screenshots

After docker-compose up, the dashboard displays:

1. **Overview row**: Key metrics in stat panels
2. **Security & Compliance row**: PII detection bar chart, security threats blocked, provider pie chart, policy summary
3. **Request Throughput row**: Request rate and blocked rate time series
4. **Latency row**: Three latency time series panels
5. **Policy Enforcement row**: Policy activity and pre-check results
6. **LLM Usage row**: Token usage, cost tracking, API calls
7. **MCP Connectors row**: Connector calls, latency, errors

## Related Documentation

- [Local Development Guide](./local-development.md)
- [Community Configuration](./community-configuration.md)
- [Audit Logging Guide](./audit-logging.md)
