# Cost Controls

Cost Controls enable you to set budgets, track LLM usage, and prevent cost overruns. This Phase 1 implementation provides core budget management and real-time usage tracking.

## Overview

Cost Controls work by:
1. **Recording usage** automatically when LLM calls are made through the router
2. **Tracking against budgets** defined at various scope levels
3. **Alerting** when usage approaches or exceeds thresholds
4. **Optionally blocking** requests when budgets are exceeded

## Budget Configuration

### Budget Scopes

Budgets can be set at different scope levels:

| Scope | Description | Use Case |
|-------|-------------|----------|
| `organization` | Entire organization | Company-wide spending caps |
| `team` | Specific team | Department budgets |
| `agent` | Individual agent | Per-agent cost limits |
| `workflow` | Workflow/pipeline | Per-workflow limits |
| `user` | Individual user | Per-user quotas |

### Budget Periods

| Period | Description |
|--------|-------------|
| `daily` | Resets at midnight UTC |
| `weekly` | Resets on Monday midnight UTC |
| `monthly` | Resets on the 1st of each month |
| `quarterly` | Resets every 3 months |
| `yearly` | Resets on January 1st |

### On-Exceed Actions

When a budget is exceeded:

| Action | Behavior |
|--------|----------|
| `warn` | Log warning, continue allowing requests |
| `block` | Reject new requests until next period |
| `downgrade` | Route to cheaper models (Phase 2) |

## Creating a Budget

### HTTP API

```bash
curl -X POST http://localhost:8081/api/v1/budgets \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: your-org-id" \
  -d '{
    "id": "monthly-budget",
    "name": "Monthly Production Budget",
    "scope": "organization",
    "limit_usd": 1000.00,
    "period": "monthly",
    "on_exceed": "warn",
    "alert_thresholds": [50, 80, 100]
  }'
```

### Go SDK

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    OrchestratorURL: "http://localhost:8081",
})

budget := axonflow.Budget{
    ID:              "monthly-budget",
    Name:            "Monthly Production Budget",
    Scope:           "organization",
    LimitUSD:        1000.00,
    Period:          "monthly",
    OnExceed:        "warn",
    AlertThresholds: []int{50, 80, 100},
}

err := client.CreateBudget(ctx, budget)
```

### Python SDK

```python
from axonflow import AxonFlow

client = AxonFlow(orchestrator_url="http://localhost:8081")

client.create_budget(
    id="monthly-budget",
    name="Monthly Production Budget",
    scope="organization",
    limit_usd=1000.00,
    period="monthly",
    on_exceed="warn",
    alert_thresholds=[50, 80, 100],
)
```

## Checking Budget Status

Get real-time status of a budget:

```bash
curl http://localhost:8081/api/v1/budgets/monthly-budget/status
```

Response:
```json
{
  "budget": {
    "id": "monthly-budget",
    "name": "Monthly Production Budget",
    "limit_usd": 1000.00,
    "period": "monthly"
  },
  "used_usd": 450.25,
  "remaining_usd": 549.75,
  "percentage": 45.025,
  "period_start": "2026-01-01T00:00:00Z",
  "period_end": "2026-02-01T00:00:00Z",
  "is_exceeded": false,
  "is_blocked": false
}
```

## Usage Tracking

### Usage Summary

Get aggregated usage for a period:

```bash
curl "http://localhost:8081/api/v1/usage?period=monthly" \
  -H "X-Org-ID: your-org-id"
```

Response:
```json
{
  "total_cost_usd": 450.25,
  "total_tokens_in": 1250000,
  "total_tokens_out": 375000,
  "total_requests": 5420,
  "average_cost_per_request": 0.083
}
```

### Usage Breakdown

Get usage broken down by dimension:

```bash
# By provider
curl "http://localhost:8081/api/v1/usage/breakdown?group_by=provider&period=monthly"

# By model
curl "http://localhost:8081/api/v1/usage/breakdown?group_by=model&period=monthly"

# By agent
curl "http://localhost:8081/api/v1/usage/breakdown?group_by=agent&period=monthly"
```

Response:
```json
{
  "group_by": "provider",
  "total_cost_usd": 450.25,
  "items": [
    {
      "group_by": "provider",
      "group_value": "anthropic",
      "cost_usd": 320.50,
      "tokens_in": 890000,
      "tokens_out": 245000,
      "request_count": 3200,
      "percentage": 71.2
    },
    {
      "group_by": "provider",
      "group_value": "openai",
      "cost_usd": 129.75,
      "tokens_in": 360000,
      "tokens_out": 130000,
      "request_count": 2220,
      "percentage": 28.8
    }
  ]
}
```

## Pre-Request Budget Check

Check if a request should be allowed before making an LLM call:

```bash
curl -X POST http://localhost:8081/api/v1/budgets/check \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "your-org-id",
    "team_id": "engineering",
    "agent_id": "support-bot"
  }'
```

Response (allowed):
```json
{
  "allowed": true
}
```

Response (blocked):
```json
{
  "allowed": false,
  "action": "block",
  "budget_id": "team-budget",
  "budget_name": "Engineering Team Budget",
  "used_usd": 520.00,
  "limit_usd": 500.00,
  "percentage": 104.0,
  "message": "Budget 'Engineering Team Budget' exceeded - requests blocked"
}
```

## Model Pricing

Query pricing for models:

```bash
# All providers
curl http://localhost:8081/api/v1/pricing

# Specific provider
curl "http://localhost:8081/api/v1/pricing?provider=anthropic"

# Specific model
curl "http://localhost:8081/api/v1/pricing?provider=anthropic&model=claude-sonnet-4"
```

Response:
```json
{
  "provider": "anthropic",
  "model": "claude-sonnet-4",
  "pricing": {
    "input_per_1k": 0.003,
    "output_per_1k": 0.015
  }
}
```

## Alerts

Budget alerts are triggered when usage crosses configured thresholds. In Phase 1, alerts are logged to the orchestrator output.

### Alert Types

| Type | Description |
|------|-------------|
| `threshold_reached` | Usage crossed a percentage threshold |
| `budget_exceeded` | Usage exceeded 100% of budget |
| `budget_blocked` | Requests are being blocked |

### Viewing Alerts

```bash
curl http://localhost:8081/api/v1/budgets/monthly-budget/alerts
```

Response:
```json
{
  "alerts": [
    {
      "id": 1,
      "budget_id": "monthly-budget",
      "threshold": 50,
      "percentage_reached": 52.3,
      "amount_usd": 523.00,
      "alert_type": "threshold_reached",
      "message": "Budget 'Monthly Production Budget' at 52.3% ($523.00 / $1000.00)",
      "created_at": "2026-01-15T10:30:00Z",
      "acknowledged": false
    }
  ],
  "count": 1
}
```

## Automatic Usage Recording

Usage is automatically recorded when LLM calls are made through the cost-tracking router. The router:

1. Intercepts LLM completion requests
2. Calculates cost based on configured pricing
3. Records usage with org, team, agent, and user context
4. Updates aggregates for reporting
5. Checks budget thresholds and sends alerts

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PRICING_PROVIDER` | Custom provider name | - |
| `LLM_PRICING_MODEL` | Custom model name | - |
| `LLM_PRICING_INPUT` | Custom input price per 1K | - |
| `LLM_PRICING_OUTPUT` | Custom output price per 1K | - |
| `LLM_PRICING_FILE` | Path to custom pricing JSON | - |

### Custom Pricing File

```json
{
  "providers": {
    "custom-llm": {
      "model-a": {"input_per_1k": 0.001, "output_per_1k": 0.002},
      "model-b": {"input_per_1k": 0.002, "output_per_1k": 0.004}
    }
  }
}
```

## Phase 1 Limitations

- Alerts are logged only (no email/webhook delivery yet)
- `downgrade` action is not yet implemented
- No dashboard UI for viewing budgets

## API Reference

See the full [Cost Controls API Reference](/api/orchestrator-api#cost-controls) for detailed endpoint documentation.

## Examples

Complete examples are available in [examples/cost-controls/](/examples/cost-controls/):
- Go
- Python
- TypeScript
- Java
- HTTP (curl)
