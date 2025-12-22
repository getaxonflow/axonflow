# AxonFlow API Documentation

This directory contains OpenAPI 3.0 specifications for all AxonFlow APIs.

## API Specifications

| File | Service | Description |
|------|---------|-------------|
| [`agent-api.yaml`](./agent-api.yaml) | Agent | Authentication, Gateway Mode, MCP Connectors |
| [`orchestrator-api.yaml`](./orchestrator-api.yaml) | Orchestrator | LLM Routing, Multi-Agent Planning, Workflows |
| [`policy-api.yaml`](./policy-api.yaml) | Orchestrator | Policy CRUD, Templates |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Application                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AxonFlow Agent (:8080)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Gateway   │  │    Proxy    │  │   MCP Connectors        │  │
│  │    Mode     │  │    Mode     │  │ (PostgreSQL, Amadeus)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│  • Pre-check       • Full proxy      • Query execution           │
│  • Audit           • Policy enforce  • Write commands            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   AxonFlow Orchestrator (:8081)                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  LLM Router │  │    MAP      │  │   Dynamic Policies      │  │
│  │ (OpenAI,    │  │  Planning   │  │ (Risk scoring, audit)   │  │
│  │  Bedrock)   │  │             │  │                         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start Examples

### Gateway Mode (For existing LLM integrations)

**Step 1: Pre-check before LLM call**
```bash
curl -X POST "https://agent.getaxonflow.com/api/policy/pre-check" \
  -H "Content-Type: application/json" \
  -H "X-License-Key: axf_live_your_key" \
  -d '{
    "query": "What are the best flights to LAX?",
    "user_token": "eyJhbGciOiJIUzI1NiIs...",
    "client_id": "travel-app",
    "data_sources": ["amadeus"]
  }'
```

Response:
```json
{
  "context_id": "ctx_abc123def456",
  "approved": true,
  "approved_data": {
    "amadeus": {
      "rows": [{"flight_number": "UA123", "price": 299}],
      "row_count": 5
    }
  },
  "policies": ["pii-detection", "rate-limit"],
  "expires_at": "2025-01-15T10:35:00Z"
}
```

**Step 2: Audit after LLM call**
```bash
curl -X POST "https://agent.getaxonflow.com/api/audit/llm-call" \
  -H "Content-Type: application/json" \
  -H "X-License-Key: axf_live_your_key" \
  -d '{
    "context_id": "ctx_abc123def456",
    "client_id": "travel-app",
    "response_summary": "Found 5 flights",
    "provider": "openai",
    "model": "gpt-4",
    "token_usage": {
      "prompt_tokens": 150,
      "completion_tokens": 200,
      "total_tokens": 350
    },
    "latency_ms": 1250
  }'
```

### Proxy Mode (Full interception)

```bash
curl -X POST "https://agent.getaxonflow.com/api/request" \
  -H "Content-Type: application/json" \
  -H "X-License-Key: axf_live_your_key" \
  -d '{
    "query": "Summarize the quarterly sales report",
    "user_token": "eyJhbGciOiJIUzI1NiIs...",
    "client_id": "analytics-app",
    "request_type": "llm_chat",
    "context": {
      "model_preference": "gpt-4"
    }
  }'
```

### Multi-Agent Planning (MAP)

```bash
curl -X POST "https://agent.getaxonflow.com/api/request" \
  -H "Content-Type: application/json" \
  -H "X-License-Key: axf_live_your_key" \
  -d '{
    "query": "Find flights from NYC to LAX and book a hotel near the beach",
    "user_token": "eyJhbGciOiJIUzI1NiIs...",
    "client_id": "travel-planner",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "travel",
      "execution_mode": "parallel",
      "departure_date": "2025-01-20",
      "budget": 1500
    }
  }'
```

Response:
```json
{
  "success": true,
  "result": {
    "flights": [
      {"flight_number": "UA123", "price": 299, "departure": "2025-01-20T08:00:00Z"}
    ],
    "hotels": [
      {"name": "Hilton LAX", "price_per_night": 189, "rating": 4.5}
    ],
    "summary": "Found 5 flights and 3 hotels within budget"
  },
  "plan_id": "plan_1705312200_abc123",
  "metadata": {
    "tasks_executed": 3,
    "execution_mode": "parallel",
    "execution_time_ms": 3500
  }
}
```

### MCP Connector Query

```bash
curl -X POST "https://agent.getaxonflow.com/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -H "X-License-Key: axf_live_your_key" \
  -d '{
    "client_id": "analytics-app",
    "user_token": "eyJhbGciOiJIUzI1NiIs...",
    "connector": "postgres_main",
    "statement": "SELECT * FROM orders WHERE status = $1 LIMIT 10",
    "parameters": {"1": "completed"},
    "timeout": "10s"
  }'
```

### Policy CRUD

**List policies**
```bash
curl -X GET "https://orchestrator.getaxonflow.com/api/v1/policies" \
  -H "X-Tenant-ID: tenant-123"
```

**Create a policy**
```bash
curl -X POST "https://orchestrator.getaxonflow.com/api/v1/policies" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -H "X-User-ID: admin@company.com" \
  -d '{
    "name": "Block PII Access",
    "description": "Prevent unauthorized access to PII",
    "type": "content",
    "conditions": [
      {
        "field": "query",
        "operator": "contains_any",
        "value": ["ssn", "social security", "credit card"]
      }
    ],
    "actions": [
      {
        "type": "block",
        "config": {"message": "Access to PII is restricted"}
      }
    ],
    "priority": 100,
    "enabled": true
  }'
```

**Test a policy**
```bash
curl -X POST "https://orchestrator.getaxonflow.com/api/v1/policies/pol_abc123/test" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -d '{
    "query": "Show me the customer SSN",
    "user": {"email": "analyst@company.com", "role": "analyst"}
  }'
```

### Health Checks

```bash
# Agent health
curl https://agent.getaxonflow.com/health

# Orchestrator health
curl https://orchestrator.getaxonflow.com/health

# MCP connectors health
curl https://agent.getaxonflow.com/mcp/health
```

### Metrics

```bash
# Agent metrics (JSON)
curl https://agent.getaxonflow.com/metrics

# Orchestrator metrics (JSON)
curl https://orchestrator.getaxonflow.com/metrics

# Prometheus format
curl https://agent.getaxonflow.com/prometheus
curl https://orchestrator.getaxonflow.com/prometheus
```

## API Endpoints Summary

### Agent API (Port 8080)

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Health | `/health` | GET | Service health |
| Metrics | `/metrics` | GET | JSON metrics |
| Metrics | `/prometheus` | GET | Prometheus format |
| Proxy | `/api/request` | POST | Process request |
| Proxy | `/api/clients` | GET/POST | Manage clients |
| Proxy | `/api/policies/test` | POST | Test policies |
| Gateway | `/api/policy/pre-check` | POST | Pre-check request |
| Gateway | `/api/audit/llm-call` | POST | Audit LLM call |
| MCP | `/mcp/connectors` | GET | List connectors |
| MCP | `/mcp/connectors/{name}/health` | GET | Connector health |
| MCP | `/mcp/resources/query` | POST | Execute query |
| MCP | `/mcp/tools/execute` | POST | Execute command |
| MCP | `/mcp/health` | GET | MCP health |

### Orchestrator API (Port 8081)

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Health | `/health` | GET | Service health |
| Metrics | `/metrics` | GET | JSON metrics |
| Metrics | `/prometheus` | GET | Prometheus format |
| Process | `/api/v1/process` | POST | Process request |
| MAP | `/api/v1/plan` | POST | Multi-agent planning |
| LLM | `/api/v1/providers/status` | GET | Provider status |
| LLM | `/api/v1/providers/weights` | PUT | Update weights |
| Policy | `/api/v1/policies` | GET/POST | List/create policies |
| Policy | `/api/v1/policies/{id}` | GET/PUT/DELETE | CRUD policy |
| Policy | `/api/v1/policies/{id}/test` | POST | Test policy |
| Policy | `/api/v1/policies/{id}/versions` | GET | Version history |
| Policy | `/api/v1/policies/import` | POST | Bulk import |
| Policy | `/api/v1/policies/export` | GET | Bulk export |
| Policy | `/api/v1/policies/dynamic` | GET | List dynamic |
| Template | `/api/v1/templates` | GET | List templates |
| Template | `/api/v1/templates/{id}` | GET | Get template |
| Template | `/api/v1/templates/{id}/apply` | POST | Apply template |
| Workflow | `/api/v1/workflows/execute` | POST | Execute workflow |
| Workflow | `/api/v1/workflows/executions` | GET | List executions |
| Workflow | `/api/v1/workflows/executions/{id}` | GET | Get execution |
| Audit | `/api/v1/audit/search` | POST | Search logs |
| Audit | `/api/v1/audit/tenant/{id}` | GET | Tenant logs |
| Connectors | `/api/v1/connectors` | GET | List connectors |
| Connectors | `/api/v1/connectors/{id}/install` | POST | Install |
| Connectors | `/api/v1/connectors/{id}/uninstall` | DELETE | Uninstall |

## Authentication

### License Key (X-License-Key)

Required for all client-facing endpoints. Obtained from the AxonFlow dashboard.

```bash
-H "X-License-Key: axf_live_your_key"
```

### User Token (user_token)

JWT token identifying the end user. Include in request body.

```json
{
  "user_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Tenant Headers (Policy API)

Required for policy management endpoints:

```bash
-H "X-Tenant-ID: tenant-123"
-H "X-User-ID: admin@company.com"
```

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid license key |
| `FORBIDDEN` | 403 | Tenant mismatch or policy block |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid request body |
| `RATE_LIMITED` | 429 | Rate limit exceeded |
| `SERVICE_UNAVAILABLE` | 503 | Service starting or unavailable |
| `INTERNAL_ERROR` | 500 | Internal server error |

Error response format:
```json
{
  "success": false,
  "error": "X-License-Key header required"
}
```

## Rate Limits

Default limits (SaaS):

| Endpoint Category | Limit |
|-------------------|-------|
| Standard requests | 1000/min per tenant |
| Gateway pre-check | 5000/min per tenant |
| Bulk operations | 10/min per tenant |
| MCP queries | 500/min per tenant |

Headers returned:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1705312200
```

## Viewing Documentation

### Swagger UI (Docker)

```bash
# Agent API
docker run -p 8080:8080 \
  -e SWAGGER_JSON=/spec/agent-api.yaml \
  -v $(pwd):/spec \
  swaggerapi/swagger-ui

# Orchestrator API
docker run -p 8081:8080 \
  -e SWAGGER_JSON=/spec/orchestrator-api.yaml \
  -v $(pwd):/spec \
  swaggerapi/swagger-ui

# Policy API
docker run -p 8082:8080 \
  -e SWAGGER_JSON=/spec/policy-api.yaml \
  -v $(pwd):/spec \
  swaggerapi/swagger-ui
```

### Redoc (Static HTML)

```bash
npm install -g @redocly/cli

# Generate HTML docs
redocly build-docs agent-api.yaml -o agent-api.html
redocly build-docs orchestrator-api.yaml -o orchestrator-api.html
redocly build-docs policy-api.yaml -o policy-api.html
```

## Generating Client Libraries

```bash
npm install -g @openapitools/openapi-generator-cli

# TypeScript
openapi-generator-cli generate -i agent-api.yaml -g typescript-fetch -o ./clients/ts

# Python
openapi-generator-cli generate -i agent-api.yaml -g python -o ./clients/python

# Go
openapi-generator-cli generate -i agent-api.yaml -g go -o ./clients/go
```

## Validation

```bash
# Validate specs
npm install -g @apidevtools/swagger-cli
swagger-cli validate agent-api.yaml
swagger-cli validate orchestrator-api.yaml
swagger-cli validate policy-api.yaml

# Lint with Spectral
npm install -g @stoplight/spectral-cli
spectral lint agent-api.yaml
spectral lint orchestrator-api.yaml
spectral lint policy-api.yaml
```

## Related Resources

- [SDK Documentation](https://docs.getaxonflow.com/sdk)
- [Gateway Mode Guide](https://docs.getaxonflow.com/sdk/gateway-mode)
- [Proxy Mode Guide](https://docs.getaxonflow.com/sdk/proxy-mode)
- [MCP Connectors](https://docs.getaxonflow.com/connectors)
- [OpenAPI 3.0 Specification](https://spec.openapis.org/oas/v3.0.3)
