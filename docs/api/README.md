# AxonFlow API Documentation

This directory contains OpenAPI 3.0 specifications for all AxonFlow APIs.

## API Specifications

| File | Service | Description |
|------|---------|-------------|
| [`agent-api.yaml`](./agent-api.yaml) | Agent | Authentication, Gateway Mode, MCP Connectors |
| [`orchestrator-api.yaml`](./orchestrator-api.yaml) | Orchestrator | LLM Routing, Multi-Agent Planning, Workflows |
| [`policy-api.yaml`](./policy-api.yaml) | Orchestrator | Policy CRUD, Templates |

## Architecture Overview

AxonFlow uses a **Single Entry Point Architecture** (ADR-026). All client requests go through the Agent service, which proxies to internal services automatically.

```
┌─────────────────────────────────────────────────────────────────┐
│                   Client Application / SDK                       │
│                                                                   │
│  endpoint: "https://axonflow.example.com"   (Agent only)         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   AxonFlow Agent (:8080)                         │
│                   ** Single Entry Point **                       │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Gateway   │  │    Proxy    │  │   MCP Connectors        │  │
│  │    Mode     │  │    Mode     │  │ (PostgreSQL, Amadeus)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   Static    │  │  Reverse    │  │   Cost Controls         │  │
│  │  Policies   │  │   Proxy     │  │   (proxied)             │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │ (internal only)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Internal Services (not client-facing)            │
│                                                                   │
│  ┌──────────────────────────┐  ┌──────────────────────────────┐ │
│  │   Orchestrator (:8081)   │  │      Portal (:8082)          │ │
│  │   • LLM Routing          │  │   • Code Governance          │ │
│  │   • Dynamic Policies     │  │   • Customer Portal          │ │
│  │   • Cost Controls        │  │   • Git Providers            │ │
│  │   • Execution Replay     │  │                              │ │
│  └──────────────────────────┘  └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- Clients only need one URL (Agent endpoint)
- Agent routes requests to internal services automatically
- Orchestrator and Portal are internal - never exposed to clients

## Quick Start Examples

### Gateway Mode (For existing LLM integrations)

**Step 1: Pre-check before LLM call**
```bash
# Using OAuth2-style Basic authentication
curl -X POST "https://agent.getaxonflow.com/api/policy/pre-check" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'travel-app:your_client_secret' | base64)" \
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
  -H "Authorization: Basic $(echo -n 'travel-app:your_client_secret' | base64)" \
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
  -H "Authorization: Basic $(echo -n 'analytics-app:your_client_secret' | base64)" \
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
  -H "Authorization: Basic $(echo -n 'travel-planner:your_client_secret' | base64)" \
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
  -H "Authorization: Basic $(echo -n 'analytics-app:your_client_secret' | base64)" \
  -d '{
    "client_id": "analytics-app",
    "user_token": "eyJhbGciOiJIUzI1NiIs...",
    "connector": "postgres_main",
    "statement": "SELECT * FROM orders WHERE status = $1 LIMIT 10",
    "parameters": {"1": "completed"},
    "timeout": "10s"
  }'
```

### Dynamic Policy CRUD

All policy management goes through the Agent (Single Entry Point).

**List dynamic policies**
```bash
curl -X GET "https://agent.getaxonflow.com/api/v1/dynamic-policies" \
  -H "X-Org-ID: tenant-123"
```

**Create a dynamic policy**
```bash
curl -X POST "https://agent.getaxonflow.com/api/v1/dynamic-policies" \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: tenant-123" \
  -H "X-User-ID: admin@company.com" \
  -d '{
    "name": "Block PII Access",
    "description": "Prevent unauthorized access to PII",
    "type": "content",
    "category": "pii-protection",
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

**Test a dynamic policy**
```bash
curl -X POST "https://agent.getaxonflow.com/api/v1/dynamic-policies/pol_abc123/test" \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: tenant-123" \
  -d '{
    "query": "Show me the customer SSN",
    "user": {"email": "analyst@company.com", "role": "analyst"}
  }'
```

### Static Policy Management

Static policies (PII detection, SQL injection) are managed directly on the Agent.

**List static policies**
```bash
curl -X GET "https://agent.getaxonflow.com/api/v1/static-policies" \
  -H "X-Org-ID: tenant-123"
```

**Test a static policy pattern**
```bash
curl -X POST "https://agent.getaxonflow.com/api/v1/static-policies/test" \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: tenant-123" \
  -d '{
    "input": "My SSN is 123-45-6789",
    "policy_type": "pii"
  }'
```

### Health Checks

```bash
# Agent health (primary entry point)
curl https://agent.getaxonflow.com/health

# MCP connectors health
curl https://agent.getaxonflow.com/mcp/health
```

### Metrics

```bash
# Metrics (JSON)
curl https://agent.getaxonflow.com/metrics

# Prometheus format
curl https://agent.getaxonflow.com/prometheus
```

> **Note:** Internal service health (Orchestrator, Portal) is monitored via the Agent's health endpoint, which includes backend service status.

## API Endpoints Summary

All endpoints are accessed via the Agent (port 8080). The Agent proxies requests to internal services automatically.

### Agent API - Direct Routes (Port 8080)

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Health | `/health` | GET | Service health |
| Metrics | `/metrics` | GET | JSON metrics |
| Metrics | `/prometheus` | GET | Prometheus format |
| Proxy | `/api/request` | POST | Process LLM request |
| Proxy | `/api/clients` | GET/POST | Manage clients |
| Gateway | `/api/policy/pre-check` | POST | Pre-check request |
| Gateway | `/api/audit/llm-call` | POST | Audit LLM call |
| Static Policy | `/api/v1/static-policies` | GET/POST | List/create static policies |
| Static Policy | `/api/v1/static-policies/{id}` | GET/PUT/DELETE | CRUD static policy |
| Static Policy | `/api/v1/static-policies/test` | POST | Test pattern |
| Static Policy | `/api/v1/static-policies/effective` | GET | Get effective policies |
| MCP | `/mcp/connectors` | GET | List connectors |
| MCP | `/mcp/connectors/{name}/health` | GET | Connector health |
| MCP | `/mcp/resources/query` | POST | Execute query |
| MCP | `/mcp/tools/execute` | POST | Execute command |
| MCP | `/mcp/health` | GET | MCP health |

### Agent API - Proxied Routes (via Agent to Orchestrator)

These routes are accessed via Agent but proxied to Orchestrator internally.

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Dynamic Policy | `/api/v1/dynamic-policies` | GET/POST | List/create dynamic policies |
| Dynamic Policy | `/api/v1/dynamic-policies/{id}` | GET/PUT/DELETE | CRUD dynamic policy |
| Dynamic Policy | `/api/v1/dynamic-policies/{id}/test` | POST | Test policy |
| Dynamic Policy | `/api/v1/dynamic-policies/import` | POST | Bulk import |
| Dynamic Policy | `/api/v1/dynamic-policies/export` | GET | Bulk export |
| Connectors | `/api/v1/connectors` | GET | List marketplace connectors |
| Connectors | `/api/v1/connectors/{id}/install` | POST | Install connector |
| Connectors | `/api/v1/connectors/{id}/uninstall` | DELETE | Uninstall connector |
| Cost Controls | `/api/v1/budgets` | GET/POST | Manage budgets |
| Cost Controls | `/api/v1/budgets/{id}` | GET/PUT/DELETE | CRUD budget |
| Cost Controls | `/api/v1/usage` | GET | Get usage data |
| Execution Replay | `/api/v1/executions` | GET | List executions |
| Execution Replay | `/api/v1/executions/{id}` | GET | Get execution details |
| Execution Replay | `/api/v1/executions/{id}/replay` | POST | Replay execution |
| LLM Providers | `/api/v1/llm-providers` | GET | List providers |
| LLM Providers | `/api/v1/llm-providers/{id}` | GET/PUT | Manage provider |

### Agent API - Proxied Routes (via Agent to Portal)

These routes are accessed via Agent but proxied to Portal internally.

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Code Governance | `/api/v1/code-governance/*` | Various | Code governance APIs |
| Portal | `/api/v1/portal/*` | Various | Customer portal APIs |
| Git Providers | `/api/v1/git-providers/*` | Various | Git provider management |

### Internal Services (Not Client-Facing)

> **Note:** Orchestrator (8081) and Portal (8082) are internal services. Do not expose them directly to clients. All client requests should go through the Agent.

## Authentication

### OAuth2-Style Basic Authentication (Recommended)

Use Basic authentication with `clientId:clientSecret` credentials. Obtained from the AxonFlow dashboard.

```bash
# Basic auth with client credentials
-H "Authorization: Basic $(echo -n 'your_client_id:your_client_secret' | base64)"
```

**Note:** `clientSecret` is optional for community/self-hosted mode. `clientId` is recommended for request identification.

### User Token (user_token)

JWT token identifying the end user. Include in request body.

```json
{
  "user_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Organization Headers (Policy API)

Required for policy management endpoints:

```bash
-H "X-Org-ID: tenant-123"
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
