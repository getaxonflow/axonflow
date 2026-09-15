# AxonFlow API Documentation

This directory contains OpenAPI 3.0 specifications for all AxonFlow APIs.

## API Specifications

| File | Service | Description |
|------|---------|-------------|
| [`agent-api.yaml`](./agent-api.yaml) | Agent | Authentication, Gateway Mode, Decision Mode, MCP Connectors, MCP Server, System Policies (read-only in v11), HITL, Circuit Breaker, OTLP Ingest |
| [`orchestrator-api.yaml`](./orchestrator-api.yaml) | Orchestrator | LLM Routing, Multi-Agent Planning, Workflows, Audit & Compliance, Typed Policy Authoring (the v11 policy write path) |
| [`policy-api.yaml`](./policy-api.yaml) | Orchestrator (via Agent proxy) | Tenant policies (writes refused in v11), Templates, Simulation |
| [`masfeat-api.yaml`](./masfeat-api.yaml) | Orchestrator (via Agent proxy) | MAS FEAT compliance (Singapore) — **Enterprise only** |
| [`error-codes.md`](./error-codes.md) | All | Error code reference |

## Architecture Overview

AxonFlow uses a **Single Entry Point Architecture** (ADR-024). All client requests go through the Agent service, which proxies to internal services automatically.

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
      "provider": "openai",
      "strict_provider": false,
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

### Tenant Policies

All policy management goes through the Agent (Single Entry Point).

> **v11: policy is authored through `/api/v1/typed-policies`.** `migrations/core/172` makes the legacy policy tables read-only to the application roles, so creating, updating, deleting or importing a tenant policy answers `409 LEGACY_POLICY_WRITE_FROZEN`. The policies already stored are still listed, tested and evaluated. The typed authoring routes are specified in [`orchestrator-api.yaml`](./orchestrator-api.yaml) under Typed Policy Authoring. A deployment connecting as the database owner (`AXONFLOW_DB_USE_APP_ROLE=false`) is not bound by the revoke.

**List tenant policies**
```bash
curl -X GET "https://agent.getaxonflow.com/api/v1/tenant-policies" \
  -H "X-Tenant-ID: tenant-123"
```

**Creating a tenant policy** answers, in v11:
```json
{
  "error": {
    "code": "LEGACY_POLICY_WRITE_FROZEN",
    "message": "The legacy policy tables are read-only in v11: migrations/core/172 revoked write access from the application role, and this endpoint writes them. Author policies through the typed authoring route at /api/v1/typed-policies instead. Reads on this endpoint are unaffected."
  }
}
```

**Test a tenant policy**
```bash
curl -X POST "https://agent.getaxonflow.com/api/v1/tenant-policies/pol_abc123/test" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-123" \
  -d '{
    "query": "Show me the customer SSN",
    "user": {"email": "analyst@company.com", "role": "analyst"}
  }'
```

### System Policies

System policies (PII detection, SQL injection) are served directly by the Agent. In v11 they are read-only to the application roles like the tenant policies above; the pattern test and per-policy overrides are unaffected.

**List system policies**
```bash
curl -X GET "https://agent.getaxonflow.com/api/v1/system-policies" \
  -H "Authorization: Basic $(echo -n 'my-org:your_client_secret' | base64)"
```

**Test a system policy pattern**
```bash
curl -X POST "https://agent.getaxonflow.com/api/v1/system-policies/test" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'my-org:your_client_secret' | base64)" \
  -d '{
    "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    "inputs": ["My SSN is 123-45-6789", "no pii here"]
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
| System Policy | `/api/v1/system-policies` | GET/POST | List system policies; in v11 create answers `409 LEGACY_POLICY_WRITE_FROZEN` when the agent connects as an application role (its default) |
| System Policy | `/api/v1/system-policies/{id}` | GET/PUT/DELETE/PATCH | Get a system policy; in v11 update, delete and toggle answer `409 LEGACY_POLICY_WRITE_FROZEN` when the agent connects as an application role (its default) |
| System Policy | `/api/v1/system-policies/test` | POST | Test pattern |
| System Policy | `/api/v1/system-policies/effective` | GET | Get effective policies |
| System Policy | `/api/v1/system-policies/overrides` | GET | List tenant overrides |
| System Policy | `/api/v1/static-policies*` | (all of the above) | **Deprecated** spelling, still served. See [Deprecated path spellings](#deprecated-legacy-policy-routes-v11) |
| MCP | `/mcp/connectors` | GET | List connectors |
| MCP | `/mcp/connectors/{name}/health` | GET | Connector health |
| MCP | `/mcp/resources/query` | POST | Execute query |
| MCP | `/mcp/tools/execute` | POST | Execute command |
| MCP | `/mcp/health` | GET | MCP health |

## Deprecated legacy policy routes (v11)

In v11 the legacy policy routes are a **read-only, deprecated export surface**
(PRD §1.11): policy is read, authored and activated through
`/api/v1/typed-policies`, writes on the legacy routes answer
`409 LEGACY_POLICY_WRITE_FROZEN`, and the reads stay so an organization can see
and export its legacy rows after upgrading. v11.1 removes them once the SDKs
have moved to the typed route. The surface is every spelling of every legacy
family:

| Family | Paths |
|--------|-------|
| System policies | `/api/v1/system-policies*`, `/api/v1/static-policies*`, `/api/v1/policy-overrides` |
| Tenant policies | `/api/v1/tenant-policies*`, `/api/v1/dynamic-policies*` |
| Policy CRUD, test, simulation | `/api/v1/policies*` |
| Policy templates | `/api/v1/templates*` |

The v10.0.0 rename (`static` to `system`, `dynamic` to `tenant`) still holds:
the two spellings of a family are the same routes, with one handler per pair
and the same authentication, bodies and status codes. Both spellings are
deprecated in v11.

Every response the endpoint itself produces carries the signal, including an
authentication failure and a `409`:

```
Link: </api/v1/typed-policies>; rel="successor-version"
X-AxonFlow-Removed-In: v11.1
Deprecation: @<unix time of the v11.0.0 tag>
```

- `Deprecation` is the RFC 9745 structured date on which the deprecation took
  effect, the v11.0.0 tag. It is omitted on builds made before that date is
  set at release, never guessed. The v10 form `Deprecation: true` is retired.
- `Link` (RFC 8288) names the typed authoring route for every family.
- `X-AxonFlow-Removed-In` names the release that removes the surface. No
  registered header carries a release, and RFC 8594's `Sunset` is a date, so
  there is no `Sunset` until v11.1 has one.

All three headers are CORS-exposed on the agent, the orchestrator and the
portal, so a browser client can read them. Two responses do **not** carry the
signal, so do not treat its absence as proof a path is current: a `404` or
`405` for a path or method that matches no route, and a refusal produced in
front of the endpoint (the orchestrator's proxy-authentication gate, reached
only by bypassing the agent). `/api/v1/overrides` (ADR-044 session overrides)
is not part of this surface.

### Agent API - Proxied Routes (via Agent to Orchestrator)

These routes are accessed via Agent but proxied to Orchestrator internally.

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| Tenant Policy | `/api/v1/tenant-policies` | GET/POST | List tenant policies; create answers `409 LEGACY_POLICY_WRITE_FROZEN` in v11 |
| Tenant Policy | `/api/v1/tenant-policies/{id}` | GET/PUT/DELETE | Get a tenant policy; update and delete answer `409` in v11 |
| Tenant Policy | `/api/v1/tenant-policies/{id}/test` | POST | Test policy |
| Tenant Policy | `/api/v1/tenant-policies/{id}/versions` | GET | Version history |
| Tenant Policy | `/api/v1/tenant-policies/effective` | GET | Get effective policies |
| Tenant Policy | `/api/v1/tenant-policies/import` | POST | Bulk import (answers `409` in v11) |
| Tenant Policy | `/api/v1/tenant-policies/export` | GET | Bulk export |
| Tenant Policy | `/api/v1/dynamic-policies*` | (all of the above) | **Deprecated** spelling, still served. See [Deprecated path spellings](#deprecated-legacy-policy-routes-v11) |
| Typed Policy Authoring | `/api/v1/typed-policies/*` | GET/POST | The v11 policy write path; see `orchestrator-api.yaml` |
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

### Tenant Headers (Policy API)

Tenant-policy endpoints resolve the tenant from `X-Tenant-ID`
(stamped by the agent proxy from the authenticated identity when calls go
through the single entry point) and record the actor from `X-User-ID`:

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

Error response format (handler-written errors):
```json
{
  "success": false,
  "error": "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)"
}
```

Middleware-written errors (auth 401s, static-policy API) use a second envelope:
```json
{
  "error": { "code": 401, "message": "..." }
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
redocly build-docs masfeat-api.yaml -o masfeat-api.html
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
swagger-cli validate masfeat-api.yaml

# Lint with Spectral
npm install -g @stoplight/spectral-cli
spectral lint agent-api.yaml --ruleset ../../.spectral.yaml
spectral lint orchestrator-api.yaml --ruleset ../../.spectral.yaml
spectral lint policy-api.yaml --ruleset ../../.spectral.yaml
spectral lint masfeat-api.yaml --ruleset ../../.spectral.yaml
# CI (validate-openapi.yml) lints all four specs with a pinned spectral;
# see the workflow for the exact pinned versions.
```

## Related Resources

- [SDK Documentation](https://docs.getaxonflow.com/docs/sdk/overview)
- [Gateway Mode Guide](https://docs.getaxonflow.com/docs/sdk/gateway-mode)
- [Proxy Mode Guide](https://docs.getaxonflow.com/docs/sdk/proxy-mode)
- [MCP Connectors](https://docs.getaxonflow.com/docs/mcp/overview)
- [OpenAPI 3.0 Specification](https://spec.openapis.org/oas/v3.0.3)
