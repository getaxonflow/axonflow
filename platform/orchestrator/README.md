# AxonFlow Orchestrator
> Deprecated in v11.0.0: the legacy policy write routes answer 409 LEGACY_POLICY_WRITE_FROZEN on an application-role deployment; use the typed policy routes instead. This material is rewritten or deleted in v11.1.0.


The intelligent orchestration layer of the AxonFlow platform that handles policy enforcement on the anchored engine, multi-LLM routing, and response processing.

> **v11:** the anchored policy engine (ADR-065) decides this service's requests, workflow steps, multi-agent plan steps and LLM responses from the typed policies in force, and a stored dynamic (tenant) policy decides none of them. The dynamic policies can no longer be written either: `migrations/core/172` makes the legacy policy tables read-only to the application roles, the write routes below answer `409 LEGACY_POLICY_WRITE_FROZEN`, and policy is authored through the typed policy routes (ADR-065) listed under [Typed Policy Authoring](#typed-policy-authoring-adr-065-every-edition).

## Overview

The AxonFlow Orchestrator is the core intelligence engine that:
- Routes requests to appropriate LLM providers based on cost, performance, and capabilities
- Decides each request, workflow step and multi-agent plan step on the anchored policy engine (ADR-065)
- Performs response filtering and PII redaction
- Maintains comprehensive audit logs
- Handles failover and load balancing across providers

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  AxonFlow Agent │────▶│  AxonFlow Orchestrator │────▶│  LLM Providers  │
│                 │     │                        │     │                 │
│ Static Policies │     │  • Policy Decisions    │     │ • OpenAI        │
│ Authentication  │     │  • LLM Routing         │     │ • Anthropic     │
│                 │     │  • Response Processing │     │ • Local Models  │
└─────────────────┘     │  • Audit Logging       │     └─────────────────┘
                        └──────────────────────┘
                                    │
                        ┌───────────▼────────────┐
                        │   AxonFlow Storage     │
                        │   • Audit Logs         │
                        │   • Policy Cache       │
                        │   • Metrics            │
                        └────────────────────────┘
```

## Key Components

### 1. Request Router
- Intelligent routing based on query type, cost, and performance
- Provider health monitoring and automatic failover
- Load balancing across multiple provider instances

### 2. Request and Step Decisions
- ONE anchored decision per request on `/api/v1/process` and `/api/v1/plan/execute`, and per gated workflow
  or multi-agent plan step, from the typed policies in force (ADR-065)
- A stored dynamic policy decides nothing: its content detector supplies a fact the decision reads, and its
  routing hints steer a request the decision admitted
- A request answered in one round trip cannot be held, so a challenge withholds it (`approval_required`); a
  workflow step or plan step can be held for approval

### 3. Response Processor
- ONE anchored decision per LLM response, on the `orchestrator_response` plane, evaluated for the client
  credential the agent forwarded rather than for the end user
- Three outcomes, and only these three: the response as the provider sent it, the response masked, or the
  response withheld. A pass that cannot decide withholds and names its cause; it never releases by default
- Detectors produce the FACTS that decision reads. They author no verdict: a detector saying "blocked"
  changes nothing on its own
- Response enrichment with metadata

The decision travels where a reader can see it: `engine`, `subject_type`, `policy_bundle` and `verdict` on
the API response, and the same members on the canonical plane=llm audit row. A withheld response carries no
content: the body and the audit row both carry a substitute. See PRD v11 §1.1 and ADR-065.

### 4. Audit Logger
- Complete request/response logging
- Policy decision tracking
- Performance metrics collection

## API Endpoints

### Request Processing
```
POST /api/v1/process
- Processes requests from AxonFlow Agent
- Decides the request on the anchored policy engine; a withheld request answers 403
- Routes to appropriate LLM
- Returns filtered response
```

### Health & Status
```
GET /health
- Service health check

GET /api/v1/providers/status
- Status of all LLM providers
- Current routing weights
- Performance metrics
```

### Tenant Policies (ADR-024)
```
GET    /api/v1/tenant-policies           - List tenant policies
POST   /api/v1/tenant-policies           - Create a policy (v11: 409 LEGACY_POLICY_WRITE_FROZEN)
GET    /api/v1/tenant-policies/{id}      - Get policy by ID
PUT    /api/v1/tenant-policies/{id}      - Update policy (v11: 409 LEGACY_POLICY_WRITE_FROZEN)
DELETE /api/v1/tenant-policies/{id}      - Delete policy (v11: 409 LEGACY_POLICY_WRITE_FROZEN)
GET    /api/v1/tenant-policies/effective - Get effective policies
POST   /api/v1/tenant-policies/{id}/test - Test policy evaluation
```

`/api/v1/dynamic-policies` is the deprecated spelling of the same routes and is still served. The full reference, including import and export, is [`policy-api.yaml`](../../docs/api/policy-api.yaml). A deployment connecting as the database owner (`AXONFLOW_DB_USE_APP_ROLE=false`) is not bound by the v11 revoke.

### Typed Policy Authoring (ADR-065, every edition)
```
GET  /api/v1/typed-policies/edition  - What this deployment may author
POST /api/v1/typed-policies/validate - Validate a candidate document
POST /api/v1/typed-policies/publish  - Publish a document as a signed artifact
POST /api/v1/typed-policies/activate - Activate a published digest
GET  /api/v1/typed-policies/active   - The document currently in force
GET  /api/v1/typed-policies/active/summary - How many policies are in force, and whose
GET  /api/v1/typed-policies/system   - The platform's own controls, read-only
```

The v11 policy write path; specified in [`orchestrator-api.yaml`](../../docs/api/orchestrator-api.yaml).

### LLM Providers
```
GET  /api/v1/llm-providers          - List configured providers
POST /api/v1/llm-providers          - Add provider
GET  /api/v1/llm-providers/{name}   - Get provider details
PUT  /api/v1/llm-providers/{name}   - Update provider config
GET  /api/v1/llm-providers/status   - All providers health status
GET  /api/v1/llm-providers/routing  - Current routing weights
```

### Cost Controls
```
POST /api/v1/budgets        - Create budget
GET  /api/v1/budgets        - List budgets
GET  /api/v1/budgets/{id}   - Get budget
PUT  /api/v1/budgets/{id}   - Update budget
GET  /api/v1/usage          - Usage summary
GET  /api/v1/usage/records  - Detailed usage records
```

### Execution Replay
```
GET    /api/v1/executions           - List executions
GET    /api/v1/executions/{id}      - Get execution details
GET    /api/v1/executions/{id}/steps - Get execution steps
DELETE /api/v1/executions/{id}      - Delete execution
```

### Audit & Metrics
```
POST /api/v1/audit/search              - Search audit logs
GET  /api/v1/audit/tenant/{tenant_id}  - Tenant audit logs
GET  /api/v1/metrics                   - Service metrics
```

### Admin/Debugging (Legacy)
```
GET  /api/v1/policies/dynamic - List policies (legacy, use /api/v1/dynamic-policies)
POST /api/v1/policies/test    - Test policy evaluation
```

## Configuration

### Environment Variables
```bash
# Service Configuration
PORT=8081
ENV=production
LOG_LEVEL=info

# Database
DATABASE_URL=postgres://user:pass@host:5432/axonflow

# LLM Providers
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
LOCAL_LLM_ENDPOINT=http://localhost:11434

# Policy Configuration
POLICY_CACHE_TTL=300
DYNAMIC_POLICY_ENABLED=true
PII_REDACTION_ENABLED=true

# Audit Configuration
AUDIT_RETENTION_DAYS=90
AUDIT_BATCH_SIZE=100
```

## Development

### Local Setup
```bash
cd platform/orchestrator
go mod download
go run .
```

### Testing
```bash
# Unit tests
go test ./...

# Integration tests
docker compose -f docker-compose.test.yml up
```

### Building
```bash
docker build -t axonflow-orchestrator .
```

## Deployment

### Docker
```bash
# DEPLOYMENT_MODE selects the runtime security posture AND which database
# migrations are applied. It has no baked-in default in the image on purpose —
# see scripts/lint-deployment-mode.sh. An unset value resolves to the enterprise
# posture; an unrecognised one is a hard boot failure.
docker run -p 8081:8081 \
  -e DEPLOYMENT_MODE=${DEPLOYMENT_MODE:-community} \
  -e DATABASE_URL=$DATABASE_URL \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  axonflow-orchestrator
```

### Kubernetes

`DEPLOYMENT_MODE` must be set on the container. This manifest shipped without
an `env:` block at all, which since #3096 means the deployment runs the
enterprise posture by accident (#3170).

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: axonflow-orchestrator
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: orchestrator
        image: axonflow/orchestrator:latest
        env:
        - name: DEPLOYMENT_MODE
          value: in-vpc-enterprise
        ports:
        - containerPort: 8081
```

## Integration with AxonFlow Platform

The Orchestrator integrates with:
- **AxonFlow Agent**: Receives authenticated requests
- **AxonFlow Storage**: Stores audit logs and metrics
- **AxonFlow Monitor**: Provides metrics for monitoring
- **Admin Portal**: Policy configuration interface

## Performance Considerations

- Request processing: < 100ms overhead
- Policy evaluation: < 10ms per policy
- PII detection: < 50ms for typical responses
- Audit logging: Asynchronous batch processing

## Security

- All provider API keys encrypted at rest
- TLS for all external communications
- Request signing between Agent and Orchestrator
- No direct internet exposure (behind Agent)