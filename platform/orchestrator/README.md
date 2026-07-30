# AxonFlow Orchestrator

The intelligent orchestration layer of the AxonFlow platform that handles dynamic policy enforcement, multi-LLM routing, and response processing.

## Overview

The AxonFlow Orchestrator is the core intelligence engine that:
- Routes requests to appropriate LLM providers based on cost, performance, and capabilities
- Applies dynamic policies based on content analysis
- Performs response filtering and PII redaction
- Maintains comprehensive audit logs
- Handles failover and load balancing across providers

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  AxonFlow Agent │────▶│  AxonFlow Orchestrator │────▶│  LLM Providers  │
│                 │     │                        │     │                 │
│ Static Policies │     │  • Dynamic Policies    │     │ • OpenAI        │
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

### 2. Dynamic Policy Engine
- Content-based policy evaluation
- Real-time risk assessment
- Custom policy rule execution

### 3. Response Processor
- PII detection in LLM responses
- Dynamic redaction based on user permissions
- Response enrichment with metadata

### 4. Audit Logger
- Complete request/response logging
- Policy decision tracking
- Performance metrics collection

## API Endpoints

### Request Processing
```
POST /api/v1/process
- Processes requests from AxonFlow Agent
- Applies dynamic policies
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

### Dynamic Policies (ADR-024)
```
GET    /api/v1/dynamic-policies           - List all dynamic policies
POST   /api/v1/dynamic-policies           - Create a dynamic policy
GET    /api/v1/dynamic-policies/{id}      - Get policy by ID
PUT    /api/v1/dynamic-policies/{id}      - Update policy
DELETE /api/v1/dynamic-policies/{id}      - Delete policy
GET    /api/v1/dynamic-policies/effective - Get effective policies
POST   /api/v1/dynamic-policies/{id}/test - Test policy evaluation
```

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