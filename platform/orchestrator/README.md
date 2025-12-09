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

### Policy Management
```
GET /api/v1/policies/dynamic
- List active dynamic policies

POST /api/v1/policies/test
- Test policy evaluation
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
docker-compose -f docker-compose.test.yml up
```

### Building
```bash
docker build -t axonflow-orchestrator .
```

## Deployment

### Docker
```bash
docker run -p 8081:8081 \
  -e DATABASE_URL=$DATABASE_URL \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  axonflow-orchestrator
```

### Kubernetes
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