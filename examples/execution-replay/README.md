# Decision & Execution Replay Examples

This directory contains examples demonstrating how to use the AxonFlow Decision & Execution Replay API with the AxonFlow SDKs.

## Overview

The Decision & Execution Replay feature captures every step of workflow execution and policy decisions for:
- **Debugging**: Step-by-step inspection of workflow execution
- **Auditing**: Complete audit trail of AI decisions
- **Compliance**: Export execution data for regulatory requirements

## SDK Methods

All examples use the official AxonFlow SDKs which provide native methods for the Decision & Execution Replay API:

| SDK | Methods |
|-----|---------|
| **Go** | `ListExecutions()`, `GetExecution()`, `GetExecutionSteps()`, `GetExecutionTimeline()`, `ExportExecution()`, `DeleteExecution()` |
| **Python** | `list_executions()`, `get_execution()`, `get_execution_steps()`, `get_execution_timeline()`, `export_execution()`, `delete_execution()` |
| **TypeScript** | `listExecutions()`, `getExecution()`, `getExecutionSteps()`, `getExecutionTimeline()`, `exportExecution()`, `deleteExecution()` |
| **Java** | `listExecutions()`, `getExecution()`, `getExecutionSteps()`, `getExecutionTimeline()`, `exportExecution()`, `deleteExecution()` |

## Running Examples

### Go

```bash
cd go
go mod tidy
go run main.go
```

### Python

```bash
cd python
pip install -r requirements.txt
python main.py
```

### TypeScript

```bash
cd typescript
npm install
npm run dev
```

### Java

```bash
cd java
mvn compile exec:java
```

### HTTP/curl

For raw HTTP API examples without SDK:

```bash
cd http
./examples.sh
```

## SDK Configuration

All SDKs accept an `orchestratorUrl` (or `orchestrator_url`) configuration option:

```go
// Go
client, _ := axonflow.NewClient(axonflow.AxonFlowConfig{
    AgentURL:        "http://localhost:8080",
    OrchestratorURL: "http://localhost:8081", // For Execution Replay API
})
```

```python
# Python
client = AxonFlow.sync(
    agent_url="http://localhost:8080",
    orchestrator_url="http://localhost:8081",  # For Execution Replay API
)
```

```typescript
// TypeScript
const client = new AxonFlow({
    endpoint: "http://localhost:8080",
    orchestratorEndpoint: "http://localhost:8081", // For Execution Replay API
});
```

```java
// Java
AxonFlowConfig config = AxonFlowConfig.builder()
    .agentUrl("http://localhost:8080")
    .orchestratorUrl("http://localhost:8081") // For Execution Replay API
    .build();
```

If not specified, the SDK defaults to the agent URL with port 8081.

## API Reference

The SDK methods correspond to these REST API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/executions` | List workflow executions |
| GET | `/api/v1/executions/{id}` | Get execution details with all steps |
| GET | `/api/v1/executions/{id}/steps` | Get all steps for an execution |
| GET | `/api/v1/executions/{id}/timeline` | Get execution timeline view |
| GET | `/api/v1/executions/{id}/export` | Export execution for compliance |
| DELETE | `/api/v1/executions/{id}` | Delete an execution |

## Query Options

### ListExecutionsOptions

| Option | Description |
|--------|-------------|
| `limit` | Maximum results (default: 50, max: 100) |
| `offset` | Pagination offset (default: 0) |
| `status` | Filter by status: pending, running, completed, failed |
| `workflowId` | Filter by workflow name |
| `startTime` | Filter by start time (RFC3339 format) |
| `endTime` | Filter by end time (RFC3339 format) |

### ExecutionExportOptions

| Option | Description |
|--------|-------------|
| `format` | Export format (default: json) |
| `includeInput` | Include step inputs (default: true) |
| `includeOutput` | Include step outputs (default: true) |
| `includePolicies` | Include policy events (default: true) |

## Data Model

### ExecutionSummary

```json
{
  "request_id": "req-123",
  "workflow_name": "customer-support",
  "status": "completed",
  "total_steps": 3,
  "completed_steps": 3,
  "started_at": "2025-01-01T10:00:00Z",
  "completed_at": "2025-01-01T10:00:05Z",
  "duration_ms": 5000,
  "total_tokens": 500,
  "total_cost_usd": 0.005,
  "org_id": "org-1",
  "tenant_id": "tenant-1"
}
```

### ExecutionSnapshot (Step)

```json
{
  "request_id": "req-123",
  "step_index": 0,
  "step_name": "classify-intent",
  "status": "completed",
  "started_at": "2025-01-01T10:00:00Z",
  "completed_at": "2025-01-01T10:00:01Z",
  "duration_ms": 1000,
  "provider": "anthropic",
  "model": "claude-3-5-sonnet",
  "tokens_in": 100,
  "tokens_out": 50,
  "cost_usd": 0.001,
  "policies_checked": ["pii-detection"],
  "policies_triggered": [],
  "input": {...},
  "output": {...}
}
```

### TimelineEntry

```json
{
  "step_index": 0,
  "step_name": "classify-intent",
  "status": "completed",
  "started_at": "2025-01-01T10:00:00Z",
  "completed_at": "2025-01-01T10:00:01Z",
  "duration_ms": 1000,
  "has_error": false,
  "has_approval": false
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AXONFLOW_AGENT_URL` | AxonFlow Agent URL | `http://localhost:8080` |
| `AXONFLOW_ORCHESTRATOR_URL` | Orchestrator URL for Execution Replay | `http://localhost:8081` |

## Related Documentation

- [API Reference](/docs/api/)
- [Workflow Engine](/docs/orchestration/)
- [Compliance Features](/docs/governance/)
