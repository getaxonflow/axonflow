# Unified Execution Tracking Examples

These examples demonstrate how to use AxonFlow's **Unified Execution Tracking API** to monitor both MAP plans and WCP workflows with a consistent interface.

**Issue #1075 - EPIC #1074: Unified Workflow Infrastructure**

## Features Demonstrated

- Unified `ExecutionStatus` schema for MAP plans and WCP workflows
- `getExecutionStatus()` - Get status by execution ID
- `listUnifiedExecutions()` - List executions with filters
- `ExecutionHelpers` - Utility functions for working with execution data
- Real-time progress tracking with step-level details
- Cost tracking per step and total

## Prerequisites

- AxonFlow running (default: `http://localhost:8080`)
- SDK installed for your language (for SDK examples)

## Environment Variables

All examples support these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_AGENT_URL` | `http://localhost:8080` | AxonFlow Agent URL |
| `AXONFLOW_CLIENT_ID` | `demo` | Client ID for authentication |
| `AXONFLOW_CLIENT_SECRET` | `demo` | Client secret for authentication |

## Running the Examples

### HTTP (cURL)

```bash
cd http
chmod +x example.sh
./example.sh
```

### Python

```bash
cd python
pip install -r requirements.txt
python main.py
```

### Go

```bash
cd go
go run main.go
```

### TypeScript

```bash
cd typescript
npm install
npm start
```

### Java

```bash
cd java
mvn compile exec:java -Dexec.mainClass="com.getaxonflow.examples.ExecutionTrackingExample"
```

## What the Examples Do

Each example demonstrates the unified execution tracking API:

1. **Create a MAP plan** to generate an execution ID
2. **Track execution** using `getExecutionStatus()` with real-time progress updates
3. **Display step-level progress** using the unified `UnifiedStepStatus` format
4. **Show final results** including execution type, duration, and costs
5. **List executions** using `listUnifiedExecutions()` with type filtering

## Expected Output

```
AxonFlow Unified Execution Tracking Example - [Language]
=======================================================

Creating MAP plan...
Plan ID: plan_abc123
Execution ID: exec_xyz789

Tracking execution with unified API...
[1s] Type: map_plan, Status: pending, Progress: 0.0%
[2s] Type: map_plan, Status: running, Progress: 0.0%
  Step 0 (analyze): running
[3s] Type: map_plan, Status: running, Progress: 33.3%
  Step 0 (analyze): completed (2s)
  Step 1 (research): running
[5s] Type: map_plan, Status: running, Progress: 66.7%
  Step 0 (analyze): completed (2s)
  Step 1 (research): completed (3s)
  Step 2 (synthesize): running
[8s] Type: map_plan, Status: completed, Progress: 100.0%

Execution Complete!
-------------------------------------------------------
Execution Type: MAP Plan
Duration: 8s
Total Cost: $0.0420

Steps:
  1. analyze: completed (2s) - $0.0100 [llm_call]
  2. research: completed (3s) - $0.0200 [tool_call]
  3. synthesize: completed (3s) - $0.0120 [synthesis]

Listing recent MAP executions...
Found 15 MAP executions (showing 5)

=======================================================
Unified Execution Tracking Test: PASS
```

## Unified Execution Status Schema

Both MAP plans and WCP workflows return the same unified schema:

```json
{
  "execution_id": "exec_xyz789",
  "execution_type": "map_plan",
  "name": "Analyze data",
  "status": "running",
  "current_step_index": 1,
  "total_steps": 3,
  "progress_percent": 33.33,
  "started_at": "2026-01-24T10:00:00Z",
  "duration": "5s",
  "estimated_cost_usd": 0.05,
  "actual_cost_usd": 0.02,
  "steps": [
    {
      "step_id": "step_0_analyze",
      "step_index": 0,
      "step_name": "analyze",
      "step_type": "llm_call",
      "status": "completed",
      "started_at": "2026-01-24T10:00:00Z",
      "ended_at": "2026-01-24T10:00:02Z",
      "duration": "2s",
      "cost_usd": 0.01,
      "model": "gpt-4",
      "provider": "openai"
    },
    {
      "step_id": "step_1_research",
      "step_index": 1,
      "step_name": "research",
      "step_type": "tool_call",
      "status": "running",
      "started_at": "2026-01-24T10:00:02Z"
    }
  ],
  "tenant_id": "tenant_123",
  "org_id": "org_456",
  "user_id": "user_789",
  "created_at": "2026-01-24T10:00:00Z",
  "updated_at": "2026-01-24T10:00:05Z"
}
```

## Execution Types

| Type | Description |
|------|-------------|
| `map_plan` | Multi-Agent Planning execution |
| `wcp_workflow` | Workflow Control Plane execution |

## Execution Status Values

| Status | Description |
|--------|-------------|
| `pending` | Execution created but not started |
| `running` | Execution in progress |
| `completed` | Execution finished successfully |
| `failed` | Execution failed with error |
| `cancelled` | Execution cancelled by user |
| `aborted` | WCP workflow aborted |
| `expired` | MAP plan expired before execution |

## Step Types

| Type | Description |
|------|-------------|
| `llm_call` | LLM inference call |
| `tool_call` | External tool invocation |
| `connector_call` | MCP connector call |
| `human_task` | Human-in-the-loop task |
| `synthesis` | MAP result synthesis |
| `action` | Generic action step |
| `gate` | WCP policy gate evaluation |

## API Endpoints

### Get Execution Status

```http
GET /api/v1/executions/{execution_id}
```

### List Executions

```http
GET /api/v1/executions?execution_type=map_plan&status=completed&limit=10
```

## Learn More

- [Execution Tracking Guide](https://docs.getaxonflow.com/docs/orchestration/execution-viewer)
- [API Reference](https://docs.getaxonflow.com/docs/api/orchestrator-endpoints)
- [SDK Documentation](https://docs.getaxonflow.com/docs/sdk/overview)
