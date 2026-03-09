# Workflow Control Plane Examples

> "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."

These examples demonstrate the **Workflow Control Plane** feature, which provides governance gates for external orchestrators like LangChain, LangGraph, and CrewAI.

## Overview

The Workflow Control Plane allows you to:

1. **Register workflows** from external orchestrators
2. **Check step gates** before each workflow step
3. **Apply policies** at step transitions (allow/block/require_approval)
4. **Track workflow lifecycle** (complete/abort)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  External Orchestrator                          │
│              (LangChain / LangGraph / CrewAI)                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
 ┌──────────┐       ┌──────────┐       ┌──────────┐
 │  Step 1  │──────▶│  Step 2  │──────▶│  Step 3  │
 │   Gate   │       │   Gate   │       │   Gate   │
 └────┬─────┘       └────┬─────┘       └────┬─────┘
      │                  │                  │
      ▼                  ▼                  ▼
 ┌──────────────────────────────────────────────┐
 │              AxonFlow Agent                   │
 │  POST /api/v1/workflows/{id}/steps/{sid}/gate │
 └──────────────────────────┬───────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────┐
 │          AxonFlow Orchestrator               │
 │   • Policy Evaluation (scope: workflow)      │
 │   • HITL Routing (require_approval)          │
 │   • Audit Logging                            │
 └──────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- AxonFlow Agent running at `http://localhost:8080`
- AxonFlow Orchestrator running at `http://localhost:8081`

### Run Examples

```bash
# HTTP/curl
cd http && ./workflow-control.sh

# Go
cd go && go run main.go

# Python
cd python && pip install -r requirements.txt && python main.py

# TypeScript
cd typescript && npm install && npx tsx index.ts

# Java
cd java && mvn compile exec:java -Dexec.mainClass="com.getaxonflow.examples.WorkflowControl"
```

## Examples

### 1. Basic Workflow (All Languages)

The main examples demonstrate the core workflow:

```python
# 1. Create a workflow
workflow = await client.create_workflow(
    workflow_name="code-review-pipeline",
    source="langgraph"
)

# 2. Check gate before each step
gate = await client.step_gate(
    workflow_id=workflow.workflow_id,
    step_id="step-1",
    step_name="Generate Code",
    step_type="llm_call",
    model="claude-haiku-4-5-20251001",
    provider="anthropic"
)

if gate.decision == "allow":
    # Execute your step
    result = run_step()

    # Mark step completed
    await client.mark_step_completed(
        workflow_id=workflow.workflow_id,
        step_id="step-1"
    )

elif gate.decision == "block":
    print(f"Blocked: {gate.reason}")

elif gate.decision == "require_approval":
    print(f"Approval needed: {gate.approval_url}")

# 3. Complete the workflow
await client.complete_workflow(workflow.workflow_id)
```

### 2. LangGraph Adapter (Python)

For Python users with LangGraph workflows, use the specialized adapter:

```python
from axonflow import AxonFlow
from axonflow.adapters import AxonFlowLangGraphAdapter

async with AxonFlow(endpoint="http://localhost:8080") as client:
    adapter = AxonFlowLangGraphAdapter(client, "my-workflow")

    # Start workflow
    await adapter.start_workflow()

    # Before each node
    if await adapter.check_gate("generate", "llm_call", model="claude-haiku-4-5-20251001", provider="anthropic"):
        result = await generate_code(state)
        await adapter.step_completed("generate")

    # Complete workflow
    await adapter.complete_workflow()
```

See `python/langgraph_example.py` for a full example.

## Gate Decisions

| Decision | Description |
|----------|-------------|
| `allow` | Step proceeds immediately |
| `block` | Step is blocked with reason |
| `require_approval` | Step requires human approval (Enterprise) |

## Step Types

| Type | Description |
|------|-------------|
| `llm_call` | LLM API call (OpenAI, Anthropic, etc.) |
| `tool_call` | Tool/function execution |
| `connector_call` | MCP connector call |
| `human_task` | Human-in-the-loop task |

## Workflow Sources

| Source | Description |
|--------|-------------|
| `langgraph` | LangGraph workflow |
| `langchain` | LangChain workflow |
| `crewai` | CrewAI workflow |
| `external` | Other external orchestrator |

## Policy Configuration

Create policies that match workflow steps:

```json
{
  "name": "block-gpt4-in-workflows",
  "scope": "workflow",
  "conditions": {
    "step_type": "llm_call",
    "model": "gpt-4"
  },
  "action": "block",
  "reason": "GPT-4 not allowed in workflows"
}
```

## SSE Streaming

WCP supports real-time execution monitoring via Server-Sent Events (SSE). Use `streamExecutionStatus()` to receive live updates as workflow steps are evaluated and completed.

```python
# Stream execution status updates in real time
async for event in client.stream_execution_status(workflow_id=workflow.workflow_id):
    print(f"Step: {event.step_id}, Status: {event.status}")
```

| Feature | Edition | Notes |
|---------|---------|-------|
| SSE streaming (`streamExecutionStatus`) | Community | 5 concurrent connections per tenant |

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/workflows` | Create workflow |
| GET | `/api/v1/workflows/{id}` | Get workflow status |
| GET | `/api/v1/workflows/{id}/stream` | SSE stream for real-time execution status |
| POST | `/api/v1/workflows/{id}/steps/{step_id}/gate` | Check step gate |
| POST | `/api/v1/workflows/{id}/steps/{step_id}/complete` | Mark step completed |
| POST | `/api/v1/workflows/{id}/complete` | Complete workflow |
| POST | `/api/v1/workflows/{id}/abort` | Abort workflow |
| POST | `/api/v1/workflows/{id}/resume` | Resume workflow |
| GET | `/api/v1/workflows` | List workflows |

## Next Steps

- [Workflow Control Plane Guide](../../docs/guides/workflow-control-plane.md)
- [Policy Configuration](../../docs/guides/policies.md)
- [LangGraph Integration](../../docs/integrations/langgraph.md)
