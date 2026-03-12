# Workflow Control Plane

> "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."

The Workflow Control Plane provides governance gates for external orchestrators like LangChain, LangGraph, and CrewAI. Instead of modifying your orchestrator's code, you simply add checkpoint calls to AxonFlow before each step executes.

## Real-World Use Cases

### 1. Code Review Pipeline with GPT-4 Restrictions

**Scenario:** Your engineering team runs a multi-step code review pipeline using LangGraph. However, compliance requires that GPT-4 cannot be used for reviewing code that touches financial modules.

```
Step 1: Parse PR → Step 2: Identify affected modules → Step 3: Generate review
                                                              ↓
                                                    [AxonFlow Gate Check]
                                                    Policy: Block GPT-4 for financial code
```

**Solution:** Add a step gate before the "Generate review" step. AxonFlow evaluates policies and blocks if the affected modules include financial code and the model is GPT-4.

### 2. Data Pipeline with PII Detection

**Scenario:** An analytics team runs customer data transformations using CrewAI agents. Before any LLM processes customer data, you need to ensure no PII (credit cards, SSNs) is passed to external APIs.

**Solution:** Each step gate call includes the `step_input`. AxonFlow's PII detection policy evaluates the input and blocks the step if critical PII is detected, with the specific policy match returned in `policiesMatched`.

### 3. Deployment Workflow with Human Approval

**Scenario:** Your CI/CD pipeline uses LangChain to generate deployment configurations. Production deployments require manager approval before execution.

**Solution:** Configure a policy with `require_approval` action for steps where `step_type == "connector_call"` and `step_name contains "production"`. AxonFlow returns an approval URL, and the workflow pauses until a manager approves via the Enterprise Portal.

### 4. Multi-Model Routing with Cost Controls

**Scenario:** Your customer service bot uses different models for different query types. You want to enforce that expensive models (GPT-4, Claude Opus) are only used for complex queries, not simple FAQs.

**Solution:** Step gates include `model` and `provider` fields. Policies can enforce routing rules based on query classification, blocking expensive models for queries tagged as simple.

## Overview

External orchestrators (LangChain, LangGraph, CrewAI) are great at workflow execution, but enterprises need governance controls. The Workflow Control Plane solves this by providing:

1. **Step Gates** - Policy checkpoints before each workflow step
2. **Decision Types** - Allow, block, or require approval
3. **Policy Integration** - Reuses AxonFlow's policy engine
4. **Audit Trail** - Every step decision is recorded

## Quick Start

### 1. Start AxonFlow

```bash
docker compose up -d
```

### 2. Create a Workflow

```bash
curl -X POST http://localhost:8080/api/v1/workflows \
  -H "Content-Type: application/json" \
  -d '{
    "workflow_name": "code-review-pipeline",
    "source": "langgraph"
  }'
```

> **Note:** `total_steps` is deprecated. Omit it — the server automatically sets it to the actual step count when the workflow completes, aborts, or fails.

Response:
```json
{
  "workflow_id": "wf_abc123",
  "workflow_name": "code-review-pipeline",
  "status": "in_progress"
}
```

### 3. Check Step Gate

Before executing each step, check if it's allowed:

```bash
curl -X POST http://localhost:8080/api/v1/workflows/wf_abc123/steps/step-1/gate \
  -H "Content-Type: application/json" \
  -d '{
    "step_name": "Generate Code",
    "step_type": "llm_call",
    "model": "gpt-4",
    "provider": "openai"
  }'
```

Response (allowed):
```json
{
  "decision": "allow",
  "step_id": "step-1"
}
```

Response (blocked):
```json
{
  "decision": "block",
  "step_id": "step-1",
  "reason": "GPT-4 not allowed in production",
  "policy_ids": ["policy_gpt4_block"]
}
```

### 4. Complete Workflow

```bash
curl -X POST http://localhost:8080/api/v1/workflows/wf_abc123/complete
```

## SDK Integration

### Python

```python
from axonflow import AxonFlow
from axonflow.workflow import (
    CreateWorkflowRequest,
    StepGateRequest,
    StepType,
    GateDecision,
)

async with AxonFlow(endpoint="http://localhost:8080") as client:
    # Create workflow
    workflow = await client.create_workflow(
        CreateWorkflowRequest(
            workflow_name="code-review-pipeline",
            source="langgraph"
        )
    )

    # Check gate before each step
    gate = await client.step_gate(
        workflow_id=workflow.workflow_id,
        step_id="step-1",
        request=StepGateRequest(
            step_name="Generate Code",
            step_type=StepType.LLM_CALL,
            model="gpt-4"
        )
    )

    if gate.is_allowed():
        # Execute your step
        result = execute_step()
        await client.mark_step_completed(workflow.workflow_id, "step-1")
    elif gate.is_blocked():
        print(f"Blocked: {gate.reason}")

    # Complete workflow
    await client.complete_workflow(workflow.workflow_id)
```

### LangGraph Adapter

For LangGraph workflows, use the specialized adapter:

```python
from axonflow import AxonFlow
from axonflow.adapters import AxonFlowLangGraphAdapter

async with AxonFlow(endpoint="http://localhost:8080") as client:
    adapter = AxonFlowLangGraphAdapter(client, "my-workflow")

    # Start workflow
    await adapter.start_workflow()

    # Before each LangGraph node
    if await adapter.check_gate("generate", "llm_call", model="gpt-4"):
        result = await generate_code(state)
        await adapter.step_completed("generate")

    # Complete workflow
    await adapter.complete_workflow()
```

### MCP Tool Interceptor (MultiServerMCPClient)

When using LangGraph's `MultiServerMCPClient` from `langchain-mcp-adapters`, use `mcp_tool_interceptor()` to wrap every MCP tool call with AxonFlow input/output policy enforcement:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from axonflow import AxonFlow
from axonflow.adapters import AxonFlowLangGraphAdapter, MCPInterceptorOptions

async with AxonFlow(endpoint="http://localhost:8080") as client:
    adapter = AxonFlowLangGraphAdapter(client, "my-workflow")

    mcp_client = MultiServerMCPClient(
        {"lookup": {"url": "http://localhost:8000/mcp", "transport": "http"}},
        tool_interceptors=[adapter.mcp_tool_interceptor()],
    )
    tools = await mcp_client.get_tools()
```

Use `MCPInterceptorOptions` to customise connector type derivation or operation:

```python
opts = MCPInterceptorOptions(
    connector_type_fn=lambda req: req.server_name,  # default: "{server_name}.{tool_name}"
    operation="query",  # default: "execute"
)
tool_interceptors=[adapter.mcp_tool_interceptor(opts)]
```

The interceptor enforces `mcp_check_input → handler → mcp_check_output`, raises `PolicyViolationError` on block, and automatically substitutes `redacted_data` when output redaction is applied.

### Go

```go
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint: "http://localhost:8080",
})

// Create workflow
workflow, _ := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
    WorkflowName: "code-review-pipeline",
    Source:       axonflow.WorkflowSourceLangGraph,
})

// Check gate
gate, _ := client.StepGate(workflow.WorkflowID, "step-1", axonflow.StepGateRequest{
    StepName: "Generate Code",
    StepType: axonflow.StepTypeLLMCall,
    Model:    "gpt-4",
})

if gate.IsAllowed() {
    // Execute step
    client.MarkStepCompleted(workflow.WorkflowID, "step-1", nil)
}

client.CompleteWorkflow(workflow.WorkflowID)
```

### TypeScript

```typescript
import { AxonFlow } from "@axonflow/sdk";

const axonflow = new AxonFlow({ endpoint: "http://localhost:8080" });

// Create workflow
const workflow = await axonflow.createWorkflow({
  workflowName: "code-review-pipeline",
  source: "langgraph",
});

// Check gate
const gate = await axonflow.stepGate(workflow.workflowId, "step-1", {
  stepName: "Generate Code",
  stepType: "llm_call",
  model: "gpt-4",
});

if (gate.decision === "allow") {
  // Execute step
  await axonflow.markStepCompleted(workflow.workflowId, "step-1");
}

await axonflow.completeWorkflow(workflow.workflowId);
```

### Java

```java
AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
    .endpoint("http://localhost:8080")
    .build());

// Create workflow
CreateWorkflowResponse workflow = client.createWorkflow(
    CreateWorkflowRequest.builder()
        .workflowName("code-review-pipeline")
        .source(WorkflowSource.LANGGRAPH)
        .build()
);

// Check gate
StepGateResponse gate = client.stepGate(
    workflow.getWorkflowId(),
    "step-1",
    StepGateRequest.builder()
        .stepName("Generate Code")
        .stepType(StepType.LLM_CALL)
        .model("gpt-4")
        .build()
);

if (gate.isAllowed()) {
    // Execute step
    client.markStepCompleted(workflow.getWorkflowId(), "step-1", null);
}

client.completeWorkflow(workflow.getWorkflowId());
```

## Gate Decisions

| Decision | Description | Action |
|----------|-------------|--------|
| `allow` | Step is allowed to proceed | Execute the step |
| `block` | Step is blocked by policy | Skip or abort workflow |
| `require_approval` | Human approval required | Wait for approval (Enterprise) |

## Step Types

| Type | Description | Example |
|------|-------------|---------|
| `llm_call` | LLM API call | OpenAI, Anthropic, Bedrock |
| `tool_call` | Tool/function execution | Code execution, file operations |
| `connector_call` | MCP connector call | Database, API integrations |
| `human_task` | Human-in-the-loop task | Manual review, approval |

## Workflow Sources

| Source | Description |
|--------|-------------|
| `langgraph` | LangGraph workflow |
| `langchain` | LangChain workflow |
| `crewai` | CrewAI workflow |
| `external` | Other external orchestrator |

## Policy Configuration

Create policies with `scope: workflow` to control step execution:

### Block Specific Models

```json
{
  "name": "block-gpt4-in-workflows",
  "scope": "workflow",
  "conditions": {
    "step_type": "llm_call",
    "model": "gpt-4"
  },
  "action": "block",
  "reason": "GPT-4 not allowed in production workflows"
}
```

### Require Approval for Deployments

```json
{
  "name": "require-approval-for-deploy",
  "scope": "workflow",
  "conditions": {
    "step_type": "connector_call",
    "step_name": "deploy"
  },
  "action": "require_approval",
  "reason": "Deployment steps require human approval"
}
```

### Block PII in Step Inputs

```json
{
  "name": "block-pii-in-workflow-inputs",
  "scope": "workflow",
  "conditions": {
    "step_input.contains_pii": true
  },
  "action": "block",
  "reason": "PII detected in workflow step input"
}
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/workflows` | Create workflow |
| GET | `/api/v1/workflows/{id}` | Get workflow status |
| POST | `/api/v1/workflows/{id}/steps/{step_id}/gate` | Check step gate |
| POST | `/api/v1/workflows/{id}/steps/{step_id}/complete` | Mark step completed |
| POST | `/api/v1/workflows/{id}/complete` | Complete workflow |
| POST | `/api/v1/workflows/{id}/abort` | Abort workflow |
| POST | `/api/v1/workflows/{id}/fail` | Fail workflow with error |
| POST | `/api/v1/workflows/{id}/resume` | Resume workflow |
| GET | `/api/v1/workflows` | List workflows |

## Best Practices

### 1. Use Descriptive Step Names

```python
# Good
await adapter.check_gate("generate_code", "llm_call")
await adapter.check_gate("review_code", "tool_call")
await adapter.check_gate("deploy_to_staging", "connector_call")

# Bad
await adapter.check_gate("step1", "llm_call")
await adapter.check_gate("step2", "tool_call")
```

### 2. Always Handle Block Decisions

```python
gate = await client.step_gate(...)

if gate.is_blocked():
    # Log the reason
    logger.warning(f"Step blocked: {gate.reason}")
    # Abort the workflow
    await client.abort_workflow(workflow_id, gate.reason)
    return
```

### Fail vs Abort

Use `failWorkflow()` when an error condition occurs (e.g., a step throws an exception, an LLM call returns invalid output). Use `abortWorkflow()` when manually cancelling a workflow that hasn't errored.

```python
# Abort: manual cancellation
await client.abort_workflow(workflow_id, "No longer needed")

# Fail: error condition
await client.fail_workflow(workflow_id, "Step 3 timed out after 60s")
```

After failing, the workflow status becomes `failed` and cannot be resumed.

### 3. Use Context Manager for Cleanup

```python
async with AxonFlowLangGraphAdapter(client, "my-workflow") as adapter:
    await adapter.start_workflow()
    # If exception occurs, workflow is automatically aborted
    # If successful, workflow is automatically completed
```

### 4. Include Relevant Metadata

```python
workflow = await client.create_workflow(
    CreateWorkflowRequest(
        workflow_name="code-review-pipeline",
        metadata={
            "environment": "production",
            "team": "engineering",
            "triggered_by": "github-action"
        }
    )
)
```

## Community vs Enterprise

| Feature | Community | Enterprise |
|---------|-----------|------------|
| Step gates (allow/block) | Yes | Yes |
| Policy evaluation | Yes | Yes |
| SDK support (4 languages) | Yes | Yes |
| LangGraph adapter | Yes | Yes |
| `require_approval` action | Returns decision | Routes to Portal HITL |
| Org-level policies | No | Yes |
| Cross-workflow analytics | No | Yes |

## Troubleshooting

### Gate Returns "allow" When Expected to Block

1. Check if the policy exists and is enabled
2. Verify the policy scope is `workflow`
3. Check if conditions match the step request

### Workflow Stuck in "in_progress"

1. Ensure you call `complete_workflow()` or `abort_workflow()`
2. Check for unhandled exceptions in your code
3. Use the context manager for automatic cleanup

### Connection Refused

1. Ensure AxonFlow Agent is running: `docker compose ps`
2. Check the endpoint URL matches your configuration
3. Verify network connectivity

## Examples

See the complete examples in `examples/workflow-control/`:

- `http/workflow-control.sh` - HTTP/curl example
- `go/main.go` - Go SDK example
- `python/main.py` - Python SDK example
- `python/langgraph_example.py` - LangGraph adapter example
- `typescript/index.ts` - TypeScript SDK example
- `java/WorkflowControl.java` - Java SDK example

## Related

- [Architecture Decision Record (ADR-028)](../../technical-docs/architecture-decisions/ADR-028-workflow-control-plane.md)
- [API Specification](../api/orchestrator-api.yaml)
- [Policy Configuration](./policies.md)
