# Execution Viewer

**Last Updated:** April 2026

**Platform Version:** v5.0.0 | **SDK Version:** v5.0.0

AxonFlow provides multiple interfaces for inspecting workflow executions: the `axonctl` CLI, an embedded web UI, the REST API (via curl or SDK), and SDK clients in Go, Python, TypeScript, and Java.

## CLI: `axonctl executions`

### Setup

```bash
cd platform/cmd/axonctl
go build -o axonctl .
export AXONFLOW_ENDPOINT="http://localhost:8080"
export AXONFLOW_CLIENT_ID="your-org"
export AXONFLOW_CLIENT_SECRET="your-secret"
```

### Commands

#### List executions

```bash
axonctl executions list
axonctl executions list --status completed --limit 50
axonctl executions list --workflow-id my-workflow --format json
```

| Flag | Description | Default |
|------|-------------|---------|
| `--limit` | Max results | 20 |
| `--offset` | Pagination offset | 0 |
| `--status` | Filter: pending, running, completed, failed | (all) |
| `--workflow-id` | Filter by workflow name | (all) |
| `--format` | Output format: table, json | table |

#### Get execution details

```bash
axonctl executions get <execution-id>
axonctl executions get <execution-id> --format json
```

Shows the execution summary, all steps with timing and LLM details, and triggered policy events.

#### Replay execution

```bash
axonctl executions replay <execution-id>
axonctl executions replay <execution-id> --show-io
```

Interactive step-by-step replay. Press Enter to advance, `q` to quit. Steps are color-coded by status (green=completed, red=failed, yellow=running).

| Flag | Description | Default |
|------|-------------|---------|
| `--show-io` | Show full input/output for each step | false |

#### Export execution

```bash
axonctl executions export <execution-id>
axonctl executions export <execution-id> --output report.json --include-io
```

Downloads execution data as JSON for compliance and auditing.

| Flag | Description | Default |
|------|-------------|---------|
| `--output`, `-o` | Output file path | `execution-<id>.json` |
| `--include-io` | Include full input/output data | false |

## Embedded Web UI

AxonFlow includes a lightweight execution viewer at `/ui/executions/`, accessible through the agent.

### Access

```
http://localhost:8080/ui/executions/
```

The agent proxies UI requests to the orchestrator, which serves the static files. This follows the single-entry-point architecture where all user traffic goes through the agent.

### Features

**List view** (`/ui/executions/`)
- Table of all executions with ID, workflow, status, steps, duration, cost
- Filter by status and workflow name
- Pagination controls

**Detail view** (`/ui/executions/detail.html?id=<execution-id>`)
- Summary card with execution metadata
- Expandable step timeline with input/output, LLM details, and policy events
- JSON export download button

### Architecture

The UI uses vanilla JavaScript with Tailwind CSS (CDN). Static files are embedded in the Go binary via `embed.FS`, requiring no additional services or build steps.

Files:
- `platform/orchestrator/ui/static/index.html` - List view
- `platform/orchestrator/ui/static/detail.html` - Detail view
- `platform/orchestrator/ui/static/app.js` - Client-side logic
- `platform/orchestrator/ui/static/styles.css` - Custom styles
- `platform/orchestrator/ui/handler.go` - Go handler with embed.FS

### API Endpoints Used

The UI fetches data from the same REST API used by the SDKs:

| Endpoint | Used by |
|----------|---------|
| `GET /api/v1/executions` | List view |
| `GET /api/v1/executions/{id}` | Detail view |
| `GET /api/v1/executions/{id}/export` | Export button |

## Enterprise Portal

Enterprise license holders have access to the Customer Portal UI with dedicated pages for execution monitoring and approval management.

### Execution Timeline (`/executions`)

The enterprise portal provides a full-featured Execution Timeline page:

- Filter executions by type (MAP/WCP) and status
- Expandable rows showing the complete step timeline with color-coded status indicators
- Policy gate decisions visible per step (allow, block, require_approval)
- LLM usage details (model, provider, token counts, cost)
- Per-step and total cost tracking
- Collapsible JSON input/output for debugging

### Approval Dashboard (`/approvals`)

For workflows using HITL (human-in-the-loop) approval policies, the portal includes an Approval Dashboard:

- Queue of pending approval requests across all active workflows
- Policy context for each approval (matched policies, decision reason, step input)
- Approve or reject with required justification (audit trail)
- Live pending count badge in navigation
- Real-time queue refresh

The enterprise portal is available at your configured portal domain (e.g., `ecommerce-prod-us.getaxonflow.com`). See the [enterprise documentation](../enterprise/execution-timeline.md) for details.

## REST API (curl)

You can query execution data directly via the Agent REST API (port 8080). Use `X-Client-Id` and `X-Client-Secret` headers for authentication (alternatively, `Authorization: Basic` is supported).

### List executions

```bash
curl -s http://localhost:8080/api/v1/executions?limit=5 \
  -H "X-Client-Id: your-org" \
  -H "X-Client-Secret: your-secret"
```

Example response:

```json
{
  "executions": [
    {
      "execution_id": "exec_a1b2c3d4",
      "workflow_id": "data-analysis",
      "status": "completed",
      "total_steps": 3,
      "completed_steps": 3,
      "duration": "12s",
      "actual_cost_usd": 0.0412,
      "started_at": "2026-02-07T14:30:00Z",
      "completed_at": "2026-02-07T14:30:12Z"
    },
    {
      "execution_id": "exec_e5f6g7h8",
      "workflow_id": "summarize",
      "status": "failed",
      "total_steps": 2,
      "completed_steps": 1,
      "duration": "4s",
      "error": "policy violation: PII detected in request",
      "started_at": "2026-02-07T14:28:00Z",
      "completed_at": "2026-02-07T14:28:04Z"
    }
  ],
  "total": 142,
  "limit": 5,
  "offset": 0
}
```

### Get execution details

```bash
curl -s http://localhost:8080/api/v1/executions/exec_a1b2c3d4 \
  -H "X-Client-Id: your-org" \
  -H "X-Client-Secret: your-secret"
```

Example response:

```json
{
  "execution_id": "exec_a1b2c3d4",
  "workflow_id": "data-analysis",
  "status": "completed",
  "total_steps": 3,
  "completed_steps": 3,
  "progress_percent": 100.0,
  "duration": "12s",
  "actual_cost_usd": 0.0412,
  "steps": [
    {
      "step_id": "step_0_analyze",
      "step_name": "analyze",
      "step_type": "llm_call",
      "status": "completed",
      "duration": "5s",
      "model": "gpt-4o",
      "provider": "openai",
      "cost_usd": 0.0280
    },
    {
      "step_id": "step_1_transform",
      "step_name": "transform",
      "step_type": "action",
      "status": "completed",
      "duration": "1s"
    },
    {
      "step_id": "step_2_summarize",
      "step_name": "summarize",
      "step_type": "llm_call",
      "status": "completed",
      "duration": "6s",
      "model": "gpt-4o",
      "provider": "openai",
      "cost_usd": 0.0132
    }
  ],
  "started_at": "2026-02-07T14:30:00Z",
  "completed_at": "2026-02-07T14:30:12Z"
}
```

### Export execution

```bash
curl -s http://localhost:8080/api/v1/executions/exec_a1b2c3d4/export \
  -H "X-Client-Id: your-org" \
  -H "X-Client-Secret: your-secret" \
  -o execution-report.json
```

## SDK Examples

### Go

```go
package main

import (
    "fmt"
    "os"

    "github.com/getaxonflow/axonflow-sdk-go/v8"
)

func main() {
    client := axonflow.NewClient(axonflow.AxonFlowConfig{
        Endpoint:     os.Getenv("AXONFLOW_ENDPOINT"),
        ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
        ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
    })

    // List recent executions
    executions, err := client.Executions.List(axonflow.ListExecutionsRequest{
        Limit:  10,
        Status: "completed",
    })
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }

    for _, exec := range executions.Executions {
        fmt.Printf("[%s] %s - %s (%.4f USD)\n",
            exec.Status, exec.ExecutionID, exec.Duration, exec.ActualCostUSD)
    }

    // Get execution details
    detail, err := client.Executions.Get("exec_a1b2c3d4")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Execution %s: %d/%d steps completed\n",
        detail.ExecutionID, detail.CompletedSteps, detail.TotalSteps)
    for _, step := range detail.Steps {
        fmt.Printf("  %s: %s (%s)\n", step.StepName, step.Status, step.Duration)
    }
}
```

### Python

```python
import os
from axonflow import AxonFlow

client = AxonFlow(
    endpoint=os.environ["AXONFLOW_ENDPOINT"],
    client_id=os.environ["AXONFLOW_CLIENT_ID"],
    client_secret=os.environ["AXONFLOW_CLIENT_SECRET"],
)

# List recent executions
executions = client.executions.list(limit=10, status="completed")
for ex in executions:
    print(f"[{ex.status}] {ex.execution_id} - {ex.duration} ({ex.actual_cost_usd:.4f} USD)")

# Get execution details
detail = client.executions.get("exec_a1b2c3d4")
print(f"Execution {detail.execution_id}: {detail.completed_steps}/{detail.total_steps} steps")
for step in detail.steps:
    print(f"  {step.step_name}: {step.status} ({step.duration})")
```

### TypeScript

```typescript
import { AxonFlow } from '@axonflow/sdk';

const client = new AxonFlow({
  endpoint: process.env.AXONFLOW_ENDPOINT!,
  clientId: process.env.AXONFLOW_CLIENT_ID!,
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET!,
});

// List recent executions
const executions = await client.executions.list({ limit: 10, status: 'completed' });
for (const ex of executions) {
  console.log(`[${ex.status}] ${ex.executionId} - ${ex.duration} ($${ex.actualCostUsd?.toFixed(4)})`);
}

// Get execution details
const detail = await client.executions.get('exec_a1b2c3d4');
console.log(`Execution ${detail.executionId}: ${detail.completedSteps}/${detail.totalSteps} steps`);
for (const step of detail.steps ?? []) {
  console.log(`  ${step.stepName}: ${step.status} (${step.duration})`);
}
```

### Java

```java
import com.axonflow.sdk.AxonFlowClient;
import com.axonflow.sdk.model.Execution;

AxonFlowClient client = AxonFlowClient.builder()
    .endpoint(System.getenv("AXONFLOW_ENDPOINT"))
    .clientId(System.getenv("AXONFLOW_CLIENT_ID"))
    .clientSecret(System.getenv("AXONFLOW_CLIENT_SECRET"))
    .build();

// List recent executions
var executions = client.executions().list(10, "completed");
for (Execution ex : executions) {
    System.out.printf("[%s] %s - %s (%.4f USD)%n",
        ex.getStatus(), ex.getExecutionId(), ex.getDuration(), ex.getActualCostUsd());
}

// Get execution details
var detail = client.executions().get("exec_a1b2c3d4");
System.out.printf("Execution %s: %d/%d steps%n",
    detail.getExecutionId(), detail.getCompletedSteps(), detail.getTotalSteps());
for (var step : detail.getSteps()) {
    System.out.printf("  %s: %s (%s)%n", step.getStepName(), step.getStatus(), step.getDuration());
}
```

## Troubleshooting

### UI returns 404

1. Verify the agent is running and accessible at `http://localhost:8080`
2. Check that the orchestrator is reachable from the agent (the agent proxies UI requests)
3. Confirm the binary was built with embedded static files (`embed.FS`)

### Empty execution list

1. Ensure you have executed at least one workflow or plan
2. Verify your `X-Client-Id` / `X-Client-Secret` match a valid tenant
3. Check the time range filter in the UI (default: last 1 hour)

### Execution details show no steps

1. The execution may still be in `pending` state (steps populate when execution begins)
2. For WCP workflows, steps appear after gate checks complete
3. Check orchestrator logs for errors during step initialization

### CLI authentication errors

1. Verify `AXONFLOW_ENDPOINT`, `AXONFLOW_CLIENT_ID`, and `AXONFLOW_CLIENT_SECRET` are set
2. Ensure the endpoint is reachable: `curl http://localhost:8080/healthz`
3. Check that the license key has not expired
