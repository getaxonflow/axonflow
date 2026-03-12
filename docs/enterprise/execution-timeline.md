# Execution Timeline (Customer Portal)

**Last Updated:** March 2026

**Platform Version:** v5.0.0 | **SDK Version:** v4.0.0

The Execution Timeline page provides enterprise customers with a centralized view of all MAP plan and WCP workflow executions. It surfaces real-time status, step-level timelines, policy gate decisions, LLM usage details, and per-step cost tracking directly within the Customer Portal.

## Overview

The Execution Timeline consolidates monitoring across both execution types (MAP plans and WCP workflows) into a single table with inline expansion for step-level detail. This replaces the need to query individual execution APIs or use the embedded community UI for production monitoring.

Key benefits:

- **Unified view** of MAP and WCP executions in a single sortable, filterable table
- **Step-level timeline** with color-coded status indicators and policy gate context
- **Cost visibility** at both execution and step level
- **Policy gate inspection** showing matched policies, block reasons, and approval status
- **LLM usage details** including model, provider, token counts, and per-step cost

## Access

The Execution Timeline is available at the `/executions` route within the Customer Portal.

```
https://{client}-{env}-{region}.getaxonflow.com/executions
```

For example:

```
https://ecommerce-prod-us.getaxonflow.com/executions
```

Authentication is handled by the portal session. Users must be logged in with valid organization credentials.

## Features

### Execution List

The main view displays a table of executions with the following columns:

| Column | Description |
|--------|-------------|
| Name | Execution name and ID |
| Type | `MAP` (Multi-Agent Plan) or `WCP` (Workflow Control Plane) |
| Status | Color-coded badge: pending, running, completed, failed, aborted, expired, cancelled |
| Started | Timestamp when the execution began |
| Duration | Total elapsed time |
| Cost | Actual cost in USD (formatted to 4 decimal places) |
| Steps | Current step progress (e.g., `2/5`) |

Clicking any row expands it inline to show the full step timeline.

### Filtering

Two filters are available above the execution table:

- **Execution Type** -- Filter by `All Types`, `MAP Plan`, or `WCP Workflow`
- **Status** -- Filter by `All Statuses`, `Pending`, `Running`, `Completed`, `Failed`, `Cancelled`, `Aborted`, or `Expired`

> The UI maps `MAP Plan` to `execution_type=map_plan` and `WCP Workflow` to `execution_type=wcp_workflow` in API queries.

Changing a filter resets pagination to page 1.

### Pagination

Results are paginated at 20 executions per page. The pagination bar shows:

- Current range (e.g., "Showing 1 to 20 of 142 executions")
- Up to 5 page number buttons with smart windowing around the current page
- Previous/Next navigation

### Inline Execution Detail

When a row is expanded, the detail panel shows:

**Summary Bar** (4 cards):
- Total Duration
- Total Cost (aggregated from steps, or execution-level fallback)
- Progress Percent
- Steps Completed / Total

**Error Display:** If the execution has an error, it appears as a red banner with the error message.

**Step Timeline:** Each step is rendered as a timeline item with:

- Color-coded status dot (green = completed, red = failed/blocked, blue = running with pulse animation, yellow = approval required, gray = pending/skipped)
- Step name and type badge
- Duration and per-step cost (right-aligned)
- Policy block reason (red text, shown inline when a step is blocked)
- Approval status (yellow text, shown inline when approval is required, including who approved)

### Step Detail Expansion

Clicking a step within the timeline expands it to show:

**LLM Details** (when applicable):
- Model name (e.g., `gpt-4o`, `claude-sonnet-4-6`)
- Provider (e.g., `openai`, `anthropic`, `azure`)
- Tokens In (input token count)
- Tokens Out (output token count)

**Error:** Step-level error message, if any.

**Result Summary:** A text summary of the step result.

**Matched Policies:** Purple badges showing all policy names that matched during this step's execution.

**Input/Output:** Collapsible `<details>` sections showing the full JSON input and output for the step. These are collapsed by default and render as syntax-highlighted JSON with a max height of 192px and horizontal scroll.

### Status Color Reference

**Execution statuses:**

| Status | Color |
|--------|-------|
| Pending | Gray |
| Running | Blue |
| Completed | Green |
| Failed | Red |
| Cancelled | Gray |
| Aborted | Orange |
| Expired | Gray |

**Step statuses:**

| Status | Indicator |
|--------|-----------|
| Completed | Green dot |
| Failed | Red dot |
| Blocked | Red dot |
| Running | Blue dot (pulsing) |
| Pending | Gray dot |
| Approval | Yellow dot |
| Skipped | Light gray dot |

## API Endpoints

The Execution Timeline page uses the following API endpoints via the Customer Portal backend:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/unified/executions` | GET | List executions with pagination and filters |
| `/api/v1/unified/executions/{executionId}` | GET | Get full execution detail including steps |

### Query Parameters for List Endpoint

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Maximum results per page (default: 20) |
| `offset` | integer | Pagination offset |
| `execution_type` | string | Filter by `map_plan` or `wcp_workflow` |
| `status` | string | Filter by execution status |

### Response Schema

The list endpoint returns:

```json
{
  "executions": [...],
  "total": 142,
  "limit": 20,
  "offset": 0,
  "has_more": true
}
```

Each execution in the detail view includes a `steps` array with objects containing:

- `step_id`, `step_name`, `step_type`, `status`, `duration`
- `model`, `provider`, `tokens_in`, `tokens_out`, `cost_usd` (LLM usage)
- `decision`, `decision_reason`, `policies_matched` (policy evaluation)
- `approval_status`, `approved_by` (HITL approval, when applicable)
- `input`, `output` (full JSON payloads)
- `result_summary`, `error`

## Screenshots

<!-- TODO: Add screenshots -->

**Execution list view with filters:**
[Screenshot placeholder: execution-timeline-list.png]

**Expanded execution with step timeline:**
[Screenshot placeholder: execution-timeline-detail.png]

**Step detail showing LLM usage and policy context:**
[Screenshot placeholder: execution-timeline-step-detail.png]

## Related Documentation

- [Unified Execution Tracking](../guides/execution-tracking.md) -- API and schema reference for the unified execution system
- [Execution Viewer](../guides/execution-viewer.md) -- Community execution viewer (CLI, embedded UI, SDK examples)
- [Workflow Control Plane](../guides/workflow-control-plane.md) -- WCP workflow configuration and step gates
- [Cost Controls](../governance/cost-controls.md) -- Budget and cost governance policies
