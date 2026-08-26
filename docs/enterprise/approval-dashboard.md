# Approval Dashboard (Customer Portal)

**Last Updated:** April 2026

**Platform Version:** 9.14.0 | **SDK Version:** 9.0.0

The Approval Dashboard provides a human-in-the-loop (HITL) approval queue for workflow steps that require manual review before proceeding. It displays pending approvals with full policy context, enables approve/reject actions with mandatory justification, and supports real-time queue management.

## Overview

When AxonFlow policy evaluation determines that a workflow step requires human approval (policy decision: `require_approval`), the step is paused and an entry is added to the approval queue. The Approval Dashboard surfaces these pending items so authorized reviewers can inspect the policy context, review the step input, and make an informed approve or reject decision.

Key capabilities:

- **Pending approval queue** showing all steps awaiting review across all active workflows
- **Policy context** with the triggering decision reason and matched policy names
- **Step input inspection** to review the data that triggered the approval gate
- **Approve/Reject with justification** requiring a minimum 10-character explanation
- **Real-time queue refresh** with manual refresh button and optimistic removal on action
- **Success/error feedback** with auto-dismissing success messages

## Access

The Approval Dashboard is available at the `/approvals` route within the Customer Portal.

```
https://{client}-{env}-{region}.getaxonflow.com/approvals
```

For example:

```
https://banking-prod-india.getaxonflow.com/approvals
```

Authentication is handled by the portal session. Users must be logged in with valid organization credentials.

## Features

### Approval Queue Table

The main view displays a table of pending approvals with the following columns:

| Column | Description |
|--------|-------------|
| Workflow | Workflow name and ID |
| Step | Step name and type badge (e.g., `llm_call`, `action`) |
| Policy Trigger | The decision reason that caused the approval gate (truncated to 60 characters in the table, full text on hover) |
| Age | Relative timestamp (e.g., `5m ago`, `2h ago`, `3d ago`) |
| Actions | Approve and Reject buttons |

When there are no pending approvals, the page displays an empty state with a shield icon and the message "No pending approvals."

### Refresh

A manual Refresh button in the page header reloads the approval queue. The button shows "Refreshing..." and is disabled during the fetch to prevent duplicate requests.

### Approval Detail Panel

Clicking on a row (or the Approve/Reject buttons) expands a detail panel below the table. The panel contains:

**Decision Reason:** The full policy decision reason text, displayed in a bordered card for readability.

**Matched Policies:** Purple badges showing every policy name that matched during evaluation. These are the specific policies that triggered the `require_approval` decision.

**Step Input (JSON):** A collapsible section showing the complete JSON input payload for the step. This allows reviewers to inspect exactly what data is being processed before making a decision. Collapsed by default with a max height of 256px when expanded.

### Approve/Reject with Justification

The detail panel includes a justification form:

- **Justification text area** with placeholder text "Enter justification (required, min 10 characters)"
- **Validation feedback** showing how many more characters are needed when the justification is between 1 and 9 characters
- **Approve Step** button (green) -- enabled only when justification is 10+ characters
- **Reject Step** button (red) -- enabled only when justification is 10+ characters
- **Cancel** button -- closes the detail panel without taking action
- Both action buttons show "Processing..." and are disabled while the API call is in flight

### Feedback Messages

- **Success:** A green banner auto-dismisses after 3 seconds (e.g., 'Step "analyze-data" approved successfully')
- **Error:** A red banner with dismiss button persists until manually closed

### Optimistic Updates

When a step is approved or rejected, it is immediately removed from the local list (before the background refresh completes), providing responsive feedback.

## Justification Requirements

Justification is mandatory for both approve and reject actions. The minimum length is 10 characters (after trimming whitespace). This ensures that all approval decisions have an auditable rationale.

The justification is submitted as part of the approve/reject API call and is recorded in the step audit trail for compliance and audit purposes.

## API Endpoints

The Approval Dashboard uses the following API endpoints via the Customer Portal backend:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/workflows/approvals/pending` | GET | List pending approvals for the organization |
| `/api/v1/workflows/{workflowId}/steps/{stepId}/approve` | POST | Approve a pending step |
| `/api/v1/workflows/{workflowId}/steps/{stepId}/reject` | POST | Reject a pending step |

### Query Parameters for List Endpoint

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Maximum number of pending approvals to return (optional) |

### Approve Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `comment` | string | Yes | Audit justification for approving the step (minimum 10 characters after trimming) |

```json
{
  "comment": "Reviewed input data and confirmed no PII exposure risk."
}
```

### Reject Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | Yes | Audit justification for rejecting the step (minimum 10 characters after trimming) |

```json
{
  "reason": "Output contains PII that was not redacted."
}
```

### Approval Response

Both approve and reject endpoints return an `ApprovalActionResponse` with the step status update, including `step_id`, `approval_status`, and the reviewer identity.

## Tier Availability

Creating HITL approval entries requires a Professional, Enterprise or Enterprise
Plus license:

| Tier | Creating approvals | Resolving existing approvals | Max pending approvals |
|------|-------------------|------------------------------|-----------------------|
| Community, Free, Pro, Premium | Refused | Not reachable | n/a |
| Evaluation | Refused | Reachable (approve, reject, pending list) | n/a |
| Professional | Available, API only | Available | Unlimited |
| Enterprise, Enterprise Plus | Available | Available | Unlimited |

On an unentitled tier a step matching a `require_approval` policy is **held**,
not admitted, but no reviewer entry is created: the response carries
`approval_enqueue: "tier_disabled"` with no `approval_id`.

Evaluation keeps the resolve endpoints deliberately. A deployment that held
pending approvals before the tier lost the creation entitlement must still be
able to drain them, and its expiry sweeper still runs; otherwise those entries
could never be cleared and their workflows could never proceed.

The Approval Dashboard itself is a Customer Portal surface and is accessible on
Enterprise and Enterprise Plus. Professional is API-only.

Pending approvals expire on the tier's configured window and are recorded as
`expired` rather than `rejected` - a timeout is not a human decision - and their
associated workflows are aborted.

## Screenshots

<!-- TODO: Add screenshots -->

**Approval queue with pending items:**
[Screenshot placeholder: approval-dashboard-queue.png]

**Expanded detail panel with policy context and justification form:**
[Screenshot placeholder: approval-dashboard-detail.png]

**Empty state when no approvals are pending:**
[Screenshot placeholder: approval-dashboard-empty.png]

## Related Documentation

- [Execution Timeline](./execution-timeline.md) -- Execution monitoring with step timelines in the Customer Portal
- [Workflow Control Plane](../guides/workflow-control-plane.md) -- WCP workflow configuration and approval gate setup
- [PII Detection](../guides/pii-detection.md) -- Common policy trigger for approval gates
- [Audit Logging](../guides/audit-logging.md) -- Approval justifications in the audit log
