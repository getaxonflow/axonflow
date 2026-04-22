# HITL Response Parity (v7.4.0)

This example demonstrates the unified approve/reject response shape returned by
both the Workflow Control Plane endpoint
(`POST /api/v1/workflows/{id}/steps/{step_id}/approve`) and the MAP plan-scoped
equivalent (`POST /api/v1/plans/{id}/steps/{step_id}/approve`).

## What changed in v7.4.0

Before v7.4.0 the two planes drifted:

- The **WCP** approve/reject response was `{workflow_id, step_id, approval_status,
  approved_by, message}` — no `retry_context`, no `approval_id`, no
  `policies_matched`.
- The **MAP** plan-scoped approve/reject response was even thinner:
  `{plan_id, step_id, status, execution_id}`.

Agents that needed the full governance trail had to fetch the workflow status
separately. Agents that worked across both planes had to branch on which plane
they were hitting.

In v7.4.0 both endpoints return the same `StepGateHTTPResponse` shape:

- `decision` — resolves to `"allow"` on approve, `"block"` on reject
- `approval_status` — terminal state (`approved` / `rejected`)
- `approval_id` — the HITL queue entry UUID (deterministic UUID v5 over
  `(workflow_id, step_id)`)
- `approved_by` / `approved_at` (approve path) or `rejected_by` / `rejected_at`
  (reject path) — reviewer identity from the workflow step row
- `policies_matched` — the policies that triggered the original
  `require_approval` decision
- `retry_context` — the full retry state (same shape as the gate response), so
  the reviewer tool sees gate counters, prior completion status, and the
  idempotency key without a second call
- `plan_id` — MAP-plane responses only; empty on WCP responses

## Tier

The approve/reject endpoints on both planes require **Evaluation** or
**Enterprise** tier — pure community mode returns 403 because HITL approval
gates aren't available there. MAP's plan-scoped endpoints (previously
Enterprise-only) became Evaluation-tier in v7.4.0 as part of this parity work.

## Running the example

Spin the orchestrator up with HITL enabled and either an Evaluation license
on the community binary or an Enterprise stack. The minimal environment
the scripts expect:

```bash
# Agent URL (port 8080 — the SDKs/CLI target this too)
export AGENT_URL=http://localhost:8080

# Authentication. Either Basic (client_id + client_secret from your license
# payload) or Bearer (a signed JWT from the portal). Pick one.
export AXONFLOW_CLIENT_ID=<your-client-id>
export AXONFLOW_CLIENT_SECRET=<your-client-secret>
# or
export USER_TOKEN=<jwt>

# Tenant header (set to whatever tenant owns the workflows you're testing)
export TENANT_ID=tenant-demo

# The orchestrator must have HITL enabled:
#   AXONFLOW_HITL_ENABLED=true
# and the process should have access to a dynamic policy that matches the
# demo step (e.g., a policy that fires require_approval on
# step_input.amount_eur > 1000). A starter policy is documented below.
```

For ready-made docker-compose stacks with evaluation / enterprise licenses
baked in, see the [AxonFlow quickstart docs](https://docs.getaxonflow.com/docs/getting-started/).

### End-to-end via curl

```bash
./http/hitl-response-parity.sh
```

The script:

1. Creates a WCP workflow with a require_approval policy match on step 1.
2. Approves the step via the WCP endpoint and saves the response.
3. Creates a MAP plan in confirm mode (backed by a WCP workflow internally).
4. Approves the first step via the MAP plan-scoped endpoint and saves the response.
5. Diffs the two responses field-by-field and asserts the only difference is
   the `plan_id` field (populated on MAP, absent on WCP) — every other field is
   identical in shape.

The script exits non-zero on any parity violation, so it's safe to drop into
CI as a smoke test.

### Plane-scoped pending approvals (v7.4.0 — Issue #1680)

`list-pending-plan-approvals.sh` covers the reviewer-tool listing surface
that ships alongside the approve/reject parity work:

```bash
./http/list-pending-plan-approvals.sh
```

The script:

1. Creates a MAP confirm-mode plan that pauses its first step on a
   `require_approval` policy.
2. Calls `GET /api/v1/plans/approvals/pending` and verifies every entry
   carries `plan_id` — the intentional asymmetry with the WCP listing.
3. Calls `GET /api/v1/workflows/approvals/pending` and verifies that
   listing does **not** leak `plan_id` on any entry (omitempty semantics).
4. Exercises the `?plan_id=` filter and asserts the filtered listing is
   scoped to a single plan.
5. Approves the step and re-lists the MAP plane to confirm the entry
   disappears.

Runs end-to-end against an Evaluation-licensed community binary or an
Enterprise stack — the new endpoint shares its tier gate with the MAP
plan-scoped approve/reject endpoints.

## Related

- [HITL Approval Gates reference](https://docs.getaxonflow.com/docs/features/hitl-approval-gates/)
  covers both planes' approve/reject and pending-list endpoints.
- [Human-in-the-Loop governance guide](https://docs.getaxonflow.com/docs/governance/human-in-the-loop/)
  puts the API in the context of the operating model.
- [Retry Semantics & Idempotency](https://docs.getaxonflow.com/docs/orchestration/wcp/retry-and-idempotency/)
  defines the `retry_context` block that both planes now surface on approve /
  reject in addition to `/gate`.
- The Go / Python / TypeScript / Java SDKs grew matching `ApproveStepResponse`
  / `RejectStepResponse` fields plus new `GetPendingPlanApprovals`-equivalent
  methods in v5.6.0 / v6.6.0 / v5.6.0 / v5.7.0 respectively.
