# Policy Actions and the Detection Posture Lever

**Status:** documents shipped behavior as of #3360 (2026-08). This page answers one operator question precisely: *when a policy row stores an `action`, what actually decides the runtime outcome on each enforcement plane?*

## TL;DR

For the four **detection categories** (`pii-*`, `security-sqli`, `sensitive-data`, `security-dangerous`), the **deployment/org posture lever is authoritative on almost every plane, not the policy row's action column**. The lever is, in resolution order:

1. Per-org detection override (Enterprise, set through the detection posture API/portal)
2. Environment levers: `PII_ACTION`, `SQLI_ACTION`, `SENSITIVE_DATA_ACTION`, `DANGEROUS_COMMAND_ACTION` (per-plane variants such as `GATEWAY_PII_ACTION` and `MCP_PII_ACTION` refine them)
3. `AXONFLOW_PROFILE` defaults (`dev`=log, default=warn, `strict`/`compliance`=block for PII; see the profile matrix in `platform/agent/profile.go`)

A `pii-*` policy row seeded with `action='block'` therefore does **not** deny on the decide, gateway, MCP, or OpenAI-compat planes unless the posture lever itself resolves to `block`. This is the designed authority order (ADR-036 governance profiles; the engine applies the lever at `EvalOptions.ActionOverrides`), not a fail-open: the lever exists so an operator can move the whole deployment between log/warn/redact/block postures without editing policy rows.

Compliance categories (`compliance-*`, `fincrime`) and `admin-access` have **no lever entry**: their row action is honored directly wherever those categories are evaluated.

## What you see when the lever weakens a stored action

Since #3360, a matched policy whose stored action was resolved DOWNWARD (for example stored `block` resolved to `redact` under the compose default posture) is never silent:

- The decide plane's allow verdict carries an advisory reason naming the policy, both actions, and the lever that governed it, and the same reason is persisted on the audit row.
- The agent increments `axonflow_agent_policy_stored_action_displaced_total{category, stored, resolved}` on every plane that evaluates through the shared conversion, so operators can alert on "the action column is lying" instead of discovering it in a demo.

Upward displacement (a strict profile tightening a `warn` row to `block`) is the lever doing its designed job and is not flagged.

## Per-plane outcome matrix (detection-category policies)

"Resolved action" means the action AFTER the lever applied. Row-action honored means the plane reads `static_policies.action` directly instead of the lever.

| Plane | block | require_approval | redact | warn / log | Row action honored? |
|---|---|---|---|---|---|
| decide (`POST /api/v1/decide`) | deny | needs_approval (Enterprise); allow + advisory (Community) | allow + `redact_pii` obligation | allow + advisory reason (PII categories) | No (lever) |
| gateway pre-check | approved=false | approved=false (Enterprise); allow (Community) | allow + `requires_redaction` (masking is the caller-side contract) | allow, logged | No (lever) |
| MCP `tools/execute`, `resources/query` | HTTP 403 | allow, logged only | allow, logged only (request phase) | logged only | No (lever) |
| MCP `check-input` / `check_policy` | allowed=false | allowed=true | allowed + masked statement | allowed | No (lever) |
| OpenAI-compat (`/v1/chat/completions`) | HTTP 400 | allow | allow (no masking on this plane) | allow | No (lever) |
| Cowork / Claude Code OTEL storage | forced redact | forced redact | redact | forced redact | No (hard-pinned redact at the collector) |
| Orchestrator response phase | withhold | n/a | mask | nothing | No (lever) |
| Proxy (`/api/v1/request`) tier engine (Phase 2) | deny (403) | RequiresApproval | logged only | logged only | **Yes** |

The proxy plane's Phase 2 tier engine is the one surface that reads the raw row action with no lever. The same `pii-*` row can therefore deny on `/api/v1/request` while allowing (with a redact obligation) on `/api/v1/decide` in the same deployment. Whether that plane should adopt the lever is an open product ruling tracked on issue #3380 (blocked on an operator decision); until it lands, treat the proxy plane's behavior as the documented exception, not the rule.

## Worked example: sys_pii_indonesia_ktp

The seeded row (migration 116) stores `action_request='block'`. On a compose deployment (`PII_ACTION` defaults to `redact`):

- `POST /api/v1/decide` with a KTP number in the query returns `verdict=allow` with a `redact_pii` obligation, the policy id in `evaluated_policies`, and (since #3360) an advisory reason: the stored `block` was resolved to `redact` by the PII posture lever.
- Setting `PII_ACTION=block` (or `AXONFLOW_PROFILE=strict`/`compliance`, or an org detection override of `pii=block`) makes the same request return `verdict=deny`. Verified live: the deny may attribute `indonesia_pii_protection` rather than the static row, because the same lever also arms the Enterprise validator-backed Indonesia detector, which runs before the static engine and wins the early return. Both ids mean the lever-armed Indonesia PII control denied.
- `POST /api/v1/request` (proxy plane) denies with 403 either way, per the exception above.

If your compliance posture requires KTP/NIK to hard-deny (for example KYC requirements), set the lever: `PII_ACTION=block` or the org detection override. Do not rely on the row's action column.

## Authoring guidance

When creating or editing a policy in a detection category, treat the `action` field as the authoring default for deployments whose posture delegates to rows (currently only the proxy tier engine) and as documentation of intent elsewhere. The runtime outcome on the lever-governed planes follows the posture. The CRUD API accepts `action='block'` on a `pii-*` row without warning today; an authoring-time warning is a tracked follow-up on #3380; the adjacent plane defects found by the same census are #3378 and #3379.
