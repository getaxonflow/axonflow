# Changelog

All notable changes to AxonFlow will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry is grouped by edition: **Community** changes also ship in the
community mirror, **Enterprise** changes are EE-only.

---

## [Unreleased]

**Enterprise:**

- **Per-category detection action overrides on the marketplace CFN
  template.** Self-hosted enterprise stacks gain four new optional
  CloudFormation parameters — `SQLIAction`, `PIIAction`,
  `SensitiveDataAction`, `DangerousQueryAction` (each: `block` / `warn` /
  `log`, `PIIAction` also accepts `redact`). Empty leaves the active
  `AXONFLOW_PROFILE` default in place; setting one overrides only that
  category without flipping the global profile. Lets operators tighten
  enforcement on a single category (e.g. `SQLIAction=block` for a
  benchmark stack) without inheriting the strict profile's PII redact
  behaviour. No change for existing deployments — the parameters
  default to empty.

- **Per-category circuit breaker threshold overrides on the
  marketplace CFN template.** Two new optional CloudFormation
  parameters — `CBErrorThreshold` and `CBPolicyViolationThreshold`
  (integers) — let operators tune the agent's per-client circuit
  breaker without forking the template. Production defaults stay
  at the Article-14 posture (10 errors / 20 policy violations per
  5-min window per client); empty values leave defaults in place.
  Useful for benchmark stacks running attack-pattern load that would
  otherwise trip the breaker after the first second.

## [7.5.1] - 2026-05-01 — Policy-engine response cleanup + booking-ref pattern fix

Patch release with three user-facing improvements to the policy enforcement
response. No breaking changes; existing SDK / dashboard consumers continue
to work.

**Bug fixes:**

- **`policy_info` no longer reports duplicate matched policies.** When a
  policy's pattern matched both the query string and a request parameter,
  the response field listed the same policy twice (e.g.
  `["sys_sqli_grant", "sys_sqli_grant"]`). Each policy is now reported
  once per evaluation regardless of how many contexts it matched in.
  Block-decision behaviour is unchanged.
- **`sys_pii_booking_ref` no longer fires on SQL keywords.** The original
  pattern `\b[A-Z0-9]{6}\b` matched any 6-char alphanumeric token,
  including SELECT, INSERT, DELETE, UPDATE, CREATE — generating a
  booking-reference audit-log entry for every benign SQL query and
  inflating "PII detected" counts in compliance dashboards. The pattern
  now requires a booking-context label (booking, reservation, reference,
  ref, pnr, confirmation, conf) before the alphanumeric token. Real
  booking refs like `booking ABC123` or `PNR XYZ789` continue to match.
  Action remains `log` — requests are not affected, only audit-trail
  noise. A follow-up SQL migration (074) updates already-deployed
  systems in place; new deployments seed the corrected pattern from
  the start.

**API additions:**

- **`policy_info.matched_policies` field added** alongside the existing
  `policies_evaluated`. The new field name is the canonical one; the
  legacy `policies_evaluated` is kept populated with the same values
  for backward compatibility and will be removed in the next major
  release. The original field name suggested "every policy the engine
  ran against the input" but the value has always been the matched-
  policies list — the new name reflects what's actually reported.

## [7.5.0] - 2026-04-29 — Production, quality, and security hardening — upgrade encouraged

**Upgrade strongly recommended.** Over the past month we've shipped substantial
production, quality, and security hardening across the AxonFlow platform —
upgrade for a more secure, reliable, and bug-free experience.

**Security highlights from this release cycle:**
- **Multi-tenant isolation in MAP execution** (v7.4.5). A body-supplied
  `org_id` could override the authenticated org for both recording AND
  policy evaluation. Identity is now sourced from authenticated headers
  consistently across recording, read filters, and policy evaluation.
- **SQL-injection enforcement restored on `try.getaxonflow.com`** (v7.5.0).
  The Community SaaS endpoint had inherited the `warn` default since
  v6.2.0; SQLi-shaped requests passed through to the LLM. Default flipped
  back to `block`; configurable per deploy.
- **Cross-tenant audit-log isolation** (v7.2.0). Evidence and explain
  handlers fail-closed when tenant context is missing instead of
  returning data scoped to a different tenant.

The full set of platform-side security fixes addressed in this cycle —
including five additional access-control and DoS hardening items not
listed above — is documented in the consolidated security advisory
[GHSA-9h64-2846-7x7f](https://github.com/getaxonflow/axonflow/security/advisories/GHSA-9h64-2846-7x7f).

**Reliability and bug-fix highlights:**
- **`/health` now reports the deployed platform semver** (v7.5.0). Was
  returning `1.0.0` on every deployed stack because the image tag
  failed the version-resolver regex. New `PlatformVersion` CFN parameter
  + repo-root `VERSION` file as single source of truth.
- **ALB idle timeout 300s on Community SaaS** (v7.5.0). Long MAP plan
  generation requests no longer 504 at the load balancer before the
  orchestrator finishes.
- **`decision_id` on every governance decision path** (v7.5.0).
  Allow paths on `/api/v1/mcp/check-input` and `/api/v1/mcp/check-output`
  no longer silently drop the audit correlator; every allow / deny /
  redact decision now surfaces `decision_id` for forensic correlation.

No breaking platform changes. Existing SDK and plugin callers continue
to work; they receive a one-time upgrade hint when they sit below the
new floor.

### SDKs and Plugins

Coordinated major-version bump across all eight artifacts. The four
SDKs (Go, Python, TypeScript, Java) advance to **v7.0.0**. The OpenClaw
plugin advances to **v2.0.0**; the Claude Code, Cursor, and Codex CLI
plugins graduate from `v0.x.x` to **v1.0.0**. The breaking change
driving all eight is the `DO_NOT_TRACK` telemetry opt-out removal —
`AXONFLOW_TELEMETRY=off` is now the canonical and only opt-out across
every SDK and every plugin.

### Community

#### Added

- **`/health` advertises plugin version compatibility.** New
  `plugin_compatibility` field declares `min_plugin_version` and
  `recommended_plugin_version` per plugin id (`openclaw`, `claude-code`,
  `cursor`, `codex`), mirroring the long-standing `sdk_compatibility`
  shape. Plugins query `/health` at startup, log a one-time upgrade
  warning when they're below the floor, and stay quiet otherwise — the
  same downgrade-warning gate every SDK already runs. The
  `HealthResponse` OpenAPI schema gains the new field; older platforms
  without the field degrade silently on the plugin side.
- **Community-SaaS registration lifecycle.** Registration TTL bumped
  from 30 days to 1 year; existing 30-day registrations within 60 days
  of expiry are auto-extended at deploy time so no live tenant gets
  locked out. New tombstone semantics keep the `tenant_id` slot
  reserved indefinitely after a cascade-delete so a UUID is never
  reused, and a distinct `ErrRegistrationTerminated` error returns an
  actionable "re-register" message instead of the generic invalid-
  credentials response. The disclaimer returned by
  `POST /api/v1/register` now matches the public privacy policy and
  the plugin first-run setup message — single source of truth across
  surfaces.
- **Daily Community-SaaS inactivity sweep** terminates tenants idle for
  more than 3 months and tenants past the 1-year hard cap, cascade-
  deleting their tenant-scoped data (audit logs, policies, workflows,
  plans, etc.) in a single transaction so a partial failure rolls the
  whole tick back. The cascade table list is reflected from
  `information_schema` at agent startup with a hard non-cascade
  allowlist for structural tables. Multi-instance correctness via
  Postgres advisory lock — only one agent task runs the sweep per
  tick. Opt-in per deploy via `COMMUNITY_SAAS_SWEEP_ENABLED=true`,
  with `COMMUNITY_SAAS_SWEEP_DRYRUN=true` available so operators can
  soak the predicate logic for 24h before flipping the real switch.
  Per-termination audit-log line plus Prometheus counters for
  inactivity terminations, hard-cap terminations, lock-skip events,
  cascade row counts, and tick failures.

#### Changed

- **OpenAPI specs now declare 24 fields the platform has been emitting
  on the wire but the spec hadn't documented.** `AuditLogEntry`
  (`metadata`, `model`, `policy_violations`), `DynamicPolicy` (7 CRUD
  fields), `PlanResponse` (4 plan-context fields),
  `ResumePlanResponse` (7 resume-context fields), plus 16
  lower-priority schemas covering audit query params, budget/usage
  fields, execution-snapshot HITL fields, workflow step audit context,
  and the multimodal payload field on `ClientRequest`. Closes the
  spec-side gap surfaced by the Python SDK's wire-shape contract gate.

#### Fixed

- **`/health` now reports the deployed platform semver.** Previously
  the `version` field returned `1.0.0` on every deployed stack because
  the CloudFormation templates wired `AXONFLOW_VERSION` to the agent
  image tag (`latest`, git SHA, etc.), which failed the semver regex
  in the agent's version resolver. A new dedicated `PlatformVersion`
  CFN parameter with a built-in semver `AllowedPattern` is now wired
  to `AXONFLOW_VERSION` independently of the image tag, and a new
  `VERSION` file at the repo root is the single source of truth read
  by both the build pipeline and the deploy script. A version-
  alignment validator runs on every push.
- **`MCPCheckInputResponse` now emits `decision_id` on the allow path**
  of `POST /api/v1/mcp/check-input` (it was already emitted on every
  deny path). Every governance decision was supposed to surface
  `decision_id` so callers can correlate the decision back to
  the audit log via `/explain/{id}` without a round-trip — the allow
  path silently dropped it. Same fix applied to
  `MCPCheckOutputResponse` (which gains a `decision_id` field) and to
  the MCP-tool variants so plugin-visible shape is consistent across
  HTTP and MCP-tool surfaces.
- **`try.getaxonflow.com` blocks SQL injection again.** Community SaaS
  deployments now pin `SQLI_ACTION=block` on the agent task,
  overriding the v6.2.0+ relaxed default profile that demoted SQLi
  enforcement to `warn`. Configurable per-deploy via the new
  `SqliAction` CFN parameter (`block` / `warn` / `log`, default
  `block`). Takes effect on the next community-saas deployment.
- **`try.getaxonflow.com` plan generation no longer 504s at 60 seconds.**
  The community-saas CFN template's `AlbIdleTimeoutSeconds` parameter
  (default 300) ships pre-set; the next deployment of the running
  stack picks up the 300s idle timeout so long MAP plan-generation
  requests complete without hitting the front-door gateway timeout.
- **`docs/api/agent-api.yaml` and `docs/api/orchestrator-api.yaml` now
  lint clean.** 21 broken `$ref` references to a non-existent `Error`
  schema in `agent-api.yaml` are repointed to the existing
  `ErrorResponse` (same shape both handlers return). Five additional
  broken refs in `orchestrator-api.yaml` are resolved by adding the
  missing `OrgIDQuery` parameter and three EU AI Act conformity
  schemas. Several malformed-example errors and `no-$ref-siblings`
  violations across the two specs are corrected.

#### Documentation

- **SDK telemetry contract: 7-day delivered-heartbeat.** All four SDKs
  follow the same contract: AxonFlow emits at most one anonymous
  heartbeat per environment every 7 days during SDK activity. The
  telemetry contract document is rewritten with the new cadence
  section, per-OS stamp-file specification, and a 9-case heartbeat
  conformance test matrix plus a 4-run cross-process E2E. Plugin
  parity (sibling 7-day-heartbeat at hook-fire time) noted at the
  bottom of the contract, including the deliberate stamp-filename
  split: SDKs use `{sdk}-telemetry-last-sent` while plugins keep the
  legacy `{codex,claude-code,cursor,openclaw}-plugin-telemetry-sent`
  so existing installs preserve their `instance_id` across the
  upgrade.
- **Telemetry opt-out is `AXONFLOW_TELEMETRY=off` everywhere.**
  `DO_NOT_TRACK` is no longer honored as an opt-out across all four
  SDKs and all four plugins. `DO_NOT_TRACK` is commonly inherited from
  host tools and developer environments — host CLIs like Codex and
  Claude Code inject it unconditionally — making it an unreliable
  expression of user intent. Documentation, ADRs, and the README
  callout are updated.
- **Examples and SDK reference docs updated for the v7 majors.**
  Install-command snippets, dependency declarations, getting-started
  guides, tutorials, gateway/proxy guides, compliance pages, MCP audit
  logging, execution tracking, and the configurable-agents reference
  now point at the new SDK majors. Historical "Since vX" references
  are intentionally left as-is — those document when a feature was
  added.

#### CI / Testing

- **Tier-gate contract CI** now runs every PR that touches the agent
  or orchestrator code paths against a fresh docker-compose stack in
  community, evaluation, and enterprise modes, and asserts that each
  guarded endpoint returns the documented status code per tier.
  Catches drift between the published tier matrix and actual handler
  enforcement before merge.
- **OpenAPI validation now covers all three specs.** Previously only
  `policy-api.yaml` was linted in CI; `agent-api.yaml` and
  `orchestrator-api.yaml` were silently exempt and accumulated
  structural defects (broken refs, duplicate schemas, malformed
  examples). The validator now loops over all three specs and runs
  per-spec breaking-change diffs against the base branch.

### Evaluation

- All Community changes apply.
- The plugin-compatibility check, the openapi corrections, and the
  Community-SaaS lifecycle additions all flow through Evaluation
  unchanged. No new Evaluation-tier endpoints, no Evaluation-only
  behaviour changes in this release.

### Enterprise

- All Community + Evaluation changes apply.
- No Enterprise-only behaviour changes in this release. The portal,
  customer-portal-ui, and the rest of the Enterprise tree pick up the
  Community-side fixes (correct `/health` semver, `decision_id` on
  allow, etc.) automatically.

### SDKs

- **Go SDK v7.0.0** — module path advances from `/v6` to `/v7`.
  `DO_NOT_TRACK` is no longer honored; use `AXONFLOW_TELEMETRY=off`.
  Anonymous heartbeat now follows the 7-day-per-environment cadence.
- **Python SDK v7.0.0** — `axonflow>=7.0.0`. `StaticPolicy` and
  `PolicyVersion` now serialize wire fields in snake_case to match
  the OpenAPI spec; camelCase keys still accepted on input via field
  validation aliases so existing consumers keep working — round-trip
  identity is no longer preserved for callers that built models from
  camelCase dicts. `DO_NOT_TRACK` removed; 7-day heartbeat cadence
  shipped.
- **TypeScript SDK v7.0.0** — `@axonflow/sdk@^7.0.0`. `DO_NOT_TRACK`
  removed; 7-day heartbeat cadence shipped.
- **Java SDK v7.0.0** — `<version>7.0.0</version>` on the
  `axonflow-sdk` dependency. `DO_NOT_TRACK` removed; 7-day heartbeat
  cadence shipped.

See each SDK's release notes for the per-language migration shape.

### Plugins

- **OpenClaw v2.0.0** — `npm install @axonflow/openclaw@^2.0.0`.
  `DO_NOT_TRACK` removed; `AXONFLOW_PLUGIN_VERSION_CHECK=off` to skip
  the new platform compatibility check.
- **Claude Code plugin v1.0.0** — graduates from the 0.x line to a
  stable 1.x. `DO_NOT_TRACK` removed.
- **Cursor plugin v1.0.0** — graduates from the 0.x line to a stable
  1.x. `DO_NOT_TRACK` removed.
- **Codex plugin v1.0.0** — graduates from the 0.x line to a stable
  1.x. `DO_NOT_TRACK` removed.

All four plugins query the platform's `/health` at startup, read
`plugin_compatibility.min_plugin_version[<canonical id>]`, and emit a
single upgrade hint to stderr when the runtime version is below the
floor. Below recommended-but-above-min logs an info-level note;
at-or-above recommended is silent. Older platforms that don't
advertise the field degrade silently. Skippable per-plugin via
`AXONFLOW_PLUGIN_VERSION_CHECK=off`.

## [7.4.5] - 2026-04-28 — Phase 1 quality-freeze fixes + MAP execution-tracking org isolation

PATCH: bug fixes only. The headline platform fix is a pair of org-identity propagation bugs in the MAP execution path that made `GET /api/v1/executions` return zero rows for newly-completed plans and let body-supplied identity override the authenticated org/tenant on policy evaluation. The rest is the close-out of the Phase 1 quality-freeze sweep against the bundled examples — every example now compiles, runs, and exits with a clear PASS/FAIL summary against a stock community-mode docker-compose stack.

No breaking changes. No new endpoints, SDK methods, or features.

### Community

#### Fixed

- **`GET /api/v1/executions` returned zero rows for newly-completed MAP plans.** Plans executed via `POST /api/request` with `request_type=execute-plan` were recorded in the execution-tracking store with an empty `org_id`, while the read-side filter (driven by the authenticated org from Basic auth) required a non-empty match — so every MAP plan execution produced a row that was invisible to subsequent list calls. The execution recorder now persists the same authenticated org used for filtering on read, and policy evaluation, plan storage, and replay tracking all read org and tenant from the same authoritative source on every request. A request can no longer be recorded under one org and policy-evaluated under another, even if a caller bypasses the agent and supplies mismatched values directly.
- **MAP examples updated to current SDK releases** — Go 5.8.0, TypeScript 6.1.0, Python 6.8.0, Java 6.1.0 — so `go run`, `npm start`, `python main.py`, and `mvn exec:java` work against the published SDKs on a fresh checkout.
- **`examples/cost-estimation/http/execution-cost-validation.sh`** now exits with a clear PASS/FAIL summary instead of aborting mid-run with exit code 5 when a response is malformed (e.g. on auth failure). The script was rewritten to use the generate-plan → execute-plan → fetch-cost flow that actually surfaces a non-zero plan cost in Community.
- **`examples/risk-tiered-approvals/go`** now compiles from a clean checkout. The directory was missing `go.mod` and `go.sum`, so `go run main.go` failed with `no required module provides package`. The example also referenced an SDK type that was renamed before release; corrected to the published name. Both Go and Python variants now pass end-to-end. Test 3 (HITL queue listing) skips on Community and Evaluation with an accurate message — the queue endpoint is Enterprise-only and was previously mis-labelled.
- **`examples/media-governance-policies/typescript`** Test 4b no longer fails with `tenant_id=undefined`. The TypeScript SDK exposes `MediaGovernanceConfig` fields in camelCase (`tenantId`); the example was asserting on the wire-shape snake_case field. Aligned the assertion and the log line.
- **`examples/audit-logging` (TypeScript and Java)** now match the Python variant's authentication setup so `auditToolCall` succeeds without `Missing authentication` errors.
- **`examples/llm-routing/go`** updated to the current routing API shape so the demo works against a stock stack.
- **`examples/mcp-connectors/cloud-storage`** rewritten to exercise a working S3-compatible flow against the MinIO instance bundled in the docker-compose stack.
- **`examples/.gitignore`** no longer excludes `go.sum`. Every Go example now ships with its lockfile committed so a clean clone runs without needing `go mod tidy`. Two stale `replace` directives in `examples/wcp-retry-idempotency/{community,evaluation}/go/go.mod` (pointing at sibling-checkout SDK paths) and a 0-byte orphan `examples/policies/go/go.mod` were also cleaned up.
- **`examples/policies/http/policies.sh`** Create Custom Policy now sends a valid request body — a single `pattern` regex with a recognized category — instead of an invalid array shape that the platform was rejecting with HTTP 400. The script previously printed "Status: Created" without checking the response, masking the failure.
- **`examples/gateway-policy-config/python`** no longer crashes with `TypeError: get_env() missing 1 required positional argument`.
- **`examples/workflow-control/go`** now compiles. `ApproveStep` and `RejectStep` were called with two arguments after the SDK signatures had added a third (approver_id).
- **`examples/hello-world/typescript`** is now a policy-only demo matching the other three SDKs. The Gateway Mode TypeScript example moved to `examples/integrations/gateway-mode/typescript/`.

#### Documentation

- **Python version prerequisite for examples.** `examples/README.md` and a new `examples/retry-semantics/python/README.md` now state that several Python examples require Python 3.10+ and the current `axonflow` PyPI release. The older pinned `axonflow==4.1.0` from earlier examples does not expose retry-policy or lifecycle fields used here and will fail on import or with a missing-attribute error. Users on systems where `python3` defaults to 3.9 (e.g. older macOS) should create a venv on a newer interpreter before running these examples.

## [7.4.4] - 2026-04-25 — `CreateOverrideResponse` schema split

PATCH: documentation-grade correction — no platform behaviour change. Splits the `POST /api/v1/policies/{id}/overrides` create-response shape from the at-rest `PolicyOverride` entity, matching what the platform server has been emitting all along and the precedent established by `CreateWorkflowResponse` (orchestrator-api.yaml). Code-generated clients written against the prior spec would have read `undefined` for the create-time TTL clamping fields (`ttl_seconds`, `requested_ttl`, `clamped`, `clamped_reason`) and looked for at-rest fields (`action_override`, `enabled_override`, `tool_signature`) that the create response doesn't carry.

### Community

#### Fixed

- **`CreateOverrideResponse` schema added** to `docs/api/agent-api.yaml`. The `createStaticPolicyOverride: 201` response now references this dedicated schema instead of the at-rest `PolicyOverride`. Carries `id`, `policy_id`, `policy_type`, `expires_at`, `ttl_seconds`, optional `requested_ttl` / `clamped` / `clamped_reason` (populated when server-side TTL clamping kicked in), and `created_at`. The at-rest `PolicyOverride` schema retains its role on `GET /api/v1/policy-overrides` / `GET /api/v1/policy-overrides/{id}`.

  AxonFlow's hand-written OpenClaw plugin already implements `CreateOverrideResult` matching the actual server shape — this fix aligns the spec with the plugin's reality and unblocks code-generated clients.

## [7.4.3] - 2026-04-25 — Plugin Batch 1 spec corrections

PATCH: documentation-grade corrections — no platform behaviour change. Companion to the 4 plugin wire-shape contract gates landing alongside (parity with the four SDK gates). Auto-resolves the bulk of those plugins' initial baseline drift entries.

### Community

#### Fixed

- **OpenAPI spec corrections — Plugin Batch 1 explainability fields.** Two MCP-response schemas have been stale relative to what the agent has emitted since Plugin Batch 1 shipped. The fix unblocks code-generated clients and auto-resolves baseline drift entries on every AxonFlow plugin's wire-shape contract gate.
  - **`MCPCheckInputResponse`** gains the five Plugin Batch 1 fields the agent has emitted since v7.1.0 (`decision_id`, `risk_level`, `policy_matches`, `override_available`, `override_existing_id`).
  - **`MCPCheckOutputResponse`** gains `redacted_message` (text-redaction counterpart to `redacted_data`), `decision_id`, and `policy_matches`.
  - **`ExplainPolicy`**, **`ExplainRule`**, **`DecisionExplanation`** schemas added — these are the explainability shapes returned by the `explain_decision` MCP tool. Hand-written SDKs and plugins are already aligned with what the agent emits; this just documents the wire contract.

## [7.4.2] - 2026-04-25 — OpenAPI spec corrections

PATCH: documentation-grade corrections — no platform behavior change.
Two OpenAPI schemas were stale relative to what the server has been
emitting. Code-generated clients written against the prior spec would
have read `undefined` for the affected fields. AxonFlow's hand-written
SDKs (TS, Python, Go, Java) are correct against the server and gain
no functional change from this release; the fix lives entirely in the
spec artefacts.

### Community

#### Fixed

- **`AISystemRegistry.materiality` → `materiality_classification`**
  in `docs/api/masfeat-api.yaml`. Server has emitted
  `materiality_classification` since the 3-dimensional risk rating
  refactor for MAS AI Risk Management Guidelines 2025.
- **`DynamicPolicyInfo`** in `docs/api/agent-api.yaml` rewritten from
  8 aspirational fields to the 4 actual server fields
  (`policies_evaluated`, `matched_policies`, `orchestrator_reachable`,
  `processing_time_ms`).

## [7.4.1] - 2026-04-23 — Portal HITL + audit trail fixes

PATCH: portal-visible bugs fixed around human approval visibility —
approver identity on the execution timeline, Compliance Summary card
aggregates, HITL audit trail row emission, workflow-level aborted
status propagation, stale-snapshot reconciliation for pre-patch
workflows, and a sidebar badge refresh on approve/reject. Platform-only
release — no SDK or plugin changes. All fixes hit the same HITL audit
and approval visibility story so operators can answer "who approved
what, when, and did the compliance summary count it?" without joining
three tables.

### Community

#### Fixed

- **Unified execution step now distinguishes approver from rejector.**
  The unified execution API (`/api/v1/unified/executions/{id}`)
  populated `approved_by` with the rejector's email on rejected steps
  because the serializer projected `workflow_steps.approved_by`
  verbatim regardless of terminal state. The step serializer now
  splits into `approved_by` / `approved_at` on the approval path and
  `rejected_by` / `rejected_at` on the rejection path, mirroring the
  split already done by `workflow_control.ProjectStepGateToHTTP` on
  the WCP HTTP response. `execution.StepStatus` gains two new fields
  (`RejectedBy`, `RejectedAt`).
- **`/api/v1/audit/summary` returns six card-view aggregates.** The
  response previously emitted `total_events` / `by_severity` /
  `by_action` / `top_policies` / `compliance_score` — the handler
  now additionally computes and returns `total_requests`,
  `allowed_requests`, `blocked_requests`, `modified_requests`,
  `block_rate_percent`, `avg_latency_ms`. Legacy fields retained for
  back-compat. Block rate is derived from the allowed/blocked/modified
  counts; average latency is a separate query over `response_time_ms`
  excluding rows where latency wasn't measured (HITL decisions,
  workflow-lifecycle events).
- **Compliance Summary arithmetic always closes.** The summary
  handler previously only counted `allowed` / `blocked` / `redacted`
  decisions explicitly; `pending_approval` (from `workflow_step_gate`
  rows where HITL fires require_approval) and `error` decisions were
  dropped between the buckets, so `total_requests` could exceed
  `allowed_requests + blocked_requests + modified_requests` by the
  number of orphan rows. Now every non-blocked, non-redacted decision
  rolls into Allowed — Total = Allowed + Blocked + Modified is
  always true. `pending_approval` counts as allowed because the
  policy didn't block; the subsequent human decision writes its own
  `workflow_step_approved` / `workflow_step_rejected` row.
- **Historical workflows decided before v7.4.1 deployed now render
  their terminal approval state.** The unified-execution cache was
  written at `/gate` time (approval_status=pending) and pre-v7.4.1
  approve/reject paths did not re-sync it — so any workflow decided
  before the fix deployed would forever show "Approval: pending" on
  the execution API. `GetWorkflowStatus` now reconciles cached step
  snapshots against current `workflow_steps` state on every read via
  a new `reconcileStepApprovals` helper. Steps present in the cache
  but absent from the fresh rows are left untouched so partial WCP
  state can't clobber the cache; WCP fetch failure falls back to the
  cached snapshot.

### Evaluation

#### Fixed

- **WCP step approve + reject now emit rows in `audit_logs`.** The
  WCP step-approve/reject endpoints
  (`/api/v1/workflows/{id}/steps/{step_id}/approve|reject`, Evaluation+)
  previously updated `workflow_steps.approval_status` and fired a
  webhook but never wrote to `audit_logs`, so any audit pipeline that
  reads `audit_logs` had no trace of approvals or rejections — rejected
  steps never appeared as "Blocked" rows, compliance summaries ignored
  the events, and operator dashboards showed "N/A" under user. Both
  paths now write an `audit_logs` row via the existing
  `WorkflowAuditEntry` pipeline with `request_type="workflow_step_approved"`
  / `"workflow_step_rejected"`, `policy_decision="allowed"` on approve
  / `"blocked"` on reject, and the reviewer's `X-User-Email` populated
  on `user_email`. `WorkflowAuditEntry` gains `UserEmail` / `UserRole`
  so reviewer identity carries through the audit adapter end-to-end.
- **Reject propagates the aborted status to the unified execution
  tracker.** `RejectStep` flipped `workflow_steps.approval_status`
  and called `repo.Abort(...)` on the workflow, but never notified
  `executionTracker.OnWorkflowAborted(...)`. `GetWorkflowStatus`
  prefers the cached unified execution when one exists, so
  `/api/v1/unified/executions/{id}` kept reporting the overall
  execution as running/pending even though the rejection had already
  aborted the workflow. Now calls `OnWorkflowAborted` after the abort
  succeeds — only when the abort actually landed, so we don't lie
  about workflow state on an abort failure.

### Enterprise

#### Fixed

- **HITL queue approve + reject now emit rows in `audit_logs`.** The
  Enterprise HITL queue endpoints
  (`/api/v1/hitl/queue/{id}/approve|reject`) previously wrote only to
  `hitl_approval_history` (the immutable compliance audit trail), so
  the audit-logs-based portal audit page had no trace of queue-driven
  approvals/rejections — the USER / TENANT column showed "N/A" and
  rejections never appeared as "Blocked" rows. Both paths now write
  an `audit_logs` row via a new `Repository.WriteHITLAuditEvent`
  helper with `request_type="workflow_step_gate"`,
  `policy_decision="allowed"` on approve / `"blocked"` on reject,
  the reviewer's email and role populated, and `workflow_id` /
  `step_id` / `request_id` / `policy_name` in `policy_details`. Write
  is best-effort — a DB failure does not fail the mutation because
  `hitl_approval_history` remains the authoritative record.
- **Portal execution timeline renders rejector identity correctly.**
  The portal execution page already read `approved_by` and
  `rejected_by` as separate fields, but the Community-side serializer
  only populated `approved_by` — so a rejected step appeared as
  "approved by \<rejector\>". Paired with the Community-side split
  above, the timeline now renders "Approval: rejected by \<email\>
  on \<date\>" when `approval_status=rejected` and the approved
  variant when approved, suppressing the other field in each case.
  `ExecutionStep` on the portal API client gains `rejected_by` /
  `rejected_at`.
- **Sidebar approvals badge refreshes immediately after approve or
  reject in the same tab.** The Navigation component polls
  `getPendingApprovals` every 30 s. When a reviewer approved or
  rejected from the side panel, the approvals list removed the row
  optimistically but the `1` badge next to "Approvals" in the sidebar
  lingered until the next poll — visually making the queue look
  unreclaimed. The approvals page now dispatches an
  `approvals:updated` CustomEvent on success; Navigation listens and
  re-fetches immediately. Event listener cleaned up on unmount
  alongside the polling interval. Cross-tab approvals (second browser
  window, SDK, or CLI) still fall back to the 30 s poll — same-tab
  only is the scope of this fix.

---

## [7.4.0] - 2026-04-22 — HITL Response Parity

MINOR: both HITL planes now return the same rich response shape, MAP's
plan-scoped approve/reject endpoints are now available at **Evaluation** tier
(previously Enterprise-only), and MAP gains a plane-scoped pending-approvals
listing symmetric with the existing WCP endpoint. `decision` resolves to
`"allow"` / `"block"` once the mutation lands, `retry_context` mirrors the
gate response retry state, approver metadata comes from the same persisted
row, `approval_id` surfaces the HITL queue entry UUID, and `policies_matched`
reconstructs the governance trail. Contract tests in CI lock the two planes'
response shapes together so future additions surface on both endpoints by
default — both for approve/reject and for the plane-scoped pending listings.

No breaking changes. Purely additive — the legacy `workflow_id` / `step_id` /
`status` / `approval_status` / `approved_by` / `message` fields existing
callers rely on are unchanged.

### Community

#### Added

- **Shared HITL response projection helper** in the community codebase —
  `workflow_control.ProjectStepGateToHTTP` and `DeriveHITLApprovalID`. Both
  planes' handlers use it, so the wire shape stays consistent and the
  deterministic HITL queue UUID reappears on every response where the
  backing workflow_steps row exists.
- **Plan-to-workflow lookup** — `GetWorkflowByPlanID` service method +
  PostgreSQL repository implementation (index on `metadata->>'plan_id'`).
  Enables plan-scoped HITL endpoints to project from the same
  `workflow_steps` row that /gate and /complete use.

#### Deprecated

- `DO_NOT_TRACK=1` as an AxonFlow SDK telemetry opt-out — scheduled for
  removal after 2026-05-05 in the next major release. Use
  `AXONFLOW_TELEMETRY=off` instead. All 4 SDKs emit a one-line migration
  warning when `DO_NOT_TRACK=1` is the active control and
  `AXONFLOW_TELEMETRY=off` is not also set. See the SDK CHANGELOGs for
  per-language notes.

### Evaluation

#### Added

- **Rich WCP approve/reject responses.** `POST /api/v1/workflows/{id}/steps/{step_id}/approve`
  and `.../reject` now return `decision`, `reason`, `retry_context`,
  `approval_id`, `approved_by` / `approved_at` (or `rejected_by` /
  `rejected_at`), `policies_matched`, `status`, and `message`. Documented
  in OpenAPI as `ApprovalResponse`; mirrors the step-gate response field set.
- **Rich MAP approve/reject responses** at the `/api/v1/plans/{id}/steps/{step_id}/approve|reject`
  endpoints. Same shape as WCP plus a `plan_id` field. Two underlying flows —
  confirm/step mode (WCP-backed) and legacy policy-driven pause/resume —
  now surface a uniform shape so clients don't branch on which mode the
  plan ran in.
- **Plane-scoped pending-approvals listing** — new
  `GET /api/v1/plans/approvals/pending` endpoint (Evaluation+), the MAP
  counterpart of the existing `GET /api/v1/workflows/approvals/pending`.
  Returns `{pending_approvals, count}` with every entry carrying `plan_id`
  (populated from `workflows.metadata->>'plan_id'`). Optional `?plan_id=`
  query param scopes the listing to a single plan so reviewer tools can
  render per-plan context without filtering client-side. Tier-gated on
  `IsHITLApprovalEnabled()` — same gate as the plane-scoped approve/reject.

#### Changed

- **MAP plan-scoped HITL tier gate lowered to Evaluation+** (was Enterprise-only
  pre-v7.4.0). Tier check now matches WCP: community + Evaluation license →
  accepted; community + no license → 403; enterprise mode → accepted. Error
  message updated from "requires Enterprise license" to "requires Evaluation
  or Enterprise license."
- **Cross-plane contract test** in CI asserts the WCP and MAP response field
  sets stay aligned modulo the intentional `plan_id` asymmetry. Guards
  against silent future drift when either plane grows a new field. A sibling
  `TestPendingApprovalsPlaneParity` does the same for the plane-scoped
  pending-approvals listings — the intentional `plan_id` asymmetry is
  enforced: populated on every MAP entry, never on WCP entries.

### SDKs

- **Go SDK v5.6.0** — `ApproveStepResponse` / `RejectStepResponse` gain
  `Decision`, `Reason`, `ApprovalStatus`, `ApprovalID`, `ApprovedBy` /
  `ApprovedAt` / `RejectedBy` / `RejectedAt`, `PoliciesMatched`,
  `RetryContext`, `Message`, `PlanID`. New `GetPendingPlanApprovals` method
  covers the MAP-plane listing. `PendingApproval` extended with `PlanID`,
  `StepIndex`, `Decision`, `DecisionReason`, `PoliciesMatched`, `StepInput`,
  `ApprovalStatus`. Also fixes three pre-existing URL bugs on
  `ApproveStep` / `RejectStep` / `GetPendingApprovals` (they were hitting
  non-existent `/api/v1/workflow-control/` paths) and renames the response
  wire shape to match the server (`PendingApprovals` / `Count`).
- **TypeScript SDK v5.6.0** — same rich fields on `ApproveStepResponse` /
  `RejectStepResponse` interfaces, new `getPendingPlanApprovals`, extended
  `PendingApproval` interface, and the same WCP URL / response-shape fixes.
- **Python SDK v6.6.0** — rich optional fields on the pydantic
  `ApproveStepResponse` / `RejectStepResponse` models, new
  `get_pending_plan_approvals` method (sync wrapper included), extended
  `PendingApproval` model, and the same WCP URL / response-shape fixes.
- **Java SDK v5.7.0** — rich fields on `WorkflowTypes.ApproveStepResponse`
  and `.RejectStepResponse`, plus back-compat 3-arg constructors so existing
  test fixtures keep compiling. New `getPendingPlanApprovals` + async
  variant. Extended `PendingApproval` class with back-compat 6-arg
  constructor. Same WCP URL / response-getter fixes.

---

## [7.3.0] - 2026-04-21 — Retry Semantics & Idempotency

MINOR: first-class retry and idempotency surfaces on the Workflow Control
Plane. The `cached: bool` signal every gate response has been returning is
now a deprecated alias — responses carry a `retry_context` block that
answers "how many gate calls?", "did any prior attempt complete?", and
"what was the prior decision?" unambiguously. A new caller-supplied
`idempotency_key` on gate + complete anchors a workflow step to a
business-level identity (payment intent, invoice, claim reference), with
strict match validation between the two endpoints.

No breaking changes. Purely additive.

### Community

#### Added

- **`retry_context` on every `StepGateResponse`** — always present, including
  on the first gate call (where counters are 1/0 and
  `prior_completion_status` is `"none"`). Fields: `gate_count`,
  `completion_count`, `prior_completion_status` (enum `none` / `completed` /
  `gated_not_completed`), `prior_output_available`, `prior_output`,
  `prior_completion_at`, `first_attempt_at`, `last_attempt_at`,
  `last_decision`, `idempotency_key`. Counter bookkeeping is atomic inside
  the repository UPSERT; a separate cached-hit update keeps counters
  accurate across idempotent retries without re-evaluating policy.
- **`?include_prior_output=true` query param on `/gate`** — opt-in inclusion
  of the prior `/complete` payload in `retry_context.prior_output`. Default
  is `false` (null) because output may be large and/or contain sensitive
  data. When the opt-in is set AND a prior completion exists, the full
  output is returned so agents can safely short-circuit re-execution.
- **Caller-supplied `idempotency_key` on `/gate` and `/complete`** —
  optional opaque string up to 255 chars. Recorded on the first gate call
  that sets it; immutable for the step's lifetime. Surfaced on every
  subsequent `retry_context.idempotency_key`. Audit log records the key
  on every `step_gate` and `step_completed` event.
- **`HTTP 409 IDEMPOTENCY_KEY_MISMATCH`** returned when `/complete` (or a
  subsequent `/gate`) passes a different key than the one recorded on the
  first gate, or when one side supplies a key and the other omits it.
  Response envelope includes `expected_idempotency_key` and
  `received_idempotency_key` so SDKs can build typed errors.
- **`cached` and `decision_source` fields remain on every response** so
  existing SDK versions continue working unchanged. Both are marked
  deprecated in the wire docs; `retry_context.gate_count > 1` replaces
  `cached: true` and `retry_context.prior_completion_status` replaces the
  string-typed `decision_source`.

#### Changed

- **`MarkStepCompleted` HTTP handler** now reads tenant identity from
  `X-Tenant-ID` consistently with `StepGate` rather than from
  `X-Client-ID`. A real multi-tenant caller setting the tenant header now
  works on both endpoints; previously the complete path rejected the
  request as "workflow not found" because the isolation check compared
  against the wrong attribute. No behavior change for callers using
  empty headers.

### Evaluation

#### Added

- **Retry-aware dynamic policy conditions** — the policy engine now
  resolves seven new `step.*` fields: `step.gate_count`,
  `step.completion_count`, `step.prior_completion_status` (enum `none` /
  `completed` / `gated_not_completed`), `step.prior_output_available`,
  `step.last_decision`, `step.first_attempt_age_seconds`, and
  `step.idempotency_key`. Policy authors can write rules like
  "retry on un-completed payment requires approval", "more than three
  attempts = block", or "rapid retry within 30 seconds escalates severity"
  without custom code. These fields are added to `ValidPolicyFields` so
  the create/update policy APIs accept them.
- **Tier-gated create:** attempting to author a dynamic policy with any
  `step.*` condition on a Community license is rejected at create time
  with `FEATURE_REQUIRES_EVALUATION_LICENSE`. Evaluation and Enterprise
  tiers accept. Enforcement sits in `PolicyService.validateTierForCreate`
  before the tenant policy-count check, so the rejection fires cleanly
  without a DB roundtrip.
- **UX note for policy authors:** retry-aware policies only fire when
  callers pass `retry_policy: "reevaluate"` on subsequent `/gate` calls.
  Default-idempotent retries hit the cache and bypass the policy engine,
  consistent with the existing cache semantics. Documented in the
  bundled Evaluation-tier example.

### Enterprise

No Enterprise-exclusive additions in this release. Cross-workflow
idempotency lookup, windowed operators like `idempotency_key_seen_within`,
retry-pattern correlation across workflows, and compliance-grade
audit/reporting for duplicate prevention are on the roadmap for a
later release.

---

## [7.2.1] - 2026-04-21

PATCH: surface the HITL approval metadata that was already being captured
internally but dropped on the way out of the API. No schema changes, no
breaking changes — callers that previously handled `null` simply start
seeing real values.

### Community

#### Fixed

- **`/api/v1/workflows/{id}` now surfaces `approved_by` and `approved_at` on
  each step.** The `StepInfo` DTO used by the workflow-detail response was
  missing both fields, so callers polling for approval completion saw
  `approval_status: "approved"` but no approver identity or timestamp.
  Both fields were already captured by `ApproveStep` and persisted on the
  `WorkflowStep` row — the DTO just wasn't copying them over. Portal and
  SDK consumers now get the full provenance without a second round-trip
  to the audit log.
- **`StepGateResponse.approval_id` populated on `require_approval`
  decisions.** The HITL adapter was creating the approval queue entry and
  setting `StepGateEvaluation.ApprovalID`, but the API response struct
  didn't carry the field. SDK clients that want to correlate a paused
  step with its HITL queue row (for Slack/PagerDuty routing, direct
  portal deep-links, or programmatic approval) now get `approval_id` on
  the same response that reports the `require_approval` decision.

### Enterprise

#### Fixed

- **Customer Portal `/approvals` page no longer crashes on expand.** The
  `PendingApproval.policies_matched` TypeScript type declared the field
  as `string[]`, but the `/api/v1/workflows/approvals/pending` endpoint
  returns an array of `PolicyMatch` objects (`{policy_id, policy_name,
  action, risk_level, allow_override, policy_description}`). React
  tried to render the object directly and threw error #31 ("Objects
  are not valid as a React child"), dumping the approver into the
  ErrorBoundary fallback the moment they clicked a row to expand the
  detail panel. The approvals page now accepts either shape, extracts
  `policy_name` when given an object, and surfaces `policy_description`
  as a tooltip on the matched-policy chip.

---

## [7.2.0] - 2026-04-20 — The Bug Bash Bonanza 🪲🔨

A focused hardening release: a full sweep across the Customer Portal
HTTP surface, tenant-scope fail-closed enforcement on every
read-and-action endpoint, three new public platform knobs for the
MAP plan-execution budget, dedicated HTTP examples for every route
the Portal calls, a login-endpoint fix that closes an
org-enumeration leak via both response body and timing, and fixes
to make MAP plans run the full 5 minutes the server is happy to
give them. MINOR per semver — additive surface only; every 7.1.x
caller keeps working without changes.

### Added

#### Community

- **`AXONFLOW_MAP_MAX_TIMEOUT_SECONDS` orchestrator env.** Caps the
  MAP plan-execution budget without a binary rebuild. Clamped to
  60..1800 seconds; default 300. The effective value is logged at
  startup when non-default. If you front the orchestrator with a
  reverse proxy or load balancer, set its idle / read timeout to
  at least the orchestrator cap — otherwise long plans will be
  cut off at the proxy before the orchestrator finishes.

#### Enterprise

- **`AlbIdleTimeoutSeconds` CloudFormation parameter on the
  AWS Marketplace template.** Mirror of the Community knob.
- **`middleware.MaxBodyBytesMiddleware` exported on the Customer
  Portal.** Caps every POST/PUT/PATCH request body at 1 MiB by
  default; `MaxBodyBytesMiddlewareWithLimit(n int64)` returns a
  variant for routes that legitimately need a larger ceiling (SAML
  metadata, future file uploads). GET/HEAD are not wrapped.
- **Per-feature HTTP examples for every route the Portal UI
  calls.** Each example is runnable against a local Docker Compose
  stack and covers one topic end-to-end:
    - Full RBI AI-system lifecycle: register → validate → incident
      → kill-switch → board report → audit export.
    - SEBI dashboard, retention, readiness, and audit export.
    - EU AI Act conformity, accuracy/bias, and async export jobs.
    - Compliance evidence bundle (summary + stream-download).
    - Decision explainability with the cross-tenant 404 guard
      asserted.
    - License, deployment, nodes, and session metadata.
    - Policy bundle export/import with `overwrite_mode` semantics.
    - Full `/api/v1/auth/*` walkthrough: login, session, logout,
      SSO availability, forgot-password, reset-password,
      change-password — including the auth-enum identical-body
      assertions.
  A curl-based smoke runner covers every Portal API route (44
  total) without needing a browser, pairing with the Playwright
  health spec so CI and demo-freeze runs have a Playwright-free
  verification path. Every script passes `shellcheck` and runs
  green against local compose.
- **Compliance → Evidence Export Download button.** The Compliance
  page showed per-type record counts (audit logs, workflow steps,
  HITL approvals) but had no way to actually download the bundle.
  Added a Download Evidence button that streams the JSON bundle as
  a blob with a 30-day default window (the backend caps by tier)
  and saves as `axonflow-evidence-<start>-to-<end>.json`. Disabled
  with a tooltip explanation when counts are zero. Surfaces any
  backend error (tier / license / quota) as an inline alert
  instead of silently doing nothing.

### Fixed

#### Community

- **Agent now proxies `/api/v1/euaiact/*` to the orchestrator.**
  The single-entry-point mux listed `/rbi`, `/sebi`, and
  `/masfeat` alongside the rest of the compliance family but
  omitted `/euaiact`, so every EU AI Act call that landed on the
  front-door ALB returned `404 page not found` and the Portal's
  Compliance page reported the module as "not enabled for this
  tenant" even though peer modules rendered fine. Added the prefix
  to both the router and the proxy-allow-list.
- **Canonical `/api/v1/policy-overrides` alias on the agent.** The
  Portal's overrides handler proxies to this path, matching the
  `policy-categories` / `static-policies` / `dynamic-policies`
  naming pattern; the agent previously only exposed the tenant
  override list under `/api/v1/static-policies/overrides`.
  Callers using the canonical path hit 404 and the Portal's
  Policies → Overrides tab rendered empty. Same handler, new
  path, auth unchanged.
- **Agent `/health` includes `tier`.** The validated license tier
  (`Community` / `Evaluation` / `Professional` / `Enterprise` /
  `starting`) is now surfaced on the health response. Operators
  querying `curl /health | jq .tier` used to get `"unknown"`
  because the field was not present.
- **Orchestrator MAP plan-execution budget now caps at 300s by
  default.** MAP plans chain multiple LLM calls (~15s each); a
  typical 5-step plan routinely ran past the old 60s server-side
  default and truncated mid-stream even though the orchestrator
  was still working. The cap is now 300s out of the box and
  tunable via `AXONFLOW_MAP_MAX_TIMEOUT_SECONDS`. SDK note: the
  TypeScript SDK's default `mapTimeout` is 120s; clients relying
  on the default will cut off at 120s before the server cap
  takes effect. Pass `mapTimeout: 300000` on the SDK client
  config to match.
- **Orchestrator policy type allowlist accepts `context_aware`.**
  Three seeded system policies (Tenant Isolation, Debug Mode
  Restriction, Sensitive Data Control) ship with
  `policy_type=context_aware`; any update through
  `PUT /api/v1/policies/{id}` returned 400 because that type was
  missing from the allowlist.
- **`POST /api/v1/policies/{id}/overrides` accepts
  `require_approval` (HITL).** The override validator's allow-list
  was hand-written as `{block, redact, warn, log}`, silently
  dropping the HITL action even though the rest of the stack
  accepted it end-to-end. Standardised on a single canonical list
  of valid actions:
    - Policy authoring — `alert`, `block`, `log`, `modify_risk`,
      `redact`, `require_approval`, `route`, `warn`.
    - Override endpoint (terminal-action subset) — `block`,
      `require_approval`, `redact`, `warn`, `log`. Authoring-only
      actions are deliberately excluded — they have no
      terminal-action meaning and the agent's override repository
      would reject them anyway.
- **Test / Edit / Delete / Versions of legacy-named policies no
  longer 400.** The policy-ID validator only accepted UUIDs and
  the `sys_*` prefix, so seeded policies like
  `sensitive_data_control` and `tenant_isolation` failed every
  per-policy action with "Invalid policy ID format". Allowlist now
  also accepts the legacy snake-case form.
- **`GET /api/v1/policies` honours the `tier` and `category` query
  params.** The orchestrator's list handler dropped both at the
  handler boundary even though the repo supported them. Without
  this every Tier / Category dropdown in the Portal's
  `/policies` page returned the full unfiltered list.
- **Legacy V1 HMAC license format purged from active code.** The
  V2 Ed25519 format has been the only accepted key for months;
  stale HMAC references would have produced confusing failures
  in a clean shell. The rejection-path code that returns `"V1
  license format no longer supported"` is kept so an old key
  ever surfacing gets a clear error, not silent acceptance.

#### Enterprise

- **RBI FREE-AI: registering an AI system no longer 500s.** The
  repository's INSERT listed `board_approval_required`, but that
  column is a stored-generated column computed from
  `risk_category`. PostgreSQL rejected every write with
  `cannot insert a non-DEFAULT value into column
  board_approval_required`, so the Portal's RBI compliance page
  could never progress past step 1. Removed the column from the
  INSERT and UPDATE statements; the Go struct field is still
  populated at read time.
- **RBI FREE-AI: generating a board report no longer 500s.** The
  service layer set `generation_method = "automated"` but the
  database check constraint only accepts `'automatic'` or
  `'manual'`. Fixed the literal.
- **Marketplace CloudFormation: Agent security group can reach the
  Customer Portal.** Per the single-entry-point architecture,
  every public request funnels through the Agent, which then
  proxies `/api/v1/auth/*`, `/api/v1/portal/*`,
  `/api/v1/code-governance/*`, and `/api/v1/git-providers/*` to
  the Customer Portal over Cloud Map. The security group allowed
  ALB → Portal and Portal → Agent but nothing allowed Agent →
  Portal, so every auth call hitting the raw stack domain timed
  out after 30 seconds and fell back to `503 Backend service
  unavailable`. The vanity-domain host-header rule routed
  directly to the UI and masked the issue during demo prep; only
  requests on the raw stack domain surfaced it. Applies on
  `update-stack` without recycling ECS tasks.
- **Usage & Billing no longer returns zeros for every tenant.**
  The daily rollup was defined but never invoked — no scheduler,
  no goroutine, no on-demand call — so the rollup table stayed
  empty forever and the Portal's summary and time-series queries
  returned zeros even when the underlying events had rows. The
  aggregator is now idempotent (re-running an overlapping window
  recomputes the bucket rather than adding to it) and is called
  on-demand from the Usage handlers before they query the
  rollup — self-healing, no scheduler required. A pre-existing
  latent bug that surfaced once rollups populated
  (`COALESCE(AVG())` returns numeric, the scan target was int)
  is fixed in the same change.
- **`GET /api/v1/export/usage` no longer 500s.** The handler
  queried columns that didn't exist (`policy_id`, `latency_ms`,
  `success` — the real columns are `policy_decision`,
  `response_time_ms`, and a derived success flag), constructed
  `INTERVAL '$2 days'` which is not valid PostgreSQL
  parameterization (the `$2` inside a string literal is treated
  as literal characters, not a placeholder), and ignored the
  `start` / `end` query params the UI sends (only honouring a
  legacy `days=` param). Rewritten against the per-request
  metering table with correct columns, proper date-range handling
  for RFC3339 timestamps or `YYYY-MM-DD` dates, and surfaced DB
  errors in the server log instead of swallowing them behind the
  generic `"Database error"` response.
- **`GET /api/v1/license/status` no longer 500s for orgs without
  an `expires_at`.** The handler scanned the column into a
  non-nullable type; NULL expiry blew up inside `Scan`. Switched
  to a nullable target and treats NULL as ACTIVE.
- **`GET /api/v1/admin/organizations/{id}` no longer 500s.** The
  join against the SSO configuration table used the wrong join
  column; every org detail page 500'd with `pq: column
  s.org_id does not exist`.
- **Admin org list queries fixed against the heartbeat schema.**
  Both the list and detail endpoints joined `agent_heartbeats` on
  column names that don't exist (`organization_id`,
  `last_heartbeat_at`); the real columns are `org_id` and
  `last_heartbeat`. Both endpoints returned 500 with
  `pq: column "organization_id" does not exist`.
- **Customer Portal Docker image builds with the Enterprise Go
  tag.** The Portal Dockerfile previously hard-coded a Community
  build, so `license.GenerateLicenseKey` always returned the
  Community stub and admin onboarding 500'd on every call,
  leaving the orgs table empty and the SaaS deployment with no
  orgs to log in as.
- **Dashboard "Workflows Run" counts MAP plans too.** The
  dashboard summary queried the WCP-only execution endpoint, so
  MAP-only tenants saw `Workflows Run: 0` even after running
  plans. Now queries the cross-type unified executions endpoint
  with a fallback to the legacy shape for older server builds.
- **Dashboard no longer renders "Welcome," with an empty name.**
  The page mounted before `AuthContext.checkSession()` resolved,
  so the heading printed "Welcome," and the License Status card
  printed an empty Organization ID. The dashboard now waits on
  the session-loading gate.
- **Sidebar pending-approvals badge no longer fires a console
  401 on first paint.** The poll fired from a `useEffect` on
  mount without a user guard; on a hard refresh the first poll
  raced the session check and hit the catch-all orchestrator
  proxy without an authenticated session. The poll now waits
  for the user to be non-null and re-runs when the user
  changes.
- **`setup-vanity-domain` workflow overwrites stale CFN-managed
  ALB private-DNS aliases.** When a stack is rebuilt the old ALB
  DNS goes away; the workflow used to refuse to touch the
  existing record, leaving the Portal UI's API backend URL
  resolving to a deleted ALB inside the VPC — surfaced as 503
  "Backend service unavailable" on the login page. The workflow
  now upserts when the existing target matches the CFN naming
  pattern, and continues to skip operator-managed records.
- **Policy editor accepts `context_aware` and exposes
  `require_approval`.** Mirrors the orchestrator allowlist change
  above; users can now author HITL policies end-to-end without
  the request-level 400 that previously dropped the action at
  the Portal boundary.
- **Policy modal interactions no longer swallowed by the
  backdrop.** A CSS stacking-context bug made Save Changes,
  Cancel, and every form input unclickable; the Edit-policy
  flow looked broken. Promoted the dialog content to a higher
  z-index.
- **Modal form inputs readable in OS dark mode.** A leftover
  `prefers-color-scheme: dark` block from the create-next-app
  template repointed form text to near-white over a hardcoded
  white modal, so field values looked empty. The block is
  removed and native controls (checkboxes, scrollbars) now
  follow the light color scheme.
- **`/export` page no longer logs a React hydration error.** The
  date-range hint rendered `new Date().toLocaleDateString()`
  directly in JSX, producing different output on the SSR pass
  vs the client. Deferred the dates behind a `mounted` flag.
- **`POST /api/v1/admin/onboard-customer` accepts an optional
  `license_key`.** Lets operators register an org against an
  already-minted license (Lambda bootstrap, key-rotation
  scripts, existing SDK customers) without forcing the Portal
  to re-key. When set, in-process generation is skipped and
  the existing Secrets Manager entry is left untouched.
- **Marketplace CloudFormation: orchestrator connector secrets
  resolve under the per-stack environment name.** Fourteen
  connector secret paths used the wrong path component; on any
  non-default stack every connector came up with empty
  credentials. The `TaskExecutionRole` IAM grant now matches
  the per-stack path as well, with an `AllowedPattern` on
  `EnvironmentName` so typos fail at `CreateChangeSet` time
  rather than at runtime.

### Security

#### Community

- **Internal-service auth no longer accepts a static fallback
  token in non-Community deployments.** When the
  internal-service secret was unset, the agent fell through to
  a literal-string compare against a constant. Any caller
  knowing that constant could supply internal-service headers
  and impersonate the orchestrator, injecting arbitrary
  `X-Tenant-ID` / `X-Org-ID` for cross-tenant access. The
  fallback path is now gated to Community / Community-SaaS
  modes only; outside those a one-time security warning is
  logged at startup. HMAC and legacy plain-secret paths are
  unchanged.
- **Orchestrator audit handler fails closed when proxy auth is
  missing in non-Community deployments.** The handler
  previously skipped the proxy-auth validation entirely when
  the token validator was nil — the same misconfiguration
  shape that enabled the agent fallback bypass above. An
  attacker reaching the orchestrator directly could spoof
  `X-Org-ID` for cross-tenant audit attribution. The handler
  now returns 403 if the validator is nil and the deployment
  mode is not Community.
- **`GET /api/v1/decisions/{id}/explain` filters tenant in the
  SELECT clause.** The handler used to look up the audit entry
  by `decision_id` only and post-check the tenant; the
  short-circuit on email failed open whenever the user-email
  column was NULL, and the email check itself was bypassable
  by an attacker who happened to share an email with the
  decision owner across tenants. Now: `X-Tenant-ID` is
  required, the SELECT binds on `(decisionID, callerTenant)`,
  and cross-tenant requests return 404 (not 403) so the
  response shape doesn't leak whether `decision_id` exists in
  another tenant. The post-fetch tenant comparison is kept as
  defense-in-depth.
- **`POST /api/v1/evidence/export` and `GET /api/v1/evidence/summary`
  fail closed when the tenant scope is missing.** Both endpoints
  previously fell back to an empty-string tenant when neither
  `X-Tenant-ID` nor a context-stored `tenant_id` was set, then
  ran SQL with `WHERE tenant_id = ''` — zero rows in practice
  but silently burned a daily-export quota slot for an empty
  bucket and would have leaked data the moment a downstream
  query stopped filtering. Both now return 401
  `TENANT_REQUIRED` when neither source provides a scope.
- **`POST /api/v1/policies/simulate` and
  `POST /api/v1/policies/{id}/impact-report` adopt the same
  fail-closed tenant resolution.** Same header-then-context-
  then-fall-through-to-empty pattern as evidence/export; would
  have shared a global empty-tenant rate-limit bucket when
  called without `X-Tenant-ID`.
- **`POST /api/v1/cost/estimate` and
  `GET /api/v1/plans/{id}/cost` reject anonymous callers.**
  Both substituted a `"_default"` literal for an empty
  `X-Tenant-ID`, so every unauthenticated caller drained the
  same daily quota. Both now return 401 `TENANT_REQUIRED`.
- **`GET /api/v1/audit/tenant/{tenant_id}` requires
  `X-Tenant-ID`.** The URL-vs-session tenant mismatch check
  was gated on a non-empty session tenant, so omitting the
  header bypassed the cross-check entirely. The header is now
  required; mismatches still return 403.
- **`/api/v1/audit/search` enforces tenant scoping from the
  trusted header.** The handler ignored the proxy-injected
  tenant header and only filtered on caller-supplied criteria,
  so a Portal user for tenant A could read tenant B's audit
  logs by POSTing to `/api/v1/audit/search`. The header is now
  required and decoded into a JSON-tag-ignored field so a
  malicious payload cannot override it. The same path also
  silently-disabled tenant filtering on
  `/api/v1/audit/tenant/{id}` because the tenant-only struct
  shape no longer matched after a `StartTime` field was added;
  the new SQL filter fixes that too.
- **`/api/v1/audit/tenant/{tenant_id}` rejects URL paths that
  don't match the session tenant.** Without the cross-check a
  Portal user for tenant A could read tenant B's audit history
  by browsing to `/api/v1/audit/tenant/B`.

#### Enterprise

- **Customer Portal login no longer leaks org existence or auth
  mode.** `POST /api/v1/auth/login` returned three
  distinguishable failure responses that together let an
  unauthenticated caller enumerate valid org IDs and classify
  each org by auth mode:
    - Unknown org: `401 "Invalid credentials"` (no bcrypt work).
    - Known org with no password set (SSO-only): `401 "Password
      authentication not enabled for this organization"` (no
      bcrypt work).
    - Known org, bad password: `401 "Invalid credentials"`
      (full bcrypt compare).
  The distinct no-password body outed which orgs existed and
  which were password-backed; even with a uniform body the
  missing bcrypt on the first two branches leaked the same bit
  through response timing. Every failure now returns `"Invalid
  credentials"`; the no-password branch runs a throwaway
  bcrypt compare against a fixed placeholder hash so the
  timing profile matches a real check. SSO-only orgs cannot
  log in through this path — they are simply indistinguishable
  from wrong-password attempts to an external caller.
- **Customer Portal request-body size capped at 1 MiB.** The
  Portal had no upstream bound on JSON-decode; a single
  multi-GB POST could pin goroutines and memory. The new
  middleware caps POST/PUT/PATCH bodies at 1 MiB by default
  and is wired into the Portal's outer chain so SCIM, admin,
  and session-protected handlers all inherit it.
- **System policies visible in the Customer Portal.** The
  Portal's fetch-static-policies call landed on the agent
  without internal-service credentials and was denied 401, so
  the Static (Read-only) count showed 0 next to a Total
  Policies of 17 — the 80+ PII / SQLi / dangerous-commands
  rules were invisible. Three paired changes restore
  visibility: the agent accepts internal-service credentials
  from headers alongside the hint-based path, the Portal
  signs every agent call with the internal-service secret,
  and CloudFormation injects that secret into the Portal task
  definition. Missing-secret deployments log a startup
  warning and continue with empty static policies so dev
  environments degrade gracefully.
- **`POST /api/v1/admin/onboard-customer` is no longer
  unauthenticated, and supplied `license_key` payloads are
  verified.** The route was registered on the bare router
  with a "legacy / no auth for backward compatibility"
  comment; anyone reachable on the Portal could hit it,
  write rows into the orgs table, mint license keys, and
  overwrite Secrets Manager entries. Two paired fixes close
  the gap: the route now lives under the admin subrouter
  that runs the admin auth middleware (API key required in
  SaaS production; optional otherwise), and when the request
  supplies `license_key` the handler validates the Ed25519
  signature, expiry, and signed org/tier match before
  accepting. The signed payload's `expires_at` and
  `max_nodes` win over the request body — the body cannot
  widen what the license actually grants.

## [7.1.1] - 2026-04-19

Patch release: closes ten Plugin Batch 1 gaps surfaced across two rounds
of post-release install-and-use E2E testing — first with
`@axonflow/openclaw@1.3.0` (six HTTP-path gaps), then with Claude Code /
Cursor / Codex plugins (four MCP-tool-path gaps the first round missed).
All features from v7.1.0 are unchanged in scope; this release makes them
actually work end-to-end for plugin consumers across both the HTTP and
MCP JSON-RPC surfaces.

### Fixed

- **MCP check-input responses now carry richer context.** Block responses
  include `decision_id`, `risk_level`, `policy_matches`, and
  `override_available`/`override_existing_id` when the caller provides
  `X-User-Email`. Previously the agent returned only the legacy
  `allowed`/`block_reason`/`policies_evaluated` trio, so plugins could
  not surface a useful reason on a block or offer an override CTA.
- **`explainDecision` resolves MCP-path decisions.** MCP
  check-input/check-output decisions are now dual-written to
  `audit_logs` with the decision id in `policy_details`, so the
  existing explain endpoint returns the full `DecisionExplanation`
  rather than 404.
- **MCP check-input now consults active overrides.** Previously the
  handler surfaced `override_available: true` but still returned
  `allowed: false` because override enforcement was wired into the WCP
  path only. A flip-to-allow emits an `override_used` audit event
  mirroring the WCP path.
- **Audit search tolerates NULL columns.** `SearchAuditLogs` previously
  aborted the row scan on a NULL `provider`/`model`/`error_message`/`cost`/
  `response_time_ms`/`tokens_used` and dropped the entire result set,
  hiding every Plugin Batch 1 audit row. The scan now uses nullable
  types and maps to zero values for the caller's `AuditEntry`.
- **Cache invalidation on override create matches WCP cache shape.**
  `invalidateCachedDeniedDecisions` previously matched the policy UUID
  against `workflow_steps.policies_matched[].policy_id`, but the WCP
  adapter writes the policy NAME in that slot. The helper now resolves
  UUID + slug + name synonyms and matches any of them, so overrides
  actually flush the WCP cache.
- **WCP-path overrides now apply.**
  `DatabaseDynamicPolicyEngine.EvaluateDynamicPolicies` (used by the WCP
  step gate) now populates `result.AppliedPoliciesDetail`. Previously
  only the in-memory engine did, so `ApplyOverrideToResult` iterated an
  empty slice on the WCP path and no override ever flipped a deny.
- **MCP `tools/call` path now emits richer-context on blocks.** Same
  fix as the HTTP check-input path, mirrored into `mcpToolCheckPolicy`
  and `mcpToolCheckOutput`. Pre-fix, Claude Code / Cursor / Codex
  plugins (which use the MCP server's JSON-RPC surface rather than the
  HTTP endpoint OpenClaw uses) saw a terse "blocked" string with no
  `decision_id` / `risk_level` / `policy_matches` / `override_available`.
  Override apply + audit dual-write are now mirrored identically across
  both surfaces.
- **`createOverride` / `listOverrides` accept UUID *or* slug/name for
  `policy_id`.** Plugins read `policy_id` from a check-input response's
  `policy_matches[]` (where static policies carry the slug, not the
  UUID) and pass that straight to the override endpoints. Pre-fix, the
  orchestrator required the UUID and returned 404 for slug callers.
  `policyRiskAndOverride` now resolves either and stores the canonical
  UUID in `policy_overrides.policy_id`.
- **`DatabaseDynamicPolicyEngine` schema covers the new columns.**
  `dbPolicyEngineSchema()` now includes `id UUID`, `risk_level`, and
  `allow_override` so integration tests and fresh clusters match
  migration 070's shape.
- **`policy_override_repository.policyRiskAndOverride` returns the
  canonical UUID.** Callers can no longer store the user-supplied
  value (which may be a slug) in `policy_overrides.policy_id`.

### Changed

- **Workflow handler `getUserID` falls back to `X-User-Email`.** Matches
  the Plugin Batch 1 convention of per-user identity via the email
  header, so WCP workflows capture per-user scoping and the cache
  invalidation query finds the right rows.

### Internal

- New `platform/agent/mcp_richer_context.go` helper module.
- New install-E2E scenario scripts at
  `tests/e2e/plugin-batch-1/{openclaw,claude,cursor,codex}-install/`
  covering the post-release "install from npm / GitHub release and use
  as a real user would" layer that caught these ten gaps across both
  the HTTP check-input path and the MCP tools/call path.
  `PLUGIN_E2E_TESTING_WORKFLOW.md` now mandates both paths as separate
  install-E2E layers for every future plugin batch.

---

## [7.1.0] - 2026-04-18

Combined release: Workflow State Management & HITL Enhancement +
Plugin Batch 1 — Governed Overrides & Explainability.

### Added

#### Workflow State Management & HITL Enhancement

- **Execution boundary semantics** — Step gate decisions are now idempotent
  by default. Calling the same `(workflow_id, step_id)` returns the cached
  decision without re-running the policy evaluator. Pass
  `retry_policy: "reevaluate"` to force a fresh evaluation when external state
  has changed. Responses include `cached` (boolean) and `decision_source`
  ("fresh" or "cached") so callers always know the provenance of the decision.

- **Workflow checkpoints** — Every step gate evaluation automatically creates
  a checkpoint capturing the decision, policy context, and full step metadata
  (model, provider, tool context, actor identity). Checkpoints are
  governance-aware resume boundaries, not arbitrary snapshots.
  - Community: list checkpoints via `GET /api/v1/workflows/{id}/checkpoints`
  - Evaluation: resume from last checkpoint via `POST /api/v1/workflows/{id}/checkpoints/resume`
  - Enterprise: resume from any checkpoint via `POST /api/v1/workflows/{id}/checkpoints/{id}/resume`

- **Risk-tiered approval routing** — HITL approval requests now carry a
  severity level (critical, high, medium, low) derived from the triggering
  policy's action config or the policy evaluation risk score. When multiple
  policies match, the highest severity wins. The HITL queue can be filtered
  by severity.
  - Enterprise: auto-approve low-risk actions after a configurable delay,
    escalate critical-risk actions past SLA threshold. Configure via
    `AXONFLOW_RISK_TIER_ENABLED`, `AXONFLOW_RISK_TIER_ORG_ID`,
    `AXONFLOW_LOW_AUTO_APPROVE_DELAY_MIN`, `AXONFLOW_CRITICAL_ESCALATION_SLA_MIN`.

- **Deterministic approval deduplication** — WCP approval creation uses a
  deterministic UUID derived from `(workflow_id, step_id)` combined with
  `ON CONFLICT` to guarantee exactly one approval per execution boundary,
  even under concurrent first-time calls.

#### Plugin Batch 1 — Governed Overrides & Explainability

- **Governed session overrides** — users can grant themselves a time-bounded,
  audit-logged override on a policy that would otherwise deny, closing the
  dev-mode UX gap without weakening governance. TTL is clamped server-side
  (default 60 minutes, hard cap 24 hours, zero for critical-risk policies).
  A free-text justification is mandatory on every override. Four new audit
  event types record the full lifecycle: `override_created`, `override_used`,
  `override_expired`, `override_revoked`. New endpoints: `POST /api/v1/overrides`,
  `GET /api/v1/overrides`, `GET /api/v1/overrides/{id}`,
  `DELETE /api/v1/overrides/{id}`.
- **Policy risk level + override flag** — every policy now carries an explicit
  `risk_level` (`low` | `medium` | `high` | `critical`) and an
  `allow_override` boolean. The combination is enforced as a contract: a
  database trigger forces `allow_override=false` whenever `risk_level=critical`,
  and the override creation endpoint rejects with 403 if either condition
  forbids the override. Existing policies are migrated with sensible defaults
  (dangerous commands, RCE, and privilege-escalation categories set to
  `critical`; SQLi, prompt injection, and secret leaks set to `high`).
- **Richer approval context** — `PolicyMatch` now includes `risk_level`,
  `allow_override`, `matched_rule`, and `policy_description` fields. Plugins
  can surface a structured reason on every block rather than a terse string.
  Existing consumers are unaffected — all new fields use `omitempty`.
- **Explain-on-demand endpoint** — `GET /api/v1/decisions/{id}/explain`
  returns a stable `DecisionExplanation` payload: matched policies with
  descriptions, decision + reason, risk level, override availability and any
  existing active override, historical hit count for the same rule in the
  caller's rolling 24-hour session window, and a tool signature. Authorization
  is scoped to the decision owner or same-tenant callers. Payload shape is
  frozen — additive fields only until a major version bump.
- **Audit search filter parity** — `POST /api/v1/audit/search` accepts three
  new optional filters: `decision_id` for explain flows, `policy_name` for
  "what did this policy block" queries, and `override_id` to reconstruct the
  full lifecycle of a single override. Existing filters remain unchanged.
- **MCP tool surface** — `explain_decision`, `create_override`, `delete_override`,
  and `list_overrides` are now exposed as MCP tools on the agent's MCP server,
  alongside the existing `check_policy` / `check_output` / `audit_tool_call`
  / `list_policies` / `get_policy_stats` / `search_audit_events` tools. Agents
  running in the plugin ecosystem can drive the full override lifecycle and
  decision explainability without leaving the MCP surface.

### Changed

- **Step gate upsert** — Re-evaluation (`retry_policy: "reevaluate"`) now
  updates all step metadata (step_name, step_type, step_input, model,
  provider) in the persisted step record, not just the decision columns.

- **Concurrent safety** — After upserting a step decision, the service reads
  back the persisted row to ensure the response matches what actually landed
  in the database. If a concurrent call won the race with a different
  decision, the persisted (winning) decision is returned.

- **Feature matrix** — Updated with checkpoint and risk-tiered approval rows
  across Community, Evaluation, and Enterprise tiers.

- `DynamicPolicy` and `StaticPolicy` structs gained `risk_level` and
  `allow_override` fields. Policy repositories persist them via migration 070.

### Fixed

- **Severity was hardcoded** — HITL approval severity was always set to
  "high" regardless of the triggering policy's risk level. Now derived from
  the policy's `require_approval` action config or the evaluation risk score.

### Database

- Migration `069_*` — workflow state management (#1607).
- Migration `070_policy_batch1_risk_and_override_extensions.sql` adds
  `risk_level` and `allow_override` columns (with seeded defaults per category)
  to `static_policies` and `dynamic_policies`; extends the existing
  `policy_overrides` table with `tool_signature`, `revoked_at`, `revoked_by`;
  adds `audit_logs` indexes on `decision_id` for the new filters; installs a
  trigger that enforces the critical-risk no-override invariant at the
  database level.

### Plugin ecosystem

The companion plugin releases for Plugin Batch 1 (OpenClaw v1.3.0,
Claude Code v0.5.0, Cursor v0.5.0, Codex v0.4.0) ship the user-facing
consumption of the new override, explain, and audit-search endpoints.

---

## [7.0.1] - 2026-04-11

### Fixed

- **Authentication on all endpoints** — Unified auth handling across gateway,
  MCP, proxy, and API routes. Fixes 401 errors on community-saas (try.getaxonflow.com)
  for gateway pre-check, audit, proxy, and MCP endpoints. Proxy routes
  (dynamic policies, cost controls) were previously inaccessible in
  community-saas mode.
- **Community mode tenant isolation** — Requests in community mode now
  preserve per-tenant scoping. Previously all requests collapsed to a
  single synthetic client, mixing audit and policy data across tenants.
- **Telemetry tracking** — All authenticated requests (including MCP and
  JSON-RPC sessions) now correctly record telemetry in community-saas mode.
- **Audit identity** — Audit records now use the authenticated client identity
  instead of trusting the request body, preventing cross-tenant attribution.
- **MCP server DB auth** — MCP JSON-RPC handler now validates clients
  registered via database, not just the in-memory whitelist.
- **Example credentials** — 139 example files updated to read auth credentials
  from environment variables, fixing failures on authenticated servers.
- **Deploy workflow** — Stack discovery excludes auxiliary services when
  deploying community-saas.
- **Next.js security update** — Customer portal updated to 16.2.3
  (GHSA-q4gf-8mx6-v5v3).

## [7.0.0] - 2026-04-09

### Breaking Changes

#### Changed — Default detection actions relaxed

- **Breaking:** the default `PII_ACTION` is now `warn` (previously `redact`). SQLi and
  sensitive-data categories also default to `warn`. Compliance categories (HIPAA, GDPR,
  PCI, RBI, MAS FEAT) default to `log`. Only unambiguously dangerous patterns — reverse
  shells, `rm -rf /`, SSRF to `169.254.169.254`, `/etc/shadow`, credential files — block
  by default.

  **Why this is a major version bump:** upgrading without explicit config reduces enforcement.
  A governance product silently weakening default protections is exactly the kind of change
  that warrants a major version signal.

  **Migration path:**
  - To restore previous behavior: set `AXONFLOW_PROFILE=strict` or `PII_ACTION=redact`
  - To keep new defaults: no action needed
  - Explicit `*_ACTION` env vars are unaffected — they always take highest precedence

- **Database migration for system-default policies.** A migration rewrites system-default
  policies to match the new defaults. User-created and tenant-owned policies are untouched.
  An accompanying down migration restores the previous strict defaults.

### Community

#### Added — Community SaaS evaluation server (try.getaxonflow.com)
- `DEPLOYMENT_MODE=community-saas` — new deployment mode for shared evaluation server.
  Requires self-registration via `POST /api/v1/register`. Rate-limited: 20 req/min +
  500 req/day per tenant. Ollama is the only LLM provider. No license required.
- `POST /api/v1/register` — generates UUID tenant_id (prefixed `cs_`) and one-time-display
  secret (bcrypt-hashed at cost 12). Credentials expire after 30 days. IP-rate-limited
  to prevent registration abuse (5/hour/IP).
- Migration 068: `community_saas_registrations` + `community_saas_daily_usage` tables +
  `increment_csaas_daily()` atomic counter function for daily rate limiting.
- Community SaaS usage telemetry to dedicated DynamoDB table (`community-saas-telemetry-events`).
  Records endpoint, method, status_code, platform version, correlation_id per request.
  Never records request content, query params, or IP addresses. 30-day TTL, PITR enabled,
  server-side encryption enabled.
- Ollama EC2 infrastructure template (`infrastructure/cloudformation/ollama-ec2.yaml`)
  with security-group-scoped port 11434, SSM management, GPU driver auto-install for
  g4dn/g5 instance types.
- Dedicated community CloudFormation template (`community-saas-ecs.yaml`) — stripped-down
  stack with Agent, Orchestrator, Prometheus, and Grafana only. No Customer Portal,
  no Portal UI, no enterprise connectors. Deploy script auto-selects the right template
  based on `deployment_mode` in the environment config.
- Docker Compose overlay (`docker-compose.community-saas.yml`) for local E2E testing with
  bundled Ollama service and automatic model pull.
- `community-saas` added to deploy-application and deploy-platform workflow dropdowns.
- Checkpoint telemetry accepts `community-saas` as a valid `endpoint_type` value.

#### Added — Governance profiles and per-category enforce

- **`AXONFLOW_PROFILE` env var** (`dev` | `default` | `strict` | `compliance`). Resolved at agent and orchestrator startup, applied to the policy engine, and logged on boot. A single env var picks the enforcement posture instead of tuning eight individual `*_ACTION` env vars. The matrix is documented in the Governance Profiles guide. Explicit category env vars (`PII_ACTION=block`, `SQLI_ACTION=warn`, etc.) continue to override the profile, so existing automation keeps working.

- **`AXONFLOW_ENFORCE` env var** for per-category opt-in enforcement. Accepts a comma-separated subset of `pii`, `sqli`, `sensitive_data`, `high_risk`, `dangerous_queries`, `dangerous_commands`, plus the sentinels `all` and `none`. `all` is a true alias for the strict profile; `none` is a true alias for the dev profile — both match the documented profile matrices exactly. An explicit category list forces listed categories to `block` while leaving non-listed categories at the active profile's value (non-listed are no longer silently downgraded to `warn`). Unknown tokens are rejected at startup — previously this used `log.Fatalf` which crashed test binaries when developers had stale env vars set; it now returns an error cleanly. Precedence (highest → lowest): explicit `*_ACTION` env vars > `AXONFLOW_ENFORCE` > `AXONFLOW_PROFILE` > built-in defaults.

- **Profile banner at startup.** Both the agent AND the orchestrator now log the active profile and resolved per-category actions on boot, so operators can confirm what posture each component is running in without grepping the env. Example: `[Profile] agent active: dev — PII=log, SQLI=log, SensitiveData=log, HighRisk=log, DangerousQuery=warn, DangerousCommand=warn`.

- **Precedence chain regression tests** — unit tests verify `ProfileDefaults → ApplyEnforce → *_ACTION env var` end-to-end through `DetectionConfigFromEnv`, plus the invalid-value-preserves-profile guarantees under both strict and dev profiles.

#### Fixed — Invalid env var values now preserve the active profile

- **`DetectionConfigFromEnvWithBase` fallback bug.** On a `dev` or `default` deployment, a typo like `PII_ACTION=blok` used to silently tighten behavior back to `redact` — the hardcoded legacy fallback in `parseDetectionAction` ignored the already-resolved profile base and reverted to the v6.1.0 default. Now the fallback preserves the base config's value (`cfg.PIIAction`, `cfg.SQLIAction`, etc.) so an invalid value on a dev profile stays at `log` and on a strict profile stays at `block`. Applies to PII, SQLi, sensitive data, high risk, dangerous queries, and dangerous commands. Regression tests verify the behavior on both strict and dev profiles.

#### Fixed — `AXONFLOW_ENFORCE=all` and `none` now match their documented profile aliases

- **Sentinel semantics corrected.** The comments and docs said `AXONFLOW_ENFORCE=all` was equivalent to `AXONFLOW_PROFILE=strict` and `none` equivalent to `dev`, but the old `ApplyEnforce` implementation turned listed categories into `block` and all others into `warn`. In practice `all` over-blocked `high_risk` (strict leaves it at warn), and `none` produced `warn`-only behavior instead of dev's `log`-only posture for PII/SQLi/sensitive data. `ApplyEnforce` now reads the sentinel and returns `ProfileDefaults(ProfileStrict)` / `ProfileDefaults(ProfileDev)` directly, so the sentinels match the documented profile matrices exactly.

- **Non-listed categories preserved.** When an explicit category list is provided (e.g. `AXONFLOW_ENFORCE=pii,sqli`), listed categories are forced to `block` as before, but non-listed categories now preserve the active profile's value instead of being silently downgraded to `warn`. A dev-profile deployment with `AXONFLOW_ENFORCE=pii` now blocks PII and keeps everything else at `log`, not `warn`.

#### Fixed — `LoadEnforceFromEnv` no longer calls log.Fatalf

- **`LoadEnforceFromEnv` returns an error instead of calling `log.Fatalf`.** Any developer with a stale `AXONFLOW_ENFORCE=garbage` in their shell used to crash the entire test binary at package init. Now the error is returned cleanly and the calling code logs and continues with the profile base.

#### Fixed — `deploy-client.sh` JWT path silent failure

- **`scripts/multi-tenant/deploy-client.sh` no longer silently falls back to a hardcoded Secrets Manager path.** The "Path B" fallback was reading a hardcoded `axonflow/clients/travel/production/user-token` regardless of the client being deployed, swallowing AWS errors with `2>/dev/null || echo ""`, and silently passing an empty `USER_TOKEN` into the container — which the agent then rejected at runtime with a misleading "token signature is invalid" error. The variable `AXONFLOW_STACK_PREFIX_JWT` is now required; the script fails loudly if missing. The generated `USER_TOKEN` is now validated with a structural check: three base64url segments, header that decodes to JSON with an `alg` field, payload that decodes to JSON with an `exp` or `iat` field (previously the check was a regex that accepted any `a.b.c` literal). All client environment files under `configs/environments/clients/` have been updated to declare the variable. A new runbook documents the underlying JWT secret rotation flow.

#### Fixed — Evaluation tier `MaxPendingApprovals` outlier

- **`EvaluationLimits.MaxPendingApprovals` corrected from 100 to 25** to match the rest of the evaluation tier caps (`MaxConcurrentExec`, `MaxSSEConnections`, `MaxVersionsPerPlan`). The previous value of 100 was an outlier that contradicted the tier boundary test and inflated evaluation-tier capacity above what was documented and tested.

### Security

- **Ed25519 enterprise license signing key rotated.** The previous private seed was found embedded in `scripts/setup-e2e-testing.sh`, where it had been since the script was authored. Anyone with read access to the repo could mint valid Enterprise / Professional / Plus licenses for any `org_id`, bypassing tier gating in any deployment. As part of this release the key has been rotated, all active customer and per-stack licenses re-signed under the new key, and the agent's embedded `enterprisePublicKey` byte array updated. The previous public key (first 8 bytes `9a b6 f6 b2`) is no longer accepted. A new internal-only runbook documents the rotation procedure for any future operator.

- **Rotation tool now enumerates secrets dynamically.** The initial rotation tool held a hardcoded list of license secrets, which missed the per-stack `axonflow-<stack>-license-key` boot license secrets and broke running agents mid-rotation. The rewritten tool paginates `ListSecrets` and `DescribeParameters` across all configured regions, filters by name + value prefix, re-signs every enumerated Ed25519 and legacy V2 license, and writes re-signed licenses back to AWS BEFORE rotating the signing-key secret (so a write-back failure never leaves SM in a split-brain state where the new signing key is active but some licenses still hold signatures under the old key).

- **Re-signed V2 licenses preserve both `tenant_id` and `org_id`.** The legacy V2 HMAC format only carried `tenant_id`; the fresh Ed25519 payload now writes both fields so downstream consumers that key off either stay compatible.

- **`scripts/setup-e2e-testing.sh` no longer hardcodes any signing keys.** The eval and dev-only enterprise keys are sourced from the environment (CI uses GitHub Actions secrets) or fetched at runtime from AWS Secrets Manager. A separate dev-only enterprise keypair has been created so local E2E never touches the production signing key. The `.env` file written by the script is `chmod 600` so the signing-key material it contains is not world-readable.

- **Pre-commit `gitleaks` rule** added at `.gitleaks.toml` and wired into `.pre-commit-config.yaml`. The rule blocks any commit that introduces a base64 Ed25519 seed near a `*_SIGNING_KEY` env var assignment. CI runs gitleaks on every PR.

- **Checkpoint telemetry retention bumped from 90 → 180 days.** Evaluation-to-production conversion windows run 2-4 months in observed data, so 90 days was cutting off the tail. 180 days still fits comfortably in DynamoDB free tier at current volume.

#### Fixed — Multi-tenant SaaS correctness and security

- **`X-Org-ID` now derived from the validated client license, not the deployment env var.** The agent's Single Entry Point proxy middleware (`platform/agent/proxy.go`) was forcibly overwriting the authenticated client's `org_id` with the deployment's `ORG_ID` environment variable on every request, preventing a single deployment from serving multiple organizations. Every tenant on a shared stack was being stamped with the same `org_id`, making true multi-tenant workflow scoping impossible. The middleware now forwards `X-Org-ID` from the cryptographically validated client license payload (`client.OrgID`) — matching the behavior of `apiAuthMiddleware` in `auth.go`, which was already correct. The Ed25519 signature on the client license guarantees the `org_id` claim cannot be forged, so trusting it is both safe and required for multi-tenant operation. Deployments with a single org per stack are unaffected; deployments serving multiple orgs now correctly scope workflows, policies, and audit data per-tenant.

- **Internal orchestrator forwarding path fixed.** `platform/agent/run.go` also had the same bug in the direct HTTP forwarding path that bypasses the Single Entry Point mux. It was checking whether the client had an `org_id` and then setting the header to `getDeploymentOrgID()` anyway. Now uses `client.OrgID` directly.

- **MCP check-input and check-output audit log OrgID.** `platform/agent/mcp_handler.go` was writing every MCP audit record with `OrgID: getDeploymentOrgID()` regardless of which client authenticated. Multi-tenant audit trails were structurally broken — all records from all tenants were attributed to the deployment. Both handlers now lift `orgID` into function-level scope alongside `tenantID`, populated from `client.OrgID` in enterprise auth, `X-Org-ID` header in internal-service auth, and `getDeploymentOrgID()` in community mode.

- **Removed `validateClient()` mock authentication fallback.** `platform/agent/run.go` had a `validateClient(clientID)` function that accepted any `client_id` from the request body and returned a fake "Demo Client" with the deployment's own `org_id`, no credential validation. All four MCP handlers (`/api/v1/mcp/query`, `/api/v1/mcp/execute`, `/api/v1/mcp/check-input`, `/api/v1/mcp/check-output`) called this as a fallback when Basic auth was missing. Effectively: in enterprise mode, any request without Basic auth but with a `client_id` field in the JSON body was silently authenticated as that client. Removed the function and all four call sites now reject unauthenticated requests with 401.

- **Orchestrator workflow tenant/org ownership checks.** `platform/orchestrator/workflow_control/service.go` — **nine** service methods now enforce tenant/org ownership before acting on a workflow: `GetWorkflow`, `StepGate`, `MarkStepCompleted`, `ApproveStep`, `RejectStep`, `ResumeWorkflow`, `CompleteWorkflow`, `FailWorkflow`, `AbortWorkflow`. Previously `GetWorkflow` (called from `GET /api/v1/workflows/{id}`) did no tenant/org filtering — any authenticated client that knew a workflow ID could fetch any workflow (classic IDOR). The same gap existed on every other workflow state transition: an attacker could approve, reject, resume, complete, fail, or abort any other tenant's workflow, or inject fake cost/token metrics into another tenant's audit trail by calling `MarkStepCompleted`. All matching HTTP handlers in `handlers.go` extract tenant/org from request headers (`X-Tenant-ID`, `X-Org-ID`) and pass them through. Callers in `run.go` (MAP confirm mode) and `unified_execution_handler.go` also updated. `ListWorkflows` was already filtering correctly.

- **Unified execution handler `checkTenantOwnership` hardened.** `platform/orchestrator/unified_execution_handler.go` previously had permissive fallbacks: requests without `X-Tenant-ID` were allowed through, and executions without a `tenant_id` were accessible to any caller. Both were cross-tenant data leak vectors. The check now:
  - Requires **both** `X-Tenant-ID` and `X-Org-ID` on every request (401 if missing).
  - Rejects executions that lack either `tenant_id` or `org_id` (404).
  - Requires exact match on both fields (404 on any mismatch).
  - All mismatch responses return 404 (not 403) to prevent cross-tenant existence leakage.

#### Added — Customer portal multi-tenant identity

- **`tenant_id` column on `user_sessions`** (migration 065). The customer portal previously aliased `tenantID := orgID` in `auth.go` with the comment *"organizations table doesn't have tenant_id column"*. That collapsed two concepts and prevented a single portal org from representing multiple tenants (prod, staging, dev). The new column lets a portal session track which tenant within an org the user is currently viewing.

- **`portal_default_tenant_id()` SQL helper** (migration 065). Resolves the default tenant for an org: prefers `tenant_id = org_id` (canonical default) and falls back to the oldest tenant in the `tenants` table, then to `org_id` itself for community deployments. Used at login time to populate the session.

- **Automatic default tenant backfill** for every existing organization (migration 065). Every org gets a canonical tenant row inserted into the `tenants` table if one doesn't already exist, so portal login can deterministically resolve a tenant without schema changes to customer data.

#### Changed — Customer portal auth and proxy

- **`AuthHandler.HandleLogin`** now resolves `defaultTenantID` via `portal_default_tenant_id()` at login time, inserts it into `user_sessions.tenant_id`, and returns both `org_id` and `tenant_id` in the login response. Legacy fallback kicks in if migration 065 hasn't been applied yet.

- **`AuthHandler.HandleCheckSession`** (GET /api/v1/auth/session) now reads and returns `tenant_id` alongside `org_id`.

- **`middleware/dev_auth.go`** stops joining `customers.tenant_id` and reads `user_sessions.tenant_id` directly. The previous `orgID + "_tenant"` fallback is replaced with a deterministic fallback to `org_id` for legacy sessions.

- **`api/orchestrator_proxy.go`** forwards `X-Tenant-ID` from `session.TenantID` (the currently-selected tenant within the org) and `X-Client-ID` from the tenant identifier — previously both collapsed to `session.OrgID`. `X-Org-ID` continues to carry `session.OrgID`. A warning log fires when `session.TenantID` is empty (legacy session, unexpected after migration 065).

- **`ORG_ID` environment variable role clarified.** Previously documented as "canonical org identity (single source of truth)", the env var is now understood as:
  - **Stack-level deployment label** (used in logs, metrics, startup validation against the stack's own boot license)
  - **Community mode fallback** (when no client license is present)
  - **NOT a routing key** for per-request multi-tenant data scoping — that comes from the authenticated client license

#### Fixed — Deployment tooling

- **`deploy-cloudformation.sh` missing required `OrganizationID` parameter.** The script built the `aws cloudformation deploy --parameter-overrides` list without passing `OrganizationID`, so creating a new stack from a clean state failed with `Parameter 'OrganizationID' must have a value`. Existing stack updates worked because CloudFormation falls back to `UsePreviousValue` for parameters not passed explicitly. The script now reads `deployment.organization_id` from the environment yaml config, falling back to the environment name if not set, and passes it on every deploy. This unblocks creating fresh environments from `deploy-platform.yml`.

### Security

- **IDOR on `GET /api/v1/workflows/{id}` closed.** Before v6.2.0, any authenticated client could fetch any workflow by ID regardless of which tenant or org it belonged to. Combined with the `X-Org-ID` deployment-env-var override, this meant a compromised tenant could enumerate workflow IDs and read every other tenant's execution state. Both the header source fix and the service-layer ownership check are required to close the hole end-to-end.
- **No-auth fallback on MCP handlers closed.** Before v6.2.0, in enterprise mode, any request with a `client_id` field in the JSON body (but no Basic auth credentials) was silently authenticated as that client and attributed to the deployment's own org. Removed entirely.
- **Permissive cross-tenant fallback on unified execution endpoints closed.** Before v6.2.0, executions without a `tenant_id` were accessible to any caller, and requests without `X-Tenant-ID` were accepted. Both now rejected.

---

## [6.1.0] - 2026-04-06

### Community

#### Added

- **Mistral AI LLM provider.** Full integration with Mistral's OpenAI-compatible API. Supports `mistral-small-latest` (default), `mistral-large-latest`, `codestral-latest`, and other models. Includes streaming, cost estimation, health checking, and automatic bootstrap from `MISTRAL_API_KEY` environment variable. Six example suites with 42 total assertions.
- **Cursor IDE plugin launch.** AxonFlow governance for Cursor via `preToolUse`/`postToolUse` hooks. Enforces policy on Shell, Write, Edit, Read, Task, NotebookEdit, and MCP tools. PII detection in file writes with configurable `PII_ACTION` (block, redact, warn, log). 3 skills, 1 governance rule, 6 MCP tools. Plugin at [axonflow-cursor-plugin](https://github.com/getaxonflow/axonflow-cursor-plugin).
- **OpenAI Codex plugin launch.** Hybrid governance for Codex: enforcement via hooks for terminal commands (`exec_command`), advisory governance for other tools via skills with implicit activation. 6 skills, 6 MCP tools. Plugin at [axonflow-codex-plugin](https://github.com/getaxonflow/axonflow-codex-plugin).
- **Integration activation for Cursor and Codex.** Auto-detection via connector type prefix (`cursor.*`, `codex.*`) and client name matching. Integration-specific policies enabled on first request (migration 064).
- **GovernedTool examples for TypeScript, Go, Java.** Framework-agnostic tool governance examples matching the existing Python example, with 8 E2E-verified test cases per language.

#### Changed

- **Telemetry defaults clarified for SDKs and plugins.** Anonymous telemetry remains enabled by default for all endpoints, including localhost/self-hosted evaluation, unless `DO_NOT_TRACK=1`, `AXONFLOW_TELEMETRY=off`, or an explicit SDK/plugin setting disables it. Related docs now also describe plugin timeout tuning for remote or high-latency deployments.

---

## [6.0.0] - 2026-04-05

> **Upgrade note:** Most users running with default settings are unaffected. If you customized `ORG_ID` or `AXONFLOW_CLIENT_ID` in your docker-compose, verify they still match your deployed identity before upgrading. See [deployment/licensing](https://docs.getaxonflow.com/docs/deployment/licensing) for details.

### BREAKING CHANGES

- **Unified identity model.** `tenant_id` (from Basic auth `clientId`) for data isolation, `org_id` (from deployment `ORG_ID` env var) for entitlement scope. SDKs send credentials, server derives identity — no client-supplied identity headers.
- **License payload field renamed: `tenant_id` → `org_id`.** Existing licenses with `tenant_id` will not be recognized; regenerate with the updated keygen tool.
- **`X-Client-ID` header removed.** Redundant with `X-Tenant-ID`. All orchestrator reads changed to `X-Tenant-ID`.
- **License `org_id` must match deployment `ORG_ID`.** Agent validates at startup; mismatch causes a fatal error.
- **`X-Tenant-ID` header no longer accepted from clients.** The server derives tenant context from OAuth2 Client Credentials (Basic auth). SDKs must be updated to v5.0+ (Python), v5.0+ (Go), v5.0+ (TypeScript), v5.0+ (Java).
- **Legacy DatabasePolicyEngine removed.** All policy evaluation flows through the unified SharedPolicyEngine.
- **Basic auth required in evaluation/enterprise mode.** All proxied API endpoints require `Authorization: Basic base64(clientId:clientSecret)` when `DEPLOYMENT_MODE` is not `community`.

### Community

#### Added

- **`tenants` table** (migration 062) maps tenant_id → org_id. Auto-populated on first authenticated request. Enables multi-tenant deployments (prod, staging, dev under one org).
- **`org_id` column** on `audit_logs` (migration 059) and `mcp_query_audits` (migration 061) with backfill from `tenant_id`. All audit write paths now populate `org_id`.
- **Auto-registration of organizations and tenants.** In-memory cache skips DB on subsequent requests. Self-hosted users never need to manually seed identity tables.
- **Claude Code plugin** ([getaxonflow/axonflow-claude-plugin](https://github.com/getaxonflow/axonflow-claude-plugin)) — automatic policy enforcement, PII scanning, and audit trails via PreToolUse/PostToolUse hooks and 6 MCP tools.
- **MCP server protocol endpoint** (`/api/v1/mcp-server`). JSON-RPC 2.0 over Streamable HTTP with 6 governance tools: `check_policy`, `check_output`, `audit_tool_call`, `list_policies`, `get_policy_stats`, `search_audit_events`.
- **Integration policy activation system.** Integration-specific policies auto-enabled when an integration is detected via `AXONFLOW_INTEGRATIONS` env var, connector type auto-detection, or MCP client identification.
- **10 dangerous command system policies** (migration 059): reverse shells, destructive filesystem ops, credential access, download-and-execute, SSRF, path traversal, dynamic code execution.
- **`DANGEROUS_COMMAND_ACTION` config** split from `DANGEROUS_QUERY_ACTION`. Different risk profiles, configured independently.
- **OAuth2 Client Credentials authentication** for all policy API endpoints.
- **Community mode identity headers.** Agent injects `X-Tenant-ID` and `X-Org-ID` in community mode. Orchestrator identity always server-derived.
- **MCP handler Basic auth support.** All 4 MCP handlers accept Basic auth (service license validation), falling back to legacy whitelist.
- **Startup org_id mismatch validation.** Agent fails fast if license `org_id` doesn't match deployment `ORG_ID`.
- **Response PII detection uses database-driven policy engine.** Shared engine wired in orchestrator for response scanning.
- **PII detection modes example** (`examples/pii-detection/http/pii-modes.sh`). Tests request-side and response-side PII with ISO timestamp false positive regression test.
- **Proxy routes** for MCP processing, MAP cost estimation, unified execution cancel, legacy policy reads.
- **Runtime table creation moved to migrations.** `audit_logs`, `dynamic_policies`, `policy_metrics`, `media_governance_config`.
- **ADR-041**: Organization and Tenant Identity Separation.
- **Setup script repo override.** `COMMUNITY_REPO` environment variable in `setup-e2e-testing.sh` allows pointing community-mode testing at any repo path.

#### Changed

- **All example CLIENT_ID defaults standardized to `"community"`.** Previously random per-example defaults.
- **All examples migrated to Basic auth.** 15 examples converted from `X-Client-ID`/`X-Client-Secret` headers.
- **All examples use agent single entry point.** 106 files migrated from orchestrator-direct (port 8081) to agent (port 8080).
- **`PII_ACTION` environment variable** controls enforcement on both request and response sides: `block`, `redact` (default), `warn`, `log`.
- **Static policy API endpoints** protected by `apiAuthMiddleware` via gorilla/mux subrouter.
- **License keygen parameter renamed.** `tenantID` → `orgID`.
- **Enterprise compose stale V2 secret removed.** `AXONFLOW_CLIENT_SECRET` default cleared. Use `setup-e2e-testing.sh` to generate valid Ed25519 licenses.
- **Orchestrator `ORG_ID` fallback changed from `"default"` to `"local-dev-org"`.** Logs a warning when not explicitly set.

#### Removed

- **`DatabasePolicyEngine`** (`db_policies.go`, ~744 lines).
- **`StaticPolicyEngine`** struct and methods (~634 lines collapsed to ~39 lines).
- **`db_policies_test.go`** (~1,648 lines), **`static_policies_test.go`** (~1,964 lines), **`agent_bench_test.go`** (~400 lines).

#### Fixed

- **Agent auth collapsed tenant_id and org_id.** Now `TenantID` comes from Basic auth clientId, `OrgID` from deployment `ORG_ID` env var.
- **Community mode X-Tenant-ID was spoofable.** Now always overrides with server-derived value.
- **Response PII redaction now respects `PII_ACTION` env var.** `warn`/`log` modes skip redaction but still run detection for audit.
- **4 PII false positives on ISO timestamps** (migration 063). SSN, phone, bank account, Singapore UEN patterns tightened.
- **MCP execute/check-input/check-output handlers ignored Basic auth.** All 4 handlers now use same auth pattern.
- **check-input/check-output rejected Basic auth requests.** `tenant_id` validation moved to after authentication.
- **Validator substring matching** in policy evaluator. Fixed with word-boundary matching.
- **System policies counted against tenant limit.** System-tier policies now excluded from quota.
- **MAP confirm mode end-to-end.** Three bugs fixed (org_id forwarding, execution tracker sync, response envelope).
- **13 HTTP examples missing Basic auth.** `AUTH_B64` variable defined after migration.
- **Compliance module log messages misleading in community mode.** Now shows "routes inactive — Enterprise build required".
- **SSE streaming missing `X-Tenant-ID`.** Updated 6 examples.
- **Cloud-storage example SDK API mismatch.** Updated for SDK v4.3.0.
- **Version-check example SDK struct mismatch.** Rewrote to use raw HTTP.
- **Policy example used wrong agent paths.** Updated to `/api/v1/static-policies`.
- **Support-demo Docker build.** `go.sum` was gitignored under `examples/`. Changed Dockerfile to use `go mod tidy`. Docker network name configurable via `AXONFLOW_NETWORK` env var.
- **Python 3.10+ compatibility in test scripts.** `test-all.sh` and `demo.sh` now respect `PYTHON` env var.
- **Proxy community mode tenant injection.** Agent proxy now derives tenant from Basic auth `clientId` (or defaults to `community`).
- **`AXONFLOW_CLIENT_SECRET` not exported in evaluation mode.** Setup script now exports both `LICENSE_KEY` and `CLIENT_SECRET`.
- **Enterprise setup reused stale `DEPLOYMENT_MODE=evaluation` from .env.** `start_enterprise()` now explicitly sets `DEPLOYMENT_MODE=enterprise`.
- **Community mode `org_id` defaulted to `"demo-org"`.** Changed to `getDeploymentOrgID()` (resolves to `"local-dev-org"` by default).

### Enterprise

#### Added

- **Missing proxy routes for enterprise endpoints.** Policy simulation, evidence export, RBI/SEBI compliance, webhooks, media governance config.

#### Changed

- **Static policy API auth middleware.** All 12 endpoints use `apiAuthMiddleware`.
- **MAP confirm/step mode execution.** WCP workflows correctly store `org_id`. Resume handler syncs execution tracker.

#### Fixed

- **Circuit breaker routes bypassed auth.** All routes now use auth-protected subrouters.
- **Auth middleware didn't inject identity headers.** `apiAuthMiddleware` now sets `X-Tenant-ID` and `X-Org-ID`.
- **MCP permission evaluator rejected `mcp:*:*` wildcard.**
- **HITL queue creation failed with nil JSON context.**
- **Enterprise HITL handler missing `/api/v1/hitl/status` endpoint.**
- **MCP enterprise examples missing `client_id` and `user_token` in request body.**
- **Tier-limits example used Bearer auth instead of Basic auth.**
- **Bedrock inference profile ID** missing `us.` prefix.

### SDK

#### Fixed

- **Missing `status` field on `PlanResponse`** across Go, Python, and TypeScript SDKs.
- **All SDKs reject `client_secret` without `client_id`** to prevent wrong-tenant data storage.
- **Bedrock inference profile ID** in E2E setup script.

---

## [5.5.0] - 2026-04-01

### Community

#### Added

- **OpenClaw integration**: E2E examples and architecture documentation for the `@axonflow/openclaw` plugin. Demonstrates tool input governance, outbound message scanning, and audit logging using `openclaw.*` connector types.
- **Computer Use governance**: E2E examples for Anthropic Computer Use with `ComputerUseGovernor` (Python SDK) and raw HTTP tests. Covers bash command blocking, PII detection, credential exfiltration prevention, and output redaction.
- **Claude Agent SDK integration**: TypeScript example demonstrating MCP tool governance with Claude Agent SDK using existing `mcpCheckInput`/`mcpCheckOutput`.
- **GovernedTool E2E examples**: LangChain AgentExecutor, LangGraph ToolNode, and HTTP examples for framework-agnostic tool governance.
- **SSRF prevention**: Pre-flight URL validation (scheme allowlist, DNS resolution, private IP blocking) on SSO metadata fetch and media URL fetch, complementing existing socket-level protections.
- **Log injection prevention**: Sanitized user-controlled values in log statements across agent proxy, orchestrator, and HITL handler to prevent newline/ANSI injection.
- **Dockerfile hardening**: Non-root user directives, pinned base image tags, and health checks across all Dockerfiles.
- **Go binary hardening**: Strip debug symbols, symbol tables, and build paths from production binaries.
- **Source map prevention**: Disabled source map generation in frontend Docker builds to prevent source code exposure.

#### Changed

- **Docker Compose version default**: Updated `AXONFLOW_VERSION` from `5.1.0` to `5.5.0`. The stale default caused missing endpoints (e.g., `audit/tool-call`) for users running `docker compose up` without explicitly setting the version.

#### Security

- **Amadeus connector SSRF enforcement**: Added pre-flight URL validation for Amadeus connector callbacks.
- **SQL injection prevention in demo backends**: Demo backends now use read-only transactions to prevent SQL injection in example queries.
- **Version alignment CI check**: New CI workflow validates that version defaults in Docker Compose, Dockerfiles, and CHANGELOG stay in sync.

#### Fixed

- **Stale docker-compose/Dockerfile version defaults**: Updated hardcoded version defaults from `5.1.0`/`4.8.0` to `5.5.0` across Docker Compose files and Dockerfiles.

- **Broken docs links**: Fixed 15+ stale links across platform surfaces (AWS Marketplace, SCIM, axonctl, Cloudflare Access setup).
- **Spring Boot/Tomcat update**: Bumped Spring Boot to 3.5.13, Spring Framework to 6.2.17, and Tomcat to 10.1.52 in integration example (CVE fixes).
- **Dependency update**: Bumped `golang.org/x/image` to v0.38.0, fixing out-of-memory vulnerability via crafted TIFF file.

#### Documentation

- **Computer Use governance architecture**: Sampling loop governance boundary, tool action taxonomy, default blocked bash patterns.
- **OpenClaw integration architecture**: Plugin hook flow, connector type convention, approval flow integration, lightweight HTTP client design.

### Enterprise

#### Added

- **Infrastructure hardening**: CloudFormation template updated with RDS private access, restricted security group egress, KMS encryption for SNS/Secrets Manager/CloudWatch, HTTP-to-HTTPS redirect, and ALB invalid header dropping. Terraform modules updated with KMS encryption for DynamoDB, CloudWatch, and Secrets Manager, plus Lambda X-Ray tracing.
- **GovernedTool integration comparison**: Internal documentation comparing GovernedTool, tool_output_wrapper, and mcp_tool_interceptor across framework compatibility, governance scope, and deployment patterns.

---

## [5.4.1] - 2026-03-30

### Community

#### Fixed

- **Cloud storage connectors now available in Community edition**: S3, Azure Blob, and GCS connectors were implemented in the community code path but only registered in the enterprise connector factory. Moved registration to the community factory so all users can use cloud storage connectors without an enterprise license.

#### Added

- **Cloud storage connector examples**: New E2E examples for S3/MinIO operations with hardened assertions in HTTP, Go, Python, TypeScript, and Java (`examples/mcp-connectors/cloud-storage/`).
- **MinIO service in community Docker Compose**: Added MinIO to `docker-compose.yml` for local S3-compatible storage testing without requiring enterprise mode.

---

## [5.4.0] - 2026-03-25

### Community

#### Security

- **Log injection prevention** (CodeQL): Sanitize user-controlled values in log statements across agent proxy, WCP service, and HITL handler using `logutil.Sanitize()`. Prevents newline/ANSI injection into structured logs. Affects `platform/agent/proxy.go`, `platform/orchestrator/workflow_control/service.go`, `platform/orchestrator/hitl_wcp_community.go`.

#### Added

- **Policy conflict detection** (#1062): New `POST /api/v1/policies/conflicts` endpoint analyzes active policies for contradictions (`contradictory_action`), shadows, and redundancies. Helps teams validate policy configurations before deploying changes. Available at Evaluation tier and above, sharing the simulation rate limiter.
- **Policy simulation examples**: 8-step deterministic E2E examples in HTTP/cURL, Python, TypeScript, Go, and Java demonstrating simulate, impact report, and conflict detection workflows.
- **LangGraph tool output enforcement example** (#1413): Python example demonstrating `tool_output_wrapper()` for policy enforcement on local `@tool` outputs in LangGraph workflows.
- **LangGraph 1-line wrapper example**: New `langgraph_wrapper_example.py` demonstrating `wrap_langgraph()` for transparent governance of compiled LangGraph StateGraphs without modifying the graph definition.
- **Per-tool governance in HTTP example**: `workflow-control.sh` now uses the `tool_context` field in step gate requests for tool_call steps, demonstrating structured tool-level policy evaluation.

### Enterprise

#### Security

- **Log injection prevention** (CodeQL): Sanitize user-controlled values in checkpoint-service and customer-portal log statements. Affects `ee/platform/checkpoint-service/pkg/{notification,handler,bakeoff}`, `ee/platform/customer-portal/api/orchestrator_proxy.go`.
- **Prototype pollution fix** (Dependabot GHSA-rf6f-7fwh-wjgh): Updated `flatted` dependency in customer-portal-ui via `npm audit fix`.

#### Added

- **Portal: Policy Simulation Modal**: "Simulate Policies" button on the Policies page for dry-running all active policies against test queries. Shows allowed/blocked status, risk score, applied policies, and daily usage.
- **Portal: Policy Impact Modal**: "Preview Impact" per-policy button for batch-testing a policy against multiple inputs. Displays match/block rates with per-input results table. Auto-detects conflicts on the target policy.
- **OpenAPI spec**: Added `POST /api/v1/policies/conflicts` endpoint definition.

---

## [5.3.1] - 2026-03-24

### Community

#### Added

- **Audit compliance summary endpoint**: `POST /api/v1/audit/summary` returns aggregated compliance stats for a date range including total events, breakdown by severity and action type, top triggered policies, and a compliance score. Used by the Customer Portal audit page.

#### Fixed

- **Cross-tenant dynamic policy cache collision** (#1410): Dynamic policy cache was keyed by policy name, causing policies with the same name across different tenants to silently overwrite each other. In multi-tenant deployments, this could result in step gate evaluations using the wrong tenant's policy or skipping policies entirely due to tenant mismatch. Cache key changed from `name` to `policy_id` to ensure all policies coexist regardless of naming. Includes `GetPolicy()` fallback search by name field for backward compatibility.
- **step_input/tool_input field resolution in dynamic policies** (#1408): Dynamic policy conditions referencing `step_input.*` and `tool_input.*` fields now resolve correctly during step gate evaluation. Previously these fields were not extracted from the policy evaluation context, causing conditions like `step_input.query contains "DROP"` to never match.
- **Step gate policy matching for step_input fields** (#1409): Fixed policy matching logic to correctly evaluate conditions against step_input fields in the dynamic policy engine. Added comprehensive test coverage for step_input and tool_input condition matching.

### Enterprise

#### Added

- **SSO metadata URL fetcher**: `POST /api/v1/sso/fetch-metadata` in the Customer Portal fetches and parses SAML IDP metadata from a URL. Includes SSRF protection (HTTPS-only, private IP rejection, DNS validation), per-session rate limiting (5/min), 1MB response size limit, and automatic provider detection (Okta, Azure AD, Google, OneLogin, Auth0).

#### Fixed

- **Portal proxy missing headers**: Customer Portal orchestrator proxy now forwards `X-Org-ID` and `X-Client-ID` headers from session context, fixing 401 errors on SEBI compliance endpoints and other handlers that require these headers.
- **SEBI audit export integer-only org IDs**: SEBI audit export service migrated from `int orgID` to `string tenantID` for consistency with the rest of the platform. Portal tenants with string IDs (e.g., `travel-us`) now work correctly with SEBI endpoints.
- **SEBI org name lookup**: `getOrgName` now queries `org_id` column first (matching the varchar tenant ID from portal), with fallback to numeric `id` for backward compatibility.
- **Compliance page crash on EU AI Act data**: Fixed `StatusBadge` component crash when `status` is undefined. Added null-safety guard. Also fixed `getEUAIActConformity()` API function to transform the backend list response (`{assessments: [...]}`) into the single-object shape (`{status, risk_level, last_assessment, requirements}`) expected by the compliance page UI.
- **SCIM page smoke test false positive**: Playwright smoke test `afterEach` filter now catches browser-level "Failed to load resource: 403/404" console errors that lack endpoint URL context, preventing false failures on the SCIM settings page when SCIM provisioning is not configured.

---

## [5.3.0] - 2026-03-17

### Community

#### Added

- **Circuit breaker error auto-trip** (#1176): Upstream LLM errors (orchestrator hard failures, orchestrator-level errors, proxy 502s) now automatically trip client-scoped circuits after threshold exceeded within a sliding window. Previously, `RecordError` was implemented but not wired into the request pipeline.
- **Sliding window for circuit breaker thresholds** (#1176): Error and policy violation counting now uses a time-windowed approach (default 5 minutes) instead of lifetime counters. Errors outside the window are automatically discarded.
- **Per-tool governance examples** (#1243): LangGraph adapter examples for TypeScript, Go, and Java demonstrating per-tool gate checks within tools nodes.
- **WCP guide updated**: Workflow Control Plane documentation expanded with TypeScript, Go, and Java LangGraph adapter examples alongside Python.

### Enterprise

#### Added

- **Per-tenant circuit breaker thresholds** (#1176): Tenants can override global circuit breaker defaults (error threshold, violation threshold, window duration, timeout, auto-recovery) via `GET/PUT /api/v1/circuit-breaker/config`. Null fields fall back to global defaults. In-memory cache with 1-minute TTL.
- **Circuit breaker notification fan-out** (#1176): Auto-trip events trigger notifications via webhook (HMAC-SHA256 signed), Slack (Block Kit), or PagerDuty (Events API v2). CRUD endpoints at `/api/v1/circuit-breaker/notifications`. Includes SSRF protection (private IP rejection) and retry with exponential backoff.
- **SDK circuit breaker observability** (#1176): New methods across all 4 SDKs: `GetCircuitBreakerStatus`, `GetCircuitBreakerHistory`, `GetCircuitBreakerConfig`, `UpdateCircuitBreakerConfig`.

#### Fixed

- **Customer Portal UI fixes** (#1360, #1361, #1362, #1364): SaaS dashboard rendering, navbar overflow on long org names, graceful 404 handling, sidebar navigation cleanup, and React hooks ordering fix.

#### Docs

- **Customer Portal access guide** (#1355): Step-by-step guide for enterprise portal authentication, JWT setup, and role-based access.

---

## [5.2.0] - 2026-03-14

### Community

#### Security

- **Proxy route authentication** (#1340): Agent gateway now validates client credentials on all proxied `/api/v1/*` routes before forwarding to backend services. Previously, proxy routes forwarded requests without authentication.
- **Proxy auth token hardening** (#1340): Reject static fallback proxy token when `AXONFLOW_INTERNAL_SERVICE_SECRET` is configured; only HMAC-signed tokens accepted in hardened deployments.

#### Added

- **Tool call audit endpoint** (#1260): `POST /api/v1/audit/tool-call` records non-LLM tool call audit entries (API calls, MCP executions, function invocations) for compliance tracking. Includes Basic auth enforcement and 1MB request body size limit.
- **Audit query SDK methods** (#1260, ADR-023): `GetAuditLogsByTenant` and `SearchAuditLogs` for programmatic audit log retrieval with pagination and filtering. Supported in all 4 SDKs (v4.1.0+).

#### Fixed

- Allow tenant/client ID mismatch on proxy-verified requests where the Agent maps client IDs to different tenant IDs (e.g., `healthcare-demo` -> `healthcare_tenant`) (#1340)
- AWS Marketplace CloudFormation template updated to v5.0.0 (#1339)
- Deploy workflow resolves version from ECR instead of HEAD (#1341, #1343)
- Migration 122 FK ordering fix + GCP secret backup docs (#1344)

---

## [5.1.0] - 2026-03-12

### Community

#### Security

- **`check-input` parameter scanning** (#1287): The `check-input` endpoint now inspects `parameters` field values individually for SQLi, PII, and compliance violations. Previously, a caller could pass a benign `statement` while embedding payloads in parameters that bypassed all policy checks. Each parameter value is scanned independently by the static policy engine; string values are scanned directly, nested objects/arrays are JSON-serialized before scanning, numeric values are converted to strings for PII/compliance detection, and boolean values are skipped.

#### Added

- **Audit: parameter tracking in MCP query audits** (#1287): Added `parameters_hash` (SHA-256) and `parameter_count` columns to `mcp_query_audits` table for forensic analysis of check-input requests. Migration: `057_mcp_audit_parameters.sql`
- **Dynamic policy: parameter condition fields** (#1287): Dynamic policies can now match on `parameters.<key>` (individual parameter values) and `parameter_count` (number of parameters) as condition fields

### Enterprise

#### Added

- **Execution Timeline page** (#1329): New customer portal page showing unified MAP and WCP execution history with real-time status, step-level drill-down, cost tracking, and policy decision visibility. Supports filtering by execution type and status, pagination, and keyboard-accessible expandable rows.
- **HITL Approval Flow Dashboard** (#1330): New customer portal page for human-in-the-loop approval queue management. Displays pending approval steps with workflow context, policy triggers, and matched policies. Supports approve/reject with mandatory justification, expandable detail panels with step input inspection, and real-time badge count polling in navigation. Migration `058_approval_justification.sql` adds `approval_comment` column to `workflow_steps`.
- **Enterprise portal documentation** (#1331): Added enterprise docs for Execution Timeline and Approval Dashboard. Fixed OpenAPI spec paths and added `minLength` constraints on approval comment/reason fields.

---

## [5.0.0] - 2026-03-09

### Community

#### Breaking Changes

- **Removed `total_steps` from `CreateWorkflowRequest` API** (#1318): The field was deprecated since Platform v4.5.0. Total steps are now exclusively auto-computed when the workflow reaches a terminal state (completed, aborted, or failed). Clients sending `total_steps` in create requests will have the field silently ignored. The `total_steps` field remains in `WorkflowStatusResponse`.
- **MCP `operation` default changed from `"query"` to `"execute"`** (#1307): `mcpCheckInputHandler` now defaults to `"execute"` when no `operation` is specified. Callers relying on the implicit `"query"` default must now pass `operation: "query"` explicitly.

#### Added

- **Python SDK: MCP Tool Interceptor** (SDK PR #109, #112): New `mcp_tool_interceptor()` factory method on `AxonFlowLangGraphAdapter` for enforcing AxonFlow input/output policies around MCP tool calls in LangGraph agents. Includes `MCPInterceptorOptions` configuration and JSON serialization fix.
- **Python LangGraph MCP Interceptor Example** (#1317): New example demonstrating MCP input/output policy checks integrated into a LangGraph agent with tool interception

#### Fixed

- Community sync workflow: include `docs/tutorials/` in sync using include-before-exclude rsync pattern (#1297)
- Community sync workflow: fixed commit detection to use merged PRs instead of workflow runs, fixed pathspec with positive `.` anchor (#1302)
- Community sync workflow: fixed jq parse error, split detection step permissions, added GH_TOKEN to sync step (#1295, #1299-#1301)
- Restored historical version annotations incorrectly bumped in docs sweep (#1298)

### Enterprise

#### Fixed

- Customer portal UI: removed vulnerable `@tootallnate/once` dependency (#1309)

### Note

This major version also formally acknowledges a breaking change shipped in a prior minor release:
- `MediaAnalysisResult.extractedText` replaced by `hasExtractedText` + `extractedTextLength` (v4.4.0)

---

## [4.8.0] - 2026-03-03

### Community

#### Added

- **External Trace ID for Workflows** (#1259): Add optional `trace_id` field to workflows for correlation with external tracing systems (Langsmith, Datadog, OpenTelemetry)
  - `trace_id` on `CreateWorkflowRequest` and `CreateWorkflowResponse`
  - `trace_id` on `WorkflowStatusResponse` and `GET /workflows` query parameter
  - Partial index on `trace_id` column for query performance (NULL values not indexed)
  - Migration 055: `ALTER TABLE workflows ADD COLUMN trace_id VARCHAR(255)`
- **Per-Tool Governance (Phase 1)** (#1243): Add `ToolContext` to step gate requests for tool-aware policy evaluation within tool_call steps
  - New `ToolContext` struct: `tool_name`, `tool_type` (function/mcp/api), `tool_input`
  - Policy adapter propagates tool context into policy evaluation (tool_name, tool_type, tool_input.* keys)
  - Optional field — fully backward compatible with existing SDKs
  - ADR-038 documents Phase 1 (context enrichment) and Phase 2 (tool-scoped policies, future)
- **Per-Tool Governance Example**: New `langgraph_tools_example.py` demonstrating `check_tool_gate()` and `tool_completed()` for individual tool invocations within a LangGraph tools node
- **SDK-Platform Version Discovery** (#1275): Health endpoints now report real platform version, capability registry, and SDK compatibility information
  - `/health` response includes `version` (from `AXONFLOW_VERSION` env var), `capabilities` array, and `sdk_compatibility` object
  - Capability registry lists all platform features with the version that introduced them (15 capabilities from v1.0.0 through v4.8.0)
  - `sdk_compatibility` reports `min_sdk_version` and `recommended_sdk_version` for programmatic upgrade guidance
  - Applies to both Agent and Orchestrator health endpoints
- **Version Check Examples**: New `examples/version-check/` with HTTP, Go, Python, TypeScript, and Java variants demonstrating capability discovery
- **Compatibility Matrix**: New `docs/COMPATIBILITY_MATRIX.md` mapping platform versions to minimum SDK versions
- **SDK Telemetry Documentation**: New `docs/TELEMETRY.md` and `docs/TELEMETRY_CONTRACT.md` describing what SDK telemetry collects (version, OS, architecture), what is never collected (prompts, payloads, PII, API keys), defaults by deployment mode, and opt-out methods (`AXONFLOW_TELEMETRY=off` or `DO_NOT_TRACK=1`)

#### Changed

- **WCP Examples Updated**: All 6 existing workflow-control examples (Go, Python, Python LangGraph, TypeScript, Java, HTTP) updated with trace_id support and verification assertions

#### Fixed

- **Hardcoded health endpoint versions**: Agent and Orchestrator `/health` previously returned `"1.0.0"` regardless of actual platform version
- **Dockerfile version labels**: Agent and Orchestrator Dockerfiles now use `AXONFLOW_VERSION` build arg with `ENV` propagation for runtime access

### Enterprise

#### Added

- **SDK Telemetry Checkpoint Service**: New Lambda service at `checkpoint.getaxonflow.com` for anonymous SDK runtime telemetry
  - `POST /v1/ping` receives SDK telemetry, stores in DynamoDB, returns latest version info
  - `GET /v1/version` returns latest SDK versions (cacheable)
  - Privacy-preserving: IPs hashed (SHA256), 90-day TTL, no PII stored
  - Terraform infrastructure: Lambda, API Gateway, DynamoDB, CloudWatch alarms
- **Per-Tool Governance Policy Adapter**: `wcp_policy_adapter.go` propagates `ToolContext` fields into the dynamic policy evaluation context, enabling tool-aware governance rules
- **Evaluation Tier Feature Unlock**: Three high-impact features unlocked for Evaluation license holders, giving evaluators immediate demo value for governance control, safety simulation, and compliance proof
  - **HITL Approval Gates**: `require_approval` policy action now routes to a real HITL queue with Evaluation+ licenses. Approve/reject API, max 100 pending approvals, 24h fixed expiry with auto-reject, expiry cleanup goroutine
  - **Policy Simulation + Impact Report**: Two new endpoints for dry-run policy evaluation
    - `POST /api/v1/policies/simulate`: Run all active policies against input (Evaluation: 300/day, Enterprise: unlimited)
    - `POST /api/v1/policies/impact-report`: Test a single policy against N inputs with aggregate stats (Evaluation: 50 inputs, Enterprise: 100)
  - **Evidence Export Pack**: Bundled JSON export of audit logs, workflow steps, and HITL approvals
    - `POST /api/v1/evidence/export`: Synchronous JSON export with date range and type filters (Evaluation: 5K records, 14-day window, 3/day; Enterprise: unlimited, no watermark)
    - `GET /api/v1/evidence/summary`: Counts by evidence type within the tier's lookback window
    - Evaluation exports include `"NOT FOR REGULATORY SUBMISSION"` watermark; Enterprise exports are clean
  - Updated `TierLimits` struct with 9 new fields for feature gating
  - Updated `LicenseChecker` interface with 9 new methods
  - MaxPendingApprovals for Evaluation tier raised from 25 → 100
  - Database migration 056: `evidence_exports` table for export tracking and rate limiting
  - OpenAPI spec updated with 4 new endpoint definitions

---

## [4.7.0] - 2026-02-28

### Community

#### Added

- **Standalone MCP Policy-Check Endpoints** (#1265): Two new endpoints for external orchestrators (LangGraph, CrewAI) to validate MCP requests and responses against AxonFlow policies without executing connector queries
  - `POST /api/v1/mcp/check-input`: Validate SQL/commands against input policies (SQLi detection, dangerous query blocking, PII in queries, dynamic policies). Returns `allowed: true` or `403` with `block_reason`
  - `POST /api/v1/mcp/check-output`: Validate response data against output policies (PII redaction, exfiltration limits, dynamic policies). Returns original or redacted data with `policy_info`
  - Supports both query-style (`response_data`) and execute-style (`message` + `metadata`) output validation
  - Full audit logging for both endpoints
  - 1033-line test suite covering both endpoints with edge cases
- **MCP Check Endpoint Examples** (#1267, #1268): Full examples in 6 language variants — HTTP curl scripts, Python SDK, Python-HTTP (raw requests), Go SDK, TypeScript SDK, Java SDK
- **OpenAPI Spec for MCP Check Endpoints** (#1266): 4 new schemas (`MCPCheckInputRequest`, `MCPCheckInputResponse`, `MCPCheckOutputRequest`, `MCPCheckOutputResponse`) added to `agent-api.yaml`

#### Fixed

- **Python-HTTP MCP check example** (#1271): Added standalone `python-http/` variant with `requirements.txt` and virtual environment setup; refactored Python SDK example for clarity

#### Security

- **CVE-2026-24051**: Bumped `go.opentelemetry.io/otel/sdk` v1.38.0 → v1.40.0 in platform module (HIGH — OTel SDK resource attribute injection)
- **GHSA-72hv-8253-57qq**: Overrode transitive `jackson-core` 2.17.0 → 2.18.6 across 69 Java example pom.xml files (HIGH — async JSON parser `maxNumberLength` bypass)
- **OpenTelemetry BOM**: Added `opentelemetry-bom` dependency management to all Java examples for transitive CVE remediation (#1271)

### Enterprise

#### Added

- **Circuit Breaker Pipeline Wiring** (#1176, Phase 1): Wire existing circuit breaker state machine into the Agent request pipeline — previously `Check()`, `RecordError()`, `RecordPolicyViolation()` were dead code
  - `CB.Check()` runs before policy evaluation in both `clientRequestHandler` and `handlePolicyPreCheck` — returns HTTP 503 with dynamic `Retry-After` header when circuit is open
  - `RecordPolicyViolation()` called on every policy block, tracking violations toward auto-trip threshold (default: 20 violations in 5 minutes)
  - Active circuits loaded from DB on startup for restart persistence; background goroutine expires circuits every minute for auto-recovery
  - Community stubs added (`Check`, `IsAllowed`, `RecordError`, `RecordPolicyViolation`, `LoadCircuits`, `ExpireCircuits`) — no-op, always allowed
  - Example README updated with correct endpoint names and auto-trip documentation; shell script updated with auto-trip demonstration

---

## [4.6.0] - 2026-02-26

### Community

#### Fixed

- **Open-ended WCP workflows require hardcoded `total_steps`**: `total_steps` is now optional in `CreateWorkflow`. Omitting it (or passing `null`) creates an open-ended workflow — the step count is finalised automatically to `current_step_index` when the workflow reaches any terminal state (completed, aborted, or failed). Fixes LangGraph adapter use case where the graph iterates an unknown number of times. LangGraph example updated to omit `total_steps`; OpenAPI spec and guide updated

### Enterprise

#### Added

- **Cloud Storage Backends for Audit Exports**: S3, Azure Blob Storage, and GCS implementations of `StorageBackend` for durable, compliance-grade audit log export storage
  - S3: SSE-KMS encryption, Object Lock (WORM compliance), presigned URL downloads, configurable retention
  - Azure Blob Storage: SAS URL generation, shared key and connection string authentication
  - GCS: Signed URL generation, ADC / credentials file / credentials JSON authentication
  - Factory constructor: `AUDIT_EXPORT_STORAGE_TYPE` env var selects backend (`s3` | `azure` | `gcs` | `local`)
  - MinIO integration: Docker Compose enterprise config with MinIO for local S3-compatible testing
- **RBI Audit Export to Cloud Storage**: `AuditExportService` uploads exports to configured cloud backend, generates presigned download URLs on-demand, and manages cloud lifecycle (delete, cleanup expired). New `download_url`, `storage_type`, `storage_key` columns on `rbi_audit_exports`. Download handler returns HTTP 307 redirect for cloud exports. Falls back to local filesystem when no backend configured
- **SEBI Audit Export to Cloud Storage**: Large exports (>1000 records) automatically uploaded to cloud storage with presigned URL population. Small exports retain inline data response
- **EU AI Act Export to Cloud Storage**: `ExportService` wired with `StorageBackend` for cloud uploads during async export processing. Download handler generates presigned URLs for cloud-stored exports. New `download_url`, `storage_type`, `storage_key` columns on `euaiact_exports`
- **RBI Module Consolidation**: RBI module merged into `ee/` Go module — removed separate `go.mod`/`go.sum`, aligning with SEBI/EUAIACT/MASFEAT which already share the `ee/` module
- **Compliance Examples**: `audit-export-cloud/` examples (HTTP, Go, Python, TypeScript, Java) demonstrating full round-trip cloud export with presigned URL download and checksum verification

#### Fixed

- **India PII detector test failures**: 5 pre-existing test expectations corrected — UPI positive indicator precedence, sequential bank account rejection, Verhoeff all-zeros checksum, short bank account masking, `extractContext` boundary calculation

---

## [4.5.0] - 2026-02-22

### Community

#### Added

- **Media Governance Policy Engine** (#1224): Tiered media governance with system-managed policies
  - 5 default media governance rules seeded automatically: NSFW blocking, violence warning, biometric audit, PII blocking, sensitive document detection
  - Media governance enable/disable: Community deployments opt-in via `MEDIA_GOVERNANCE_ENABLED=true` environment variable
  - Media governance status API: `GET /api/v1/media-governance/status` returns feature availability per tier
  - Media policy categories: `media-safety`, `media-biometric`, `media-pii`, `media-document`
  - System media policy toggle: All tiers can enable/disable system media policies
  - New examples: `media-governance-policies/` demonstrating policy CRUD and governance outcomes (HTTP, Go, Python, TypeScript, Java)
- **Per-Step Token Tracking** (#1223): `tokens_in`/`tokens_out` fields through the full WCP step execution pipeline — types, migration 051, repository, service, and all 3 tracker mapping paths
- **Per-Step Cost Tracking** (#1229): `cost_usd` field through the full WCP step execution pipeline — types, migration 052, repository, service, and tracker. MAP workflows already had cost tracking; WCP now has parity
- **MAP/WCP Step Result Sync** (#1232): `SyncStepResults()` syncs step-level data (status, provider, model, tokens, cost) from `WorkflowExecution` to the unified execution tracker. Called from `executePlanHandler` before `SyncPlanStatus` in all 3 code paths
- **Prompt-Aware Cost Estimation** (#1230): `EstimatePlanCost` now uses actual step prompt length (`len(prompt)/4 + 50` input tokens) and `max_tokens` for output estimates, instead of hardcoded 1000/500. Output schema overhead calculated via `json.Marshal`. 5 new unit tests added
- **Stale Model ID CI Guardrail** (#1233, #1235): CI workflow scans docs and technical-docs markdown files on PRs for deprecated LLM model IDs. Fails CI when stale Anthropic, OpenAI, Ollama, or Bedrock model identifiers are introduced. Hardened with `fetch-depth: 0`, `rg` availability check, and runtime error handling

#### Fixed

- **StepComplete ignores post-execution metrics**: `MarkStepCompleted` handler silently dropped request body — `tokens_in`, `tokens_out`, `cost_usd` were only set at gate time, never updated at completion. Now accepts `StepCompleteRequest` with actual post-execution values that override gate-time estimates via COALESCE. Also stores `step_output` (migration 054). All 4 SDKs updated on v3.6.0 branches
- **Execution viewer token/cost rendering** (#1228): Token display showed "undefined" when value was `0` (used `!= null` check and `?? 0` nullish coalescing). Cost display skipped legitimate `$0.0000` values. Policy events rendered blank rows due to type mismatch between `[]string` and expected objects
- **WCP gate decisions invisible in unified execution** (#1228): `Decision`, `DecisionReason`, `PoliciesMatched`, `ApprovalStatus`, `ApprovedBy` were never mapped into unified `StepStatus`. Added conversion helpers: `extractPolicyNames`, `mapWCPGateDecision`, `mapWCPApprovalStatus`
- **Step status clobbering** (#1228): `BaseExecutionTracker.AddStep` unconditionally overwrote step status to `pending`, discarding WCP-computed status. Now preserves pre-set status
- **Execution cost null in API** (#1232): `actual_cost_usd` always null in API responses. Added `TotalCost()` calculation in `resolveExecution` and `ListExecutions`
- **WCP steps stuck at "running"** (#1232): Steps remained in running state when workflow completed. Replaced O(n) `ListExecutions` scan with O(1) indexed `GetByMetadata` lookup
- **Cost estimation used hardcoded tokens** (#1230): `EstimatePlanCost` ignored `Prompt` and `MaxTokens` fields on `WorkflowStep`, always using 1000/500. All 5 cost-estimation examples sent non-existent `estimated_tokens_in`/`estimated_tokens_out` fields silently dropped by JSON unmarshaling

#### Changed

- **LLM Model ID Sweep** (#1236): ~200 files updated across code defaults, pricing tables, tests, examples, infrastructure, and technical docs. Migration 053 updates COALESCE default for Bedrock model in `llm_provider_configs`
  - Anthropic: `claude-3-*`/`claude-3-5-*` → `claude-opus-4-20250514`/`claude-sonnet-4-20250514`/`claude-haiku-4-5-20251001`
  - Bedrock: Updated to region-prefixed inference profile IDs (`us.anthropic.claude-sonnet-4-20250514-v1:0` etc.)
  - OpenAI: `gpt-3.5-turbo` → `gpt-4o-mini`, `gpt-4-turbo` → `gpt-4o`
  - Ollama: `llama3.1` → `llama3.2`, `codellama` → `qwen2.5-coder:32b`, `mistral:7b` → `mistral:latest`, `mixtral:8x7b` → `mixtral:latest`
- **LLM provider diversity in examples** (#1223): 20 WCP and HITL example files updated from hardcoded `openai/gpt-4` to a mix of providers (ollama, anthropic, gemini, bedrock, azure) demonstrating provider-agnostic governance
- **Execution viewer UI** (#1223): Wired to unified execution API (`/api/v1/unified/executions`) with correct field mappings, gate decision/approval display, and step_index handling
- Media governance disabled by default on Community tier — previously ran globally if analyzers were registered (#1224)
- Dynamic policy API (`/api/v1/dynamic-policies`) now accepts `media-*` category prefixes alongside `dynamic-*` (#1224)
- Dynamic policy listing now includes system/global policies alongside tenant policies (#1224)
- Documentation: All LLM model references updated to current versions across docs and technical-docs (#1231)
- SDK version references bumped to v3.5.0 (#1221)
- Docker base images: Go 1.25-alpine → 1.26-alpine for agent and orchestrator (#1189, #1190)
- CI dependencies: `actions/github-script` 7→8, `docker/build-push-action` 5→6, `actions/upload-artifact` 4→6, `aws-actions/configure-aws-credentials` 4→6, `actions/download-artifact` 4→7 (#1197-#1201)

### Enterprise

#### Added

- **Per-Tenant Media Governance Configuration** (#1224): `GET/PUT /api/v1/media-governance/config` for enable/disable and analyzer restriction per tenant
- **System Media Policy Modification** (#1224): Enterprise tier can modify actions and priority on system media policies
- **Media Governance Audit Export** (#1224): `GET /api/v1/media-governance/audit/export` for compliance reporting (CSV/JSON)

#### Fixed

- **Customer portal Docker build failure** (#1226): `go.mod` in `ee/platform/customer-portal/` pinned `golang.org/x/crypto v0.45.0` while platform bumped to `v0.47.0` during v4.4.0 merge

### Breaking

- Community deployments that previously had media governance running globally must now set `MEDIA_GOVERNANCE_ENABLED=true` to opt back in

---

## [4.4.0] - 2026-02-18

### Community

#### Added

- **Multimodal Image Governance Pipeline** (#1214): Images are governed the same way as prompts — analyzed before routing, policies can block, and everything is audited.
  - `platform/orchestrator/media/` package: registry, factory, pipeline, audit, cost tracking, and license gating
  - Pluggable `MediaAnalyzer` interface with Name(), Type(), Analyze(), HealthCheck(), Capabilities()
  - Local OCR analyzer via Tesseract (`exec.CommandContext`, stdin/stdout, no temp files)
  - PII detection via composition — OCR text feeds existing `PIIDetectorFunc`, no drift
  - Pipeline runs analyzers in parallel per image, aggregates worst-case signals
  - Community default: fail-open (warn and audit), never blocks
  - 11 policy fields: `media.has_pii`, `media.has_faces`, `media.nsfw_score`, `media.violence_score`, `media.content_safe`, `media.has_biometric_data`, `media.is_sensitive_document`, `media.document_type`, `media.face_count`, `media.has_extracted_text`, `media.extracted_text_length`
  - API: `media` array on request, `media_analysis` object on response with per-image results
  - SHA-256 hashing for base64 and URL-sourced images (URL download with 30s timeout, 20MB limit, cached)
  - Validation: MIME type allowlist, max 20MB per image, max 8192px per dimension, max 10 images per request
  - Audit logging: hash, MIME type, file size, PII detection, content safety, timing (Enterprise adds biometric, safety scores, per-analyzer details)
  - New examples in 5 languages (HTTP/curl, Go, Python, TypeScript, Java) with strict field validation
- **SDK Media Types**: All 4 SDKs updated with `MediaContent`, `MediaAnalysisResult`, `MediaAnalysisResponse`
  - Go: `ProxyLLMCallWithMedia()` method
  - Python: `proxy_llm_call_with_media()` async + sync, caching disabled for media requests
  - TypeScript: media support in `proxyLLMCall()` options
  - Java: media in `ClientRequest.Builder`

### Enterprise

#### Added

- **Cloud Media Analyzers** (build tag `enterprise`): AWS Rekognition, Google Cloud Vision, Azure Computer Vision
- **Biometric and NSFW detection**: Face detection with count, NSFW and violence scoring, biometric data detection
- **Document classification**: Sensitive document detection (tax forms, medical records, bank statements, etc.)
- **Rich audit fields**: Per-analyzer details, biometric data, safety scores, document classification (gated behind `isEnterprise`)
- **Fail-closed enforcement**: Configurable to block requests when media analysis fails (Enterprise only)

#### Changed (Hardening)

- **Structured warning codes**: All media warnings now include a `code` + `message` (e.g., `WarnMediaAnalyzerError`). Both `warnings` (string array, backward-compatible) and `structured_warnings` (code/message objects) are returned in API responses.
- **Pre-decode base64 size check**: Oversized base64 payloads rejected before decode (avoids memory allocation).
- **Base64 decoded bytes cache**: Decoded bytes from `Validate()` are reused by `ComputeSHA256()` and `GetRawData()`, eliminating redundant base64 decoding.
- **Decompression bomb guard**: Images exceeding 100M pixels are rejected via `image.DecodeConfig` header check (fail-open for unparseable formats). New error code `ErrMediaDecompressionBomb`.
- **Analyzer concurrency cap**: Default max 10 concurrent analyzers per image via semaphore (configurable via `WithMaxConcurrentAnalyzers`).
- **Context cancellation**: Pipeline respects `ctx.Done()` during result collection; fail-open returns partial results with `WarnMediaPartialResults`, fail-closed returns error.
- **Deterministic analyzer result ordering**: `AnalyzerResults` sorted by `AnalyzerName`.
- **Fail-closed when no analyzers**: If enforcement is fail-closed and no analyzers are registered, pipeline returns error instead of empty results.
- **Orchestrator fail-closed handler**: When media analysis fails in fail-closed mode, orchestrator responds `403 Forbidden`.
- **Audit redaction**: Enterprise audit records redact `ExtractedText` to `[redacted: N chars]` and `PIIFinding.Value` to `[redacted]`.
- **SDK cache skip for media**: Go and Java SDKs skip response caching when media is present (binary content makes cache keys unreliable).

#### Breaking

- **`extracted_text` removed from API responses and policy context.** Replaced by `has_extracted_text` (bool) and `extracted_text_length` (int). Existing policies referencing `media.extracted_text` must be updated to use `media.has_extracted_text` or `media.extracted_text_length`.

---

## [4.3.1] - 2026-02-16

### Community

#### Fixed

- **Execution cost always $0.0000**: `recordStepSnapshot()` now calculates actual cost from tokens using pricing config instead of leaving `CostUSD` as zero. Costs visible in Execution Viewer UI and API responses
- **Router cost used pre-execution estimates**: LLM router now uses actual response token counts for cost calculation instead of pre-execution estimates, with fallback for providers that only report total tokens

---

## [4.3.0] - 2026-02-13

### Community

#### Fixed

- **WCP error sentinel consistency (Bugs A, I)**: All repository methods (`CompleteWorkflow`, `AbortWorkflow`, `FailWorkflow`, `ResumeWorkflow`) now wrap `ErrWorkflowNotFound` with `%w` instead of creating new errors. `errors.Is(err, ErrWorkflowNotFound)` works correctly across all WCP operations. Added missing `rows.Err()` checks in `List()`, `GetStepsForWorkflow()`, `GetPendingApprovals()`.
- **MAP execution tracking accuracy (Bugs C, D)**: `SyncPlanStatus` replaced O(n) `ListExecutions` scan with direct `GetExecutionByPlanID()` lookup using new GIN index on `metadata->>'plan_id'`. Expired plans now tracked as `expired` status instead of incorrectly mapping to `completed`.
- **StepModeEvaluator idempotency (Bug J)**: Step gate evaluation keyed on `(planID, stepIndex)` via `sync.Map` instead of a plain counter. Retries return the cached decision instead of advancing the counter.
- **Connection tracker tenant validation (Bug K)**: SSE connections with missing `X-Tenant-ID` header now return `400 Bad Request` instead of silently falling back to a shared `"default"` bucket.
- **SyncPlanStatus error visibility (Bug L)**: `SyncPlanStatus` errors logged as warnings instead of silently discarded via `_ =`.
- **json.Marshal error handling (Bug B)**: Abort and fail reason marshaling errors in WCP repository now propagated instead of suppressed with `_ :=`.

#### Added

- **Cost Estimation Endpoints** (#1072): Pre-execution cost analysis for MAP plans
  - `POST /api/v1/plans/estimate`: Estimate cost from provider/model/steps specification
  - `GET /api/v1/plans/{id}/cost`: Get cost estimate for an existing plan
  - Tiered response: community gets aggregate total only (10/day), evaluation gets per-step breakdown (100/day), enterprise unlimited
- **WCP Community Approve/Reject**: Basic approval flow via step gates with HITL status endpoint (`GET /api/v1/hitl/status`)
  - Tiered limits: community max 5 pending approvals, evaluation max 25, enterprise unlimited
- **Direct Metadata Lookup**: `GetExecutionByPlanID()` and `GetExecutionByMetadata()` methods for efficient execution lookups
- **Expired Execution Status**: `ExecutionStatusExpired` constant and `ExpireExecution()` method for proper lifecycle tracking
- **Migration 050**: GIN index on `execution_history.metadata->>'plan_id'`, `expired` enum value for `execution_status`
- **New examples**: `workflow-fail/`, `cost-estimation/`, `hitl-queue/` across Go, Python, TypeScript, Java, and HTTP

### Enterprise

#### Added

- **MAP-HITL Integration** (#1076): Enterprise HITL approval workflow for MAP plan steps
  - `POST /api/v1/plans/{id}/steps/{step_id}/approve` and `reject` endpoints
  - `HITLWorkflowEngine` wired when enterprise license present
  - Community mode returns 403 for HITL endpoints
- **HITL Expiration Background Job**: Automatic expiration of stale approval requests
  - 1-hour ticker interval with configurable schedule
  - `ExpireRequests()` method in service and repository layers
  - Graceful shutdown via stop channel
- **HITL Queue API in SDKs**: All 4 SDKs now include HITL queue methods (list, get, approve, reject, stats)
- **New enterprise examples**: `ee/examples/hitl-queue/`, `ee/examples/hitl-expiration/`, `ee/examples/map-hitl/`, `ee/examples/cost-estimation-enterprise/`, `ee/examples/tier-limits/`

---

## [4.2.2] - 2026-02-12

### Community

#### Fixed

- Unified execution `CancelExecution` and `StreamExecutionStatus` endpoints returned 404 when given a WCP workflow ID or MAP plan ID. Now uses the same multi-strategy resolution as `GetExecutionStatus` (direct ID → WCP tracker → MAP tracker → metadata fallback)
- Execution history FK constraint on `tenant_id` prevented record creation in community mode when SDK sends a default client ID. Dropped FK constraint in favor of RLS policy for tenant isolation (migration 049)

## [4.2.1] - 2026-02-10

### Community

#### Fixed

- `FailWorkflow()` missing webhook notification, audit log, and HTTP endpoint (`POST /api/v1/workflows/{id}/fail`)
- WCP example fixes: TypeScript `PendingApprovalsResponse.items` → `.approvals`, Java `WorkflowStatus` enum-to-string comparison

#### Added

- FailWorkflow test coverage across all 5 WCP examples and 4 webhook unit tests with `MockWebhookNotifier`

---

## [4.2.0] - 2026-02-10

### Community

#### Added

- **Evaluation Tier Licensing**: Free 90-day license with elevated limits for production proof-of-concepts
  - Request at [getaxonflow.com/evaluation-license](https://getaxonflow.com/evaluation-license)
  - Limits: 50 tenant policies, 5 org policies, 5 connectors with custom policies, 3 LLM providers, 14-day audit retention, 100 plans, 25 versions/plan
  - Graceful degradation to Community tier on expiry. No downtime, no data loss
- **Ed25519 License Signing**: Asymmetric cryptographic signatures replace HMAC-SHA256
  - Public keys embedded in binary; private keys stay in infrastructure (AWS Secrets Manager)
  - Format: `AXON-{PAYLOAD}.{SIGNATURE}`. Old V2 (`AXON-V2-...`) and V1 formats rejected with clear upgrade message
  - Two keypairs: evaluation (for free licenses) and enterprise (for paid licenses). Blast radius isolation
- **Feature Limits Boundary Testing**: `examples/feature-limits/http/test_feature_limits.sh` validates all tier limits across Community, Evaluation, and Enterprise modes
- **E2E Setup Script**: `scripts/setup-e2e-testing.sh` now supports `evaluation` mode alongside `community` and `enterprise`
- **Workflow Control Plane v1** (#834): Governance gates for external orchestrators (LangChain, LangGraph, CrewAI)
  - `POST /api/v1/workflows`: Register workflow with name, source, total_steps, metadata
  - `GET /api/v1/workflows`: List workflows with status/source filters
  - `GET /api/v1/workflows/{id}`: Get workflow status and step history
  - `POST /api/v1/workflows/{id}/steps/{step_id}/gate`: Policy-based step gate (allow/block/require_approval)
  - `POST /api/v1/workflows/{id}/steps/{step_id}/complete`: Mark step completed with output data
  - `POST /api/v1/workflows/{id}/complete`: Mark workflow completed
  - `POST /api/v1/workflows/{id}/abort`: Abort workflow with reason
  - `POST /api/v1/workflows/{id}/resume`: Resume after approval
  - Step gate responses include `policies_evaluated` and `policies_matched` for policy transparency
  - Audit logging: `workflow_created`, `workflow_step_gate`, `workflow_completed`, `workflow_aborted`
- **MAP Plan Versioning & Rollback** (#1072): Full plan lifecycle management with optimistic locking
  - `UpdatePlan()`: Update plan with version conflict detection (`ErrVersionConflict` on mismatch)
  - `GetPlanVersions()`: Retrieve full version history with change tracking (changed_by, change_type, change_summary)
  - `RollbackPlan()`: Restore to a previous version snapshot (creates pre-rollback snapshot first)
  - `CleanupExpiredPlans()`: Background worker removes expired plans (configurable interval, default 15min)
  - Community limits: max 25 plans with versioning, max 10 versions per plan
  - Migration `047_plan_versioning.sql`: adds `version` column to plans, creates `plan_versions` table
- **MAP Confirm & Step Execution Modes** (#1072): HITL execution modes via WCP infrastructure
  - Confirm mode: every step requires explicit approval before proceeding
  - Step mode: first step auto-allowed, subsequent steps require approval
  - Creates WCP workflow (`map-confirm-{planID}` / `map-step-{planID}`) to track step gates
  - Maps plan steps to WCP step types (llm-call, tool-call, connector-call, etc.)
- **MAP Plan Cancellation** (#1074): `PlanStatusCancelled` constant and `CancelPlan()` method in planning service
- **Unified Execution Tracking** (#1074, #1075): Consistent status tracking across MAP plans and WCP workflows
  - `GET /api/v1/unified/executions`: List executions with type/status filters
  - `GET /api/v1/unified/executions/{id}`: Get status by execution ID, workflow ID, or plan ID
  - `POST /api/v1/unified/executions/{id}/cancel`: Cancel execution (propagates to MAP or WCP)
  - MAPExecutionTracker: adapts planning service to unified format, syncs plan state changes
  - WCPExecutionTracker: adapts WCP service to unified format, maps step decisions to unified status
  - Lookup by execution ID, `wf_*`/`wcp_*` prefix, `plan_*` prefix, or metadata search
- **SSE Execution Streaming** (#1074): `GET /api/v1/unified/executions/{id}/stream` provides real-time execution events
  - Events: `execution.started`, `execution.completed`, `execution.failed`, `execution.cancelled`, `step.started`, `step.completed`, `step.failed`, `step.decision`
  - Auto-closes on terminal state; no external dependencies (pure Go channels)
  - Per-tenant connection limits: Community (5), Evaluation (25), Enterprise (unlimited)
  - HTTP 429 with `Retry-After: 30` header when limit exceeded
  - `ConnectionTracker` with atomic acquire/release pattern (handles disconnect, timeout, panic)
- **EventHub Pub-Sub** (#1074): Channel-based event bus in `platform/shared/execution/event_hub.go`
  - Buffered channels (cap 16), non-blocking publish with slow subscriber protection
  - Both MAP and WCP trackers publish events on state transitions
- **Unified Execution Handler Tests**: Tests covering list, get, cancel, CORS, and route registration
- **CancelPlan Tests**: 6 tests covering cancel from pending/executing states, validation
- **Cost Estimation** (#1072): `GET /api/v1/plans/{id}/cost` and `POST /api/v1/plans/estimate` for pre-execution cost estimation with per-step breakdowns
- **MAP + WCP Examples**: `map-confirm-mode/`, `map-lifecycle/`, `workflow-control/` across all 5 languages (Go, Python, TypeScript, Java, HTTP)

#### Fixed

- **Tenant ownership check on unified execution endpoints**: Execution list/get/cancel now validates tenant ownership, preventing cross-tenant data access
- **Agent gateway always returned `success: true`**: Orchestrator errors (409 cancelled, 410 expired, 403 blocked) were buried in nested response data. Agent never propagated them to `ClientResponse`. SDKs never raised exceptions for failed operations. Also fixed metrics counting errors as successes and usage recorder status codes.
- **MAP confirm mode not enforced**: `ConfirmModeEvaluator` was defined but never wired into WCP `StepGate()`. Policy engine always returned "allow" instead of "require_approval". Fixed by adding `GateOverride` to `StepGateRequest`, used by `ExecuteWithConfirm` and `resumePlanHandler`.
- **MAP execution timeout too tight**: Hardcoded 60s timeout caused `context deadline exceeded` on multi-step balanced mode plans. Now scales to 30s per step with 60s minimum floor.
- **Examples hardcoded user tokens**: All examples now read `AXONFLOW_USER_TOKEN` env var with safe community defaults
- **25 broken documentation links**: Replaced stale `docs.getaxonflow.com` URLs across 15 markdown files
- **Down migrations 045/046 destructive**: Replaced destructive Down sections with no-ops to prevent CI `psql -f` from reversing Up migrations

#### Changed

- **License format migration**: All licenses must use Ed25519 format (`AXON-{PAYLOAD}.{SIGNATURE}`). Old V2 HMAC format (`AXON-V2-...`) returns Community tier with upgrade guidance. No action needed for users without a license (Community mode unchanged).
- **HMAC startup check removed**: `ValidateHMACSecretAtStartup()` is now a no-op. No HMAC secret environment variable required at startup
- **BaseExecutionTracker**: Now publishes events via EventHub after every state change (start, complete, fail, cancel, step transitions)
- **UnifiedExecutionHandler**: Accepts EventHub and PlanService; registers cancel, stream, and list/get routes
- **ADR-030**: Updated with SSE streaming, cancellation, and versioning architecture patterns
- **License tier names normalized**: `PRO`→`Professional`, `ENT`→`Enterprise`, `PLUS`→`Plus`, `BASIC`/`EVALUATION`→`Evaluation`. Migration 122 updates all tier-related tables. DB constraint enforces canonical names.
- **SDK versions bumped to v3.3.0** across all examples and docs
- **CI dependencies bumped**: actions/checkout v6, actions/setup-go v6, Go 1.25, Docker Alpine 3.23
- **Coverage thresholds raised to 76%** for orchestrator and connectors modules
- **Documentation quality improved** across 36 files: correct auth patterns, SDK method names, "source-available" terminology, current versions

### Enterprise

#### Added

- **WCP HITL Approval Gates** (#1169): Human-in-the-loop approval for workflow steps
  - `POST /api/v1/workflows/{id}/steps/{step_id}/approve`: Approve a pending step (requires approval_id from gate)
  - `POST /api/v1/workflows/{id}/steps/{step_id}/reject`: Reject step with optional reason
  - `GET /api/v1/workflows/approvals/pending`: List all workflows awaiting human approval
  - Approval URLs generated for notification links
- **Webhook Notification System** (#1169): Event-driven notifications for workflow and approval events
  - `POST /api/v1/webhooks`: Create webhook subscription
  - `GET /api/v1/webhooks`: List subscriptions
  - `GET /api/v1/webhooks/{id}`: Get subscription details
  - `PUT /api/v1/webhooks/{id}`: Update subscription
  - `DELETE /api/v1/webhooks/{id}`: Delete subscription
  - 7 event types: `step.approval_required`, `step.approved`, `step.rejected`, `step.completed`, `workflow.completed`, `workflow.aborted`, `workflow.failed`
  - HMAC-SHA256 request signing when secret configured; secret never exposed in API responses
  - SSRF protection: blocks private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
  - Retry strategy: exponential backoff (1s, 2s, 4s), max 3 retries, 10s timeout per attempt
  - Migration `048_webhook_subscriptions.sql`: subscription and delivery tracking tables

---

## [4.1.0] - 2026-02-05

### Community

#### Added

- **AES-256-GCM Connector Credential Encryption** (#1157): Credentials encrypted at rest via `CONNECTOR_ENCRYPTION_KEY` env var
  - Credentials stored separately from connection URLs. No secrets in `connection_url` column
  - Supports encrypted, JSON-quoted encrypted, and plain JSON formats (backward compatible)
- **Connector SDK Runtime Wiring** (#1140): Connector installs persist to `connector_configs` table; Agent reads runtime configs from DB with static fallback
  - All SDK-backed connectors (Postgres, MySQL, MongoDB, Redis, Cassandra, HTTP) migrated to `connectors/sdk.BaseConnector`
  - Runtime config service loads connector credentials and options from DB, reconstructs connection URLs at runtime
- **LLM Provider SDK Registration** (#1140): SDK-backed LLM providers (OpenAI, Anthropic, Gemini) registered at orchestrator startup via factory pattern
  - Azure OpenAI runtime config parity across env/config/DB paths
- **Strict Provider Pinning** (#1140): `context.strict_provider=true` hard-pins to a specific provider; default remains preference with failover
- **Direct LLM Config Passing** (#1157): `BootstrapFromConfig` replaces goroutine-unsafe `ApplyLLMConfigToEnv` / `os.Setenv`
- **Atomic LLM Provider Update** (#1157): `Registry.Update()` method prevents gap where provider is missing during reconfiguration
- **Audit Logging Examples** (#1135): Complete audit logging examples across Go, Python, TypeScript, Java SDKs
- **Testcontainers for Integration Tests** (#1136, #1137): PostgreSQL integration tests use testcontainers instead of mock DB
- **Runtime Connector Config Migrations** (#1140): `007_runtime_connector_configuration.sql`, `045_connector_configs_credentials.sql`

#### Fixed

- **Encrypted credentials never decrypted on load** (#1157): `RuntimeConfigService` now uses `CredentialEncryptor.Decrypt()` instead of `json.Unmarshal`
- **MySQL DSN credentials persisted in stored URLs** (#1157): `StripURLCredentials` now handles `@tcp()` and `@unix()` DSN formats
- **Connector uninstall DB/registry divergence** (#1157): Unregister from memory first, then delete DB record
- **PII detection examples require `PII_ACTION=block`** (#1154): Updated examples and docs with prerequisite
- **Migration runner safety** (#1140): `_down.sql` files skipped by migration runner to prevent accidental rollbacks
- **Internal MCP calls carry tenant ID** (#1140): Orchestrator→Agent MCP calls now include tenant ID for correct access isolation

#### Changed

- **Connector install/uninstall requires `tenant_id`** when a DB is present (#1140, #1157): Prevents silent inconsistent state; matches schema constraints
- **`context.provider` remains preference** (#1140): Failover still default unless `strict_provider` is set
- **LLM provider runtime constraints** (#1140): Expanded allowed provider names to include `gemini`, `azure-openai`, and `custom`
- **Connector runtime constraints** (#1140): Expanded allowed connector types to include SDK-backed connectors (http/mysql/mongodb/redis/s3/etc)
- **SDK versions bumped to v3.2.0** across all examples and docs (#1158, #1145)
- **README**: Design Partner program CTA (#1149), Feedback Week (#1151), LLM provider scope clarification (#1159)

### Enterprise

#### Added

- **Enterprise runtime config bootstrap** (#1140): Ensures runtime connector/LLM config tables are created after `customers` exists
- **Bedrock example hardening** (#1140): Enterprise Bedrock example now uses standard env aliases + enterprise JWT for policy pre-checks

## [4.0.0] - 2026-02-03

### Community

#### Added

- **Configurable System Policy Architecture** (#1121): Per-mode policy control for MCP and Gateway modes
  - `MCP_STATIC_POLICIES_ENABLED` / `GATEWAY_STATIC_POLICIES_ENABLED`: enable/disable static policies per mode
  - `MCP_PII_ACTION` / `GATEWAY_PII_ACTION`: override PII action per mode (block/redact/warn/log)
  - `MCP_SQLI_ACTION` / `GATEWAY_SQLI_ACTION`: override SQLi action per mode
  - `MCP_STATIC_POLICIES_SKIP_CATEGORIES` / `GATEWAY_STATIC_POLICIES_SKIP_CATEGORIES`: skip specific categories
  - Env var precedence: mode-specific → global (`PII_ACTION`) → engine defaults
- **Policy Engine Consolidation** (#1122): Single evaluation path across all modes
  - Proxy, Gateway, and MCP all use `UnifiedPolicyEngine` as primary path (was three separate engines)
  - Standalone `AuditManager` decoupled from `DatabasePolicyEngine`; shared engine now receives audit adapter
  - Admin role handling via `SkipCategories` instead of engine-level role checks
- **MCP Execute Policy Responses** (#969): `policy_info`, `redacted`, `redacted_fields` in MCP execute responses
- **Execution Replay CLI + Embedded Execution Viewer UI** (#1120):
  - `axonctl executions list/get/replay/export`: CLI commands for inspecting workflow executions from the terminal
  - Browser-based execution viewer at `/ui/executions/` via Go `embed.FS`. Filterable execution list, step timeline visualization, JSON export
  - Supports both MAP (Multi-Agent Planning) and WCP (Workflow Control Plane) executions
- **HMAC-Signed Internal Service Tokens** (#627, #1114): HMAC-SHA256 signed tokens replace plain shared-secret for orchestrator-to-agent auth. 5-minute replay protection. Backward-compatible with deprecation warning.
- **Singapore PII patterns documentation** (#1076, #1118): SDK feature coverage docs updated with NRIC, FIN, UEN patterns

#### Fixed

- **Gateway pre-check ignoring `GATEWAY_STATIC_POLICIES_ENABLED=false`** (#1121): Fell through to `dbPolicyEngine` which didn't check the flag
- **Orchestrator ignoring action overrides** (#1121): `processWithSharedEngine()` and `DetectWithSharedEngine()` now respect per-mode config
- **Proxy mode ignoring per-mode policy config** (#1122): Now uses `UnifiedPolicyEngine` with `GATEWAY_*` env vars
- **Shared policy engine had nil audit queue** (#1122): Policy evaluations in MCP/Gateway now log through audit infrastructure
- **Dockerfile missing `/var/lib/axonflow/audit/`** (#1122): Audit queue fallback failed for non-root user
- **Gateway enterprise integration tests** (#283, #1112): Fixed OAuth2 Basic auth with valid V2 license format
- **Marketplace connector persistence tests** (#283, #1112): Fixed lazy-loaded connectors after `ReloadFromStorage`
- **HITL examples only tested CRUD** (#1090, #1113): All 4 SDKs now test actual enforcement via `ProxyLLMCall`

#### Changed

- **SDKs v3.0.0**: All four SDKs bumped to v3.0.0 (Python skips v2.0.0 for cross-SDK version consistency):
  - **Removed `executeQuery()`** (deprecated since v2.5): Use `proxyLLMCall()` for proxy mode or MCP connector queries
  - **TypeScript**: Removed 5 deprecated LLM interceptors, added `wasRedacted()` helper
  - **Python**: Skipped v2.0.0 → v3.0.0 for consistency. Added `was_redacted()`, fixed internal MCP call serialization, fixed null `policies_evaluated` validation
  - **Go**: Updated module path to `axonflow-sdk-go/v3`, added `WasRedacted()`
  - **Java**: Removed `executeQuery()`/`executeQueryAsync()`, verified `isRedacted()`
- **Gateway mode examples enhanced**: PII detection (SSN, India PAN, Aadhaar) and SQLi blocking (DROP TABLE, UNION SELECT) assertions added across all 4 SDKs
- **New examples**: `policy-configuration/` and `gateway-policy-config/` (Go, Python, TypeScript, Java)
- **Enhanced examples**: `pii-detection/`, `sqli-detection/`, `mcp-policies/`, `map/` updated with multi-action mode and `policy_info`

#### Breaking Changes

- **`executeQuery()` removed from all SDKs**: Use `proxyLLMCall()` or MCP connector queries. Deprecated since v2.5.
- **Env var behavior change**: Global detection env vars (`PII_ACTION`, `SQLI_ACTION`) now control the primary shared engine. Existing deployments may see different behavior in MCP and Gateway modes. Use mode-specific vars (`MCP_PII_ACTION`, `GATEWAY_PII_ACTION`) for precise control.

---

## [3.6.1] - 2026-01-30

### Community

#### Fixed

- **MCP Community Auth** (#1109): MCP query/execute endpoints incorrectly required license validation in community mode, returning HTTP 401
  - Replaced raw environment variable check with canonical `isCommunityMode()` helper
  - Extracted duplicated license validation into shared `validateServiceLicense()` helper
- **MAP Replay Recording** (#1108): Parallel execution path was missing replay recording. MAP executions left no trace in `execution_snapshots`
  - Added `StartExecution`, `recordStepSnapshot`, `CompleteExecution`/`FailExecution` calls to parallel path
- **MAP Parallel Data Race** (#1108): Input map shared across parallel goroutines without protection
- **MAP Silent Error Swallowing** (#1108): `FailExecution` errors silently discarded in 4 call sites
- **EU AI Act Export Data Race** (#1109): `CreateExport` returned shared pointer mutated by async goroutine, causing flaky tests under `-race`
- **Anthropic Default Model** (#1109): Updated default from `claude-3-5-sonnet-20241022` (404) to `claude-sonnet-4-20250514`

#### Added

- **HTTP Examples** (#1109): Added missing HTTP examples for `mcp-connectors` and `map` (completing 30/30 cross-language coverage)

### Enterprise

#### Fixed

- **V1 License Error Messaging** (#1106): Renamed error code to `V1_LICENSE_NOT_SUPPORTED`, removed internal tool paths from user-facing errors
- **DEPLOYMENT_MODE Case Handling** (#1109): Removed unnecessary case normalization in admin auth middleware

#### Security

- **Next.js** (GHSA-h25m-26qc-wcjf): Bumped in customer-portal-ui (16.0.10→16.1.6) and banking-demo (15.5.9→15.5.10)

---

## [3.6.0] - 2026-01-26

### Community

#### Added

- **Unified Execution Tracking** (#1075): Consistent status tracking for MAP plans and WCP workflows
  - New unified execution history table (`execution_history`) for both MAP and WCP executions
  - `GET /api/v1/executions/{id}` - Get unified execution status by ID
  - `GET /api/v1/executions` - List executions with type/status filters
  - `ExecutionType`: `map_plan`, `wcp_workflow`
  - `ExecutionStatusValue`: `pending`, `running`, `completed`, `failed`, `cancelled`, `aborted`, `expired`
  - `StepStatusValue`: `pending`, `running`, `completed`, `failed`, `skipped`, `blocked`, `approval`
  - `UnifiedStepType`: `llm_call`, `tool_call`, `connector_call`, `human_task`, `synthesis`, `action`, `gate`
  - Unified step tracking with duration, cost, and policy decision fields
  - SDK support in Go v2.7.0, Python v1.7.0, TypeScript v2.7.0, Java v2.7.0

- **Singapore PII Detection** (#1078): MAS FEAT compliance patterns for PII detection
  - NRIC pattern detection (S/T/M/F/G prefixes) with critical severity
  - FIN pattern detection (F/G prefixes) for foreign identification
  - UEN pattern detection for business entities
  - Singapore phone numbers (+65 format)
  - Singapore postal codes (6-digit)
  - Examples: Go, Python, TypeScript, HTTP

- **Compliance Policy Categories** (#1081): New policy category constants for compliance evaluation
  - Added `CategoryComplianceEUAIAct` and `CategoryComplianceMASFEAT` constants
  - Added `IsComplianceCategory()` and `AllComplianceCategories()` helper functions
  - RBI, SEBI, EU AI Act, and MAS FEAT categories evaluated at gateway and MCP handlers

- **Redis Policy Store** (#1071): Distributed rate limiting and budget tracking for MCP policies with automatic fallback

- **Budget Enforcement Wiring** (#1082): Budget limits now block requests when exceeded
  - Gateway calls `CheckBudget()` before processing requests
  - HTTP 402 returned when budget exceeded with `on_exceed=block`
  - `X-Budget-Warning` header for `on_exceed=warn`
  - `BudgetInfo` in response

- **HITL Workflow Engine Wiring** (#1082): Human-in-the-Loop integrated with workflow execution
  - `ExecuteWithHITL()` wired to production execution path
  - Enterprise: Database persistence; Community: In-memory with auto-approve

- **WCP to HITL Connection** (#1082): `require_approval` decisions create HITL queue entries

- **MAP Conditional Branch Execution** (#1082): Branches now execute steps, not just record intent

- **MAP Parallel Execution Tolerance** (#1082): Configurable `SoftFailureTolerance` replaces hardcoded logic

- **Policy Cache Refresh API** (#1082): Immediate policy availability after CRUD operations
  - New `PolicyEngineRefresher` interface for policy engines
  - `RefreshPolicies()` method on both `DynamicPolicyEngine` and `DatabaseDynamicPolicyEngine`
  - `PolicyService` triggers refresh after create, update, delete, and import operations
  - Eliminates 30-second cache delay for WCP HITL integration

- **Dynamic Policy `require_approval` Action** (#1082): HITL trigger from dynamic policies
  - New `require_approval` action type in dynamic policy evaluation
  - Sets `Allowed=false` and adds `require_approval` to `RequiredActions`
  - Supports `reason` field in action config for approval context

- **Nested Context Path Support** (#1082): Enhanced dynamic policy field matching
  - `context.step_input.query` now correctly resolves to `req.Context["step_input.query"]`
  - Supports arbitrary depth in dotted notation (e.g., `context.a.b.c`)

#### Fixed

- **HMAC Secret Panic** (#1082): Enterprise Docker images no longer panic when HMAC secret not initialized
  - Added `isHMACSecretInitialized()` thread-safe check using RLock
  - `IsEnterpriseTier()` returns false gracefully instead of panicking
  - Allows enterprise images to run in community mode without configuration changes

- **MCP Dynamic Policy Evaluation** (#1071): Fixed multiple pre-existing bugs preventing MCP dynamic policies from working
  - Added MCP policy types to validation, fixed DATABASE_URL propagation, created interface for both in-memory and database engines
- **Agent DB Auth** (#1071): Fixed JSON parsing for permissions from JSONB array
- **Cassandra Connector** (#1071): Apply timeout from query config to CQL operations

- **SDK Examples with Assertions** (#1082, #1097, #1099): Examples now have proper pass/fail testing and exit with code 1 on failure
  - Added assertions across all 4 SDKs (Go, Python, TypeScript, Java)
  - Community examples fixes (#1099): workflow examples, policy examples, integration examples

- **HITL Enforcement for Compliance Frameworks** (#1089): Fixed HITL not triggering in Proxy Mode
  - Root cause: Database constraint missing `require_approval` action + runtime wiring gap
  - Migration 044: Added `require_approval` to `action_request`/`action_response` constraints
  - Added `ActionRequireApproval` action type to shared policy types
  - Multi-strategy HITL detection: `eu_ai_act_article_14`, `requires_hitl` + compliance context, high-risk + compliance framework
  - EU AI Act and RBI-SEBI examples now achieve 100% HITL compliance rate

#### Deprecated

- **API: page_size → limit** (#1099): Standardized pagination parameter name
  - **Action Required:** Migrate from `page_size` to `limit` before v4.0.0
  - `page_size` query parameter is deprecated and **will be removed in v4.0.0**
  - Affected endpoints: `/api/v1/static-policies`, `/api/v1/dynamic-policies`
  - Both parameters work during transition period; `limit` takes precedence

- **SDK: ExecuteQuery → ProxyLLMCall** (#1052): Renamed for clearer Proxy Mode semantics
  - **Action Required:** Migrate from `executeQuery()` to `proxyLLMCall()` before the next major release
  - Old methods emit deprecation warnings and **will be removed in v4.0.0**
  - New names clarify the two integration modes:
    - **Proxy Mode:** `proxyLLMCall()` - AxonFlow proxies your LLM request
    - **Gateway Mode:** `getPolicyApprovedContext()` + `auditLLMCall()` - You call LLM directly
  - All SDK examples and demos updated to use new method names
  - Applies to: Go SDK, TypeScript SDK, Python SDK, Java SDK

### Enterprise

#### Added

- **MAS FEAT Compliance Module**: Singapore financial services AI governance framework
  - Implements Monetary Authority of Singapore FEAT (Fairness, Ethics, Accountability, Transparency) guidelines
  - AI System Registry with 3-Dimensional Risk Rating (Customer Impact × Model Complexity × Human Reliance)
  - Materiality Classification: High (sum≥12), Medium (sum≥8), Low (sum<8)
  - FEAT Assessment lifecycle: pending → in_progress → completed → approved/rejected
  - Four pillar scoring: Fairness, Ethics, Accountability, Transparency (with detailed sub-metrics)
  - Kill Switch with automatic triggering based on accuracy, bias, and error rate thresholds
  - 7-year audit retention for regulatory compliance
  - Singapore-specific PII detection with Verhoeff checksum validation (NRIC, FIN, UEN)

- **MAS FEAT Database Schema**: New tables for compliance data
  - `ai_system_registry` - AI system registration with materiality tracking
  - `feat_assessments` - FEAT assessment records with pillar scores
  - `kill_switch` - Kill switch configuration and status
  - `kill_switch_events` - Kill switch event audit log

- **MAS FEAT API Endpoints**: Full REST API for compliance operations
  - AI System Registry CRUD (`/api/v1/masfeat/registry/*`)
  - FEAT Assessment lifecycle (`/api/v1/masfeat/assessments/*`)
  - Kill Switch management (`/api/v1/masfeat/killswitch/*`)

- **Compliance Runtime Wiring** (#1081): Enterprise compliance module initialization
  - RBI, SEBI, EU AI Act, and MAS FEAT module initialization with health checks
  - Compliance route registration (`/api/v1/rbi/*`, `/api/v1/sebi/*`, `/api/v1/euaiact/*`, `/api/v1/masfeat/*`)
  - Compliance examples with strict HITL assertion validation

- **HITL Execution Store** (#1071): In-memory store with SaveExecution/GetExecutionStatus for pause/resume workflow

- **SCIM Provisioning Examples** (#1082): User, group, token management examples

- **WCP HITL Queue Integration** (#1092): `require_approval` policy actions now create HITL queue entries
  - Enterprise: Database persistence in `hitl_approval_queue` with `wcp_step_gate` request type
  - Community: No-op stub with informational logging
  - 24-hour default expiry for approval requests
  - New E2E example at `ee/examples/workflows/wcp-hitl/go` verifying queue entry creation

#### Fixed

- **WCP HITL Approval Queue Insert** (#1082): Fixed INSERT query for `hitl_approval_queue` table
  - Removed explicit `id` column from INSERT (now auto-generated by sequence)
  - `request_id` (UUID) is the primary identifier for approval requests

- **SDK Examples Fixes** (#1099): Fixed enterprise examples (eu-ai-act, rbi-sebi, healthcare, llm-providers/e2e-tests) across all 4 SDKs

#### SDK Support

- TypeScript SDK v2.7.0: `client.masfeat.*` namespace, `budgetInfo`
- Python SDK v1.7.0: `client.masfeat.*` namespace, `budget_info`
- Go SDK v2.7.0: `client.MASFEAT*()` methods, `BudgetInfo`
- Java SDK v2.7.0: `client.masfeat().*` namespace, `getBudgetInfo()`

---

## [3.5.0] - 2026-01-18

### Added

- **Workflow Policy Enforcement** (#1019, #1020, #1021): Policy evaluation at workflow transitions
  - **MAP Policy Enforcement** (#1020): Dynamic policy evaluation before plan execution
    - Policy check in `executePlanHandler` with allow/block decisions
    - `PolicyInfo` field in `PlanResponse` with evaluated policies and risk score
    - Policy results recorded in step execution snapshots for replay/audit
  - **WCP Policy Enforcement** (#1021): Connect WCP to dynamic policy engine
    - New `WCPPolicyAdapter` bridges workflow_control to orchestrator policy engine
    - `policies_evaluated` and `policies_matched` fields in `StepGateResponse`
    - Detailed policy match information (policy_id, policy_name, action, reason)
    - Support for allow/block/require_approval decisions based on policy evaluation

### Tests

- Added unit tests for MAP policy enforcement (blocked/allowed scenarios)
- Added unit tests for WCP policy adapter (allow/block/require_approval/nil engine)
- Added unit tests for WCP policy info in response (4 new test cases)

### Documentation

- Updated `docs/api/orchestrator-api.yaml` with policy info fields in PlanResponse and StepGateResponse
- Added `PolicyMatch` schema for detailed policy evaluation results

---

## [3.4.0] - 2026-01-17

### Added

- **Workflow Control Plane V1**: Governance gates for external orchestrators (LangChain, LangGraph, CrewAI)
  - "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
  - Register workflows from external orchestrators with `POST /api/v1/workflows`
  - Step gate checks with allow/block/require_approval decisions
  - Policy evaluation at step transitions with new `workflow` scope
  - Workflow lifecycle tracking (in_progress/completed/aborted/failed)
  - New database tables: `workflows`, `workflow_steps`
  - SDK support: Go, TypeScript (Python and Java in standalone repos)
  - Examples: HTTP, Go, Python, TypeScript, Java + LangGraph adapter

- **Grafana Dashboard**: Security & Compliance section with PII detection, provider distribution, and policy metrics panels

### Fixed

- Improved enterprise license validation consistency

### Documentation

- New guide: `docs/guides/workflow-control-plane.md` - Workflow Control Plane user guide
- Updated API spec: `docs/api/orchestrator-api.yaml` - Workflow endpoints

---

## [3.3.0] - 2026-01-16

### Added

- **MCP Connector Audit Logging** (#1006): Full audit trail for all MCP connector queries and commands
  - New `mcp_query_audits` table captures all MCP operations with policy evaluation results
  - REQUEST phase logging: SQLi detection, PII blocking, matched policies
  - RESPONSE phase logging: PII redaction, redacted field paths (JSONPath format)
  - EXFILTRATION logging: Row counts, volume limit violations
  - Compliance mode (sync) for violations, performance mode (async) for success
  - Statement privacy: SHA256 hash stored instead of raw queries
  - `audit_id` field correlates with SDK `PolicyInfo` for traceability

- **MCP Audit Examples**: Comprehensive examples for all 4 SDKs + HTTP API
  - `examples/mcp-audit/http/` - HTTP API examples (curl/bash)
  - `examples/mcp-audit/go/` - Go SDK example
  - `examples/mcp-audit/python/` - Python SDK example
  - `examples/mcp-audit/typescript/` - TypeScript SDK example
  - `examples/mcp-audit/java/` - Java SDK example

### Documentation

- New guide: `docs/guides/audit-logging.md` - Comprehensive audit logging architecture guide
- New guide: `docs/guides/mcp-audit-logging.md` - MCP audit logging configuration and usage
- Updated API docs: `docs/api/agent-api.yaml` - Added audit logging details to MCP endpoints

---

## [3.2.0] - 2026-01-14

### Added

- **MCP Exfiltration Detection** (#966): Row and data volume limits for MCP connector queries
  - Configurable row count limits (default: 10,000 per query)
  - Configurable data volume limits (default: 10MB per response)
  - Returns 403 with detailed limit information when exceeded
  - `ExfiltrationCheck` field in `PolicyInfo` response

- **MCP Dynamic Policy Evaluation** (#968): Real-time policy evaluation via Orchestrator
  - Pre-query policy evaluation for rate limits, budgets, time/role access
  - Graceful degradation when Orchestrator is unavailable
  - `DynamicPolicyInfo` field in `PolicyInfo` response

### Fixed

- Removed unused `MCP_DYNAMIC_POLICIES_ENDPOINT` environment variable (#1003)

### Tests

- Added integration tests for MCP exfiltration and dynamic policy features (#1002)

### Documentation

- Updated community/enterprise feature matrix with MCP policy features (#1000)

---

## [3.1.0] - 2026-01-09

### Added

- **MCP Tiered Policy Enforcement** (#963, #975): Phase-aware policy enforcement for MCP connector requests
  - REQUEST phase: SQLi pattern blocking (DROP TABLE, UNION SELECT, OR 1=1, DELETE, TRUNCATE)
  - REQUEST phase: Critical PII blocking (SSN, Credit Card, India PAN, Aadhaar)
  - RESPONSE phase: PII redaction in connector data (SSN, Credit Card masked)
  - PolicyInfo metadata in all MCP responses (`policies_evaluated`, `redactions_applied`, `processing_time_ms`)
  - Non-critical PII (Email, Phone) allowed through with logging

- **MCP PII Redaction Examples**: Comprehensive examples for all 4 SDKs + HTTP API
  - `examples/mcp-policies/pii-redaction/go/` - Go SDK example
  - `examples/mcp-policies/pii-redaction/python/` - Python SDK example
  - `examples/mcp-policies/pii-redaction/typescript/` - TypeScript SDK example
  - `examples/mcp-policies/pii-redaction/java/` - Java SDK example
  - `examples/mcp-policies/pii-redaction/http/` - HTTP API examples (curl)

### Enterprise

- **Healthcare PHI Patterns**: Enterprise example for HIPAA-compliant PHI detection
  - Medical Record Number (MRN) detection
  - DEA Number detection
  - NPI (National Provider Identifier) detection
  - Medicare Beneficiary Identifier (MBI) detection
  - ICD-10 code detection

### Fixed

- **Healthcare example**: Fixed policy verification to use `GetStaticPolicy` instead of `ListStaticPolicies`

---

## [3.1.1] - 2026-01-09

### Fixed

- **MAP GetPlanStatus API**: Fixed response fields to match SDK expectations
  - Changed `step_count` to `total_steps` in API response
  - Added `completed_steps` field (0 when pending, equals total_steps when completed)
  - SDK methods `GetPlanStatus()` / `get_plan_status()` now correctly receive step tracking info

---

## [3.0.2] - 2026-01-08

### Fixed

- **Agent proxy routes**: Fixed missing proxy routes for `/api/v1/pricing`, `/api/v1/plan`, and `/api/v1/audit` endpoints. SDK methods like `getPricing()`, `generatePlan()`, `executePlan()`, and `searchAuditLogs()` now work correctly through the Agent single entry point (ADR-024). Previously these returned 404 errors.

### Changed

- **GoReleaser upgraded to v2**: Release workflow now uses GoReleaser v2 configuration format for better compatibility.

### Enterprise

- **OAuth2 Basic auth support**: Agent now accepts `Authorization: Basic base64(clientId:clientSecret)` for authentication (ADR-027), in addition to existing `X-License-Key` header.
- **Code governance: ClosePR endpoint**: Added endpoint for closing PRs without merging, useful for cleaning up test/demo PRs.

---

## [3.0.1] - 2026-01-07

### Fixed

- **Multi-Agent Planning (MAP) Two-Step Execution**: Fixed race condition where plan execution started before DB commit
  - `GeneratePlan` now stores workflow plan in database with 1-hour TTL before returning
  - `ExecutePlan` retrieves stored plan by `plan_id` and executes workflow
  - New `migrations/core/037_plans.sql` - Plans table for deferred execution
  - New `migrations/core/038_plans_composite_index.sql` - Composite index for cross-tenant queries
  - New `platform/orchestrator/planning/` package (service, repository, types)
  - Agent routes `execute-plan` requests to `/api/v1/plan/execute`

- **Agent Environment Variable Support for ECS/K8s**: Fixed orchestrator URL detection in containerized environments
  - Agent now checks `ORCHESTRATOR_URL` env var first (required for ECS, Kubernetes)
  - Priority: env var → Docker detection → localhost fallback
  - Increased MAP timeout to 60s

- **Support Demo Fixes**: Fixed broken support-demo in community repo
  - Removed vendor dependency causing Docker build failures
  - Fixed network naming (`axonflow_axonflow-network` requires `COMPOSE_PROJECT_NAME=axonflow`)
  - Removed direct orchestrator calls (all requests go through Agent)
  - Fixed role/region provider display for EU users

- **Dynamic Policy API Path**: Fixed incorrect API path in examples
  - Changed `/api/v1/policies/dynamic` → `/api/v1/dynamic-policies`

- **Dynamic Policy Payload Format**: Fixed condition format in examples
  - Changed `conditions: "{}"` → `conditions: "[]"` (array, not object)

### Added

- **Portal Proxy Routes (Enterprise)**: Agent now proxies `/api/v1/auth/*` for portal authentication

---

## [3.0.0] - 2026-01-05

### Breaking Changes

- **Single Entry Point Architecture (ADR-024)**: All API routes now go through the Agent (port 8080)
  - Agent proxies `/api/v1/dynamic-policies/*`, `/api/v1/budgets/*`, `/api/v1/usage/*`, `/api/v1/executions/*` to Orchestrator
  - Agent proxies `/portal/*` routes to Customer Portal
  - SDKs now use single `endpoint` parameter (default: `http://localhost:8080`)
  - **Deprecated**: `agent_url` and `orchestrator_url` SDK parameters (use `endpoint` instead)
  - **Deprecated**: Direct Orchestrator access on port 8081 (still works but not recommended)

- **Detection Defaults Changed (ADR-025)**: More nuanced default actions based on detection confidence
  - PII detection: `block` → `redact` (non-blocking, better UX)
  - High risk score (>0.8): `block` → `warn` (composite score needs tuning)
  - SQL injection: remains `block` (high confidence attacks)
  - Dangerous queries (DROP/TRUNCATE): remains `block` (destructive operations)

- **Environment Variable Changes**:
  - **New**: `SQLI_ACTION` (values: `block`, `warn`, `log`) - replaces `SQLI_BLOCK_MODE`
  - **New**: `PII_ACTION` (values: `block`, `warn`, `redact`, `log`) - replaces `PII_BLOCK_CRITICAL`
  - **New**: `SENSITIVE_DATA_ACTION` (values: `block`, `warn`, `log`) - credentials/secrets detection
  - **New**: `HIGH_RISK_ACTION` (values: `block`, `warn`, `log`) - high risk score threshold
  - **New**: `DANGEROUS_QUERY_ACTION` (values: `block`, `warn`, `log`) - DROP/TRUNCATE detection
  - **Deprecated**: `SQLI_BLOCK_MODE` (use `SQLI_ACTION` instead)
  - **Deprecated**: `PII_BLOCK_CRITICAL` (use `PII_ACTION` instead)

### Added

- **Sensitive Data Patterns in Database**: Credential and secret detection patterns now stored in `static_policies` table
  - Password, API key, token, secret, credentials, connection string patterns
  - Context exclusions for SQL keywords (PRIMARY KEY, FOREIGN KEY no longer false positives)
  - Per-tenant customization via policy overrides (Enterprise)

- **Environment Variable Precedence**: Clear hierarchy for detection configuration
  1. Per-tenant policy override (API) - highest priority
  2. Environment variable (docker-compose)
  3. Per-policy DB default (migration seed) - lowest priority

- **PII Redaction Support in SDKs**: New `requiresRedaction` field in `PolicyApprovalResult`
  - Returns `true` when PII was detected with `redact` action
  - Callers should process response for redaction when this flag is set
  - Available in all SDKs: `isRequiresRedaction()` (Java), `requires_redaction` (Python), `RequiresRedaction` (Go), `requiresRedaction` (TypeScript)

- **Strict Provider Enforcement for Dynamic Policies** (Issue #883): Compliance-aware LLM routing
  - Policies can specify `allowed_providers` to restrict which LLM providers handle requests
  - Requests **fail** (instead of fallback) if no compliant provider is available
  - Multiple policies use **intersection logic** (least privilege - most restrictive wins)
  - Enables GDPR, HIPAA, RBI compliance scenarios (e.g., EU data stays on-premise)
  - Example: `{"allowed_providers": ["ollama"]}` ensures only local model handles sensitive data

### Fixed

- **Dynamic policy condition evaluation**: `DatabaseDynamicPolicyEngine` now correctly evaluates conditions before applying actions
  - Previously, all policy actions were applied regardless of whether conditions matched
  - Now supports operators: `equals`, `not_equals`, `contains`, `not_contains`, `contains_any`, `regex`, `greater_than`, `less_than`, `in`, `not_in`

- **Tenant extraction bug**: Fixed `Client.ID` → `Client.TenantID` in policy evaluation

### Changed

- **SDK Method Signatures**: All SDKs updated for single endpoint
  - Go: `axonflow.NewClient(axonflow.AxonFlowConfig{Endpoint: "http://localhost:8080"})`
  - Python: `AxonFlow(endpoint="http://localhost:8080")`
  - TypeScript: `new AxonFlow({ endpoint: "http://localhost:8080" })`
  - Java: `AxonFlow.create(AxonFlowConfig.builder().endpoint("http://localhost:8080").build())`

### Migration Guide

**SDK Migration:**
```python
# Before (v2.x)
client = AxonFlow(
    agent_url="http://localhost:8080",
    orchestrator_url="http://localhost:8081"
)

# After (v3.0)
client = AxonFlow(endpoint="http://localhost:8080")
```

**Environment Variable Migration:**
```yaml
# Before (v2.x)
SQLI_BLOCK_MODE: "block"
PII_BLOCK_CRITICAL: "true"

# After (v3.0)
SQLI_ACTION: "block"
PII_ACTION: "redact"
SENSITIVE_DATA_ACTION: "warn"
HIGH_RISK_ACTION: "warn"
```

---

## [2.6.0] - 2026-01-04

### Added

- **Decision & Execution Replay API**: Debug and audit workflow executions with full state capture and policy decisions
  - `GET /api/v1/executions` - List executions with filtering (status, time range, agent/workflow)
  - `GET /api/v1/executions/{id}` - Get execution with all step snapshots
  - `GET /api/v1/executions/{id}/steps` - Get individual step snapshots
  - `GET /api/v1/executions/{id}/timeline` - Timeline view for visualization
  - `GET /api/v1/executions/{id}/export` - Export for compliance and archival
  - `DELETE /api/v1/executions/{id}` - Delete execution records
  - SDK examples for Go, Python, TypeScript, Java

- **Cost Controls Phase 1**: Budget management and LLM usage tracking
  - Budget scopes: Organization, Team, Agent, Workflow, User
  - Budget periods: Daily, Weekly, Monthly, Quarterly, Yearly
  - Enforcement actions: Warn, Block, Downgrade on exceed
  - Configurable alert thresholds (default 50%, 80%, 100%)
  - Usage aggregation: Hourly, Daily, Weekly, Monthly
  - Provider pricing for OpenAI, Anthropic, Azure, Gemini, Bedrock, Ollama
  - SDK examples for Go, Python, TypeScript, Java

### Fixed

- **Replay Data Race**: Fixed race condition in background summary update when multiple goroutines access execution state

### Documentation

- **ADR-022**: SDK method inclusion criteria for feature parity decisions
- **SDK Feature Coverage**: Cross-SDK method availability matrix

---

## [2.5.0] - 2026-01-02

### Added

- **Azure OpenAI Provider** (Community): Native Azure OpenAI Service integration
  - Supports both Azure AI Foundry (`cognitiveservices.azure.com`) and Classic (`openai.azure.com`) endpoints
  - Automatic authentication detection (Bearer token vs api-key header)
  - Streaming support via `GenerateContentStream`
  - Health checks and provider status endpoints
  - Environment variables: `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT_NAME`, `AZURE_OPENAI_API_VERSION`

- **Azure OpenAI Examples**: Complete example suite
  - Hello World (Go, Python, TypeScript, Java, HTTP)
  - PII Detection (Python)
  - SQL Injection Scanning (TypeScript)
  - Proxy Mode (Go)

- **README Philosophy Section**: Added positioning section explaining AxonFlow's "secure-by-default, configurable enforcement" approach for LLM discoverability

### Changed

- **Docker Compose UX**: Reorganized environment variables for better developer experience
  - **CORE CONFIGURATION**: 10 essential variables (LLM API keys, Azure config, ports, deployment mode)
  - **ADVANCED CONFIGURATION**: Defaults work for most users (database, internal services, routing)
  - Added explicit security configuration toggles (`SQLI_SCANNER_MODE`, `SQLI_BLOCK_MODE`)

### Documentation

- Added Azure OpenAI to Supported LLM Providers in README
- Provider documentation at `docs/llm/azure-openai.md`
- Updated Community vs Enterprise feature matrix

---

## [2.4.0] - 2025-12-31

### Changed

- **DEPLOYMENT_MODE Unification**: Single env var for auth (`community` = no auth, `enterprise` = license required)
  - Replaces `SELF_HOSTED_MODE` with clearer naming
  - New `isCommunityMode()` helper for consistent mode checks

### Added

- **MCP Connector Examples**: Python, TypeScript, Java implementations
- **Workflow Examples**: 6 patterns (sequential, parallel, conditional, fallbacks, pipelines, approvals)

### Fixed

- Shell script audit endpoint URL corrected
- Unit tests for enterprise mode validation

---

## [2.3.0] - 2025-12-30

### Changed

- **LLM Router Consolidation**: Completed migration to interface-based router architecture
  - Removed legacy `LLMRouter` concrete implementation (~1,700 lines)
  - All routing now through `LLMRouterInterface` abstraction introduced in v2.2.0
  - Cleaner codebase with single routing implementation path

- **Docker Compose Architecture**: Simplified deployment configuration
  - `docker-compose.yml` now serves as Community base configuration
  - Enterprise features available via overlay pattern

- **Default Anthropic Model**: Updated to `claude-sonnet-4-20250514` (Claude 4)

### Added

- **LLM Provider E2E Tests**: Comprehensive end-to-end test suite
  - Coverage for OpenAI, Anthropic, Google Gemini, and AWS Bedrock
  - Multi-language test implementations (Go, Python, TypeScript, Java)

### Removed

- `llm_router.go` - Superseded by `UnifiedRouterWrapper`
- `llm_routing_strategy.go` - Consolidated into unified router
- Legacy router test files

---

## [2.2.0] - 2025-12-29

### Added

- **LLM Router Interface Abstraction**: Components now depend on standard interface rather than concrete implementations
  - `LLMRouterInterface` - Standard interface for router abstraction
  - `UnifiedRouterWrapper` - Adapter enabling UnifiedRouter as drop-in LLMRouter replacement
  - Type conversion utilities between legacy and new router types

- **LLM Provider Routing Examples**: New HTTP/curl examples for direct API access
  - Shell script examples for all supported providers (OpenAI, Anthropic, Ollama, Gemini)
  - Gateway mode pre-check and audit examples
  - Java SDK example for provider routing

### Changed

- Orchestrator now uses interface type for LLM router configuration
- Improved test coverage for audit logging and routing strategies

---

## [2.1.0] - 2025-12-28

### Added

- **Human-in-the-Loop (HITL)**: New `require_approval` policy action for human oversight
  - Enterprise: Pauses execution, creates approval request in HITL queue
  - Community: Auto-approves (upgrade path to Enterprise)
  - EU AI Act Article 14 and SEBI AI/ML compliance support

- **Code Governance**: Automatic detection and audit of LLM-generated code
  - Identifies language, code type, potential secrets, unsafe patterns
  - Detects eval, exec, shell injection risks
  - Metadata logged for compliance

- **LLM Provider Routing**: Runtime control over provider selection
  - Weighted routing across providers
  - Health-based automatic failover
  - Per-request provider preferences

### Fixed

- Anthropic provider now respects `ANTHROPIC_MODEL` environment variable
- Support demo build and runtime fixes
- HITL example tier filter fixes

---

## [2.0.0] - 2025-12-25

**Unified Policy Architecture - Major Release**

This major release introduces enterprise-grade policy management to AxonFlow with a new three-tier hierarchy for granular control at every level.

### ⚠️ Breaking Changes

**Category Enum Values Changed in Responses**

| Old Category | New Category |
|--------------|--------------|
| `sql_injection` | `security-sqli` |
| `admin_access` | `security-admin` |
| `pii_detection` | `pii-global`, `pii-us`, `pii-eu`, `pii-india` |
| `dangerous_queries` | `security-sqli` |

**Migration Notes:**
- Old category values are still accepted in **request** parameters (backwards compatible)
- Update your code if you're parsing category values from **responses**
- SDKs don't require updates - they pass through category values as strings

### Added

- **Three-Tier Policy Hierarchy**: New policy architecture with System → Organization → Tenant inheritance
  - **System Tier**: 63 immutable security policies (53 static + 10 dynamic)
  - **Organization Tier**: Company-wide policies (Enterprise only)
  - **Tenant Tier**: Team-specific policies with full CRUD
  - Tier-aware policy resolution with caching

- **63 System Policies**: Comprehensive security and compliance coverage out-of-the-box
  - **Security - SQL Injection** (37): UNION, boolean-based, time-based, stacked queries, etc.
  - **Security - Admin Access** (4): Users table, audit log, config table access
  - **PII - Global** (7): Credit card, email, phone, IP, passport, DOB
  - **PII - US** (2): SSN, bank accounts
  - **PII - EU** (1): IBAN
  - **PII - India** (2): PAN, Aadhaar
  - **Dynamic** (10): Risk, compliance (HIPAA, GDPR), cost, access control

- **Policy CRUD APIs**: Full create, read, update, delete for organization and tenant policies
  - `GET /api/v1/static-policies` - List with tier/category filtering
  - `POST /api/v1/static-policies` - Create custom policy
  - `PUT /api/v1/static-policies/{id}` - Update policy
  - `DELETE /api/v1/static-policies/{id}` - Delete policy
  - `GET /api/v1/effective-policies` - Get merged hierarchy for tenant

- **Policy Overrides** (Enterprise): Customize system policy behavior
  - Disable system policies for organization
  - Change action (only to more restrictive)
  - Expiration dates for temporary overrides
  - Audit trail with reason requirement

- **SDK Policy Methods**: All 4 SDKs support policy management
  - TypeScript: `listStaticPolicies()`, `createStaticPolicy()`, etc.
  - Python: `list_static_policies()`, `create_static_policy()`, etc.
  - Go: `ListStaticPolicies()`, `CreateStaticPolicy()`, etc.
  - Java: `listStaticPolicies()`, `createStaticPolicy()`, etc.

- **Customer Portal UI**: Visual policy management for Enterprise customers
  - Unified policy dashboard
  - Override management
  - Policy testing interface

### Changed

- **Policy Categories**: New category naming convention
  - `security-sqli`, `security-admin` for security policies
  - `pii-global`, `pii-us`, `pii-eu`, `pii-india` for PII detection
  - `dynamic-risk`, `dynamic-compliance`, `dynamic-cost`, `dynamic-access` for context-aware policies

- **Performance**: Static policy evaluation maintains < 5ms p99 latency
  - Tier-aware caching with configurable TTL
  - Optimized regex pattern compilation

### Fixed

- **PII Detection Priority**: Credit card detection now correctly takes priority over phone number detection
  - Root cause: Policies were sorted by severity string (alphabetically "medium" > "critical")
  - Fix: Changed to `ORDER BY priority DESC` using numeric priority field

- **Tenant Policy Isolation**: Tenant-specific policies now only apply to their respective tenants
  - Root cause: `LoadPoliciesFromDB()` was loading ALL policies without tier filtering
  - Fix: Added two-phase evaluation - system policies via fast path, tenant policies via tier-aware engine

### Enterprise Features

- Organization-tier policy management
- System policy override capabilities
- Policy version history
- Customer Portal policy UI

---

## [1.1.3] - 2025-12-21

### Fixed

- **Usage Recording:** Fixed postgres errors in Community mode when `usage_events` table doesn't exist ([#96](https://github.com/getaxonflow/axonflow/issues/96))
  - Usage metering is now properly separated as an Enterprise-only feature
  - Community builds have zero-overhead no-op implementation using build tags
  - Thanks to [@gzak](https://github.com/gzak) for identifying and contributing the initial fix ([#97](https://github.com/getaxonflow/axonflow/pull/97))

- **OpenAI Provider:** Fixed "you must provide a model parameter" error when `OPENAI_MODEL` not explicitly set ([#100](https://github.com/getaxonflow/axonflow/pull/100))
  - `OpenAIProvider` now reads `OPENAI_MODEL` environment variable with `gpt-4o` fallback
  - Consistent with other providers (Anthropic, Gemini, Ollama)

### Changed

- **Code Cleanup:** Removed 450+ lines of dead code
  - Removed unused `AnthropicProvider` struct (superseded by `EnhancedAnthropicProvider`)
  - Usage package refactored with build tags for clean Community/Enterprise separation

---

## [1.1.2] - 2025-12-20

### Fixed

- **LLM Router:** Use provider's configured model instead of hardcoded defaults ([#94](https://github.com/getaxonflow/axonflow/pull/94))
  - Previously, `selectModel()` returned hardcoded model names (e.g., `gpt-3.5-turbo`, `claude-3-5-sonnet`) which caused failures when the API key didn't have access to those specific models
  - Now respects `OPENAI_MODEL`, `ANTHROPIC_MODEL`, and other provider-specific environment variables
  - Model specified in request context takes highest priority

### Changed

- Added `OPENAI_MODEL` and `ANTHROPIC_MODEL` environment variable passthrough in docker-compose.yml

---

## [1.1.1] - 2025-12-20

### Fixed

- **Self-hosted mode:** Fixed authentication bypass not working when `userToken` is empty or omitted ([#89](https://github.com/getaxonflow/axonflow/pull/89))
  - Previously, self-hosted mode required a dummy `userToken`/`apiKey` even though it should accept requests without credentials
  - Now correctly bypasses authentication when `SELF_HOSTED_MODE=true` and `SELF_HOSTED_MODE_ACKNOWLEDGED=I_UNDERSTAND_NO_AUTH` are set
  - Thanks to [@gzak](https://github.com/gzak) for the contribution

---

## [1.1.0] - 2025-12-19

**SDK Feature Parity & Terminology Update**

### Added

- **Google Gemini LLM Provider**: Native Gemini integration now available in Community edition
  - Supports Gemini Pro and Gemini Pro Vision models
  - Automatic failover and routing alongside OpenAI, Anthropic, Ollama

- **SDK Feature Parity**: All four SDKs now have complete feature parity
  - **TypeScript SDK** (v1.4.0): 85.75% test coverage
  - **Python SDK** (v0.3.0): 71.39% test coverage
  - **Java SDK** (v1.1.0): 81.9% test coverage
  - **Go SDK** (v1.5.0): 82.8% test coverage

- **LLM Interceptors** (all SDKs): Wrapper-based governance for LLM providers
  - OpenAI, Anthropic, Gemini, Ollama, AWS Bedrock interceptors
  - Gateway Mode: Two-phase policy checking with `getPolicyApprovedContext()` and `auditLLMCall()`
  - Proxy Mode: Single-call governance with `executeQuery()`

### Changed

- **Terminology**: Renamed "OSS" to "Community" across the entire codebase
  - Environment variable: `AXONFLOW_MODE=community` (previously `oss`)
  - API responses: `"mode": "community"` (previously `"oss"`)
  - Documentation updated throughout

### Breaking Changes

- **`AXONFLOW_MODE` Environment Variable**: If you were using `AXONFLOW_MODE=oss`, update to `AXONFLOW_MODE=community`
- **API Response**: The `mode` field in API responses now returns `"community"` instead of `"oss"`

### Migration Notes

To upgrade from 1.0.x:

1. Update environment variables:
   ```bash
   # Before
   AXONFLOW_MODE=oss

   # After
   AXONFLOW_MODE=community
   ```

2. Update any code that checks for `mode === "oss"` to check for `mode === "community"`

3. Update SDKs to latest versions for LLM Interceptors support

---

## [1.0.1] - 2025-12-16

### Added

- **Internal Service Authentication**: Shared secret authentication for secure agent↔orchestrator communication via `AXONFLOW_INTERNAL_SERVICE_SECRET`

### Changed

- **PII Detection**: Made critical PII blocking configurable per-policy (Aadhaar, PAN patterns)

---

## [1.0.0] - 2025-12-14

**Community Launch Release**

This is the first public release of AxonFlow, a self-hosted governance and orchestration platform for production AI systems.

### Core Platform

- **Policy Enforcement Agent**: Real-time policy enforcement with single-digit millisecond overhead
  - Static policy engine with configurable rules
  - PII detection (SSN, credit cards, PAN, Aadhaar)
  - SQL injection blocking in user inputs
  - Rate limiting and request validation

- **Multi-Agent Planning (MAP)**: Declarative agent orchestration
  - YAML-based agent configuration
  - Natural language to workflow conversion
  - Sequential and parallel execution modes
  - Error handling with fallbacks

- **MCP Connectors**: Model Context Protocol integration
  - PostgreSQL, MySQL, MongoDB, Redis, HTTP connectors (Community)
  - Salesforce, Slack, Snowflake, ServiceNow (Enterprise)

- **Gateway Mode**: Wrap existing LLM calls with governance
  - Pre-check → your LLM call → audit trail
  - Incremental adoption path for existing codebases

- **Multi-Model Routing**: Intelligent LLM provider management
  - OpenAI, Anthropic, Ollama (Community)
  - AWS Bedrock, Google Gemini (Enterprise)
  - Automatic failover and cost-based routing

### Security & Compliance

- **SQL Injection Response Scanning**: Detect SQLi payloads in MCP connector responses
  - 37 regex patterns across 8 attack categories
  - Monitoring mode by default (detect and log, configurable blocking)
  - Per-connector configuration overrides
  - Audit trail integration for compliance
  - Basic scanner (Community), Advanced ML-based scanner (Enterprise)

- **EU AI Act Compliance** (Articles 12, 13, 14, 15, 43):
  - Decision chain tracing with full audit trails
  - Transparency headers (X-AI-Decision-ID, X-AI-Model-Provider, etc.)
  - Human-in-the-Loop (HITL) workflows (Enterprise)
  - Conformity assessment endpoints (Enterprise)
  - Emergency circuit breaker (Enterprise)

- **RBI FREE-AI Framework**: Data integrity monitoring for financial AI (India)

- **SEBI AI/ML Guidelines**: Security audit trail for investment platforms (India)

### Infrastructure

- **Docker Compose Deployment**: Local development in under 5 minutes
- **Row-Level Security**: Database-level multi-tenant isolation
- **Production Migrations**: Idempotent, versioned database migrations
- **Test Coverage**: 70%+ coverage across core packages

### Documentation

- Getting Started Guide
- LLM Provider Configuration
- MCP Connector Development Guide
- Security Best Practices
- EU AI Act Compliance Guide

---

## Links

- [GitHub Repository](https://github.com/getaxonflow/axonflow)
- [Documentation](https://docs.getaxonflow.com)
- [AWS Marketplace](https://aws.amazon.com/marketplace)
- [Security Policy](./SECURITY.md)
- [Contributing Guide](./CONTRIBUTING.md)

---

**For a complete list of changes, see the [commit history](https://github.com/getaxonflow/axonflow/commits/main).**
