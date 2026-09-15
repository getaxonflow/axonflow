# Policy Actions and Detection-Posture Overrides
> Deprecated in v11.0.0: the legacy policy write routes answer 409 LEGACY_POLICY_WRITE_FROZEN on an application-role deployment; use the typed policy routes instead. This material is rewritten or deleted in v11.1.0.


**Status:** documents shipped behavior as of v11 (#3961). This page answers one operator question precisely: *when a policy row stores an `action`, what actually decides the runtime outcome on each enforcement plane?* Before v11 the answer was a deployment-wide environment "posture lever"; that lever is gone (see [Removed in v11](#removed-in-v11-environment-variables-and-profiles)).

## TL;DR

**The action stored on the matched policy decides.** For the detection categories (`pii-*`, `security-sqli`, `security-dangerous`) exactly one thing can replace it: the organization's **recorded detection-posture override**, a row in `detection_action_overrides`.

| Override category | Policy categories it reaches |
|---|---|
| `pii` | every `pii-*` category |
| `sqli` | `security-sqli` |
| `dangerous_command` | `security-dangerous` |
| `dangerous_query` | none: it maps onto no policy category |
| `obligation_fallback` | not a policy category: the action taken when a plane cannot fulfil a redact obligation (`block` or `log` only) |

Override actions are `block`, `redact`, `warn` and `log`. An override applies to the whole category for that organization.

`sensitive-data` has **no override category**, so its stored action always decides. The compliance categories (`compliance-*`, `fincrime`) and `admin-access` have none either.

The override is written through the customer portal API (Enterprise). It uses session auth and requires the `sso:configure` permission:

```
GET    /api/v1/detection-posture
PUT    /api/v1/detection-posture/{category}     body: {"action":"block"}
DELETE /api/v1/detection-posture/{category}
```

Every write is audited to `admin_audit_log` and records `updated_by`. Agents pick up a change within the override cache TTL, `AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS` (default 60, minimum 5).

The other supported way to change an outcome is to **change the policy's action**: create a system-policy override (`POST /api/v1/system-policies/{id}/override`, Enterprise). Editing the tenant policy was the other way before v11; in v11 the legacy policy tables are read-only to the application roles (`migrations/core/172`), so that edit answers `409 LEGACY_POLICY_WRITE_FROZEN`.

### Shipped stored actions

| Rows | `action_request` / `action_response` |
|---|---|
| every `sys_sqli_*` | `warn` / `warn` |
| `sys_pii_indonesia_ktp` | `block` / NULL (request phase only) |
| `sys_pii_singapore_nric` | `warn` / `redact` |
| `sys_pii_ssn`, `sys_pii_credit_card` | `warn` / `redact` |
| `sys_pii_passport`, `sys_pii_dob`, `sys_pii_email` | `log` / `redact` |
| `sys_sensitive_*` (migration `core/177`) | `warn` / `warn` |
| `security-dangerous` command rows | `block` / NULL |
| prompt-injection rows | `block` / `redact` |

**SQL injection warns out of the box.** Every shipped `sys_sqli_*` row stores `warn`, so a detection is recorded and the request proceeds, unless the organization records `sqli=block` or the policy's action is changed. Community SaaS (try.getaxonflow.com) warns until its provisioning writes an override (#4017).

**Code-backed detectors with no stored row.** `indonesia_pii_protection` (checksum-validated NIK/NPWP) and `rbi_pii_protection` (India PII) have no policy row to store an action. They block only under an organization `pii=block` override and emit a redact obligation only under `pii=redact`. With no override they detect and record, and the stored static policy rows decide.

### Removed in v11: environment variables and profiles

These environment variables no longer set any action: `PII_ACTION`, `SQLI_ACTION`, `DANGEROUS_COMMAND_ACTION`, `SENSITIVE_DATA_ACTION`, `MCP_PII_ACTION`, `MCP_SQLI_ACTION`, `MCP_DANGEROUS_QUERY_ACTION`, `MCP_DANGEROUS_COMMAND_ACTION`, `GATEWAY_PII_ACTION`, `GATEWAY_SQLI_ACTION`, `GATEWAY_DANGEROUS_QUERY_ACTION`, `GATEWAY_DANGEROUS_COMMAND_ACTION`, `SQLI_BLOCK_MODE`, `PII_BLOCK_CRITICAL`, `DANGEROUS_QUERY_ACTION`, `HIGH_RISK_ACTION`, `AXONFLOW_PROFILE` and `AXONFLOW_ENFORCE`. The `dev` / `default` / `strict` / `compliance` profile matrix no longer exists.

A deployment that still sets one keeps running with the stored actions. At boot the agent logs one line per variable that is set:

```
WARN [agent] detection posture env var ignored: <NAME>=<value> no longer sets an action (v11); the stored policy action decides - see release notes. ...
```

and increments `axonflow_ignored_posture_env_total{name="<NAME>"}` on `/prometheus`. Remove the variables, and replace any posture you relied on with an organization override or a policy edit. The design record is the 2026-09-10 amendment to ADR-065.

The non-action variables are unchanged: `MCP_STATIC_POLICIES_ENABLED`, `GATEWAY_STATIC_POLICIES_ENABLED`, `MCP_STATIC_POLICIES_SKIP_CATEGORIES`, `GATEWAY_STATIC_POLICIES_SKIP_CATEGORIES`, `MCP_STATIC_POLICIES_CONNECTORS` and `SQLI_SCANNER_MODE`. They set no action, but the enable and skip-category switches can still stop a control from being evaluated with nothing recorded; that is tracked in #4027.

## Which column is "the stored action"

`platform/shared/policy/loader.go` carries **two disjoint column sets**, and which one a surface reads determines which value it is talking about:

| Path | Columns read | Reads `action`? | Feeds |
|------|--------------|-----------------|-------|
| `PolicyLoader` (runtime evaluation: `initQueries`, `loadFromDatabase`, `LoadSystemPolicies`, `GetPolicyByID`) | `phase`, `action_request`, `action_response` | **No** | the shared engine on the decide, gateway and MCP planes |
| `ScanEffectivePolicyRows` / `effectivePolicyColumns` (the `GetEffective` admin/API path) | `sp.action` | **Yes**, and never the phase columns | `StaticPolicyRepository.GetEffective` and `/api/v1/static-policies/effective` (so the portal's Policies page); until #4253 also the proxy plane's Phase-2 tier engine |

So on every shared-engine plane the base `action` column is read by nothing: `GetActionForPhase` resolves the phase column, or falls back to a category+severity derivation when it is NULL, and unless an organization override replaces it that PHASE-resolved action stands. Until #4253 the base `action` column was read at runtime only by the proxy plane's Phase-2 tier engine. Since #4253 no runtime plane reads it: what that engine read on a shipped row survives only as the compiled `retired_tier_pass_action` arms on `proxy_request` (see the matrix below). Migration `core/124` exists because a row's base action and its phase action had drifted apart, which is exactly what two disjoint read paths over one table produce.

This also means "stored action" is ambiguous unless the column is named. `PolicyMatch.StoredAction`, the audit displacement advisory and the `axonflow_agent_policy_stored_action_displaced_total{stored=...}` label all mean the **phase** column. A surface showing `static_policies.action` is showing a different value and must say so.

## What you see when an override weakens a stored action

A matched policy whose stored action was resolved DOWNWARD by an organization override (for example stored `block` resolved to `redact` under `pii=redact`) is never silent (#3360):

- The decide plane's allow verdict carries an advisory reason naming the policy, both actions, and the override category that governed it (`policy <id> stores action=<stored> but resolved to action=<resolved>: the organization's <category> detection override governs <policy category> enforcement on this plane`), and the same reason is persisted on the audit row.
- The agent increments `axonflow_agent_policy_stored_action_displaced_total{category, stored, resolved}` on every plane that evaluates through the shared conversion, so operators can alert on a weakened stored action instead of discovering it in a demo.

Upward displacement (an override tightening a `warn` row to `block`) is the override doing its designed job and is not flagged. The override write itself is always on `admin_audit_log`.

## Per-plane outcome matrix (detection-category policies)

"Resolved action" means the stored phase action, or the organization's override where one is recorded for the category.

| Plane | block | require_approval | redact | warn / log | Org override applies? |
|---|---|---|---|---|---|
| decide (`POST /api/v1/decide`) | deny | needs_approval (Enterprise); allow + advisory (Community) | allow + `redact_pii` obligation | allow + advisory reason (PII categories) | Yes |
| gateway pre-check | approved=false | approved=false (Enterprise); allow (Community) | allow + `requires_redaction` (masking is the caller-side contract) | allow, logged; the policy id is listed in `policies` | Yes |
| MCP `tools/execute`, `resources/query` | HTTP 403 | allow, logged only | allow, logged only (request phase) | logged only | Yes |
| MCP `check-input` / `check_policy` | allowed=false | allowed=true | allowed + masked statement | allowed | Yes |
| OpenAI-compat (`/v1/chat/completions`) | HTTP 400 | allow | allow (no masking on this plane) | allow | Yes |
| Cowork / Claude Code OTEL storage | forced redact | forced redact | redact | forced redact | No (hard-pinned redact at the collector) |
| Orchestrator response phase | withhold | n/a | mask | nothing | Yes |
| Proxy (`/api/request`), one anchored pass since #4253 | deny (403) | refused: an approval challenge is a refusal here, no hold (#4254) | refused: this wire carries no obligation | allow | Yes |

Until v11.0.0 the proxy plane's Phase 2 tier engine read the raw row `action` and applied no override, so the same `pii-*` row could deny on `/api/request` while allowing (with a redact obligation) on `/api/v1/decide` in the same organization (#3380). #4253 deleted that pass: `/api/request` is one anchored pass and applies an organization's override as the other planes here do. What the retired pass read from a shipped row's stored `action` is kept in the compiled corpus as `retired_tier_pass_action` on `proxy_request` (a system row's stored block, and a template row's stored action where it outranks the phase resolution), and an organization's override displaces it as it displaces any resolved action.

## Worked example: sys_pii_indonesia_ktp

The seeded row (migration 116) stores `action_request='block'`.

- **No override:** `POST /api/v1/decide` with a query that matches the row's KTP pattern returns `verdict=deny`; the stored `block` decides. The code-backed `indonesia_pii_protection` detector detects and records but does not decide.
- **`pii=redact` override:** the same request returns `verdict=allow` with a `redact_pii` obligation, the policy id in `evaluated_policies`, and the displacement advisory: the stored `block` was resolved to `redact` by the organization's `pii` override.
- **`pii=block` override:** the request returns `verdict=deny`. The deny may attribute `indonesia_pii_protection` rather than the static row, because the override also arms the validator-backed Indonesia detector, which runs before the static engine and wins the early return. Both ids mean the Indonesia PII control denied.
- `POST /api/v1/request` (proxy plane) denies with 403 in every case, per the exception above.

If your compliance posture requires KTP/NIK to hard-deny (for example KYC requirements), do not record a `pii` override weaker than `block`; record `pii=block` if checksum-validated NIK/NPWP must also deny through `indonesia_pii_protection`.

## Authoring guidance

When creating or editing a policy in a detection category, the `action` you set is the runtime outcome on every plane except the ones marked "No" above, unless the organization records an override for that category. Changing an action is a policy write; changing an override is an audited detection-posture write, and it reaches every policy in the category. The proxy-plane divergence is tracked on #3380; the adjacent plane defects found by the same census are #3378 and #3379.
