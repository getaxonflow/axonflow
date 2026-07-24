# SDK-Platform Compatibility Matrix

This document maps platform versions to minimum SDK versions and the features each release introduced.

**Current (platform 9.12.0):** minimum SDK **8.0.0** (Go/Python/TypeScript/Java; Rust **0.7.0**), recommended SDK **9.0.0** (Rust **0.8.1**). These floors are what the platform `/health` endpoint advertises (`min_sdk_version` / `recommended_sdk_version`).

> **Note on version numbers:** SDK versions are deliberately decoupled from platform versions. The Go SDK's module path tracks its major: SDK 8.x is `github.com/getaxonflow/axonflow-sdk-go/v8`, SDK 9.x is `.../v9`. The Rust SDK is on an independent 0.x line (currently 0.8.1) and does not carry the 9.0.0 LangGraph/computer-use adapters.

## Version Compatibility

| Platform Version | Min SDK Version | Recommended SDK | Key Features Added |
|-----------------|----------------|-----------------|-------------------|
| v9.12.0 | v8.0.0 (Rust v0.7.0) | v9.0.0 (Rust v0.8.1) | Five-role RBAC enforced (`owner`/`admin`/`policy_admin`/`developer`/`viewer`; `member` removed), owner bootstrap + lifecycle + break-glass, policy CRUD RBAC-gated on every family, permission-driven PII visibility, JumpCloud SSO preset, SCIM deprovision revokes roles fail-closed, `tokens` column on audit-export CSV |
| v9.11.0 | v8.0.0 (Rust v0.7.0) | v9.0.0 (Rust v0.8.1) | Streaming prompt-DLP (ext_proc SSE legs), seam-capability-aware obligations + `obligation_fallback` posture, matched-PII policies never return a bare allow, Path B fleet-identity fixes (per-org fleet role seeding, SCIM org key), tool identity: `caller_name` + separate `tool` field on check-output. **SDK 9.0.0 majors are required for the de-concatenated `tool` wire field** (check-output floor: platform 9.11.0) |
| v9.10.0 | v8.0.0 (Rust v0.7.0) | v9.0.0 (Rust v0.8.1) | Per-user identity for fleets: `X-User-Token` (admin-minted HS256 + OIDC/JWKS "Path B"), role-scoped reads on audit/decisions/overrides/cost/replay. **Behavior change:** shared-credential callers with no per-user token read zero rows from governed read tools. Separate `tool` field accepted on check-input (floor: platform 9.10.0) |
| v9.9.0 | v8.0.0 (Rust v0.7.0) | v8.5.1 (Rust v0.8.1) | Trust-gated identity headers: `AXONFLOW_TRUST_IDENTITY_HEADERS` (default **off**) gates `X-User-Email`/`X-User-ID`/`X-Session-Id` attribution on all four governance planes (`identity_header_attribution` capability); session-override forgery closed on every override-apply ingress |
| v9.8.0 | v8.0.0 (Rust v0.7.0) | v8.5.1 (Rust v0.8.1) | agentgateway/Envoy PEP adapters (ExtMcp, ext_authz, ext_proc; adapters require platform ≥9.7.0), 41-column TIMESTAMPTZ retype migrations (plan a maintenance window on large `audit_logs`), API-reference reconciliation |
| v9.7.0 | v8.0.0 (Rust v0.7.0) | v8.5.1 (Rust v0.8.1) | Fail-closed hardening sweep (request plane, gateway, check-output `redaction_evaluated`), per-client version telemetry (`client_version_telemetry` capability), Rust SDK joins the compatibility maps (floor 0.7.0) |
| v9.5.0 – v9.6.1 | v8.0.0 | v8.5.x | OTLP `/v1/metrics` ingest (9.5.0); session-summary reporting API + Claude Code usage dashboard (9.6.0); audit-search `session_id` drill-down (9.6.1) |
| v9.2.0 – v9.4.0 | v8.0.0 | v8.5.x | Read-only MCP posture, tamper-evident audit signing, turnkey SIEM export (9.2.0); per-developer + per-session audit identity, audit read/report/export API, portal Log Explorer (9.3.0); capability-scoped detection (9.4.0) |
| v9.0.0 – v9.1.1 | v8.0.0 | v8.5.x | **Breaking:** canonical `policy_decision` vocabulary, DB-`CHECK`-enforced (`allow`→`allowed`, `deny`→`blocked`, `pending_approval`→`needs_approval`); `/decisions?decision=` rejects legacy filter values; compliance-export outcomes canonicalized (9.0.0). Audit coverage made permanent + sensitive-data lever enforced (9.1.0); container/CodeQL security patch (9.1.1) |
| v8.5.0 – v8.7.0 | v8.0.0 | v8.4.0–v8.5.x (Rust v0.6.0–0.7.0) | Decision Mode `context` propagation + Pasal 56(b) transfer basis + multi-arch images (8.5.0, SDK 8.4.0/Rust 0.6.0 train); request + response NIK/NPWP redaction on every plane, engine-fulfillable obligations (8.6.0); audit-trail consolidation (`decision_id`, `plane`, `correlation_id` on `audit_logs`) + per-org detection posture on every plane (8.7.0). SDK 8.5.0 / Rust 0.7.0 added the Decision Mode `decide → fulfill → forward` PEP contract |
| v8.2.0 – v8.4.0 | v8.0.0 | v8.2.0–v8.3.0 | Decision Mode PDP/PEP service (`POST /api/v1/decide`) + OTel decision tracer (8.2.0); `pii-indonesia` detection category, OJK/UU PDP compliance modules, OTel exporter configs — SDKs v8.3.0 / Rust v0.5.0 (8.3.0); OpenAI-compatible gateway endpoint (8.4.0) |
| v8.0.0 – v8.1.0 | v8.0.0 train (v7.x-era SDKs continue to work over HTTP) | v8.0.0 | **Breaking for direct SQL:** identity model separates `org_id` (customer org, RLS boundary), `client_id` (API credential), and deployment license identity; Row-Level Security enforced by default (FORCE RLS + non-owner `axonflow_app_role`); `X-Tenant-ID` accepted as deprecated alias; Go module path `/v8` (8.0.0). HITL outbound webhook callback + HTTP `Idempotency-Key` dedup (8.1.0) |
| v7.5.0 – v7.9.0 | v5.0.0 (Go/TS/Java), v6.0.0 (Python) | Go/TS v5.6.x, Py v6.6.x, Java v5.7.x | Per-category enforcement controls (7.6.0); Plugin Pro launches + structured upgrade envelope + Rust SDK announced (7.7.0/7.8.0); Decision History API + `policy_version` on every decision (7.9.0) |
| v7.3.0 – v7.4.5 | v5.0.0 (Go/TS/Java), v6.0.0 (Python) | Go/TS v5.6.0, Py v6.6.0, Java v5.7.0 | `retry_context` on every step-gate response + caller-supplied `idempotency_key` (7.3.0, ADR-045); HITL response parity across WCP/MAP + `/api/v1/plans/approvals/pending` (7.4.0, ADR-046) |
| v7.0.0 – v7.2.1 | v5.0.0 (Go/TS/Java), v6.0.0 (Python) | v5.x / v6.x | **Breaking:** default detection actions relaxed (PII default `redact`→`warn`); governance profiles `AXONFLOW_PROFILE` (`dev`/`default`/`strict`/`compliance`) + per-category `AXONFLOW_ENFORCE` (7.0.0); Community SaaS evaluation mode + self-registration (7.0.0); workflow checkpoints, idempotent step gates, governed overrides + explainability (7.1.0) |
| v6.1.0 | v5.0.0 (Go/TS/Java), v6.0.0 (Python) | v5.1.0 / v6.1.0 | Mistral LLM provider, Cursor/Codex integration, GovernedTool adapter (TS/Go/Java), checkToolInput/checkToolOutput aliases |
| v6.0.0 | v5.0.0 (Go/TS/Java), v6.0.0 (Python) | v5.1.0 / v6.1.0 | OAuth2 Basic auth required, legacy engine removed, agent single entry point, Go module v5 |
| v5.0.0 | v4.0.0 | v4.1.0 | Removed `total_steps` from create workflow, MCP operation default `"execute"`, Go module v4 |
| v4.8.0 | v3.8.0 | v3.8.0 | Version discovery, capability registry, User-Agent headers |
| v4.7.0 | v3.7.0 | v3.7.0 | MCP check-input/check-output endpoints, circuit breaker pipeline |
| v4.6.0 | v3.6.0 | v3.6.0 | Open-ended WCP workflows (optional total_steps) |
| v4.5.0 | v3.6.0 | v3.6.0 | WCP step-complete post-execution metrics |
| v4.4.0 | v3.5.0 | v3.5.0 | Media governance, cost controls |
| v4.3.0 | v3.4.0 | v3.4.0 | MAP, WCP, execution replay |
| v4.0.0 | v3.0.0 | v3.0.0 | Client credentials auth (OAuth2-style) |

Patch releases within a line (e.g. 9.2.1/9.2.2, 9.3.1, 8.5.1/8.5.2, 7.4.1–7.4.5) carry fixes only and keep their line's compatibility.

## Upgrade Guidance

- **Always upgrade the platform before or alongside SDK upgrades.** New SDK features may call endpoints that only exist in newer platform versions.
- The SDK 9.0.0 majors send the MCP server/tool identity as a separate `tool` wire field (no longer concatenated into `connector_type`). The platform accepts this on check-input from 9.10.0 and on check-output from 9.11.0; older platforms ignore the field.
- If you see a version mismatch warning in SDK logs, upgrade your platform to the recommended version.
- Use `healthCheckDetailed()` / `health_check_detailed()` to programmatically check what the platform supports before using new features.

## Backward Compatibility Guarantees

| Scenario | Behavior |
|----------|----------|
| **Old SDK + New Platform** | Safe. Old SDKs ignore unknown JSON fields. Exception: the v9.0.0 canonical-verdict cutover changes `policy_decision` values an integrator reads back — see the v8 → v9 migration guide. |
| **New SDK + Old Platform** | Safe. New fields (`capabilities`, `sdk_compatibility`, `tool`) will be absent or ignored. SDKs return empty/nil values. |
| **Old SDK + Old Platform** | No change in behavior. |

## Capability Discovery

Starting with platform v4.8.0, the `/health` endpoint returns a `capabilities` array listing all supported features, plus `min_sdk_version` / `recommended_sdk_version` maps. SDKs can use this for runtime feature detection:

```go
// Go
health, _ := client.HealthCheckDetailed()
if health.HasCapability("mcp_check_endpoints") {
    // Safe to use MCP check endpoints
}
```

```python
# Python
health = client.health_check_detailed()
if health.has_capability("mcp_check_endpoints"):
    # Safe to use MCP check endpoints
    ...
```

```typescript
// TypeScript
const health = await client.healthCheck();
if (AxonFlow.hasCapability(health, 'mcp_check_endpoints')) {
    // Safe to use MCP check endpoints
}
```

```java
// Java
HealthStatus health = client.healthCheck();
if (health.hasCapability("mcp_check_endpoints")) {
    // Safe to use MCP check endpoints
}
```

Capabilities added in recent releases include `client_version_telemetry` (9.7.0), `identity_header_attribution` (9.9.0), and `seam_capability_decisioning` (9.11.0).
