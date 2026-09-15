# Configuration Reference
> Deprecated in v11.0.0: the legacy policy write routes answer 409 LEGACY_POLICY_WRITE_FROZEN on an application-role deployment; use the typed policy routes instead. This material is rewritten or deleted in v11.1.0.


AxonFlow is designed with secure-by-default settings that are fully configurable. This document covers all environment variables for controlling security detection and policy enforcement.

## Security Detection Configuration (Issue #891)

**Changed in v11 (#3961): no environment variable sets a detection action.** A detection takes the action stored on the policy that matched it. The only thing that replaces a stored action is an organization's recorded detection-posture override. See [Policy Actions and Detection-Posture Overrides](governance/policy-action-authority.md) for the per-plane detail.

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `SQLI_SCANNER_MODE` | `off`, `basic`, `advanced` | `basic` | SQL injection scanning mode (selects the scanner; it sets no action) |
| `AXONFLOW_DETECTION_OVERRIDE_TTL_SECONDS` | seconds, `5` to `600` | `60` | How long an agent caches an organization's detection-posture overrides; an override change takes effect within this window |

### Action Types

| Action | Behavior |
|--------|----------|
| `block` | Reject request immediately |
| `redact` | Mask/redact detected content, allow request |
| `warn` | Log warning, allow request |
| `log` | Log for audit only, allow request |

### Changing an Action

There are two supported ways, and neither is an environment variable.

1. **Record an organization override** (Enterprise). The customer portal API writes the organization's row in `detection_action_overrides`. It uses session auth and requires the `sso:configure` permission; every write is audited to `admin_audit_log` and records `updated_by`.

   ```bash
   # List the organization's overrides
   curl -b "axonflow_session=$SESSION" http://localhost:8082/api/v1/detection-posture

   # Block SQL injection for this organization
   curl -b "axonflow_session=$SESSION" -X PUT -H 'Content-Type: application/json' \
     -d '{"action":"block"}' http://localhost:8082/api/v1/detection-posture/sqli

   # Remove the override; the stored policy action decides again
   curl -b "axonflow_session=$SESSION" -X DELETE http://localhost:8082/api/v1/detection-posture/sqli
   ```

   | Category | Reaches |
   |----------|---------|
   | `pii` | every `pii-*` policy category |
   | `sqli` | `security-sqli` |
   | `dangerous_command` | `security-dangerous` |
   | `dangerous_query` | no policy category |
   | `obligation_fallback` | the action when a plane cannot fulfil a redact obligation (`block` or `log` only) |

   Actions are `block`, `redact`, `warn` and `log`. `sensitive-data` has no override category, so its stored action always decides.

2. **Change the policy's action.** Create a system-policy override (`POST /api/v1/system-policies/{id}/override`, Enterprise). Editing the tenant policy was the other way before v11; in v11 the legacy policy tables are read-only to the application roles (`migrations/core/172`), so that edit answers `409 LEGACY_POLICY_WRITE_FROZEN`.

### Removed in v11: Detection Action Environment Variables

These variables no longer set any action: `PII_ACTION`, `SQLI_ACTION`, `DANGEROUS_COMMAND_ACTION`, `SENSITIVE_DATA_ACTION`, `MCP_PII_ACTION`, `MCP_SQLI_ACTION`, `MCP_DANGEROUS_QUERY_ACTION`, `MCP_DANGEROUS_COMMAND_ACTION`, `GATEWAY_PII_ACTION`, `GATEWAY_SQLI_ACTION`, `GATEWAY_DANGEROUS_QUERY_ACTION`, `GATEWAY_DANGEROUS_COMMAND_ACTION`, `SQLI_BLOCK_MODE`, `PII_BLOCK_CRITICAL`, `DANGEROUS_QUERY_ACTION`, `HIGH_RISK_ACTION`, `AXONFLOW_PROFILE` and `AXONFLOW_ENFORCE`. The `AXONFLOW_PROFILE` presets (`dev`, `default`, `strict`, `compliance`) and the `AXONFLOW_ENFORCE` category list are gone with them.

A deployment that still sets one keeps running with the stored actions. At boot the agent logs one line per variable that is set:

```
WARN [agent] detection posture env var ignored: <NAME>=<value> no longer sets an action (v11); the stored policy action decides - see release notes. ...
```

and increments `axonflow_ignored_posture_env_total{name="<NAME>"}` on `/prometheus`. Remove them from your environment and use one of the two ways under [Changing an Action](#changing-an-action) instead.

These non-action variables are unchanged: `MCP_STATIC_POLICIES_ENABLED`, `GATEWAY_STATIC_POLICIES_ENABLED`, `MCP_STATIC_POLICIES_SKIP_CATEGORIES`, `GATEWAY_STATIC_POLICIES_SKIP_CATEGORIES`, `MCP_STATIC_POLICIES_CONNECTORS` and `SQLI_SCANNER_MODE`.

### Shipped Stored Actions

| Detection | Stored action (request / response) | Notes |
|-----------|------------------------------------|-------|
| SQL injection (every `sys_sqli_*`) | `warn` / `warn` | **SQL injection warns out of the box.** Record `sqli=block` or change the policy action to block it |
| Dangerous commands (`security-dangerous` command rows) | `block` / none | |
| Prompt injection | `block` / `redact` | |
| PII: SSN, credit card (`sys_pii_ssn`, `sys_pii_credit_card`), Singapore NRIC | `warn` / `redact` | |
| PII: passport, date of birth, email | `log` / `redact` | |
| PII: Indonesia KTP (`sys_pii_indonesia_ktp`) | `block` / none | Request phase only |
| Sensitive data (`sys_sensitive_*`) | `warn` / `warn` | No override category; only a policy edit changes it |

The code-backed detectors that have no stored policy row (`indonesia_pii_protection` for checksum-validated NIK/NPWP, `rbi_pii_protection` for India PII) block only under an organization `pii=block` override and emit a redact obligation only under `pii=redact`. With no override they detect and record, and the stored static policy rows decide.

Community SaaS (try.getaxonflow.com) warns on SQL injection until its provisioning writes an override (#4017).

### Progressive Enforcement

A common adoption pattern:

1. **Day 1: Out-of-the-box** - Start with the shipped stored actions (SQL injection warns; PII warns or logs on requests and is redacted in responses)
2. **Week 1: Review** - Check audit logs for detection accuracy
3. **Week 2: Tune** - Record organization overrides or change policy actions based on your risk tolerance
4. **Ongoing: Enforce** - Move categories to `block` (for example `sqli=block`) as confidence grows

## Action Resolution

```
┌─────────────────────────────────────────────────────────────────┐
│ Priority 1: Organization detection-posture override (Enterprise)│
│   pii / sqli / dangerous_command - recorded, audited            │
├─────────────────────────────────────────────────────────────────┤
│ Priority 2: The matched policy's stored action                  │
│   action_request / action_response - changed by a policy write  │
└─────────────────────────────────────────────────────────────────┘
```

No environment variable takes part (v11).

## Deployment Mode

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `DEPLOYMENT_MODE` | `community`, `community-saas`, `evaluation`, `enterprise`, `saas`, `in-vpc-enterprise`, `in-vpc-healthcare`, `in-vpc-banking`, `in-vpc-travel` | **none — must be set** | Controls authentication, read authority and feature set |

- **community**: No authentication required, all Community features enabled
- **enterprise** (and every other value): License key required, Enterprise features unlocked

### `DEPLOYMENT_MODE` must be set explicitly

**Changed by #3096** (9.13.0). An *unset* `DEPLOYMENT_MODE` used to mean
`community`. It no longer does. The Community posture is the most permissive one
the platform has — it disables authentication and license validation, skips the
MCP connector permission check, auto-approves `require_approval` policies, and
grants tenant-wide admin read authority before any token or role is examined —
so it now has to be asked for **by name**. Every other value, **including the
empty string and a typo**, gets the enterprise posture.

The value is matched **exactly**: not trimmed, not case-folded. `" community"`
and `"Community"` are *not* the Community posture. That is deliberate — every
widening of this predicate disables authentication, so the accepting set is
exactly the canonical token. A malformed value fails closed and fails loudly,
because the agent then demands a license it was not given.

A deployment that omits the variable still **starts normally**. What changes is
that the orchestrator stops granting `{tenant-wide, admin}` read authority, so
audit, decisions, cost and replay reads answer `403` or return no rows for any
caller that carries no role. Symptom to recognise: healthy containers, green
health checks, empty dashboards.

Two consequences worth stating plainly:

- **Migration selection did not change.** The migration-path selector still
  treats an unset value as `community` and runs core migrations only. So an
  unconfigured deployment gets the enterprise *posture* with the community
  *schema* — another reason to set the variable rather than rely on any default.
- **Tier gating reads the other way.** Enterprise-only routes are registered
  when the mode is *not* `community`, so an unset value now registers budget
  management, WCP approve/reject, agent CRUD, the `confirm`/`step` execution
  modes, plan resume and plan rollback. Those routes still require the internal
  proxy-auth token, so this is a licensing consequence, not an access one.

The container images deliberately carry **no** `ENV DEPLOYMENT_MODE` default. A
baked-in default would recreate the same defect one layer down: whatever value
was baked in would become the posture you get by forgetting to configure one,
and the process could no longer tell "the operator chose this" from "the
operator chose nothing". Set it on the service, task definition or unit file.

A repository lint (`scripts/lint-deployment-mode.sh`) fails CI if any Compose
service or ECS task definition that runs the agent or the orchestrator omits the
variable.

## Cross-Origin Requests (CORS)

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `AXONFLOW_CORS_ALLOWED_ORIGINS` | comma-separated origins (exact, or containing `*`), or `*` | unset | Browser origins permitted to call the agent, orchestrator and customer-portal HTTP APIs. Credentials are advertised only for an all-exact list |

**Added by #3096** (9.13.0). Entries are scheme + host + optional port:

```bash
AXONFLOW_CORS_ALLOWED_ORIGINS=https://portal.example.com,https://app.example.com
```

The resolved policy:

| `AXONFLOW_CORS_ALLOWED_ORIGINS` | `DEPLOYMENT_MODE` | Policy |
|---|---|---|
| exact origins | any | those origins, credentials **enabled** |
| an entry contains `*` | any | those entries, matched by prefix + suffix, credentials **disabled**, warning logged |
| an entry **is** `*` | any | `*`, credentials **disabled**, warning logged |
| unset | `community` | `*`, credentials **disabled** — see the portal exception below |
| unset | anything else | **all cross-origin requests denied** |

The customer-portal differs on one row only. Its API is authenticated by a
session cookie, and `*` can never be paired with credentials, so a wildcard
Community fallback would be useless to it. In Community mode with the variable
unset it falls back to `http://localhost:3000` and `http://localhost:3001`
**with** credentials, for local `next dev` front ends. That fallback applies on
no other `DEPLOYMENT_MODE` — `community-saas` included — and any configured
value replaces it rather than extending it.

Credentials are enabled only for a list of **exact** origins — that is the only
combination the Fetch specification actually permits, and the only one where the
admitted set is a set somebody wrote down. The previous configuration (`*`
together with credentials) was one that no browser would honour.

> **An entry containing `*` is not ignored.** Earlier revisions of this page said
> there was "no suffix matching". That was wrong about the library underneath:
> an entry is split on the first `*` and matched by prefix and suffix, so
> `https://*.example.com` admits **every** subdomain. Such an entry is honoured
> — silently dropping a configured origin is its own failure mode — but
> credentials are then not advertised for any entry in the list, and a warning
> is logged once at startup. Corrected in #3161.

Set it on **every** service a browser calls — the agent, the orchestrator and
the customer-portal each resolve the policy independently, so a value on one of
them only part-opens the door.

| Deployment surface | How to set it |
|---|---|
| `docker-compose.yml` (this repo, and the partner install bundle) | `AXONFLOW_CORS_ALLOWED_ORIGINS` in `.env` — both services already read it |
| `docker-compose.enterprise.yml`, `docker/docker-compose.base.yaml`, `docker-compose.test.yml` | same variable — every non-community Compose surface reads it. The customer-portal reads it in `docker-compose.enterprise.yml` and `docker-compose.test.yml`; `docker/docker-compose.base.yaml` runs no portal |
| `ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml` (and the partner mirror) | the `CorsAllowedOrigins` stack parameter, wired into the agent, orchestrator and customer-portal task definitions |
| `infrastructure/cloudformation/community-saas-ecs.yaml` | the same parameter. `community-saas` is **not** `community`, so this deployment denies cross-origin requests too. That template deploys no customer-portal |

**Changed by #3161** (9.13.0): the customer-portal used to
ignore this variable entirely and answer from an allowlist compiled into the
image — `localhost:3000`, `localhost:3001`, two `getaxonflow.com` domains and a
bare eu-central-1 EC2 address — with credentials enabled. On a self-hosted
stack those were third-party origins that could be neither removed nor extended
without rebuilding the image. If you relied on any of them, name it here.

Leaving it empty is the safe default and is exactly equivalent to leaving it
unset — `os.Getenv` cannot tell the two apart. The shipped Customer Portal UI
never needs it: it calls its own Next.js origin and is proxied server-side.

**The unset default outside Community mode denies everything.** This is safe for
the shipped topologies: the Customer Portal UI calls its own Next.js origin and
is proxied server-side, so it is same-origin by construction, and the
orchestrator has no browser-facing load-balancer listener at all. Set the
variable if a browser served from some *other* origin has to call these APIs
directly.

## Per-Connector Overrides

Security settings can be overridden per-connector in your configuration file:

```yaml
# axonflow.yaml
connectors:
  postgresql_main:
    sqli_scanner_mode: advanced  # Use advanced scanning for sensitive DB
  redis_cache:
    sqli_scanner_mode: off       # Disable for trusted internal cache
```

## Docker Compose Example

```yaml
services:
  axonflow-agent:
    environment:
      # === Security Detection Configuration (Issue #891) ===
      # Philosophy: Block high-confidence threats, warn on heuristics, redact PII

      # SQLi Scanner: "off", "basic" (default), "advanced" (enterprise)
      SQLI_SCANNER_MODE: "basic"

      # Detection ACTIONS are not set here (v11, #3961): the stored policy
      # action decides, and an organization's recorded detection-posture
      # override is the only replacement. See "Changing an Action" above.

      # === Deployment Mode ===
      # REQUIRED. "community" = no auth required; every other value (and an
      # UNSET value) = the enterprise posture, which requires a license.
      # There is no image-level default — see "Deployment Mode" above.
      DEPLOYMENT_MODE: "community"

      # === Cross-origin browser access (optional) ===
      # Unset + a non-community mode denies all cross-origin requests.
      # AXONFLOW_CORS_ALLOWED_ORIGINS: "https://portal.example.com"
```

Set `DEPLOYMENT_MODE` on the **orchestrator** service too, with the same value.
The agent and the orchestrator each read it independently, and a divergence
shows up as empty audit/decisions/cost reads rather than as a startup error.

## Legacy Configuration (Removed)

`PII_BLOCK_CRITICAL` and `SQLI_BLOCK_MODE`, deprecated by Issue #891, were removed in v11 along with the `*_ACTION` variables that replaced them. They are ignored with the same boot WARN and counter; see [Removed in v11](#removed-in-v11-detection-action-environment-variables).

## Service Ports and Single Entry Point (ADR-024)

AxonFlow implements a **single entry point architecture** where all SDK requests go through the Agent on port 8080. The Agent automatically proxies requests to the appropriate backend service.

| Service | Port | Description |
|---------|------|-------------|
| Agent | 8080 | **Single entry point for all SDK requests** |
| Orchestrator | 8081 | Internal - handles dynamic policies, LLM providers, cost controls |
| Portal | 8082 | Internal - handles auth, code governance (Enterprise) |

### Proxied Routes

The Agent automatically proxies these routes:

| Route Prefix | Proxied To | Purpose |
|--------------|-----------|---------|
| `/api/v1/auth/*` | Portal | Login, logout, session management |
| `/api/v1/code-governance/*` | Portal | Code Governance API |
| `/api/v1/portal/*` | Portal | Portal management |
| `/api/v1/git-providers/*` | Portal | Git provider configuration |
| `/api/v1/tenant-policies/*` (deprecated spelling `/api/v1/dynamic-policies/*`) | Orchestrator | Tenant policies; writes answer `409 LEGACY_POLICY_WRITE_FROZEN` in v11 |
| `/api/v1/typed-policies/*` | Orchestrator | Typed policy authoring, the v11 policy write path |
| `/api/v1/connectors/*` | Orchestrator | Connector management |
| `/api/v1/cost/*` | Orchestrator | Cost controls |
| `/api/v1/executions/*` | Orchestrator | Execution replay |
| `/api/v1/llm-providers/*` | Orchestrator | LLM provider configuration |

All other routes (e.g., `/api/v1/policies/*`, `/api/request`, `/health`) are handled directly by the Agent.

### SDK Configuration

Configure your SDK to use only the Agent endpoint:

```go
// Go SDK
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint: "http://localhost:8080",  // Single entry point
})
```

```python
# Python SDK
client = AxonFlow(
    endpoint="http://localhost:8080",  # Single entry point
)
```

## Related Documentation

- [PII Detection](https://docs.getaxonflow.com/docs/security/pii-detection/) - Supported PII types and configuration
- [SQL Injection Scanning](https://docs.getaxonflow.com/docs/security/sql-injection-scanning/) - SQLi detection modes
- [Policy Enforcement](https://docs.getaxonflow.com/docs/policies/overview/) - Custom policy rules
