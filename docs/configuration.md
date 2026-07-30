# Configuration Reference

AxonFlow is designed with secure-by-default settings that are fully configurable. This document covers all environment variables for controlling security detection and policy enforcement.

## Security Detection Configuration (Issue #891)

AxonFlow uses a tiered default approach: **block high-confidence threats, warn on heuristics, redact PII**.

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `SQLI_ACTION` | `block`, `warn`, `log` | `block` | SQL injection detection action (high confidence) |
| `PII_ACTION` | `block`, `warn`, `redact`, `log` | `redact` | PII detection action (preserves UX) |
| `SENSITIVE_DATA_ACTION` | `block`, `warn`, `log` | `warn` | Credential/token detection action (may have false positives) |
| `HIGH_RISK_ACTION` | `block`, `warn`, `log` | `warn` | High risk score (>0.8) action (needs tuning) |
| `DANGEROUS_QUERY_ACTION` | `block`, `warn`, `log` | `block` | DROP/TRUNCATE detection action (destructive) |
| `SQLI_SCANNER_MODE` | `off`, `basic`, `advanced` | `basic` | SQL injection scanning mode |

### Action Types

| Action | Behavior |
|--------|----------|
| `block` | Reject request immediately |
| `redact` | Mask/redact detected content, allow request |
| `warn` | Log warning, allow request |
| `log` | Log for audit only, allow request |

### Deprecated Environment Variables

These environment variables are deprecated and will be removed in a future release:

| Deprecated | Replacement | Notes |
|------------|-------------|-------|
| `SQLI_BLOCK_MODE` | `SQLI_ACTION` | `block` → `SQLI_ACTION=block`, `warn` → `SQLI_ACTION=warn` |
| `PII_BLOCK_CRITICAL` | `PII_ACTION` | `true` → `PII_ACTION=block`, `false` → `PII_ACTION=log` |

### Philosophy: Tiered Defaults

The default configuration is designed to minimize friction during evaluation while maintaining security:

| Detection Type | Default | Rationale |
|----------------|---------|-----------|
| SQL Injection | `block` | High confidence, real attacks |
| Dangerous Queries | `block` | Destructive operations |
| PII | `redact` | Non-blocking, preserves user experience |
| Sensitive Data | `warn` | May have false positives (e.g., "PRIMARY KEY") |
| High Risk Score | `warn` | Composite score needs per-environment tuning |

### Progressive Enforcement

A common adoption pattern:

1. **Day 1: Out-of-the-box** - Start with defaults (PII redacted, SQLi blocked)
2. **Week 1: Review** - Check audit logs for detection accuracy
3. **Week 2: Tune** - Adjust actions based on your risk tolerance
4. **Ongoing: Enforce** - Enable stricter blocking as confidence grows

## Environment Variable Precedence

```
┌─────────────────────────────────────────────────────────────────┐
│ Priority 1: Per-tenant policy override (Enterprise API)         │
│   Enterprise users can override any policy via API              │
├─────────────────────────────────────────────────────────────────┤
│ Priority 2: Environment variable (docker-compose)               │
│   SQLI_ACTION=warn overrides all SQLi policies                  │
├─────────────────────────────────────────────────────────────────┤
│ Priority 3: Per-policy DB default (migration seed)              │
│   static_policies.action from seed data                         │
└─────────────────────────────────────────────────────────────────┘
```

## Deployment Mode

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `DEPLOYMENT_MODE` | `community`, `community-saas`, `evaluation`, `enterprise`, `saas`, `in-vpc-enterprise`, `in-vpc-healthcare`, `in-vpc-banking`, `in-vpc-travel` | **none — must be set** | Controls authentication, read authority and feature set |

- **community**: No authentication required, all Community features enabled
- **enterprise** (and every other value): License key required, Enterprise features unlocked

### `DEPLOYMENT_MODE` must be set explicitly

**Changed by #3096** (next release after 9.12.2). An *unset* `DEPLOYMENT_MODE` used to mean
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

**Added by #3096** (next release after 9.12.2). Entries are scheme + host + optional port:

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

**Changed by #3161** (next release after 9.12.2): the customer-portal used to
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

      # SQLI_ACTION: block|warn|log (default: block - high confidence attacks)
      SQLI_ACTION: "block"

      # PII_ACTION: block|warn|redact|log (default: redact - preserves UX)
      PII_ACTION: "redact"

      # SENSITIVE_DATA_ACTION: block|warn|log (default: warn - may have false positives)
      SENSITIVE_DATA_ACTION: "warn"

      # HIGH_RISK_ACTION: block|warn|log (default: warn - composite score needs tuning)
      HIGH_RISK_ACTION: "warn"

      # DANGEROUS_QUERY_ACTION: block|warn|log (default: block - DROP/TRUNCATE)
      DANGEROUS_QUERY_ACTION: "block"

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

## Legacy Configuration (Deprecated)

For backwards compatibility, the old environment variables still work but will log deprecation warnings:

```yaml
# DEPRECATED - use new *_ACTION variables instead
environment:
  PII_BLOCK_CRITICAL: "true"  # Use PII_ACTION=block instead
  SQLI_BLOCK_MODE: "warn"     # Use SQLI_ACTION=warn instead
```

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
| `/api/v1/dynamic-policies/*` | Orchestrator | Dynamic policy CRUD |
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
