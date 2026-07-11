# Identity-Header Trust Model (Per-User Audit Attribution)

**Platform Version:** v9.9.0

**Status:** Active

**Applies To:** All deployment modes (Community and Enterprise)

---

## What This Covers

AxonFlow's governance planes accept three client-asserted identity headers:

| Header | Meaning |
|--------|---------|
| `X-User-Email` | The end-user (principal) on whose behalf the governed call is made |
| `X-User-ID` | An optional per-user id (MCP-server plane only) |
| `X-Session-Id` | The AI-tool session the call belongs to (e.g. one Claude Code / Claude Desktop session) |

These headers exist because many Policy Enforcement Points (PEPs) front **many
principals behind one credential**: the Claude Code plugin fleet authenticates
with a shared org license, and the Claude Desktop governance proxy
authenticates with HTTP Basic `org:license-key`. Without the headers, every
action would attribute to the fleet/service identity in the audit trail.

## The Trust Gate

Because any governed caller can set these headers, they are **forgeable**. A
deployment must explicitly declare that its identity source is trusted before
the platform honors them:

```bash
# Agent environment. Default: off. Only the exact string "true" opts in.
AXONFLOW_TRUST_IDENTITY_HEADERS=true
```

Parse semantics (shared with the agentgateway PEP adapters shipped in v9.8.0):

- `true` — trust the headers (exact string, after whitespace trim).
- unset / `false` — ignore the headers (the secure default).
- anything else (`1`, `TRUE`, `yes`, …) — treated as **false**, with a
  once-per-process warning log so a typo cannot silently downgrade intent.

### How much to worry about the trust boundary

For a **small team or individual deployment**, enabling the gate is fine out of
the box — the "a colleague forges my identity header" threat is largely
theoretical when you know and trust everyone who can reach the agent. The trust
boundary matters at **fleet scale**, where an insider forging another
principal's identity is a real concern: there, source the identity from a place
the end user cannot edit (MDM/JumpCloud-managed plugin settings, a
gateway that sets it from a validated JWT). That is a scale-dependent hardening,
not a prerequisite for turning the gate on.

## Behavior Per Gate State

All four governance planes apply the same rule — `/api/v1/decide`,
`/api/v1/mcp/check-input`, `/api/v1/mcp/check-output`, and the MCP-server
`tools/call` path:

| | Gate **on** | Gate **off** (default) |
|---|---|---|
| `audit_logs.user_email` | `X-User-Email` (falls back to the plane's validated/fallback identity when absent) | Plane's validated/fallback identity only |
| `audit_logs.session_id` | `X-Session-Id` | NULL (header ignored) — session-summary reporting and the Claude Code dashboard's per-session drill-down stop attributing new rows |
| ADR-044 session-override scope | Per-user, keyed on the same trusted identity | The plane's validated identity; overrides asserted via headers do not apply |
| Per-user dynamic policies (MCP-server plane: user-scoped rate limits / budgets keyed on `X-User-ID`/`X-User-Email`) | Keyed on the trusted identity (as for pre-9.9.0 trusted fleets) | Keyed on the client-scoped identity |
| Verdicts / authz / policy selection / tenant + org resolution | **Never influenced by a forged header** | **Never influenced by the headers at all** |

The fallback identity is plane-specific: `/api/v1/decide`, check-input and
check-output resolve the user from the authenticated credentials
(`user_token` JWT in Enterprise, the synthesized service/community user
otherwise); the MCP-server plane uses the client-scoped pseudo-identity
`mcp-client:<client-id>`. Neither is ever an attacker-controlled value.

### No shared identity holds session overrides

Session overrides are scoped to an individual user. From 9.9.0 **no
platform-synthesized shared identity** can create, be offered, or apply an
ADR-044 session override on any plane — a shared identity's override would
flip a deny for every caller on the client. The full set the guard rejects:

- `mcp-client:<client-id>` — the MCP-server client-scoped pseudo-identity;
- `<client-id>@axonflow.local` — the enterprise no-user-token service fallback;
- `unknown@axonflow.local` — the audit-writer fallback;
- `orchestrator@axonflow.internal` — the internal-service identity;
- `evaluator@try.getaxonflow.com` — the community-SaaS evaluator identity;
- `local-dev@axonflow.local` — the community identity, **only** when asserted
  outside community mode (in community mode it is the single local developer
  and keeps full override behavior).

A `create_override` attempt under any of these fails with an actionable error
naming the trust gate; blocked responses under them carry no override
affordance.

### Direct orchestrator access cannot forge the override identity

Every orchestrator ingress that keys an ADR-044 override apply on a per-user
identity requires the AxonFlow Agent's HMAC proxy token
(`X-Axonflow-Proxy-Auth`):

- `POST /api/v1/overrides` — override create (the identity becomes the
  override's owner);
- the Workflow Control Plane step-gate — the identity keys the override apply;
- `POST /api/v1/plan/execute` and `POST /api/v1/plan/{id}/resume` — the MAP
  confirm-mode execute and plan-resume paths persist the actor identity into
  a resumable checkpoint;
- `POST /api/v1/workflows/{id}/checkpoints/resume` and
  `.../checkpoints/{checkpoint_id}/resume` — checkpoint resume re-evaluates
  the step and applies any override keyed on the checkpoint's stored actor
  identity.

The MAP execute path additionally sources the checkpoint's actor **email**
from the trust-gated `X-User-Email` header, never the request body — the body
is a channel the header gate does not cover, so a body-supplied actor email
would otherwise seed a forged identity into the checkpoint.

A caller reaching the orchestrator directly (rather than through the agent) is
rejected with `403 — request must be routed through AxonFlow Agent`. Community
mode (no internal-service secret) is exempt, matching the existing
audit-tool-call enforcement.

This is defense-in-depth beneath a stronger first layer: the **agent proxy
trust-gates the per-user identity headers on every proxied route** (not a
per-prefix allowlist). With the gate off (the default) a forged
`X-User-Email` / `X-User-ID` / `X-Session-Id` is stripped before it can reach
*any* orchestrator route, so the override identity can never be attacker-
controlled in the default posture; with the gate on, the headers are forwarded
sanitized from a trusted deployment, and the per-ingress proxy-auth still
guarantees they arrived through the agent. The auth-derived tenant/org headers
and the proxy-auth token are never gated.

When the gate is **off** and a governed request carries identity headers, the
agent logs a once-per-process detection warning:

```
received identity headers (X-User-Email) but AXONFLOW_TRUST_IDENTITY_HEADERS is off —
audit attribution is using the validated/fleet identity; set
AXONFLOW_TRUST_IDENTITY_HEADERS=true if your identity source (gateway, proxy,
or managed plugin) is trusted to assert end-user identity
```

so an operator never silently loses attribution after an upgrade.

## The Security Invariant

**Identity headers may set audit attribution fields only.** They must never
influence a verdict, an authorization decision, policy selection, or
tenant/org resolution, on any plane, gate on or off. With the gate off, a
request's verdict and audit identity are identical with and without the
headers. This invariant is pinned by verdict-invariance and forged-header
tests on every plane.

The one identity-*scoped* feature is the ADR-044 per-user session override:
an override is created by and applies to a specific user identity. That scope
rides on the same trusted identity as attribution — which is exactly why the
gate must default to off: honoring an unvalidated `X-User-Email` for override
scope (the pre-9.9.0 behavior on check-input and MCP-server) let any governed
caller apply another user's active override to their own blocked request.

## When To Turn It On

Set `AXONFLOW_TRUST_IDENTITY_HEADERS=true` only when **every** network path to
the agent's governance endpoints goes through a hop that strips inbound
identity headers and re-sets them from a validated source, for example:

- The **Claude Desktop governance proxy**: Claude Desktop cannot override the
  proxy's `AXONFLOW_LEADER_EMAIL`; the proxy asserts it on decide and
  check-output.
- A **managed Claude Code plugin fleet**: `AXONFLOW_USER_EMAIL` provisioned
  per developer via MDM/JumpCloud-managed settings.
- An **agentgateway / Envoy deployment** where a jwtAuth filter re-sets the
  headers from token claims (see the gateway adapters' matching
  `AXONFLOW_TRUST_IDENTITY_HEADERS` knob — set both, they are one contract).

If governed clients can reach the agent directly with arbitrary headers, leave
the gate off.

## Upgrade Note (pre-9.9.0 deployments)

Before 9.9.0 the check-input and MCP-server planes honored `X-User-Email`
unconditionally. If your deployment relies on per-user attribution or
per-user session overrides from plugin-supplied headers, set
`AXONFLOW_TRUST_IDENTITY_HEADERS=true` after upgrading — the always-trust
behavior was a forgery exposure and was deliberately not preserved. Until the
flag is set, attribution falls back to the validated/fleet identity and the
detection warning above appears in the agent logs.

## Discovery

Platforms with this behavior advertise the `identity_header_attribution`
capability in `GET /health`, so PEPs (desktop proxy, plugins) can detect
whether trust-gated attribution is available.
