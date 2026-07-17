# Per-User Token Provisioning (Enterprise)

> **Part of** the fleet-identity epic [#2919](https://github.com/getaxonflow/axonflow-enterprise/issues/2919) (provisioning workstream [#2924](https://github.com/getaxonflow/axonflow-enterprise/issues/2924)) · **Edition:** Enterprise

Fleet deployments historically authenticated every developer's plugin with a
single shared tenant credential (`org_id:license`). That gives **attribution,
not authorization**: anyone holding the shared credential can assert any
identity. Per-user tokens give every developer a validated, non-forgeable
`{identity, role}` that AxonFlow's fleet plane uses for role-scoped access.

Two provisioning paths converge on the same validated identity:

| | Path A — AxonFlow-managed | Path B — IdP-issued (OIDC) |
|---|---|---|
| Token issuer | AxonFlow admin API (HS256) | Your IdP: JumpCloud, Okta, Azure AD… (RS256/JWKS) |
| Role source | Admin-assigned at mint | SCIM group→role mappings (never the token's own role claim) |
| Revocation | Server-side deny-list, immediate | IdP token lifetime + IdP-side deactivation |
| Best for | Teams without an IdP; evals; break-glass | IdP-managed fleets |

Path A is not a stopgap — it is the permanent no-IdP tier.

---

## Path A — Admin-minted per-user tokens

### Prerequisites

- The customer-portal task definition carries **`JWT_SECRET`** (the same
  value as the agent — minted tokens are validated agent-side) and
  **`ADMIN_API_KEY`**.
- Migrations ≥ `enterprise/135` applied (the revocation deny-list).

> **Security model:** the role travels as a JWT claim, so *whoever can mint
> sets the role*. Mint/rotate/revoke therefore require a **valid
> `X-Admin-API-Key` even in deployment modes where admin auth is otherwise
> optional** (in-vpc). If `ADMIN_API_KEY` is not configured, the endpoints
> refuse with 401/503 — they never fall open.
>
> **Blast radius:** `ADMIN_API_KEY` is the same credential that gates org and
> license management, and it works across every org. It is now also a
> "mint an `admin`-role token for any org" credential — treat it as a
> top-tier secret (rotate on a schedule, restrict to operators, never embed
> it in a fleet-distributed config).

### Mint

```bash
curl -X POST "$PORTAL_URL/api/v1/admin/organizations/{org_id}/user-tokens" \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_email": "dev@yourco.com", "role": "developer", "ttl_hours": 720}'
```

Response (`201`) — the token is returned **exactly once** and never stored or
logged:

```json
{
  "success": true,
  "user_token": {
    "token": "eyJ...",
    "jti": "f3b0…",
    "user_email": "dev@yourco.com",
    "role": "developer",
    "org_id": "yourco",
    "expires_at": "2026-08-15T00:00:00Z"
  }
}
```

- `role` must be one of `admin`, `owner`, `policy_admin`, `developer`,
  `member`, `viewer`.
- `ttl_hours` defaults to 720 (30 days), capped at 8760 (1 year). Every token
  carries `exp` — unbounded tokens cannot be minted.
- Emails are canonicalized (lower-cased, trimmed) at mint, validation, and
  revocation, so audit attribution and read-scoping key on the same value.

### Rotate

```bash
curl -X POST "$PORTAL_URL/api/v1/admin/organizations/{org_id}/user-tokens/rotate" \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_email": "dev@yourco.com", "role": "developer"}'
```

Rotation revokes **every** existing token for the user (issued before the
rotation instant), then mints the replacement. Note: revocation granularity
is one second — a token minted in the *same second* as the rotation survives
it.

### Revoke

```bash
# One token (by jti — from the mint response or MINT_USER_TOKEN audit row):
curl -X DELETE "$PORTAL_URL/api/v1/admin/organizations/{org_id}/user-tokens" \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jti": "f3b0…", "reason": "laptop stolen"}'

# All of a user's tokens (offboarding):
curl -X DELETE "$PORTAL_URL/api/v1/admin/organizations/{org_id}/user-tokens" \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_email": "dev@yourco.com", "reason": "offboarded"}'
```

Revocation is enforced server-side on every validation (the deny-list is
consulted before a token is accepted; if the deny-list is unreachable the
token is rejected — fail closed).

Every mint/rotate/revoke writes an `admin_audit_log` row (actor, target user,
role, ttl, jti). The token value itself never lands in any log or audit row.

### Fleet-scale delivery (Claude Code managed settings)

Deliver each developer's token via your MDM's managed-settings file so it
never transits chat/email:

```jsonc
// /Library/Application Support/ClaudeCode/managed-settings.json (per device)
{
  "env": {
    "AXONFLOW_USER_TOKEN": "<that developer's token>"
  }
}
```

Scope the managed-settings payload **per device/user** in your MDM — a
fleet-wide static file would hand every developer the same identity (and one
developer's token to all others). Rotate on your credential cadence with the
rotate endpoint above.

---

## Path B — IdP-issued OIDC tokens (JumpCloud example)

Your IdP issues each developer a standard OIDC access token; AxonFlow
validates it against the IdP's **JWKS** (issuer, audience, expiry, RS256
signature) and resolves the developer's role from the **SCIM-synced
directory** — deliberately *not* from any role claim inside the token, so
role assignment stays on AxonFlow's audited SCIM/admin surface and an IdP
misconfiguration cannot mint an admin.

### 1. Create the OIDC application in JumpCloud

1. JumpCloud Admin Console → **SSO Applications → Add New Application →
   Custom OIDC App**.
2. Grant types: *Authorization Code* (+ *Refresh Token* as desired). Redirect
   URI: your token-delivery tooling (device-flow/CLI helper).
3. Note the values:
   - **Issuer:** `https://oauth.id.jumpcloud.com/`
   - **JWKS URI:** `https://oauth.id.jumpcloud.com/.well-known/jwks.json`
   - **Audience:** your app's client ID (or the custom audience you configure).
4. Ensure the `email` claim is included (standard scopes: `openid email`).
5. Assign the app to your developer group(s).

### 2. Configure AxonFlow (per tenant, requires `sso:configure`)

```bash
curl -X POST "$PORTAL_URL/api/v1/sso/config" \
  -H "Cookie: <portal session>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "oidc",
    "enabled": true,
    "oidc_issuer": "https://oauth.id.jumpcloud.com/",
    "oidc_audience": "<your client id>",
    "oidc_jwks_uri": "https://oauth.id.jumpcloud.com/.well-known/jwks.json",
    "oidc_claim_mapping": {"email": "email"}
  }'
```

- Issuer and JWKS URI must be **https** (plaintext HTTP is refused except
  loopback, because a swapped JWKS would turn validation into a forgery
  oracle). URLs targeting an internal / cloud-metadata endpoint
  (`169.254.169.254`, RFC-1918 hosts, `*.internal`) are rejected — the
  platform fetches these server-side.
- **Use a per-tenant issuer, not a shared multi-tenant "common" issuer.** The
  verifier trusts the identity in a token signed by the configured issuer +
  audience; if two AxonFlow tenants configure the *same* issuer/audience, a
  token minted for one is structurally valid for the other. Give each tenant a
  distinct OIDC app (distinct issuer or audience) so a token cannot cross a
  tenant boundary.
- `oidc_claim_mapping.email` names the claim carrying the developer identity
  (default `email`; e.g. `preferred_username` for some IdPs).
- As of #2924 the SSO-config mutation endpoints require the `sso:configure`
  permission (previously declared but unenforced).

### 3. Map SCIM groups to roles

Path B roles come from the SCIM directory: map each JumpCloud group to an
AxonFlow role via `PUT /api/v1/scim/groups/{id}/role-mapping` (also gated on
`sso:configure`). A developer with no mapped role resolves to **least
privilege** (own-rows read scope), never admin.

### 4. Verification hygiene (what AxonFlow enforces)

- RS256 only — `alg: none` and HS256 algorithm-confusion tokens are rejected
  before any key material is consulted.
- `iss` exact match, `aud` must contain the configured audience, `exp`
  required and enforced, `nbf` honored (60s clock-skew leeway).
- `email_verified`, when present, must be `true` — an IdP that emits a
  self-asserted/unverified email (e.g. multi-tenant Azure AD) cannot be used
  to impersonate another directory user's identity (and thus their role).
- JWKS cached 15 minutes; an unknown `kid` triggers a rate-limited refetch,
  so IdP signing-key rotation is picked up automatically.
- Every failure mode is fail-closed: unknown key, expired token, wrong
  audience, unreachable role directory → the request is not authenticated.

---

## Which token wins?

Both paths produce the same validated `{identity, role}` for the fleet
plane's pluggable validator (#2920). Registration order and plane wiring are
part of the #2920 foundation; this page covers provisioning only.

---

## Role-scoped audit / decision / override reads

Once a developer's `{identity, role}` is validated, AxonFlow **scopes what they
can read** — `admin`/`owner` see the full tenant trail, everyone else sees only
their own rows, and a caller with no resolvable identity sees nothing
(fail-closed). This is the fix for the broken-access-control gap: before it, any
holder of the shared tenant credential could read the entire tenant's audit
trail, decision history, and overrides.

The complete model — the role→scope rule, the two enforcement layers
(agent-first, orchestrator-second over the trusted proxy-auth channel), the
covered surfaces, admin-gated compliance exports, and the attribution caveat —
lives in its own page:

> **→ [Role-Scoped Audit, Decision & Override Reads](./rbac-read-scoping.md)**

Two points worth stating alongside provisioning:

- **Emails are canonicalized** (lower-cased, trimmed) at mint, validation, and
  revocation, so audit attribution and read-scoping key on the same value — a
  developer always sees the full set of their own attributed history.
- **Path B roles come from the SCIM directory, never the token.** A developer
  with no mapped role resolves to least-privilege (own-rows), so an IdP
  misconfiguration can never mint an admin.
