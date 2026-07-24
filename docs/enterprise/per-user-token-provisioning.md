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
  `viewer`.
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

Your IdP issues each developer a standard OIDC token; AxonFlow validates it
against the IdP's **JWKS** (issuer, audience, expiry, RS256 signature) and
resolves the developer's role from the **SCIM-synced directory** —
deliberately *not* from any role claim inside the token, so role assignment
stays on AxonFlow's audited SCIM/admin surface and an IdP misconfiguration
cannot mint an admin.

### Prerequisites

- **Migrations** `core/143` (the OIDC verifier columns), `core/145` (org-key
  decoupling — **required for in-vpc**, see the in-vpc note below), and
  `core/146` (seeds the fleet-mappable system roles) applied.
- **Enterprise deployment.** Per-user token resolution runs only for
  enterprise-authenticated fleet callers. Community / community-saas /
  internal-service callers keep their existing bypass and never resolve a
  per-user identity, so a token presented there is ignored.
- **The agent has a database connection.** The OIDC validator and the SCIM
  role resolver auto-register at startup *only* if one is available. Without
  it, no validator registers and a presented token is ignored (least-privilege
  attribution) rather than honoured — the agent logs a rate-limited warning
  saying exactly this.
- **`sso:configure`** permission for the operator doing the setup (steps 3–4).

> **In-VPC note.** Before the fix for
> [#2960](https://github.com/getaxonflow/axonflow-enterprise/issues/2960),
> in-vpc deployments wrote the SSO config under a platform-wide sentinel org,
> while the fleet verifier looked it up under the real (licensed) org — so
> every OIDC token was rejected fail-closed and Path B could not work at all.
> **Path A is unaffected** by this.
>
> `core/145` repairs an already-affected row, but **only if it can identify the
> deployment org**: it reads `ORG_ID` (as `app.deployment_org_id`) and refuses
> to stamp an org it cannot verify, logging a `WARNING` and leaving the row
> alone — in which case Path B stays broken exactly as before. So: make sure
> `ORG_ID` is set to the licensed org before upgrading, and check the agent's
> migration logs for a `Migration 145` warning. Confirm the result with
> `SELECT tenant_id, org_id FROM sso_configurations;` — on in-vpc you want
> `tenant_id = '__platform__'` and `org_id = <your org>`.

### 1. Configure SCIM provisioning FIRST

Path B resolves roles from the SCIM-synced directory, so **the directory must
be populated before any token will resolve to more than least privilege.**
Group→role mappings only take effect for users SCIM has actually provisioned
(mapping a group syncs its current members' roles). Do this first, or every
developer authenticates successfully and then reads nothing.

1. Create a SCIM bearer token in the portal (**Settings → SCIM → Create
   Token**; the page is titled *Platform SCIM Provisioning* on in-vpc) — copy
   it once; it is not shown again.
2. Point JumpCloud's SCIM/directory-sync at `$PORTAL_URL/scim/v2` using that
   token, and assign your developer group(s) so users and groups sync.

Full walkthrough: [SCIM setup](../../ee/docs/scim/setup.md) ·
[group→role mapping](../../ee/docs/scim/group-role-mapping.md).

### 2. Create the OIDC application in JumpCloud

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

> **Verify these against your own tenant's OIDC discovery document** —
> `https://oauth.id.jumpcloud.com/.well-known/openid-configuration` — rather
> than copying them. IdPs vary the issuer (trailing slash included), the JWKS
> URI, and the scopes needed to emit `email`; a mismatched `iss` or `aud` is
> rejected fail-closed, which looks identical to "tokens don't work".

### 3. Configure AxonFlow (per tenant, requires `sso:configure`)

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

- **`POST` creates; it returns `409` if a config already exists.** To change an
  existing one — including switching a tenant from SAML to OIDC — use
  `PUT /api/v1/sso/config` with the same body. (`PATCH` toggles `enabled`;
  `DELETE` removes the config.)

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

### 4. Map SCIM groups to roles

Path B roles come from the SCIM directory (step 1), never from the token. Map
each synced JumpCloud group to an AxonFlow role. Both calls are session-
authenticated and gated on `sso:configure` — deliberately *not* reachable with
a SCIM directory-sync token, so a sync token cannot grant its own group roles.

First discover the role UUIDs:

```bash
curl "$PORTAL_URL/api/v1/scim/roles" -H "Cookie: <portal session>"
# => {"roles":[{"id":"3f2b…","name":"developer","display_name":"Developer",…}, …],
#     "count":5}
```

Every org has the five fleet-mappable system roles seeded automatically:
`owner`, `admin`, `policy_admin`, `developer`, `viewer`. New orgs get them on
creation; existing orgs were backfilled. These
are the only role names a SCIM group may map to — the fleet resolver keys on the
role **name**, so mapping a group to a differently-named custom role is
**rejected** (`400`) at the next step rather than silently resolving every
member to least privilege. Map each group to whichever of the five fits: `admin`
or `owner` for a group that should read the whole tenant, `developer` /
`viewer` for own-rows access.

Then map a group. The `<group-id>` is the SCIM group id — list them from the
SCIM router with the **SCIM bearer token** (a different router and credential
to the session-authenticated calls here):
`curl "$PORTAL_URL/scim/v2/Groups" -H "Authorization: Bearer $SCIM_TOKEN"`.

```bash
curl -X PUT "$PORTAL_URL/api/v1/scim/groups/<group-id>/role-mapping" \
  -H "Cookie: <portal session>" \
  -H "Content-Type: application/json" \
  -d '{"role_id": "3f2b…"}'
# => {"group_id":"…","role_id":"3f2b…","role_name":"Developer","users_updated":12}
```

`users_updated` counts the group members whose role assignments were
re-synced. A `0` means the mapping applied to nobody — an empty group, members
SCIM has not provisioned yet (revisit step 1), or members that failed to
resolve. It is not by itself an error, but on a group you expect to have
developers in it, treat it as one. Send `{"role_id": null}` to clear a mapping.

Review current mappings with `GET /api/v1/scim/groups/role-mappings`.

A developer in no mapped group resolves to **least privilege** (own-rows read
scope), never admin.

### 5. Deliver the token to the fleet

The IdP token travels on the fleet request as **`X-User-Token`**:

```
X-User-Token: <the developer's OIDC token>
```

**Use `X-User-Token` everywhere.** `Authorization: Bearer <token>` is accepted
*only* on the MCP-server plane, as a concession to deployments that
authenticate the tenant out-of-band. On the agent-proxied REST plane (the
audit / decision / override read surfaces) `Authorization` is **only** ever the
tenant credential — a Bearer per-user token there is parsed as a tenant
credential and rejected. `X-User-Token` is the one header both planes read, so
it is the only correct answer for a fleet.

The plugins send this header for you when `AXONFLOW_USER_TOKEN` is set; see
Path A's fleet-scale delivery note above, which applies unchanged to Path B
tokens.

> **Send an ID token, not (necessarily) an access token.** AxonFlow requires
> both an `email` claim and an `aud` matching the configured audience. Those are
> reliably present on **ID tokens**; many IdPs issue access tokens that are
> opaque, carry a resource-server `aud`, or omit `email` entirely — any of which
> is rejected fail-closed. Configure your token-delivery tooling to hand
> AxonFlow a token type that carries both, and confirm against a decoded sample
> before rolling out to the fleet.

### 6. Verification hygiene (what AxonFlow enforces)

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
