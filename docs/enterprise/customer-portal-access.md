# Customer Portal Access Guide

## Overview

The Customer Portal provides organization management, execution timeline, approval dashboard, and policy management through a web interface. It consists of two main components:

- **Customer Portal UI** (Next.js, port 3000) -- the frontend
- **Customer Portal API** (Go, port 8090) -- the backend

Two deployment modes are supported: SaaS (multi-tenant, AxonFlow-hosted) and In-VPC (customer-managed, typically single-tenant).

## Architecture

```
                         +------------------+
                         |   ALB (443)      |
                         +--------+---------+
                                  |
              +-------------------+-------------------+
              |                   |                   |
     Port 8080 (Agent)   Port 8090 (Portal API)  Port 3000 (Portal UI)
              |                   |                   |
   +----------+----------+  +----+----+         +-----+-----+
   | Agent Gateway        |  | Portal  |         | Next.js   |
   | - /api/v1/auth/* ----|->| API     |         | Frontend  |
   |   (proxied, no auth) |  | (Go)    |         |           |
   | - /api/v1/* (authed) |  +---------+         +-----------+
   +-----------+----------+
```

Key points:

- The Agent Gateway on port 8080 proxies all `/api/v1/auth/*` requests to the Portal API. No Basic auth is required on this path, allowing unauthenticated login and SSO flows.
- The ALB exposes listeners on ports 443 (Agent), 8090 (Portal API), and 3000 (Portal UI).
- Vanity domains (e.g., `app.getaxonflow.com`) are configured via the `setup-vanity-domain.yml` workflow.
- The Portal UI requires `API_BACKEND_URL` to be configured to point to the Portal API on port 8090.

## Organization Provisioning

### Method 1: Admin API (Recommended for Running Stacks)

**Endpoint:** `POST https://{stack-domain}:8090/api/v1/admin/organizations`

This is the recommended way to create organizations on an already-running stack. The endpoint is idempotent (uses `ON CONFLICT (org_id) DO UPDATE`).

**Authentication:** See the Admin Auth Matrix below. No auth required for enterprise/in-vpc deployments.

**Request body:**

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `org_id` | string | Yes | -- | Unique organization identifier |
| `name` | string | Yes | -- | Display name |
| `license_key` | string | Yes | -- | Pre-generated license key |
| `password` | string | No | -- | Portal login password (bcrypt hashed internally) |
| `tier` | string | No | `DEVELOPER` | One of: `DEVELOPER`, `Professional`, `Enterprise`, `Plus` |
| `status` | string | No | `ACTIVE` | One of: `ACTIVE`, `SUSPENDED`, `CANCELLED` |
| `max_nodes` | int | No | Tier default | Override default node limit for tier |
| `contact_email` | string | No | -- | Admin contact email |
| `contact_phone` | string | No | -- | Admin contact phone |
| `expires_at` | string | No | 1 year | Format: `YYYY-MM-DD` |

**Example:**

```bash
curl -X POST https://{stack-domain}:8090/api/v1/admin/organizations \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "acme-corp",
    "name": "Acme Corporation",
    "license_key": "axf_pro_acme_...",
    "password": "secure-portal-password",
    "tier": "Professional"
  }'
```

For SaaS production, include the admin API key header:

```bash
curl -X POST https://{stack-domain}:8090/api/v1/admin/organizations \
  -H "Content-Type: application/json" \
  -H "X-Admin-API-Key: ${ADMIN_API_KEY}" \
  -d '{ ... }'
```

### Method 2: Customer Onboarding API (Full Provisioning)

**Endpoint:** `POST https://{stack-domain}:8090/api/v1/admin/onboard-customer`

This endpoint generates a license key automatically, inserts the organization into the database, and stores the license key in AWS Secrets Manager at `axonflow/customers/{org-id}/license-key`.

**Authentication:** None (legacy endpoint, registered outside the admin auth middleware).

> **Security Warning:** This endpoint is unauthenticated in all deployment modes. In non-SaaS deployments, port 8090 must be network-restricted (security groups, NACLs, or VPN) to prevent unauthorized organization creation. Never expose port 8090 to the public internet without additional access controls.

**Request body:**

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `org_id` | string | Yes | -- | Unique organization identifier |
| `name` | string | Yes | -- | Display name |
| `tier` | string | No | `Professional` | One of: `Professional`, `Enterprise`, `Plus` |
| `validity_days` | int | No | `365` | License validity in days |
| `email` | string | No | -- | Contact email |
| `phone` | string | No | -- | Contact phone |
| `status` | string | No | `ACTIVE` | Organization status |
| `password` | string | No | -- | Portal login password |

**Example:**

```bash
curl -X POST https://{stack-domain}:8090/api/v1/admin/onboard-customer \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "acme-corp",
    "name": "Acme Corporation",
    "tier": "Enterprise",
    "validity_days": 365,
    "contact_email": "admin@acme.com",
    "password": "secure-portal-password"
  }'
```

The response includes the generated `license_key`, Secrets Manager ARN, and database record ID.

### Method 3: Direct Database Seeding (Test Environments Only)

> **Warning:** This method is for E2E testing only. Do not use direct SQL inserts for customer or production bootstrapping. Use Method 1 or Method 2 instead, which handle password hashing, validation, and audit logging correctly.

For E2E test environments, organizations can be seeded directly via SQL. This approach is used by `scripts/setup-e2e-testing.sh` (approximately lines 730-790).

```sql
INSERT INTO organizations (org_id, name, license_key, tier, password_hash, status, max_nodes, expires_at)
VALUES (
  'test-org',
  'Test Organization',
  'axf_test_license_key_here',
  'Professional',
  '$2a$12$...', -- bcrypt hash, cost 12
  'ACTIVE',
  10,
  NOW() + INTERVAL '365 days'
)
ON CONFLICT (org_id) DO UPDATE SET
  license_key = EXCLUDED.license_key,
  password_hash = EXCLUDED.password_hash;
```

The password must be bcrypt hashed at cost 12. A corresponding row in the `customers` table is also needed for tenant isolation.

**Reference:** `scripts/setup-e2e-testing.sh`

### Method 4: Seed Test Data Workflow (Staging Only)

The `seed-test-data.yml` GitHub Actions workflow seeds organizations via the Admin API on staging environments. Production is blocked.

```bash
gh workflow run seed-test-data.yml -f environment=staging -f confirm=seed
```

**Reference:** `.github/workflows/seed-test-data.yml`

## Portal Login

### Password Authentication

**Endpoint:** `POST /api/v1/auth/login`

This endpoint is proxied through the Agent Gateway on port 8080 -- no Basic auth is needed on this path. The Agent forwards all `/api/v1/auth/*` requests to the Portal API without authentication checks.

**Request:**

```json
{
  "org_id": "acme-corp",
  "password": "secure-portal-password"
}
```

**Response:**

```json
{
  "session_id": "abc123...",
  "org_id": "acme-corp",
  "email": "admin@acme.com",
  "name": "Acme Corporation",
  "expires_at": "2026-03-17T12:00:00Z"
}
```

**Session management:**

- Session cookie: `axonflow_session` (HttpOnly, Secure, SameSite=Lax)
- Expiry: 24 hours (`MaxAge: 86400`)
- Rate limit: 5 attempts per minute per IP

**Related endpoints (also proxied through Agent, no Basic auth):**

- `POST /api/v1/auth/logout` -- clears session
- `GET /api/v1/auth/session` -- checks current session validity
- `POST /api/v1/auth/forgot-password` -- initiates password reset. With an
  email transport plus `AXONFLOW_FROM_EMAIL` and `AXONFLOW_PORTAL_BASE_URL`
  configured (#2330, #3311) it emails a reset link to the org's contact email
  and always answers the same generic 200; without them it returns 501. Rate
  limited: 5 requests/min per IP. A reset token is only ever returned in the
  response body on a local development machine with no email backend. See
  [Sending password-reset email](#sending-password-reset-email) for the two
  transports.

**"The user requested a reset and no email arrived."** The endpoint answers the
same generic 200 in every case, so the response never tells you which of these
happened. Check them in this order:

1. **The deployment has no email backend.** The response is `501`, not `200`,
   and the boot log says so. Reset the password with
   `POST /api/v1/admin/organizations/{org_id}/password` instead.
2. **The email backend is half-configured.** A transport is set but
   `AXONFLOW_FROM_EMAIL` or `AXONFLOW_PORTAL_BASE_URL` is not, or the SMTP
   settings are incomplete (host without port, username without password, an
   unparseable port, an unrecognized `AXONFLOW_SMTP_TLS` value). The portal
   refuses to build the sender at startup and the endpoint returns `501`. The
   boot log names the missing or malformed variable. Note a base URL of `/`
   counts as unset.
3. **The organization has no `contact_email`.** There is nowhere to send it.
   The log records `no contact email on organization` for that org.
4. **A reset link was already sent in the last 5 minutes.** Each organization
   has a re-issue cooldown: while an unused, unexpired link exists, a repeat
   request deliberately sends **no second email** and does **not** replace the
   outstanding link, so the one already in the user's inbox still works. Tell
   them to use the first email, or wait out the window. The log records
   `suppressed re-issue`, and `admin_audit_log` carries a
   `PASSWORD_RESET_REQUESTED` row with that reason.
5. **The send failed.** The log line is org-scoped and `admin_audit_log`
   carries a `PASSWORD_RESET_EMAIL_FAILED` row. The reset token itself never
   appears in either.

**Rate limits count per client address.** The portal reads that address from
`X-Forwarded-For` and by default trusts **one** proxy layer (an ALB, or a
single nginx). If requests reach it through two or more trusted proxies -- for
example Cloudflare in front of your own nginx -- set `AXONFLOW_TRUST_PROXY_HOPS`
to the number of layers, or every user counts as the same client and five
failed sign-ins from anyone locks out everyone for a minute. Never set it above
the real number of proxies: a larger value counts on a header segment the
caller can choose. The resolved value is printed at startup.
- `POST /api/v1/auth/reset-password` -- completes password reset
- `POST /api/v1/auth/change-password` -- changes password (authenticated)

### Sending password-reset email

The portal supports **two** email transports and activates exactly one.

| Transport | Configure with | Suits |
|---|---|---|
| SMTP relay | `AXONFLOW_SMTP_HOST` + `AXONFLOW_SMTP_PORT` | Self-hosted and in-VPC deployments. No third-party vendor, no sending-domain verification, mail never leaves your infrastructure. |
| Resend | `RESEND_API_KEY` | Deployments already using Resend, with a domain verified there. |

If you are running AxonFlow yourself, use SMTP. You almost certainly already
have a relay (Postfix, Exchange, SES SMTP, your provider's submission host),
and it keeps reset mail inside your own network, which is usually the only
answer a regulated deployment can give.

**Precedence.** If `RESEND_API_KEY` is set, Resend wins and the SMTP settings
are ignored entirely. The boot log says so explicitly. Unset `RESEND_API_KEY`
to use the relay. On an AWS CloudFormation stack you cannot even create the
ambiguity: setting both `ResendAPIKeySecretArn` and `SMTPHost` fails the stack
update.

#### SMTP setup

```bash
# Required together. There is no default port: 587 and 465 need different
# transport security, so the portal will not guess one for you.
AXONFLOW_SMTP_HOST=smtp.internal.acme.example
AXONFLOW_SMTP_PORT=587

# Required, shared with the Resend transport. Your relay must be willing to
# send as this address. AXONFLOW_RESET_FROM_EMAIL overrides it for reset mail
# specifically.
AXONFLOW_FROM_EMAIL="Acme Portal <no-reply@acme.example>"

# Required. Every reset link is built from this. See the rename note below.
AXONFLOW_PORTAL_BASE_URL=https://portal.acme.example

# Optional, set BOTH or NEITHER. Many internal relays need neither.
AXONFLOW_SMTP_USERNAME=portal
AXONFLOW_SMTP_PASSWORD=...

# Optional. starttls (default) | tls | none
AXONFLOW_SMTP_TLS=starttls

# Optional. PEM bundle for a relay whose certificate comes from your internal
# CA. Compose and self-hosted deployments only: it names a path inside the
# container, so it needs a mounted file. (CloudFormation has no parameter for
# it -- use a publicly-chaining certificate on that path.)
AXONFLOW_SMTP_CA_FILE=/etc/axonflow/relay-ca.pem
```

**Transport security.**

- `starttls` (the default when `AXONFLOW_SMTP_TLS` is unset) connects in
  plaintext and upgrades. Typical port 587. If the relay does not advertise
  STARTTLS the send **fails**; it never continues unencrypted.
- `tls` is implicit TLS from the first byte. Typical port 465.
- `none` sends the session in the clear. It exists for an internal relay on a
  trusted network, it has to be typed (you cannot reach it by leaving the
  variable unset), and the portal **refuses to start** if you combine it with
  `AXONFLOW_SMTP_USERNAME`: SMTP AUTH PLAIN is base64, not encryption.

There is deliberately no setting that disables certificate verification. If
your relay uses a private CA, supply the CA with `AXONFLOW_SMTP_CA_FILE`.

#### Fail-closed behaviour

The selection has exactly three outcomes, and "silently does nothing" is not
one of them:

| Configuration | Result |
|---|---|
| No transport configured | Noop sender. `POST /api/v1/auth/forgot-password` returns **501**, exactly as before this feature existed. Use the admin reset endpoint. |
| A transport fully configured | Mail is sent. Startup logs which transport is live. |
| A transport **partly** configured | The portal **refuses** to build the sender, logs the specific variable at boot, and the endpoint returns **501**. |

That third row is the important one. Setting `AXONFLOW_SMTP_PORT` and
forgetting `AXONFLOW_SMTP_HOST`, typing `AXONFLOW_SMTP_TLS=tsl`, or giving a
username with no password does **not** quietly fall back to "email disabled" --
it is a named error in the boot log. A silent 501 reads as "the feature was
never built"; a log line reads as "you set two of three variables".

The same applies to the two shared prerequisites. A transport without
`AXONFLOW_FROM_EMAIL`, or without `AXONFLOW_PORTAL_BASE_URL`, is refused in
**every** deployment mode -- including `saas`. Without a base URL every emailed
link would carry a live reset token to `https://app.getaxonflow.com`, a host
you do not control.

#### `SSO_BASE_URL` is now `AXONFLOW_PORTAL_BASE_URL`

The portal's external base URL is used by the emailed reset link **and** by the
SAML ACS / OIDC redirect URLs. Naming it `SSO_BASE_URL` misled deployments that
use password login and no SSO into skipping it, after which reset mail either
refused to start or pointed at the wrong host.

`AXONFLOW_PORTAL_BASE_URL` is the name to use. `SSO_BASE_URL` keeps working as
a deprecated alias, read only when the new name is unset or empty, and logged
once at startup so you know to rename it. If both are set, the new name wins.
Nothing breaks on upgrade: existing deployments that set only `SSO_BASE_URL`
behave exactly as before, and the CloudFormation template renders both names
from the single `PortalExternalBaseURL` parameter.

A value that is nothing but separators (`/`, `//`), or only whitespace, is not
a usable base URL and counts as unconfigured under either name. Precedence is
decided **after** that normalization, so an unusable value under one name never
shadows a working value under the other: if `AXONFLOW_PORTAL_BASE_URL` is `/`
and `SSO_BASE_URL` holds a real URL, the real one is used. That ordering
matters because an unresolved base URL does not mean the same thing everywhere
- password reset refuses to send, but SAML ACS and OIDC redirect URLs fall back
to the AxonFlow SaaS host, which your deployment does not serve.

### SSO/SAML Authentication

SSO requires `SSO_ENABLED=true` (multi-tenant SAML) or `SAML_ENABLED=true` (single-tenant SAML) environment variables on the Portal API.

**Check availability:**

```
GET /api/v1/auth/sso/availability?org_id={org_id}
```

Returns `sso_enabled`, `sso_provider`, `enforce_sso`, and `sso_login_url` if configured.

**SAML login flow:**

1. `GET /auth/saml/{tenantID}/login` -- initiates SAML login redirect to IdP
2. IdP redirects back to `POST /auth/saml/{tenantID}/callback` (ACS endpoint)
3. Portal auto-provisions `portal_users` record on first SSO login
4. Portal creates session and sets `axonflow_session` cookie
5. User is redirected to `/portal/dashboard`

**Supported IdPs:** Okta, Azure AD, Auth0 (configured per-tenant via SSO config API).

**SAML metadata:** Available at `GET /auth/saml/{tenantID}/metadata` for IdP configuration.

## Deployment Modes

### SaaS Mode

- Multi-tenant, AxonFlow-hosted
- Admin API requires `X-Admin-API-Key` header in production (read from `ADMIN_API_KEY` env var)
- Organizations created during customer onboarding by AxonFlow team
- Portal accessible via vanity domain (e.g., `app.getaxonflow.com`)
- Tenant isolation via RLS (row-level security)

### In-VPC Mode

- Customer-managed deployment on customer's AWS account
- Admin API has no auth requirement (customer controls network access)
- Customer creates their org via Admin API after CloudFormation stack deployment
- Portal accessible via ALB domain on port 3000, or custom domain via `setup-vanity-domain.yml`
- Typically single-tenant

## CloudFormation Deployment Notes

The CloudFormation template (`ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml`) includes a `LicenseKeyGenerator` Lambda that creates a license key and stores it in Secrets Manager. However, this Lambda does NOT create the organization in the database.

After stack creation, the admin must call one of:

- `POST /api/v1/admin/organizations` (Method 1, if you have a license key)
- `POST /api/v1/admin/onboard-customer` (Method 2, generates its own license key)

The Portal UI container needs `API_BACKEND_URL` configured to point to the Portal API (port 8090).

## Admin Auth Matrix

| DEPLOYMENT_MODE | ENVIRONMENT | Auth Required for Admin API? |
|-----------------|-------------|------------------------------|
| `saas` | `production` | Yes -- `X-Admin-API-Key` header required |
| `saas` | `staging` | Optional -- respected if sent, anonymous allowed |
| `enterprise` | any | No -- anonymous allowed |
| `in-vpc-*` | any | No -- customer controls network access |
| `community` | any | No (no admin portal in community edition) |

When auth is optional and an invalid key is provided, the request is still rejected (constant-time comparison). Only missing keys are allowed through in optional mode.

**Source:** `ee/platform/customer-portal/middleware/admin_auth.go`

## Verification

### Check Portal UI health

```bash
curl https://{domain}:3000/api/healthz
```

### Check Portal API health

```bash
curl https://{domain}:8090/health
```

### Check deployment configuration

```bash
curl https://{domain}:8090/api/v1/deployment/config
```

Returns deployment mode, feature flags, and environment info. This endpoint is unauthenticated (the frontend needs mode info before login).

### Test password login

```bash
curl -X POST https://{domain}/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"org_id": "test-org", "password": "test-password"}'
```

Note: This goes through the Agent Gateway on port 443/8080 (which proxies to Portal API). You can also hit the Portal API directly on port 8090.

### Check SSO availability

```bash
curl "https://{domain}:8090/api/v1/auth/sso/availability?org_id=acme-corp"
```

## Reading the Audit Logs

The **Audit Logs** page (`/audit`) is the tenant's compliance trail. It has two views:

- **Log Explorer** — a filterable, paginated table of every governed request. Columns
  include timestamp, verdict (Allowed / Blocked / Redacted / Needs Approval / Error),
  **user email**, tenant, request type, matched policy, and latency.
  - **Filters combine.** Narrow by user email (partial match), verdict, and date range
    at the same time; the table and the export both respect the active filters.
  - **Expand any row** (the ▸ chevron, or click the query) to see the full record:
    the query / blocked command, redacted response, matched policy and the reasons it
    fired, and the correlation / decision / session IDs used to stitch a request across
    planes.
- **Report by Action** — per-verdict counts for the selected range (filterable by user).
  Select a verdict card to drill straight into the matching rows in the Log Explorer.

**Redaction is preserved.** Values the engine masked before storage (e.g. an Indonesian
NIK, an email) are shown exactly as stored and are clearly labelled *"Redacted before
storage"*. The portal never reconstructs the original content — there is no "unmask".

**Export.** *Export CSV* / *Export JSON* download the filtered result set (not just the
current page). Large ranges are capped at the server row limit; when that happens the
page warns that the file is partial so you can narrow the range and re-export.

## Related Resources

| Resource | Path |
|----------|------|
| Vanity domain setup | `.github/workflows/setup-vanity-domain.yml` |
| Seed test data | `.github/workflows/seed-test-data.yml` |
| E2E setup script | `scripts/setup-e2e-testing.sh` |
| Portal UI source | `ee/platform/customer-portal-ui/` |
| Portal API source | `ee/platform/customer-portal/` |
| Admin auth middleware | `ee/platform/customer-portal/middleware/admin_auth.go` |
| Auth handler | `ee/platform/customer-portal/api/auth.go` |
| Organizations handler | `ee/platform/customer-portal/api/organizations.go` |
| Onboarding handler | `ee/platform/customer-portal/api/admin.go` |
| Agent proxy (auth routing) | `platform/agent/proxy.go` |
| CloudFormation template | `ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml` |
