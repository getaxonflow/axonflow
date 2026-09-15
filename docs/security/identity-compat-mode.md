# Identity-Compat Mode and the Identity Comparison (retired in v11)

**Platform Version:** v11.0.0. v11.0.0 retires the identity-compat mode: it and its comparison shipped in v10.2.0, dark and `off` by default.

**Status:** Retired. This page states what replaced them and what a deployment that configured them has to change.

**Applies To:** All deployment modes (Community and Enterprise), on both the agent and the orchestrator. The per-organization identity settings and the Shared Signals receiver are **Enterprise only**.

---

## What Changed

From v10.2 to v10.4 the legacy credential paths decided authentication, and the identity-compat mode chose whether the ADR-065 identity plane also resolved the same credential beside them: `off`, `shadow` (recorded only) or, for one organization at a time, `enforce`, where the identity plane could additionally refuse. The comparison recorded where the two differed.

**v11 has no identity-compat mode and no identity comparison.** The identity plane alone decides whether a credential is admitted as the subject a decision is evaluated for, and nothing resolves it the pre-v11 way beside it (PRD v11 §1.3). Nothing records or enforces a second opinion: there is no `off`, no `shadow`, no `enforce`, no per-organization mode and no process flag. How a caller with only a client credential is decided, and why a user token that fails verification is still refused, is on the decision mode's retirement page, [Callers With Only a Client Credential](decision-shadow-mode.md#callers-with-only-a-client-credential).

## If You Configured the Mode

| What you set | What v11 does | What to do |
|---|---|---|
| Any of `AXONFLOW_IDENTITY_COMPAT_MODE`, `_ENFORCE_REASONS`, `_PATHS`, `_AGREEMENT_LOG_EVERY`, set to a non-empty value on the agent or the orchestrator, `off` included | **The process refuses to boot**, and the message names every one that is set | Remove the variable. An empty value is accepted, because earlier compose files and templates pass these variables through empty |
| The CloudFormation parameters `IdentityCompatMode`, `IdentityCompatEnforceReasons`, `IdentityCompatPaths`, `IdentityCompatAgreementLogEvery` | Removed from both templates. CloudFormation rejects a stack update that passes a parameter the template does not declare | Remove them from your parameter overrides before the update |
| `compat_mode` in `PUT /api/v1/admin/organizations/{org_id}/identity-settings` (Enterprise) | **Refused with a 400** that names the retirement | Remove the field from the request |
| A stored per-organization `compat_mode` value | Ignored. The column stays in the schema, unread, until [#4165](https://github.com/getaxonflow/axonflow-enterprise/issues/4165) drops it: during a rolling deploy a v10.x customer portal, which writes it by name, still runs against the migrated schema | Nothing |
| `AXONFLOW_IDENTITY_ORG_SETTINGS_TTL_SECONDS` on the orchestrator | Not read. The orchestrator read the settings only for the comparison; the agent still reads them, [below](#per-organization-identity-settings-enterprise) | Remove it from the orchestrator |
| Dashboards, alerts or log queries on `axonflow_identity_compat_*` or `[IDENTITY-COMPAT]` | The series are no longer exported and the lines are no longer written | Remove the panels, alerts and queries |
| The counter `axonflow_identity_compat_org_settings_read_failures_total` or the alert `AxonFlowIdentityCompatOrgSettingsUnreadable` | Renamed `axonflow_identity_org_settings_read_failures_total` and `AxonFlowIdentityOrgSettingsUnreadable`. The counter counts the same failures and the alert fires on the same condition | Rename them in any query, panel or silence |
| A client that matches `identity_realm_refused` in a `401` body | Never emitted: it marked a refusal by the identity-compat `enforce`, and there is none | Remove the match |

The variables are refused rather than ignored for a reason. Each one chose whether a second authority resolved a credential, which reasons it refused on, which credential paths it saw or how often it logged. A deployment that sets one believes it still does that. A container that will not start is noticed at once; a variable ignored with a log line leaves the deployment running in a posture its own configuration misdescribes.

## An Outage Is Always Reported as an Outage

In v10.x the wording of an outage rejection depended on the mode. With the identity plane running, the Enterprise per-user token validators and the customer portal's SSO login verifier reported a revocation check or a key set that could not be consulted as unavailable; with the mode unset they reported it as an invalid token.

**In v11 an outage is always reported as an outage**, on every deployment. The error names the revocation status or the key material as unavailable (`ErrRevocationUnavailable`, `ErrJWKSUnavailable`), never as an invalid token. The status stays `401` and the credential is still rejected. Only the wording changes, so an IdP key rotation is no longer reported as a forged token.

## Per-Organization Identity Settings (Enterprise)

The per-organization record stays, for the Shared Signals opt-in. It lives in the `identity_org_settings` table created by migration `enterprise/146`. **Do not write the table by hand**: use the admin API, which enforces the table's constraints and the organization scope:

```bash
# Read the current record. 404 when none exists, which is the ordinary state.
GET    /api/v1/admin/organizations/{org_id}/identity-settings

# Create or update it.
PUT    /api/v1/admin/organizations/{org_id}/identity-settings

# Remove it. Idempotent: 204 either way.
DELETE /api/v1/admin/organizations/{org_id}/identity-settings
```

All three are platform-operator routes on the customer portal, behind the existing `X-Admin-API-Key` admin middleware, and every database access is scoped to the named organization. They are not reachable from a tenant session.

On `PUT`, **`caep_enabled` preserves**: omitting it leaves the stored opt-in and its audience exactly as they were, so disabling the opt-in has to be stated explicitly. Setting `caep_enabled: true` without a `caep_audience` is refused with a `400`, because a Security Event Token with no required audience is one any receiver would accept.

**Propagation is bounded by a TTL, not by an event.** The portal writes the row in a different process from the agent that reads it, and there is no invalidation channel between them, so a write takes effect on the agent when its memo window for that organization expires:

```bash
# How long the agent memoizes one organization's record.
# Default 60 seconds, clamped to 1-600. Never fatal: an unparseable or
# out-of-range value falls back to the default.
AXONFLOW_IDENTITY_ORG_SETTINGS_TTL_SECONDS=60
```

Through a storage outage the agent serves **the last row it successfully read** for an organization. For an organization it has never read, the settings read as an outage, and the Shared Signals receiver answers that organization's events `503` so its transmitter redelivers. Every failed read is counted on `axonflow_identity_org_settings_read_failures_total{component}` whether or not a last-good row masked it, and the shipped `AxonFlowIdentityOrgSettingsUnreadable` alert fires on it.

## The Shared Signals (CAEP) Receiver (Enterprise, opt-in)

The agent puts an authenticated HTTP route in front of the OpenID Shared Signals / CAEP intake, so an IdP can push a revocation or session-change event instead of the platform waiting out a cache window:

```
POST /api/v1/identity/caep/events      # on the AGENT
Content-Type: application/secevent+jwt
```

It is **off unless three things all agree**, and each is a separate gate:

1. The build is an **enterprise** build. A community build registers no route at all.
2. The process wired the receiver's three collaborators (the attribute resolver, the tenant OIDC configuration provider and the organization settings store). Otherwise the route is not registered.
3. The organization's `identity_org_settings` row sets `caep_enabled` **with an audience**, which is what makes its OIDC realm declare Shared Signals as its revocation source. The receiver re-reads that row on every request and treats it as authoritative over the realm's memoized declaration, so revoking the opt-in takes effect without waiting for the realm's own window.

Turn it on for one organization with the admin API above:

```bash
curl -X PUT "$PORTAL/api/v1/admin/organizations/acme/identity-settings" \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"caep_enabled": true, "caep_audience": "https://agent.acme.example/caep"}'
```

**The organization is taken from the caller's authenticated credential, never from the event body.** The transmitter authenticates with an ordinary client credential; nothing in the Security Event Token can select a different tenant, which is the property that keeps one customer's IdP from invalidating another customer's sessions.

**No key material is fetched before the event is shown to be plausible.** The issuer is resolved against the realm registry, and the algorithm and key id are checked against the realm, before the JWKS is touched, so a token from an undeclared issuer, or one carrying `alg=none`, cannot make the process make a network call. For the only realm kind that can carry Shared Signals the allow-list is `RS256`, and verification is RSA/SHA-256 against the realm's own key set. The JWS `typ` must be `secevent+jwt`. Only an `iss_sub` subject whose issuer equals the realm's canonical issuer becomes a principal; every other RFC 9493 subject format is refused.

Refusals carry the RFC 8935 `{"err","description"}` body, and **the status tells a transmitter which of the two things to do**:

| Status | Meaning for the transmitter | Examples |
|---|---|---|
| `202` | accepted (also the answer to a redelivered `jti` inside the 30-minute window, which is acknowledged without being applied twice) | |
| `400`, `403` | **stop; do not redeliver.** The event is wrong, or this organization is not opted in | wrong content type, unparseable or oversized token, bad `typ`, undeclared issuer, disabled realm, disallowed algorithm, wrong audience, unknown key, bad signature, out-of-range times, unusable subject, realm not opted in |
| `503` | **redeliver.** The receiver could not act yet | realm source, settings row, OIDC configuration or key set unreadable; and a cache invalidation that FAILED, which is deliberately not acknowledged so the event is sent again |

**What an applied event actually does.** The subject is mapped to the emails the organization's SCIM directory holds for it, under that organization's scope, and each one's cached governance segment set is invalidated, so a revocation at the IdP takes effect without waiting out the segment cache TTL, which is the reason to wire this up at all. A subject the directory does not know (no `scim_users.external_id` match) drops the organization's whole cached segment set instead, so nothing about it can stay live. A directory lookup that **fails** is answered `503` rather than swallowed: falling back to an organization-wide drop would report success for an event the platform could not attribute, and a directory outage would then read as a burst of successful revocations.

Two Prometheus counters are exported on the agent's **`/prometheus`** endpoint (not `/metrics`, which is a separate JSON summary): `axonflow_identity_caep_push_total{outcome,stage}`, where `outcome` is `applied`, `duplicate` or `refused` and `stage` names the refusing stage, and `axonflow_identity_caep_invalidations_total{scope}`, where `scope` is `subject` (the directory resolved it) or `org` (it did not, and the organization-wide drop was taken).

## Related

- `technical-docs/product/PRD_V11_POLICY_DECISION_PLANE.md` §1.3 and §5.1: the v11 definition this page implements (enterprise repository)
- `docs/security/decision-shadow-mode.md`: the decision mode's retirement, and how a decision's subject is admitted
- [Identity-Header Trust Model](identity-header-trust.md): the `AXONFLOW_TRUST_IDENTITY_HEADERS` gate the trusted-header credential path sits behind
- [Require User Token](require-user-token.md): the per-user token requirement
- `CHANGELOG.md`, v11.0.0
