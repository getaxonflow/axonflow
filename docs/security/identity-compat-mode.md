# Identity Compatibility Mode (ADR-065 Identity Plane in Shadow)

**Platform Version:** v10.2.0 (feature introduced in v10.2.0; ships **dark**, mode `off` by default)

**Status:** Active

**Applies To:** All deployment modes (Community and Enterprise), on both the agent and the orchestrator. Per-organization enablement and the Shared Signals receiver are **Enterprise only**.

---

## What This Covers

v10.2.0 carries the ADR-065 identity plane: organization-scoped **trust realms**, canonical realm-qualified **principals**, ordered **actor chains** and a normalized **directory graph** (`platform/shared/identity`). None of that changes how a request is authenticated. What connects it to live traffic is a set of **compatibility adapters** that take what one of the four legacy credential paths already decided and run the same credential through realm verification, producing an independent second opinion about the same request.

| Legacy path | Where it is adapted | Built-in realm |
|---|---|---|
| `api_credential` (Ed25519 license key, bcrypt API key, community-SaaS registration secret, and the internal-service HMAC hop) | agent `Authenticate` | `axonflow-api-credential`, `axonflow-internal-service`, `axonflow-community` |
| `hs256` (AxonFlow-minted per-user tokens: `user_token` / `X-User-Token`) | agent `validateUserToken` and the fleet choke point `ResolveToken` | `axonflow-minted` |
| `oidc` (the tenant's configured OIDC issuer, Enterprise) | the same fleet choke point | `oidc` (one per organization) |
| `trusted_header` (`X-User-ID` / `X-User-Email` behind `AXONFLOW_TRUST_IDENTITY_HEADERS=true`) | agent MCP-server session identity; orchestrator `applyAuthoritativePrincipal` (records only, see below) | `axonflow-trusted-header` |

The built-in realms declare **what the legacy path already enforces**, plus the two invariants a trust realm structurally requires (an expiry is required; an audience is bounded), and nothing else. That is deliberate: a realm declaring an audience the platform never checked, or an assurance floor nobody attested, would make every request diverge and bury the findings that matter.

## The Mode Switch

```bash
# Agent AND orchestrator environment. Default: unset, which is off.
AXONFLOW_IDENTITY_COMPAT_MODE=off      # identity-plane verification does not run
AXONFLOW_IDENTITY_COMPAT_MODE=shadow   # runs, and is RECORDED ONLY
# NOT ACCEPTED (#3633). The process REFUSES to boot on enforce; see below.
# AXONFLOW_IDENTITY_COMPAT_MODE=enforce
```

Parse semantics, and how they differ from `AXONFLOW_TRUST_IDENTITY_HEADERS`:

- unset or empty: `off`. This is the only spelling of "off by omission".
- `off` (also accepted: `false`, `0`, `disabled`) and `shadow`, case-insensitive and whitespace trimmed: that mode.
- **`enforce` is REFUSED at boot, by name** (#3633). The process-wide flag has no per-organization dimension, so a process-wide enforce begins refusing requests on **every organization at once**, before any shadow phase has measured what it would refuse - and the divergences it refuses on are per-`(organization, path)` constants rather than tail events, so the blast radius is a whole population rather than a tail. The refusal names the route that exists instead: **enforcement is granted per organization** (below), where it is gated on that organization already being in `shadow` with a non-zero observed denominator, zero unexplained divergences, and `AXONFLOW_IDENTITY_COMPAT_ENFORCE_REASONS` set. This mirrors the decision axis, whose `AXONFLOW_DECISION_SHADOW_MODE` has always refused `enforce` by name.

  **Rollback width:** the process flag rolls the whole deployment between `off` and `shadow`. Per-organization enforcement rolls back one organization with a single call, without a redeploy.

  Because the process refuses it, `enforce` is **not offered** on any deployment surface either: the CloudFormation `IdentityCompatMode` parameter lists only `''`, `off` and `shadow`, so a change set carrying `enforce` is rejected before a container is ever replaced.
- **anything else is FATAL at boot.** The process logs the value and exits. `AXONFLOW_TRUST_IDENTITY_HEADERS` treats a typo as `false` with a warning, because its safe direction is "ignore the header". This flag has no safe direction to fall back to: `off` would leave an operator who typed `shdaow` believing their deployment records, and guessing a stricter mode would take authentication down on a typo. A deployment that will not start is the one failure an operator notices immediately.

**Set it on both services.** The agent binds a caller's principal from every credential path; the orchestrator binds one from the trust-gated identity headers (and notes at boot whether a SCIM-backed directory is wired, so the built-in realms declare the directory source the deployment actually has). A value on one and not the other is exactly the "consulted in some planes and not others" split the adapter exists to prevent. `docker-compose.yml`, `docker-compose.enterprise.yml` and `docker-compose.scaled.yml` carry all **four** compat variables on both services; `AXONFLOW_IDENTITY_ORG_SETTINGS_TTL_SECONDS` (below) is carried on both services in the first two but **not** in `docker-compose.scaled.yml`, where the 60-second default applies and cannot be tuned from compose. `docker-compose.community-saas.yml` and `docker-compose.test.yml` do not pass any of them through, and the CloudFormation stack templates carry parameters for the mode, the enforce-reason allow-list, the agreement log rate and the per-path lever (`IdentityCompatMode`, `IdentityCompatEnforceReasons`, `IdentityCompatAgreementLogEvery`, `IdentityCompatPaths`) on both the community-SaaS and marketplace templates, so an ECS deployment sets them at change-set time. `IdentityCompatMode` offers only `''`, `off` and `shadow` — `enforce` is refused by the binaries at boot and is therefore not advertised (#3633). `IdentityCompatPaths` defaults to empty, which means every path; its `AllowedPattern` enumerates the four declared path names, so a typo is rejected at change-set time rather than becoming a container that never converges. `AXONFLOW_IDENTITY_ORG_SETTINGS_TTL_SECONDS` remains compose-only.
### Narrowing to specific credential paths

```bash
# Absent (the default) evaluates EVERY path — the only complete window.
AXONFLOW_IDENTITY_COMPAT_PATHS=hs256,oidc
```

The declared paths are `hs256`, `oidc`, `api_credential` and `trusted_header`.
A path **omitted** from the list evaluates as `off` **for that path only**: it
records nothing, refuses nothing, and takes the identical early return an `off`
mode takes — no clock read, no registry touch, no recorder call.

**Why the lever exists.** The failure that actually happens is one path going
wrong for everyone: a fleet asserting only an email on `trusted_header`, an IdP
whose JWKS endpoint starts timing out on `oidc`. Without this, the only remedies
are lowering an organization (which loses its other three paths) or lowering the
deployment (which loses the window entirely) — neither proportionate to "one
credential path is noisy", and both discarding measurements that were fine.

**An unrecognised path is FATAL at boot**, exactly as `AXONFLOW_DECISION_SHADOW_PLANES`
is on the decision axis. Case and surrounding whitespace are normalised
(`Trusted_Header ` is fine), but a name that matches nothing — `trusted-header`
with a hyphen — refuses to boot rather than being dropped: a list that silently
omitted the entry would measure three paths while its author read four. Note
this is stricter than `AXONFLOW_IDENTITY_COMPAT_MODE`, which accepts `false`,
`0` and `disabled` as spellings of `off`; a *mode* is a posture written by hand,
where synonyms are kind, and a *path list* is a set of identifiers, where they
are how a typo becomes a silent narrowing.

**An empty list is refused too.** Unset means every path; a list naming none
would evaluate nothing while reading as configured. Those are opposite postures
and one is reachable by accident (a trailing comma, an unset shell variable), so
it is refused rather than honoured.

| | Rollback width | Takes effect |
|---|---|---|
| `AXONFLOW_IDENTITY_COMPAT_PATHS` | one **credential path**, deployment-wide | restart |
| `AXONFLOW_IDENTITY_COMPAT_MODE` | the whole **deployment** (`off` / `shadow`) | restart |
| per-organization record | one **organization**, all its paths | settings TTL, no restart |

**Set it on both services.** The agent binds a caller's principal from every credential path; the orchestrator binds one from the trust-gated identity headers (and notes at boot whether a SCIM-backed directory is wired, so the built-in realms declare the directory source the deployment actually has). A value on one and not the other is exactly the "consulted in some planes and not others" split the adapter exists to prevent. The wiring is the same for the lever as for the mode: `docker-compose.yml`, `docker-compose.enterprise.yml` and `docker-compose.scaled.yml` carry it on both services, and both CloudFormation templates expose it as `IdentityCompatPaths`. See the paragraph under **Set it on both services** above for the full per-file picture, which this section previously restated in a copy that had gone stale.

## Per-Organization Enablement (Enterprise)

The process flag above is the deployment-wide default. On an **Enterprise** deployment the same mode is also settable **per organization**, which is the recommended way to start: it bounds the blast radius of a first look to one tenant and is reversible with a single call.

A per-organization record **wins over the process flag in both directions**. It can raise one organization to `shadow` (or, once gated, `enforce`) on a deployment that is otherwise `off`, and it can lower one organization to `off` on a deployment running `shadow`. **It is the only route to `enforce` at all**, since the process flag refuses it. An organization with **no** record runs on the process flag, and that is byte-for-byte the behaviour of every release before v10.2.0.

Resolution happens in exactly one function, `effectiveMode`, which composes the two inputs and is the only reader of either. Three cases all resolve to the process flag: no record exists, the record could not be read, and the record names a mode the reader does not accept. Only the last two are counted and logged, because an absent record is the ordinary state and not a fault.

**Community builds wire no source at all.** The composition machinery ships on the community mirror, but `effectiveMode` returns the process flag on its first branch and performs no lookup, so on Community the process flag is the whole story.

### The management surface

Records live in the `identity_org_settings` table created by migration `enterprise/146` (Enterprise only; a community deployment applies nothing). **Do not write the table by hand** - use the admin API, which enforces both CHECK constraints and the organization scope:

```bash
# Read the current record. 404 when none exists, which is the ordinary state.
GET    /api/v1/admin/organizations/{org_id}/identity-settings

# Create or update it.
PUT    /api/v1/admin/organizations/{org_id}/identity-settings

# Remove it, so the process flag decides again. Idempotent: 204 either way.
DELETE /api/v1/admin/organizations/{org_id}/identity-settings
```

All three are platform-operator routes on the customer portal, behind the existing `X-Admin-API-Key` admin middleware, and every database access is scoped to the named organization. They are not reachable from a tenant session.

### Raising an organization to `enforce`

`enforce` is the one mode that can refuse live traffic, so the `PUT` above does
not simply store it. It is granted only when **all four** hold, and refused with
**409** and a machine-readable `reason` otherwise:

| Precondition | `reason` on refusal | What to do |
|---|---|---|
| The organization is currently in `shadow` | `org_not_in_shadow` | Put it in shadow first. Enforcement is entered from a measured shadow phase, never in one step from `off` — and an organization with **no record** runs on the process flag, which is never `enforce`, so it has no shadow phase of its own to have completed. |
| It has a non-zero **organic** comparison count | `org_not_measured` | Run real traffic through it. Synthetic (canary) comparisons are deliberately excluded: a canary exists to give the window a denominator, so letting it satisfy this would unlock enforcement for traffic nobody has served. |
| It has **zero** unexplained divergences | `org_still_diverging` | Drive the named divergence classes to zero in shadow. The refusal names them. |
| The deployment sets `AXONFLOW_IDENTITY_COMPAT_ENFORCE_REASONS` | `enforce_reasons_unset` | Name the reasons you have driven to zero. Unset means enforcement would refuse on **every** enforceable reason at once. |

The two observed preconditions are read from Prometheus counters the agent
exports:

| Metric | What it answers |
|---|---|
| `axonflow_identity_compat_org_comparisons_total{org,synthetic}` | the **denominator** — was this organization measured at all. Read with `synthetic="false"`, so a canary cannot satisfy it. |
| `axonflow_identity_compat_org_divergences_total{org,synthetic,divergence}` | the **numerator** — is it still diverging, and in which class. |

They are read **in that order**, and the order is the soundness argument rather
than a preference: a `CounterVec` with no children exports no series, so an
absent divergence series is equally consistent with "nothing diverged" and
"nothing ran". Only a non-zero organic denominator makes the absence readable as
zero. A dashboard built on the divergence metric alone would present an
organization nobody has measured as one that is ready to enforce.

Recording rules for both are in `platform/monitoring/rules/identity-compat.rules.yml`
(`axonflow:identity_compat_org_comparisons:increase1h` and
`axonflow:identity_compat_org_divergences:increase1h`).

A fifth reason, `precondition_unavailable`, means the portal could not **ask** —
the agent was unreachable, answered a non-200, or returned something that did
not parse. It is deliberately distinct from the four above: "we could not check"
needs a different remedy from "this organization is not ready", and the request
is **refused** rather than granted, so a broken internal call can never become
the easiest way to enable enforcement.

The observed preconditions are read from the agent, not from the portal, over
the internal-service channel:

```
GET /api/v1/identity/internal/enforce-precondition?org_id={org_id}
```

That route is internal, enterprise-only, read-only, and requires
internal-service credentials — a tenant credential gets **403**. It exists
because the comparison and divergence counters live in the **agent's process**
and the enforce-reason allow-list is wired onto the agent and the orchestrator
and deliberately not onto the portal; a portal-side read would compile, find
nothing, and refuse every organization for ever.

**Rollback is one call and takes effect within the settings TTL:** `PUT` the
organization back to `shadow` or `off`, or `DELETE` the record to fall back to
the process flag. Lowering is never gated — only raising is.

Put one organization into shadow:

```bash
curl -X PUT "$PORTAL/api/v1/admin/organizations/acme/identity-settings" \
  -H "X-Admin-API-Key: $ADMIN_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"compat_mode": "shadow"}'
```

Two merge rules on `PUT` are worth knowing before you use it:

- **`compat_mode` clears.** Absent or null removes the per-organization mode, so the deployment flag decides again. This is the same effect as `DELETE` for that field.
- **`caep_enabled` preserves.** Omitting it leaves the stored Shared Signals opt-in and its audience exactly as they were. Disabling the opt-in has to be stated explicitly. Setting `caep_enabled: true` without a `caep_audience` is refused with a `400`, because a Security Event Token with no required audience is one any receiver would accept.

### Propagation is bounded by a TTL, not by an event

```bash
# How long the agent and the orchestrator memoize one organization's record.
# Default 60 seconds, clamped to 1-600. Never fatal: an unparseable or
# out-of-range value falls back to the clamped default.
AXONFLOW_IDENTITY_ORG_SETTINGS_TTL_SECONDS=60
```

The portal writes the row in a different process from the agent and the orchestrator that read it, and **there is no invalidation channel between them**. A write therefore takes effect on each reading process only when its memo window expires, up to the TTL. The `PUT` and `DELETE` responses carry a `propagation` string naming that bound. Lower the TTL while you are iterating on a rollout; raise it if the read volume matters more than the latency of a change.

Through a storage outage the store serves **the last row it successfully read**, rather than reporting an absence, so an organization does not silently fall back to the deployment default the moment the database blinks. If it has never read a row for that organization, the process mode applies and the failure is logged once per window.

An Enterprise deployment that upgrades the binaries but has **not yet applied `enterprise/146`** keeps its previous behaviour for the same reason: every settings read fails, is counted, and falls back to the process mode.

### Companion variables

```bash
# Narrows what `enforce` refuses to a comma-separated allow-list of reason codes.
# Empty (default) means every reason. It can only NARROW: a reason not on the
# list is recorded exactly as it would be in shadow. An unrecognized code is
# fatal at boot, like an unrecognized mode, and it is parsed in EVERY mode, so
# a typo here stops the process even with the mode unset.
AXONFLOW_IDENTITY_COMPAT_ENFORCE_REASONS=UNKNOWN_REALM,ORG_BINDING_MISMATCH

# How many AGREEMENTS pass between sampled agreement log lines. Default 100000.
# Set it to 1 while reading a shadow phase, so "the adapter ran on this path and
# agreed" is distinguishable from "the adapter never ran"; 0 disables agreement
# lines entirely (the counters still move). An unparseable value falls back to
# the default with a warning; it is never fatal, because it decides how chatty
# a log line is and not whether authentication changes.
AXONFLOW_IDENTITY_COMPAT_AGREEMENT_LOG_EVERY=1
```

The reason allow-list is one of the two **staged rollout** axes, and it stays **process-wide** even where the mode itself is set per organization (below): it applies whenever the RESOLVED mode is `enforce`. The two axes are independent - the per-organization record chooses WHICH tenants run the plane, the allow-list chooses WHICH reasons refuse. The divergences this plane surfaces are per-(organization, path) constants rather than tail events: a plugin fleet asserting only an email produces `SUBJECT_MISSING` on every request it makes, and an organization with no enabled SSO row produces `UNKNOWN_REALM` on all of its token traffic. Enforce the reasons you have driven to zero in shadow; keep recording the rest.

## Behavior Per Mode

| | `off` (default) | `shadow` | `enforce` |
|---|---|---|---|
| Legacy authentication decides the request | yes | yes | yes, and the identity plane may additionally refuse |
| Identity-plane verification runs | no. `Resolve` returns before consulting the registry or the recorder, and nothing it produces is observed, stored, forwarded or logged | yes | yes |
| Counterfactual recorded | nothing | every evaluation (agreements sampled, divergences always) | every evaluation, plus `enforced=true` on applied refusals |
| What a caller sees | legacy behavior, unchanged | legacy behavior: the authentication outcome (status, error, blocked) is identical to `off`, request for request, except that on the Enterprise outage legs a `401` body carries the outage wording (see [the one caller-visible effect](#the-divergences-to-expect)) where `off` carries 10.1.0's bytes | a `401` (a `403` on the audit-verification read authority) where the identity plane does not admit a credential legacy accepted; renderings under [What enforce refuses](#what-enforce-refuses) |
| Orchestrator trusted-header plane | records nothing | records | **records and never acts** (see below) |

Two invariants hold in every mode:

1. **The adapter can only ever refuse.** It has no path that turns a legacy rejection into an acceptance. A credential the legacy path rejected reaches realm verification with `signature_verified=false` and is denied for exactly that reason, so "the identity plane admitted what legacy rejected" is unreachable rather than unlikely, and it carries its own `ALARM` log line if it ever fires. The worst a misconfigured `enforce` deployment can do is deny requests legacy would have served.
2. **No call site reads the mode.** Every enforcing call site is one line, `CompatResolve(ctx, legacy).Refusal()`, and the refusal is constructed in exactly one function under the mode check. A call site cannot forget the mode because there is no mode for it to forget. Since v10.2.0 the package reads it in exactly **one** function, `effectiveMode`, which composes the process flag with the organization's record and is the only reader of either input; an AST census fails the build on any other reader. `Resolve`, which owns admission, and `outageSentinelsActive`, which decides no admission - it only selects the wording of the outage errors below, and every branch it selects between rejects the credential, in every mode - both read the value that one function returns.

**Why the orchestrator plane never enforces.** Clearing the actor on a refusal looks fail-closed and is not: the shipped `policy_defaults.go` carries a `{user.role equals "evaluation"} -> modify_risk` condition, so clearing the role stops that modifier applying and the request is scored *lower*. It would also destroy a role established by the validated-token channel over a refusal about the header one. The credential that plane sees is enforced where it is authenticated, on the agent.

## What Shadow Records

The shadow phase's only product is the counterfactual record. It is written to the process log under the `[IDENTITY-COMPAT]` prefix. The recorder keeps counters behind it (by divergence, and divergences by path), but nothing in either process exposes them: **no exporter for the shadow counters ships in v10.2.0** (see [Not Covered](#not-covered-in-v1020)), so the log is the surface to read. The two Prometheus counters v10.2.0 does export belong to the Shared Signals receiver alone and say nothing about the shadow phase.

At startup, always:

```
[IDENTITY-COMPAT] agent: AXONFLOW_IDENTITY_COMPAT_MODE=shadow (identity-plane verification runs and is RECORDED ONLY; legacy authentication decides every request)
```

Per divergence, per indeterminate outcome, and per enforced refusal, always:

```
[IDENTITY-COMPAT] component=agent mode=shadow path=hs256 org=acme divergence=identity_refused legacy=accepted legacy_reason="" identity=DENY/UNKNOWN_REALM detail="issuer \"https://idp.example\" has no declared trust realm in this organization; a validly signed credential is not a declared one" realm= principal= epoch=0 enforced=false
```

| Field | Meaning |
|---|---|
| `component` | which binary recorded it (`agent`, `orchestrator`) |
| `mode` | the mode the process was running in |
| `path` | the legacy path: `api_credential`, `hs256`, `oidc`, `trusted_header` |
| `org` | the authenticated organization |
| `divergence` | `none` (agreement); `identity_refused` (legacy accepted, identity plane denied); `identity_indeterminate` (legacy accepted, identity plane could not tell); `identity_admitted_legacy_rejected` (the unreachable direction, always accompanied by an `ALARM` line); `adapter_defect` (the adapter was handed input it could not evaluate); `not_evaluated` |
| `legacy` / `legacy_reason` | what the legacy path decided and, on a refusal, why. Never credential material |
| `identity` | the identity plane's admission state and reason code |
| `detail` | **the field that makes the record actionable**: the issuer that has no realm, the claim that was absent, the audience that did not intersect. Never surfaced to a caller |
| `realm` / `principal` / `epoch` | the realm and canonical principal the identity plane resolved, and the realm registry's epoch at the time |
| `enforced` | whether this record was applied as a refusal (`enforce` only) |

Agreements are counted and logged once per `AXONFLOW_IDENTITY_COMPAT_AGREEMENT_LOG_EVERY`. **Divergences are never sampled**: the classes below are per-(organization, path) constants rather than tail events, so an organization whose token traffic all diverges on one class (every request from a fleet asserting only an email, say) writes one line per request until that class is cleared. Read the expected volume before enabling shadow on a high-traffic deployment. An **indeterminate** outcome is logged individually even when the two planes agree, because "your IdP is unreachable" and "your revocation store is down" both arrive as agreements and are the operationally sharpest records this plane produces.

Every caller-influenced field is sanitized before it reaches the log, so a newline in an asserted header cannot inject lines.

### The divergences to expect

Each of these is a real fact about the installed platform, not an artifact of the realm declarations:

| Reason | What it means | Where it comes from |
|---|---|---|
| `UNKNOWN_REALM` | the credential's issuer is declared by no realm | the legacy per-user token path does not require an issuer the deployment has declared. This is the single largest expected divergence and the whole point of the plane; declare a realm for every issuer you mint or accept |
| `ORG_BINDING_MISMATCH` | the token asserts an `org_id` other than the credential's | the legacy path reads the organization claim without binding it to the credential that authenticated; the identity plane binds the two |
| `REVOCATION_UNAVAILABLE` | a realm declares a revocation source and the credential carries no revocation key (`jti`), or the revocation lookup itself failed | the agent's per-user token path treats a `jti`-less token as unrevocable-and-therefore-fine (the fleet validator already requires `jti`); the identity plane calls it indeterminate |
| `SUBJECT_MISSING` | the trusted-header upstream asserted only `X-User-Email` | an email is an **alias**, never an identifier (ADR-065 invariant 3). A trusted-header deployment that wants a canonical principal has to assert a stable subject (`X-User-ID`); one that asserts only an address gets attribution, not identity |

You will also see **indeterminate agreements** logged individually, which are not divergences: `KEY_MATERIAL_UNAVAILABLE` (the verifying key set could not be obtained: JWKS unreachable, or cached keys past the staleness bound). Both planes reject that credential, so the two agree, but it is logged on every occurrence because it is an **outage, not a forgery**, deliberately distinct from a signature failure so an operator paged for it goes looking at their IdP rather than for forged tokens.

**The one caller-visible effect of enabling shadow rides the same distinction, and it is deliberate.** With the identity plane running (shadow or enforce), the Enterprise fleet per-user token validators (`hs256_validator.go`, `oidc_verifier.go`) and the portal SSO login verifier (`IDTokenVerifier.Verify`) word an outage as an outage: a revocation check or JWKS that cannot be consulted carries `ErrRevocationUnavailable` / `ErrJWKSUnavailable` and says the revocation status or the key material is unavailable, where with the mode unset every one of those errors emits 10.1.0's exact bytes and `errors.Is` semantics (pinned by `compat_flagoff_bytes_test.go`). The status stays `401`, the verdict stays a rejection, in every mode; only the wording of an outage rejection changes, so an IdP key rotation stops being reported as an invalid token. The gate is `outageSentinelsActive` (invariant 2 above), which decides no admission.

Two further classes are latent rather than live: a token carrying no `exp` is refused as `CREDENTIAL_EXPIRED` (both production minters stamp one), and a token minted for a different audience is refused (neither production minter sets `aud`).

## What `enforce` Refuses

Only a credential the legacy path **accepted** that the identity plane did **not admit**, for a reason on the allow-list (or any reason, if the list is empty). The refusal is a `401` on every adapted agent path except the audit-verification read authority, which keeps its existing `403`. **There is no machine-readable refusal code on the wire in v10.2.0**: the internal `AuthError.Code` is set to `identity_realm_refused`, but no renderer emits that field, so what a caller can match on is the message text, and it differs by rendering:

| Adapted site | What the caller receives |
|---|---|
| API and proxy middleware (`Authenticate`) | `401`; message `Authentication refused by the identity plane (REASON). The credential authenticated, but ...`. The string `identity_realm_refused` is NOT in the body |
| Per-user token path (`validateUserToken` via `ResolveUser`) | `401`; message `Invalid user token: identity_realm_refused: ...` |
| Fleet choke point (`ResolveToken`) via the MCP REST routes | `401`; `{"error": "invalid user token: identity_realm_refused: ..."}` |
| MCP-server session (`authenticateMCPSession`, and `ResolveToken` on that plane) | `401` JSON-RPC error on `initialize` whose message begins `invalid user token: identity_realm_refused:` (trusted-header refusals: `identity_realm_refused: upstream-asserted identity refused ...`); every non-`initialize` call on a refused session answers the generic `Authentication required` with no refusal string |
| Audit-verification read authority (`auditVerificationAuthorized`) | the existing `403`, no string; this site returns a boolean and has no error channel |

Previously an identity-plane refusal would have shared `invalid_user_token` with a tampered signature, so "my realm configuration is wrong" and "someone is forging tokens" were indistinguishable. The message text now distinguishes an identity-plane refusal on four of the five renderings (the API and proxy body says so in words) and carries the `identity_realm_refused` token on three; a code field on the wire is owed (routed on #3566).

**"Did not admit" includes two indeterminate outcomes.** With an empty allow-list, `enforce` also refuses on `REVOCATION_UNAVAILABLE` (a `jti`-less token on the agent's per-user token path under a realm declaring a revocation source, or the adapter's own revocation lookup failing; the fleet validator already requires `jti`, so on that path a `jti`-less token is a legacy rejection and nothing is added) and on `IDENTITY_INTERNAL_ERROR` (the organization's trust realms could not be established, for instance an unreadable SSO configuration row, for a credential whose issuer is not already declared; or a realm re-declared mid-verification). `KEY_MATERIAL_UNAVAILABLE` is accepted in the allow-list but inert there: a JWKS outage is already a legacy rejection, and the adapter never refuses what legacy refused. This is the reason to list the reasons you enforce rather than enabling `enforce` bare: an operator who wants realm and organization binding enforced while `jti`-less tokens and realm-source outages keep being recorded lists `UNKNOWN_REALM,ORG_BINDING_MISMATCH` and leaves the two indeterminate codes off.

### How much to worry about turning it on

`shadow` changes no status, no verdict and no authentication outcome, and is safe to enable on any deployment; the runtime suite for this feature proves the authentication outcome (status, error, blocked) is identical to `off`, request for request, across its 20 assertions - none of which induces an outage. The one thing a caller can observe change in shadow is the outage wording described under [What Shadow Records](#what-shadow-records): an Enterprise `401` for a revocation or key-material outage carries the reclassified message where `off` carries 10.1.0's bytes. `enforce` can only deny, so the risk of enabling it is availability, not exposure: every request the identity plane refuses is one the legacy path would have served. Run `shadow` first, read the divergence records, fix or accept each class, and enable `enforce` with the reasons you have cleared listed in `AXONFLOW_IDENTITY_COMPAT_ENFORCE_REASONS`.

## The Shared Signals (CAEP) Receiver (Enterprise, opt-in)

v10.2.0 puts an authenticated HTTP route in front of the OpenID Shared Signals / CAEP intake, so an IdP can push a revocation or session-change event instead of the platform waiting out a cache window:

```
POST /api/v1/identity/caep/events      # on the AGENT
Content-Type: application/secevent+jwt
```

It is **off unless three things all agree**, and each is a separate gate:

1. The build is an **enterprise** build. A community build registers no route at all.
2. The process wired the receiver's three collaborators (the attribute resolver, the tenant OIDC configuration provider and the org settings store). Otherwise the route is not registered.
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

**What an applied event actually does.** The subject is mapped to the emails the organization's SCIM directory holds for it, under that organization's scope, and each one's cached governance segment set is invalidated - so a revocation at the IdP takes effect without waiting out the segment cache TTL, which is the reason to wire this up at all. A subject the directory does not know (no `scim_users.external_id` match) drops the organization's whole cached segment set instead, so nothing about it can stay live. A directory lookup that **fails** is answered `503` rather than swallowed: falling back to an organization-wide drop would report success for an event the platform could not attribute, and a directory outage would then read as a burst of successful revocations.

Two Prometheus counters are exported on the agent's **`/prometheus`** endpoint (not `/metrics`, which is a separate JSON summary): `axonflow_identity_caep_push_total{outcome,stage}`, where `outcome` is `applied`, `duplicate` or `refused` and `stage` names the refusing stage, and `axonflow_identity_caep_invalidations_total{scope}`, where `scope` is `subject` (the directory resolved it) or `org` (it did not, and the organization-wide drop was taken). These are the receiver's own counters and say nothing about the shadow phase.

## What `enforce` Will Mean at v11

The ADR-065 release plan cuts every enforcement plane over to the new policy decision point in **one major release, v11.0.0**, with default deny and a time-bound compatibility profile. For the identity plane that means:

- the canonical `(realm, subject)` principal becomes the identity every decision is evaluated against, and the legacy `validateUserToken` issuer-less path stops being an independent authority;
- the shadow-observed divergences above must be at **zero unexplained** for the agreed observation window before the cutover (ADR-065 acceptance gate 18 applied to identity);
- a deployment arriving at v11 from v10.x without having run `shadow` receives the compatibility profile window rather than silent breakage.

Nothing in v10.2.x cuts a plane over. The mode switch is how an operator prepares: enable `shadow` during v10.2.x, drive the divergence classes to zero, then enable `enforce` with the reason allow-list ahead of v11. The compatibility adapters exist only to bridge the legacy credential paths; the release plan retires the legacy evaluators and compatibility profiles at v12.0.0, and the adapters have no purpose past that point.

## Not Covered in v10.2.0

Named here so the gap is visible rather than assumed closed:

- **The customer-portal authentication surfaces** (OIDC and SAML login, SCIM, the portal middleware): no realm verification runs there. The honest reasons to defer are that the portal is its own Go module with its own regression surface, and that SAML is a fifth credential class with no `CredentialType` yet - NOT import feasibility: the portal can and does import `platform/shared` (23 of its files import `platform/shared/identity`). One portal surface is already partially covered: the portal SSO OIDC login verifier classifies a JWKS-unavailable failure as an outage under the same mode gate (above), so with the plane running an IdP key rotation during login stops being reported to the user as an invalid id_token.
- **Further in-process `X-User-Email` readers** (overrides, explain, the MAP HITL adapter, read scope, reviewer binding, circuit breaker, the static policy API handlers, workflow control). They are downstream of an adapted decision under both postures; consolidating them onto one choke point is its own change.
- **An exporter for the shadow counters.** The recorder's divergence counters, the per-organization mode fall-back count and the settings store's read-failure count exist in-process and nothing exports them; the log is still the surface to read. The two Prometheus counters v10.2.0 does export cover the Shared Signals receiver alone.
- **A cross-process invalidation channel.** An admin write reaches the reading processes only when their memo window expires (above).
- **`AXONFLOW_IDENTITY_ORG_SETTINGS_TTL_SECONDS` in `docker-compose.scaled.yml`**, and a CloudFormation parameter for it. It is the last compat variable without one: the mode, the enforce-reason allow-list, the agreement log rate and the per-path lever all have parameters on both templates.
- **A correlation id** joining the four to six records one request produces across two processes.
- **Realm-registry persistence**, which needs a migration number the operator allocates. `enterprise/146` covers the per-organization settings row and nothing else.
- **Per-organization enablement on Community.** The composition machinery ships, but no source is wired, so the process flag is the whole story there.

## Related Pages

- [Identity-Header Trust Model](identity-header-trust.md): the `AXONFLOW_TRUST_IDENTITY_HEADERS` gate this flag's `trusted_header` path sits behind.
- [Require User Token](require-user-token.md): the per-user token requirement the `hs256` and `oidc` paths verify.
- ADR-065 (policy decision and identity control plane) and its implementation guide, which live under `technical-docs/` in the enterprise repository and are not carried on the community mirror.
