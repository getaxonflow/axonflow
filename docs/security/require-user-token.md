# Require User Token (Closing Identity Suppression on Segment-Scoped Policies)

**Platform Version:** Unreleased (targeting the next MAJOR train; #3476)

**Status:** Active

**Applies To:** Enterprise deployments (community mode is unaffected - see
[Which Planes Enforce It](#which-planes-enforce-it))

---

## What This Covers

AxonFlow's governance planes authenticate most fleet traffic with a single
**shared credential** - an org/license Basic-auth pair, or an org-scoped
Enterprise service license. Behind that one credential can sit many human
principals, each optionally forwarding a **per-user token** (`user_token` in
a request body, or the `X-User-Token` header on the MCP-server plane) that
proves who they are.

Before this control, presenting that per-user token was **optional** on
every enterprise gate point. A caller who sent none was never refused for
lacking an identity - it was synthesized a shared service identity
(`<client-id>@axonflow.local`, `Role: "service"`) and served anyway. For most
traffic that is the correct, backward-compatible answer: an infrastructure
gateway acting as a Policy Enforcement Point has no end-user JWT to forward,
and there is nothing wrong with governing it as a service.

It stops being correct the moment an organization adopts
**segment-scoped policies** (ADR-060, `static_policies.segment_id`, SCIM
group membership). A segment-scoped policy restricts a caller AxonFlow can
identify as a member of some group. A caller AxonFlow cannot identify at all
resolves to **no segments** - which is the deliberately safe, restriction-only
answer for a genuine non-member (see
[`identity-header-trust.md`](./identity-header-trust.md) and
`runtime-e2e/3430_mcp_human_segment` for why a nil/empty segment set must
never itself deny). But a nil segment set is safe for the **policy** and
dangerous for the **plane**: nothing stopped a member who did not want to be
governed from simply not presenting the token that would have identified
them as one. Dropping a single header switched the control off for exactly
the person it was written to restrict.

**This is an authentication problem, not a policy problem.** ADR-060's
combining rule (a request is scoped to the caller's real, resolved segment
set, restriction-only) is unchanged by this control and remains correct. The
fix is not to make policy evaluation guess at an unresolved identity - it is
to stop letting a caller who has an identity choose not to present it. That
is what `require_user_token` does: it moves the refusal to
**authentication**, before any policy is ever evaluated.

## The Operator Contract

**Segment-scoped policies require per-user tokens, and `require_user_token`
is the switch.**

State this plainly to anyone designing a segment-scoped rollout: **with the
flag off, a segment-scoped policy still enforces against every caller who
presents a token.** It is not inert - a validated per-user-token member is
blocked exactly as authored. It is **evadable**: a member who wants out of
scope can simply not forward the token, and the request is served under the
shared service identity instead of being denied. Turning the flag on for an
org is what makes that evasion impossible - a token-less caller in that org
is refused at authentication and never reaches policy evaluation, so there
is no unresolved-identity path left to exploit.

An organization that has not adopted segment-scoped policies has no reason
to set this flag: it exists to close a gap that only *matters* once a
segment-scoped policy exists, and every gate point's default posture is
identical to how it behaved before this control shipped (see
[Semver](#semver-and-compatibility)).

## Both Levers

| Lever | Scope | Type | Default |
|---|---|---|---|
| `organizations.require_user_token` (mig 163) | Per-org | `BOOLEAN NOT NULL` | `false` |
| `AXONFLOW_REQUIRE_USER_TOKEN` | Deployment-wide | env var (`true`/`1`/`yes` vs `false`/`0`/`no`, case-insensitive; unset or unrecognized falls back to `false`) | `false` |

The **per-org column** is for a shared, multi-tenant deployment (SaaS, or one
self-hosted install serving several orgs) where only some orgs have adopted
segment-scoped policies. The **env var** is a deployment-wide default,
useful for a single-org self-hosted install that wants the posture set once
and left alone.

**An explicit per-org row wins over the env default in EITHER direction.**
An org can opt OUT of a deployment-wide `true` default just as it can opt IN
over a deployment-wide `false` default - the column, when present, is always
authoritative for that org.

## The Full Resolution Decision Table

`ResolveRequireUserToken(ctx, orgID)` (`platform/agent/require_user_token.go`)
resolves in this order:

| Case | Org row state | Result | Notes |
|---|---|---|---|
| 1 | Row exists, `require_user_token = true` | **`true`** | Explicit opt-in wins over any env default |
| 2 | Row exists, `require_user_token = false` | **`false`** | Explicit opt-out wins over an env default of `true` |
| 3 | Row genuinely absent (`sql.ErrNoRows`) | The deployment's `AXONFLOW_REQUIRE_USER_TOKEN` default | **Not an error.** "No row" means "no per-org posture set," not "posture unreadable" |
| 4 | No database wired at all (community / no-DB topology) | The deployment's `AXONFLOW_REQUIRE_USER_TOKEN` default | Also not fail-closed - there is no posture *store* to fail to read |
| 5 | Query or scan genuinely fails (DB down, table/column absent, driver error) | **`true`** (fail CLOSED) | See [Fail-Closed on an Unreadable Posture](#fail-closed-on-an-unreadable-posture) below |
| 6 | `orgID` is empty (a credential authenticated by a licence carrying no `org_id` claim) | Resolved against `getDeploymentOrgID()` instead | A posture *read* keyed on the deployment's own identity, not a privilege decision - see the function's doc comment for why this cannot be steered by request input |

### Case 3 vs. Case 5: "no row" is not "read failed"

These two cases must never be conflated, because they resolve in **opposite
directions**:

- **"No row" (Case 3)** means the org has never touched this lever. Treating
  it as an error would fail every org WITHOUT a row closed, which breaks the
  compatibility guarantee that an org which has never adopted this control
  behaves exactly as it did before the control shipped.
- **"Read failed" (Case 5)** means the platform cannot currently determine
  the org's posture at all. Resolving that to `false` would silently turn
  the control off for the whole outage window - the opposite of what an
  authentication control must do under uncertainty.

### Fail-Closed on an Unreadable Posture

This is the one place `require_user_token`'s resolver deliberately does
**not** mirror `detection_override.go`'s posture-lookup pattern.
`detection_override.go` governs a *detection* posture, where "keep running
under yesterday's settings" is the safe answer to a lookup failure, so it
fails **safe** to the deployment-global config. `require_user_token` governs
an **authentication** gate: its entire job is to make an org's "callers must
present an identity" promise not optional. A lookup failure that silently
resolved to "not required" would let a DB hiccup quietly disable the control
for every request in the failure window. So on DB down, table/column absent,
schema drift, or any scan error, resolution returns **`true`** (required)
and caches that outcome for a short, bounded window (≤15s, mirroring
`detection_override.go`'s own error-TTL bound) so a failing DB is not
hammered on the hot path - but the cached value during that window is always
the fail-closed `true`, never `false`.

## Which Planes Enforce It

`require_user_token` is wired into **six gate points**, all Enterprise-only
(`AuthKindEnterprise`; community mode never reaches the branch that
resolves this posture at all, so a token-less community caller is never
refused regardless of the flag):

| Plane | File | Refusal shape |
|---|---|---|
| `POST /api/v1/decide` | `decision_handler.go` | `401`, audited `user_token_required` |
| `POST /mcp/resources/query` | `mcp_handler.go` | `401`, audited `user_token_required` |
| `POST /mcp/tools/execute` | `mcp_handler.go` | `401`, audited `user_token_required` |
| `POST /api/v1/mcp/check-input` | `mcp_handler.go` | `401`, audited `user_token_required` |
| `POST /api/v1/mcp/check-output` | `mcp_handler.go` | `401`, audited `user_token_required` |
| MCP-server JSON-RPC plane (`POST /api/v1/mcp-server`) | `mcp_server_handler.go`, `authenticateMCPSession` | `401` at authentication (see below - this plane audits no auth failure at all) |

On the four REST routes and `/decide`, the condition guarding the refusal is
`AuthKindEnterprise && req.UserToken == "" && ResolveRequireUserToken(ctx,
orgID)` - the SAME condition that, when the flag is false, takes the
existing synthetic-service-identity compatibility branch. A **presented**
but invalid token never reaches this branch at all; it is refused by the
pre-existing `user_token_rejected` path (#3472) regardless of this flag.

On the MCP-server plane the condition is `vid == nil &&
ResolveRequireUserToken(ctx, orgID)`, deliberately keyed on `vid == nil`
rather than `perUserToken == ""`. `sharedidentity.ResolveToken` returns
`(nil, nil)` for **two** distinct inputs: no token presented at all, and a
token presented in a deployment where no per-user-token validator is
registered (the pre-existing #2932 fail-safe misconfiguration case). Gating
only on the empty-token case would leave the second one open - an org that
opted in could still be suppressed by presenting any junk string on a
deployment whose validators failed to register. Both are closed by keying on
`vid == nil`.

### The Gateway Pre-Check Plane Is Out of Scope, on Purpose

The gateway pre-check plane (`run.go`'s `clientRequestHandler`, #3312) is
**not** one of the six gate points, and does not need to be: it already
refuses a caller without a valid token **unconditionally**. Any
`ResolveUser` failure is refused as `user_token_invalid`, with no policy
census at all, because this plane never had the synthetic-service-identity
compatibility fallback the six gate points above do. `require_user_token`
exists precisely because that other planes *do* have that fallback; a plane
with no fallback to begin with has nothing for this flag to change.

### `POST /v1/chat/completions` (OpenAI-Compat) Is NOT Covered

The OpenAI-compatible plane keeps its synthetic-service-identity fallback and
this flag does **not** gate it. With `require_user_token = true`, a caller
holding the shared enterprise credential is refused on `/decide` and all four
MCP REST routes, and served on `/v1/chat/completions`.

This is not an oversight in the enumeration, and it is not closeable here. The
endpoint has **no per-user token field on the wire at all** - it calls
`ResolveUser(authResult, "")` with a hardcoded empty token and synthesises an
email from the unvalidated Basic username. Every other gate point refuses a
caller who *could* have presented a token and did not, which is a **migration
ask**: the caller can comply. Here a refusal would be a **wall** - no caller
can comply, because the protocol carries nowhere to put an identity - so
turning the flag on would simply make the endpoint unusable for every
enterprise caller rather than making identity mandatory.

That distinction is the criterion ADR-060's coverage matrix uses to decide
which planes are resolvable today and which need the verified machine/agent
principal. Closing this one requires that principal: tracked as **#3410**,
which depends on **#3279**.

Operators relying on `require_user_token` should know that this endpoint is
outside its guarantee.

### `/decide` and the Four REST Routes: Segment Enforcement Is Token-Conditional

As of the verified-human segment promotion that landed with this flag's
stack, `/decide`, `mcpQueryHandler`, `mcpExecuteHandler`,
`mcpCheckInputHandler`, and `mcpCheckOutputHandler` all resolve the caller's
segments through `resolveHumanActorSegmentsForPolicy` before policy
evaluation, and a segment-resolution failure for a verified caller denies
fail-closed. **A segment-scoped policy IS enforced on these five planes, but
only for a caller presenting a validated per-user token.** The segments key
on the validated token's email claim; there is still no ADR-043/044
fleet-token flow on these routes.

That conditionality is exactly why this flag matters here: a token-less
caller is still evaluated org-only with no refusal, so a member can shed a
segment-scoped restriction by simply not sending a token, unless
`require_user_token` is on for the org, which removes the token-less path
entirely. Treat the flag as the enforcement switch for segment scoping on
these planes, and keep an org-scoped policy behind any segment-scoped one
until it is on.

The **MCP-server JSON-RPC plane's** `check_policy`/`check_output` tools were
the first place in the platform where a segment-scoped policy could actually
block a caller (ADR-060 P3, #3430); the five planes above joined it in the
same train that shipped this flag. That plane's segment gate
(`resolveMCPServerSegmentsForPolicy`, `platform/agent/mcp_identity.go`) is
already independently fail-closed for any caller with no validated per-user
principal, whenever the org has an enabled segment-scoped policy for that
phase - a protection #3430 shipped and this flag does not duplicate.
`require_user_token`'s contribution on this specific plane is to refuse the
caller **earlier** (at authentication, before a session is even created)
rather than relying solely on that downstream, per-tool gate - which matters
for every OTHER tool on this plane (audit search, override create/delete,
decision listing) that has no segment gate of its own at all.

## The Two Audit Markers

Two distinct `security_event` values distinguish *why* a caller was
refused, so the audit trail (and any downstream alerting on it) never
conflates a caller who never tried to prove who they were with one who
tried and failed:

| Marker | Cause | Introduced |
|---|---|---|
| `user_token_required` | Token **absent**, and the org's posture requires one | #3476 |
| `user_token_rejected` | Token **presented**, but invalid (malformed, expired, wrong algorithm, bad signature, or revoked) | #3472 |

Both are written via the same canonical `audit_logs` row shape every other
governance deny uses; query them with **JSONB containment**
(`policy_details->'policy_ids' @> '["user_token_required"]'::jsonb`), never
`LIKE`/`ILIKE` - a `_` in a `LIKE` pattern is a single-character wildcard, so
`'%user_token_required%'` can also match unrelated prose sharing the same
row.

### The MCP-Server Plane Audits Neither

The MCP-server JSON-RPC plane does not write an `audit_logs` row for **any**
authentication failure on this path - not `user_token_required`, not a
rejected token, nothing. `tools/call`'s `requireMCPAuth` collapses every
authentication-failure cause into one generic JSON-RPC error, `Authentication
required`, specifically so a caller cannot distinguish causes by probing.
The one place the specific cause **is** observable is the `initialize`
handshake (`handleMCPInitialize`), which surfaces
`authenticateMCPSession`'s raw error message verbatim:

- Token absent, posture requires one: `"user token is required for this
  organization"`
- Token presented, resolution failed: `"invalid user token: <reason>"`

On this plane, in other words, the two causes are distinguished **by
message**, not by an audit marker - the plane's audit posture for
authentication failures is unchanged by this control.

## The TTL Knob

`AXONFLOW_REQUIRE_USER_TOKEN_TTL_SECONDS` controls how long a resolved
per-org posture is cached before the next request re-reads the database -
i.e., **how long a posture change takes to actually take effect** once an
operator flips the column.

- Default: **60 seconds**.
- Clamped to **`[5, 600]` seconds**. A value outside that range (or
  unparseable) is clamped to the nearest bound; an unset or non-numeric
  value falls back to the 60s default.
- A lookup-error outcome is cached separately, for at most **15 seconds**
  regardless of the configured TTL - short enough that the control recovers
  quickly once the database heals, long enough that a failing database is
  not hammered on every request.

An operator who flips `organizations.require_user_token` should expect the
new posture to be live everywhere **within one TTL window** - up to 60
seconds by default, or as low as 5 seconds with the knob turned down (the
floor this suite's own CI run uses, so a flip-and-verify cycle does not
require a multi-minute wait).

## Semver and Compatibility

This is a **MAJOR** change under the platform's operator semver policy
(*"removed fallback / new required credential / new refusal / fatal config
value = MAJOR"*): setting `require_user_token` introduces a **new refusal**
for callers who previously were served.

It ships **opt-in per org**. `organizations.require_user_token` defaults to
`false` (migration 163: `ADD COLUMN ... NOT NULL DEFAULT false`, no
backfill, no data migration), and `AXONFLOW_REQUIRE_USER_TOKEN` defaults to
unset (`false`). **A deployment that never touches either lever sees no
behavior change at all** - every gate point's compatibility fallback for a
token-less enterprise caller is untouched until an operator (or an org's own
row) opts in. The MAJOR classification is about what the *feature* enables
an operator to do to their own traffic, not about a change every existing
deployment must absorb on upgrade.
