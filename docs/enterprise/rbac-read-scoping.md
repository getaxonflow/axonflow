# Role-Scoped Audit, Decision & Override Reads (Enterprise)

> **Edition:** Enterprise · **Companion:** [Per-User Token Provisioning](./per-user-token-provisioning.md)

Once a developer holds a validated per-user `{identity, role}` — minted by your
admin (Path A) or issued by your IdP (Path B), see the provisioning guide —
AxonFlow **scopes what they can read**. This page is the authoritative model for
who sees which rows across every governance read surface.

## Why this exists

A fleet historically authenticated every developer's plugin with one shared
tenant credential (`org_id:license`). That credential gives **attribution, not
authorization**: anyone holding it could read the **entire tenant's** audit
trail, decision history, and policy overrides — through the MCP read tools or a
direct `curl`. Role-scoped reads close that gap: a non-admin sees only their own
activity, while admins and owners retain full-tenant visibility for oversight
and compliance.

## The rule

| Resolved role | Audit / decision / override reads |
|---|---|
| `admin`, `owner` | **Full tenant** — every user's rows |
| `developer`, `viewer`, `policy_admin` | **Own rows only** — rows attributed to their identity |
| unmapped / unknown role, with a validated per-user identity | **Own rows only** (least-privilege) |
| no per-user token, or a shared / synthesized identity (`mcp-client:*`, the reserved `@axonflow.local` / `@axonflow.internal` service domains) | **Zero rows** — fail-closed. A shared identity is a multi-developer pool, so scoping a read to it would return that whole pool; the read resolves to no rows instead. |

The scope is derived from the role and applied **in the SQL `WHERE` clause**,
not as a post-fetch filter — a non-admin's query never selects another user's
rows in the first place.

## Enforcement properties (all fail-closed)

- **Endpoint-level, not tool-level.** The scope applies at the API, so a direct
  `curl` to `/api/v1/mcp-server` or `/api/v1/audit/search` is covered, not just
  the MCP tool wrapper. There is no unscoped back door.
- **Filters can only narrow.** A caller-supplied `user_email` filter narrows a
  non-admin's view to their own identity — it can never widen it to a
  colleague's rows.
- **Canonical identity match.** The scope keys on the same canonical identity —
  `lower(trim(email))` — that the write path stamps into every audit row, so a
  developer always sees the complete set of their *own* history.
- **No identity ⇒ no rows.** A caller with no resolvable per-user identity
  receives an **empty** result set, never the tenant trail.
- **Reject, don't downgrade.** A per-user token that is presented but invalid
  (tampered, expired, revoked, or minted for another org) is **rejected (401)** —
  never silently downgraded to a shared-credential read.

## Surfaces covered

Every cross-user read reachable with the tenant credential is scoped: the
`search_audit_events`, `list_recent_decisions`, `list_overrides`,
`get_policy_stats`, and `explain_decision` MCP tools, and the underlying
`/api/v1/audit/{search,export,report,summary,session-summary,:id}`,
`/api/v1/decisions`, `/api/v1/decisions/:id/explain`, and `/api/v1/overrides`
endpoints. Revoking an override is scoped the same way — a non-admin can revoke
only overrides they created.

### Whole-tenant compliance exports are admin-gated, not scoped

The evidence pack (`/api/v1/evidence/{export,summary}`), media-governance audit
export, and the regulator audit exports read the whole tenant's audit log **by
design** — a per-user "own-rows" export is not a meaningful compliance artifact.
These require **tenant-wide read authority** (an `admin`/`owner` role, or a
portal session your team's RBAC has authorized for audit reads). A non-admin
caller is **denied (403)**, not served a scoped subset.

### Cost/usage and execution reads are admin-gated, not scoped

The cost/usage APIs (`/api/v1/usage`, `/api/v1/usage/{breakdown,records}`,
`/api/v1/budgets` and its `{id}`, `{id}/status`, `{id}/alerts` routes) and the
execution APIs (`/api/v1/executions` and its by-id, steps, timeline, export and
DELETE routes, `/api/v1/unified/executions`, and the workflow-engine
`/api/v1/workflows/executions` list/by-id/by-tenant routes) expose
**tenant-wide spend and execution input/output summaries**, and their tables
are not stamped with a per-user identity — so there is no meaningful "own rows"
form to scope down to.
Like the compliance exports, they require **tenant-wide read authority**; a
non-admin holder of the shared tenant credential is **denied (403)**. This also
covers the mutation variants: a non-admin cannot delete another user's
execution trail, cancel an execution, or create/update/delete budgets.

Two deliberate exceptions stay reachable to any authenticated tenant caller:
`GET /api/v1/pricing` (static model pricing, no tenant data) and
`POST /api/v1/budgets/check` (the budget **enforcement** decision — SDKs gate
LLM spend on it). For a non-admin, the budget-check response is reduced to the
bare verdict (`allowed` + `action`): the absolute spend figures **and** the
budget id/name are stripped, and the check is pinned to the caller's
authenticated org (a body-supplied `org_id` cannot probe another org's budget).
The per-execution HITL approval-status poll
(`/api/v1/workflows/executions/{id}/hitl-status`) also stays reachable — it is
a status poll, not an execution input/output read.

Additionally, every by-id budget and execution route is **org/tenant-isolated
in the SQL `WHERE` clause** (and the workflow-engine by-id / by-tenant routes
are bound to the authenticated tenant identity, never the client-supplied path
`tenant_id`): even a tenant-wide caller cannot fetch, export, or delete another
organization's budget or execution by guessing its id.

## The two enforcement layers (defense in depth)

The **agent gateway** is the internet-exposed surface, so scoping is enforced
there **first and unconditionally**: the agent validates the per-user token,
resolves the `{identity, role}`, and scopes the read (or, for a proxied request,
forwards the validated role to the orchestrator).

The **orchestrator** applies the *same* scope as a **second layer**, but it
derives the caller's role and read-scope **only from the trusted
agent→orchestrator channel** — an HMAC-signed proxy-auth token that only the
agent and portal hold. A request that reaches the orchestrator **without valid
proxy-auth is treated as least-privilege**, regardless of what its role header
claims. This is deliberate: it means the second layer can never be re-forged by
a client that sets its own `X-Axonflow-User-Role` header. The portal proxy
asserts tenant-wide read scope over the same channel only for portal sessions
its own RBAC authorizes.

Concretely, the same developer token behaves identically whether the read
arrives via the MCP `search_audit_events` tool or a direct `curl` to the agent's
`/api/v1/audit/search`; and a direct call to the orchestrator carrying a forged
`admin` role header — but no proxy-auth — gets least-privilege, never the tenant
trail.

## Where the role comes from

- **Path A (admin-minted):** the role is a claim in the token, set by your admin
  at mint time. Whoever can mint sets the role — so the mint API requires the
  admin key even where admin auth is otherwise optional. See the provisioning
  guide's Path A security model.
- **Path B (IdP-issued OIDC):** the role comes from the **SCIM-synced
  directory**, never from a claim inside the IdP token. A developer with no
  mapped role resolves to **least-privilege** (own-rows), never admin — so an IdP
  misconfiguration cannot mint an admin.

## Completeness caveat (attribution-gated)

"A developer sees **all** of their own history" holds only for rows written
**while per-user attribution was on** — i.e. a validated per-user token was
presented, or the deployment enabled trusted identity headers and the
developer's identity arrived on a trusted header. Rows written *without* per-user
attribution carry a synthetic client-scoped identity, not the real developer, so
a non-admin will **not** see them (fail-closed is correct — they belong to no
single user). A fleet that has not yet rolled out per-user tokens will find a
developer's own-rows view is empty until attribution is enabled; **admins see
everything either way**.

## Server-side scope supersedes client-side redaction

Earlier plugin builds relied on a client-side redaction hook to blank
identity-derivable fields in read responses. That hook is a UI nicety, not a
security boundary — a modified client could skip it. The authoritative control
is **server-side**: a non-admin never receives another user's rows in the first
place, because the row is filtered out in SQL before the response is built. Treat
the server-side scope as the boundary; client-side redaction is defense in depth
on top of it.

## How a per-user token is presented on each plane

The two planes read the per-user token from **different headers**, because they
authenticate the *tenant* differently:

- **Proxied REST plane** (`/api/v1/audit/*`, `/api/v1/decisions`,
  `/api/v1/overrides` on the agent): the per-user token rides in
  **`X-User-Token`** only. `Authorization` on this plane carries the **tenant**
  credential (the enterprise JWT / Basic that the SDKs send) and is **not**
  reinterpreted as a per-user token — so a legacy `Authorization: Bearer`
  tenant integration keeps working unchanged. A present-but-invalid
  `X-User-Token` is **rejected (401)**, fail-closed.
- **MCP-server plane** (`/api/v1/mcp-server`): the tenant authenticates with
  **HTTP Basic** in `Authorization`, which leaves `Authorization` free — so a
  per-user token may ride in **`X-User-Token`** *or* **`Authorization: Bearer`**.
  A present-but-invalid per-user token is **rejected (401)**, fail-closed.

To scope reads by developer, provision each developer a real per-user token
(Path A or B) and send it in **`X-User-Token`**. Callers that present only the
shared tenant credential (no per-user token) are unaffected — they resolve to
the least-privilege client identity and read own-rows/none.
