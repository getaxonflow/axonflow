# Hosted Portal authorization census

This is the release census for the Hosted Starter Portal required by #4488.
It covers every public page, every API router, the catch-all proxy, searches,
pagination, exports, downloads, asynchronous jobs, queues, object storage and
realtime transports. The code-level route inventory is executable:
`TestHostedPortalAuthorizationCensus` fails when a new Portal route or page is
not in one of the zones below, and `TestOrchestratorRoutesAreClassified`
independently requires every route reachable through the catch-all proxy to be
allowed, locally served, or explicitly refused with a reason.

## Principals and invariants

| Principal | Source of organization | Allowed authority |
| --- | --- | --- |
| Anonymous browser | none | Health, deployment mode, rate-limited login/reset/link issuance, and SAML/OIDC handshake only. |
| Portal person | server-side session row | Explicit role permissions. Owner, member and reviewer are never inferred from payment or request headers. |
| Hosted service credential | bcrypt-backed `community_saas_registrations` row | SDK/plugin/MCP and Agent calls. It cannot create a Portal session. Owner-only Portal endpoints rotate, revoke and recover it. |
| SCIM client | hashed SCIM bearer token | `/scim/v2/*` directory synchronization for exactly its resolved organization. It cannot manage its own token or role mappings. |
| Platform operator | required admin API key | `/api/v1/admin/*`; cross-organization operations use the separate audited platform-admin pool. |
| Internal service | HMAC-authenticated service identity | Explicit internal routes only. Browser headers are overwritten and never become this identity. |

Every authenticated customer query is scoped from the resolved session or
credential and runs as `axonflow_app_role` with transaction-local organization
scope. Caller-supplied tenant, organization, user, role and read-scope headers
are not authorization inputs.

## HTTP authorization zones

| Zone | Complete route family | Gate | Data and mutation boundary |
| --- | --- | --- | --- |
| Public health/config | `GET /health`, `GET /api/v1/deployment/config` | No identity; no customer rows | Process health and deployment mode only. |
| Public authentication | `/api/v1/auth/login`, Hosted request/consume link, logout/session validation, SSO availability, forgot/reset/change password | Per-IP rate limits where applicable; token/session validation in handler; change-password has an explicit session gate | Login tokens are hashed, short-lived and single-use. Community SaaS refuses organization-password login. Service secrets are not accepted. |
| Federated handshake | `/auth/saml/*`, `/auth/oidc/*` | Tenant configuration lookup, signed protocol response, mapped person identity | Creates a person session only after provider and organization validation. |
| Operator plane | `/api/v1/admin/*` | `AdminAuthMiddleware`; credential/owner operations additionally require authenticated admin posture | Organization, license, owner, identity-setting and user-token lifecycle. Not a customer-session surface. |
| SCIM sync | `/scim/v2/*` | SCIM bearer middleware | Users and groups inside the token's resolved organization. |
| Person API | All explicitly registered `/api/v1/*` routes below `apiRouter` | Cookie session. In Community SaaS every non-read verb then defaults to explicit-grant-only owner permission (`sso:configure`), including helper-package routes; the executable exception list contains only own-row outcomes, reviewer-gated approvals and pure typed-policy validate/diff. | Keys, license status, nodes, usage, deployments, docs access, connectors, model providers, SSO, typed policies, HITL, SCIM token/mapping, roles, members, credential lifecycle, posture and code governance. A new mutation is owner-only until explicitly classified. |
| Hosted outcomes | `/api/v1/hosted/outcomes/cases*`, `/usage`, `/export`, `/review-queue`, `/review/cases*` | Cookie session; normal case operations are own-row and bind to the resolved person; review queue/read/approve/reject requires `approval:review`; signed loopback identity is rechecked by the sidecar | Person-owned typed cases, independent reviewer access only while acting through the review family, synthetic actions only, 100 created cases per calendar month and 100 retained cases, 16 KiB inputs, 25 signed requests per minute and 30-day primary retention. Browser authority headers and cookies never reach the sidecar. |
| Approval writes | HITL approve/reject, workflow/plan step approve/reject | `approval:review`; workflow binding and self-approval checks downstream | No live money adapter exists in Hosted Starter. |
| Policy/config writes | typed policy publish/promote/rollback/withdraw/dismiss, overrides, API keys, deployments, docs access, connectors, model providers, SSO/SCIM/posture, roles/members/credentials and code-governance provider/PR mutations | Community SaaS first requires explicit-grant-only `sso:configure` at the whole session subrouter, then preserves any narrower route permission; Hosted service-credential read/rotate/revoke also specifically requires `sso:configure` | Only the owner can mutate the non-outcome Hosted control plane. An ordinary wildcard admin cannot acquire this explicit permission. New helper-package mutations are covered without relying on their registrar to remember a gate. |
| Catch-all proxy | Remaining `/api/v1/*` | Session plus `ProxyAllowedRoutes`; default `ROUTE_NOT_PROXIED` refusal | Each Orchestrator method/path is independently classified by the executable proxy census. No role-less fallback exists. |

## Browser pages

Public pages are `/`, `/login`, `/hosted/sign-in`, `/forgot-password`, and
`/reset-password`. Authenticated pages are `/dashboard`, `/api-keys`,
`/approvals`, `/audit`, `/compliance`, `/connectors`, `/executions`, `/export`,
`/llm-providers`, `/nodes`, `/outcomes`, `/policy-authoring`, `/usage`,
`/settings/detection-posture`, `/settings/members`, `/settings/scim`, and
`/settings/sso`. The UI has one same-origin `/api/v1/[...path]` transport;
that transport adds no authorization and cannot bypass the API router.

## Reads, searches, queues, jobs, exports and downloads

| Surface | Scope and permission | Async/download behavior |
| --- | --- | --- |
| Audit search/detail/session summary | Session organization plus `audit:read`; service credentials receive no person permission | Search filters, count, limit, offset and cursors remain inside the organization. Audit CSV/JSON export requires tenant-wide export authority. |
| Execution/workflow/plan search and detail | Session organization and proxy read-scope classification | Pagination and guessed IDs are checked at the backing service. Execution export is classified separately from detail reads. |
| HITL and workflow/plan approval queues | Organization from session; list is read-scoped, action requires `approval:review` | Query allowlist pins status and validates limit/offset. Foreign IDs, requester self-approval and stale bindings are rejected. |
| Hosted outcome cases and review queue | Normal list/read/export is restricted to the session person's own case owner ID; review queue/read/approve/reject is a separate `approval:review` route family | Case inputs and state are PostgreSQL-backed under FORCE RLS. The Portal signs method, rewritten path, organization, tenant, person, capability and a 60-second timestamp for a loopback-only sidecar; guessed foreign case IDs return not found. |
| Usage export | Session organization | Synchronous CSV; date bounds and row scope are enforced in the Portal query. |
| Compliance/evidence/regulatory exports | `audit:read` for reads; whole-tenant export authority for generation | Job creation, list, status, artifact download and retry are separate allowlist entries. Authorization is rechecked on every poll/download; an ID is not a capability. |
| Code-governance export | Session organization and handler permissions | Synchronous response from organization-scoped repository. |
| Deployment upgrade jobs | Session organization | Create, list and status are explicit Portal handlers. Job IDs are scoped on every read. |
| Connectors/model providers | Session organization; mutation permission in handler | Secret material is never returned by list/get/export. Test calls use the stored organization-scoped configuration. |

## Non-HTTP surfaces

- Realtime: the Portal registers no WebSocket or server-sent-event endpoint.
  Adding `WebSocket`, `EventSource` or `text/event-stream` to the Portal trees is
  a census change requiring an explicit organization/role contract and test.
- Object storage: the Portal has no direct S3/GCS/Azure object-key or presigned
  URL handler. Export downloads are backing-service API routes and are
  reauthorized on access; object keys are never accepted as standalone proof.
- Background workers: the Portal process has no customer-data worker. It can
  create and poll explicitly classified backing-service jobs. Workers must
  re-resolve organization and entitlement on dequeue; browser/session headers
  are not persisted authority.
- Hosted outcome sidecar: `case-workflows` shares the Portal ECS task network
  namespace, binds only `127.0.0.1`, has no ALB mapping, and accepts only a
  short-lived HMAC over the exact method, downstream route, resolved person,
  capability, and request-body SHA-256 digest. Its PostgreSQL writes use the
  app-role DSN and FORCE-RLS tables; process memory is never the case, approval,
  retention, or idempotency authority.
- Cache: no Portal customer-data cache is an authorization source. Revocation
  deletes server-side sessions and pending login tokens; credential revocation
  is checked by the Agent's database-backed pre-auth lookup.

## Executable evidence

- `hosted_identity_http_realpg_test.go`: owner/member/reviewer, forged headers,
  foreign IDs, stale sessions, service-secret rotate/revoke/recover and audit.
- `orchestrator_proxy_census_test.go`: every backing route is locally served,
  explicitly admitted or refused; additions fail closed.
- `orchestrator_proxy_allowlist_test.go` and read-scope tests: exact methods,
  exports, searches, queues and administrative read width.
- `hosted_authorization_census_test.go`: every literal Portal registration,
  including the helper-registered code-governance surface, and every UI page
  remains assigned to this census; unknown and near-match mutations prove the
  global Hosted owner boundary fails closed.

The deployed negative matrix must repeat these properties through the public
hostnames against exact reviewed images. Local classification is necessary but
does not substitute for that runtime evidence.
