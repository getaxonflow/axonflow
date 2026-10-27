# Hosted paid workflows: security audit and launch gate

Status: implementation and staging certification in progress, 25 October 2026. Issue: [#4488](https://github.com/getaxonflow/axonflow-enterprise/issues/4488). The first $9.99/month hosted tier depends on this gate. This document records the implemented boundary and the evidence required before activation.

## Decision and scope

The first paid tier should let an identified person run bounded FinCrime, payment exception, and support refund investigations with customer supplied cases, then inspect their organization's permitted case and audit records in a Portal. Built-in synthetic cases are useful for onboarding and regression tests but are insufficient as the paid product. Initial hosted use should accept only the documented typed fields, with size, retention, model-processing, and action boundaries enforced by the service. No shared hosted route may initiate a payment, retry, refund, credit, or customer-system write. The buyer's system remains the executor after its own authorization. Any direct live adapter or unrestricted sensitive-record flow needs a separately reviewed Enterprise VPC or isolated hosted deployment.

The issue's **design target**, pending cost and buyer validation, is one organization, two users, all three capabilities, 100 case evaluations per month, one standard integration, and 30-day case and audit retention. Governed-event and model-use caps must be set with #4487 before publication. The Portal must show usage and remaining allowance. The standard integration must be defined as a bounded import or API contract, not an unrestricted live connector.

Payment is an entitlement check, not an identity or authorization check. A paid subscription must never promote a shared tenant secret into a human Portal session or an organization-wide audit reader.

## Current state and evidence

| Area | Implemented and verified | Remaining launch evidence |
| --- | --- | --- |
| Hosted topology | The Community SaaS template has an opt-in combined Portal API/UI Fargate task, private API sidecar communication, host-based ALB routing, dedicated logs and security group, secret references, and safe default desired count zero. Local `cfn-lint` passes after excluding the template's documented baseline warnings. | The exact reviewed task definition must reach `UPDATE_COMPLETE`, targets must be healthy, and the dedicated hostname must have public DNS plus a matching ACM certificate. |
| Human identity | Migration 190 creates forced-RLS person memberships and hashed, 15-minute, single-use login tokens. The first paid registrant becomes owner; an owner can invite one member or reviewer. The database trigger enforces the tenant/organization binding and two-seat cap. Revocation atomically removes sessions, role grants, and outstanding login tokens so re-invitation cannot revive an older link. Organization password login is refused in Hosted mode. | Complete the public email-link flow against Resend staging and prove session and pending-link revocation after member removal. |
| Authorization | Reviewer gets only `audit:read` and `approval:review`; member gets the existing developer role; owner gets the system owner role. Approval routes require `approval:review`. The role-less tenant-wide proxy fallback was removed. Portal session and reusable service credentials remain separate. | Run the deployed owner/member/reviewer matrix, including self-approval refusal and guessed foreign IDs across reads, exports, and queues. |
| Entitlement | Token issue and consumption both require an active paid subscription. Billing, Checkout, webhook ordering, refund/dispute handling, metering, and client fail-closed behavior come from #4487. Refund and dispute processing resolves the exact Stripe payment lineage before every Hosted terminal update, refuses missing, ambiguous, or period-less lineage, and compares the resolved paid period even when a pre-fix row retained a stale non-null payment intent. A distinct renewal can supersede a same-second terminal event only when it carries a strictly later paid period. | Activate a dedicated tenant through Stripe test mode and run the full register, pay, login, workflow, approval, revoke path. A manual database update is not evidence. |
| RLS proof | `TestHostedIdentityPaidPersonIsolationAndSeatBoundaryRealPostgres` proves person/seat isolation. `TestHostedMemberHTTPIsolationRealPostgres` adds the production app role, real cookie middleware, production-shared route registration, RBAC gate, and Hosted member handlers; it rejects foreign member IDs, forged tenant/organization/user/role headers, member and reviewer directory or revocation access, and a revoked stale session. It also found and now guards the nullable Hosted display-name authentication failure. The HTTP proof enables and forces the Hosted `admin_audit_log` policy and proves member invite and revoke commit with their audit rows under `axonflow_app_role`; a bare pool insert is rejected with SQLSTATE `42501`. `TestHostedCustomerDataRLSMigrationRealPostgres` applies the actual core and Hosted migrations, models migration 193 as already recorded, then applies forward repair migration 194. It inventories every direct text `org_id`/`tenant_id` customer table, requires FORCE RLS plus the exact named tenant-bound restrictive guard expression, rejects disabled/unforced indirect tables and tenant-GUC tautology impostors, and performs non-vacuous two-tenant reads across audit, policy, workflow, usage, and API-key stores. It reproduces the shared-database Grafana 10.2.2 schema and proves migration 194 repairs only the explicit numeric organization-table inventory while preserving unknown tables and recorded pre-existing RLS flags. `TestHostedBillingRLSIsolationRealPostgres` separately proves subscription/event isolation and the narrow webhook admin path. `TestWebhookHandlerTerminalEventsWinSameSecondReverseLexicalRealPostgres` proves both delivery orders for same-second refunds and disputes, historical payments on the current subscription, older paid invoices, replay repair of an active row whose earlier parser missed `paid_until`, missing Hosted API credentials, and subscription deletion cannot leave or incorrectly restore entitlement. The production-handler E2E repeats the historical-payment regression. The Community SaaS Agent repeats the catalog census at startup and refuses to serve on drift. | Repeat the public staging journey on the final image and require zero unexpected `audit_row_lost` events. Retain redacted positive, foreign-row, case, export, queue, deletion, and credential-lifecycle evidence. |
| Portal UI | Hosted login requests an email link, explicit confirmation prevents mail scanners from consuming it, and the members screen shows seat usage, roles, invitation, and revocation. Static or backend deployment config selects Hosted behavior. | Browser E2E through the public staging hostname. |
| Workflow scope | #4486 is merged in PR #4489 and provides the three case workflows. Shared Hosted remains proposal and approval only; no payment, retry, refund, credit, or customer-system write adapter is enabled. | Exercise every workflow with a bounded permitted-data case and verify the proposed action is simulated. |
| Operations | The launch runbook identifies 404 as an old-image symptom, documents secret-name resolution, safe-off parameters, same-stack recovery, rollback, DNS, and retained evidence. Update and application workflows now understand the combined Community Portal service. | Finish deployed certification and hostile PR review, then record accepted issue and PR links. |

Production returning 404 for Hosted billing routes is expected while its running Agent remains the older image. Secrets Manager contents do not register HTTP handlers; deploying the reviewed enterprise image does.

### Portal authorization census

The complete Portal page/API/job/export/search/download/realtime inventory and
its executable anti-drift checks are in
[`hosted-portal-authorization-census.md`](hosted-portal-authorization-census.md).
The public UI catch-all adds no authority: every backing Orchestrator route is
independently classified as locally served, explicitly admitted, or refused,
and every new literal Portal route or page fails the census test until assigned
to an authorization zone.

## Data contract for the first paid tier

The hosted product should admit customer supplied, bounded case facts for the three workflows. It should reject fields outside the versioned schema rather than accepting arbitrary source documents. A case can contain opaque customer references, amounts, currencies, status codes, timestamps, reason codes, policy facts, and short free-text descriptions after validation. Do not request account numbers, card data, government identifiers, full customer profiles, access tokens, or raw third-party exports. Before launch, privacy and security owners must decide whether any named person or transaction reference is allowed on the shared tier, record the lawful processing basis and buyer notice, and specify deletion and model-provider terms. If a needed case cannot fit the admitted data class, route that buyer to a scoped isolated PoC.

| Data flow | Required boundary before enablement |
| --- | --- |
| Registration, checkout, and entitlement | Verified email and server-created organization ID; checkout metadata set by the server; verified payment events bind a subscription to that organization. Never put reusable credentials in checkout URLs or email. |
| Typed case input and tool arguments | Schema allowlist, per-field and total payload limits, tenant and person from authenticated context, encryption in transit and at rest, prompt-injection handling, and explicit rejection of secrets or prohibited identifiers. |
| Model prompt and result | Minimize case facts, state provider and region, disable provider training where contractually available, set retention and timeout, record model version and usage, and treat output as a proposal with cited evidence. |
| Policy decision and approval | Bind case, action, amount, currency, payee or customer reference, evidence digest, policy version, requester, and reviewer. A changed binding invalidates a pending approval. A reviewer cannot approve their own proposal. |
| Audit and case evidence | Record organization, actor, service credential, action, source, decision, result, and immutable timestamps. Scope row access by organization and role. Define a short hosted retention period, deletion propagation, backup expiry, and export rules before launch. |
| Simulated action | Return an explicit `simulated` outcome in API and UI. The shared tier has no live payment, refund, credit, retry, or customer-system write adapter. |

The exact limits, lifecycle, region, model boundary, backup expiry, deletion
SLA and unit-economics decision are fixed in
[`hosted-starter-product-data-economics-acceptance.md`](hosted-starter-product-data-economics-acceptance.md).
Changing those values or enabling external model processing requires a new
acceptance; no customer case data is admitted outside that contract.

### Synthetic acceptance corpus

Synthetic records must use reserved `demo_` references and invented names only. Each case should pass the same typed case validation as a paid customer's permitted case, and each API and Portal result must label simulated actions.

| Case | Evidence and proposed disposition | Refusal control |
| --- | --- | --- |
| FinCrime payment screening | An invented transfer with typed amount, currency, origin, destination category, and risk indicators yields an evidence-linked hold or review proposal. | A changed amount or missing policy version invalidates the decision; the model cannot turn a hold into an allow. |
| Payment exception | An invented failed disbursement with provider failure, ledger state, timestamp, and idempotency reference yields wait, reconcile, or a proposed retry after evidence review. | A later success, stale or contradictory status, changed payee, or changed evidence forbids even simulated retry approval. |
| Support refund | An invented order with eligibility facts, prior concessions, amount, currency, and reason yields a reviewable refund or credit proposal and draft response. | Duplicate, pending, excessive, or changed-amount proposals are refused or returned for review. |

The built-in corpus is for explanation and verification. Paid acceptance still requires the same bounded path to process an organization's permitted data.

### Cost and architecture decision

At the design target, measure monthly infrastructure, database and backup storage, model input and output tokens, queue and network use, support time, payment fees, and abuse reserve per active organization. The contribution margin calculation is `$9.99 minus payment fees minus 100 times marginal case cost minus 30-day storage and support allocation minus shared infrastructure allocation`. Use observed p50 and p95 case cost, not a single optimistic average. State hard caps for case count, governed events, model tokens, seats, request rate, payload size, and storage. If a shared stack cannot meet the accepted data boundary or target margin, evaluate a logically isolated hosted architecture or a higher-priced isolated tier before taking a paid order. Do not weaken person or tenant isolation to fit the price.

## Threat model and controls

| Threat | Attack path to test | Required control |
| --- | --- | --- |
| Cross-tenant read | Forged `X-Tenant-ID`, guessed case or audit ID, pagination cursor, search filter, export ID, object key, cache key, or realtime subscription | Resolve organization from session or credential on the server. Filter in SQL and, where feasible, FORCE RLS under `axonflow_app_role`. Reject any mismatch before dereferencing an object or job. |
| Within-tenant overread | Shared SDK secret, role-less session, viewer with `audit:read`, member querying another person's restricted rows | Separate service, owner, member, and reviewer principals. Explicit per-person permissions and row policy. No role-less tenant-wide carve-out in the paid Portal path. |
| Privilege escalation | Portal cookie from service secret, caller-supplied role/read-scope headers, admin-pool fallback, SSO identity with no role | Strictly separate credential types. Strip untrusted headers at ingress. Require explicit grants on every Portal and proxy path. Admin-pool operations must be narrow, audited, and unreachable from customer input alone. |
| Confused entitlement | Checkout for tenant A applied to tenant B, webhook replay, stale paid cache, tenant rotation or email re-registration | Subscription maps to immutable server-side organization identity. Verify event signatures and order. Check current entitlement at every hosted governance entry point with bounded cache staleness and revocation behavior. |
| Action abuse | Model output or case text asks for a retry/refund, stale approval, changed amount, duplicate request | Model and case text cannot authorize execution. Typed policy and separate reviewer bind the exact action. Shared tier uses only a fake executor and idempotent simulated outcomes. |
| Persistence after revocation | Stale session, copied API key, pending job, downloadable export, cache, deleted tenant ID | Short sessions with server-side revocation, hashed service secrets with rotation, job authorization on dequeue and result read, cache invalidation, tombstoned organization IDs, deletion tests. |

## Enrollment and authorization design

1. A person registers with verified email. The account exists before checkout but can see only pricing, its own account state, and synthetic preview material.
2. The server creates one organization and a checkout session with immutable organization metadata. A verified payment event activates its entitlement. Provisioning is idempotent across webhook replay and out-of-order events. Existing prepaid terms continue as promised under #4487.
3. The first verified person becomes owner after an audited, transactional grant. Invitations create member or reviewer identities with verified email. A reviewer can read the evidence needed for an assigned approval, but cannot mint credentials or approve their own action. Owner access to all audit rows is an explicit permission, never inferred from subscription payment or absence of roles.
4. The Portal uses person sessions with secure cookies, CSRF protection, short idle and absolute expiry, rotation on login, server-side revocation, and organization resolution on each request. SSO and password paths must produce the same principal and grants before either is enabled for this product.
5. The owner enrolls a separate service credential for an SDK, plugin, or MCP client. Show its secret once in an authenticated session, store only a hash or protected reference, bind its organization and narrow scopes server-side, and support expiry, rotation, revocation, and an audit entry for each lifecycle event. A service secret never signs into the Portal and never receives human `audit:read` by default. Device authorization can be a later client UX if it preserves the same separation.
6. Recovery restores a verified person's access to the same organization through an audited recovery flow. It does not create a fresh tenant with inherited data or subscription. Lost service secrets are rotated, not emailed.

The legacy `cs_<uuid>` registration path and existing client credentials need a migration policy under #4487. They must not be silently interpreted as Portal people, team roles, or paid entitlements.

## Isolation verification matrix

Run the end-to-end suite against real Postgres with migrations applied, `axonflow_app_role` confirmed as `NOBYPASSRLS`, `axonflow_platform_admin` confirmed as `BYPASSRLS`, and the actual agent, orchestrator, Portal, cache, object store, and worker configuration. Seed two organizations, at least two people per organization, and distinct service credentials. Put distinct marker records in every store so a zero-row test cannot pass vacuously.

| Surface | Negative cases that must fail |
| --- | --- |
| Agent and orchestrator REST, MCP, SDK and plugin | Foreign organization header/body, forged role/read-scope header, old shared credential, missing person context, expired or revoked credential, alternate route to the same read. |
| Portal pages and APIs | Guessed case/audit/decision/approval ID, own versus colleague row, role downgrade, stale cookie, SSO versus password session, export and download links, browser cache. |
| Search and async work | Filters, pagination and cursors, counts, saved search, queue listing, background job execution and result polling, retry after revocation, realtime subscription. |
| Storage and lifecycle | Object keys, signed URLs, cache keys, tombstoned organization, deletion and re-registration, credential rotation, backup and retention expiry. |
| Approval and action | Requester approving own proposal, wrong reviewer, altered amount/currency/payee, changed evidence/policy version, duplicate action, live-adapter invocation on hosted tier. |

Every test must also prove the matching authorized path returns the planted record. Test both direct internal-service routes and public ingress so a secure Portal proxy cannot conceal an unguarded sibling route. Log and inspect denied attempts without storing raw secrets or prohibited case data.

## Phased implementation and ownership

| Phase | Work and exit condition | Boundary |
| --- | --- | --- |
| 0: inventory | Confirm live CloudFormation/ECS/ALB routes, security groups, production database roles, data stores, SDK/plugin credential behavior, and all Portal read/export/job routes. Reconcile the current public data notice. | #4488 audit; no new hosted routes. |
| 1: account foundation | Add verified person, organization membership, entitlement binding, and separate hashed service credentials with audited lifecycle. Repair #4469 and test fresh onboarding under the app role. All new code starts disabled. | #4487 owns checkout, subscription state, and migration of existing terms; #4488 owns person and service authorization. |
| 2: bounded cases | Agree typed accepted data fields, limits, retention, model processing, and simulated-action contract. Wire #4486 case and policy interfaces through disabled hosted gates with no live adapter. | #4486 owns investigation, case schema, action binding, and customer-neutral workflow implementation. #4488 owns hosted intake and data controls. |
| 3: isolation | Implement and run the real-stack matrix, fix all gaps, inventory every Portal route, and perform independent security review. No production enablement while a cross-tenant or cross-person path remains. | #4488 security gate. |
| 4: staged launch | Exercise register, pay, issue credential, sign in, each of the three workflows, case create/read, decision, separate approve/deny, revoke, export, and delete in staging. Enable cohorts with independent switches for entitlement, each workflow, case intake, and Portal; test rollback and support access. | Operator-reviewed deployment only after phases 0 to 3. |

The Portal infrastructure uses `CustomerPortalDesiredCount=0` as the deployment gate. Paid governance remains independently safe-off through `AXONFLOW_HOSTED_PAID_GATE=off`, a zero cohort, empty acceptance values, and zero governed-event and burst allowances. Enabling a Portal task does not activate Checkout or governed traffic.

## Launch decision

**Still closed pending deployed evidence.** The implementation now supplies the person/service split, two-seat enforcement, reviewer separation, RLS test, Portal topology, and safe-off controls. Do not activate paid enforcement or accept customer case data until the exact reviewed images pass the live staging journey, public DNS and TLS work, the hostile review has no unresolved findings, economics set a positive governed-event allowance, and the operator records acceptance for #4486 and #4488.
