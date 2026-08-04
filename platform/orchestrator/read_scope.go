// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"log"
	"net/http"
	"strings"

	sharedidentity "axonflow/platform/shared/identity"
)

// tenantWideAuditExportPaths are the whole-tenant compliance / evidence / media
// audit-export endpoints (#2922/#2923 census, R3). Each reads audit_logs
// cross-user (user_email / user_role / raw query text) for the WHOLE tenant —
// the same data class the per-user read tools scope, just via an export route.
// A per-user ("own-rows") export is meaningless for a compliance artifact, so
// these are gated on tenant-wide READ AUTHORITY (admin/owner, or the trusted
// portal audit:read plane, or Community): a non-admin caller is DENIED (403),
// not scoped down. This closes the sibling ingress both R3 passes flagged — a
// fleet developer with the shared tenant credential could otherwise curl
// /api/v1/evidence/export (or the compliance exports) and receive every user's
// audit rows. Centralized here (the census output) rather than scattered as a
// per-handler check, and enforced as one middleware so the in-package handlers
// AND the euaiact/sebi/ojk sub-module routes are covered uniformly.
// NOT included, deliberately: /api/v1/rbi/audit-exports* exports RBI
// registry/validation/incident/board-report governance artifacts (rbi's own
// tables), NOT per-user audit_logs rows — a different data class, so it is
// outside this audit_logs census. /api/v1/masfeat has no audit export.
var tenantWideAuditExportPaths = []string{
	"/api/v1/evidence/export",
	"/api/v1/evidence/summary",
	"/api/v1/media-governance/audit/export",
	"/api/v1/euaiact/export",
	"/api/v1/sebi/audit/export",
	"/api/v1/ojk/audit/export",
	// #3241 / epic #2892: the unified compliance report facade. Its GENERATION
	// and DOWNLOAD routes are this same data class; its status POLL is not.
	// See complianceReportPollShape below - that carve-out is the only reason
	// this entry is not a plain whole-prefix gate.
	complianceReportBasePath,
}

// complianceReportBasePath is the compliance report facade's collection route.
// Declared here rather than imported from the compliancereport package because
// that package is Enterprise-tagged and this file compiles in both editions.
// TestComplianceReport_BasePathMatchesTheFacade asserts the two agree.
const complianceReportBasePath = "/api/v1/compliance/reports"

// isTenantWideAuditExportPath reports whether p is (or is a sub-path of) a
// whole-tenant audit-export endpoint. Prefix match so the euaiact/…/export/{id}
// download variants are covered too.
func isTenantWideAuditExportPath(p string) bool {
	for _, base := range tenantWideAuditExportPaths {
		if p == base || strings.HasPrefix(p, base+"/") {
			return true
		}
	}
	return false
}

// isTenantWideAuditExportRequest is the REQUEST-aware form the middleware uses.
//
// It exists for one route family. Epic #2892 D4 splits the compliance report
// facade across the two axes this file keeps apart (see callerReadScope):
//
//   - GENERATING a report and DOWNLOADING its artifact produce a whole-tenant
//     compliance artifact. That is the export class: admin authority, 403 for
//     everyone else, exactly like the five entries above.
//
//   - POLLING a report's STATUS returns the JOB RECORD: id, regulator,
//     framework, format, period, status, report_state, progress, record_count,
//     size_bytes, checksum, requested_by, the failure cause when it failed, and
//     the lifecycle timestamps. It contains no audit ROWS - no query text, no
//     user emails, no decision records - but record_count IS a count derived
//     from the tenant's governed activity, and requested_by names a colleague.
//     That is the viewing class rather than the export class, and the poll is
//     gated on TENANCY BINDING ALONE: the facade requires a bound
//     tenantscope.Scope and authorizes the row on both dimensions, and there is
//     no additional positive read-authority check on this path.
//
//     Stated plainly because the alternative - gating the poll on admin
//     authority - means a compliance viewer cannot see whether the report they
//     asked for has finished, and the portal has to poll as an administrator on
//     their behalf. If the record_count / requested_by exposure is judged too
//     wide for a non-admin, the fix is to narrow the POLL PAYLOAD, not to widen
//     this gate.
//
// The carve-out is a WHITELIST OF ONE SHAPE, not a blacklist: exactly
// `GET /api/v1/compliance/reports/{id}` with no further path segments. Every
// other method and every other shape under the prefix - POST, DELETE, the
// /download suffix, a future sub-resource - stays gated. Written this way round
// because the failure mode of a blacklist is silent: a route added later would
// be ungated by default and nothing would say so
// (`[[feedback_guard_by_capability_not_by_shape]]`).
//
// Note the poll is still ORGANIZATION-scoped and tenancy-authorized inside the
// facade (tenantscope.Authorize on the fetched row); this decides only whether
// the caller needs ADMIN authority on top of that.
func isTenantWideAuditExportRequest(r *http.Request) bool {
	if !isTenantWideAuditExportPath(r.URL.Path) {
		return false
	}
	return !complianceReportPollShape(r)
}

// complianceReportPollShape reports whether r is exactly the compliance report
// STATUS POLL: GET on the base path plus one non-empty segment.
func complianceReportPollShape(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	rest, ok := strings.CutPrefix(r.URL.Path, complianceReportBasePath+"/")
	if !ok {
		return false
	}
	// Exactly one segment: "abc" polls, "abc/download" and "" do not.
	return rest != "" && !strings.Contains(rest, "/")
}

// enforceTenantWideAuditExport is orchestrator middleware that requires
// tenant-wide read authority for the whole-tenant audit-export endpoints
// (see tenantWideAuditExportPaths). It runs before every matched route; for a
// non-export path it is a cheap prefix check + pass-through. CORS preflight
// (OPTIONS) is always allowed. A caller lacking authority gets 403 — the same
// fail-closed posture the per-user read handlers apply, expressed as a denial
// because these exports have no meaningful own-rows form.
func enforceTenantWideAuditExport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || !isTenantWideAuditExportRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		// #3060: gates on AdminAuthority, NOT TenantWide. These are an
		// AUTHORIZATION question ("is this caller an administrator?"), and the
		// two axes diverge for Community-SaaS — a single-operator evaluator
		// reads its own tenant tenant-wide without thereby earning
		// whole-tenant compliance artifacts. See callerReadScope.
		if scope := resolveCallerReadScope(r); !scope.AdminAuthority {
			log.Printf("[audit-export] BLOCKED: caller lacks tenant-wide read authority for %s", r.URL.Path)
			sendErrorResponse(w, "tenant-wide audit export requires an admin/owner role", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Role-scoped read authorization (#2922, epic #2919).
//
// Every cross-user read surface over audit_logs / policy_overrides (search,
// export, report, detail, decision + override listings, session summaries,
// audit summaries, decision explain) resolves the caller's read scope through
// resolveCallerReadScope and applies it in the SQL WHERE clause — never as a
// post-fetch comparison (#1623 retro: post-fetch authz silently fails open).
//
// The reported exploit (#2922): any holder of the shared tenant credential — a
// fleet developer — could read the ENTIRE tenant's audit trail through the MCP
// read tools or a direct curl. The fix scopes non-admin callers to their own
// user_email rows, keyed on the SAME canonical email the write path stamps.

// callerReadScope is the resolved read authority for one request.
//
// It carries TWO INDEPENDENT AXES. Keeping them apart is load-bearing; they
// were one field until #3060 and that conflation is why answering the scoping
// question could not help but answer the authorization one:
//
//   - TenantWide is a SCOPING answer: "how wide may this caller see WITHIN its
//     own tenant?" It never crosses the tenant — every consumer applies it on
//     top of a server-derived tenant predicate.
//   - AdminAuthority is an AUTHORIZATION answer: "is this caller an
//     administrator of the tenant?" It gates route families that have no
//     own-rows form at all and are therefore denied outright to non-admins.
//
// Admin authority IMPLIES tenant-wide scoping (an org admin reads everything in
// the org). The converse does NOT hold: a single-operator Community-SaaS
// evaluator sees its whole tenant precisely because its tenant is itself, which
// says nothing about whether it may run a whole-tenant compliance export or
// mutate budgets. Widening one axis must never silently widen the other.
type callerReadScope struct {
	// TenantWide is true when the caller may read every user's rows within
	// the (already header-forced) tenant scope: a validated admin/owner role
	// delivered over the trusted proxy-auth channel, an internal-service
	// tenant-scope assertion (customer-portal plane), a Community-mode
	// deployment, or an agent-proxied Community-SaaS caller (both
	// single-operator, no fleet — see resolveCallerReadScope).
	TenantWide bool
	// AdminAuthority is true only when the caller has established ADMINISTRATIVE
	// authority over the tenant: a validated admin/owner/policy_admin role over
	// the trusted proxy-auth channel, the customer-portal's explicit
	// X-Axonflow-Admin-Authority: true assertion, or Community mode (a local
	// single-operator deployment where the operator IS the administrator —
	// this is the pre-#3060 behavior and must not narrow).
	//
	// NOT derivable from X-Axonflow-Read-Scope (#3241 round 2). It was until
	// then, and because the portal stamps that header for every audit:read
	// holder — including the seeded viewer role — the two axes were joined
	// again on the portal plane after #3060 had separated them on the
	// orchestrator's. Authority is its own assertion on its own header.
	//
	// Deliberately FALSE for Community-SaaS (#3060). A csaas tenant is a
	// self-registered free evaluation account: it should read its own
	// governance data, and it should NOT thereby acquire whole-tenant
	// compliance exports, budget-governance CRUD, execution cancel/delete, or
	// unredacted spend figures. Those 403s are the free-tier boundary, not
	// collateral damage from the read bug.
	//
	// Consumed ONLY by the two router-level gates (enforceTenantWideAuditExport,
	// enforceDomainReadAuthority) and the budgets/check spend-redaction
	// decision. Every other consumer asks the scoping question and must keep
	// reading TenantWide.
	AdminAuthority bool
	// UserEmail is the canonical own-rows identity for a non-tenant-wide
	// caller. Empty means the caller presented no per-user identity at all —
	// consumers MUST return an empty result set, never fall through to an
	// unscoped query (an empty-string match would alias every row whose
	// user_email was written blank, which under the default trust gate is
	// most of the tenant trail — the exact leak this fix closes).
	UserEmail string
}

// resolveCallerReadScope derives the trusted (scope, identity) pair for a
// read request.
//
// Trust rules, in order:
//
//  1. Community mode: tenant-wide AND admin authority. A community deployment
//     is a single-operator local instance — there is no per-user token
//     machinery (validators are enterprise-only) and no fleet of distinct users
//     to protect from each other; scoping it to own-rows would permanently
//     blind the operator to the non-attributed rows their own SDK traffic
//     writes. The operator is also the administrator, so admin authority comes
//     with it — this is the pre-#3060 behavior and must not narrow, or a local
//     stack loses its compliance exports and cost/usage APIs. Mirrors the
//     Community posture of verifyAgentProxyAuth (agent_proxy_guard.go).
//
//  2. Valid X-Axonflow-Proxy-Auth token (the #2896 trusted channel — only the
//     agent gateway / customer-portal hold the HMAC secret): honor
//     X-Axonflow-User-Role (validated fleet role; admin/owner/policy_admin ⇒
//     tenant-wide + admin authority) and X-Axonflow-Read-Scope: tenant
//     (portal-plane assertion, same). The agent strips both headers from
//     inbound client traffic on every proxied route and the MCP forwarders
//     build fresh requests, so a governed caller can never launder either
//     header through the gateway.
//
//     That "every proxied route" claim had one hole until #3092:
//     proxyAuthMiddleware returned early on OPTIONS, ABOVE the strip, while
//     the reverse-proxy Director appended a valid HMAC proxy-auth token
//     unconditionally — so a preflight was a request shape on which a caller
//     could self-assert X-Axonflow-User-Role and have the agent vouch for it.
//     It was not exploitable only because every handler here independently
//     405s or guards OPTIONS, i.e. it was one route registration away from
//     live. The agent now terminates preflights at the auth boundary and
//     scrubs the headers regardless (agent/proxy.go:
//     stripClientAssertedProxyHeaders), so the claim above holds for every
//     method, not just the ones that reach a handler.
//
//     Community-SaaS (#3060) is admitted here — INSIDE the validated-token
//     branch, deliberately not alongside Community in rule 1, and with
//     AdminAuthority deliberately FALSE. See the inline comment at the grant
//     for the full argument; in short, a csaas tenant is single-operator
//     (OrgID == TenantID == ClientID == cs_<uuid>) so "tenant-wide" is exactly
//     that one evaluator's own data, but the tenant boundary on these reads is
//     a SQL `tenant_id = $N` predicate fed from X-Tenant-ID — with no RLS
//     backstop on audit_logs — so the grant is only sound when that header is
//     agent-stamped rather than self-asserted.
//
//  3. Everything else — no/invalid proxy-auth, or proxy-auth without an
//     elevating header — is least-privilege: own-rows on the canonical
//     X-User-Email. For requests through the agent that header is the
//     trust-gated / token-validated identity; for a direct-to-orchestrator
//     caller it is self-claimed, which grants at most that one identity's
//     rows (never the tenant trail) and matches the documented posture for
//     the in-VPC defense-in-depth layer.
//
// Fail-closed properties: an unset/invalid proxy token can never elevate; an
// unknown role string normalizes to least-privilege; a missing identity yields
// scope.UserEmail == "" which consumers must map to zero rows.
func resolveCallerReadScope(r *http.Request) callerReadScope {
	if isCommunityMode() {
		return callerReadScope{TenantWide: true, AdminAuthority: true}
	}

	if proxyTokenValidator != nil {
		if tok := r.Header.Get("X-Axonflow-Proxy-Auth"); tok != "" {
			if valid, _, _ := proxyTokenValidator.ValidateToken(tok); valid {
				// #3060: Community-SaaS reads are tenant-wide, for the same
				// reason Community's are in rule 1 — a csaas tenant is a
				// single-operator evaluation account. Registration mints one
				// cs_<uuid> that IS the org, the tenant and the credential
				// (community_saas_register.go: csaas_register_tenant +
				// registerTenantAndOrg(tenantID, tenantID); auth.go stamps
				// OrgID == TenantID == ClientID == the Basic-auth username), so
				// there is no fleet of distinct users inside a csaas tenant to
				// protect from each other. "Tenant-wide" here reads exactly the
				// rows the caller's own credential wrote.
				//
				// Without this the mode had NO path to a non-empty audit or
				// decision read at all: csaas is not Community, per-user tokens
				// are enterprise-only (proxy.go gates on AuthKindEnterprise),
				// POST /api/v1/dev/token is unregistered in csaas, the agent
				// strips X-Axonflow-User-Role / X-Axonflow-Read-Scope
				// unconditionally, and X-User-Email is deleted unless the
				// trust gate is on — and even then the rows carry
				// evaluator@try.getaxonflow.com, which IsSharedSyntheticIdentity
				// censuses to "". Every branch below therefore terminated in
				// own-rows-on-empty-identity ⇒ a silent 200 with zero rows.
				//
				// Gated on the VALIDATED proxy token rather than granted in
				// rule 1 next to Community, because the two modes have
				// different tenant-boundary substrates. audit_logs is NOT
				// RLS-enabled (migration 018's table list covers
				// agent_audit_logs / orchestrator_audit_logs, not audit_logs),
				// so cross-tenant isolation on these reads rests entirely on
				// the handlers' `tenant_id = $N` predicate, sourced from
				// X-Tenant-ID. That header is trustworthy only when the agent
				// set it from the authenticated cs_ credential
				// (proxy.go proxyAuthMiddleware Set()s it over any client
				// value); a caller reaching the orchestrator directly asserts
				// it freely. Community mode ships as a single-tenant local
				// stack where that distinction is moot; csaas is a shared
				// multi-tenant deployment where it is the whole ballgame — so
				// tenant-wide is granted only over the channel that makes the
				// tenant id non-forgeable. A direct-to-orchestrator csaas
				// caller falls through to least-privilege below exactly as
				// before, and a csaas deployment that forgot
				// AXONFLOW_INTERNAL_SERVICE_SECRET (proxyTokenValidator == nil)
				// never reaches this branch — both fail closed, now visibly:
				// applyReadScopeHeader stamps X-Axonflow-Read-Scope: none and
				// logs the reason.
				//
				// AdminAuthority is deliberately left FALSE. TenantWide is
				// consumed by two ROUTER-LEVEL middlewares as well as by the
				// read handlers, so granting it as one undifferentiated flag
				// would flip twelve route families from 403-everyone to
				// 200-tenant-wide — the whole compliance/evidence export
				// family, budget-governance CRUD, execution cancel/delete, and
				// unredacted spend on budgets/check. Those 403s are the free
				// tier's boundary, not collateral damage from this bug, and
				// restoring an evaluator's own audit trail must not hand a
				// self-registered free account whole-tenant compliance
				// artifacts. See callerReadScope's two-axes note.
				//
				// The non-empty X-Tenant-ID guard is defence in depth: every
				// read handler rejects a missing tenant header on its own, but
				// enforceDomainReadAuthority is a bare gate with no such check
				// and replay/postgres_repository.go treats an empty org as
				// UNFILTERED. Pre-fix that path had a hard 403; keep it
				// unreachable rather than relying on the consumers.
				// TrimSpace, not a bare != "": not every consumer trims, so a
				// whitespace-only header would satisfy a bare check and then
				// reach a consumer that treats it as empty.
				if isCommunitySaasMode() && strings.TrimSpace(r.Header.Get("X-Tenant-ID")) != "" {
					return callerReadScope{TenantWide: true}
				}
				if sharedidentity.RoleCanReadTenant(r.Header.Get(sharedidentity.HeaderUserRole)) {
					return callerReadScope{TenantWide: true, AdminAuthority: true}
				}
				if r.Header.Get(sharedidentity.HeaderReadScope) == sharedidentity.ReadScopeTenant {
					// #3241 round 2: AdminAuthority is NOT derivable from the
					// read-scope header. It used to be, and that re-created the
					// #3060 conflation one plane up: the portal stamps
					// X-Axonflow-Read-Scope for any session holding audit:read,
					// which the seeded VIEWER role holds, so a viewer passed
					// every AdminAuthority gate - whole-tenant compliance
					// exports, /api/v1/evidence/export, /api/v1/sebi/audit/export,
					// budget-governance CRUD, execution cancel/delete and
					// unredacted spend.
					//
					// Authority now needs its own assertion on the same trusted
					// channel, stamped by the portal only for sessions its RBAC
					// authorizes as administrators (orchestrator_proxy.go
					// sessionHasAdminAuthority). A caller with read scope and no
					// authority is exactly the viewer: tenant-wide reads, 403 on
					// everything administrative.
					return callerReadScope{
						TenantWide:     true,
						AdminAuthority: sharedidentity.AdminAuthorityFromHeader(r.Header.Get(sharedidentity.HeaderAdminAuthority)),
					}
				}
			}
		}
	}

	email := sharedidentity.CanonicalEmail(r.Header.Get("X-User-Email"))
	// #2919 Finding 1 + #2938: X-User-Email can carry a platform-synthesized
	// SHARED identity rather than a person. On the governed plane a token-less
	// fleet caller resolves to mcp-client:<clientID> (#2936); an in-VPC caller
	// curling the orchestrator directly can assert any of the other shared
	// spellings the platform mints into audit_logs.user_email
	// (<client-id>@axonflow.local, unknown@axonflow.local,
	// orchestrator@axonflow.internal, evaluator@try.getaxonflow.com). Each is
	// one spelling shared by a whole pool of callers, so scoping a read to it
	// would return the entire pool — the cross-developer audit-read leak. Fail
	// closed on the FULL shared-identity census: empty scope ⇒ zero rows
	// (consumers map "" to no rows). communityMode=false because community
	// already returned tenant-wide above — a local-dev assertion reaching this
	// point is a non-community caller spoofing the community synthetic. A
	// validated per-user token or trust-gated X-User-Email yields a real
	// address here and reads own-rows normally; admin/owner already returned
	// tenant-wide above.
	if sharedidentity.IsSharedSyntheticIdentity(email, false) {
		email = ""
	}
	return callerReadScope{
		UserEmail: email,
	}
}

// Read-scope observability (#1, #2991). Before this, a fail-closed empty audit
// read was a silent 200 {total:0} with nothing logged — indistinguishable to a
// partner from "the data is gone." The additive X-Axonflow-Read-Scope RESPONSE
// header echoes the resolved read authority on every audit read, and the
// fail-closed "none" path logs one diagnostic line. This is purely diagnostic:
// the response BODY is unchanged (clients/SDKs parse total/entries), and nothing
// keys authorization off the response header.
//
// NB the header name is deliberately the SAME sharedidentity.HeaderReadScope the
// portal plane uses as an INBOUND trusted assertion — request and response
// headers are separate channels, so echoing it outbound cannot be laundered
// back inbound to elevate: even if a response value were somehow replayed as a
// request header, the inbound path honors ONLY "tenant" AND only when carried
// over a valid X-Axonflow-Proxy-Auth token (resolveCallerReadScope), so an
// echoed "own-rows"/"none" is ignored and an echoed "tenant" still needs the
// HMAC proxy-auth secret. Values below are the outbound vocabulary.
const (
	// readScopeOwnRows: the read was scoped to the caller's own user_email rows.
	readScopeOwnRows = "own-rows"
	// readScopeNone: fail-closed empty read — the caller presented neither
	// tenant-wide authority nor a per-user identity, so zero rows were returned.
	readScopeNone = "none"
)

// readScopeLabel classifies a resolved callerReadScope into its
// X-Axonflow-Read-Scope response-header value: "tenant" (cross-user),
// "own-rows" (scoped to the caller's own email), or "none" (fail-closed empty).
func readScopeLabel(scope callerReadScope) string {
	switch {
	case scope.TenantWide:
		return sharedidentity.ReadScopeTenant // "tenant"
	case scope.UserEmail != "":
		return readScopeOwnRows
	default:
		return readScopeNone
	}
}

// applyReadScopeHeader sets the additive X-Axonflow-Read-Scope response header
// from the resolved scope and, on the fail-closed "none" path, emits one
// diagnostic log line (these are low-frequency endpoints, so one line per
// request is acceptable). It MUST be called before the handler writes its
// status line / body, so callers invoke it immediately after resolving the
// scope. Returns the label it set.
func applyReadScopeHeader(w http.ResponseWriter, r *http.Request, scope callerReadScope) string {
	label := readScopeLabel(scope)
	w.Header().Set(sharedidentity.HeaderReadScope, label)
	if label == readScopeNone {
		log.Printf("[read-scope] %s: caller has no tenant-wide read authority (no admin/owner token) and no per-user identity → 0 rows returned. See docs/enterprise/per-developer-identity#role-scoped-reads", r.URL.Path)
	}
	return label
}
