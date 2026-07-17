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
}

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

// enforceTenantWideAuditExport is orchestrator middleware that requires
// tenant-wide read authority for the whole-tenant audit-export endpoints
// (see tenantWideAuditExportPaths). It runs before every matched route; for a
// non-export path it is a cheap prefix check + pass-through. CORS preflight
// (OPTIONS) is always allowed. A caller lacking authority gets 403 — the same
// fail-closed posture the per-user read handlers apply, expressed as a denial
// because these exports have no meaningful own-rows form.
func enforceTenantWideAuditExport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || !isTenantWideAuditExportPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if scope := resolveCallerReadScope(r); !scope.TenantWide {
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
type callerReadScope struct {
	// TenantWide is true when the caller may read every user's rows within
	// the (already header-forced) tenant scope: a validated admin/owner role
	// delivered over the trusted proxy-auth channel, an internal-service
	// tenant-scope assertion (customer-portal plane), or a Community-mode
	// deployment (single-operator, no fleet — see resolveCallerReadScope).
	TenantWide bool
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
//  1. Community mode: tenant-wide. A community deployment is a single-operator
//     local instance — there is no per-user token machinery (validators are
//     enterprise-only) and no fleet of distinct users to protect from each
//     other; scoping it to own-rows would permanently blind the operator to
//     the non-attributed rows their own SDK traffic writes. Mirrors the
//     Community posture of verifyAgentProxyAuth (agent_proxy_guard.go).
//
//  2. Valid X-Axonflow-Proxy-Auth token (the #2896 trusted channel — only the
//     agent gateway / customer-portal hold the HMAC secret): honor
//     X-Axonflow-User-Role (validated fleet role; admin/owner ⇒ tenant-wide)
//     and X-Axonflow-Read-Scope: tenant (portal-plane assertion). The agent
//     strips both headers from inbound client traffic on every proxied route
//     and the MCP forwarders build fresh requests, so a governed caller can
//     never launder either header through the gateway.
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
		return callerReadScope{TenantWide: true}
	}

	if proxyTokenValidator != nil {
		if tok := r.Header.Get("X-Axonflow-Proxy-Auth"); tok != "" {
			if valid, _, _ := proxyTokenValidator.ValidateToken(tok); valid {
				if sharedidentity.RoleCanReadTenant(r.Header.Get(sharedidentity.HeaderUserRole)) {
					return callerReadScope{TenantWide: true}
				}
				if r.Header.Get(sharedidentity.HeaderReadScope) == sharedidentity.ReadScopeTenant {
					return callerReadScope{TenantWide: true}
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
