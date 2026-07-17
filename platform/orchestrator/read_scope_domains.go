// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"log"
	"net/http"
	"strings"

	"axonflow/platform/orchestrator/cost"
)

// Role-scoped read authorization for the cost/usage and execution domains
// (#2934, epic #2919 — the sibling of read_scope.go's audit/decision/override
// scoping and of tenantWideAuditExportPaths).
//
// The reported leak class, different data domain: any holder of the shared
// tenant credential could read the WHOLE tenant's spend (usage summary /
// breakdown / records, budget status and alerts) and every user's execution
// input/output summaries (replay + unified execution APIs), and could DELETE
// another user's execution trail or the org's budget governance config.
//
// Census outcome (#2934): neither domain stamps a per-user identity —
// usage_records.user_id has no wired production writer, and
// execution_summaries.user_id / execution_history.user_id carry the NUMERIC
// id of the shared license user row, identical for every developer on one
// org credential. There is therefore no meaningful "own rows" form, and
// scoping on user identity would be a vacuous filter. Posture: these are
// tenant-governance surfaces — a caller needs tenant-wide read authority
// (admin/owner over the trusted proxy-auth channel, the portal plane, or
// Community mode); everyone else is DENIED (403), mirroring
// tenantWideAuditExportPaths. Cross-ORG isolation is additionally enforced in
// the cost/replay repositories' SQL WHERE clauses (see AccessScope /
// GetBudgetScoped), since those tables have no RLS.
//
// Deliberate exceptions, documented per route in the #2934 census:
//   - GET /api/v1/pricing: static model pricing tables, no tenant or user
//     data — ungated.
//   - POST /api/v1/budgets/check: the budget-ENFORCEMENT decision plane (SDK
//     CheckBudget gates LLM spend on it); denying it would break cost
//     governance itself. It stays reachable, but non-tenant-wide callers get
//     the verdict with the absolute spend figures redacted
//     (cost.WithSpendRedaction).

// domainGovernanceReadPrefixes are the route families gated on tenant-wide
// read authority. Prefix match with a path-segment boundary, so e.g.
// /api/v1/usage covers /api/v1/usage/breakdown but not a hypothetical
// /api/v1/usage-other.
var domainGovernanceReadPrefixes = []string{
	"/api/v1/cost",                 // cost: reserved prefix (proxy-forwarded; no handler today — gated for future-proofing per the #2934 brief)
	"/api/v1/usage",                // cost: usage summary / breakdown / records
	"/api/v1/budgets",              // cost: budget CRUD, status, alerts (check exempted below)
	"/api/v1/executions",           // replay: list / get / steps / timeline / export / DELETE
	"/api/v1/unified/executions",   // unified execution tracking: list / get / stream / cancel
	"/api/v1/workflows/executions", // workflow engine: list / by-id / by-tenant (hitl-status exempted below)
}

// budgetCheckPath is the budget-enforcement decision endpoint — reachable to
// any authenticated tenant caller, with spend figures redacted for callers
// lacking tenant-wide read authority.
const budgetCheckPath = "/api/v1/budgets/check"

// hitlStatusSuffix marks the per-execution HITL approval-status poll
// (/api/v1/workflows/executions/{id}/hitl-status). It sits under the
// workflows/executions prefix but is a legitimate developer-facing status
// poll (lesser data class than the execution Input/Output the sibling routes
// expose), so it is exempted from the tenant-wide-authority gate. Its handler
// carries no tenant field to bind on today, so its own cross-tenant scoping is
// tracked as a follow-up (#2949) rather than gated here — gating it admin-only
// would break HITL polling for fleet developers.
const hitlStatusSuffix = "/hitl-status"

// isDomainGovernancePath reports whether p belongs to a gated route family.
// The hitl-status poll is exempted even though it sits under the
// workflows/executions prefix.
func isDomainGovernancePath(p string) bool {
	if strings.HasSuffix(p, hitlStatusSuffix) {
		return false
	}
	for _, base := range domainGovernanceReadPrefixes {
		if p == base || strings.HasPrefix(p, base+"/") {
			return true
		}
	}
	return false
}

// enforceDomainReadAuthority is orchestrator middleware that requires
// tenant-wide read authority for the cost/usage and execution route families.
// It runs before every matched route; for any other path it is a cheap prefix
// check + pass-through. CORS preflight (OPTIONS) is always allowed. A caller
// lacking authority gets 403 — these domains have no meaningful own-rows
// form (see the census note above), so the fail-closed posture is a denial,
// exactly like enforceTenantWideAuditExport.
func enforceDomainReadAuthority(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || !isDomainGovernancePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == budgetCheckPath {
			if scope := resolveCallerReadScope(r); !scope.TenantWide {
				r = r.WithContext(cost.WithSpendRedaction(r.Context()))
			}
			next.ServeHTTP(w, r)
			return
		}

		if scope := resolveCallerReadScope(r); !scope.TenantWide {
			log.Printf("[domain-read-scope] BLOCKED: caller lacks tenant-wide read authority for %s %s", r.Method, r.URL.Path)
			sendErrorResponse(w, "cost/usage and execution APIs require an admin/owner role", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
