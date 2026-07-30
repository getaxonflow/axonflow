// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package tenantscope is the single authorization choke point for by-id reads
// and writes on tenant-keyed rows (#3065, epic #3071 Tier 2).
//
// # Why this package exists
//
// Eight-plus call sites across the orchestrator and agent shared one idiom:
//
//	if callerOrg != "" && row.OrgID != "" && row.OrgID != callerOrg { reject }
//
// Every one of them FAILS OPEN when either side is empty. The caller's org
// arrives as a self-asserted X-Org-ID header (or, for budgets, an `org_id`
// query parameter) on routes that mostly lacked the agent proxy-auth gate —
// so "empty" was attacker-selectable and **omitting a header was the
// exploit**: a tenant could abort/complete/resume another tenant's workflows,
// approve or reject their pending human-approval steps, cancel or roll back
// their plans, delete their budgets, and read their webhook HMAC signing key.
//
// The idiom also survives being rewritten into SQL — `cost/postgres_repository.go`
// carried it as an `org_id IS NULL OR org_id = <empty> OR org_id = $2`
// disjunction while its own comment claimed the check was "isolated in the
// SQL WHERE clause — never post-fetch". Patching sites one at a time therefore
// guarantees a ninth site. This package is the fix; the converted call sites
// are its first consumers, and TestNoFailOpenOrgCompare (the syntactic lint in
// tenantscope_lint_test.go) makes site nine fail the build.
//
// # The contract
//
//	Bind(r)                          — fail closed when no authenticated scope
//	                                   is present on the request.
//	Scope.Authorize(rowOrg, rowTen)  — fail closed when EITHER side is empty.
//	Scope.AuthorizeOrgOnly(rowOrg)   — same, for tables with no tenant key.
//
// There is deliberately no "trusted caller passes empty strings" bypass. The
// AxonFlow Agent's proxyAuthMiddleware and apiAuthMiddleware both Set (not
// Add) X-Org-ID and X-Tenant-ID from the cryptographically validated
// credential on EVERY proxied route, in every deployment mode — community
// included, where the org defaults to the ORG_ID env var ("local-dev-org")
// and the tenant to the client id. The customer portal's orchestrator proxy
// does the same from the session. So a request that reaches a governed
// handler without both values did not traverse an authenticating hop, and the
// only safe answer is to refuse it.
//
// # Relationship to RLS
//
// None. Do not reason about Postgres RLS as a backstop here: `plans`,
// `budgets`, `webhook_subscriptions` and `workflows` have no RLS at all, and
// where RLS does exist its policies key on `org_id` while handlers scope on
// `tenant_id` — different values under a single enterprise license (#3071).
// Application-level scoping is the only thing between a coding mistake and a
// cross-tenant leak on these surfaces.
package tenantscope

import (
	"errors"
	"net/http"
	"strings"
)

// Header names carrying the authenticated caller scope. Both are Set (never
// Add) by the authenticating hop, so a client-supplied value is always
// overwritten before a governed handler sees it.
const (
	HeaderOrgID    = "X-Org-ID"
	HeaderTenantID = "X-Tenant-ID"
)

// UnownedOrgSentinel is the org/tenant key stamped by migration core/156 onto
// pre-existing rows that carry no tenancy key at all. Those rows are, by
// definition, owned by nobody: the sentinel keeps the NOT NULL + CHECK
// constraints satisfiable without destroying history, and Authorize refuses
// it on BOTH sides so an operator who sets ORG_ID to the sentinel string
// still cannot reach another tenant's orphan rows.
//
// The value is deliberately not a plausible org id (org ids come from a
// license payload or the ORG_ID env var).
const UnownedOrgSentinel = "__axonflow_unowned__"

var (
	// ErrNoCallerScope means the request carried no authenticated tenancy.
	// Callers MUST map this to 401 and early-return — never degrade to an
	// unscoped query.
	ErrNoCallerScope = errors.New("tenantscope: caller scope not bound (X-Org-ID and X-Tenant-ID are required; they are set by the AxonFlow Agent gateway or the customer portal proxy)")

	// ErrNotOwned means the target row is not owned by the caller's tenancy,
	// or carries no tenancy key at all. Callers MUST map this to 404 — not
	// 403 — so the response is indistinguishable from a genuinely absent id
	// and cannot be used as a cross-tenant existence oracle.
	ErrNotOwned = errors.New("tenantscope: row is not owned by the caller's tenancy")
)

// Scope is an authenticated caller's tenancy. The zero value is unbound and
// authorizes nothing.
type Scope struct {
	OrgID    string
	TenantID string
}

// Bind resolves the caller's authenticated scope from a request, failing
// closed when either dimension is absent.
//
// The ONLY source is the auth-stamped header. Values are trimmed; a
// whitespace-only header is treated as absent (a trailing space would
// otherwise produce a scope that matches no row AND passes the non-empty
// check, i.e. a silent zero-rows failure of exactly the class #3039 was).
//
// #3065 R3 round 1: an earlier version also fell back to
// ctx.Value("org_id") / ctx.Value("tenant_id") with plain string keys. A
// census of every context.WithValue in the tree found ZERO production writers
// of those keys — only tests — so the fallback bought nothing and cost a
// colliding-string-key trust path into an authorization decision. Removed. If
// an in-process caller ever needs to assert a scope, it uses New().
func Bind(r *http.Request) (Scope, error) {
	if r == nil {
		return Scope{}, ErrNoCallerScope
	}
	return New(
		strings.TrimSpace(r.Header.Get(HeaderOrgID)),
		strings.TrimSpace(r.Header.Get(HeaderTenantID)),
	)
}

// New builds a Scope outside an HTTP context (background workers, adapters,
// tests) with the same fail-closed validation Bind applies.
func New(orgID, tenantID string) (Scope, error) {
	s := Scope{OrgID: strings.TrimSpace(orgID), TenantID: strings.TrimSpace(tenantID)}
	if s.OrgID == "" || s.TenantID == "" {
		return Scope{}, ErrNoCallerScope
	}
	if s.OrgID == UnownedOrgSentinel || s.TenantID == UnownedOrgSentinel {
		return Scope{}, ErrNoCallerScope
	}
	return s, nil
}

// NewOrgOnly builds a Scope carrying only an org key, for the surfaces whose
// call sites cannot supply a tenant (the plan-execution path threads a bare
// orgID string through a signature owned by another workstream's region of
// run.go). The result authorizes AuthorizeOrgOnly only — Authorize always
// denies it, because its TenantID is empty.
func NewOrgOnly(orgID string) Scope {
	org := strings.TrimSpace(orgID)
	if org == UnownedOrgSentinel {
		org = ""
	}
	return Scope{OrgID: org}
}

// Bound reports whether both dimensions of the scope are present and usable.
func (s Scope) Bound() bool {
	return usable(s.OrgID) && usable(s.TenantID)
}

// Authorize is the choke point for a row carrying BOTH tenancy keys. It fails
// closed when the caller's org or tenant is empty, when the row's org or
// tenant is empty, when either side is the unowned sentinel, or on any
// mismatch. Returns nil only on an exact match of both dimensions.
// The caller's scope is checked in full BEFORE the row is consulted, so an
// unauthenticated request always reports ErrNoCallerScope regardless of which
// row it named — the refusal cannot double as an existence oracle.
//
// Both sides are trimmed before comparison: a Scope built by struct literal
// (the in-service call sites, which receive already-extracted strings) never
// passed through New's normalization, and " org-a" must not be treated as a
// distinct tenancy from "org-a".
func (s Scope) Authorize(rowOrg, rowTenant string) error {
	if !usable(s.OrgID) || !usable(s.TenantID) {
		return ErrNoCallerScope
	}
	if !usable(rowOrg) || !usable(rowTenant) {
		return ErrNotOwned
	}
	if strings.TrimSpace(rowOrg) != strings.TrimSpace(s.OrgID) {
		return ErrNotOwned
	}
	if strings.TrimSpace(rowTenant) != strings.TrimSpace(s.TenantID) {
		return ErrNotOwned
	}
	return nil
}

// AuthorizeOrgOnly is the choke point for a row whose table has no reliable
// tenant key. It applies the identical fail-closed rules to the org dimension
// and does not consult the tenant dimension of the row.
//
// Every call site is pinned by TestAuthorizeOrgOnlyCallSitesArePinned — adding
// one is a conscious, reviewed act, never a silent widening.
func (s Scope) AuthorizeOrgOnly(rowOrg string) error {
	if !usable(s.OrgID) {
		return ErrNoCallerScope
	}
	if !usable(rowOrg) || strings.TrimSpace(rowOrg) != strings.TrimSpace(s.OrgID) {
		return ErrNotOwned
	}
	return nil
}

// usable reports whether a tenancy key is present and is not the sentinel
// that marks a row (or a misconfigured deployment) as owned by nobody.
func usable(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != UnownedOrgSentinel
}

// ValidateOrgKey is the single-dimension form of ValidateRowKeys, for the
// surfaces whose SQL keys on org alone (the HITL approval queue, whose
// ListFilter has no tenant dimension — it is the deployment-wide queue view
// scoped by org). An empty or sentinel org is a denial.
func ValidateOrgKey(rowOrg string) error {
	if !usable(rowOrg) {
		return ErrNoCallerScope
	}
	return nil
}

// ValidateRowKeys is the write-side counterpart: it refuses to persist a row
// that carries no tenancy key, so "row org is empty" cannot occur in the
// first place. Migration core/156 enforces the same invariant in the
// database; this is the application-layer half that produces a useful error
// instead of a constraint violation.
func ValidateRowKeys(rowOrg, rowTenant string) error {
	if !usable(rowOrg) || !usable(rowTenant) {
		return ErrNoCallerScope
	}
	return nil
}
