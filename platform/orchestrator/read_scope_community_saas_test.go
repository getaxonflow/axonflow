// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3060 — Community-SaaS read scope.
//
// Before this fix DEPLOYMENT_MODE=community-saas had NO code path to a
// non-empty audit or decision read: not Community (rule 1 excludes it by
// construction), no per-user tokens (enterprise-only), role/scope headers
// stripped by the agent, X-User-Email deleted under the default trust gate,
// and — even with the gate on — an evaluator@try.getaxonflow.com identity that
// IsSharedSyntheticIdentity censuses to "". Every branch terminated in
// own-rows-on-empty-identity ⇒ a silent 200 with zero rows.
//
// The grant is deliberately narrower than "csaas ⇒ tenant-wide": it lives
// INSIDE the validated-proxy-token branch, because audit_logs carries no RLS
// and the tenant boundary on these reads is the handlers' `tenant_id = $N`
// predicate fed from X-Tenant-ID — trustworthy only when the agent stamped it
// from the authenticated cs_ credential. These tests pin BOTH halves: the
// grant fires over the agent channel, and it does NOT fire for anything else.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// csaasRequest builds a read request shaped like the one the agent forwards on
// community-saas: auth-derived tenant/org/client headers all the same cs_ id,
// no role or read-scope header (the agent strips both unconditionally), and
// the shared synthetic evaluator identity the csaas write path stamps.
func csaasRequest(t *testing.T, tenant string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set("X-Tenant-ID", tenant)
	r.Header.Set("X-Org-ID", tenant)
	r.Header.Set("X-Client-ID", tenant)
	r.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
	return r
}

const csaasTestTenant = "cs_11111111-1111-1111-1111-111111111111"

// The fix: an agent-proxied community-saas caller reads tenant-wide, which on
// this mode means exactly the rows their own cs_ credential wrote.
func TestResolveCallerReadScope_CommunitySaas_TenantWideOverAgentChannel(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)

	r := csaasRequest(t, csaasTestTenant)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))

	scope := resolveCallerReadScope(r)
	if !scope.TenantWide {
		t.Fatalf("agent-proxied community-saas caller must be tenant-wide, got %+v", scope)
	}
	if got := readScopeLabel(scope); got != sharedidentity.ReadScopeTenant {
		t.Fatalf("read-scope label = %q, want %q", got, sharedidentity.ReadScopeTenant)
	}
}

// Vacuity control for the test above: assert the pre-fix inputs really did
// resolve to the fail-closed empty scope. If this ever starts returning
// tenant-wide, the test above proves nothing about the fix.
//
// This is the exact request the plugin sent to try.getaxonflow.com — the
// shared synthetic identity is the last thing standing between the caller and
// own-rows, and it censuses to "".
func TestResolveCallerReadScope_CommunitySaas_PreFixInputsResolvedToNone(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)

	// No proxy token: this is what the resolution looked like before the
	// grant existed, on every ingress.
	r := csaasRequest(t, csaasTestTenant)

	scope := resolveCallerReadScope(r)
	if scope.TenantWide {
		t.Fatal("control invalid: community-saas without the agent channel must NOT be tenant-wide")
	}
	if scope.UserEmail != "" {
		t.Fatalf("control invalid: the csaas evaluator identity must census to empty, got %q", scope.UserEmail)
	}
	if got := readScopeLabel(scope); got != readScopeNone {
		t.Fatalf("read-scope label = %q, want %q (fail-closed empty)", got, readScopeNone)
	}
}

// A community-saas caller reaching the orchestrator DIRECTLY self-asserts
// X-Tenant-ID — there is no RLS on audit_logs to catch it — so it must not be
// tenant-wide. This is the cross-tenant guard on the widening itself: the
// request below claims to be a DIFFERENT tenant and presents no proxy token.
func TestResolveCallerReadScope_CommunitySaas_DirectToOrchestrator_NotTenantWide(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)

	for _, tc := range []struct {
		name  string
		mutot func(*http.Request)
	}{
		{"no proxy token", func(r *http.Request) {}},
		{"empty proxy token", func(r *http.Request) { r.Header.Set("X-Axonflow-Proxy-Auth", "") }},
		{"garbage proxy token", func(r *http.Request) { r.Header.Set("X-Axonflow-Proxy-Auth", "not-a-token") }},
		{"structurally plausible but unsigned", func(r *http.Request) {
			r.Header.Set("X-Axonflow-Proxy-Auth", "1735689600:deadbeefdeadbeefdeadbeefdeadbeef")
		}},
		// A forged role header cannot substitute for the token either.
		{"forged admin role, no token", func(r *http.Request) {
			r.Header.Set(sharedidentity.HeaderUserRole, "admin")
		}},
		{"forged read-scope assertion, no token", func(r *http.Request) {
			r.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Claim a foreign tenant — the shape of the attack this guards.
			r := csaasRequest(t, "cs_22222222-2222-2222-2222-222222222222")
			tc.mutot(r)
			if scope := resolveCallerReadScope(r); scope.TenantWide {
				t.Fatalf("direct-to-orchestrator csaas caller must NOT be tenant-wide (%s), got %+v", tc.name, scope)
			}
		})
	}
}

// A csaas deployment that never set AXONFLOW_INTERNAL_SERVICE_SECRET has no
// validator, so no request can prove it came through the agent. Fail closed —
// NOT "community-saas, therefore trust it".
func TestResolveCallerReadScope_CommunitySaas_NoValidator_FailsClosed(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	orig := proxyTokenValidator
	proxyTokenValidator = nil
	t.Cleanup(func() { proxyTokenValidator = orig })

	r := csaasRequest(t, csaasTestTenant)
	r.Header.Set("X-Axonflow-Proxy-Auth", "anything-at-all")

	if scope := resolveCallerReadScope(r); scope.TenantWide {
		t.Fatalf("csaas with no proxy validator must fail closed, got %+v", scope)
	}
}

// The grant must not leak into any other deployment mode. Enterprise with the
// SAME agent-channel request (valid proxy token, no elevating role) stays
// least-privilege — a csaas-shaped request cannot buy tenant-wide reads on an
// enterprise deployment.
func TestResolveCallerReadScope_OtherModes_NotWidenedByTheCsaasGrant(t *testing.T) {
	for _, mode := range []string{"enterprise", "in-vpc-enterprise", "saas", "COMMUNITY-SAAS", "community_saas", "unknown-mode"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			readScopeTestValidatorOn(t)

			r := csaasRequest(t, csaasTestTenant)
			r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))

			if scope := resolveCallerReadScope(r); scope.TenantWide {
				t.Fatalf("mode %q must not be tenant-wide via the #3060 grant, got %+v", mode, scope)
			}
		})
	}
}

// isCommunitySaasMode is an exact-match on the canonical spelling and is NOT a
// member of isCommunityMode's true set. Both properties are load-bearing for
// the grant above (case/underscore variants must not elevate, and community
// must keep its own rule-1 path), so pin them here rather than assume.
func TestCommunitySaasModePredicate(t *testing.T) {
	cases := []struct {
		mode      string
		wantCsaas bool
		wantComm  bool
	}{
		{"community-saas", true, false},
		{"community", false, true},
		// #3096: unset no longer confers the community posture.
		{"", false, false},
		{"COMMUNITY-SAAS", false, false},
		{"community_saas", false, false},
		{" community-saas", false, false},
		{"enterprise", false, false},
	}
	for _, c := range cases {
		t.Run("mode="+c.mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", c.mode)
			if got := isCommunitySaasMode(); got != c.wantCsaas {
				t.Errorf("isCommunitySaasMode() = %v, want %v", got, c.wantCsaas)
			}
			if got := isCommunityMode(); got != c.wantComm {
				t.Errorf("isCommunityMode() = %v, want %v", got, c.wantComm)
			}
		})
	}
}

// The csaas write path stamps evaluator@try.getaxonflow.com, which the shared
// census maps to "" — that is what closed the last remaining read path. The
// grant returns BEFORE the census, so the synthetic identity is no longer
// load-bearing on csaas. Pin the census itself so a future edit that removes
// the evaluator spelling doesn't silently change what this fix rests on.
func TestCsaasEvaluatorIdentityIsStillCensusedElsewhere(t *testing.T) {
	if !sharedidentity.IsSharedSyntheticIdentity(sharedidentity.CommunitySaaSEvaluatorIdentity, false) {
		t.Fatalf("%q must remain a shared synthetic identity — a non-csaas caller asserting it must still fail closed",
			sharedidentity.CommunitySaaSEvaluatorIdentity)
	}
	// …and the grant short-circuits it on csaas over the agent channel.
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)
	r := csaasRequest(t, csaasTestTenant)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	if scope := resolveCallerReadScope(r); !scope.TenantWide {
		t.Fatalf("the census must no longer zero a csaas read, got %+v", scope)
	}
}

// ---------------------------------------------------------------------------
// The two axes (#3060 round 2).
//
// TenantWide answers "how wide within my tenant?"; AdminAuthority answers "am I
// an administrator of this tenant?". They were one field, which is why granting
// community-saas its own audit trail would otherwise also have handed a
// self-registered free account the whole compliance-export family, budget
// governance, execution cancel/delete and unredacted spend.
//
// These tests pin the free-tier boundary rather than assuming it.
// ---------------------------------------------------------------------------

// The grant sets the SCOPING axis and deliberately not the AUTHORIZATION one.
func TestResolveCallerReadScope_CommunitySaas_TenantWideWithoutAdminAuthority(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)

	r := csaasRequest(t, csaasTestTenant)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))

	scope := resolveCallerReadScope(r)
	if !scope.TenantWide {
		t.Fatalf("community-saas must be tenant-wide for reads, got %+v", scope)
	}
	if scope.AdminAuthority {
		t.Fatal("community-saas must NOT carry admin authority — that would hand a free " +
			"evaluation account whole-tenant compliance exports, budget CRUD and execution cancel")
	}
}

// Every other elevating path keeps BOTH axes, unchanged from before the split.
func TestResolveCallerReadScope_AxesByBranch(t *testing.T) {
	cases := []struct {
		name           string
		mode           string
		validator      bool
		mutate         func(*testing.T, *http.Request)
		wantTenantWide bool
		wantAdmin      bool
	}{
		{
			name: "community mode: operator is the administrator",
			mode: "community", validator: false,
			mutate:         func(t *testing.T, r *http.Request) {},
			wantTenantWide: true, wantAdmin: true,
		},
		{
			name: "admin over the trusted channel",
			mode: "enterprise", validator: true,
			mutate: func(t *testing.T, r *http.Request) {
				r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
				r.Header.Set(sharedidentity.HeaderUserRole, "admin")
			},
			wantTenantWide: true, wantAdmin: true,
		},
		{
			name: "owner over the trusted channel",
			mode: "enterprise", validator: true,
			mutate: func(t *testing.T, r *http.Request) {
				r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
				r.Header.Set(sharedidentity.HeaderUserRole, "owner")
			},
			wantTenantWide: true, wantAdmin: true,
		},
		{
			name: "policy_admin over the trusted channel (unchanged by the split)",
			mode: "enterprise", validator: true,
			mutate: func(t *testing.T, r *http.Request) {
				r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
				r.Header.Set(sharedidentity.HeaderUserRole, "policy_admin")
			},
			wantTenantWide: true, wantAdmin: true,
		},
		{
			// INVERTED in #3241 round 2. This case asserted wantAdmin: true,
			// which is precisely the conflation the round-2 fix removes: the
			// portal stamps this header for EVERY session holding audit:read,
			// and the seeded viewer role holds it - so "read scope asserted"
			// meant "administrator" for a read-only user.
			//
			// The case is kept rather than deleted, with the expectation
			// flipped, because it is the one that would go red if the grant
			// came back.
			name: "portal tenant-scope assertion ALONE: scoping, NOT authority",
			mode: "enterprise", validator: true,
			mutate: func(t *testing.T, r *http.Request) {
				r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
				r.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
			},
			wantTenantWide: true, wantAdmin: false,
		},
		{
			// The other half of the axes split, and the positive control for
			// the case above: a fix that simply never granted AdminAuthority on
			// this branch would satisfy that case and 403 every administrator.
			name: "portal tenant-scope assertion PLUS an admin-authority assertion: both",
			mode: "enterprise", validator: true,
			mutate: func(t *testing.T, r *http.Request) {
				r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
				r.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
				r.Header.Set(sharedidentity.HeaderAdminAuthority, sharedidentity.AdminAuthorityAsserted)
			},
			wantTenantWide: true, wantAdmin: true,
		},
		{
			// An admin-authority assertion with NO read scope. It resolves to
			// neither: the branch that reads the authority header is inside the
			// read-scope branch, so authority is not reachable on its own -
			// which is the coherent direction (AdminAuthority implies
			// TenantWide, asserted below for every case).
			name: "admin-authority assertion with no read scope: neither",
			mode: "enterprise", validator: true,
			mutate: func(t *testing.T, r *http.Request) {
				r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
				r.Header.Set(sharedidentity.HeaderAdminAuthority, sharedidentity.AdminAuthorityAsserted)
			},
			wantTenantWide: false, wantAdmin: false,
		},
		{
			name: "community-saas over the agent channel: scoping only",
			mode: "community-saas", validator: true,
			mutate: func(t *testing.T, r *http.Request) {
				r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
			},
			wantTenantWide: true, wantAdmin: false,
		},
		{
			name: "developer over the trusted channel: neither",
			mode: "enterprise", validator: true,
			mutate: func(t *testing.T, r *http.Request) {
				r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
				r.Header.Set(sharedidentity.HeaderUserRole, "developer")
			},
			wantTenantWide: false, wantAdmin: false,
		},
		{
			name: "community-saas with no agent channel: neither",
			mode: "community-saas", validator: true,
			mutate:         func(t *testing.T, r *http.Request) {},
			wantTenantWide: false, wantAdmin: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", c.mode)
			if c.validator {
				readScopeTestValidatorOn(t)
			}
			r := csaasRequest(t, csaasTestTenant)
			c.mutate(t, r)
			scope := resolveCallerReadScope(r)
			if scope.TenantWide != c.wantTenantWide {
				t.Errorf("TenantWide = %v, want %v", scope.TenantWide, c.wantTenantWide)
			}
			if scope.AdminAuthority != c.wantAdmin {
				t.Errorf("AdminAuthority = %v, want %v", scope.AdminAuthority, c.wantAdmin)
			}
			// The invariant that keeps the two axes coherent: admin authority
			// is a strict superset of tenant-wide scoping. A scope that
			// administers without being able to read would be incoherent.
			if scope.AdminAuthority && !scope.TenantWide {
				t.Error("AdminAuthority must imply TenantWide")
			}
		})
	}
}

// The free-tier boundary, pinned across the WHOLE #2934 route census rather
// than one sampled path — cost/usage reads AND the budget/execution mutations
// that ride the same gate.
func TestDomainReadAuthority_CommunitySaasStillDenied(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)
	router := domainGateRouter(nil)

	for _, route := range gatedDomainRoutes {
		req := httptest.NewRequest(route.method, route.path, nil)
		req.Header.Set("X-Tenant-ID", csaasTestTenant)
		req.Header.Set("X-Org-ID", csaasTestTenant)
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("community-saas caller on %s %s must stay 403 (free-tier boundary), got %d",
				route.method, route.path, w.Code)
		}
	}
}

// Same for the whole-tenant compliance/evidence export family.
func TestTenantWideAuditExport_CommunitySaasStillDenied(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)

	h := enforceTenantWideAuditExport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, path := range tenantWideAuditExportPaths {
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("X-Tenant-ID", csaasTestTenant)
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("community-saas caller on %s must stay 403 (free-tier boundary), got %d", path, w.Code)
		}
	}
}

// POST /api/v1/budgets/check stays reachable (it is the spend-enforcement
// decision the SDKs gate on) but must keep REDACTING the absolute figures for a
// community-saas caller. This is the one gated path where the pre-fix and
// post-fix behavior differ only in a context flag, so it is easy to lose.
func TestBudgetsCheck_CommunitySaasKeepsSpendRedaction(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)

	var redacted bool
	router := domainGateRouter(&redacted)

	req := httptest.NewRequest("POST", budgetCheckPath, nil)
	req.Header.Set("X-Tenant-ID", csaasTestTenant)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("budgets/check must stay reachable, got %d", w.Code)
	}
	if !redacted {
		t.Fatal("community-saas caller must receive REDACTED spend figures on budgets/check")
	}
}

// Control for the test above: an admin over the same channel is NOT redacted,
// so the assertion is testing the branch and not a constant.
func TestBudgetsCheck_AdminIsNotRedacted(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)

	var redacted bool
	router := domainGateRouter(&redacted)

	req := httptest.NewRequest("POST", budgetCheckPath, nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "admin")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK || redacted {
		t.Fatalf("admin must reach budgets/check unredacted (code=%d redacted=%v)", w.Code, redacted)
	}
}

// Defence in depth (#3060 round 2): the grant requires a non-empty X-Tenant-ID.
// Twelve of the read consumers reject a missing tenant header themselves, but
// enforceDomainReadAuthority is a bare gate and the replay repository treats an
// empty org as UNFILTERED — so an empty tenant must never reach tenant-wide.
func TestResolveCallerReadScope_CommunitySaas_EmptyTenantHeaderIsNotTenantWide(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	readScopeTestValidatorOn(t)

	for _, tenant := range []string{"", "   "} {
		r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
		if tenant != "" {
			r.Header.Set("X-Tenant-ID", tenant)
		}
		r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		r.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
		if scope := resolveCallerReadScope(r); scope.TenantWide {
			t.Fatalf("empty/blank X-Tenant-ID (%q) must not reach tenant-wide, got %+v", tenant, scope)
		}
	}
}
