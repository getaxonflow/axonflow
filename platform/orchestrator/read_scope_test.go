// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/serviceauth"
)

// resolveCallerReadScope is the trust core for the #2922 role-scoped reads.
// These tests exercise every branch of the trust ladder — the forged-header /
// no-token cases are first-class, not the happy path.

func readScopeTestValidatorOn(t *testing.T) {
	t.Helper()
	orig := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator(proxyGuardTestSecret, nil, serviceauth.DefaultClockSkew)
	t.Cleanup(func() { proxyTokenValidator = orig })
}

func TestResolveCallerReadScope_CommunityIsTenantWide(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	// Even a forged role + no proxy auth: community is single-operator, so
	// tenant-wide is correct and cannot be a cross-user leak.
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set(sharedidentity.HeaderUserRole, "viewer")
	r.Header.Set("X-User-Email", "dev@acme.com")
	if scope := resolveCallerReadScope(r); !scope.TenantWide {
		t.Fatalf("community mode must be tenant-wide, got %+v", scope)
	}
}

func TestResolveCallerReadScope_AdminOverTrustedChannel(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)

	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	r.Header.Set(sharedidentity.HeaderUserRole, "admin")
	if scope := resolveCallerReadScope(r); !scope.TenantWide {
		t.Fatalf("admin over valid proxy-auth must be tenant-wide, got %+v", scope)
	}
}

func TestResolveCallerReadScope_OwnerOverTrustedChannel(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	r.Header.Set(sharedidentity.HeaderUserRole, "owner")
	if scope := resolveCallerReadScope(r); !scope.TenantWide {
		t.Fatalf("owner over valid proxy-auth must be tenant-wide, got %+v", scope)
	}
}

func TestResolveCallerReadScope_PortalTenantScopeAssertion(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	r.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
	if scope := resolveCallerReadScope(r); !scope.TenantWide {
		t.Fatalf("portal tenant-scope assertion over valid proxy-auth must be tenant-wide, got %+v", scope)
	}
}

func TestResolveCallerReadScope_DeveloperRoleIsOwnRows(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	r.Header.Set(sharedidentity.HeaderUserRole, "developer")
	r.Header.Set("X-User-Email", "Dev@Acme.com")
	scope := resolveCallerReadScope(r)
	if scope.TenantWide {
		t.Fatalf("developer must be own-rows, got tenant-wide")
	}
	if scope.UserEmail != "dev@acme.com" {
		t.Fatalf("own-rows identity must be canonicalized, got %q", scope.UserEmail)
	}
}

// The forgery case that motivated the whole epic: a caller who reaches the
// orchestrator WITHOUT valid proxy-auth cannot mint tenant-wide scope by
// setting the role header themselves. Enterprise mode + validator on + a
// forged admin role but NO proxy token ⇒ own-rows.
func TestResolveCallerReadScope_ForgedRoleWithoutProxyAuthIsOwnRows(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set(sharedidentity.HeaderUserRole, "admin") // forged, no proxy token
	r.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
	r.Header.Set("X-User-Email", "attacker@acme.com")
	scope := resolveCallerReadScope(r)
	if scope.TenantWide {
		t.Fatal("forged role without proxy-auth must NOT be tenant-wide")
	}
	if scope.UserEmail != "attacker@acme.com" {
		t.Fatalf("own-rows identity, got %q", scope.UserEmail)
	}
}

// A forged admin role delivered with an INVALID proxy token is still own-rows —
// the validator rejects the token, so the elevating headers are never read.
func TestResolveCallerReadScope_InvalidProxyTokenIsOwnRows(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set("X-Axonflow-Proxy-Auth", "AXON-INTERNAL-9999999999-deadbeefdeadbeef")
	r.Header.Set(sharedidentity.HeaderUserRole, "admin")
	if scope := resolveCallerReadScope(r); scope.TenantWide {
		t.Fatal("invalid proxy token must NOT elevate to tenant-wide")
	}
}

// No per-user identity at all (shared-credential caller, gate off) ⇒ own-rows
// with an EMPTY identity, which every consumer maps to zero rows (fail-closed).
func TestResolveCallerReadScope_NoIdentityIsEmptyOwnRows(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t)) // valid, but no role/scope
	scope := resolveCallerReadScope(r)
	if scope.TenantWide {
		t.Fatal("no elevating header must NOT be tenant-wide")
	}
	if scope.UserEmail != "" {
		t.Fatalf("expected empty own-rows identity, got %q", scope.UserEmail)
	}
}

// Belt-and-suspenders: an unknown role string over a VALID proxy channel is
// still own-rows (NormalizeRole collapses it).
func TestResolveCallerReadScope_UnknownRoleOverTrustedChannelIsOwnRows(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	r.Header.Set(sharedidentity.HeaderUserRole, "root")
	if scope := resolveCallerReadScope(r); scope.TenantWide {
		t.Fatal("unknown role must NOT be tenant-wide even over trusted channel")
	}
}

// --- enforceTenantWideAuditExport middleware (#2923 R3 census gap) ---

func TestEnforceTenantWideAuditExport_NonAdminBlocked(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)

	called := false
	h := enforceTenantWideAuditExport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range tenantWideAuditExportPaths {
		called = false
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer") // non-admin
		req.Header.Set("X-User-Email", "dev@acme.com")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: non-admin got %d, want 403", path, w.Code)
		}
		if called {
			t.Errorf("%s: handler ran for a non-admin — export leaked", path)
		}
	}
}

func TestEnforceTenantWideAuditExport_SharedCredentialBlocked(t *testing.T) {
	// The exact exploit: shared org:license, no per-user token/role.
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	h := enforceTenantWideAuditExport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t)) // valid hop, no role
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("shared-credential caller got %d, want 403", w.Code)
	}
}

func TestEnforceTenantWideAuditExport_AdminAllowed(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	called := false
	h := enforceTenantWideAuditExport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/api/v1/euaiact/export", nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "admin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("admin got %d called=%v, want 200 + handler ran", w.Code, called)
	}
}

func TestEnforceTenantWideAuditExport_NonExportPathPassesThrough(t *testing.T) {
	// A non-export path is untouched even for a non-admin — the middleware must
	// not interfere with the per-user-scoped read endpoints (they scope
	// themselves) or any other route.
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	called := false
	h := enforceTenantWideAuditExport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/api/v1/audit/search", nil) // scoped elsewhere
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "developer")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("non-export path must pass through, got %d called=%v", w.Code, called)
	}
}

func TestEnforceTenantWideAuditExport_CommunityAllowed(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	called := false
	h := enforceTenantWideAuditExport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/api/v1/sebi/audit/export", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("community single-operator must be allowed, got %d called=%v", w.Code, called)
	}
}

var _ = http.MethodPost

// #2919 Finding 1 (RBAC-3 follow-up): a token-less fleet caller forwards the
// SHARED mcp-client:<clientID> pseudo-identity as X-User-Email — identical for
// every developer on one org:license credential. Scoping to it would return the
// whole token-less pool (the reported cross-developer audit-read leak). It must
// fail closed to an EMPTY scope (zero rows), symmetric with the REST plane's
// gate-off behavior — never scope to the shared pseudo.
func TestResolveCallerReadScope_ClientPseudoIdentityIsFailClosed(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
	// Valid proxy-auth (the agent always attaches it) but no elevating role;
	// the forwarded identity is the shared client pseudo.
	r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	r.Header.Set("X-User-Email", "mcp-client:acme-org")
	scope := resolveCallerReadScope(r)
	if scope.TenantWide {
		t.Fatalf("shared client pseudo must never be tenant-wide")
	}
	if scope.UserEmail != "" {
		t.Fatalf("shared client pseudo must fail closed to empty scope (zero rows), got %q", scope.UserEmail)
	}
}

// #2938: the read scope fails closed on the FULL shared synthetic-identity
// census, not just the mcp-client: prefix (#2936). Every spelling the platform
// mints into audit_logs.user_email as a multi-caller pool must resolve to an
// EMPTY scope (zero rows) — an in-VPC caller asserting one via X-User-Email
// must never receive that pool. The census predicate is SHARED
// (sharedidentity.IsSharedSyntheticIdentity, also consumed by the agent's
// override trust plane), so the sixth-string case pins the anti-drift
// property: a census entry named in NO local list here is still emptied,
// because this plane keys on the one shared predicate.
func TestResolveCallerReadScope_SharedSyntheticCensusFailsClosed(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	spellings := []string{
		"mcp-client:acme-org",            // token-less MCP pseudo (#2936)
		"acme-org@axonflow.local",        // enterprise no-token /decide fallback
		"unknown@axonflow.local",         // audit-writer fallback
		"orchestrator@axonflow.internal", // internal-service ResolveUser
		"system@axonflow.internal",       // HITL auto-approve reviewer (#2938 R3)
		"evaluator@try.getaxonflow.com",  // community-saas ResolveUser
		// The community synthetic asserted OUTSIDE community mode is a spoof
		// (community itself returned tenant-wide before this check).
		"local-dev@axonflow.local",
		// Case evasion: canonicalized before the census check.
		"Evaluator@Try.GetAxonflow.Com",
		// Sixth string — in the shared census rules but in no enumerated list
		// on this plane: proves the predicate is shared, not copied.
		"sixth-new-census-entry@axonflow.local",
		"future-service@axonflow.internal",
	}
	for _, s := range spellings {
		r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
		r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		r.Header.Set("X-User-Email", s)
		scope := resolveCallerReadScope(r)
		if scope.TenantWide {
			t.Errorf("%q: shared synthetic identity must never be tenant-wide", s)
		}
		if scope.UserEmail != "" {
			t.Errorf("%q: must fail closed to empty scope (zero rows), got %q", s, scope.UserEmail)
		}
	}

	// Guard against an over-broad match: a real per-user identity — including
	// near-miss domains a careless suffix check would catch — still reads its
	// own rows.
	for _, legit := range []string{"dev@acme.com", "ops@corp.local", "x@notaxonflow.local", "x@corp.internal"} {
		r := httptest.NewRequest("POST", "/api/v1/audit/search", nil)
		r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		r.Header.Set("X-User-Email", legit)
		scope := resolveCallerReadScope(r)
		if scope.TenantWide {
			t.Errorf("%q: plain identity must not be tenant-wide", legit)
		}
		if scope.UserEmail != legit {
			t.Errorf("%q: legitimate identity must keep own-rows scope, got %q", legit, scope.UserEmail)
		}
	}
}
