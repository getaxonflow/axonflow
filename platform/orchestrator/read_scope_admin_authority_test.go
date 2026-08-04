// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// The #3241 round-2 axes fix, on the PORTAL plane.
//
// read_scope.go granted AdminAuthority on X-Axonflow-Read-Scope: tenant alone.
// The customer-portal stamps that header for any session holding audit:read,
// and the seeded VIEWER role holds audit:read - so through the portal, a viewer
// passed every AdminAuthority gate: the compliance report facade's create and
// download, /api/v1/evidence/export, /api/v1/sebi/audit/export, budget
// governance CRUD, execution cancel/delete, unredacted spend.
//
// The DoD claim "non-admin: 403 on generate and download" was true on the fleet
// plane (a viewer's X-Axonflow-User-Role fails RoleCanReadTenant) and false on
// the portal plane, which is the plane a human viewer actually uses. These
// tests model the portal plane specifically: read-scope asserted, role header
// absent - exactly what orchestrator_proxy.go sends.

// portalSession builds the request the customer-portal proxy actually
// constructs: internal proxy-auth, a tenant read-scope assertion, no
// X-Axonflow-User-Role (the portal does not stamp one), and the admin-authority
// header only when asserted.
func portalSession(t *testing.T, method, path string, adminAuthority bool) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
	req.Header.Set("X-User-Email", "person@acme.com")
	req.Header.Set("X-Org-ID", "acme-org")
	req.Header.Set("X-Tenant-ID", "acme-tenant")
	if adminAuthority {
		req.Header.Set(sharedidentity.HeaderAdminAuthority, sharedidentity.AdminAuthorityAsserted)
	}
	return req
}

// adminAuthorityGatedPaths are the whole-tenant export routes the middleware
// gates. Derived from tenantWideAuditExportPaths rather than hand-listed, so a
// route family added to the gate is covered here automatically instead of
// silently escaping the property.
func adminAuthorityGatedPaths(t *testing.T) []string {
	t.Helper()
	if len(tenantWideAuditExportPaths) == 0 {
		t.Fatal("tenantWideAuditExportPaths is empty - this test would pass vacuously")
	}
	var out []string
	for _, p := range tenantWideAuditExportPaths {
		out = append(out, p)
	}
	return out
}

// TestPortalReadScopeAloneIsNotAdminAuthority is the property, stated directly.
func TestPortalReadScopeAloneIsNotAdminAuthority(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)

	req := portalSession(t, http.MethodPost, "/api/v1/compliance/reports", false)
	scope := resolveCallerReadScope(req)

	if !scope.TenantWide {
		t.Error("a portal read-scope assertion no longer grants TenantWide - the fix has over-narrowed; " +
			"a viewer must keep reading its tenant's audit trail")
	}
	if scope.AdminAuthority {
		t.Fatal("X-Axonflow-Read-Scope: tenant alone still grants AdminAuthority. The portal stamps that " +
			"header for every audit:read holder, including the seeded viewer role, so this is the viewer " +
			"passing every whole-tenant export gate.")
	}
}

// TestPortalAdminAuthorityHeaderGrantsAuthority is the positive control. Without
// it, a fix that simply always returned AdminAuthority=false would satisfy the
// test above and 403 every administrator.
func TestPortalAdminAuthorityHeaderGrantsAuthority(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)

	scope := resolveCallerReadScope(portalSession(t, http.MethodPost, "/api/v1/compliance/reports", true))
	if !scope.AdminAuthority || !scope.TenantWide {
		t.Fatalf("an asserted admin authority did not resolve: %+v", scope)
	}
}

// TestPortalViewerIs403OnEveryGatedExportPath drives the middleware itself,
// across every route family in the gate - not just the facade's. Two of these
// (/api/v1/evidence/export, /api/v1/sebi/audit/export) are the LIVE pre-existing
// instances of the conflation named in the R3 record.
func TestPortalViewerIs403OnEveryGatedExportPath(t *testing.T) {
	for _, base := range adminAuthorityGatedPaths(t) {
		t.Run(base, func(t *testing.T) {
			h, called := complianceGateHarness(t)
			req := portalSession(t, http.MethodPost, base, false)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden || *called {
				t.Fatalf("viewer through the portal: got %d called=%v, want 403 and the handler NOT reached "+
					"(this path is a whole-tenant export)", w.Code, *called)
			}
		})
	}
}

// TestPortalAdminReachesEveryGatedExportPath is the matching positive control:
// the same requests with authority asserted must pass, or the fix has simply
// broken the console for administrators.
func TestPortalAdminReachesEveryGatedExportPath(t *testing.T) {
	for _, base := range adminAuthorityGatedPaths(t) {
		t.Run(base, func(t *testing.T) {
			h, called := complianceGateHarness(t)
			req := portalSession(t, http.MethodPost, base, true)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusOK || !*called {
				t.Fatalf("admin through the portal: got %d called=%v, want 200 + handler ran", w.Code, *called)
			}
		})
	}
}

// TestPortalViewerStillPollsAComplianceReport pins that the fix did not close
// the D4 viewing half: the status poll stays reachable without authority.
func TestPortalViewerStillPollsAComplianceReport(t *testing.T) {
	h, called := complianceGateHarness(t)
	req := portalSession(t, http.MethodGet, "/api/v1/compliance/reports/creport-abc123", false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK || !*called {
		t.Fatalf("viewer poll: got %d called=%v, want 200 + handler ran", w.Code, *called)
	}
}

// TestAdminAuthorityHeaderIsIgnoredWithoutProxyAuth is the trust-boundary
// property: the header is honoured ONLY over the internal-service channel. A
// caller that reaches the orchestrator directly and asserts it gets nothing.
func TestAdminAuthorityHeaderIsIgnoredWithoutProxyAuth(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/reports", nil)
	req.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
	req.Header.Set(sharedidentity.HeaderAdminAuthority, sharedidentity.AdminAuthorityAsserted)
	req.Header.Set("X-User-Email", "attacker@acme.com")
	req.Header.Set("X-Org-ID", "acme-org")
	req.Header.Set("X-Tenant-ID", "acme-tenant")

	if scope := resolveCallerReadScope(req); scope.AdminAuthority || scope.TenantWide {
		t.Fatalf("headers asserted without proxy-auth were honoured: %+v", scope)
	}
}

// TestAdminAuthorityHeaderValueParsing pins that only "true" asserts, and that
// the parse is forgiving in the one safe direction (casing/whitespace from an
// intermediary) and unforgiving in every other.
func TestAdminAuthorityHeaderValueParsing(t *testing.T) {
	cases := map[string]bool{
		"true":   true,
		"TRUE":   true,
		" true":  true,
		"true ":  true,
		"":       false,
		"false":  false,
		"1":      false,
		"yes":    false,
		"tenant": false,
		"truthy": false,
	}
	for v, want := range cases {
		if got := sharedidentity.AdminAuthorityFromHeader(v); got != want {
			t.Errorf("AdminAuthorityFromHeader(%q) = %v, want %v", v, got, want)
		}
	}
}
