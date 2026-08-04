// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// Read-authority tests for the unified compliance report facade (#3241,
// epic #2892 D4).
//
// D4 splits this route family across the two axes read_scope.go keeps apart:
// GENERATING a report and DOWNLOADING its artifact are the whole-tenant export
// class (admin authority), while POLLING a report's status is the `audit:read`
// viewing class. These tests pin both halves, and pin that the carve-out is a
// whitelist of exactly one shape.

// nonAdminViewer builds a request from a caller who has come over the trusted
// proxy-auth channel with a NON-admin fleet role: the "viewer holding
// audit:read" of the DoD. Such a caller reads the audit trail through the
// per-user-scoped read endpoints and must NOT thereby earn whole-tenant
// compliance artifacts.
func nonAdminViewer(t *testing.T, method, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "developer")
	req.Header.Set("X-User-Email", "viewer@acme.com")
	req.Header.Set("X-Org-ID", "acme-org")
	req.Header.Set("X-Tenant-ID", "acme-tenant")
	return req
}

func complianceGateHarness(t *testing.T) (http.Handler, *bool) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	called := false
	h := enforceTenantWideAuditExport(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	return h, &called
}

// TestComplianceReport_ViewerMayPoll is the D4 viewing half: a non-admin caller
// reaches the status poll.
//
// The poll returns job metadata only - id, status, progress, report_state,
// checksum - and no audit content, and the facade still authorizes the row
// against the caller's own tenancy. Gating it on admin authority would mean a
// compliance viewer could not see whether a report they are waiting on had
// finished.
func TestComplianceReport_ViewerMayPoll(t *testing.T) {
	h, called := complianceGateHarness(t)

	req := nonAdminViewer(t, http.MethodGet, "/api/v1/compliance/reports/creport-abc123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK || !*called {
		t.Fatalf("non-admin poll: got %d called=%v, want 200 + handler ran", w.Code, *called)
	}
}

// TestComplianceReport_ViewerIsBlockedFromGenerateAndDownload is the D4 export
// half: the same caller is refused on the two routes that produce an artifact.
func TestComplianceReport_ViewerIsBlockedFromGenerateAndDownload(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{"generate", http.MethodPost, "/api/v1/compliance/reports"},
		{"download", http.MethodGet, "/api/v1/compliance/reports/creport-abc123/download"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, called := complianceGateHarness(t)
			req := nonAdminViewer(t, tc.method, tc.path)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("non-admin %s %s: got %d, want 403", tc.method, tc.path, w.Code)
			}
			if *called {
				t.Errorf("non-admin %s %s: handler ran - the artifact route is not gated", tc.method, tc.path)
			}
		})
	}
}

// TestComplianceReport_AdminReachesEveryRoute is the vacuity control. Without
// it, a gate that 403s EVERYTHING under the prefix would satisfy the test
// above.
func TestComplianceReport_AdminReachesEveryRoute(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/compliance/reports"},
		{http.MethodGet, "/api/v1/compliance/reports/creport-abc123"},
		{http.MethodGet, "/api/v1/compliance/reports/creport-abc123/download"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			h, called := complianceGateHarness(t)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
			req.Header.Set(sharedidentity.HeaderUserRole, "admin")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusOK || !*called {
				t.Fatalf("admin %s %s: got %d called=%v, want 200 + handler ran", tc.method, tc.path, w.Code, *called)
			}
		})
	}
}

// TestComplianceReport_PollCarveOutIsExactlyOneShape pins that the carve-out is
// a WHITELIST, not a hole.
//
// Everything under the prefix that is not `GET /{id}` must stay gated: a
// mutating verb on the by-id path, a deeper sub-resource, and the bare
// collection GET. The last one matters most - a future list endpoint would
// return other people's report metadata across the whole tenant, and it must be
// gated by DEFAULT rather than needing someone to remember.
func TestComplianceReport_PollCarveOutIsExactlyOneShape(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{"delete by id", http.MethodDelete, "/api/v1/compliance/reports/creport-abc123"},
		{"put by id", http.MethodPut, "/api/v1/compliance/reports/creport-abc123"},
		{"post by id", http.MethodPost, "/api/v1/compliance/reports/creport-abc123"},
		{"deeper sub-resource", http.MethodGet, "/api/v1/compliance/reports/creport-abc123/sections/1"},
		{"collection list", http.MethodGet, "/api/v1/compliance/reports"},
		{"trailing slash", http.MethodGet, "/api/v1/compliance/reports/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, called := complianceGateHarness(t)
			req := nonAdminViewer(t, tc.method, tc.path)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s: got %d, want 403 - only `GET /{id}` is carved out of the export gate",
					tc.method, tc.path, w.Code)
			}
			if *called {
				t.Errorf("%s %s: handler ran", tc.method, tc.path)
			}
		})
	}
}

// TestComplianceReport_PathIsInTheExportClassList pins the literal registration
// required by the brief: the facade's base path is a member of
// tenantWideAuditExportPaths, so the prefix match covers /download and every
// future sub-resource without a second registration.
func TestComplianceReport_PathIsInTheExportClassList(t *testing.T) {
	found := false
	for _, p := range tenantWideAuditExportPaths {
		if p == complianceReportBasePath {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q is not in tenantWideAuditExportPaths: %v", complianceReportBasePath, tenantWideAuditExportPaths)
	}
	if !isTenantWideAuditExportPath(complianceReportBasePath + "/creport-1/download") {
		t.Error("the download sub-path is not covered by the prefix match")
	}
}

// TestComplianceReport_BasePathMatchesTheExportClassConstant guards the copy of
// the route literal that read_scope.go carries.
//
// read_scope.go compiles in BOTH editions, so it cannot import the
// Enterprise-tagged compliancereport package to reference its exported
// BasePath. The constant is therefore copied here, and a copy that drifts would
// silently un-gate the whole route family - the gate would simply stop matching
// and every request would pass through. This half of the guard is
// edition-independent and lives in the shared test.
//
// The other half - that this copy still matches the literal the facade actually
// registers, read out of compliancereport/handlers.go source - is
// Enterprise-only: that file carries `//go:build enterprise` and is not present
// in the community distribution, so the cross-file assertion lives in
// read_scope_compliance_report_enterprise_test.go.
func TestComplianceReport_BasePathMatchesTheExportClassConstant(t *testing.T) {
	const want = "/api/v1/compliance/reports"
	if complianceReportBasePath != want {
		t.Fatalf("complianceReportBasePath = %q, want %q", complianceReportBasePath, want)
	}
}
