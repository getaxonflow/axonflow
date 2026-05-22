// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestSpoofing_HeadersOverwrittenByAuth verifies that a caller cannot
// override the auth-derived identity by supplying their own X-Org-ID /
// X-Client-ID / X-Tenant-ID in the request. The apiAuthMiddleware MUST
// `Set` (not `Add`) these headers with the values resolved from
// Authenticate(), so the auth-derived identity is what every downstream
// handler reads — regardless of what the caller put on the wire.
//
// v9 (ADR-052 §5 / ADR-053 §Step 2): X-Client-ID is the canonical
// credential identity wire field; X-Tenant-ID is a deprecated alias
// kept for the compatibility window.
func TestSpoofing_HeadersOverwrittenByAuth(t *testing.T) {
	// Community mode gives us a stable auth-derived identity
	// (clientID == basic-auth username, orgID == local-dev-org)
	// without needing a live registrations table.
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	var (
		gotOrg    string
		gotClient string
		gotTenant string
	)
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("X-Org-ID")
		gotClient = r.Header.Get("X-Client-ID")
		gotTenant = r.Header.Get("X-Tenant-ID")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	req.SetBasicAuth("legit-client", "any-secret")
	// Adversarial: caller tries to pretend they're another tenant.
	req.Header.Set("X-Org-ID", "victim-org")
	req.Header.Set("X-Client-ID", "victim-client")
	req.Header.Set("X-Tenant-ID", "victim-tenant")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if gotOrg == "victim-org" {
		t.Errorf("X-Org-ID was NOT overwritten by auth — spoof succeeded (got %q)", gotOrg)
	}
	if gotClient == "victim-client" {
		t.Errorf("X-Client-ID was NOT overwritten by auth — spoof succeeded (got %q)", gotClient)
	}
	if gotTenant == "victim-tenant" {
		t.Errorf("X-Tenant-ID was NOT overwritten by auth — spoof succeeded (got %q)", gotTenant)
	}
	// Affirmative shape check — auth must have stamped the canonical
	// identity. In community mode that's basic-auth username + deployment
	// org.
	if gotClient != "legit-client" {
		t.Errorf("X-Client-ID = %q, want %q (auth-derived)", gotClient, "legit-client")
	}
	if gotTenant != "legit-client" {
		t.Errorf("X-Tenant-ID = %q, want %q (compat alias of client)", gotTenant, "legit-client")
	}
	if gotOrg == "" {
		t.Errorf("X-Org-ID must be non-empty after auth, got empty")
	}
}

// TestSpoofing_ContextOverwrittenByAuth confirms the same isolation
// happens at the Go-context layer too — handlers reading from context
// (the preferred v9 path) see the auth-derived identity, not the
// adversarial header values.
func TestSpoofing_ContextOverwrittenByAuth(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	var ctxIdentity RequestIdentity
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxIdentity = RequestIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	req.SetBasicAuth("legit-client", "any-secret")
	req.Header.Set("X-Org-ID", "victim-org")
	req.Header.Set("X-Client-ID", "victim-client")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ctxIdentity.ClientID == "victim-client" || ctxIdentity.OrgID == "victim-org" {
		t.Errorf("context identity carried spoofed values: %+v", ctxIdentity)
	}
	if ctxIdentity.ClientID != "legit-client" {
		t.Errorf("ctx ClientID = %q, want %q (auth-derived)", ctxIdentity.ClientID, "legit-client")
	}
}

// TestSpoofing_ProxyHeadersOverwrittenByAuth covers the second header
// surface: the proxy that fronts orchestrator-bound traffic. proxy.go
// also `Set`s (not Add) the three identity headers; a caller cannot
// piggy-back values past the proxy boundary.
func TestSpoofing_ProxyHeadersOverwrittenByAuth(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	var gotOrg, gotClient, gotTenant string
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		gotOrg = r.Header.Get("X-Org-ID")
		gotClient = r.Header.Get("X-Client-ID")
		gotTenant = r.Header.Get("X-Tenant-ID")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/audit/summary", nil)
	req.SetBasicAuth("real-proxy-client", "secret")
	req.Header.Set("X-Org-ID", "attacker-org")
	req.Header.Set("X-Client-ID", "attacker-client")
	req.Header.Set("X-Tenant-ID", "attacker-tenant")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	if gotOrg == "attacker-org" || gotClient == "attacker-client" || gotTenant == "attacker-tenant" {
		t.Errorf("proxy did not overwrite spoofed identity headers: org=%q client=%q tenant=%q",
			gotOrg, gotClient, gotTenant)
	}
	if gotClient != "real-proxy-client" {
		t.Errorf("X-Client-ID = %q, want %q", gotClient, "real-proxy-client")
	}
}
