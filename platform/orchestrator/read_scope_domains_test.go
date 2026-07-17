// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/cost"
	sharedidentity "axonflow/platform/shared/identity"
)

// enforceDomainReadAuthority is the #2934 gate over the cost/usage and
// execution route families. Like the read_scope tests, the forged-header /
// no-identity / shared-credential cases are first-class here.

// gatedDomainRoutes is the full #2934 census of gated routes — one entry per
// registered route so a future registration outside these families shows up
// in review, not in production.
var gatedDomainRoutes = []struct {
	method, path string
}{
	{"GET", "/api/v1/usage"},
	{"GET", "/api/v1/usage/breakdown"},
	{"GET", "/api/v1/usage/records"},
	{"GET", "/api/v1/budgets"},
	{"POST", "/api/v1/budgets"},
	{"GET", "/api/v1/budgets/b1"},
	{"PUT", "/api/v1/budgets/b1"},
	{"DELETE", "/api/v1/budgets/b1"},
	{"GET", "/api/v1/budgets/b1/status"},
	{"GET", "/api/v1/budgets/b1/alerts"},
	{"GET", "/api/v1/executions"},
	{"GET", "/api/v1/executions/req-1"},
	{"GET", "/api/v1/executions/req-1/steps"},
	{"GET", "/api/v1/executions/req-1/steps/0"},
	{"GET", "/api/v1/executions/req-1/timeline"},
	{"GET", "/api/v1/executions/req-1/export"},
	{"DELETE", "/api/v1/executions/req-1"},
	{"GET", "/api/v1/unified/executions"},
	{"GET", "/api/v1/unified/executions/exec-1"},
	{"GET", "/api/v1/unified/executions/exec-1/stream"},
	{"POST", "/api/v1/unified/executions/exec-1/cancel"},
	{"GET", "/api/v1/workflows/executions"},
	{"GET", "/api/v1/workflows/executions/wf-1"},
	{"GET", "/api/v1/workflows/executions/tenant/tenant-b"},
}

// domainGateRouter registers a catch-all stub behind the middleware so every
// census path resolves to a route (mux.Use middleware only runs on matched
// routes — same contract as production, where all these paths are
// registered).
func domainGateRouter(probe *bool) *mux.Router {
	r := mux.NewRouter()
	r.Use(enforceDomainReadAuthority)
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if probe != nil {
			*probe = cost.SpendRedactionRequested(req.Context())
		}
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func TestDomainReadAuthority_SharedCredentialIsDenied(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := domainGateRouter(nil)

	for _, route := range gatedDomainRoutes {
		// The reported class: a fleet developer on the shared tenant
		// credential — proxied (valid proxy-auth) but non-admin role.
		req := httptest.NewRequest(route.method, route.path, nil)
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "dev@acme.com")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("developer on %s %s must be 403, got %d", route.method, route.path, w.Code)
		}

		// No identity at all (token-less direct caller).
		req = httptest.NewRequest(route.method, route.path, nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("identity-less caller on %s %s must be 403, got %d", route.method, route.path, w.Code)
		}

		// Forged admin role WITHOUT proxy-auth must not elevate.
		req = httptest.NewRequest(route.method, route.path, nil)
		req.Header.Set(sharedidentity.HeaderUserRole, "admin")
		req.Header.Set(sharedidentity.HeaderReadScope, sharedidentity.ReadScopeTenant)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("forged admin on %s %s must be 403, got %d", route.method, route.path, w.Code)
		}
	}
}

func TestDomainReadAuthority_TenantWidePassesThrough(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := domainGateRouter(nil)

	for _, route := range gatedDomainRoutes {
		req := httptest.NewRequest(route.method, route.path, nil)
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "admin")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("admin on %s %s must pass, got %d", route.method, route.path, w.Code)
		}
	}
}

func TestDomainReadAuthority_CommunityPassesThrough(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	r := domainGateRouter(nil)

	for _, route := range gatedDomainRoutes {
		req := httptest.NewRequest(route.method, route.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("community on %s %s must pass, got %d", route.method, route.path, w.Code)
		}
	}
}

func TestDomainReadAuthority_ExemptionsAndBoundaries(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	r := domainGateRouter(nil)

	// Documented exemptions and non-gated look-alikes stay reachable to a
	// non-admin caller.
	for _, p := range []struct{ method, path string }{
		{"GET", "/api/v1/pricing"},              // static pricing tables
		{"POST", "/api/v1/budgets/check"},       // enforcement plane (redacted)
		{"GET", "/api/v1/usage-report-other"},   // path-segment boundary
		{"GET", "/api/v1/executionsandmore"},    // path-segment boundary
		{"POST", "/api/v1/process"},             // unrelated route family
		{"OPTIONS", "/api/v1/usage/breakdown"},  // CORS preflight
		{"OPTIONS", "/api/v1/executions/req-1"}, // CORS preflight
		// hitl-status is a legitimate per-execution developer poll — exempted
		// even though it sits under the workflows/executions prefix.
		{"GET", "/api/v1/workflows/executions/wf-1/hitl-status"},
		{"GET", "/api/v1/workflows/other-thing"}, // non-executions workflows path
	} {
		req := httptest.NewRequest(p.method, p.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s must not be gated, got %d", p.method, p.path, w.Code)
		}
	}
}

func TestDomainReadAuthority_BudgetCheckRedactionFlag(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	readScopeTestValidatorOn(t)
	var redactionSeen bool
	r := domainGateRouter(&redactionSeen)

	// Non-tenant-wide caller: handler must see the redaction flag.
	req := httptest.NewRequest("POST", "/api/v1/budgets/check", nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "developer")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("budget check must stay reachable for non-admin, got %d", w.Code)
	}
	if !redactionSeen {
		t.Fatal("non-tenant-wide budget check must carry the spend-redaction flag")
	}

	// Tenant-wide caller: no redaction.
	req = httptest.NewRequest("POST", "/api/v1/budgets/check", nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "admin")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("budget check must pass for admin, got %d", w.Code)
	}
	if redactionSeen {
		t.Fatal("tenant-wide budget check must NOT carry the spend-redaction flag")
	}
}

func TestIsDomainGovernancePath(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/v1/usage":                              true,
		"/api/v1/usage/breakdown":                    true,
		"/api/v1/budgets/b1/alerts":                  true,
		"/api/v1/executions":                         true,
		"/api/v1/executions/x/export":                true,
		"/api/v1/unified/executions/x/stream":        true,
		"/api/v1/cost/anything":                      true,
		"/api/v1/workflows/executions":               true,
		"/api/v1/workflows/executions/x":             true,
		"/api/v1/workflows/executions/tenant/t":      true,
		"/api/v1/workflows/executions/x/hitl-status": false,
		"/api/v1/usage-other":                        false,
		"/api/v1/pricing":                            false,
		"/api/v1/audit/search":                       false,
		"/api/v1/unified/executionsish":              false,
		"/api/v1/budgetsandbeyond":                   false,
		"/api/v1/workflows/definitions":              false,
	} {
		if got := isDomainGovernancePath(p); got != want {
			t.Fatalf("isDomainGovernancePath(%q) = %v, want %v", p, got, want)
		}
	}
}
