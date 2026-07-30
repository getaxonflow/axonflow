// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Regression tests for #3092 — "OPTIONS passthrough runs auth-gated handlers
// anonymously".
//
// Both agent auth middlewares used to short-circuit `r.Method == OPTIONS` by
// calling the wrapped handler WITHOUT authenticating. Because rs/cors only
// answers a preflight when Access-Control-Request-Method is also present
// (github.com/rs/cors@v1.11.1 cors.go:274), a *plain* OPTIONS — no ACRM, with
// a body — sailed past it into the router, and any route registered
// `.Methods("POST", "OPTIONS")` then ran its handler with no identity in
// context.
//
// The tests below pin the three properties that close the class:
//
//  1. apiAuthMiddleware TERMINATES a preflight; the wrapped handler never runs.
//  2. proxyAuthMiddleware terminates it too AND leaves no client-supplied
//     tenancy/authority header on the request — the more dangerous half,
//     because the reverse-proxy Director injects a valid internal HMAC
//     unconditionally, so a surviving X-Tenant-ID would be a *forged* tenancy
//     the orchestrator has every reason to trust.
//  3. The two handlers that are registered for OPTIONS refuse a non-POST
//     themselves, so neither a route re-registration nor a future middleware
//     edit can hand an unauthenticated method the decision engine.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	sharedidentity "axonflow/platform/shared/identity"
)

// TestAPIAuthMiddleware_PlainOptionsDoesNotReachHandler is the middleware-level
// statement of the defect: an OPTIONS request carrying a body must not be
// forwarded to the wrapped, auth-gated handler.
func TestAPIAuthMiddleware_PlainOptionsDoesNotReachHandler(t *testing.T) {
	// Community mode is the *most permissive* posture — auth would succeed
	// here. Using it makes the test about the preflight short-circuit alone,
	// not about whether a credential happened to be missing.
	t.Setenv("DEPLOYMENT_MODE", "community")

	handlerRan := false
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, decisionHandlerPath,
		strings.NewReader(`{"stage":"pre_llm","statement":"select * from customers"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if handlerRan {
		t.Error("auth-gated handler ran for an unauthenticated OPTIONS request (#3092)")
	}
	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

// TestDecideRoute_PlainOptionsWithBodyRunsNoEngineAndWritesNoAudit drives the
// REAL route registration (RegisterDecisionHandlers) rather than a stand-in
// handler, because the defect lives in the interaction between the
// `.Methods("POST", "OPTIONS")` registration and the middleware.
//
// The audit assertion is inverted on purpose: an INSERT expectation is armed
// and the test passes only when it is left UNMET. A handler that ran would
// write a canonical plane=decision row (recordDecideDecision is called on every
// path, including the early-return denies), so "expectation unmet" is a direct
// assertion that no audit_logs row was written for an anonymous caller.
func TestDecideRoute_PlainOptionsWithBodyRunsNoEngineAndWritesNoAudit(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = mockDB.Close() }()

	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	mock.ExpectExec("INSERT INTO audit_logs").
		WillReturnResult(sqlmock.NewResult(1, 1))

	router := mux.NewRouter()
	RegisterDecisionHandlers(router)

	req := httptest.NewRequest(http.MethodOptions, decisionHandlerPath,
		strings.NewReader(`{"stage":"pre_llm","statement":"DROP TABLE customers","target":{"type":"database"}}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want %d (body=%q)", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	// handleDecide mints a decision_id and a W3C trace_id up front and returns
	// them on EVERY path, including a decode failure. Their absence is the
	// observable proof the decision engine never ran.
	if body := rr.Body.String(); strings.Contains(body, "decision_id") || strings.Contains(body, "verdict") {
		t.Errorf("decision engine ran for an anonymous OPTIONS request: body=%q", body)
	}

	if err := mock.ExpectationsWereMet(); err == nil {
		t.Error("an audit_logs row was written for an anonymous OPTIONS request (#3092)")
	}
}

// TestProxyAuthMiddleware_OptionsDoesNotForwardClientSuppliedTenancy covers the
// half of #3092 the issue calls the more dangerous one. proxyAuthMiddleware
// returned on OPTIONS *before* the header scrub, so a caller could SUPPLY
// tenancy rather than merely omit it — and the reverse-proxy Director appends a
// valid internal HMAC to whatever it forwards.
func TestProxyAuthMiddleware_OptionsDoesNotForwardClientSuppliedTenancy(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	nextRan := false
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		nextRan = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/audit/search", nil)
	forged := map[string]string{
		"X-Tenant-ID":                      "victim-tenant",
		"X-Org-ID":                         "victim-org",
		"X-Client-ID":                      "victim-client",
		"X-Axonflow-Effective-Tier":        "premium",
		sharedidentity.HeaderUserRole:      "admin",
		sharedidentity.HeaderReadScope:     "tenant",
		sharedidentity.HeaderIdentityGated: sharedidentity.IdentityGatedTrue,
	}
	for k, v := range forged {
		req.Header.Set(k, v)
	}

	rr := httptest.NewRecorder()
	handler(rr, req)

	if nextRan {
		t.Error("proxy handler ran for an unauthenticated OPTIONS request (#3092)")
	}
	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want %d", rr.Code, http.StatusNoContent)
	}

	// The scrub mutates the request in place, so a surviving value is
	// observable here regardless of whether `next` was invoked. This is the
	// assertion that keeps holding if a future edit restores next(w, r).
	for k := range forged {
		if got := req.Header.Get(k); got != "" {
			t.Errorf("client-supplied %s survived the preflight: %q", k, got)
		}
	}
}

// TestHandleDecide_RefusesNonPost is the defence-in-depth layer: the handler
// guards r.Method itself, so it stays safe even if the route is re-registered
// for another method or the middleware short-circuit is reintroduced.
func TestHandleDecide_RefusesNonPost(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	for _, method := range []string{http.MethodOptions, http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, decisionHandlerPath,
				strings.NewReader(`{"stage":"pre_llm","statement":"x"}`))
			rr := httptest.NewRecorder()
			handleDecide(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d (body=%q)", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
			}
			if body := rr.Body.String(); strings.Contains(body, "decision_id") || strings.Contains(body, "verdict") {
				t.Errorf("decision engine ran for %s: body=%q", method, body)
			}
		})
	}
}

// TestHandleOpenAICompat_RefusesNonPost mirrors the decide guard. Without it the
// handler reads up to 10 MiB of body from an unauthenticated caller before it
// finds anything to reject.
func TestHandleOpenAICompat_RefusesNonPost(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	for _, method := range []string{http.MethodOptions, http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, openaiCompatPath,
				strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
			rr := httptest.NewRecorder()
			handleOpenAICompat(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want %d (body=%q)", rr.Code, http.StatusMethodNotAllowed, rr.Body.String())
			}
		})
	}
}
