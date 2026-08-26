// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"axonflow/platform/shared/serviceauth"
)

// #3068 — the orchestrator served its whole API, including tenant-selectable
// reads AND writes on the governance control plane, with no authentication
// middleware at all. These tests drive requireInternalProxyAuth as it is
// actually wired in run.go: wrapping a real mux, in front of real routes.
//
// The headline assertions are the REFUSALS. Each is paired with a control that
// proves the same request succeeds once it carries a valid token, so a
// regression that simply denies everything fails here too.

const authnTestSecret = "authn-middleware-test-secret-at-least-32-chars"

// tenantDataRoutes are routes that read or write tenant-scoped data. Every one
// of these answered an unauthenticated request before this change (see #3064's
// reproduction). None of them may be reachable without a valid token.
var tenantDataRoutes = []struct {
	method string
	path   string
}{
	{"GET", "/api/v1/policies/dynamic"},   // the 25-policy cross-tenant dump on prod
	{"POST", "/api/v1/policies"},          // unauthenticated cross-tenant policy WRITE
	{"GET", "/api/v1/dynamic-policies"},   //
	{"GET", "/api/v1/tenant-policies"},    // #1431 successor of the line above
	{"GET", "/api/v1/decisions"},          //
	{"GET", "/api/v1/overrides"},          //
	{"POST", "/api/v1/overrides"},         //
	{"GET", "/api/v1/audit/tenant/acme"},  //
	{"POST", "/api/v1/audit/search"},      //
	{"POST", "/api/v1/process"},           // the governed request plane
	{"GET", "/api/v1/metrics"},            // NOT the exempt /metrics
	{"GET", "/api/v1/unified/executions"}, //
	{"GET", "/api/v1/usage/summary"},      //
}

// newAuthnTestHandler builds the same handler shape run.go builds: the gate
// wrapping a mux. reached reports whether the request got past the gate.
func newAuthnTestHandler() (http.Handler, *bool) {
	reached := new(bool)
	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
	return requireInternalProxyAuth(r), reached
}

// withAuthnValidator installs a real HMAC validator, as a deployment with
// AXONFLOW_INTERNAL_SERVICE_SECRET set has.
func withAuthnValidator(t *testing.T) {
	t.Helper()
	orig := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator(authnTestSecret, nil, serviceauth.DefaultClockSkew)
	t.Cleanup(func() { proxyTokenValidator = orig })
}

func validAuthnToken() string {
	return serviceauth.NewTokenGenerator(authnTestSecret, nil).GenerateToken()
}

// TestRequireInternalProxyAuth_UnauthenticatedTenantRoutesRejected is the
// headline: the exact requests that worked against production with no
// credentials must now be refused, and must not reach a handler.
func TestRequireInternalProxyAuth_UnauthenticatedTenantRoutesRejected(t *testing.T) {
	withAuthnValidator(t)

	for _, rt := range tenantDataRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			h, reached := newAuthnTestHandler()

			req := httptest.NewRequest(rt.method, rt.path, nil)
			// Exactly the #3064 reproduction: a client-chosen tenant selector
			// and no credential of any kind.
			req.Header.Set("X-Tenant-ID", "other-tenant-acme")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rr.Code)
			}
			if *reached {
				t.Error("unauthenticated request REACHED the handler")
			}
		})
	}
}

// TestRequireInternalProxyAuth_ValidTokenSucceeds is the control for the test
// above: the legitimate callers (agent proxy, agent governed forward, agent MCP
// forwarders, customer-portal proxies) all mint this token, and every one of
// those routes must still work.
func TestRequireInternalProxyAuth_ValidTokenSucceeds(t *testing.T) {
	withAuthnValidator(t)

	for _, rt := range tenantDataRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			h, reached := newAuthnTestHandler()

			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.Header.Set("X-Axonflow-Proxy-Auth", validAuthnToken())
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 — a legitimate proxied call was broken", rr.Code)
			}
			if !*reached {
				t.Error("valid token did NOT reach the handler")
			}
		})
	}
}

// TestRequireInternalProxyAuth_BadTokensRejected covers every way a token can
// fail: forged signature, wrong secret, expired, future-dated, malformed, the
// legacy plain-secret spelling, and the static fallback constant. None may pass.
// tamperLastChar flips the final signature character to a DIFFERENT one.
// Substituting a fixed literal is not safe: the signature is lowercase hex, so
// a fixed replacement is already the real character 1 time in 16, which makes
// the "tampered" token byte-identical to the valid one and the subtest fails
// only on those runs. Measured at 6.29% over 200k timestamps.
func tamperLastChar(tok string) string {
	last := tok[len(tok)-1]
	repl := byte('0')
	if last == repl {
		repl = '1'
	}
	return tok[:len(tok)-1] + string(repl)
}

func TestRequireInternalProxyAuth_BadTokensRejected(t *testing.T) {
	withAuthnValidator(t)

	valid := validAuthnToken()

	// Expired: generated outside the replay window.
	staleClock := stubClock{now: time.Now().Add(-30 * time.Minute)}
	expired := serviceauth.NewTokenGenerator(authnTestSecret, staleClock).GenerateToken()

	// Future-dated beyond the skew.
	aheadClock := stubClock{now: time.Now().Add(30 * time.Minute)}
	future := serviceauth.NewTokenGenerator(authnTestSecret, aheadClock).GenerateToken()

	// Correctly formed, signed with a DIFFERENT secret.
	wrongSecret := serviceauth.NewTokenGenerator("a-completely-different-secret-value-32ch", nil).GenerateToken()

	cases := []struct {
		name  string
		token string
	}{
		{"tampered_signature", tamperLastChar(valid)},
		{"tampered_timestamp", "AXON-INTERNAL-1700000001-" + valid[len(valid)-16:]},
		{"expired", expired},
		{"future_dated", future},
		{"wrong_secret", wrongSecret},
		{"malformed_no_separator", "AXON-INTERNAL-garbage"},
		{"malformed_empty_prefix_only", serviceauth.TokenPrefix},
		{"short_signature", "AXON-INTERNAL-1700000000-abc"},
		{"arbitrary_string", "let-me-in"},
		// The legacy plain-secret and the hard-coded fallback constant must NOT
		// authenticate: otherwise anyone reading the source could get in.
		{"legacy_plain_secret", authnTestSecret},
		{"static_fallback_constant", serviceauth.TokenFallback},
		{"whitespace", "   "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, reached := newAuthnTestHandler()

			req := httptest.NewRequest("GET", "/api/v1/policies/dynamic", nil)
			req.Header.Set("X-Axonflow-Proxy-Auth", tc.token)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("token %q: status = %d, want 403", tc.name, rr.Code)
			}
			if *reached {
				t.Errorf("token %q REACHED the handler", tc.name)
			}
		})
	}
}

// TestRequireInternalProxyAuth_ExemptPathsServed pins the exemption set. If
// this list grows, it grows here first and a reviewer sees it.
func TestRequireInternalProxyAuth_ExemptPathsServed(t *testing.T) {
	withAuthnValidator(t)

	for _, p := range []string{"/health", "/metrics", "/prometheus"} {
		t.Run(p, func(t *testing.T) {
			h, reached := newAuthnTestHandler()

			req := httptest.NewRequest("GET", p, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("exempt path %s: status = %d, want 200 (ALB/Prometheus probes hold no secret)", p, rr.Code)
			}
			if !*reached {
				t.Errorf("exempt path %s did not reach the handler", p)
			}
		})
	}
}

// TestRequireInternalProxyAuth_ExemptionCannotBeWidened is the one that matters
// for "an exemption broader than stated". The set is matched by exact string
// equality, so no prefix extension, traversal spelling or trailing-slash
// variant may inherit an exemption and reach a tenant route.
func TestRequireInternalProxyAuth_ExemptionCannotBeWidened(t *testing.T) {
	withAuthnValidator(t)

	notExempt := []string{
		"/health/../api/v1/policies/dynamic",
		"/metrics/../api/v1/policies/dynamic",
		"/prometheus/../api/v1/decisions",
		"/health/",
		"/healthz",
		"/health/detail",
		"/metrics/tenant/acme",
		"/prometheus/api/v1/query",
		"/api/v1/metrics", // NOT the exempt /metrics
		"/api/v1/health",  //
		"//health",        // double slash
		"/HEALTH",         // case must not match
	}

	for _, p := range notExempt {
		t.Run(p, func(t *testing.T) {
			h, reached := newAuthnTestHandler()

			req := httptest.NewRequest("GET", p, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("path %q: status = %d, want 403 — it must NOT inherit an exemption", p, rr.Code)
			}
			if *reached {
				t.Errorf("path %q REACHED the handler without a token", p)
			}
		})
	}
}

// TestRequireInternalProxyAuth_ExemptPathQueryStringIsStillExempt records the
// boundary precisely rather than leaving it to inference: the gate matches on
// r.URL.Path, so a query string neither widens nor narrows an exemption.
// "/health?x=1/../y" has path "/health" and is served — the traversal lives in
// the query, which nothing routes on. The exemption is still exactly three
// paths; only the PATH decides.
func TestRequireInternalProxyAuth_ExemptPathQueryStringIsStillExempt(t *testing.T) {
	withAuthnValidator(t)

	h, reached := newAuthnTestHandler()
	req := httptest.NewRequest("GET", "/health?x=1/../y", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !*reached {
		t.Errorf("/health with a query string: status = %d (reached=%v), want 200", rr.Code, *reached)
	}
}

// TestRequireInternalProxyAuth_NoValidatorFailsClosed: an unset
// AXONFLOW_INTERNAL_SERVICE_SECRET means no token CAN be verified. That is a
// misconfiguration, not a supported posture, and must deny rather than admit.
//
// The sub-cases sweep DEPLOYMENT_MODE deliberately: there is NO mode carve-out,
// so community must fail closed exactly like production. A mode-keyed carve-out
// is the defect this same PR fixes in the portal's admin gate.
func TestRequireInternalProxyAuth_NoValidatorFailsClosed(t *testing.T) {
	orig := proxyTokenValidator
	proxyTokenValidator = nil
	t.Cleanup(func() { proxyTokenValidator = orig })

	for _, mode := range []string{"", "community", "community-saas", "enterprise", "saas", "in-vpc-enterprise", "invpc"} {
		t.Run("mode="+mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)

			h, reached := newAuthnTestHandler()

			req := httptest.NewRequest("GET", "/api/v1/policies/dynamic", nil)
			// Even presenting the static fallback constant must not help.
			req.Header.Set("X-Axonflow-Proxy-Auth", serviceauth.TokenFallback)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("mode=%q: status = %d, want 403 with no validator configured", mode, rr.Code)
			}
			if *reached {
				t.Errorf("mode=%q: request REACHED the handler with no validator configured", mode)
			}
		})
	}
}

// TestRequireInternalProxyAuth_NoValidatorStillServesHealth: the fail-closed
// posture must not brick the ALB/ECS health check, or a misconfigured task
// would be killed and restarted forever with no diagnosable signal.
func TestRequireInternalProxyAuth_NoValidatorStillServesHealth(t *testing.T) {
	orig := proxyTokenValidator
	proxyTokenValidator = nil
	t.Cleanup(func() { proxyTokenValidator = orig })

	h, reached := newAuthnTestHandler()
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK || !*reached {
		t.Errorf("/health status = %d (reached=%v), want 200 even with no validator", rr.Code, *reached)
	}
}

// TestRequireInternalProxyAuth_UnmatchedRoutesGated proves the gate is a real
// choke point rather than a per-route decoration: it runs BEFORE routing, so a
// path with no registered route is refused instead of 404-ing. An
// unauthenticated caller therefore cannot map which routes exist, and a route
// added tomorrow is protected without anyone remembering to gate it.
func TestRequireInternalProxyAuth_UnmatchedRoutesGated(t *testing.T) {
	withAuthnValidator(t)

	// A mux with NO catch-all: every path below is unrouted.
	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := requireInternalProxyAuth(r)

	for _, p := range []string{"/api/v1/route-that-does-not-exist-yet", "/debug/pprof/heap", "/"} {
		req := httptest.NewRequest("GET", p, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("unrouted path %q: status = %d, want 403 (gate must precede routing)", p, rr.Code)
		}
	}
}

// TestRequireInternalProxyAuth_MethodsAllGated: the gate is method-agnostic.
// A write must not slip through because only GET was considered.
func TestRequireInternalProxyAuth_MethodsAllGated(t *testing.T) {
	withAuthnValidator(t)

	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		t.Run(m, func(t *testing.T) {
			h, reached := newAuthnTestHandler()
			req := httptest.NewRequest(m, "/api/v1/policies", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("%s: status = %d, want 403", m, rr.Code)
			}
			if *reached {
				t.Errorf("%s REACHED the handler without a token", m)
			}
		})
	}
}

// stubClock drives token generation at a chosen instant so expiry and
// future-dating can be exercised without sleeping.
type stubClock struct{ now time.Time }

func (c stubClock) Now() time.Time { return c.now }

// TestBuildOrchestratorHandler_GateIsActuallyInstalled is the regression test
// for the fix ITSELF, not for the middleware in isolation.
//
// Every other test in this file exercises requireInternalProxyAuth directly, so
// all of them keep passing if someone deletes the gate from the served handler.
// That is exactly the revert that would silently re-open #3068. This test builds
// the handler the way Run() does — via buildOrchestratorHandler, the single
// function Run() calls — and asserts a token-less request to a tenant route is
// refused.
func TestBuildOrchestratorHandler_GateIsActuallyInstalled(t *testing.T) {
	withAuthnValidator(t)

	reached := false
	r := mux.NewRouter()
	r.HandleFunc("/api/v1/policies/dynamic", func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")

	// Same CORS options Run() constructs.
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})
	handler := buildOrchestratorHandler(c, r)

	req := httptest.NewRequest("GET", "/api/v1/policies/dynamic", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("served handler answered a token-less tenant request with %d, want 403 — "+
			"the authentication gate is NOT installed in the handler Run() serves", rr.Code)
	}
	if reached {
		t.Fatal("token-less request reached the route handler through the SERVED handler")
	}

	// Control: the same served handler must still serve an authenticated call,
	// so this test fails on a broken-everything regression too.
	reached = false
	req = httptest.NewRequest("GET", "/api/v1/policies/dynamic", nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", validAuthnToken())
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !reached {
		t.Fatalf("served handler rejected an AUTHENTICATED request: status=%d reached=%v", rr.Code, reached)
	}
}

// TestBuildOrchestratorHandler_CORSPreflightNotRefused pins the ordering claim:
// the gate sits INSIDE the CORS handler, so a browser preflight — which never
// carries a proxy-auth token — is answered by rs/cors rather than 403'd. If the
// two wrappers were swapped, preflight would break.
func TestBuildOrchestratorHandler_CORSPreflightNotRefused(t *testing.T) {
	withAuthnValidator(t)

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/policies/dynamic", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})
	handler := buildOrchestratorHandler(c, r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/policies/dynamic", nil)
	req.Header.Set("Origin", "https://portal.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Error("CORS preflight was refused by the auth gate — the gate must sit INSIDE the CORS handler")
	}
}
