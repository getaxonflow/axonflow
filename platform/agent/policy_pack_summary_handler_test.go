// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/shared/activationinputs"
	"axonflow/platform/shared/anchoredenforcer"
	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/serviceauth"
)

const packSummaryOrg = "org-pack-summary"

// withPackSummaryEnforcer installs a process enforcer over docs for the test,
// with packs installed.
func withPackSummaryEnforcer(t *testing.T, docs activeDocumentSource, install func(*anchoredEnforcer)) {
	t.Helper()
	snap := enfSnapshot(t)
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newAnchoredEnforcer(docs, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch, sharedidentity.NoGraphOnlyResolver{})
	if err != nil {
		t.Fatal(err)
	}
	if install != nil {
		install(e)
	}
	prev := anchoredEnforcerInstance.Load()
	anchoredEnforcerInstance.Store(e)
	t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })
}

// packSummaryRequest is a GET of the route as a caller of kind reaches the
// handler, naming org in X-Org-ID ("" for none).
func packSummaryRequest(kind AuthKind, withKind bool, org string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, activationinputs.AgentSummaryPath, nil)
	if org != "" {
		r.Header.Set("X-Org-ID", org)
	}
	if withKind {
		r = r.WithContext(context.WithValue(r.Context(), ContextKeyAuthKind, kind))
	}
	return r
}

func decodePackSummary(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rr.Body.String(), err)
	}
	return body
}

// THE AGENT'S SUMMARY ROUTE (#4249): only the internal-service credential is
// answered, the organization is the one it names, and the count is of the
// activation this agent enforces, packs counted even when none is installed.
func TestThePolicyPackSummaryRouteAnswersOnlyTheInternalServiceCredential(t *testing.T) {
	withPackSummaryEnforcer(t, &enfDocuments{nothingPublished: map[string]bool{packSummaryOrg: true}}, nil)

	for _, c := range []struct {
		name     string
		kind     AuthKind
		withKind bool
	}{
		{"no credential at all", 0, false},
		{"a tenant's enterprise credential", AuthKindEnterprise, true},
	} {
		t.Run(c.name+" is 401", func(t *testing.T) {
			rr := httptest.NewRecorder()
			policyPackSummaryHandler(rr, packSummaryRequest(c.kind, c.withKind, packSummaryOrg))
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401: %s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "this route answers the internal-service credential only") {
				t.Fatalf("the 401 does not say why: %s", rr.Body.String())
			}
		})
	}

	t.Run("no X-Org-ID is 400", func(t *testing.T) {
		rr := httptest.NewRecorder()
		policyPackSummaryHandler(rr, packSummaryRequest(AuthKindInternalService, true, ""))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status %d, want 400: %s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "X-Org-ID names the organization whose summary is read, and it is missing") {
			t.Fatalf("the 400 does not say why: %s", rr.Body.String())
		}
	})

	t.Run("no packs installed is a counted zero", func(t *testing.T) {
		rr := httptest.NewRecorder()
		policyPackSummaryHandler(rr, packSummaryRequest(AuthKindInternalService, true, packSummaryOrg))
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d, want 200: %s", rr.Code, rr.Body.String())
		}
		got := decodePackSummary(t, rr)
		if got["success"] != true || got["scope"] != "decide" || got["packs_counted"] != true || got["pack"] != float64(0) {
			t.Fatalf("summary %v; want success, scope decide, packs_counted true and pack 0", got)
		}
		if _, present := got["packs_uncounted_reason"]; present {
			t.Fatalf("summary %v carries packs_uncounted_reason", got)
		}
		shipped, org, total := got["shipped"].(float64), got["organization"].(float64), got["total"].(float64)
		if shipped == 0 || org != 0 || total != shipped+org {
			t.Fatalf("summary %v; want the implicit baseline: total = shipped, nothing the organization's", got)
		}
	})
}

// The path the agent registers is the path its readers call.
func TestThePolicyPackSummaryRouteIsWhereItsReadersCall(t *testing.T) {
	if policyPackSummaryPath != activationinputs.AgentSummaryPath {
		t.Fatalf("the agent registers %q, the orchestrator and the portal call %q", policyPackSummaryPath, activationinputs.AgentSummaryPath)
	}
}

// A process with no enforcer, or an organization whose document cannot be
// read, answers 503 naming why, never a count.
func TestThePolicyPackSummaryRouteFailsClosedNamingTheCause(t *testing.T) {
	t.Run("no enforcer", func(t *testing.T) {
		prev := anchoredEnforcerInstance.Load()
		anchoredEnforcerInstance.Store(nil)
		t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })
		rr := httptest.NewRecorder()
		policyPackSummaryHandler(rr, packSummaryRequest(AuthKindInternalService, true, packSummaryOrg))
		if rr.Code != http.StatusServiceUnavailable || decodePackSummary(t, rr)["reason"] != "decision_enforcement_unavailable" {
			t.Fatalf("status %d body %s; want 503 decision_enforcement_unavailable", rr.Code, rr.Body.String())
		}
	})
	t.Run("an unreadable active document", func(t *testing.T) {
		withPackSummaryEnforcer(t, &enfDocuments{broken: map[string]bool{packSummaryOrg: true}}, nil)
		rr := httptest.NewRecorder()
		policyPackSummaryHandler(rr, packSummaryRequest(AuthKindInternalService, true, packSummaryOrg))
		if rr.Code != http.StatusServiceUnavailable || decodePackSummary(t, rr)["reason"] != anchoredenforcer.CauseActiveDocument {
			t.Fatalf("status %d body %s; want 503 naming the active document", rr.Code, rr.Body.String())
		}
	})
}

// THE ROUTE AND THE TYPED-POLICIES PROXY DO NOT MEET. The agent forwards the
// whole /api/v1/typed-policies prefix to the orchestrator (proxy.go), so the
// summary route lives elsewhere: registered as run.go registers them, a tenant's
// GET of the typed-policies summary still reaches the proxy, and this route is
// matched only by its own path.
func TestThePolicyPackSummaryRouteNeitherShadowsNorIsShadowedByTheTypedPoliciesProxy(t *testing.T) {
	h, err := NewReverseProxyHandler(ProxyConfig{OrchestratorInternalURL: "http://orchestrator.invalid", PortalInternalURL: "http://portal.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	r := mux.NewRouter()
	RegisterPolicyPackSummaryHandler(r) // run.go registers it before the proxy routes
	h.RegisterProxyRoutes(r)

	template := func(path string) string {
		t.Helper()
		var m mux.RouteMatch
		if !r.Match(httptest.NewRequest(http.MethodGet, path, nil), &m) || m.Route == nil {
			t.Fatalf("nothing matches GET %s", path)
		}
		tpl, err := m.Route.GetPathTemplate()
		if err != nil {
			t.Fatal(err)
		}
		return tpl
	}
	if got := template("/api/v1/typed-policies/active/summary"); got != "/api/v1/typed-policies" {
		t.Errorf("GET /api/v1/typed-policies/active/summary matches %q, want the typed-policies proxy prefix", got)
	}
	if got := template(activationinputs.AgentSummaryPath); got != activationinputs.AgentSummaryPath {
		t.Errorf("GET %s matches %q, want the summary route itself", activationinputs.AgentSummaryPath, got)
	}
}

// THE ROUTE AS REGISTERED (#4249). The cells above call the handler with an
// auth kind already in the context; this one registers the route the way
// run.go does, behind the agent's own auth middleware and a real token
// validator, and sends each credential over the wire. Without the middleware
// every caller would reach the handler with no auth kind and be refused, so
// only this cell can tell a registration that authenticates from one that
// refuses everyone.
func TestThePolicyPackSummaryRouteAuthenticatesThroughTheAgentMiddleware(t *testing.T) {
	const secret = "s6-f3b-internal-service-secret-for-tests-only"
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	prevVal := internalTokenValidator
	internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
	t.Cleanup(func() { internalTokenValidator = prevVal })
	withPackSummaryEnforcer(t, &enfDocuments{nothingPublished: map[string]bool{packSummaryOrg: true}}, nil)

	router := mux.NewRouter()
	RegisterPolicyPackSummaryHandler(router)
	signed := serviceauth.NewTokenGenerator(secret, nil).GenerateToken()
	foreign := serviceauth.NewTokenGenerator("a-secret-this-deployment-does-not-hold", nil).GenerateToken()

	send := func(t *testing.T, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, activationinputs.AgentSummaryPath, nil)
		r.Header.Set("X-Org-ID", packSummaryOrg)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, r)
		return rr
	}

	t.Run("the signed internal-service pair is answered with the count", func(t *testing.T) {
		rr := send(t, map[string]string{serviceauth.ServiceIDHeader: serviceauth.ClientID, serviceauth.ServiceTokenHeader: signed})
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d, want 200: %s", rr.Code, rr.Body.String())
		}
		if body := decodePackSummary(t, rr); body["packs_counted"] != true {
			t.Fatalf("the signed pair was answered without a counted pack: %v", body)
		}
	})

	for _, c := range []struct {
		name    string
		headers map[string]string
	}{
		{"no credential", nil},
		{"the service id alone", map[string]string{serviceauth.ServiceIDHeader: serviceauth.ClientID}},
		{"the token alone", map[string]string{serviceauth.ServiceTokenHeader: signed}},
		{"a token signed with another secret", map[string]string{serviceauth.ServiceIDHeader: serviceauth.ClientID, serviceauth.ServiceTokenHeader: foreign}},
		{"the fallback token on an Enterprise deployment", map[string]string{serviceauth.ServiceIDHeader: serviceauth.ClientID, serviceauth.ServiceTokenHeader: serviceauth.TokenFallback}},
		{"a tenant's Basic credential", map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("tenant-client:tenant-secret"))}},
	} {
		t.Run(c.name+" is refused", func(t *testing.T) {
			rr := send(t, c.headers)
			if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 401 or 403: %s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "packs_counted") {
				t.Fatalf("a refused caller was answered the summary: %s", rr.Body.String())
			}
		})
	}
}
