// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"axonflow/platform/shared/policypath"
	"axonflow/platform/shared/serviceauth"
)

// LIST_POLICIES READS BOTH LISTS WITH THEIR CREDENTIALS (#4265).
//
// On an Enterprise deployment the MCP list_policies tool answered 401 on both
// legs: its loopback read of the agent's static list carried no credential, and
// its dynamic read went through the agent's orchestrator proxy, which admits
// only a licensed Basic caller. The backends here are the ones an Enterprise
// deployment runs: the agent's static list behind the REAL apiAuthMiddleware
// (Authenticate with internalServiceHints' pair), and an orchestrator that
// admits only an X-Axonflow-Proxy-Auth the serviceauth validator accepts, as
// requireInternalProxyAuth does. Both are routed by the policypath constants.

const lpSecret = "w3aa-4265-internal-service-secret-for-tests-only"

type lpBackends struct {
	mu                              sync.Mutex
	staticArrived, staticAdmitted   int
	staticScope                     []string
	dynamicArrived, dynamicAdmitted int
	dynamicScope                    []string
	static, orch                    *httptest.Server
}

func lpList(prefix string, n int) map[string]interface{} {
	ps := make([]interface{}, 0, n)
	for i := 0; i < n; i++ {
		ps = append(ps, map[string]interface{}{"id": fmt.Sprintf("%s-%d", prefix, i), "category": "pii", "severity": "high"})
	}
	return map[string]interface{}{"policies": ps, "pagination": map[string]interface{}{"total": n}}
}

// lpSetup installs both backends, the signing generator and the validator the
// agent's middleware reads, on an Enterprise deployment; all restored at
// cleanup.
func lpSetup(t *testing.T, nStatic, nDynamic int) *lpBackends {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	validator := serviceauth.NewTokenValidator(lpSecret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
	prevGen, prevVal, prevOrch := proxyTokenGenerator, internalTokenValidator, orchestratorURL
	proxyTokenGenerator = serviceauth.NewTokenGenerator(lpSecret, nil)
	internalTokenValidator = validator
	t.Cleanup(func() { proxyTokenGenerator, internalTokenValidator, orchestratorURL = prevGen, prevVal, prevOrch })

	b := &lpBackends{}
	guarded := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.staticAdmitted++
		b.staticScope = append(b.staticScope, r.Header.Get("X-Tenant-ID")+"|"+r.Header.Get("X-Org-ID")+"|"+r.URL.Query().Get("limit"))
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(lpList("static", nStatic))
	}))
	staticMux := http.NewServeMux()
	staticMux.Handle(policypath.LegacySystemPolicies, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.staticArrived++
		b.mu.Unlock()
		guarded.ServeHTTP(w, r)
	}))
	b.static = httptest.NewServer(staticMux)
	t.Cleanup(b.static.Close)
	u, _ := url.Parse(b.static.URL)
	t.Setenv("PORT", u.Port())

	orchMux := http.NewServeMux()
	orchMux.HandleFunc(policypath.LegacyTenantPolicies, func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.dynamicArrived++
		b.mu.Unlock()
		if valid, _, err := validator.ValidateToken(r.Header.Get("X-Axonflow-Proxy-Auth")); !valid || err != nil {
			http.Error(w, `{"error":"invalid internal proxy credential"}`, http.StatusUnauthorized)
			return
		}
		b.mu.Lock()
		b.dynamicAdmitted++
		b.dynamicScope = append(b.dynamicScope, r.Header.Get("X-Tenant-ID")+"|"+r.Header.Get("X-Org-ID")+"|"+r.URL.Query().Get("limit"))
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(lpList("dynamic", nDynamic))
	})
	b.orch = httptest.NewServer(orchMux)
	t.Cleanup(b.orch.Close)
	orchestratorURL = b.orch.URL
	return b
}

// lpWithTokenGenerator installs a signing generator for a test that must reach
// the transport rather than the #4265 guards, and restores what was there.
func lpWithTokenGenerator(t *testing.T) func() {
	t.Helper()
	prev := proxyTokenGenerator
	proxyTokenGenerator = serviceauth.NewTokenGenerator(lpSecret, nil)
	return func() { proxyTokenGenerator = prev }
}

func lpSession() *mcpSession {
	return &mcpSession{tenantID: "tenant-4265", orgID: "org-4265", clientID: "client-4265", authKind: AuthKindEnterprise}
}

// lpCount reads the tool's count and its per-source split.
func lpCount(t *testing.T, resp interface{}) (int, map[string]int) {
	t.Helper()
	m, ok := resp.(map[string]interface{})
	if !ok {
		t.Fatalf("list_policies answered %T, not an object: %v", resp, resp)
	}
	n, _ := m["count"].(int)
	by := map[string]int{}
	ps, _ := m["policies"].([]interface{})
	for _, p := range ps {
		if pm, ok := p.(map[string]interface{}); ok {
			s, _ := pm["source"].(string)
			by[s]++
		}
	}
	return n, by
}

func TestListPoliciesReadsBothListsWithTheirCredentials(t *testing.T) {
	const want = "tenant-4265|org-4265|200"

	t.Run("Enterprise: both lists admitted once each, scoped to the session, the count both lists", func(t *testing.T) {
		b := lpSetup(t, 3, 2)
		for attempt := 1; attempt <= 2; attempt++ { // replayed, the answer is the same
			resp, err := mcpToolListPolicies(lpSession(), map[string]interface{}{})
			if err != nil {
				t.Fatalf("attempt %d: list_policies failed: %v", attempt, err)
			}
			if n, by := lpCount(t, resp); n != 5 || by["static"] != 3 || by["dynamic"] != 2 {
				t.Fatalf("attempt %d: count %d by source %v; want 5 = static 3 + dynamic 2", attempt, n, by)
			}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.staticArrived != 2 || b.staticAdmitted != 2 || b.dynamicArrived != 2 || b.dynamicAdmitted != 2 {
			t.Fatalf("static arrived %d admitted %d, dynamic arrived %d admitted %d; want every read admitted", b.staticArrived, b.staticAdmitted, b.dynamicArrived, b.dynamicAdmitted)
		}
		for _, s := range append(append([]string{}, b.staticScope...), b.dynamicScope...) {
			if s != want {
				t.Fatalf("a read was scoped %q; want the session's %q with limit=200", s, want)
			}
		}
	})

	// The backends must refuse what an Enterprise deployment refuses, or the
	// case above proves nothing about the credential.
	t.Run("CONTROL: each backend refuses a read without its credential, with another secret's, or with the public fallback", func(t *testing.T) {
		b := lpSetup(t, 3, 2)
		foreign := serviceauth.NewTokenGenerator("another-secret-the-deployment-does-not-hold", nil).GenerateToken()
		for name, token := range map[string]string{"no credential": "", "another secret's token": foreign, "the public fallback token": serviceauth.TokenFallback} {
			req, _ := http.NewRequest("GET", b.static.URL+policypath.LegacySystemPolicies+"?limit=200", nil)
			req.Header.Set("X-Tenant-ID", "tenant-4265")
			req.Header.Set("X-Org-ID", "org-4265")
			if token != "" {
				req.Header.Set(internalServiceIDHeader, serviceauth.ClientID)
				req.Header.Set(internalServiceTokenHeader, token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("static, %s: HTTP %d; want 401", name, resp.StatusCode)
			}
			oreq, _ := http.NewRequest("GET", b.orch.URL+policypath.LegacyTenantPolicies, nil)
			if token != "" {
				oreq.Header.Set("X-Axonflow-Proxy-Auth", token)
			}
			oresp, err := http.DefaultClient.Do(oreq)
			if err != nil {
				t.Fatal(err)
			}
			_ = oresp.Body.Close()
			if oresp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("orchestrator, %s: HTTP %d; want 401", name, oresp.StatusCode)
			}
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.staticAdmitted != 0 || b.dynamicAdmitted != 0 {
			t.Fatalf("a refused read was admitted: static %d, dynamic %d", b.staticAdmitted, b.dynamicAdmitted)
		}
	})

	t.Run("no internal-service secret: the static read is refused by name and never sent", func(t *testing.T) {
		b := lpSetup(t, 3, 2)
		proxyTokenGenerator = nil
		_, err := mcpToolListPolicies(lpSession(), map[string]interface{}{})
		if err == nil || !strings.Contains(err.Error(), serviceauth.SecretEnvVar) {
			t.Fatalf("list_policies answered %v; want an error naming %s", err, serviceauth.SecretEnvVar)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.staticArrived != 0 {
			t.Fatalf("the static list received %d unsigned read(s)", b.staticArrived)
		}
	})

	for _, c := range []struct {
		name        string
		tenant, org string
	}{{"a session with no organization", "tenant-4265", ""}, {"a session with no tenant", "", "org-4265"}} {
		t.Run(c.name+": the static read is refused, never scoped to a default", func(t *testing.T) {
			b := lpSetup(t, 3, 2)
			s := lpSession()
			s.tenantID, s.orgID = c.tenant, c.org
			resp, err := mcpToolListPolicies(s, map[string]interface{}{})
			if err != nil {
				t.Fatalf("list_policies failed outright: %v; want the dynamic list alone", err)
			}
			if n, by := lpCount(t, resp); n != 2 || by["static"] != 0 {
				t.Fatalf("count %d by source %v; want the dynamic list alone", n, by)
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.staticArrived != 0 {
				t.Fatalf("the static list received %d read(s) for an unscoped session", b.staticArrived)
			}
		})
	}

	t.Run("dependency states: each backend down answers the other list; both down is an error", func(t *testing.T) {
		b := lpSetup(t, 3, 2)
		b.orch.Close()
		if resp, err := mcpToolListPolicies(lpSession(), map[string]interface{}{}); err != nil {
			t.Fatalf("orchestrator down: %v; want the static list", err)
		} else if n, by := lpCount(t, resp); n != 3 || by["static"] != 3 {
			t.Fatalf("orchestrator down: count %d by %v; want static 3", n, by)
		}
		b2 := lpSetup(t, 3, 2)
		b2.static.Close()
		if resp, err := mcpToolListPolicies(lpSession(), map[string]interface{}{}); err != nil {
			t.Fatalf("static list down: %v; want the dynamic list", err)
		} else if n, by := lpCount(t, resp); n != 2 || by["dynamic"] != 2 {
			t.Fatalf("static list down: count %d by %v; want dynamic 2", n, by)
		}
		b2.orch.Close()
		if _, err := mcpToolListPolicies(lpSession(), map[string]interface{}{}); err == nil {
			t.Fatal("both backends down: want an error")
		}
	})

	// The loopback guard refuses a session with no scope. A COMMUNITY session
	// must never be one: its org comes from getDeploymentOrgID, which answers
	// "local-dev-org" when ORG_ID is unset, and its tenant from the client id,
	// "community" when no header is sent. This drives the REAL Authenticate
	// with both unset, so a future change that let either go empty would fail
	// here rather than turning Community's count into a partial answer.
	t.Run("Community with ORG_ID and X-Client-ID unset: the guard cannot fire, and the count is answered", func(t *testing.T) {
		b := lpSetup(t, 3, 2)
		t.Setenv("DEPLOYMENT_MODE", "community")
		t.Setenv("ORG_ID", "")
		req := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
		auth, authErr := Authenticate(req, &AuthHints{})
		if authErr != nil {
			t.Fatalf("a community caller presenting nothing was not authenticated: %v", authErr.Message)
		}
		s := &mcpSession{tenantID: auth.TenantID, orgID: auth.OrgID, clientID: auth.ClientID, authKind: auth.Kind}
		if s.orgID == "" || s.tenantID == "" {
			t.Fatalf("a community session carries tenant %q org %q; the loopback read would be refused as unscoped", s.tenantID, s.orgID)
		}
		resp, err := mcpToolListPolicies(s, map[string]interface{}{})
		if err != nil {
			t.Fatalf("community list_policies failed: %v", err)
		}
		if n, by := lpCount(t, resp); n != 5 || by["static"] != 3 {
			t.Fatalf("community count %d by source %v; want 5 with the static list read", n, by)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.staticAdmitted == 0 {
			t.Fatal("the static list was never admitted on a community session")
		}
	})

	// The case that would have caught the regression R3 round 1 found: on
	// Community with NO internal-service secret, the platform admits the public
	// fallback token, and a refusal here would turn a working count into a
	// partial answer on the documented community configuration.
	t.Run("Community with no internal-service secret: the static list still answers", func(t *testing.T) {
		b := lpSetup(t, 3, 2)
		t.Setenv("DEPLOYMENT_MODE", "community")
		proxyTokenGenerator = nil
		internalTokenValidator = nil
		resp, err := mcpToolListPolicies(lpSession(), map[string]interface{}{})
		if err != nil {
			t.Fatalf("community with no secret: %v; want the static list", err)
		}
		// The STATIC read is what this PR must not take away, and it is
		// admitted: the community arm accepts the public fallback token.
		//
		// The DYNAMIC read stays refused, and not by anything here: with no
		// secret the orchestrator has no validator, and requireInternalProxyAuth
		// denies EVERY request rather than waving them through
		// (platform/orchestrator/authn_middleware.go:131-142). So a deployment
		// with no shared secret has no orchestrator API at all, which is its
		// configuration and not this tool's. Do not "fix" this back to 5.
		if n, by := lpCount(t, resp); n != 3 || by["static"] != 3 || by["dynamic"] != 0 {
			t.Fatalf("count %d by source %v; want 3 from the static list alone", n, by)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.staticArrived == 0 || b.staticAdmitted == 0 {
			t.Fatalf("the static read was refused before it was sent (arrived %d, admitted %d): the unsigned guard fired on Community", b.staticArrived, b.staticAdmitted)
		}
	})

	// ...and its Enterprise twin, so the guard is not simply deleted: there the
	// fallback is not admitted, and an unsigned read must never be sent.
	t.Run("Enterprise with no internal-service secret: the static read is refused by name and never sent", func(t *testing.T) {
		b := lpSetup(t, 3, 2)
		proxyTokenGenerator = nil
		_, err := mcpProxyToLocal(lpSession(), "GET", b.static.URL+policypath.LegacySystemPolicies)
		if !errors.Is(err, errLoopbackUnsigned) {
			t.Fatalf("got %v; want the named unsigned refusal", err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.staticArrived != 0 {
			t.Fatalf("an unsigned read reached the route %d time(s)", b.staticArrived)
		}
	})

	// The refusal the unscoped guard emits is named, so a reader of the log or
	// the error can act on it; the tool-level effect (the static read never
	// sent) is what the unscoped cases above assert.
	t.Run("the unscoped refusal is errLoopbackUnscoped by name", func(t *testing.T) {
		lpSetup(t, 3, 2)
		s := lpSession()
		s.orgID = ""
		_, err := mcpProxyToLocal(s, "GET", "http://127.0.0.1:1"+policypath.LegacySystemPolicies)
		if !errors.Is(err, errLoopbackUnscoped) {
			t.Fatalf("got %v; want the named unscoped refusal", err)
		}
	})

	t.Run("Community answers the same count: the credential is harmless where any caller is admitted", func(t *testing.T) {
		lpSetup(t, 3, 2)
		t.Setenv("DEPLOYMENT_MODE", "community")
		resp, err := mcpToolListPolicies(lpSession(), map[string]interface{}{})
		if err != nil {
			t.Fatalf("community: %v", err)
		}
		if n, _ := lpCount(t, resp); n != 5 {
			t.Fatalf("community: count %d; want 5", n)
		}
	})
}
