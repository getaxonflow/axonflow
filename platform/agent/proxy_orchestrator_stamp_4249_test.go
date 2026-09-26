// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
)

// #4249 row 5706434342: the orchestrator reads X-Org-ID as the caller's
// organization on the MAP plan routes, plan resume and the unified execution
// routes, and trusts it because every hop holding the internal-service secret
// Sets it from authenticated state. For the agent's reverse proxy that holds
// ONLY because each orchestrator-bound entry in RegisterProxyRoutes is wrapped
// by proxyAuthMiddleware: the proxy's Director keeps the client's headers and
// adds nothing but the proxy token (createReverseProxy). A route registered
// with a bare h.ProxyToOrchestrator would carry the client's X-Org-ID to the
// orchestrator under a valid token, and every other test in this package would
// stay green.
//
// The cell classifies nothing by hand. It walks the router RegisterProxyRoutes
// built, sends every registered route and method an authenticated request that
// also asserts a hostile X-Org-ID, and fails if the orchestrator backend ever
// receives that value. A route added tomorrow is covered without editing this
// file. The planted positive is a bare route added inside RegisterProxyRoutes,
// which this cell reds by name.
func TestEveryOrchestratorBoundProxyRouteStampsTheAuthenticatedOrg(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	const hostileOrg = "attacker-org-4249"

	var mu sync.Mutex
	// Per request that reached the orchestrator: the X-Org-ID it carried.
	orchSeen := map[string]string{} // "METHOD template" -> X-Org-ID
	orch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		orchSeen[r.Header.Get("X-S8-Route")] = r.Header.Get("X-Org-ID")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer orch.Close()
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer portal.Close()

	handler, err := NewReverseProxyHandler(ProxyConfig{
		OrchestratorInternalURL: orch.URL,
		PortalInternalURL:       portal.URL,
	})
	if err != nil {
		t.Fatalf("NewReverseProxyHandler: %v", err)
	}
	r := mux.NewRouter()
	handler.RegisterProxyRoutes(r)

	pathVar := regexp.MustCompile(`\{[^}]*\}`)
	sent := 0
	walkErr := r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return nil // a route with no path matcher routes nothing here
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			methods = []string{http.MethodGet}
		}
		path := pathVar.ReplaceAllString(tmpl, "1")
		for _, m := range methods {
			if m == http.MethodOptions {
				continue // terminated by proxyAuthMiddleware, never forwarded
			}
			key := m + " " + tmpl
			req := httptest.NewRequest(m, path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.SetBasicAuth("real-proxy-client", "secret")
			req.Header.Set("X-Org-ID", hostileOrg)
			req.Header.Set("X-S8-Route", key)
			r.ServeHTTP(httptest.NewRecorder(), req)
			sent++
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk: %v", walkErr)
	}

	mu.Lock()
	defer mu.Unlock()

	var leaked []string
	for key, org := range orchSeen {
		if org == hostileOrg {
			leaked = append(leaked, key)
		}
	}
	slices.Sort(leaked)
	if len(leaked) > 0 {
		t.Errorf("the orchestrator received the CLIENT's X-Org-ID on %d route(s): each is registered in "+
			"RegisterProxyRoutes without proxyAuthMiddleware, so the caller selects the organization "+
			"the orchestrator authorizes against:\n  %s", len(leaked), strings.Join(leaked, "\n  "))
	}

	// The cell above cannot fail if nothing reaches the orchestrator (a broken
	// harness, a router that matched nothing). Each route the row names must
	// have been forwarded, with an org that is not the client's.
	for _, want := range []string{
		"POST /api/v1/process",
		"POST /api/v1/plan",
		"GET /api/v1/plans",
		"GET /api/v1/unified/executions",
		"POST /api/v1/workflows",
	} {
		org, reached := orchSeen[want]
		if !reached {
			t.Errorf("%s never reached the orchestrator backend: the harness is not exercising the proxy "+
				"(sent %d requests, %d reached the orchestrator)", want, sent, len(orchSeen))
			continue
		}
		if org == hostileOrg {
			continue // already reported above
		}
		t.Logf("%s reached the orchestrator with the authenticated X-Org-ID %q", want, org)
	}
}
