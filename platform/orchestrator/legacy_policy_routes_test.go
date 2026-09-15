// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/policypath"
)

// legacyRouteProbe is one (method, path template) the registrar registered.
type legacyRouteProbe struct {
	method, template string
	route            *mux.Route
}

// fullLegacyRouter builds the router the way run.go does, with every optional
// family present - the tenant family and simulation - so a walk sees all of
// them.
func fullLegacyRouter() *mux.Router {
	r := mux.NewRouter()
	registerLegacyPolicyRoutes(r,
		NewDynamicPolicyAPIHandler(aliasListService()),
		NewPolicySimulationHandler(nil, nil, nil, &mockLicenseCheckerForSim{}))
	return r
}

// walkLegacyRoutes returns every (method, template) the router carries, from
// the router rather than from the registrar's source.
func walkLegacyRoutes(t *testing.T, r *mux.Router) []legacyRouteProbe {
	t.Helper()
	var out []legacyRouteProbe
	err := r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if route.GetHandler() == nil {
			return nil // a subrouter mount: a matcher, not a route
		}
		tpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			t.Errorf("%s registers no method set; every legacy route is method-scoped", tpl)
			return nil
		}
		for _, m := range methods {
			out = append(out, legacyRouteProbe{method: m, template: tpl, route: route})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].template != out[j].template {
			return out[i].template < out[j].template
		}
		return out[i].method < out[j].method
	})
	return out
}

// TestEveryLegacyPolicyRouteCarriesTheDeprecationSignal walks the router
// registerLegacyPolicyRoutes builds and drives one request per registered
// (method, path), asserting each response carries the v11 deprecation signal
// whatever the handler answered. The probes carry no tenant, so each handler
// refuses before it reaches a dependency this test does not wire: a 401 for
// want of a tenant, a 503 for want of a database, a 403 for want of a licence.
// The signal riding every one of those is the property.
//
// The population is the router's: a route added to the registrar is probed the
// day it is added, and a route registered on the root router instead of the
// stamped subrouter is in the walk and answers unstamped. A legacy route
// registered anywhere else in this binary is the other census's
// (TestNoLegacyPolicyRouteIsRegisteredOutsideAStampedRegistrar, in
// platform/shared/policypath).
func TestEveryLegacyPolicyRouteCarriesTheDeprecationSignal(t *testing.T) {
	r := fullLegacyRouter()
	probes := walkLegacyRoutes(t, r)

	// The Phase A census counted 19 method-and-path pairs under
	// /api/v1/policies* and /api/v1/templates* (issuecomment-5642488843), and
	// the tenant family is 10 per spelling. OPTIONS is probed too but not
	// counted: it is the CORS preflight of a route, not a route.
	counts := map[string]int{}
	for _, p := range probes {
		if p.method == http.MethodOptions {
			continue
		}
		switch {
		case strings.HasPrefix(p.template, policypath.Policies), strings.HasPrefix(p.template, policypath.Templates):
			counts["policies+templates"]++
		default:
			counts["tenant"]++
		}
	}
	if counts["policies+templates"] != 19 || counts["tenant"] != 20 {
		t.Fatalf("the registrar serves %d /policies+/templates pairs and %d tenant pairs; want 19 and 20. "+
			"A route was added or lost: update the count only after checking it belongs in the deprecated surface",
			counts["policies+templates"], counts["tenant"])
	}

	registered := map[*mux.Route]bool{}
	for _, p := range probes {
		registered[p.route] = true
	}
	// A probe answered by an EARLIER route of the same registrar is shadowed,
	// not lost: gorilla/mux matches in order, and "/api/v1/policies/{id}"
	// accepts OPTIONS, so a preflight for the three simulation routes is
	// answered by the CRUD route with id=simulate. That order predates v11 and
	// is kept; the shadows are pinned so a new one is noticed.
	wantShadowed := map[string]bool{
		"OPTIONS /api/v1/policies/simulate":      true,
		"OPTIONS /api/v1/policies/impact-report": true,
		"OPTIONS /api/v1/policies/conflicts":     true,
	}
	shadowed := map[string]bool{}

	for _, p := range probes {
		t.Run(p.method+" "+p.template, func(t *testing.T) {
			path := strings.NewReplacer("{id}", "probe-id").Replace(p.template)
			var body *strings.Reader
			if p.method == http.MethodPost || p.method == http.MethodPut {
				body = strings.NewReader(`{}`)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(p.method, path, body)

			// The probe must reach a route of this registrar, or the header
			// assertion below is about some other router's response.
			var m mux.RouteMatch
			if !r.Match(req, &m) || !registered[m.Route] {
				t.Fatalf("%s %s is not answered by a route of the legacy registrar; the probe is vacuous", p.method, path)
			}
			if m.Route != p.route {
				shadowed[p.method+" "+p.template] = true
			}

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if !policypath.IsDeprecated(path) {
				t.Fatalf("%s is registered by the legacy registrar but is not in policypath.DeprecatedFamilies, "+
					"so it answers unstamped; name its family there", p.template)
			}
			assertDeprecationSignal(t, p.method+" "+path, rr.Header())
		})
	}
	for k := range shadowed {
		if !wantShadowed[k] {
			t.Errorf("%s is now answered by an earlier route of the registrar; a route order changed", k)
		}
	}
	for k := range wantShadowed {
		if !shadowed[k] {
			t.Errorf("%s is no longer shadowed; drop it from wantShadowed", k)
		}
	}
}

// TestTheLegacyRegistrarDoesNotSwallowOtherRoutes pins what the matcher-less
// subrouter must not do: a request that matches none of its routes falls
// through to the root router, unstamped, and a route the root router registers
// after it is still reachable.
func TestTheLegacyRegistrarDoesNotSwallowOtherRoutes(t *testing.T) {
	r := fullLegacyRouter()
	r.HandleFunc("/api/v1/typed-policies/active", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}).Methods("GET")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/typed-policies/active", nil))
	if rr.Code != http.StatusTeapot {
		t.Fatalf("a root route registered after the legacy registrar answered %d, want 418 - the subrouter swallowed it", rr.Code)
	}
	for _, k := range policypath.DeprecationHeaders() {
		if got := rr.Header().Get(k); got != "" {
			t.Errorf("the typed route carries %s = %q", k, got)
		}
	}

	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/unrouted", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("an unrouted path answered %d, want 404", rr.Code)
	}
}

// assertDeprecationSignal asserts h carries the v11 deprecation signal once.
// The Link and release values are written out rather than read from
// policypath: an expectation computed by the code under test agrees with it
// whatever it does.
func assertDeprecationSignal(t *testing.T, what string, h http.Header) {
	t.Helper()
	if got, want := h.Get(policypath.HeaderLink), `</api/v1/typed-policies>; rel="successor-version"`; got != want {
		t.Errorf("%s: Link = %q, want %q", what, got, want)
	}
	if got := h.Get(policypath.HeaderRemovedIn); got != "v11.1" {
		t.Errorf("%s: %s = %q, want v11.1", what, policypath.HeaderRemovedIn, got)
	}
	// Dated only once release prep sets DeprecatedSince; policypath's own
	// tests pin the RFC 9745 format against a fixed date.
	want, dated := policypath.DeprecationValue(policypath.DeprecatedSince)
	if got, present := h[policypath.HeaderDeprecation]; present != dated || (dated && got[0] != want) {
		t.Errorf("%s: Deprecation = %v (present=%v), want present=%v value %q", what, got, present, dated, want)
	}
	for _, k := range policypath.DeprecationHeaders() {
		if n := len(h.Values(k)); n > 1 {
			t.Errorf("%s: %s appears %d times - stamped on more than one hop", what, k, n)
		}
	}
	if got := h.Get("Sunset"); got != "" {
		t.Errorf("%s: Sunset = %q - v11.1 has no agreed date", what, got)
	}
}
