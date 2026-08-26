// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"axonflow/platform/shared/policypath"
)

// #1431. /api/v1/tenant-policies is an ALIAS of /api/v1/dynamic-policies.
//
// The orchestrator half is where the alias is most likely to lose something,
// for two reasons the agent half does not have:
//
//   - these routes are registered on the ROOT router as two literal blocks
//     (the portal's AST census cannot see a path built from a constant, so a
//     shared table is not available here). Two blocks can drift;
//   - the orchestrator's authentication is a WRAPPER with a path-keyed
//     exemption map, not a per-route middleware. A path that lands in that map
//     by accident is a route serving tenant policy data to anyone.
//
// Both are asserted below over every route, not a sample.

// tenantAliasRouter builds the routes as run.go does, over a mock service.
func tenantAliasRouter(t *testing.T, svc PolicyServicer) *mux.Router {
	t.Helper()
	r := mux.NewRouter()
	NewDynamicPolicyAPIHandler(svc).RegisterRoutes(r)
	return r
}

// aliasListService returns a service whose list call yields exactly one policy,
// so a response body that carries none is recognisable as "the handler did not
// run" rather than "the tenant has no policies".
func aliasListService() PolicyServicer {
	return &mockDynamicPolicyService{
		// The returned NAME encodes the params the handler asked for. That is
		// what makes this probe able to tell two handlers apart.
		//
		// It is not decoration. handleEffective also calls ListPolicies - with
		// different params - so a mock that ignored params returned the same
		// body for both, and wiring the successor to handleEffective instead of
		// handleDynamicPolicies passed the parity test. That mutant survived
		// until this line existed: the test was comparing a response shape that
		// was identical for a reason unrelated to the alias.
		listFunc: func(_ context.Context, _ string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			return &PoliciesListResponse{
				Policies: []PolicyResource{{
					ID: uuid.NewSHA1(uuid.Nil, []byte("ws1431")).String(),
					Name: fmt.Sprintf("AliasProbe page_size=%d sort_by=%q sort_dir=%q enabled_filter=%v",
						params.PageSize, params.SortBy, params.SortDir, params.Enabled != nil),
					Category: "dynamic-cost",
					Type:     "cost",
					Enabled:  true,
				}},
				Pagination: PaginationMeta{Page: 1, PageSize: params.PageSize, TotalItems: 1, TotalPages: 1},
			}, nil
		},
		exportFunc: func(_ context.Context, _ string) (*ExportPoliciesResponse, error) {
			return &ExportPoliciesResponse{Policies: []PolicyResource{{
				ID: "export-probe", Name: "Alias Probe Policy",
				Category: "dynamic-cost", Type: "cost", Enabled: true,
			}}}, nil
		},
	}
}

// walkedTenantRoute is one registered route reduced to what parity cares about.
type walkedTenantRoute struct {
	suffix  string
	methods string
}

func walkTenantPrefix(t *testing.T, r *mux.Router, prefix string) []walkedTenantRoute {
	t.Helper()
	var out []walkedTenantRoute
	err := r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if route.GetHandler() == nil {
			return nil
		}
		tpl, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		if tpl != prefix && !strings.HasPrefix(tpl, prefix+"/") {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			methods = []string{"<any>"}
		}
		sort.Strings(methods)
		out = append(out, walkedTenantRoute{
			suffix:  strings.TrimPrefix(tpl, prefix),
			methods: strings.Join(methods, ","),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", prefix, err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].suffix != out[j].suffix {
			return out[i].suffix < out[j].suffix
		}
		return out[i].methods < out[j].methods
	})
	return out
}

// TestTenantPolicyAliasIsCompleteAndSymmetric is the guard the registration
// comment names: two literal blocks must carry the same routes on the same
// methods. This is the test that turns "I copied the block carefully" into
// something CI re-checks on every run.
func TestTenantPolicyAliasIsCompleteAndSymmetric(t *testing.T) {
	r := tenantAliasRouter(t, &mockDynamicPolicyService{})

	legacy := walkTenantPrefix(t, r, policypath.LegacyTenantPolicies)
	successor := walkTenantPrefix(t, r, policypath.TenantPolicies)

	// A floor, so two empty lists cannot pass as "symmetric". Seven
	// registrations is what RegisterRoutes writes per prefix today.
	const wantAtLeast = 7
	if len(legacy) < wantAtLeast {
		t.Fatalf("walked %d routes under %s, expected at least %d - the walk has gone blind and "+
			"every comparison below is vacuous", len(legacy), policypath.LegacyTenantPolicies, wantAtLeast)
	}
	if len(legacy) != len(successor) {
		t.Fatalf("route count differs: %s has %d, %s has %d\nlegacy: %+v\nsuccessor: %+v",
			policypath.LegacyTenantPolicies, len(legacy),
			policypath.TenantPolicies, len(successor), legacy, successor)
	}
	for i := range legacy {
		if legacy[i] != successor[i] {
			t.Errorf("route %d differs: legacy %+v, successor %+v", i, legacy[i], successor[i])
		}
	}
}

// tenantAliasProbe is one request driven against both prefixes.
type tenantAliasProbe struct {
	name        string
	method      string
	suffix      string
	wantCode    int
	mustContain string
}

func tenantAliasProbes() []tenantAliasProbe {
	return []tenantAliasProbe{
		{"list", "GET", "", http.StatusOK, "AliasProbe "},
		{"export", "GET", "/export", http.StatusOK, "policies"},
		{"effective", "GET", "/effective", http.StatusOK, "policies"},
	}
}

func serveTenantAlias(t *testing.T, p tenantAliasProbe, prefix string) *httptest.ResponseRecorder {
	t.Helper()
	r := tenantAliasRouter(t, aliasListService())
	req := httptest.NewRequest(p.method, prefix+p.suffix, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

// TestTenantPolicyAliasResponsesAreIdentical compares the whole response.
func TestTenantPolicyAliasResponsesAreIdentical(t *testing.T) {
	for _, p := range tenantAliasProbes() {
		t.Run(p.name, func(t *testing.T) {
			legacyRR := serveTenantAlias(t, p, policypath.LegacyTenantPolicies)
			successorRR := serveTenantAlias(t, p, policypath.TenantPolicies)

			// Positive control first: two 404s compare equal, and a parity
			// test that passes because neither path is routed is worse than
			// no test at all.
			if legacyRR.Code != p.wantCode {
				t.Fatalf("legacy %s%s: got %d want %d - the request never reached the handler, so "+
					"the comparisons below would be vacuous. body=%s",
					policypath.LegacyTenantPolicies, p.suffix, legacyRR.Code, p.wantCode, legacyRR.Body.String())
			}
			if !strings.Contains(legacyRR.Body.String(), p.mustContain) {
				t.Fatalf("legacy body lacks %q - the handler produced no real payload: %s",
					p.mustContain, legacyRR.Body.String())
			}

			if successorRR.Code != legacyRR.Code {
				t.Errorf("status differs: legacy %d, successor %d (body=%s)",
					legacyRR.Code, successorRR.Code, successorRR.Body.String())
			}
			if normalizeTenantVolatile(legacyRR.Body.String()) != normalizeTenantVolatile(successorRR.Body.String()) {
				t.Errorf("body differs:\n legacy:    %s\n successor: %s",
					legacyRR.Body.String(), successorRR.Body.String())
			}

			skip := map[string]bool{
				http.CanonicalHeaderKey(policypath.HeaderDeprecation): true,
				http.CanonicalHeaderKey(policypath.HeaderLink):        true,
			}
			keys := map[string]bool{}
			for k := range legacyRR.Header() {
				keys[k] = true
			}
			for k := range successorRR.Header() {
				keys[k] = true
			}
			for k := range keys {
				if skip[k] {
					continue
				}
				a, b := legacyRR.Header().Values(k), successorRR.Header().Values(k)
				if fmt.Sprint(a) != fmt.Sprint(b) {
					t.Errorf("header %q differs: legacy %v, successor %v", k, a, b)
				}
			}
		})
	}
}

func normalizeTenantVolatile(body string) string {
	return volatileTenantRE.ReplaceAllString(body, `"$1":"<normalized>"`)
}

// TestTenantPolicyDeprecationSignalIsOnLegacyOnly asserts the signal in both
// directions, on every route rather than one.
func TestTenantPolicyDeprecationSignalIsOnLegacyOnly(t *testing.T) {
	for _, p := range tenantAliasProbes() {
		t.Run(p.name, func(t *testing.T) {
			legacyRR := serveTenantAlias(t, p, policypath.LegacyTenantPolicies)
			successorRR := serveTenantAlias(t, p, policypath.TenantPolicies)

			if legacyRR.Code != p.wantCode {
				t.Fatalf("legacy request did not reach the handler (%d); header assertions vacuous", legacyRR.Code)
			}

			if got := legacyRR.Header().Get(policypath.HeaderDeprecation); got != policypath.DeprecationValue {
				t.Errorf("legacy %s%s: Deprecation = %q, want %q",
					policypath.LegacyTenantPolicies, p.suffix, got, policypath.DeprecationValue)
			}
			wantLink := policypath.LinkSuccessor(policypath.TenantPolicies + p.suffix)
			if got := legacyRR.Header().Get(policypath.HeaderLink); got != wantLink {
				t.Errorf("legacy %s%s: Link = %q, want %q",
					policypath.LegacyTenantPolicies, p.suffix, got, wantLink)
			}

			if got := successorRR.Header().Get(policypath.HeaderDeprecation); got != "" {
				t.Errorf("successor %s%s carries Deprecation = %q", policypath.TenantPolicies, p.suffix, got)
			}
			if got := successorRR.Header().Get(policypath.HeaderLink); got != "" {
				t.Errorf("successor %s%s carries Link = %q", policypath.TenantPolicies, p.suffix, got)
			}
			for _, rr := range []*httptest.ResponseRecorder{legacyRR, successorRR} {
				if got := rr.Header().Get("Sunset"); got != "" {
					t.Errorf("Sunset = %q - this change promises no removal date", got)
				}
			}
		})
	}
}

// TestTenantPolicyAliasIsAuthenticated drives requireInternalProxyAuth exactly
// as run.go wires it - the gate wrapping a real mux carrying the real routes.
//
// This is the assertion that would have caught the alias being added to the
// orchestrator's auth exemption map, which is the one way a route on this
// plane becomes anonymously readable.
func TestTenantPolicyAliasIsAuthenticated(t *testing.T) {
	withAuthnValidator(t)

	for _, prefix := range []string{policypath.LegacyTenantPolicies, policypath.TenantPolicies} {
		t.Run(prefix, func(t *testing.T) {
			build := func() http.Handler {
				return requireInternalProxyAuth(tenantAliasRouter(t, aliasListService()))
			}

			// NOTE the code. This plane answers an unauthenticated caller with
			// 403, not the 401 the AGENT's apiAuthMiddleware returns for the
			// same class of refusal on /api/v1/system-policies. The two planes
			// were written by different changes (#3068 here, apiAuthMiddleware
			// there) and never converged; asserting 401 here because that is
			// what the sibling test asserts fails against the real handler.
			anon := httptest.NewRequest("GET", prefix, nil)
			anon.Header.Set("X-Tenant-ID", "other-tenant-acme")
			anonRR := httptest.NewRecorder()
			build().ServeHTTP(anonRR, anon)
			if anonRR.Code != http.StatusForbidden {
				t.Errorf("unauthenticated GET %s: got %d, want 403 - this route is anonymously readable",
					prefix, anonRR.Code)
			}

			// Control: the same request WITH a token must succeed, or the
			// refusal above is just a broken route rather than an enforced gate.
			authed := httptest.NewRequest("GET", prefix, nil)
			authed.Header.Set("X-Tenant-ID", "test-tenant")
			// The orchestrator's proxy gate reads ONE header
			// (X-Axonflow-Proxy-Auth). The agent's internal-service pair
			// (X-Internal-Service-ID / -Token) is a DIFFERENT credential on a
			// different plane; sending it here is a request with no credential
			// at all, which is what "must be routed through AxonFlow Agent"
			// was saying.
			authed.Header.Set("X-Axonflow-Proxy-Auth", validAuthnToken())
			authedRR := httptest.NewRecorder()
			build().ServeHTTP(authedRR, authed)
			if authedRR.Code != http.StatusOK {
				t.Fatalf("authenticated GET %s: got %d, want 200 - the refusal above proves nothing "+
					"if this route refuses everyone. body=%s", prefix, authedRR.Code, authedRR.Body.String())
			}
		})
	}
}

// volatileTenantRE matches wall-clock fields that differ between two calls to
// the SAME prefix, so comparing them could never answer the alias question.
var volatileTenantRE = regexp.MustCompile(`"(computed_at|generated_at|exported_at|timestamp)":"[^"]*"`)

// TestTenantPolicyDeprecationHeadersAreCORSExposed is the orchestrator twin of
// the agent's exposure test. This plane stamps the tenant family, and the
// header is copied back through the agent's reverse proxy, so this is where
// that header's browser visibility is decided.
func TestTenantPolicyDeprecationHeadersAreCORSExposed(t *testing.T) {
	opts := resolveCORSOptions()

	exposed := map[string]bool{}
	for _, h := range opts.ExposedHeaders {
		exposed[http.CanonicalHeaderKey(h)] = true
	}
	if len(exposed) == 0 {
		t.Fatal("resolveCORSOptions exposes NO response headers - the assertions below would be " +
			"checking an empty set")
	}
	for _, want := range []string{policypath.HeaderDeprecation, policypath.HeaderLink} {
		if !exposed[http.CanonicalHeaderKey(want)] {
			t.Errorf("%q is not in ExposedHeaders %v", want, opts.ExposedHeaders)
		}
	}
}
