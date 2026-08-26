// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"

	"sort"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policypath"
	"axonflow/platform/shared/serviceauth"
)

// #1431. /api/v1/system-policies is an ALIAS of /api/v1/static-policies: one
// handler value, two prefixes. These tests are the proof, and they are written
// against the two failure modes an alias actually has.
//
// The first is INCOMPLETENESS: the successor serves a subset of the routes, or
// serves them on fewer methods, and nobody notices because the route somebody
// tried happened to be one of the ones that got copied.
//
// The second is a LOST GUARD: the successor route is reachable without the
// middleware its twin carries. That one does not show up as an error anywhere;
// it shows up as an unauthenticated caller getting a 200.
//
// Both are checked here structurally (over every route, not a sample) and then
// by paired live requests that compare the whole response.

// aliasTestSecret is the internal-service HMAC secret these tests install.
// Internal-service auth is used deliberately: it is the ONE credential shape
// that authenticates identically in the community and enterprise builds, so
// these tests exercise the real apiAuthMiddleware in both without a t.Skip.
// A skipped alias-parity test in one edition is a parity claim nobody checked
// in that edition.
const aliasTestSecret = "ws1431-alias-parity-secret-at-least-32-chars"

// withInternalServiceAuth installs the HMAC validator and returns a function
// that stamps a request with credentials apiAuthMiddleware accepts.
func withInternalServiceAuth(t *testing.T) func(*http.Request) {
	t.Helper()

	prev := internalTokenValidator
	internalTokenValidator = serviceauth.NewTokenValidator(
		aliasTestSecret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
	t.Cleanup(func() { internalTokenValidator = prev })

	// DEPLOYMENT_MODE is pinned so the community fallback token cannot be what
	// makes these pass; the HMAC must be doing the work.
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	gen := serviceauth.NewTokenGenerator(aliasTestSecret, serviceauth.RealClock{})
	return func(r *http.Request) {
		r.Header.Set("X-Internal-Service-ID", serviceauth.ClientID)
		r.Header.Set("X-Internal-Service-Token", gen.GenerateToken())
		r.Header.Set("X-Tenant-ID", "test-tenant")
		r.Header.Set("X-Org-ID", "test-org")
	}
}

// aliasRouter builds the router exactly as run.go does, over a mock DB.
func aliasRouter(t *testing.T) (*mux.Router, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	r := mux.NewRouter()
	RegisterStaticPolicyHandlers(r, db)
	return r, mock
}

// walkedRoute is one registered route, reduced to the shape parity cares about.
type walkedRoute struct {
	suffix  string
	methods string
}

// walkPrefix returns every route registered under prefix, with the prefix
// stripped, so the two families can be compared directly.
func walkPrefix(t *testing.T, r *mux.Router, prefix string) []walkedRoute {
	t.Helper()
	var out []walkedRoute
	err := r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		// Walk visits the PathPrefix(...).Subrouter() mount itself as well as
		// the routes inside it. Subrouter() attaches the child router as a
		// MATCHER, not a handler, so the mount is the one visited route whose
		// handler is nil. Counting it inflates every prefix by exactly one -
		// which is how a 13-row table first appeared to register 14.
		if route.GetHandler() == nil {
			return nil
		}
		tpl, err := route.GetPathTemplate()
		if err != nil {
			return nil // a PathPrefix-only route has no template; not ours
		}
		if tpl != prefix && !strings.HasPrefix(tpl, prefix+"/") {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			methods = []string{"<any>"}
		}
		sort.Strings(methods)
		out = append(out, walkedRoute{
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

// TestSystemPolicyAliasCoversEveryRoute is the completeness half: the two
// prefixes must carry the SAME routes on the SAME methods, derived from the
// live router rather than from the table that built it.
//
// Walking the router matters. Asserting over systemPolicyRoutes would only
// prove the table is self-consistent, which it is by construction; it would
// still pass if RegisterStaticPolicyHandlers registered the table under one
// prefix and something else under the other.
func TestSystemPolicyAliasCoversEveryRoute(t *testing.T) {
	r, _ := aliasRouter(t)

	legacy := walkPrefix(t, r, policypath.LegacySystemPolicies)
	successor := walkPrefix(t, r, policypath.SystemPolicies)

	// Floor, not just equality: two empty lists are "equal" and prove nothing.
	// 13 registrations is what systemPolicyRoutes holds today.
	const wantAtLeast = 13
	if len(legacy) < wantAtLeast {
		t.Fatalf("walked %d routes under %s, expected at least %d - the walk has gone blind "+
			"and every comparison below is vacuous", len(legacy), policypath.LegacySystemPolicies, wantAtLeast)
	}

	if len(legacy) != len(successor) {
		t.Fatalf("route count differs: %s has %d, %s has %d\nlegacy: %+v\nsuccessor: %+v",
			policypath.LegacySystemPolicies, len(legacy),
			policypath.SystemPolicies, len(successor), legacy, successor)
	}
	for i := range legacy {
		if legacy[i] != successor[i] {
			t.Errorf("route %d differs: legacy %+v, successor %+v", i, legacy[i], successor[i])
		}
	}
}

// aliasProbe is one request shape driven against both prefixes.
type aliasProbe struct {
	name      string
	method    string
	suffix    string
	setupMock func(sqlmock.Sqlmock)
	wantCode  int
	// mustContain is a substring the successful body has to carry. Without it
	// the body comparison could be two identical empty envelopes produced by
	// two handlers that both did nothing.
	mustContain string
}

// The list and effective probes drive DIFFERENT queries with DIFFERENT column
// lists, so they need different fixtures. One shared list cannot be right for
// both, and getting that wrong is silent: StaticPolicyRepository's list path
// skips a row whose scan fails without even logging, and
// policy.ScanEffectivePolicyRows logs and continues. Either way the handler
// returns an empty envelope with a 200, which is why the parity assertions
// below are backed by mustContain.
//
// #3334: both lists previously carried the legacy `organization_id` column at
// index 11 - retired by migration core/166 and gone from every production
// SELECT. The scan lists had moved on, so index 11 landed on TenantID (a
// value-typed string), and every row died with
//
//	sql: Scan error on column index 11, name "organization_id":
//	converting NULL to string is unsupported
//
// listMockCols mirrors StaticPolicyRepository.List's scopedList/scopedListBare
// column list (platform/agent/static_policy_repository.go): 20 columns, no
// segment_id, no deleted_at.
var listMockCols = []string{
	"id", "policy_id", "name", "category", "pattern", "severity",
	"description", "action", "tier", "priority", "enabled",
	"tenant_id", "org_id", "tags", "metadata",
	"version", "created_at", "updated_at", "created_by", "updated_by",
}

// effectiveMockCols is the /effective query's column list. It is DERIVED from
// the production SELECT rather than copied, so it cannot drift from it again -
// that copy is what #3334 broke.
var effectiveMockCols = sharedpolicy.EffectivePolicyColumnNames()

func expectScopedList(mock sqlmock.Sqlmock, org string, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(org).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT.*FROM static_policies`).WillReturnRows(rows)
	mock.ExpectCommit()
}

// listRow is one static_policies row shaped for the LIST query (20 columns).
func listRow() *sqlmock.Rows {
	return sqlmock.NewRows(listMockCols).AddRow(
		"uuid-1", "sql_injection_union", "SQL Injection UNION", "security-sqli",
		"union\\s+select", "critical", "Blocks UNION-based SQL injection", "block",
		"system", 100, true, "global", GlobalOrgSentinel, "[]", "{}",
		1, testTime, testTime, "system", "system",
	)
}

// effectiveRow is the same policy shaped for the EFFECTIVE query (21 columns:
// segment_id sits between org_id and tags).
func effectiveRow() *sqlmock.Rows {
	return sqlmock.NewRows(effectiveMockCols).AddRow(
		"uuid-1", "sql_injection_union", "SQL Injection UNION", "security-sqli",
		"union\\s+select", "critical", "Blocks UNION-based SQL injection", "block",
		"system", 100, true, "global", GlobalOrgSentinel, nil, "[]", "{}",
		1, testTime, testTime, "system", "system",
	)
}

// aliasProbes are request shapes whose full response is compared across the
// two prefixes. Every one is a 200: a probe that 4xx'd on both prefixes would
// "prove parity" while proving only that the request never reached a handler,
// which is the exact shape of a vacuous parity test.
func aliasProbes() []aliasProbe {
	return []aliasProbe{
		{
			name:   "list",
			method: "GET",
			suffix: "",
			setupMock: func(m sqlmock.Sqlmock) {
				expectScopedList(m, "test-org", listRow())
				expectScopedList(m, GlobalOrgSentinel, sqlmock.NewRows(listMockCols))
			},
			wantCode:    http.StatusOK,
			mustContain: "sql_injection_union",
		},
		{
			name:   "effective",
			method: "GET",
			suffix: "/effective",
			setupMock: func(m sqlmock.Sqlmock) {
				// The tenant-scoped pass additionally resolves overrides; the
				// global pass does not. Mirrors TestHandleGetEffectivePolicies.
				m.ExpectBegin()
				m.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("test-org").
					WillReturnResult(sqlmock.NewResult(0, 0))
				m.ExpectQuery(`SELECT.*FROM static_policies`).
					WillReturnRows(sqlmock.NewRows(effectiveMockCols))
				m.ExpectQuery(`SELECT po\.id, po\.policy_id`).
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "action_override", "enabled_override",
						"expires_at", "override_reason",
					}))
				m.ExpectCommit()
				expectScopedList(m, GlobalOrgSentinel, effectiveRow())
			},
			wantCode: http.StatusOK,
			// The policy_id of the row the global pass returns. #3334: this
			// used to be `"tenant_id":"test-tenant"`, which the envelope
			// carries whether or not a single row survived the scan - so the
			// probe stayed green through the whole misalignment while the
			// handler was returning zero policies. The marker has to be
			// something only a scanned ROW can produce.
			mustContain: "sql_injection_union",
		},
	}
}

// serveAlias drives one probe against one prefix on a freshly-mocked router.
func serveAlias(t *testing.T, p aliasProbe, prefix string, stamp func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r, mock := aliasRouter(t)
	if p.setupMock != nil {
		p.setupMock(mock)
	}
	req := httptest.NewRequest(p.method, prefix+p.suffix, nil)
	stamp(req)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

// TestSystemPolicyAliasResponsesAreIdentical is the paired-request half: the
// same request on both prefixes must produce the same status, the same body
// and the same headers, with the deprecation signal as the ONLY difference.
func TestSystemPolicyAliasResponsesAreIdentical(t *testing.T) {
	stamp := withInternalServiceAuth(t)

	for _, p := range aliasProbes() {
		t.Run(p.name, func(t *testing.T) {
			legacyRR := serveAlias(t, p, policypath.LegacySystemPolicies, stamp)
			successorRR := serveAlias(t, p, policypath.SystemPolicies, stamp)

			// Positive control FIRST. Everything below compares two responses,
			// and two 401s compare equal. If auth or routing broke, this is
			// what says so instead of a green parity assertion.
			if legacyRR.Code != p.wantCode {
				t.Fatalf("legacy %s%s: got %d, want %d - the request never reached the handler, "+
					"so the parity assertions below would be vacuous. body=%s",
					policypath.LegacySystemPolicies, p.suffix, legacyRR.Code, p.wantCode, legacyRR.Body.String())
			}

			if successorRR.Code != legacyRR.Code {
				t.Errorf("status differs: legacy %d, successor %d (successor body=%s)",
					legacyRR.Code, successorRR.Code, successorRR.Body.String())
			}
			if normalizeVolatile(legacyRR.Body.String()) != normalizeVolatile(successorRR.Body.String()) {
				t.Errorf("body differs:\n legacy:    %s\n successor: %s",
					legacyRR.Body.String(), successorRR.Body.String())
			}

			// The body must also be the real thing, not an empty envelope that
			// two handlers which both did nothing could agree on.
			if !strings.Contains(legacyRR.Body.String(), p.mustContain) {
				t.Fatalf("legacy body does not contain %q - the handler returned no policy data, "+
					"so the body comparison above is two empty envelopes: %s",
					p.mustContain, legacyRR.Body.String())
			}

			compareHeadersIgnoringDeprecation(t, legacyRR.Header(), successorRR.Header())
		})
	}
}

// volatileFieldRE matches response fields whose value is a wall-clock stamp
// taken when the handler ran. /effective returns one (`computed_at`), so two
// requests one microsecond apart differ in the body no matter how identical
// the handlers are.
//
// Normalising it is not the test going soft: the alias question is whether the
// two prefixes reach the same handler, and a field that differs between two
// calls to the SAME prefix cannot answer it either way. Everything else is
// still compared byte for byte, and mustContain separately proves the body is
// a real envelope rather than an empty one.
var volatileFieldRE = regexp.MustCompile(`"(computed_at|generated_at|timestamp)":"[^"]*"`)

func normalizeVolatile(body string) string {
	return volatileFieldRE.ReplaceAllString(body, `"$1":"<normalized>"`)
}

// compareHeadersIgnoringDeprecation asserts the two header maps agree on
// everything except the deprecation signal.
func compareHeadersIgnoringDeprecation(t *testing.T, legacy, successor http.Header) {
	t.Helper()
	skip := map[string]bool{
		http.CanonicalHeaderKey(policypath.HeaderDeprecation): true,
		http.CanonicalHeaderKey(policypath.HeaderLink):        true,
	}
	keys := map[string]bool{}
	for k := range legacy {
		keys[k] = true
	}
	for k := range successor {
		keys[k] = true
	}
	for k := range keys {
		if skip[k] {
			continue
		}
		a, b := legacy.Values(k), successor.Values(k)
		if fmt.Sprint(a) != fmt.Sprint(b) {
			t.Errorf("header %q differs: legacy %v, successor %v", k, a, b)
		}
	}
}

// TestDeprecationSignalIsOnLegacyPathsOnly checks the signal itself, in both
// directions. An alias rollout gets this wrong in one of two ways: the header
// is missing on the old name (nobody is told to migrate) or it is present on
// the new one (everybody is told the new name is already dying).
func TestDeprecationSignalIsOnLegacyPathsOnly(t *testing.T) {
	stamp := withInternalServiceAuth(t)

	for _, p := range aliasProbes() {
		t.Run(p.name, func(t *testing.T) {
			legacyRR := serveAlias(t, p, policypath.LegacySystemPolicies, stamp)
			successorRR := serveAlias(t, p, policypath.SystemPolicies, stamp)

			if legacyRR.Code != p.wantCode {
				t.Fatalf("legacy request did not reach the handler (%d); header assertions would be vacuous", legacyRR.Code)
			}

			if got := legacyRR.Header().Get(policypath.HeaderDeprecation); got != policypath.DeprecationValue {
				t.Errorf("legacy %s%s: Deprecation = %q, want %q",
					policypath.LegacySystemPolicies, p.suffix, got, policypath.DeprecationValue)
			}
			wantLink := policypath.LinkSuccessor(policypath.SystemPolicies + p.suffix)
			if got := legacyRR.Header().Get(policypath.HeaderLink); got != wantLink {
				t.Errorf("legacy %s%s: Link = %q, want %q",
					policypath.LegacySystemPolicies, p.suffix, got, wantLink)
			}

			if got := successorRR.Header().Get(policypath.HeaderDeprecation); got != "" {
				t.Errorf("successor %s%s carries Deprecation = %q - the new name must not "+
					"announce its own deprecation", policypath.SystemPolicies, p.suffix, got)
			}
			if got := successorRR.Header().Get(policypath.HeaderLink); got != "" {
				t.Errorf("successor %s%s carries Link = %q", policypath.SystemPolicies, p.suffix, got)
			}

			// No Sunset, on either path. A Sunset date is a removal promise,
			// and whether these paths are ever removed is undecided.
			for _, rr := range []*httptest.ResponseRecorder{legacyRR, successorRR} {
				if got := rr.Header().Get("Sunset"); got != "" {
					t.Errorf("Sunset = %q - this change promises no removal date", got)
				}
			}
		})
	}
}

// TestSystemPolicyAliasIsAuthenticated is the lost-guard half. The successor
// must refuse an unauthenticated caller exactly as its twin does.
//
// Both directions are asserted: the refusal, and a control proving the same
// request succeeds once it carries credentials. A test that only asserted 401
// would still pass if the route had been deleted.
func TestSystemPolicyAliasIsAuthenticated(t *testing.T) {
	stamp := withInternalServiceAuth(t)
	noAuth := func(*http.Request) {}

	for _, prefix := range []string{policypath.LegacySystemPolicies, policypath.SystemPolicies} {
		t.Run(prefix, func(t *testing.T) {
			p := aliasProbes()[0] // list

			anon := serveAlias(t, aliasProbe{name: p.name, method: p.method, suffix: p.suffix}, prefix, noAuth)
			if anon.Code != http.StatusUnauthorized {
				t.Errorf("unauthenticated GET %s: got %d, want 401 - the alias lost apiAuthMiddleware",
					prefix, anon.Code)
			}

			authed := serveAlias(t, p, prefix, stamp)
			if authed.Code != http.StatusOK {
				t.Fatalf("authenticated GET %s: got %d, want 200 - the 401 above proves nothing "+
					"if this route refuses everyone. body=%s", prefix, authed.Code, authed.Body.String())
			}
		})
	}
}

// TestSystemPolicyAliasSharesOneHandlerValue pins the "alias, not fork"
// property at the source: both prefixes are registered from systemPolicyRoutes,
// so a route added to that table appears on both or on neither. If someone
// replaces the loop with two hand-written blocks, the count here stops matching
// what the router carries.
func TestSystemPolicyAliasSharesOneHandlerValue(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	table := systemPolicyRoutes(NewStaticPolicyAPIHandler(db))
	if len(table) == 0 {
		t.Fatal("systemPolicyRoutes is empty")
	}

	r, _ := aliasRouter(t)
	for _, prefix := range []string{policypath.LegacySystemPolicies, policypath.SystemPolicies} {
		got := len(walkPrefix(t, r, prefix))
		if got != len(table) {
			t.Errorf("%s carries %d routes but the shared table has %d - the two prefixes are "+
				"no longer registered from one list", prefix, got, len(table))
		}
	}
}

// TestPolicyPathHelpersRejectNearMisses guards the segment-boundary rule that
// keeps the deprecation stamp off paths that merely start with the same bytes.
func TestPolicyPathHelpersRejectNearMisses(t *testing.T) {
	cases := []struct {
		path string
		want string // "" means: not a legacy path
	}{
		{"/api/v1/static-policies", "/api/v1/system-policies"},
		{"/api/v1/static-policies/effective", "/api/v1/system-policies/effective"},
		{"/api/v1/static-policies/abc/override", "/api/v1/system-policies/abc/override"},
		{"/api/v1/dynamic-policies", "/api/v1/tenant-policies"},
		{"/api/v1/dynamic-policies/x/versions", "/api/v1/tenant-policies/x/versions"},
		// near misses: same byte prefix, different route family
		{"/api/v1/static-policies-archive", ""},
		{"/api/v1/dynamic-policiesX", ""},
		// the successors are never themselves legacy
		{"/api/v1/system-policies", ""},
		{"/api/v1/tenant-policies/abc", ""},
		// unrelated
		{"/api/v1/policy-overrides", ""},
		{"/health", ""},
	}
	for _, c := range cases {
		got, ok := policypath.SuccessorOf(c.path)
		if c.want == "" {
			if ok {
				t.Errorf("SuccessorOf(%q) = %q, want no match", c.path, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("SuccessorOf(%q) = %q,%v want %q,true", c.path, got, ok, c.want)
		}
	}

	// StampDeprecation must be a no-op on a non-legacy path, so a caller
	// cannot stamp a successor by handing it the wrong string.
	h := http.Header{}
	if policypath.StampDeprecation(h, policypath.SystemPolicies) {
		t.Error("StampDeprecation reported success on a successor path")
	}
	if len(h) != 0 {
		t.Errorf("StampDeprecation wrote headers on a successor path: %v", h)
	}
}

// TestSystemPolicyAliasHasTheSameEditionPostureAsItsTwin is the edition half
// of HARD RULE 11, and it runs in BOTH builds because this file carries no
// build tag.
//
// The claim being pinned is narrow and worth stating exactly: the rename adds
// no capability, so the successor must be present in precisely the builds
// where its twin is present, and must give the same answer on the routes that
// ARE edition-gated.
//
// Nothing here is gated at REGISTRATION - none of the three files involved
// carries a build tag, and the Enterprise gate on the /override endpoints is a
// runtime ErrOverrideRequiresEnterprise inside the shared handler. That is the
// whole reason the alias inherits edition behaviour for free. This test exists
// so that if somebody later gates one prefix at registration, or wraps one in
// an edition check, CI says so in both lanes instead of only the one they ran.
func TestSystemPolicyAliasHasTheSameEditionPostureAsItsTwin(t *testing.T) {
	stamp := withInternalServiceAuth(t)
	r, _ := aliasRouter(t)

	// 1. Presence parity in THIS build, whichever it is.
	legacyOverride := routeExists(t, r, "POST", policypath.LegacySystemPolicies+"/abc/override")
	successorOverride := routeExists(t, r, "POST", policypath.SystemPolicies+"/abc/override")
	if legacyOverride != successorOverride {
		t.Fatalf("community build=%v: the Enterprise-gated override route is registered on "+
			"%s=%v but on %s=%v - the alias has a different edition posture from the name it aliases",
			isCommunityBuild, policypath.LegacySystemPolicies, legacyOverride,
			policypath.SystemPolicies, successorOverride)
	}
	if !legacyOverride {
		t.Fatalf("community build=%v: the override route is registered on NEITHER prefix, so the "+
			"parity above is vacuous", isCommunityBuild)
	}

	// 2. Same answer on the gated route. No mock expectations are set, so both
	//    requests fail the same way inside the same handler; what is asserted
	//    is that they fail IDENTICALLY and that neither 404s, which is what a
	//    missing alias route would produce.
	probe := aliasProbe{method: "POST", suffix: "/abc/override"}
	legacyRR := serveAlias(t, probe, policypath.LegacySystemPolicies, stamp)
	successorRR := serveAlias(t, probe, policypath.SystemPolicies, stamp)

	if legacyRR.Code == http.StatusNotFound || successorRR.Code == http.StatusNotFound {
		t.Fatalf("override route 404s (legacy %d, successor %d) - it is not reachable on both prefixes",
			legacyRR.Code, successorRR.Code)
	}
	if legacyRR.Code != successorRR.Code {
		t.Errorf("edition-gated route answers differently per prefix: legacy %d, successor %d",
			legacyRR.Code, successorRR.Code)
	}
	if normalizeVolatile(legacyRR.Body.String()) != normalizeVolatile(successorRR.Body.String()) {
		t.Errorf("edition-gated route body differs:\n legacy:    %s\n successor: %s",
			legacyRR.Body.String(), successorRR.Body.String())
	}
}

// routeExists reports whether the router matches method+path at all.
func routeExists(t *testing.T, r *mux.Router, method, path string) bool {
	t.Helper()
	var m mux.RouteMatch
	return r.Match(httptest.NewRequest(method, path, nil), &m)
}

// TestDeprecationHeadersAreCORSExposed pins the deprecation signal's
// VISIBILITY, which is a separate property from its presence.
//
// Neither Deprecation nor Link is a CORS-safelisted response header, and
// AllowedHeaders governs REQUEST headers only. So a response can carry a
// perfectly correct signal that a browser client reads as null - and the
// public docs tell clients to follow the Link mechanically, which the largest
// class of caller could not do.
//
// Asserted against the resolved cors.Options rather than a live preflight so
// it holds for every origin policy the deployment might resolve.
func TestDeprecationHeadersAreCORSExposed(t *testing.T) {
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
			t.Errorf("%q is not in ExposedHeaders %v - a browser client gets null from "+
				"response.headers.get(%q), so the deprecation signal is invisible to it",
				want, opts.ExposedHeaders, want)
		}
	}
}
