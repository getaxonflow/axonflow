// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/legacyfreeze"
	"axonflow/platform/shared/policypath"
)

// TestTheDeprecatedPolicyFamilyAnswersTheFreezeToo is #4036.
//
// #4014 froze /api/v1/policies and /api/v1/policies/import. This handler serves
// the SAME PolicyServicer over the SAME repository from a different type, and
// was left answering `500 INTERNAL_ERROR` - so a caller on the deprecated route
// got "ours is broken, retry" for a write path that had been retired on purpose.
// Suites 3039 and 3059 failed on it deterministically, on main, every
// production-posture run.
//
// # Both prefixes, because they are not separable
//
// RegisterRoutes points the deprecated /api/v1/dynamic-policies block and the
// current /api/v1/tenant-policies block at the SAME handler values, under one
// stamp. So freezing the handler freezes both, and
// TestTenantPolicyAliasResponsesAreIdentical asserts identical status codes
// across the two prefixes, which means a fix that covered only one would fail
// that guard. This test drives both for the same reason.
//
// # Four verbs, not one
//
// core/172 revokes INSERT, UPDATE, DELETE and TRUNCATE. The issue named the
// create path; the census named four, and a verb left unwired keeps answering
// 500 while its neighbours answer 409.
// dynamicFreezeStub is freezeStubService with a category on the looked-up
// policy.
//
// WHY IT EXISTS, because the difference is the point. updateDynamicPolicy and
// deleteDynamicPolicy each fetch the policy first and then refuse with
// `404 "Policy is not a dynamic policy"` unless its category is dynamic-/media-
// prefixed (isValidDynamicPolicyCategory). The shared freezeStubService returns
// a PolicyResource with an EMPTY category, so both verbs 404 before the write is
// ever attempted - which is exactly what the first run of this test did, on all
// four update/delete cases across both prefixes.
//
// PolicyAPIHandler has no such gate, which is why #4014's twin of this test
// never met it. Overridden locally rather than by adding a category to the
// shared stub, because five other tests in this package depend on that fixture
// and widening it to fix mine would change what they exercise.
// getErr lets the LOOKUP fail independently of the write, which is what makes
// the read-path assertion below non-vacuous. Without it GetPolicy always
// succeeds, so no test can reach updateDynamicPolicy's `if err != nil` at the
// lookup (:302) and a handler that classified the freeze on the READ path would
// pass every test in this file.
type dynamicFreezeStub struct {
	*freezeStubService
	getErr error
}

func (s *dynamicFreezeStub) GetPolicy(context.Context, string, string, string) (*PolicyResource, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return &PolicyResource{ID: "p1", Name: "existing", Category: "dynamic-compliance"}, nil
}

func TestTheDeprecatedPolicyFamilyAnswersTheFreezeToo(t *testing.T) {
	routes := []struct {
		name   string
		method string
		suffix string
		body   string
	}{
		{"create", http.MethodPost, "", `{"name":"n","type":"content","category":"dynamic-compliance"}`},
		{"update", http.MethodPut, "/p1", `{"name":"n","category":"dynamic-compliance"}`},
		{"delete", http.MethodDelete, "/p1", ``},
		{"import", http.MethodPost, "/import", `{"policies":[{"name":"n","type":"content","category":"dynamic-compliance"}]}`},
	}

	// BOTH PREFIXES. policypath owns the literals so a rename cannot leave this
	// test asserting against a path nobody serves.
	prefixes := []struct {
		label  string
		prefix string
	}{
		{"deprecated", policypath.LegacyTenantPolicies},
		{"successor", policypath.TenantPolicies},
	}

	// The registrar run.go calls, so the response carries the deprecation
	// stamp exactly as production's does.
	call := func(t *testing.T, svcErr error, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := mux.NewRouter()
		registerLegacyPolicyRoutes(r, NewDynamicPolicyAPIHandler(&dynamicFreezeStub{freezeStubService: &freezeStubService{err: svcErr}}), nil)
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Org-ID", "org-a")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}

	for _, pfx := range prefixes {
		for _, rt := range routes {
			path := pfx.prefix + rt.suffix

			t.Run(pfx.label+"/"+rt.name+" answers the freeze", func(t *testing.T) {
				rr := call(t, freezeError(), rt.method, path, rt.body)
				if rr.Code != http.StatusConflict {
					t.Fatalf("%s %s: status=%d, want 409. A 500 here is the bare INTERNAL_ERROR #4036 exists to stop, "+
						"and it is what failed suites 3039 and 3059 on every posture run. body=%s",
						rt.method, path, rr.Code, rr.Body.String())
				}
				// The refusal is served from the deprecated export surface, so it
				// names the successor on the wire as well as in its body.
				assertDeprecationSignal(t, path, rr.Header())
				// This handler writes an UNTYPED envelope (map), unlike
				// PolicyAPIHandler's typed PolicyAPIError - decoded loosely on
				// purpose, because unifying the two envelopes would change every
				// response shape in this file and is not this issue's scope.
				var out struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
					t.Fatalf("decode body: %v (%s)", err, rr.Body.String())
				}
				if out.Error.Code != legacyfreeze.ErrCode {
					t.Fatalf("%s %s: code=%q, want %q", rt.method, path, out.Error.Code, legacyfreeze.ErrCode)
				}
				// THE REMEDY MUST BE NAMED, on this family too. A refusal an
				// operator cannot act on is barely better than the 500.
				if !strings.Contains(out.Error.Message, TypedAuthoringRoutePrefix) {
					t.Fatalf("%s %s: the refusal does not name the typed authoring route: %q",
						rt.method, path, out.Error.Message)
				}
			})

			t.Run(pfx.label+"/"+rt.name+" does NOT answer an RLS violation as the freeze", func(t *testing.T) {
				// 42501 has two causes. A WITH CHECK violation is a defect in
				// OUR org scoping; reporting it as the freeze would tell an
				// operator to rewrite their integration because of our bug.
				rr := call(t, rlsError(), rt.method, path, rt.body)
				if rr.Code == http.StatusConflict {
					t.Fatalf("%s %s: an RLS WITH CHECK violation was reported as the freeze; both are 42501 and only "+
						"the message separates them. body=%s", rt.method, path, rr.Body.String())
				}
				if rr.Code != http.StatusInternalServerError {
					t.Fatalf("%s %s: status=%d, want 500 - an unclassified 42501 must keep today's behaviour",
						rt.method, path, rr.Code)
				}
			})
		}
	}

	// THE TWO PREFIXES MUST REFUSE IDENTICALLY, asserted directly rather than
	// inferred from both loops passing.
	//
	// TestTenantPolicyAliasResponsesAreIdentical already enforces this for the
	// GET probes, and its probe table is reads-only, so no existing test compares
	// the two prefixes on a WRITE. That gap is how the deprecated family could
	// have been frozen while its successor was not - which is the shape of #4036
	// itself, one level up: #4014 froze /api/v1/policies and left this family at
	// 500 because nothing held the two families equal either.
	//
	// Compared here rather than added to the alias probe table because that
	// table's helper hardcodes aliasListService(); a write probe would mean
	// parameterising a helper several other tests share, for a claim this file
	// can make directly.
	t.Run("both prefixes refuse identically", func(t *testing.T) {
		for _, rt := range routes {
			t.Run(rt.name, func(t *testing.T) {
				legacy := call(t, freezeError(), rt.method, policypath.LegacyTenantPolicies+rt.suffix, rt.body)
				successor := call(t, freezeError(), rt.method, policypath.TenantPolicies+rt.suffix, rt.body)

				// Positive control first: two identical 404s would compare equal
				// and prove nothing.
				if legacy.Code != http.StatusConflict {
					t.Fatalf("legacy %s: got %d want 409 - the comparison below would be vacuous. body=%s",
						rt.name, legacy.Code, legacy.Body.String())
				}
				if successor.Code != legacy.Code {
					t.Errorf("%s: status differs - deprecated %d, successor %d. RegisterRoutes points both at the "+
						"same handler value, so a difference here means the routes diverged. successor body=%s",
						rt.name, legacy.Code, successor.Code, successor.Body.String())
				}
				if legacy.Body.String() != successor.Body.String() {
					t.Errorf("%s: body differs\n  deprecated: %s\n  successor:  %s",
						rt.name, legacy.Body.String(), successor.Body.String())
				}
			})
		}
	})

	// ANTI-VACUITY. Without this, every assertion above would pass against a
	// handler that refused everything on this family.
	t.Run("a successful write is untouched", func(t *testing.T) {
		rr := call(t, nil, http.MethodDelete, policypath.LegacyTenantPolicies+"/p1", ``)
		if rr.Code == http.StatusConflict {
			t.Fatalf("a successful delete answered the freeze: %s", rr.Body.String())
		}
	})

	// THE READ PATH IS NOT FROZEN, and the two 500s that look identical to the
	// write ones belong to it. updateDynamicPolicy and deleteDynamicPolicy each
	// call GetPolicy first, and its failure writes the SAME
	// "Failed to update/delete dynamic policy" message as the write branch. The
	// freeze is wired only on the write; this pins that, because wiring it onto
	// the lookup would turn a read failure into a retirement notice.
	// THIS SUBTEST WAS VACUOUS AND A REVIEWER PROVED IT. As first written it
	// drove a GET against a stub whose GetPolicy could not fail, so it asserted
	// only "a GET is not a write" - and the reviewer wired the freeze onto the
	// read branch and it SURVIVED. The anti-vacuity controls could not catch that
	// either: every freeze call site sits inside `if err != nil`, so an
	// unconditional classifier is invisible to them and mutant 2 was killed by
	// the RLS twins rather than by this.
	//
	// It now makes the LOOKUP fail with the freeze error. updateDynamicPolicy
	// calls GetPolicy first (:301) and writes INTERNAL_ERROR when it errors
	// (:304); if the freeze were classified there, this reds.
	t.Run("a lookup failure is not the freeze", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			method string
			path   string
			body   string
		}{
			{"update", http.MethodPut, policypath.LegacyTenantPolicies + "/p1", `{"name":"n","category":"dynamic-compliance"}`},
			{"delete", http.MethodDelete, policypath.LegacyTenantPolicies + "/p1", ``},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r := mux.NewRouter()
				// The WRITE cannot fail here: only the lookup does. So a 409 can
				// only mean the read path was classified.
				registerLegacyPolicyRoutes(r, NewDynamicPolicyAPIHandler(&dynamicFreezeStub{
					freezeStubService: &freezeStubService{err: nil},
					getErr:            freezeError(),
				}), nil)
				var req *http.Request
				if tc.body == "" {
					req = httptest.NewRequest(tc.method, tc.path, nil)
				} else {
					req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				}
				req.Header.Set("X-Tenant-ID", "tenant-a")
				req.Header.Set("X-Org-ID", "org-a")
				rr := httptest.NewRecorder()
				r.ServeHTTP(rr, req)

				if rr.Code == http.StatusConflict {
					t.Fatalf("%s: the READ path answered the freeze. core/172 revokes WRITES; a refused "+
						"lookup is a server error, and reporting it as a retirement notice tells an operator "+
						"to rewrite an integration over a failed read. body=%s", tc.name, rr.Body.String())
				}
				if rr.Code != http.StatusInternalServerError {
					t.Fatalf("%s: status=%d, want 500 - the lookup failure must keep today's behaviour", tc.name, rr.Code)
				}
			})
		}
	})
}
