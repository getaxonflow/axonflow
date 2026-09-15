// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3948: the two pending-approval endpoints are documented as a matched pair,
// cross-reference each other, and refused differently.
//
//	GET /api/v1/workflows/approvals/pending  (WCP)  required BOTH X-Org-ID and
//	                                                X-Tenant-ID, refused the
//	                                                unowned sentinel, answered 401
//	GET /api/v1/plans/approvals/pending      (MAP)  read X-Tenant-ID RAW, never
//	                                                looked at X-Org-ID, accepted
//	                                                the sentinel, answered 400
//
// A reviewer UI sending only X-Tenant-ID worked on one and got a 401 on the
// other, and the published document said `400 Tenant ID missing` for both.
//
// # THE TENANCY QUESTION, AND WHY THIS FILE IS NOT THE THING THAT ANSWERED IT
//
// "One endpoint enforces organisation scope and its counterpart does not read
// the organisation header at all" reads like a tenancy hole, and the honest
// answer is that IT IS NOT ONE - established by driving it against a live
// stack, not by reading this code. runtime-e2e/3948_pending_approvals_pair
// holds that proof and its README holds the reasoning. In summary:
//
//   - requireInternalProxyAuth (authn_middleware.go) wraps the WHOLE mux with
//     no carve-out for any deployment mode, so a direct-to-orchestrator request
//     for either path is 403 before any handler runs;
//   - the agent and portal proxies both Set - never Add - these two headers
//     from a validated credential, so an injected X-Tenant-ID is overwritten;
//   - and both queries key on `w.tenant_id` alone, with the MAP result set a
//     strict SUBSET of the WCP one, so no organisation is reachable through one
//     that is not reachable through the other.
//
// A CALL GRAPH SAID THE OPPOSITE, and that is worth recording because it is the
// trap. mapPendingApprovalsHandler is the only one of the three MAP HITL
// handlers with no verifyAgentProxyAuth call - its siblings have one - which
// reads exactly like an unguarded surface. That is a true statement about the
// function and a false one about the surface: the global middleware post-dates
// those per-handler gates.
//
// So what was left is a CONTRACT defect and a defence-in-depth asymmetry, and
// this file pins the fix for both: the pair now agrees on its tenancy inputs
// and on its refusal status.

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/tenantscope"

	"github.com/gorilla/mux"
)

// TestBothPendingApprovalEndpointsRefuseTheSameTenancyInputs is the parity
// assertion, driven through both handlers rather than compared by reading them.
//
// It is a UNIT test and not part of the runtime suite for a reason worth
// stating: on a live stack these refusals are UNREACHABLE. Every legitimate hop
// stamps both headers, and an illegitimate one is stopped by the proxy-auth
// middleware with a 403 before the handler is entered. So the only place the
// two handlers' own tenancy verdicts can be compared is in process - and that
// is also why they were free to diverge for as long as they did.
func TestBothPendingApprovalEndpointsRefuseTheSameTenancyInputs(t *testing.T) {
	// BOTH POSTURES, and that is not belt-and-braces.
	//
	// The first version of this test pinned `enterprise` only, on the reasoning
	// that the tier gate would otherwise refuse before the tenancy check and
	// what is measured must be the tenancy verdict. That is true, and it made
	// the test blind to the defect R3 found: in COMMUNITY mode the tier gate
	// ran ABOVE the bind, so an unbound caller got a 403 whose body names the
	// licence tier and recites the entitlement matrix. Enterprise is the one
	// mode where that gate is skipped, so pinning it hid the case.
	//
	// The gate now runs below the bind, and this asserts that in the posture
	// where it is reachable.
	for _, mode := range []string{"enterprise", "community"} {
		t.Run("DEPLOYMENT_MODE="+mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			assertPendingPairRefusesIdentically(t)
		})
	}
}

func assertPendingPairRefusesIdentically(t *testing.T) {
	t.Helper()

	wcp := mux.NewRouter()
	workflow_control.NewHandler(nil).RegisterEnterpriseRoutes(wcp)

	mapRouter := mux.NewRouter()
	mapRouter.HandleFunc("/api/v1/plans/approvals/pending", mapPendingApprovalsHandler).
		Methods("GET", "OPTIONS")

	type endpoint struct {
		name    string
		path    string
		handler http.Handler
		// family is the envelope the published document declares for this
		// operation. The two DIFFER, deliberately - see the assertion below.
		family string
	}
	endpoints := []endpoint{
		{"WCP /api/v1/workflows/approvals/pending", "/api/v1/workflows/approvals/pending", wcp, familyTriplet},
		{"MAP /api/v1/plans/approvals/pending", "/api/v1/plans/approvals/pending", mapRouter, familyFlat},
	}

	// Each case is a tenancy input the pair MUST agree on. The sentinel rows
	// are the sharp ones: migration core/156 stamps the unowned sentinel onto
	// rows owned by nobody, and an operator who sets ORG_ID to that string must
	// not thereby unlock them.
	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"neither header", nil},
		{"tenant only — the reviewer-UI request that worked on one and 401'd on the other",
			map[string]string{tenantscope.HeaderTenantID: "tenant-a"}},
		{"org only", map[string]string{tenantscope.HeaderOrgID: "org-a"}},
		{"the unowned sentinel as the tenant", map[string]string{
			tenantscope.HeaderOrgID: "org-a", tenantscope.HeaderTenantID: tenantscope.UnownedOrgSentinel}},
		{"the unowned sentinel as the org", map[string]string{
			tenantscope.HeaderOrgID: tenantscope.UnownedOrgSentinel, tenantscope.HeaderTenantID: "tenant-a"}},
		{"whitespace-only tenant", map[string]string{
			tenantscope.HeaderOrgID: "org-a", tenantscope.HeaderTenantID: "   "}},
	}

	if len(cases) < 5 {
		t.Fatalf("only %d tenancy inputs are compared; this is not a parity test", len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codes := map[string]int{}
			for _, ep := range endpoints {
				req := httptest.NewRequest(http.MethodGet, ep.path, nil)
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()
				ep.handler.ServeHTTP(rec, req)
				codes[ep.name] = rec.Code

				if rec.Code != http.StatusUnauthorized {
					t.Errorf("%s answered %d, want 401. Body: %.200q\n"+
						"    Both endpoints of a documented matched pair must refuse an unbound "+
						"caller identically, and 401 is correct on both: the refusal does not "+
						"depend on the resource.", ep.name, rec.Code, rec.Body.String())
				}
				// A refusal must still be a JSON object a client can read - AND
				// it must be the envelope the published document declares.
				//
				// Asserting only "some JSON object" was the gap R3 found. The
				// pair now agrees on the STATUS and still emits two different
				// SHAPES for it: the WCP plane's writer is the triplet
				// `{error, code, message}` and the MAP plane's is the flat
				// `{success, error}`. That divergence is deliberate - each
				// endpoint uses its own plane's writer and converging either is
				// a wire change on that plane - but it is exactly the class
				// #3941 is about, so it is PINNED rather than left to be
				// rediscovered. A client of this documented pair needs two
				// error types, and the document now says so at both sites.
				fam, err := familyOfWireBody(rec.Body.Bytes())
				if err != nil {
					t.Errorf("%s: refusal body is not a recognised error envelope: %v (%.120q)",
						ep.name, err, rec.Body.String())
				} else if fam != ep.family {
					t.Errorf("%s: refusal is the %s envelope, want %s. The published document "+
						"declares %s for this operation; if the handler's writer changed, the "+
						"document must move with it.", ep.name, fam, ep.family, ep.family)
				}
			}

			// Stated as an EQUALITY between the two rather than as two separate
			// expectations of 401. If a later change moves both to some other
			// status, that is a decision; if it moves ONE, that is this issue
			// happening again, and only the equality catches it.
			if codes[endpoints[0].name] != codes[endpoints[1].name] {
				t.Errorf("the pair disagrees: %s=%d, %s=%d. These two endpoints cross-reference each "+
					"other in the published document; a client cannot use one error path for both.",
					endpoints[0].name, codes[endpoints[0].name],
					endpoints[1].name, codes[endpoints[1].name])
			}
		})
	}
}

// TestTheMAPPendingHandlerBindsAScopeRatherThanReadingAHeader pins the
// mechanism, not only the status code.
//
// A handler could be made to answer 401 for every case above while still
// reading X-Tenant-ID raw and passing it downstream - the status would match
// and the fail-open idiom #3065 exists to remove would still be there. This
// asserts the property that actually matters: a request whose org is absent is
// refused even though its TENANT is perfectly good, which is only true if the
// handler binds a scope.
func TestTheMAPPendingHandlerBindsAScopeRatherThanReadingAHeader(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/approvals/pending", mapPendingApprovalsHandler).
		Methods("GET", "OPTIONS")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plans/approvals/pending", nil)
	req.Header.Set(tenantscope.HeaderTenantID, "tenant-a") // valid, and alone
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a request carrying a good tenant and NO org was answered %d. Before #3948 this "+
			"handler read X-Tenant-ID straight off the request and served the listing; the fix is "+
			"that it binds a tenantscope.Scope, which needs both dimensions. Body: %.200q",
			rec.Code, rec.Body.String())
	}
}
