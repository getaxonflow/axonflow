// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Regression tests for #3066 slice C3-4 — POST /api/v1/mcp/evaluate-policies
// scoped its evaluation solely on the request BODY's tenant_id and never read
// the gateway-stamped X-Tenant-ID, on a route the agent gateway proxies.
//
// Any authenticated tenant could therefore POST {"tenant_id":"<victim>"} and
// receive the victim's matched_policies — policy_id, policy_name, action and
// the human-authored reason string — while ALSO consuming the victim's shared
// rate-limit window and budget period, because both counters key on the same
// body field.
//
// Every test here drives the REAL route through the REAL gorilla/mux router,
// because the defect lives on the request path (header vs body), not inside
// any evaluator method. Calling resolveEvaluationScope directly would not
// exercise the wiring that was broken.
//
// The refusals are the headline. Each is paired with a control that must keep
// returning the caller's OWN answer, so a regression that simply refused
// everything — or evaluated nothing — fails here too
// ([[feedback_absence_is_not_evidence_in_runtime_harness]]).
//
// Pre-fix status of this file: the four cross-tenant assertions
// (ForeignBodyTenantIsRefused, ForeignTenantPoliciesAreNotDisclosed,
// ForeignTenantCountersAreNotBurned, StampedButEmptyTenancyFailsClosed,
// HalfStampedTenancyFailsClosed) all FAIL against origin/main, which returns
// 200 with the victim's policy matched and the victim's counters incremented.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

// Two tenancies. "attacker" holds a valid credential for tenant A; "victim" is
// the tenant whose policies and counters must stay out of reach.
const (
	scope3066AttackerTenant = "rte3066-tenant-a"
	scope3066AttackerOrg    = "rte3066-org-a"
	scope3066VictimTenant   = "rte3066-tenant-b"
	scope3066VictimOrg      = "rte3066-org-b"

	// Distinctive strings so a disclosure assertion can search the whole
	// response body rather than one decoded field — a leak that arrived in a
	// field this test does not know about would still be caught.
	scope3066VictimPolicyID   = "pol-rte3066-victim-secret-control"
	scope3066VictimPolicyName = "Victim KYC exfiltration control"
	scope3066VictimReason     = "victim control matched: unbounded KYC read"

	scope3066AttackerPolicyID   = "pol-rte3066-attacker-own-control"
	scope3066AttackerPolicyName = "Attacker own control"
	scope3066AttackerReason     = "attacker own control matched"
)

// scope3066Policy builds a tenant-scoped content policy that blocks on a
// marker substring. Content is the type POST /api/v1/policies defaults to, so
// this is the shape a real tenant policy has (#3061).
func scope3066Policy(id, name, tenantID, marker, reason string) DynamicPolicy {
	return DynamicPolicy{
		ID:       id,
		Name:     name,
		Type:     "content",
		Enabled:  true,
		TenantID: tenantID,
		Conditions: []PolicyCondition{
			{Field: "statement", Operator: "contains", Value: marker},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{"reason": reason}},
		},
	}
}

// scope3066Policies is the seeded world: one policy per tenancy, each matching
// its own marker. Both are present in EVERY test so "did the wrong tenant's
// policy come back?" and "did the right tenant's policy still work?" are
// answerable from the same fixture.
func scope3066Policies() []DynamicPolicy {
	return []DynamicPolicy{
		scope3066Policy(scope3066VictimPolicyID, scope3066VictimPolicyName,
			scope3066VictimTenant, "rte3066_victim_marker", scope3066VictimReason),
		scope3066Policy(scope3066AttackerPolicyID, scope3066AttackerPolicyName,
			scope3066AttackerTenant, "rte3066_attacker_marker", scope3066AttackerReason),
	}
}

// scope3066Request is the wire body. tenant_id is emitted verbatim — including
// empty, which must serialize as `""` rather than being dropped, so the
// omitted-vs-empty distinction the handler draws is actually under test.
type scope3066Request struct {
	TenantID       string `json:"tenant_id"`
	OrganizationID string `json:"organization_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	ConnectorName  string `json:"connector_name"`
	Operation      string `json:"operation,omitempty"`
	Statement      string `json:"statement,omitempty"`
}

// post3066 drives the real route. headers are applied verbatim so a test can
// express "header absent" (omit the key) and "header present but empty"
// (supply an empty value) — two states the fix treats differently and which
// a map[string]string with a "" convention would collapse.
func post3066(t *testing.T, policies []DynamicPolicy, body scope3066Request, headers http.Header) *httptest.ResponseRecorder {
	t.Helper()

	engine := newTestEngine(policies)
	defer engine.Close()

	router := mux.NewRouter()
	NewMCPDynamicPolicyHandler(engine).RegisterRoutes(router)

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/evaluate-policies", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, vals := range headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// stamped builds the header set the agent gateway produces: proxy.go Sets both
// X-Tenant-ID and X-Org-ID from the validated credential on every proxied
// route. The portal's catch-all orchestrator proxy stamps the same pair from
// the session, so this fixture stands for both tenant-authenticating hops.
func stamped(tenant, org string) http.Header {
	h := http.Header{}
	h.Set("X-Tenant-ID", tenant)
	h.Set("X-Org-ID", org)
	return h
}

func decode3066(t *testing.T, rr *httptest.ResponseRecorder) MCPPolicyEvaluationResponse {
	t.Helper()
	var resp MCPPolicyEvaluationResponse
	if err := json.NewDecoder(bytes.NewReader(rr.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
	return resp
}

// assertNoVictimDisclosure searches the RAW response bytes, not a decoded
// struct. The leak this closes is a set of identifiers echoed back inside
// matched_policies; asserting on the decoded slice would miss the same strings
// resurfacing in block_reason, metadata or an error message.
func assertNoVictimDisclosure(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	body := rr.Body.String()
	for _, secret := range []string{scope3066VictimPolicyID, scope3066VictimPolicyName, scope3066VictimReason} {
		if strings.Contains(body, secret) {
			t.Errorf("response discloses the victim tenant's policy detail %q\nbody: %s", secret, body)
		}
	}
}

// ---------------------------------------------------------------------------
// The defect: a stamped caller naming someone else's tenant
// ---------------------------------------------------------------------------

// TestMCP3066_ForeignBodyTenantIsRefused is the core assertion. Pre-fix this
// returned 200.
func TestMCP3066_ForeignBodyTenantIsRefused(t *testing.T) {
	rr := post3066(t, scope3066Policies(), scope3066Request{
		TenantID:      scope3066VictimTenant, // the forged selector
		ConnectorName: "postgres",
		Operation:     "query",
		Statement:     "SELECT * FROM kyc WHERE note='rte3066_victim_marker'",
	}, stamped(scope3066AttackerTenant, scope3066AttackerOrg))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rr.Code, rr.Body.String())
	}
	assertNoVictimDisclosure(t, rr)
}

// TestMCP3066_ForeignTenantPoliciesAreNotDisclosed pins the disclosure half
// independently of the status code, so a future change that answered 200 with
// an empty result — or 403 with a diagnostic that echoed the policy — is still
// a failure.
func TestMCP3066_ForeignTenantPoliciesAreNotDisclosed(t *testing.T) {
	rr := post3066(t, scope3066Policies(), scope3066Request{
		TenantID:      scope3066VictimTenant,
		UserID:        "attacker-user",
		ConnectorName: "postgres",
		Statement:     "rte3066_victim_marker",
	}, stamped(scope3066AttackerTenant, scope3066AttackerOrg))

	assertNoVictimDisclosure(t, rr)

	if rr.Code == http.StatusOK {
		resp := decode3066(t, rr)
		for _, m := range resp.MatchedPolicies {
			t.Errorf("matched a policy on a cross-tenant request: %+v", m)
		}
	}
}

// TestMCP3066_ForeignTenantCountersAreNotBurned covers the second half of the
// finding: the rate-limit and budget stores key on the body tenant, so the
// pre-fix handler let one tenant drain another's shared window and budget
// period. The refusal must happen before either store is touched.
func TestMCP3066_ForeignTenantCountersAreNotBurned(t *testing.T) {
	const victimUser = "rte3066-victim-user"

	policies := []DynamicPolicy{
		{
			ID: "pol-rte3066-victim-ratelimit", Name: "victim rate limit", Type: "rate-limit",
			Enabled: true, TenantID: scope3066VictimTenant,
			Conditions: []PolicyCondition{{Field: "requests_per_minute", Operator: "less_than", Value: float64(5)}},
		},
		{
			ID: "pol-rte3066-victim-budget", Name: "victim budget", Type: "budget",
			Enabled: true, TenantID: scope3066VictimTenant,
			Conditions: []PolicyCondition{{Field: "max_budget", Operator: "less_than", Value: float64(100)}},
		},
	}

	rateKey := fmt.Sprintf("ratelimit:%s:%s:%s", scope3066VictimTenant, victimUser, "postgres")
	budgetKey := fmt.Sprintf("budget:%s:%s", scope3066VictimTenant, victimUser)

	// Start from a known-clean state without deleting anything another test
	// seeded: these keys are unique to this test.
	assertCounterAbsent := func(when string) {
		t.Helper()
		rateLimitMutex.RLock()
		_, rateSeen := rateLimitStore[rateKey]
		rateLimitMutex.RUnlock()
		if rateSeen {
			t.Errorf("%s: the victim tenant's rate-limit window was consumed by another tenant's request (key %q)", when, rateKey)
		}
		budgetStoreMutex.RLock()
		_, budgetSeen := budgetStore[budgetKey]
		budgetStoreMutex.RUnlock()
		if budgetSeen {
			t.Errorf("%s: the victim tenant's budget period was consumed by another tenant's request (key %q)", when, budgetKey)
		}
	}
	assertCounterAbsent("before the request")

	rr := post3066(t, policies, scope3066Request{
		TenantID:      scope3066VictimTenant,
		UserID:        victimUser,
		ConnectorName: "postgres",
		Statement:     "SELECT 1",
	}, stamped(scope3066AttackerTenant, scope3066AttackerOrg))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rr.Code, rr.Body.String())
	}
	assertCounterAbsent("after the refused request")
}

// ---------------------------------------------------------------------------
// Vacuity controls: the caller's OWN evaluation still works
// ---------------------------------------------------------------------------

// TestMCP3066_AuthenticatedTenantStillEvaluates is the anti-vacuity control
// for every refusal above. Same fixture, same route, caller naming itself.
func TestMCP3066_AuthenticatedTenantStillEvaluates(t *testing.T) {
	rr := post3066(t, scope3066Policies(), scope3066Request{
		TenantID:      scope3066AttackerTenant,
		ConnectorName: "postgres",
		Statement:     "SELECT * FROM t WHERE note='rte3066_attacker_marker'",
	}, stamped(scope3066AttackerTenant, scope3066AttackerOrg))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	resp := decode3066(t, rr)
	if resp.Allowed {
		t.Errorf("allowed = true, want false — the caller's own blocking policy did not fire")
	}
	if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0].PolicyID != scope3066AttackerPolicyID {
		t.Errorf("matched_policies = %+v, want exactly the caller's own policy %s",
			resp.MatchedPolicies, scope3066AttackerPolicyID)
	}
	assertNoVictimDisclosure(t, rr)
}

// TestMCP3066_BodyTenantMayBeOmittedWhenStamped: with an authenticated scope
// present the body field is redundant, and omitting it evaluates the caller's
// own tenancy rather than 400ing. This cannot cross a boundary — the only
// value it can resolve to is the caller's own.
func TestMCP3066_BodyTenantMayBeOmittedWhenStamped(t *testing.T) {
	rr := post3066(t, scope3066Policies(), scope3066Request{
		TenantID:      "",
		ConnectorName: "postgres",
		Statement:     "SELECT * FROM t WHERE note='rte3066_attacker_marker'",
	}, stamped(scope3066AttackerTenant, scope3066AttackerOrg))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	resp := decode3066(t, rr)
	if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0].PolicyID != scope3066AttackerPolicyID {
		t.Errorf("matched_policies = %+v, want the caller's own policy resolved from the header",
			resp.MatchedPolicies)
	}
}

// TestMCP3066_WhitespacePaddedBodyTenantMatches: " tenant-a " and "tenant-a"
// are one tenancy. Without trimming on the body side, a caller could not
// accidentally 403 itself — but more importantly the trimmed value is what
// reaches the engine, so the two spellings must not select different policy
// sets.
func TestMCP3066_WhitespacePaddedBodyTenantMatches(t *testing.T) {
	rr := post3066(t, scope3066Policies(), scope3066Request{
		TenantID:      "  " + scope3066AttackerTenant + "\t",
		ConnectorName: "postgres",
		Statement:     "rte3066_attacker_marker",
	}, stamped(scope3066AttackerTenant, scope3066AttackerOrg))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rr.Code, rr.Body.String())
	}
	resp := decode3066(t, rr)
	if len(resp.MatchedPolicies) != 1 {
		t.Errorf("matched_policies = %+v, want the caller's own policy", resp.MatchedPolicies)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed shapes
// ---------------------------------------------------------------------------

// TestMCP3066_StampedButEmptyTenancyFailsClosed: a hop that stamped the
// headers but resolved an empty tenancy must NOT fall through to the body.
// This is the shape that makes "empty" attacker-selectable elsewhere in this
// class (#3065): presence, not value, selects the strict branch.
func TestMCP3066_StampedButEmptyTenancyFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tenant string
		org    string
	}{
		{"both empty", "", ""},
		{"tenant empty", "", scope3066AttackerOrg},
		{"org empty", scope3066AttackerTenant, ""},
		{"tenant whitespace only", "   ", scope3066AttackerOrg},
		{"org whitespace only", scope3066AttackerTenant, "\t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("X-Tenant-ID", tc.tenant)
			h.Set("X-Org-ID", tc.org)

			rr := post3066(t, scope3066Policies(), scope3066Request{
				TenantID:      scope3066VictimTenant,
				ConnectorName: "postgres",
				Statement:     "rte3066_victim_marker",
			}, h)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body: %s)", rr.Code, rr.Body.String())
			}
			assertNoVictimDisclosure(t, rr)
		})
	}
}

// TestMCP3066_HalfStampedTenancyFailsClosed: the gateway sets X-Tenant-ID and
// X-Org-ID together, so a request carrying exactly one did not come from it.
// Either header alone selects the strict branch, and the strict branch needs
// both — so a half-stamped request is refused rather than being handed the
// permissive internal-service reading.
func TestMCP3066_HalfStampedTenancyFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		value  string
	}{
		{"org only", "X-Org-ID", scope3066AttackerOrg},
		{"tenant only", "X-Tenant-ID", scope3066AttackerTenant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set(tc.header, tc.value)

			rr := post3066(t, scope3066Policies(), scope3066Request{
				TenantID:      scope3066VictimTenant,
				ConnectorName: "postgres",
				Statement:     "rte3066_victim_marker",
			}, h)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body: %s)", rr.Code, rr.Body.String())
			}
			assertNoVictimDisclosure(t, rr)
		})
	}
}

// TestMCP3066_AuthorizationPrecedesInputValidation: a cross-tenant attempt is
// refused identically whether or not the rest of the body is valid, so the
// 400s cannot be used to probe which request shapes reach the evaluator.
func TestMCP3066_AuthorizationPrecedesInputValidation(t *testing.T) {
	rr := post3066(t, scope3066Policies(), scope3066Request{
		TenantID:      scope3066VictimTenant,
		ConnectorName: "", // would 400 on its own
	}, stamped(scope3066AttackerTenant, scope3066AttackerOrg))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — authorization must run before connector_name validation (body: %s)",
			rr.Code, rr.Body.String())
	}
}

// TestMCP3066_HeaderSpellingIsCanonicalized guards against a future rewrite
// that reads the header out of a raw map. HTTP header names are
// case-insensitive and net/http canonicalizes them, so a caller cannot dodge
// the strict branch by changing the spelling.
func TestMCP3066_HeaderSpellingIsCanonicalized(t *testing.T) {
	h := http.Header{}
	h["x-tenant-id"] = []string{scope3066AttackerTenant} // deliberately non-canonical

	rr := post3066(t, scope3066Policies(), scope3066Request{
		TenantID:      scope3066VictimTenant,
		ConnectorName: "postgres",
		Statement:     "rte3066_victim_marker",
	}, h)

	// http.Header.Add canonicalizes on the way in, so this arrives as
	// X-Tenant-Id and selects the strict branch; with no X-Org-ID it is a
	// half-stamped request and fails closed.
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body: %s)", rr.Code, rr.Body.String())
	}
	assertNoVictimDisclosure(t, rr)
}

// ---------------------------------------------------------------------------
// The internal-service plane must keep working
// ---------------------------------------------------------------------------

// TestMCP3066_InternalServicePlaneIsUnchanged is the production-safety
// assertion. The agent's own PEP (platform/agent/mcp_handler.go
// evaluateInputPolicies -> shared/policy.DynamicPolicyEvaluator.Evaluate)
// sends Content-Type, X-Request-Source and the HMAC proxy-auth token and NO
// tenancy headers; its body tenant is the agent's own validated credential.
//
// A blanket 401 on the header-less plane would have hard-BLOCKED every
// governed MCP tool call, because EvaluateWithGracefulDegradation refuses to
// absorb a 401/403 (#3068). This test is what stops that being "fixed" in.
func TestMCP3066_InternalServicePlaneIsUnchanged(t *testing.T) {
	rr := post3066(t, scope3066Policies(), scope3066Request{
		TenantID:      scope3066VictimTenant,
		ConnectorName: "postgres",
		Statement:     "SELECT * FROM kyc WHERE note='rte3066_victim_marker'",
	}, http.Header{}) // no tenancy headers — the in-process PEP shape

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the agent PEP plane must keep evaluating (body: %s)",
			rr.Code, rr.Body.String())
	}
	resp := decode3066(t, rr)
	if resp.Allowed {
		t.Errorf("allowed = true, want false — the tenant's own policy must still enforce on the PEP plane")
	}
	if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0].PolicyID != scope3066VictimPolicyID {
		t.Errorf("matched_policies = %+v, want the body tenant's own policy", resp.MatchedPolicies)
	}
}

// TestMCP3066_InternalServicePlaneStillRequiresATenant: the header-less plane
// keeps its original 400 rather than acquiring a silent unscoped read.
func TestMCP3066_InternalServicePlaneStillRequiresATenant(t *testing.T) {
	for _, tenant := range []string{"", "   "} {
		rr := post3066(t, scope3066Policies(), scope3066Request{
			TenantID:      tenant,
			ConnectorName: "postgres",
		}, http.Header{})

		if rr.Code != http.StatusBadRequest {
			t.Errorf("tenant_id=%q: status = %d, want 400 (body: %s)", tenant, rr.Code, rr.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// The assumption the header-less branch rests on
// ---------------------------------------------------------------------------

// TestMCP3066_RouteIsCoveredByTheInternalProxyAuthGate pins the guarantee that
// makes the header-less branch safe: only a holder of
// AXONFLOW_INTERNAL_SERVICE_SECRET can reach this handler without stamped
// tenancy. If the route ever acquired an exemption from requireInternalProxyAuth
// (#3068), the header-less branch would become tenant-selectable and the fix
// above would be worth nothing.
//
// This is a WIRING assertion, not a middleware unit test: it builds the served
// handler the way Run() does, through buildOrchestratorHandler.
func TestMCP3066_RouteIsCoveredByTheInternalProxyAuthGate(t *testing.T) {
	const path = "/api/v1/mcp/evaluate-policies"

	// The exemption set is matched by exact string equality, so pin the exact
	// path plus the spellings a careless edit might add.
	for _, spelling := range []string{
		path,
		"/api/v1/mcp",
		"/api/v1/mcp/",
		"/api/v1/mcp/evaluate-policies/",
	} {
		if _, exempt := orchestratorAuthExemptPaths[spelling]; exempt {
			t.Fatalf("%q is exempt from requireInternalProxyAuth — the header-less "+
				"evaluation branch in resolveEvaluationScope is only safe while it is not", spelling)
		}
	}

	engine := newTestEngine(scope3066Policies())
	defer engine.Close()

	r := mux.NewRouter()
	NewMCPDynamicPolicyHandler(engine).RegisterRoutes(r)
	handler := buildOrchestratorHandler(cors.New(cors.Options{AllowedOrigins: []string{"*"}}), r)

	// DELIBERATELY UNARMED: this probe must NOT carry a proxy-auth token. Its
	// whole point is that a token-less caller is refused; handing it a
	// credential would invert the property
	// ([[feedback_mechanical_sweep_must_skip_negative_auth_tests]]).
	body, err := json.Marshal(scope3066Request{
		TenantID:      scope3066VictimTenant,
		ConnectorName: "postgres",
		Statement:     "rte3066_victim_marker",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("token-less POST %s: status = %d, want 403 from requireInternalProxyAuth (body: %s)",
			path, rr.Code, rr.Body.String())
	}
	assertNoVictimDisclosure(t, rr)
}

// ---------------------------------------------------------------------------
// Direct unit coverage for the fields the HTTP response cannot show
// ---------------------------------------------------------------------------

// TestMCP3066_ResolveEvaluationScopeStampsOrganizationID: organization_id is
// not echoed in the response, so this is the only place the overwrite is
// observable. A future consumer added below the resolver must inherit the
// authenticated org, never the body's.
func TestMCP3066_ResolveEvaluationScopeStampsOrganizationID(t *testing.T) {
	h := &MCPDynamicPolicyHandler{}

	req := MCPPolicyEvaluationRequest{
		TenantID:       scope3066AttackerTenant,
		OrganizationID: scope3066VictimOrg, // forged
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/evaluate-policies", nil)
	httpReq.Header = stamped(scope3066AttackerTenant, scope3066AttackerOrg)

	if status, msg := h.resolveEvaluationScope(httpReq, &req); status != 0 {
		t.Fatalf("resolveEvaluationScope = (%d, %q), want success", status, msg)
	}
	if req.OrganizationID != scope3066AttackerOrg {
		t.Errorf("OrganizationID = %q, want the authenticated org %q", req.OrganizationID, scope3066AttackerOrg)
	}
	if req.TenantID != scope3066AttackerTenant {
		t.Errorf("TenantID = %q, want %q", req.TenantID, scope3066AttackerTenant)
	}
}

// TestMCP3066_CarriesStampedTenancyReadsPresenceNotValue pins the distinction
// the whole fix turns on. r.Header.Get would collapse "stamped empty" into
// "absent" and hand a stamped-but-empty request the permissive branch.
func TestMCP3066_CarriesStampedTenancyReadsPresenceNotValue(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(*http.Request)
		want  bool
	}{
		{"no headers", func(*http.Request) {}, false},
		{"only unrelated headers", func(r *http.Request) { r.Header.Set("X-Request-Source", "mcp-agent") }, false},
		{"tenant stamped empty", func(r *http.Request) { r.Header.Set("X-Tenant-ID", "") }, true},
		{"org stamped empty", func(r *http.Request) { r.Header.Set("X-Org-ID", "") }, true},
		{"both stamped", func(r *http.Request) {
			r.Header.Set("X-Tenant-ID", scope3066AttackerTenant)
			r.Header.Set("X-Org-ID", scope3066AttackerOrg)
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/evaluate-policies", nil)
			tc.build(r)
			if got := carriesStampedTenancy(r); got != tc.want {
				t.Errorf("carriesStampedTenancy = %v, want %v", got, tc.want)
			}
		})
	}
}
