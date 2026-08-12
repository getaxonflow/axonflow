// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Regression tests for the GET /api/v1/policies/dynamic cross-tenant
// information-disclosure fix: listDynamicPoliciesHandler used to return the
// orchestrator's DEPLOYMENT-WIDE in-memory dynamic-policy cache verbatim —
// every tenant's policy id, name, priority, owning tenant_id, and full
// conditions (regex patterns) and actions — to ANY authenticated tenant
// (confirmed live: a brand-new tenant with zero policies of its own received
// 33 policies across 11 tenant_ids). The handler now resolves the caller
// tenant from the gateway-stamped X-Tenant-ID (fail closed, 401) and returns
// only ListActivePoliciesForTenant.
//
// Style follows platform/agent/static_policy_tenant_isolation_test.go: seed
// two tenants plus the shared sentinels, drive the handler as tenant A, and
// assert on the OWNING tenant_id of every returned row — never just counts —
// with an explicit vacuity control proving tenant B's policy is in the cache.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/agent/license"
)

const (
	scopeTestTenantBPolicyID = "pol-tenant-b-secret"
	// A distinctive condition value that must NEVER appear in a response
	// served to tenant A — tenant B's policy conditions are proprietary
	// (regex patterns encode what the tenant screens for).
	scopeTestTenantBRegex = "confidential-tenant-b-pattern-[0-9]{9}"
	// The condition on the _metadata-present-but-EMPTY-tenant row. That shape
	// is enforced for NOBODY, so it must be listed to nobody either.
	scopeTestEmptyTenantRegex = "empty-tenant-pattern-[0-9]{9}"
)

// mkScopeTestPolicy builds a cache entry the way refreshPolicies stores rows
// (policy_id-keyed map, tenant carried in _metadata). withMetadata=false
// produces the no-_metadata shape, which every real writer (refreshPolicies,
// loadDefaultPolicies) avoids — it now exercises the fail-closed defect
// guard in dbCachedPolicyAppliesToTenant, not a legitimate "applies to
// everyone" shape.
func mkScopeTestPolicy(id, name, tenant, conditionRegex string, withMetadata bool) map[string]interface{} {
	p := map[string]interface{}{
		"name":       name,
		"policy_id":  id,
		"type":       "content",
		"category":   "content_safety",
		"conditions": json.RawMessage(`[{"type":"content","operator":"regex","value":"` + conditionRegex + `"}]`),
		"actions":    json.RawMessage(`[{"type":"block"}]`),
	}
	if withMetadata {
		p["_metadata"] = map[string]interface{}{
			"priority":  10,
			"tenant_id": tenant,
		}
	}
	return p
}

// newScopeTestDBEngine seeds a DatabaseDynamicPolicyEngine cache covering
// every shape that matters: tenant-a, tenant-b (x2), "global", "default" (the
// NULL-tenant sentinel refreshPolicies assigns), a row whose _metadata carries
// an EMPTY tenant_id (enforced for nobody), and a row with no _metadata at
// all — no real writer produces this, so it now pins the fail-closed defect
// guard (enforced for nobody, same as the empty-tenant row, but for a
// different reason: a missing writer contract rather than an explicit
// nobody-scoped policy).
//
// The last two shapes are both cases DynamicPolicy.TenantID cannot tell
// apart — both serialize as "" — which is why list/enforce parity is
// asserted over the raw cache entries, not the converted structs.
func newScopeTestDBEngine() *DatabaseDynamicPolicyEngine {
	return &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{
			"pol-tenant-a":           mkScopeTestPolicy("pol-tenant-a", "tenant-a-policy", "tenant-a", "aaa", true),
			scopeTestTenantBPolicyID: mkScopeTestPolicy(scopeTestTenantBPolicyID, "tenant-b-policy", "tenant-b", scopeTestTenantBRegex, true),
			"pol-global":             mkScopeTestPolicy("pol-global", "global-baseline", "global", "ggg", true),
			"pol-default":            mkScopeTestPolicy("pol-default", "null-tenant-policy", "default", "ddd", true),
			"pol-empty-tenant":       mkScopeTestPolicy("pol-empty-tenant", "empty-tenant-policy", "", scopeTestEmptyTenantRegex, true),
			"pol-no-metadata":        mkScopeTestPolicy("pol-no-metadata", "legacy-no-metadata", "", "lll", false),
			"pol-tenant-b-second":    mkScopeTestPolicy("pol-tenant-b-second", "tenant-b-second", "tenant-b", "bbb2", true),
		},
	}
}

// TestListDynamicPoliciesHandler_TenantScoped drives the real handler as
// tenant A against a cache seeded with tenant A, tenant B, global, default and
// metadata-less policies, and asserts on the owning tenant_id of every row:
// tenant A's own + the shared sentinels come back, ZERO rows owned by tenant B.
func TestListDynamicPoliciesHandler_TenantScoped(t *testing.T) {
	prev := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = prev }()
	engine := newScopeTestDBEngine()
	dynamicPolicyEngine = engine

	// VACUITY CONTROL: tenant B's policy must be IN the deployment-wide
	// cache — otherwise its absence from the response below proves nothing.
	// This is also exactly what the pre-fix handler returned, so this test
	// fails against the old unscoped behavior (the old handler encoded
	// ListActivePolicies() verbatim, tenant-b rows included).
	rawHasTenantB := false
	for _, p := range engine.ListActivePolicies() {
		if p.TenantID == "tenant-b" && p.ID == scopeTestTenantBPolicyID {
			rawHasTenantB = true
		}
	}
	if !rawHasTenantB {
		t.Fatal("vacuity control failed: tenant-b policy not present in the raw engine cache; the cross-tenant assertions below would be vacuous")
	}

	req := httptest.NewRequest("GET", "/api/v1/policies/dynamic", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a") // gateway-stamped, from the validated credential
	w := httptest.NewRecorder()

	listDynamicPoliciesHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	var got []DynamicPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Every returned row must be owned by the caller or a shared sentinel.
	// Note "" is NOT in this set: a policy surfaces with TenantID "" when its
	// _metadata carries an empty tenant (enforced for nobody) — the only
	// legitimate "" shape left, now that the no-_metadata shape also fails
	// closed (excluded, not listed at all). Identified by id below.
	allowedOwners := map[string]bool{"tenant-a": true, "global": true, "default": true}
	seenIDs := map[string]bool{}
	for _, p := range got {
		seenIDs[p.ID] = true
		if p.TenantID == "" {
			continue // checked by id below
		}
		if !allowedOwners[p.TenantID] {
			t.Errorf("response leaked a policy owned by tenant_id=%q (id=%s, name=%s) to tenant-a", p.TenantID, p.ID, p.Name)
		}
	}

	// Tenant A's own policy and the shared rows must still be served —
	// scoping must not become "return nothing".
	for _, want := range []string{"pol-tenant-a", "pol-global", "pol-default"} {
		if !seenIDs[want] {
			t.Errorf("response missing expected policy id=%q", want)
		}
	}

	// The _metadata-present-but-empty-tenant row is enforced for NOBODY, so
	// listing it to tenant A would be a disclosure with no matching
	// enforcement — the exact divergence this fix closes.
	if seenIDs["pol-empty-tenant"] {
		t.Error("response contains the empty-tenant policy, which the evaluator enforces for nobody (list/enforce divergence)")
	}

	// The no-_metadata row is not a legitimate shape any real writer
	// produces; dbCachedPolicyAppliesToTenant now treats it as a defect and
	// excludes it (fail-closed), so it must never reach the response either.
	if seenIDs["pol-no-metadata"] {
		t.Error("response contains the no-_metadata policy, which the fail-closed defect guard must exclude from both enforcement and listing")
	}

	if len(got) != 3 {
		t.Errorf("response has %d policies, want 3 (tenant-a + global + default): %+v", len(got), got)
	}

	// Belt and braces on the raw body: neither tenant B's policy id nor its
	// proprietary condition regex may appear anywhere in the payload, nor may
	// the unenforced empty-tenant row's condition or the excluded
	// no-_metadata row's condition.
	body := w.Body.String()
	if strings.Contains(body, scopeTestTenantBPolicyID) || strings.Contains(body, "tenant-b") {
		t.Errorf("raw response body mentions tenant-b: %s", body)
	}
	if strings.Contains(body, scopeTestTenantBRegex) {
		t.Errorf("raw response body leaked tenant-b's condition regex: %s", body)
	}
	if strings.Contains(body, scopeTestEmptyTenantRegex) {
		t.Errorf("raw response body leaked the empty-tenant policy's condition regex: %s", body)
	}
	if strings.Contains(body, "legacy-no-metadata") {
		t.Errorf("raw response body leaked the excluded no-_metadata policy: %s", body)
	}
}

// TestDBCachedPolicyAppliesToTenant_ShapeSemantics pins the two cache shapes
// that DynamicPolicy.TenantID cannot distinguish. Collapsing them is what made
// the first cut of this fix list a policy to tenants the evaluator never
// enforces it for.
func TestDBCachedPolicyAppliesToTenant_ShapeSemantics(t *testing.T) {
	cases := []struct {
		name          string
		policyMap     map[string]interface{}
		caller        string
		wantApplies   bool
		wantRationale string
	}{
		{
			name:          "metadata present, empty tenant → nobody",
			policyMap:     mkScopeTestPolicy("p", "p", "", "x", true),
			caller:        "tenant-a",
			wantApplies:   false,
			wantRationale: "an empty tenant_id in _metadata matches no tenant in the evaluation loop",
		},
		{
			name:          "metadata absent → fail-closed defect guard, nobody",
			policyMap:     mkScopeTestPolicy("p", "p", "", "x", false),
			caller:        "tenant-a",
			wantApplies:   false,
			wantRationale: "every writer (refreshPolicies, loadDefaultPolicies) populates _metadata; an absent one is a defect and is excluded rather than applied to everyone",
		},
		{"metadata present, global", mkScopeTestPolicy("p", "p", "global", "x", true), "tenant-a", true, "global is a shared baseline"},
		{"metadata present, default", mkScopeTestPolicy("p", "p", "default", "x", true), "tenant-a", true, "default is the NULL-tenant sentinel"},
		{"metadata present, exact match", mkScopeTestPolicy("p", "p", "tenant-a", "x", true), "tenant-a", true, "own tenant"},
		{"metadata present, other tenant", mkScopeTestPolicy("p", "p", "tenant-b", "x", true), "tenant-a", false, "another tenant's policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dbCachedPolicyAppliesToTenant(tc.policyMap, tc.caller, nil, tc.name); got != tc.wantApplies {
				t.Fatalf("dbCachedPolicyAppliesToTenant = %v, want %v (%s)", got, tc.wantApplies, tc.wantRationale)
			}
		})
	}
}

// TestMemPolicyAppliesToTenant_MirrorsEnforcement pins the fallback engine's
// predicate, which is deliberately NARROWER than the database engine's: it has
// no "global"/"default" sentinels, because getApplicablePolicies does not
// honour them either. Listing them here would be disclosure without
// enforcement.
func TestMemPolicyAppliesToTenant_MirrorsEnforcement(t *testing.T) {
	cases := []struct {
		policyTenant string
		caller       string
		want         bool
	}{
		{"", "tenant-a", true},          // community-global
		{"tenant-a", "tenant-a", true},  // own
		{"tenant-b", "tenant-a", false}, // other tenant
		{"global", "tenant-a", false},   // NOT a sentinel on this engine
		{"default", "tenant-a", false},  // NOT a sentinel on this engine
	}
	for _, tc := range cases {
		if got := memPolicyAppliesToTenant(tc.policyTenant, tc.caller, "", nil); got != tc.want {
			t.Errorf("memPolicyAppliesToTenant(%q, %q) = %v, want %v", tc.policyTenant, tc.caller, got, tc.want)
		}
	}

	// Parity with enforcement, driven through the real engine: whatever
	// getApplicablePolicies would evaluate is exactly what the scoped list
	// returns.
	engine := newTestEngine([]DynamicPolicy{
		{ID: "own", TenantID: "tenant-a", Enabled: true},
		{ID: "other", TenantID: "tenant-b", Enabled: true},
		{ID: "empty", TenantID: "", Enabled: true},
		{ID: "global", TenantID: "global", Enabled: true},
	})
	defer engine.Close()

	enforced := map[string]bool{}
	for _, p := range engine.getApplicablePolicies(OrchestratorRequest{
		User: UserContext{TenantID: "tenant-a"},
	}, nil) {
		enforced[p.ID] = true
	}
	listed := map[string]bool{}
	for _, p := range engine.ListActivePoliciesForTenant("tenant-a", nil) {
		listed[p.ID] = true
	}
	for _, id := range []string{"own", "other", "empty", "global"} {
		if enforced[id] != listed[id] {
			t.Errorf("list/enforce divergence for %q: enforced=%v listed=%v", id, enforced[id], listed[id])
		}
	}
	if len(enforced) == 0 {
		t.Fatal("vacuity control failed: enforcement returned nothing, so parity above is meaningless")
	}
}

// TestListDynamicPoliciesHandler_FailClosedWithoutTenant pins the fail-closed
// contract: when no tenant can be resolved (no gateway-stamped X-Tenant-ID
// header, no context value), the handler returns 401 and NO policy data — it
// must never fall back to the unscoped deployment-wide list.
func TestListDynamicPoliciesHandler_FailClosedWithoutTenant(t *testing.T) {
	prev := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = prev }()
	engine := newScopeTestDBEngine()
	dynamicPolicyEngine = engine

	// Vacuity control: the cache is non-empty, so "no policy data" below is
	// a real assertion about the handler, not an empty engine.
	if len(engine.ListActivePolicies()) == 0 {
		t.Fatal("vacuity control failed: engine cache is empty")
	}

	req := httptest.NewRequest("GET", "/api/v1/policies/dynamic", nil) // no X-Tenant-ID
	w := httptest.NewRecorder()

	listDynamicPoliciesHandler(w, req)

	if w.Code != 401 {
		t.Fatalf("status = %d, want 401 (fail closed): %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, leak := range []string{"pol-tenant-a", scopeTestTenantBPolicyID, "pol-global", scopeTestTenantBRegex, "conditions"} {
		if strings.Contains(body, leak) {
			t.Errorf("401 response leaked policy data (%q): %s", leak, body)
		}
	}
}

// TestDynamicPolicyEngine_ListActivePoliciesForTenant covers the fallback
// (non-database) engine's scoped list: the caller's own policies and the
// ""-tenant (community-global) ones are in; another tenant's and disabled
// policies are out.
//
// "global"/"default" are deliberately OUT on this engine: getApplicablePolicies
// does not treat them as sentinels, so listing them would be disclosure
// without matching enforcement. That asymmetry with the database engine is
// intentional and is pinned by TestMemPolicyAppliesToTenant_MirrorsEnforcement.
func TestDynamicPolicyEngine_ListActivePoliciesForTenant(t *testing.T) {
	engine := newTestEngine([]DynamicPolicy{
		{ID: "a1", Name: "own", TenantID: "tenant-a", Enabled: true},
		{ID: "b1", Name: "other", TenantID: "tenant-b", Enabled: true},
		{ID: "g1", Name: "global", TenantID: "global", Enabled: true},
		{ID: "d1", Name: "default", TenantID: "default", Enabled: true},
		{ID: "e1", Name: "empty", TenantID: "", Enabled: true},
		{ID: "a2", Name: "own-disabled", TenantID: "tenant-a", Enabled: false},
	})
	defer engine.Close()

	// Vacuity control: the unscoped list DOES carry tenant-b's policy.
	rawHasTenantB := false
	for _, p := range engine.ListActivePolicies() {
		if p.TenantID == "tenant-b" {
			rawHasTenantB = true
		}
	}
	if !rawHasTenantB {
		t.Fatal("vacuity control failed: tenant-b policy not in the unscoped list")
	}

	got := engine.ListActivePoliciesForTenant("tenant-a", nil)
	wantIDs := map[string]bool{"a1": true, "e1": true}
	if len(got) != len(wantIDs) {
		t.Fatalf("scoped list has %d policies, want %d: %+v", len(got), len(wantIDs), got)
	}
	for _, p := range got {
		if !wantIDs[p.ID] {
			t.Errorf("scoped list leaked unexpected policy id=%s tenant_id=%q", p.ID, p.TenantID)
		}
		if p.TenantID == "tenant-b" {
			t.Errorf("scoped list leaked tenant-b policy id=%s", p.ID)
		}
	}
}

// TestSimulatePolicies_TotalPoliciesScopedToTenant pins that the simulate
// response's total_policies counts only the CALLER's visible policies. It
// previously counted len(ListActivePolicies()) — the deployment-wide cache —
// leaking the total number of policies across all tenants in every
// /api/v1/policies/simulate response.
func TestSimulatePolicies_TotalPoliciesScopedToTenant(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxSimsPerDay:    300,
	}
	engine := &mockPolicyEngineForSim{activePolicies: []DynamicPolicy{
		{ID: "a1", TenantID: "tenant-a", Enabled: true},
		{ID: "a2", TenantID: "tenant-a", Enabled: true},
		{ID: "g1", TenantID: "global", Enabled: true},
		{ID: "b1", TenantID: "tenant-b", Enabled: true},
		{ID: "b2", TenantID: "tenant-b", Enabled: true},
		{ID: "b3", TenantID: "tenant-b", Enabled: true},
	}}
	handler := NewPolicySimulationHandler(engine, nil, nil, checker)
	handler.rateLimiter = &simulationRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body := []byte(`{"query":"hello","request_type":"chat"}`)
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", strings.NewReader(string(body)))
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp SimulatePoliciesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	// 2 own + 1 global = 3. The old behavior returned 6 (the whole
	// deployment), so this fails against the unscoped count.
	if resp.TotalPolicies != 3 {
		t.Errorf("total_policies = %d, want 3 (tenant-a's 2 + global; the deployment-wide cache holds 6)", resp.TotalPolicies)
	}
}
