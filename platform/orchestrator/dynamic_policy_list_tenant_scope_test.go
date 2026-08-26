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
// scope (fail closed, 401) and returns only ListActivePoliciesForTenant.
//
// Decision 5 (#3490) changed that scope from the gateway-stamped X-Tenant-ID
// to the gateway-stamped X-Org-ID, because X-Tenant-ID carries the
// Basic-auth USERNAME and the caller picks it. The disclosure assertions
// below are unchanged in kind; what changed is that the seeded rows now carry
// an org_id and the caller is identified by one.
//
// Style follows platform/agent/static_policy_tenant_isolation_test.go: seed
// two orgs plus the shared sentinels, drive the handler as org A, and
// assert on the OWNING tenant_id of every returned row — never just counts —
// with an explicit vacuity control proving org B's policy is in the cache.

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
// (policy_id-keyed map, tenancy carried in _metadata). withMetadata=false
// produces the no-_metadata shape, which every real writer (refreshPolicies,
// loadDefaultPolicies) avoids — it now exercises the fail-closed defect
// guard in dbCachedPolicyAppliesToOrg, not a legitimate "applies to
// everyone" shape.
//
// Decision 5 (#3490): the `tenant` argument fills BOTH keys. Every real row
// in the shipped schema carries both columns, and giving the fixture one
// argument keeps the seed honest about the pre-Decision-5 single-tenant
// collapse. The tests that need them to DIVERGE - which is the whole point
// of the change - build their metadata explicitly instead (see
// TestListDynamicPoliciesHandler_TenantHeaderIsNotConsulted and the org_id
// cases in TestDBCachedPolicyAppliesToOrg_ShapeSemantics).
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
			"org_id":    tenant,
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
	req.Header.Set("X-Org-ID", "tenant-a") // gateway-stamped, from the signed licence payload
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
	// produces; dbCachedPolicyAppliesToOrg now treats it as a defect and
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

// TestDBCachedPolicyAppliesToOrg_ShapeSemantics pins the two cache shapes
// that DynamicPolicy.TenantID cannot distinguish. Collapsing them is what made
// the first cut of this fix list a policy to tenants the evaluator never
// enforces it for.
func TestDBCachedPolicyAppliesToOrg_ShapeSemantics(t *testing.T) {
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
			if got := dbCachedPolicyAppliesToOrg(tc.policyMap, tc.caller, nil, tc.name); got != tc.wantApplies {
				t.Fatalf("dbCachedPolicyAppliesToOrg = %v, want %v (%s)", got, tc.wantApplies, tc.wantRationale)
			}
		})
	}
}

// TestMemPolicyAppliesToTenant_MirrorsEnforcement and
// TestDynamicPolicyEngine_ListActivePoliciesForTenant (#3319: pinned the
// retired in-memory DynamicPolicyEngine's list/enforce parity, and its
// tenant-rule asymmetry with the database engine — no "global"/"default"
// sentinels) were deleted here: that engine no longer exists, there is now
// exactly one engine and one tenant rule, and the asymmetry these tests
// existed to pin is gone with it. dbCachedPolicyAppliesToOrg's own
// sentinel semantics remain covered by TestDBCachedPolicyAppliesToOrg_ShapeSemantics
// above and TestListDynamicPoliciesHandler_TenantScoped below.

// TestListDynamicPoliciesHandler_FailClosedWithoutOrg pins the fail-closed
// contract: when no org can be resolved (no gateway-stamped X-Org-ID
// header), the handler returns 401 and NO policy data - it must never fall
// back to the unscoped deployment-wide list.
func TestListDynamicPoliciesHandler_FailClosedWithoutOrg(t *testing.T) {
	prev := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = prev }()
	engine := newScopeTestDBEngine()
	dynamicPolicyEngine = engine

	// Vacuity control: the cache is non-empty, so "no policy data" below is
	// a real assertion about the handler, not an empty engine.
	if len(engine.ListActivePolicies()) == 0 {
		t.Fatal("vacuity control failed: engine cache is empty")
	}

	req := httptest.NewRequest("GET", "/api/v1/policies/dynamic", nil) // no X-Org-ID
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
	req.Header.Set("X-Org-ID", "tenant-a")
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

// ---------------------------------------------------------------------------
// Decision 5 (#3490) regression pins. Each of these FAILS against the
// pre-Decision-5 code, which is what makes them regression tests rather than
// restatements.
// ---------------------------------------------------------------------------

// mkScopeTestPolicyDivergent builds a cache entry whose tenant_id and org_id
// DIFFER - the shape a multi-tenant org actually produces, and the shape the
// single-argument mkScopeTestPolicy above cannot express.
func mkScopeTestPolicyDivergent(id, name, tenant, org, conditionRegex string) map[string]interface{} {
	p := mkScopeTestPolicy(id, name, tenant, conditionRegex, true)
	p["_metadata"].(map[string]interface{})["org_id"] = org
	return p
}

// TestListDynamicPoliciesHandler_TenantHeaderIsNotConsulted is the disclosure
// half of the forgery closure. Pre-Decision-5 a caller chose its policy set by
// choosing its Basic-auth username, which the agent forwards verbatim as
// X-Tenant-ID; measured on a live stack, three usernames on ONE licence
// selected three different dynamic policy sets and a username no policy named
// was governed by none of them.
//
// Here the caller sends an X-Tenant-ID naming a DIFFERENT tenant than the one
// its own policy is stamped with, plus its real X-Org-ID. It must receive its
// ORG's set regardless - the tenant header must not move a single row either
// way. Against the old handler the same request returned the OTHER tenant's
// policy and not its own, so this test fails there in both directions.
func TestListDynamicPoliciesHandler_TenantHeaderIsNotConsulted(t *testing.T) {
	prev := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = prev }()

	engine := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{
			// Both rows belong to org-a; they differ only in the tenant that
			// authored them. Post-Decision-5 both govern every caller in org-a.
			"pol-alpha": mkScopeTestPolicyDivergent("pol-alpha", "alpha-authored", "alpha", "org-a", "aaa"),
			"pol-beta":  mkScopeTestPolicyDivergent("pol-beta", "beta-authored", "beta", "org-a", "bbb"),
			// A different org's row, to keep the org boundary non-vacuous.
			"pol-other": mkScopeTestPolicyDivergent("pol-other", "other-org", "gamma", "org-b", "ccc"),
		},
	}
	dynamicPolicyEngine = engine

	for _, tenantHeader := range []string{"alpha", "beta", "a-name-no-policy-targets", ""} {
		t.Run("X-Tenant-ID="+tenantHeader, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/policies/dynamic", nil)
			req.Header.Set("X-Org-ID", "org-a")
			if tenantHeader != "" {
				req.Header.Set("X-Tenant-ID", tenantHeader)
			}
			w := httptest.NewRecorder()
			listDynamicPoliciesHandler(w, req)

			if w.Code != 200 {
				t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
			}
			var got []DynamicPolicy
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			ids := map[string]bool{}
			for _, p := range got {
				ids[p.ID] = true
			}
			// Both of org-a's rows, whichever tenant authored them.
			for _, want := range []string{"pol-alpha", "pol-beta"} {
				if !ids[want] {
					t.Errorf("X-Tenant-ID=%q changed the result: missing %s (the tenant header must not select)", tenantHeader, want)
				}
			}
			// And nothing from org-b.
			if ids["pol-other"] {
				t.Errorf("X-Tenant-ID=%q leaked org-b's policy into org-a's list", tenantHeader)
			}
			if len(got) != 2 {
				t.Errorf("got %d policies, want exactly 2 (org-a's pair): %+v", len(got), got)
			}
		})
	}
}

// TestDBCachedPolicyAppliesToOrg_Decision5Shapes pins the three shapes the
// org-keyed gate introduces, each of which the tenant-keyed gate got wrong.
func TestDBCachedPolicyAppliesToOrg_Decision5Shapes(t *testing.T) {
	// A row carrying _metadata but NO org_id: a writer that predates or
	// forgot Decision 5. Admitting it would apply one org's policy to every
	// org, through a cache deliberately loaded ALL-TENANTS on a BYPASSRLS
	// pool. Same class, and same answer, as the absent-_metadata guard.
	//
	// The metadata map is built imperatively rather than as a literal on
	// purpose: this fixture's WHOLE value is the ABSENCE of org_id, and the
	// bulk fixture migration that added org_id alongside tenant_id across
	// this package's literals silently added one here too, turning the
	// assertion below into a tautology. It failed, which is how that was
	// caught -- but a negative fixture that a text transform can quietly
	// satisfy should not be written as the same shape the transform targets.
	noOrgMeta := map[string]interface{}{"priority": 1}
	noOrgMeta["tenant_id"] = "org-a"
	noOrg := map[string]interface{}{
		"name":      "legacy-writer",
		"policy_id": "p",
		"_metadata": noOrgMeta,
	}
	if _, present := noOrgMeta["org_id"]; present {
		t.Fatal("fixture invariant broken: this entry must NOT carry org_id, or the assertion below cannot fail")
	}
	if dbCachedPolicyAppliesToOrg(noOrg, "org-a", nil, "no-org") {
		t.Error("a cache entry with no org_id must be excluded (fail-closed), not matched on its tenant_id")
	}

	// An UNBOUND caller against a row whose org_id is likewise empty. This is
	// the #3065 fail-open idiom - empty matching empty - in the one place a
	// single match decides enforcement for a whole plane.
	emptyOrg := mkScopeTestPolicyDivergent("p", "p", "t", "", "x")
	if dbCachedPolicyAppliesToOrg(emptyOrg, "", nil, "empty-both") {
		t.Error("an unbound caller must not match a row with an empty org_id (empty-matches-empty is the #3065 fail-open idiom)")
	}

	// An unbound caller still gets the shared baseline: 'global' and
	// 'default' are deployment-wide by construction, and excluding them would
	// leave a caller with no org governed by nothing at all.
	for _, sentinel := range []string{"global", "default"} {
		row := mkScopeTestPolicyDivergent("p", "p", "t", sentinel, "x")
		if !dbCachedPolicyAppliesToOrg(row, "", nil, "unbound-"+sentinel) {
			t.Errorf("an unbound caller must still be governed by the %q baseline", sentinel)
		}
	}

	// The row's TENANT is irrelevant once the org matches - the whole point.
	divergent := mkScopeTestPolicyDivergent("p", "p", "some-other-tenant", "org-a", "x")
	if !dbCachedPolicyAppliesToOrg(divergent, "org-a", nil, "divergent") {
		t.Error("a row authored by a sibling tenant of the caller's org must apply; tenant_id no longer selects")
	}
	if dbCachedPolicyAppliesToOrg(divergent, "some-other-tenant", nil, "tenant-as-org") {
		t.Error("passing the row's TENANT id as the caller org must not match: the gate reads org_id only")
	}
}
