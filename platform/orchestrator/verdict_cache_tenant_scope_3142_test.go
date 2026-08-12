// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3142 — the DynamicPolicyEngine verdict cache is a single process-global
// sync.Map shared by every tenant in the deployment. Its key carried no
// tenancy, so a verdict computed for one tenant was served to another:
//
//   - DISCLOSURE — the second tenant received the first tenant's
//     AppliedPoliciesDetail: policy_id, policy_name, description, action,
//     risk_level.
//   - GOVERNANCE BYPASS — if the first tenant's verdict was `allowed`, the
//     second tenant's own blocking policy never ran. A deny control silently
//     skipped for any query another tenant had already issued.
//   - CROSS-TENANT MUTATION — the cache returned the stored POINTER, and
//     ApplyOverrideToResult mutates a verdict in place, so one tenant's
//     ADR-044 session override was written into the entry every later reader
//     of any tenancy consumed.
//
// Every test here fails on the pre-fix engine; see the PR body for the
// pre-fix run. Each one also carries a vacuity control, because a cache that
// simply stopped caching would pass the isolation assertions while doing
// nothing the feature exists for.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// newVerdictCacheTestEngine builds an engine with no database, holding exactly
// the supplied policies.
func newVerdictCacheTestEngine(t *testing.T, policies []DynamicPolicy) *DynamicPolicyEngine {
	t.Helper()
	e := &DynamicPolicyEngine{
		policies:       policies,
		riskCalculator: NewRiskCalculator(),
		cache:          NewPolicyCache(5 * time.Minute),
		stopCh:         make(chan struct{}),
	}
	t.Cleanup(e.Close)
	return e
}

// blockPolicyFor returns a policy owned by tenantID that blocks any query
// containing "kyc".
func blockPolicyFor(tenantID string) DynamicPolicy {
	return DynamicPolicy{
		ID:          "pol-victim-control-" + tenantID,
		Name:        "Victim KYC exfiltration control (" + tenantID + ")",
		Description: "blocks KYC extraction for " + tenantID,
		Type:        "content",
		Conditions:  []PolicyCondition{{Field: "query", Operator: "contains", Value: "kyc"}},
		Actions:     []PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "kyc exfiltration"}}},
		Enabled:     true,
		TenantID:    tenantID,
		RiskLevel:   "medium",
	}
}

// reqFor builds two byte-identical requests that differ ONLY in tenancy. The
// user fields are left empty on purpose: that is the shape the agent's
// governed forward produces for every caller without a per-user token, and it
// is what collapsed the old key to `::<request_type>:<query>`.
func reqFor(orgID, tenantID string) OrchestratorRequest {
	return OrchestratorRequest{
		RequestType: "query",
		Query:       "export all kyc records",
		User: UserContext{
			OrgID:    orgID,
			TenantID: tenantID,
		},
	}
}

// TestVerdictCacheDoesNotServeAnotherTenantsVerdict is the governance-bypass
// half: tenant A has no policies, tenant B blocks the query. Whichever runs
// first must not decide the other.
func TestVerdictCacheDoesNotServeAnotherTenantsVerdict(t *testing.T) {
	ctx := context.Background()

	for _, order := range []struct {
		name  string
		first string // tenant evaluated first
	}{
		{"allowed_tenant_first", "tenant-a"},
		{"blocked_tenant_first", "tenant-b"},
	} {
		t.Run(order.name, func(t *testing.T) {
			e := newVerdictCacheTestEngine(t, []DynamicPolicy{blockPolicyFor("tenant-b")})

			reqA := reqFor("org-a", "tenant-a")
			reqB := reqFor("org-b", "tenant-b")

			if order.first == "tenant-b" {
				_ = e.EvaluateDynamicPolicies(ctx, reqB)
			} else {
				_ = e.EvaluateDynamicPolicies(ctx, reqA)
			}

			resA := e.EvaluateDynamicPolicies(ctx, reqA)
			resB := e.EvaluateDynamicPolicies(ctx, reqB)

			// Vacuity control: tenant B's own policy must actually fire, or
			// "tenant A was allowed" proves nothing.
			if resB.Allowed {
				t.Fatalf("vacuity control failed: tenant-b's own blocking policy did not fire (result %+v)", resB)
			}
			if len(resB.AppliedPoliciesDetail) == 0 {
				t.Fatalf("vacuity control failed: tenant-b matched no policy detail")
			}

			// Governance bypass.
			if !resA.Allowed {
				t.Errorf("tenant-a was BLOCKED by tenant-b's policy through the shared verdict cache: %+v", resA)
			}
			// Disclosure.
			if len(resA.AppliedPolicies) != 0 || len(resA.AppliedPoliciesDetail) != 0 {
				t.Errorf("tenant-a received tenant-b's applied policies: %v / %+v",
					resA.AppliedPolicies, resA.AppliedPoliciesDetail)
			}
		})
	}
}

// TestVerdictCacheIsolatesOrgWithinTheSameTenantID pins the org half of the
// key. OrgID and TenantID legitimately diverge (license org vs customer row),
// so the same tenant string under two orgs must not share an entry.
func TestVerdictCacheIsolatesOrgWithinTheSameTenantID(t *testing.T) {
	ctx := context.Background()
	e := newVerdictCacheTestEngine(t, nil)

	reqOrgA := reqFor("org-a", "shared-tenant-id")
	reqOrgB := reqFor("org-b", "shared-tenant-id")

	keyA := e.generateCacheKey(reqOrgA, nil)
	keyB := e.generateCacheKey(reqOrgB, nil)
	if keyA == keyB {
		t.Fatalf("two orgs sharing a tenant id produced the same cache key: %+v", keyA)
	}

	_ = e.EvaluateDynamicPolicies(ctx, reqOrgA)
	if _, found := e.cache.Get(keyB); found {
		t.Error("org-b hit org-a's cached verdict")
	}
	// Vacuity control: org-a's own entry IS present, so the miss above is
	// about the org and not about the cache being dead.
	if _, found := e.cache.Get(keyA); !found {
		t.Fatal("vacuity control failed: org-a's verdict was never cached, so the org-b miss proves nothing")
	}
}

// TestVerdictCacheKeyMatchesThePolicySelector is the "resolver must match the
// writer" requirement. getApplicablePolicies falls back to Client.ID when
// User.TenantID is empty, so the key must make the same fallback: keying on
// User.TenantID alone would give two DIFFERENT policy sets one shared entry.
func TestVerdictCacheKeyMatchesThePolicySelector(t *testing.T) {
	ctx := context.Background()
	e := newVerdictCacheTestEngine(t, []DynamicPolicy{blockPolicyFor("client-tenant-b")})

	// Neither request carries User.TenantID; the selector uses Client.ID.
	base := OrchestratorRequest{RequestType: "query", Query: "export all kyc records"}
	reqA := base
	reqA.Client = ClientContext{ID: "client-tenant-a"}
	reqB := base
	reqB.Client = ClientContext{ID: "client-tenant-b"}

	if e.generateCacheKey(reqA, nil) == e.generateCacheKey(reqB, nil) {
		t.Fatal("two clients selecting different policy sets produced the same cache key — " +
			"the key resolver disagrees with getApplicablePolicies")
	}

	resB := e.EvaluateDynamicPolicies(ctx, reqB)
	if resB.Allowed {
		t.Fatalf("vacuity control failed: client-tenant-b's policy did not fire (%+v)", resB)
	}
	resA := e.EvaluateDynamicPolicies(ctx, reqA)
	if !resA.Allowed {
		t.Errorf("client-tenant-a was blocked by client-tenant-b's policy: %+v", resA)
	}
}

// TestVerdictCacheReturnsACopy is the in-place-mutation half. The engine hands
// out a verdict; ApplyOverrideToResult and friends mutate it; the next caller
// must not see those mutations.
func TestVerdictCacheReturnsACopy(t *testing.T) {
	ctx := context.Background()
	e := newVerdictCacheTestEngine(t, []DynamicPolicy{blockPolicyFor("tenant-b")})

	req := reqFor("org-b", "tenant-b")

	first := e.EvaluateDynamicPolicies(ctx, req)
	if first.Allowed {
		t.Fatalf("vacuity control failed: the blocking policy did not fire (%+v)", first)
	}
	if len(first.AppliedPolicies) == 0 {
		t.Fatal("vacuity control failed: no applied policies to mutate")
	}

	// Exactly what ApplyOverrideToResult does on an override hit.
	first.Allowed = true
	first.OverrideApplied = true
	first.OverrideID = "ov-attacker"
	first.OverrideReason = "not mine to grant"
	first.AppliedPolicies[0] = "MUTATED"
	if len(first.AppliedPoliciesDetail) > 0 {
		first.AppliedPoliciesDetail[0].PolicyName = "MUTATED"
	}

	second := e.EvaluateDynamicPolicies(ctx, req)
	if second.Allowed {
		t.Error("an in-place override on one caller's verdict flipped the CACHED verdict to allowed for the next caller")
	}
	if second.OverrideApplied || second.OverrideID != "" || second.OverrideReason != "" {
		t.Errorf("override fields leaked into the cached verdict: applied=%v id=%q reason=%q",
			second.OverrideApplied, second.OverrideID, second.OverrideReason)
	}
	if len(second.AppliedPolicies) > 0 && second.AppliedPolicies[0] == "MUTATED" {
		t.Error("AppliedPolicies shares its backing array with the cached entry")
	}
	if len(second.AppliedPoliciesDetail) > 0 && second.AppliedPoliciesDetail[0].PolicyName == "MUTATED" {
		t.Error("AppliedPoliciesDetail shares its backing array with the cached entry")
	}
}

// TestVerdictCacheStillCaches is the standalone vacuity control for the whole
// file: it proves the cache is live, so every isolation assertion above is a
// statement about the KEY rather than about a cache that quietly stopped
// working. A policy added between two identical calls must not be observed,
// because the second call is served from the entry the first one wrote.
func TestVerdictCacheStillCaches(t *testing.T) {
	ctx := context.Background()
	e := newVerdictCacheTestEngine(t, nil)

	req := reqFor("org-a", "tenant-a")

	if res := e.EvaluateDynamicPolicies(ctx, req); !res.Allowed {
		t.Fatalf("baseline: expected allow with no policies, got %+v", res)
	}

	e.policyMutex.Lock()
	e.policies = []DynamicPolicy{blockPolicyFor("tenant-a")}
	e.policyMutex.Unlock()

	if res := e.EvaluateDynamicPolicies(ctx, req); !res.Allowed {
		t.Fatalf("the second identical request re-evaluated instead of hitting the cache — " +
			"the isolation assertions in this file would be vacuous")
	}

	// A different tenancy is a cache MISS, so it does see the new policy.
	other := reqFor("org-a", "tenant-a-different")
	e.policyMutex.Lock()
	e.policies = append(e.policies, blockPolicyFor("tenant-a-different"))
	e.policyMutex.Unlock()
	if res := e.EvaluateDynamicPolicies(ctx, other); res.Allowed {
		t.Errorf("a fresh tenancy was served from the cache instead of evaluating: %+v", res)
	}
}

// TestVerdictCacheKeyCoversEveryEvaluableField pins the key against the set of
// fields getFieldValue can read. A verdict cached under a key that omits one
// of its own inputs is served to a request that would have evaluated
// differently — the cross-tenant defect is one instance of that shape, and
// these are the rest.
func TestVerdictCacheKeyCoversEveryEvaluableField(t *testing.T) {
	e := newVerdictCacheTestEngine(t, nil)

	base := OrchestratorRequest{
		RequestType: "query",
		Query:       "select 1",
		User: UserContext{
			OrgID:       "org-a",
			TenantID:    "tenant-a",
			Email:       "a@example.com",
			Role:        "developer",
			Region:      "eu",
			Permissions: []string{"read"},
		},
		Client:  ClientContext{ID: "client-a", Name: "Client A"},
		Context: map[string]interface{}{"step.gate_count": 1},
	}
	baseKey := e.generateCacheKey(base, nil)

	// This table must cover every field getFieldValue can reach — INCLUDING the
	// three reachable only through its bare-struct fallthrough. Neither inner
	// switch has a default, so a condition on an unrecognised sub-field (say
	// `user.id`, or a bare `client`) returns the WHOLE struct, which
	// evaluateCondition renders with fmt.Sprint. `user.id`, `client.org_id` and
	// `client.tenant_id` are therefore evaluation inputs even though no switch
	// arm names them. An earlier revision of this table enumerated the named
	// arms only and passed while those three were missing from the key.
	mutations := map[string]func(*OrchestratorRequest){
		"query":            func(r *OrchestratorRequest) { r.Query = "select 2" },
		"request_type":     func(r *OrchestratorRequest) { r.RequestType = "workflow" },
		"user.email":       func(r *OrchestratorRequest) { r.User.Email = "b@example.com" },
		"user.role":        func(r *OrchestratorRequest) { r.User.Role = "admin" },
		"user.region":      func(r *OrchestratorRequest) { r.User.Region = "us" },
		"user.tenant_id":   func(r *OrchestratorRequest) { r.User.TenantID = "tenant-b" },
		"user.org_id":      func(r *OrchestratorRequest) { r.User.OrgID = "org-b" },
		"user.permissions": func(r *OrchestratorRequest) { r.User.Permissions = []string{"write"} },
		"client.id":        func(r *OrchestratorRequest) { r.Client.ID = "client-b" },
		"client.name":      func(r *OrchestratorRequest) { r.Client.Name = "Client B" },
		"context":          func(r *OrchestratorRequest) { r.Context = map[string]interface{}{"step.gate_count": 2} },
		// Reachable only via the bare-struct fallthrough:
		"user.id (bare-struct fallthrough)":          func(r *OrchestratorRequest) { r.User.ID = 1337 },
		"client.org_id (bare-struct fallthrough)":    func(r *OrchestratorRequest) { r.Client.OrgID = "org-prod" },
		"client.tenant_id (bare-struct fallthrough)": func(r *OrchestratorRequest) { r.Client.TenantID = "tenant-prod" },
	}

	for field, mutate := range mutations {
		t.Run(field, func(t *testing.T) {
			req := base
			// Copy the reference-typed members so a mutation cannot write
			// through into `base` and corrupt later subtests.
			req.User.Permissions = append([]string(nil), base.User.Permissions...)
			req.Context = map[string]interface{}{"step.gate_count": 1}
			mutate(&req)
			if e.generateCacheKey(req, nil) == baseKey {
				t.Errorf("changing %s did not change the cache key — two requests the evaluator "+
					"would answer differently share one cached verdict", field)
			}
		})
	}
}

// TestVerdictCacheKeyIsFallthroughAware is the same requirement stated as a
// property rather than a table: a bare `client` condition compares against
// fmt.Sprint(req.Client), so ANY field of ClientContext is an evaluation input.
// Asserting on the rendered struct keeps this honest if a field is added later.
func TestVerdictCacheKeyIsFallthroughAware(t *testing.T) {
	e := newVerdictCacheTestEngine(t, nil)
	res := &PolicyEvaluationResult{}

	a := OrchestratorRequest{
		RequestType: "query",
		Query:       "q",
		User:        UserContext{ID: 1, OrgID: "org", TenantID: "tenant"},
		Client:      ClientContext{ID: "c", Name: "C", OrgID: "org-dev", TenantID: "t-dev"},
	}
	b := a
	b.Client.OrgID = "org-prod"

	// Precondition: the evaluator really can tell these two apart.
	if fmt.Sprint(e.getFieldValue("client", a, res)) == fmt.Sprint(e.getFieldValue("client", b, res)) {
		t.Skip("ClientContext no longer renders OrgID — this property needs restating")
	}
	if e.generateCacheKey(a, nil) == e.generateCacheKey(b, nil) {
		t.Error("two requests the evaluator can distinguish through a bare `client` condition share one cache key")
	}

	c := a
	c.User.ID = 99
	if fmt.Sprint(e.getFieldValue("user", a, res)) != fmt.Sprint(e.getFieldValue("user", c, res)) &&
		e.generateCacheKey(a, nil) == e.generateCacheKey(c, nil) {
		t.Error("two requests the evaluator can distinguish through a bare `user` condition share one cache key")
	}
}

// TestClonePreservesEmptyVersusNil pins the wire shape against cache state.
// EvaluateDynamicPolicies initialises AppliedPolicies/RequiredActions to empty
// non-nil slices and neither field carries `omitempty`, so a clone that turned
// empty into nil would render "applied_policies":[] on a cache miss and
// "applied_policies":null on a hit — for the same request. `append(T(nil), ...)`
// with zero elements does exactly that.
func TestClonePreservesEmptyVersusNil(t *testing.T) {
	empty := &PolicyEvaluationResult{
		Allowed:         true,
		AppliedPolicies: []string{},
		RequiredActions: []string{},
	}
	got := cloneEvaluationResult(empty)
	if got.AppliedPolicies == nil {
		t.Error("clone turned an empty AppliedPolicies into nil — the JSON shape would depend on cache state")
	}
	if got.RequiredActions == nil {
		t.Error("clone turned an empty RequiredActions into nil")
	}

	// And nil must stay nil, so an omitempty field is not materialised.
	var nilled PolicyEvaluationResult
	gotNil := cloneEvaluationResult(&nilled)
	if gotNil.AppliedPoliciesDetail != nil || gotNil.AllowedProviders != nil {
		t.Error("clone materialised a nil slice")
	}

	// End to end through the cache, which is where it would actually bite.
	e := newVerdictCacheTestEngine(t, nil)
	req := reqFor("org-a", "tenant-a")
	first := e.EvaluateDynamicPolicies(context.Background(), req)
	second := e.EvaluateDynamicPolicies(context.Background(), req)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal miss result: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal hit result: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Errorf("the same request serialises differently on a cache miss vs a hit:\n  miss: %s\n  hit:  %s", firstJSON, secondJSON)
	}
}

// TestVerdictCacheKeyIsNotForgeableByDelimiterInjection pins the length
// prefixing: no field value may be able to impersonate a different split.
func TestVerdictCacheKeyIsNotForgeableByDelimiterInjection(t *testing.T) {
	e := newVerdictCacheTestEngine(t, nil)

	a := OrchestratorRequest{
		RequestType: "query",
		Query:       "q",
		User:        UserContext{OrgID: "org", TenantID: "tenant", Email: "x|1:", Role: "r"},
	}
	b := a
	b.User.Email = "x"
	b.User.Role = "|1:r"

	if e.generateCacheKey(a, nil) == e.generateCacheKey(b, nil) {
		t.Error("two distinct requests collided by shifting the delimiter between adjacent fields")
	}
}
