// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3052 (ADR-060 #2989 P3b) — segment-awareness for the in-memory
// DynamicPolicyEngine. Mirrors the choke-point/fail-closed/combiner test
// shape platform/agent/segment_policy_combiner_test.go established for P3
// on the agent static plane.

import (
	"context"
	"errors"
	"testing"
)

// TestMemPolicyAppliesToTenant_SegmentMatrix is the choke-point
// applies/doesn't-apply matrix (DoD item): every combination of tenant
// match/mismatch crossed with segment match/mismatch/absent, pinned against
// the SINGLE predicate both getApplicablePolicies (enforcement) and
// ListActivePoliciesForTenant (disclosure) call.
func TestMemPolicyAppliesToTenant_SegmentMatrix(t *testing.T) {
	cases := []struct {
		name           string
		policyTenant   string
		callerTenant   string
		policySegment  string
		callerSegments []string
		want           bool
	}{
		{"no tenant, no segment: applies to all", "", "tenant-a", "", nil, true},
		{"own tenant, no segment: applies", "tenant-a", "tenant-a", "", nil, true},
		{"other tenant, no segment: excluded", "tenant-b", "tenant-a", "", nil, false},

		{"no tenant, matching segment: applies", "", "tenant-a", "seg-finance", []string{"seg-finance"}, true},
		{"no tenant, segment set but caller has none: excluded", "", "tenant-a", "seg-finance", nil, false},
		{"no tenant, wrong segment: excluded", "", "tenant-a", "seg-finance", []string{"seg-engineering"}, false},
		{"no tenant, caller in multiple incl. match: applies", "", "tenant-a", "seg-finance", []string{"seg-engineering", "seg-finance"}, true},

		{"own tenant + matching segment: applies", "tenant-a", "tenant-a", "seg-finance", []string{"seg-finance"}, true},
		{"own tenant but caller lacks segment: excluded", "tenant-a", "tenant-a", "seg-finance", nil, false},
		{"own tenant + wrong segment: excluded", "tenant-a", "tenant-a", "seg-finance", []string{"seg-engineering"}, false},

		// Tenant mismatch short-circuits regardless of segment membership —
		// segment can only ADD restriction, never bypass the tenant gate.
		{"other tenant + matching segment: still excluded (tenant gate first)", "tenant-b", "tenant-a", "seg-finance", []string{"seg-finance"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := memPolicyAppliesToTenant(tc.policyTenant, tc.callerTenant, tc.policySegment, tc.callerSegments)
			if got != tc.want {
				t.Errorf("memPolicyAppliesToTenant(%q, %q, %q, %v) = %v, want %v",
					tc.policyTenant, tc.callerTenant, tc.policySegment, tc.callerSegments, got, tc.want)
			}
		})
	}
}

// TestGetApplicablePolicies_ThreadsCallerSegments proves getApplicablePolicies
// actually uses the callerSegments parameter (not just that the predicate
// function is correct in isolation): a segment-scoped policy is selected iff
// the passed-in segment set contains it.
func TestGetApplicablePolicies_ThreadsCallerSegments(t *testing.T) {
	engine := newTestEngine([]DynamicPolicy{
		{ID: "tier", TenantID: "tenant-a", Enabled: true},
		{ID: "seg-finance", TenantID: "tenant-a", SegmentID: "seg-finance", Enabled: true},
		{ID: "seg-eng", TenantID: "tenant-a", SegmentID: "seg-engineering", Enabled: true},
	})
	defer engine.Close()

	req := OrchestratorRequest{User: UserContext{TenantID: "tenant-a"}}

	none := map[string]bool{}
	for _, p := range engine.getApplicablePolicies(req, nil) {
		none[p.ID] = true
	}
	if none["seg-finance"] || none["seg-eng"] {
		t.Fatalf("nil callerSegments must exclude every segment-scoped policy, got %v", none)
	}
	if !none["tier"] {
		t.Fatalf("nil callerSegments must still include the non-segment-scoped policy, got %v", none)
	}

	finance := map[string]bool{}
	for _, p := range engine.getApplicablePolicies(req, []string{"seg-finance"}) {
		finance[p.ID] = true
	}
	if !finance["seg-finance"] {
		t.Fatalf("caller in seg-finance must see the seg-finance policy, got %v", finance)
	}
	if finance["seg-eng"] {
		t.Fatalf("caller in seg-finance must NOT see the seg-engineering policy, got %v", finance)
	}
	if !finance["tier"] {
		t.Fatalf("caller in seg-finance must still see the non-segment-scoped policy, got %v", finance)
	}
}

// TestEvaluateDynamicPolicies_FailClosedOnResolveError is the ADR-060
// §Fail-closed DoD item: a genuine resolver error must deny the whole
// request, never silently proceed org-only.
func TestEvaluateDynamicPolicies_FailClosedOnResolveError(t *testing.T) {
	engine := newTestEngine([]DynamicPolicy{
		{ID: "harmless", Enabled: true, Actions: []PolicyAction{{Type: "log"}}},
	})
	defer engine.Close()
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{err: errors.New("scim query failed")})

	req := OrchestratorRequest{
		Query: "hello",
		User:  UserContext{OrgID: "org-a", Email: "alice@example.com", TenantID: "tenant-a"},
	}
	result := engine.EvaluateDynamicPolicies(context.Background(), req)
	if result.Allowed {
		t.Fatal("a segment resolution error must deny the request (fail-closed, ADR-060 §Fail-closed), got Allowed=true")
	}
	// S1 (#3239 round 2): the typed availability signal, not the old magic
	// string, is how a consumer tells this apart from a real policy block.
	if !result.EvaluationError {
		t.Fatal("expected EvaluationError=true for a segment resolution failure (S1), got false")
	}
	for _, p := range result.AppliedPolicies {
		if p == "segment_resolution_failed" {
			t.Fatal("expected the magic string to be gone from AppliedPolicies now that EvaluationError carries this signal")
		}
	}
}

// TestEvaluateDynamicPolicies_NilResolver_OrgOnly_NoRegression pins
// zero-behavior-change: no resolver wired (community build, or Enterprise
// without SCIM configured) must behave EXACTLY like a caller with zero
// resolved segments — not a failure.
func TestEvaluateDynamicPolicies_NilResolver_OrgOnly_NoRegression(t *testing.T) {
	ResetOrchestratorSegmentResolverForTest()
	engine := newTestEngine([]DynamicPolicy{
		{
			ID:         "tier-allow",
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "hello"}},
			Actions:    []PolicyAction{{Type: "log"}},
			Enabled:    true,
		},
	})
	defer engine.Close()

	req := OrchestratorRequest{
		Query: "hello world",
		User:  UserContext{OrgID: "org-a", Email: "alice@example.com", TenantID: "tenant-a"},
	}
	result := engine.EvaluateDynamicPolicies(context.Background(), req)
	if !result.Allowed {
		t.Fatalf("no resolver wired must never deny — expected org-only, got blocked: %+v", result)
	}
}

// TestEvaluateDynamicPolicies_SegmentAdditiveRestrictionOnly is the
// combiner DoD item (ADR-060 Decision 1): a segment-scoped block policy
// tightens the outcome for a member of that segment, and a non-member (or
// an org with no segment policies) sees zero behavior change. Because this
// engine's evaluation loop already aggregates OR-across-matches (Allowed
// goes false the moment ANY applicable policy blocks), folding
// segment-matched policies into the SAME applicable set is what makes
// segment membership able to only ADD a match, never remove one — see
// getApplicablePolicies' doc.
func TestEvaluateDynamicPolicies_SegmentAdditiveRestrictionOnly(t *testing.T) {
	engine := newTestEngine([]DynamicPolicy{
		// Tier-level policy: logs but never blocks.
		{
			ID:         "tier-log",
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "kyc"}},
			Actions:    []PolicyAction{{Type: "log"}},
			Enabled:    true,
			RiskLevel:  "low",
		},
		segmentBlockPolicyFor("seg-finance"),
	})
	defer engine.Close()

	member := OrchestratorRequest{
		Query: "export all kyc records",
		User:  UserContext{OrgID: "org-shared", Email: "alice@example.com"},
	}
	nonMember := OrchestratorRequest{
		Query: "export all kyc records",
		User:  UserContext{OrgID: "org-shared", Email: "bob@example.com"},
	}

	withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))
	memberResult := engine.EvaluateDynamicPolicies(context.Background(), member)
	if memberResult.Allowed {
		t.Fatal("a seg-finance member must be blocked by the segment-scoped policy (tightening)")
	}

	withOrchestratorSegmentResolver(t, resolverReturning("seg-engineering"))
	nonMemberResult := engine.EvaluateDynamicPolicies(context.Background(), nonMember)
	if !nonMemberResult.Allowed {
		t.Fatal("a non-member (different segment) must NOT be blocked by another segment's policy — segment can only tighten for its own members")
	}
}

// TestEvaluateDynamicPolicies_SegmentDetail_PerPolicyOverride is the
// post-refinement contract for ADR-060 Decision 1: a segment-scoped policy's
// AppliedPolicyDetail.AllowOverride is now computed EXACTLY like a tenant
// policy's — IsOverridable() on the policy's own allow_override/risk_level
// columns, with no segment-specific override-exclusion. A hard floor is
// still available per-policy via allow_override=false or risk_level=critical.
// SegmentID is always populated for attribution regardless of the
// AllowOverride outcome. See override_enforcement_test.go for the companion
// ApplyOverrideToResult-side assertions.
func TestEvaluateDynamicPolicies_SegmentDetail_PerPolicyOverride(t *testing.T) {
	cases := []struct {
		name              string
		allowOverride     bool
		riskLevel         string
		wantDetailAllowOv bool
	}{
		{"allow_override true, non-critical -> overridable", true, "medium", true},
		{"allow_override false -> hard floor regardless", false, "medium", false},
		{"critical risk -> hard floor even if allow_override true", true, "critical", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seg := segmentBlockPolicyFor("seg-finance")
			seg.AllowOverride = tc.allowOverride
			seg.RiskLevel = tc.riskLevel
			engine := newTestEngine([]DynamicPolicy{seg})
			defer engine.Close()
			withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))

			req := OrchestratorRequest{
				Query: "export all kyc records",
				User:  UserContext{OrgID: "org-shared", Email: "alice@example.com"},
			}
			result := engine.EvaluateDynamicPolicies(context.Background(), req)
			if result.Allowed {
				t.Fatal("vacuity control failed: the segment policy did not block")
			}
			if len(result.AppliedPoliciesDetail) == 0 {
				t.Fatal("vacuity control failed: no AppliedPoliciesDetail recorded")
			}
			found := false
			for _, d := range result.AppliedPoliciesDetail {
				if d.PolicyID != seg.ID {
					continue
				}
				found = true
				if d.AllowOverride != tc.wantDetailAllowOv {
					t.Errorf("AppliedPolicyDetail.AllowOverride = %v, want %v (allow_override=%v risk=%q)",
						d.AllowOverride, tc.wantDetailAllowOv, tc.allowOverride, tc.riskLevel)
				}
				if d.SegmentID != "seg-finance" {
					t.Errorf("segment-scoped policy detail must always carry its SegmentID for attribution, got %q", d.SegmentID)
				}
			}
			if !found {
				t.Fatalf("expected AppliedPoliciesDetail to include policy %q, got %+v", seg.ID, result.AppliedPoliciesDetail)
			}
		})
	}
}
