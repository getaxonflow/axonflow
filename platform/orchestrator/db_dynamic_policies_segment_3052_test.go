// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3052 (ADR-060 #2989 P3b) — segment-awareness for the DB-backed
// DatabaseDynamicPolicyEngine. Mirrors dynamic_policy_engine_segment_3052_test.go
// for this engine's own choke point (dbCachedPolicyAppliesToTenant) and its
// deliberately different sentinel/shape handling (see that function's doc).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// TestDbCachedPolicyAppliesToTenant_SegmentMatrix is the choke-point
// applies/doesn't-apply matrix (DoD item) for the DB-backed engine,
// including the shapes unique to it: metadata absent, and the
// "global"/"default" tenant sentinels.
func TestDbCachedPolicyAppliesToTenant_SegmentMatrix(t *testing.T) {
	mk := func(metadataPresent bool, tenant, segment string) map[string]interface{} {
		m := map[string]interface{}{"name": "p"}
		if metadataPresent {
			m["_metadata"] = map[string]interface{}{"tenant_id": tenant, "segment_id": segment}
		}
		return m
	}

	cases := []struct {
		name           string
		policyMap      map[string]interface{}
		callerTenant   string
		callerSegments []string
		want           bool
	}{
		{"no metadata: fail-closed defect guard excludes", mk(false, "", ""), "tenant-a", nil, false},
		{"empty tenant in metadata: applies to nobody", mk(true, "", ""), "tenant-a", nil, false},
		{"global sentinel, no segment: applies", mk(true, "global", ""), "tenant-a", nil, true},
		{"default sentinel, no segment: applies", mk(true, "default", ""), "tenant-a", nil, true},
		{"exact tenant match, no segment: applies", mk(true, "tenant-a", ""), "tenant-a", nil, true},
		{"other tenant, no segment: excluded", mk(true, "tenant-b", ""), "tenant-a", nil, false},

		{"global sentinel + matching segment: applies", mk(true, "global", "seg-finance"), "tenant-a", []string{"seg-finance"}, true},
		{"global sentinel + segment set but caller has none: excluded", mk(true, "global", "seg-finance"), "tenant-a", nil, false},
		{"global sentinel + wrong segment: excluded", mk(true, "global", "seg-finance"), "tenant-a", []string{"seg-engineering"}, false},
		{"exact tenant + matching segment: applies", mk(true, "tenant-a", "seg-finance"), "tenant-a", []string{"seg-finance"}, true},
		{"exact tenant + caller lacks segment: excluded", mk(true, "tenant-a", "seg-finance"), "tenant-a", nil, false},

		// Tenant gate short-circuits regardless of segment membership.
		{"other tenant + matching segment: still excluded", mk(true, "tenant-b", "seg-finance"), "tenant-a", []string{"seg-finance"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dbCachedPolicyAppliesToTenant(tc.policyMap, tc.callerTenant, tc.callerSegments, tc.name)
			if got != tc.want {
				t.Errorf("dbCachedPolicyAppliesToTenant(%+v, %q, %v) = %v, want %v",
					tc.policyMap, tc.callerTenant, tc.callerSegments, got, tc.want)
			}
		})
	}
}

// dbCachedSegmentPolicy builds a raw cache entry (the shape refreshPolicies
// writes) for a policy scoped to tenant "global" and the given segment,
// blocking any query containing "kyc". risk_level defaults to "medium" — use
// dbCachedSegmentPolicyWithRisk to exercise the critical-risk hard floor.
func dbCachedSegmentPolicy(policyID, segmentID string, allowOverride bool) map[string]interface{} {
	return dbCachedSegmentPolicyWithRisk(policyID, segmentID, allowOverride, "medium")
}

// dbCachedSegmentPolicyWithRisk is dbCachedSegmentPolicy with an explicit
// risk_level, so callers can exercise the per-policy override contract's
// critical-risk branch (allow_override is irrelevant once risk is critical).
func dbCachedSegmentPolicyWithRisk(policyID, segmentID string, allowOverride bool, riskLevel string) map[string]interface{} {
	conditions, _ := json.Marshal([]PolicyCondition{{Field: "query", Operator: "contains", Value: "kyc"}})
	actions, _ := json.Marshal([]PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "kyc exfiltration"}}})
	return map[string]interface{}{
		"policy_id":  policyID,
		"name":       "segment KYC block",
		"type":       "content",
		"conditions": json.RawMessage(conditions),
		"actions":    json.RawMessage(actions),
		"tenant_id":  "global",
		"priority":   100,
		"_metadata": map[string]interface{}{
			"id":             policyID,
			"name":           "segment KYC block",
			"tenant_id":      "global",
			"segment_id":     segmentID,
			"priority":       100,
			"risk_level":     riskLevel,
			"allow_override": allowOverride,
		},
	}
}

func TestDatabaseDynamicPolicyEngine_EvaluateDynamicPolicies_FailClosedOnResolveError(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{"p1": dbCachedSegmentPolicy("p1", "seg-finance", false)},
	}
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

func TestDatabaseDynamicPolicyEngine_EvaluateDynamicPolicies_NilResolver_OrgOnly_NoRegression(t *testing.T) {
	ResetOrchestratorSegmentResolverForTest()
	engine := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{}, // no policies at all — trivially allowed
	}
	req := OrchestratorRequest{
		Query: "hello world",
		User:  UserContext{OrgID: "org-a", Email: "alice@example.com", TenantID: "tenant-a"},
	}
	result := engine.EvaluateDynamicPolicies(context.Background(), req)
	if !result.Allowed {
		t.Fatalf("no resolver wired must never deny — expected org-only, got blocked: %+v", result)
	}
}

// TestDatabaseDynamicPolicyEngine_SegmentAdditiveRestrictionOnly is the
// combiner DoD item for the DB-backed engine: a segment member is blocked,
// a non-member of that segment is not.
func TestDatabaseDynamicPolicyEngine_SegmentAdditiveRestrictionOnly(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{"p1": dbCachedSegmentPolicy("p1", "seg-finance", false)},
	}

	member := OrchestratorRequest{
		Query: "export all kyc records",
		User:  UserContext{OrgID: "org-shared", Email: "alice@example.com", TenantID: "global"},
	}
	nonMember := OrchestratorRequest{
		Query: "export all kyc records",
		User:  UserContext{OrgID: "org-shared", Email: "bob@example.com", TenantID: "global"},
	}

	withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))
	memberResult := engine.EvaluateDynamicPolicies(context.Background(), member)
	if memberResult.Allowed {
		t.Fatal("a seg-finance member must be blocked by the segment-scoped policy")
	}

	withOrchestratorSegmentResolver(t, resolverReturning("seg-engineering"))
	nonMemberResult := engine.EvaluateDynamicPolicies(context.Background(), nonMember)
	if !nonMemberResult.Allowed {
		t.Fatal("a non-member (different segment) must NOT be blocked by another segment's policy")
	}
}

// TestDatabaseDynamicPolicyEngine_SegmentDetail_PerPolicyOverride mirrors the
// mem-engine test of the same shape (dynamic_policy_engine_segment_3052_test.go):
// post-refinement, a segment-scoped policy's AppliedPolicyDetail.AllowOverride
// is computed exactly like a tenant policy's — from the policy's own
// allow_override/risk_level metadata, with no segment-specific exclusion. A
// hard floor is still available per-policy via allow_override=false or
// risk_level=critical. SegmentID is always populated for attribution.
func TestDatabaseDynamicPolicyEngine_SegmentDetail_PerPolicyOverride(t *testing.T) {
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
			engine := &DatabaseDynamicPolicyEngine{
				policies: map[string]interface{}{
					"p1": dbCachedSegmentPolicyWithRisk("p1", "seg-finance", tc.allowOverride, tc.riskLevel),
				},
			}
			withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))

			req := OrchestratorRequest{
				Query: "export all kyc records",
				User:  UserContext{OrgID: "org-shared", Email: "alice@example.com", TenantID: "global"},
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
				if d.PolicyID != "p1" {
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
				t.Fatalf("expected AppliedPoliciesDetail to include policy p1, got %+v", result.AppliedPoliciesDetail)
			}
		})
	}
}

// TestDatabaseDynamicPolicyEngine_ListActivePoliciesForTenant_SegmentThreading
// proves the segmentIDs parameter actually reaches dbCachedPolicyAppliesToTenant
// for the list/disclosure path too — list and enforce cannot diverge.
func TestDatabaseDynamicPolicyEngine_ListActivePoliciesForTenant_SegmentThreading(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{
			"p1": dbCachedSegmentPolicy("p1", "seg-finance", false),
		},
	}

	none := engine.ListActivePoliciesForTenant("global", nil)
	if len(none) != 0 {
		t.Fatalf("nil segments must exclude the segment-scoped policy from the list, got %+v", none)
	}

	finance := engine.ListActivePoliciesForTenant("global", []string{"seg-finance"})
	if len(finance) != 1 || finance[0].SegmentID != "seg-finance" {
		t.Fatalf("caller in seg-finance must see the segment-scoped policy, got %+v", finance)
	}
}
