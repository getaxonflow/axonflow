// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3281 (ADR-060 #2989 P3b) - segment enforcement on WCP workflow
// step-gates. Before this fix, WCPPolicyAdapter.convertToOrchestratorRequest
// built User: UserContext{TenantID: step.TenantID} with no OrgID and no
// Email, so resolveUserSegments always took the "no verified identity"
// org-only path on a step-gate and every segment-scoped dynamic policy was
// silently unenforced there, even though the identical policy IS enforced on
// /api/v1/process (run.go) and MAP. These tests exercise the FULL
// adapter -> real DatabaseDynamicPolicyEngine -> resolveUserSegments
// path (not the mockPolicyEngineForWCP double used elsewhere in
// wcp_policy_adapter_test.go), the same way
// db_dynamic_policies_segment_3052_test.go does for /api/v1/process, so a
// regression here is caught even if a future change makes the wiring
// correct-looking at the OrchestratorRequest level but broken end-to-end.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"axonflow/platform/orchestrator/workflow_control"
)

// dbCachedSegmentPolicyForStep mirrors db_dynamic_policies_segment_3052_test.go's
// dbCachedSegmentPolicy, but matches on step_name (populated by
// convertToOrchestratorRequest's contextData["step_name"] = step.StepName)
// instead of "query" - convertToOrchestratorRequest never populates
// OrchestratorRequest.Query, so a "query contains ..." condition (the
// sibling file's shape) would never match a step-gate request and would
// silently pass every test in this file regardless of whether segment
// enforcement actually worked.
func dbCachedSegmentPolicyForStep(policyID, segmentID, matchStepName string) map[string]interface{} {
	conditions, _ := json.Marshal([]PolicyCondition{{Field: "step_name", Operator: "equals", Value: matchStepName}})
	actions, _ := json.Marshal([]PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "segment-restricted step"}}})
	return map[string]interface{}{
		"policy_id":  policyID,
		"name":       "segment step-gate block",
		"type":       "content",
		"conditions": json.RawMessage(conditions),
		"actions":    json.RawMessage(actions),
		"tenant_id":  "global",
		"priority":   100,
		"_metadata": map[string]interface{}{
			"id":             policyID,
			"name":           "segment step-gate block",
			"tenant_id":      "global",
			"org_id":         "global",
			"segment_id":     segmentID,
			"priority":       100,
			"risk_level":     "medium",
			"allow_override": false,
		},
	}
}

// dbCachedNonSegmentPolicyForStep is a plain tenant-scoped (segment_id="")
// policy, used to prove the org-only path (nil resolver / unverified
// identity) still enforces non-segment-scoped policies rather than denying
// or allowing everything.
func dbCachedNonSegmentPolicyForStep(policyID, matchStepName string) map[string]interface{} {
	conditions, _ := json.Marshal([]PolicyCondition{{Field: "step_name", Operator: "equals", Value: matchStepName}})
	actions, _ := json.Marshal([]PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "org-wide restricted step"}}})
	return map[string]interface{}{
		"policy_id":  policyID,
		"name":       "org-wide step-gate block",
		"type":       "content",
		"conditions": json.RawMessage(conditions),
		"actions":    json.RawMessage(actions),
		"tenant_id":  "global",
		"priority":   100,
		"_metadata": map[string]interface{}{
			"id":             policyID,
			"name":           "org-wide step-gate block",
			"tenant_id":      "global",
			"org_id":         "global",
			"segment_id":     "",
			"priority":       100,
			"risk_level":     "medium",
			"allow_override": false,
		},
	}
}

func stepGateCtxFor(orgID, email string) *workflow_control.StepGateContext {
	return &workflow_control.StepGateContext{
		WorkflowID: "wf-3281",
		StepID:     "step-1",
		StepName:   "export_finance_report",
		StepType:   workflow_control.StepTypeToolCall,
		TenantID:   "global",
		OrgID:      orgID,
		Email:      email,
	}
}

// (i) member -> segment-scoped policy enforces on a step-gate, asserting
// WHICH policy fired (not just a boolean verdict).
func TestWCPPolicyAdapter_EvaluateStepGate_SegmentMember_Enforced(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{
			"seg-p1": dbCachedSegmentPolicyForStep("seg-p1", "seg-finance", "export_finance_report"),
		},
	}
	withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))

	adapter := NewWCPPolicyAdapter(engine)
	result := adapter.EvaluateStepGate(context.Background(), stepGateCtxFor("org-shared", "alice@example.com"))

	if result.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("expected a seg-finance member to be blocked by the segment-scoped policy, got decision=%s reason=%q", result.Decision, result.Reason)
	}
	// PoliciesMatched carries the structured AppliedPoliciesDetail (PolicyID,
	// not the display name PolicyIDs/AppliedPolicies uses) - the field a
	// caller checks to know WHICH policy fired, not just that something did.
	found := false
	for _, m := range result.PoliciesMatched {
		if m.PolicyID == "seg-p1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the deny to name the specific policy that fired (seg-p1), got PoliciesMatched=%+v", result.PoliciesMatched)
	}
}

// (ii) non-member IN A DIFFERENT SEGMENT (not merely zero segments) -> does
// NOT enforce. Using a different segment rather than an empty set proves the
// choke point is doing a real membership comparison, not just "caller has
// any segments at all".
func TestWCPPolicyAdapter_EvaluateStepGate_SegmentNonMember_DifferentSegment_NotEnforced(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{
			"seg-p1": dbCachedSegmentPolicyForStep("seg-p1", "seg-finance", "export_finance_report"),
		},
	}
	withOrchestratorSegmentResolver(t, resolverReturning("seg-engineering"))

	adapter := NewWCPPolicyAdapter(engine)
	result := adapter.EvaluateStepGate(context.Background(), stepGateCtxFor("org-shared", "bob@example.com"))

	if result.Decision != workflow_control.GateDecisionAllow {
		t.Fatalf("expected a seg-engineering caller (not a seg-finance member) to NOT be blocked by the seg-finance policy, got decision=%s reason=%q policyIDs=%v",
			result.Decision, result.Reason, result.PolicyIDs)
	}
	for _, id := range result.PolicyIDs {
		if id == "seg-p1" {
			t.Fatalf("#3266 disclosure: the segment-scoped policy must not even be reported to a non-member, got PolicyIDs=%v", result.PolicyIDs)
		}
	}
}

// (iii) resolver error -> step-gate DENIES fail-closed, and the deny is
// explicitly named (not indistinguishable from a generic policy block) so
// the audit row and API response can key off it.
func TestWCPPolicyAdapter_EvaluateStepGate_ResolverError_FailsClosed(t *testing.T) {
	engine := &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{
			"seg-p1": dbCachedSegmentPolicyForStep("seg-p1", "seg-finance", "export_finance_report"),
		},
	}
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{err: errors.New("scim query failed")})

	adapter := NewWCPPolicyAdapter(engine)
	result := adapter.EvaluateStepGate(context.Background(), stepGateCtxFor("org-shared", "alice@example.com"))

	if result.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("a segment resolution error must DENY the step-gate (fail-closed, ADR-060 §Fail-closed), got decision=%s", result.Decision)
	}
	if result.Decision == workflow_control.GateDecisionRequireApproval {
		t.Fatal("a resolution failure must never be treated as require_approval (that is not fail-closed for an external caller who can just not respond)")
	}
	wantPolicyID := "segment_resolution_failed"
	found := false
	for _, id := range result.PolicyIDs {
		if id == wantPolicyID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the fail-closed deny to name %q in PolicyIDs (matching run.go's convention), got %v", wantPolicyID, result.PolicyIDs)
	}
}

// (iv) nil resolver / empty email -> org-only: non-segment-scoped policies
// still enforce (the fail-closed change must not become an accidental
// fail-open for ordinary tenant-wide policies), and a segment-scoped policy
// does not apply (no verified identity to check membership against).
func TestWCPPolicyAdapter_EvaluateStepGate_NilResolver_OrgOnly(t *testing.T) {
	ResetOrchestratorSegmentResolverForTest()

	t.Run("non-segment-scoped policy still enforces", func(t *testing.T) {
		engine := &DatabaseDynamicPolicyEngine{
			policies: map[string]interface{}{
				"org-p1": dbCachedNonSegmentPolicyForStep("org-p1", "export_finance_report"),
			},
		}
		adapter := NewWCPPolicyAdapter(engine)
		result := adapter.EvaluateStepGate(context.Background(), stepGateCtxFor("org-shared", "alice@example.com"))
		if result.Decision != workflow_control.GateDecisionBlock {
			t.Fatalf("a non-segment-scoped policy must still enforce with no resolver wired, got decision=%s reason=%q", result.Decision, result.Reason)
		}
	})

	t.Run("segment-scoped policy does not apply", func(t *testing.T) {
		engine := &DatabaseDynamicPolicyEngine{
			policies: map[string]interface{}{
				"seg-p1": dbCachedSegmentPolicyForStep("seg-p1", "seg-finance", "export_finance_report"),
			},
		}
		adapter := NewWCPPolicyAdapter(engine)
		result := adapter.EvaluateStepGate(context.Background(), stepGateCtxFor("org-shared", "alice@example.com"))
		if result.Decision != workflow_control.GateDecisionAllow {
			t.Fatalf("no resolver wired must never deny on a segment-scoped-only policy set - expected org-only allow, got decision=%s reason=%q", result.Decision, result.Reason)
		}
	})

	t.Run("empty email with a resolver wired also stays org-only, not a failure", func(t *testing.T) {
		fake := resolverReturning("seg-finance")
		withOrchestratorSegmentResolver(t, fake)
		engine := &DatabaseDynamicPolicyEngine{
			policies: map[string]interface{}{
				"org-p1": dbCachedNonSegmentPolicyForStep("org-p1", "export_finance_report"),
			},
		}
		adapter := NewWCPPolicyAdapter(engine)
		result := adapter.EvaluateStepGate(context.Background(), stepGateCtxFor("org-shared", "")) // no Email
		if result.Decision != workflow_control.GateDecisionBlock {
			t.Fatalf("empty email must still allow non-segment-scoped enforcement (org-only), got decision=%s reason=%q", result.Decision, result.Reason)
		}
		if fake.callCount() != 0 {
			t.Fatalf("resolver must not even be called when email is empty (no verified identity), got %d calls", fake.callCount())
		}
	})
}

// Regression test for the exact bug this issue closes: previously
// convertToOrchestratorRequest built User: UserContext{TenantID: step.TenantID}
// only, silently dropping OrgID and Email so every step-gate resolved
// segments on the "no verified identity" path. This test pins the wiring
// directly against the OrchestratorRequest the adapter builds, independent
// of the engine's own segment-resolution behavior (covered above).
func TestWCPPolicyAdapter_ConvertToOrchestratorRequest_ThreadsOrgAndEmail(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{Allowed: true, AppliedPolicies: []string{}},
	}
	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf-wiring",
		StepID:     "step-1",
		StepType:   workflow_control.StepTypeToolCall,
		TenantID:   "tenant-9",
		OrgID:      "org-9",
		Email:      "carol@example.com",
	}
	adapter.EvaluateStepGate(context.Background(), stepCtx)

	if mockEngine.lastReq.User.TenantID != "tenant-9" {
		t.Errorf("User.TenantID = %q, want tenant-9", mockEngine.lastReq.User.TenantID)
	}
	if mockEngine.lastReq.User.OrgID != "org-9" {
		t.Errorf("User.OrgID = %q, want org-9 (was previously left zero - the #3281 bug)", mockEngine.lastReq.User.OrgID)
	}
	if mockEngine.lastReq.User.Email != "carol@example.com" {
		t.Errorf("User.Email = %q, want carol@example.com (was previously left empty - the #3281 bug)", mockEngine.lastReq.User.Email)
	}
}
