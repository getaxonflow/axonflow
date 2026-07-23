// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"
)

func TestSelectOverridablePolicy_NoneOverridable(t *testing.T) {
	policies := []AppliedPolicyDetail{
		{PolicyID: "p-1", RiskLevel: "critical", AllowOverride: true}, // critical never overridable
		{PolicyID: "p-2", RiskLevel: "high", AllowOverride: false},    // explicitly disabled
	}
	got := SelectOverridablePolicy(policies)
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestSelectOverridablePolicy_ReturnsFirstMatch(t *testing.T) {
	policies := []AppliedPolicyDetail{
		{PolicyID: "p-critical", RiskLevel: "critical", AllowOverride: false},
		{PolicyID: "p-overridable", RiskLevel: "high", AllowOverride: true},
		{PolicyID: "p-third", RiskLevel: "medium", AllowOverride: true},
	}
	got := SelectOverridablePolicy(policies)
	if got == nil {
		t.Fatal("expected non-nil, got nil")
	}
	if got.PolicyID != "p-overridable" {
		t.Errorf("PolicyID = %q, want 'p-overridable'", got.PolicyID)
	}
}

func TestSelectOverridablePolicy_EmptyList(t *testing.T) {
	if got := SelectOverridablePolicy(nil); got != nil {
		t.Errorf("expected nil for nil list, got %+v", got)
	}
	if got := SelectOverridablePolicy([]AppliedPolicyDetail{}); got != nil {
		t.Errorf("expected nil for empty list, got %+v", got)
	}
}

func TestApplyOverrideToResult_AllowedResultNoOp(t *testing.T) {
	result := &PolicyEvaluationResult{Allowed: true}
	applied, ov := ApplyOverrideToResult(context.Background(), nil, nil, result, "t", "o", "u@x.com", "")
	if applied {
		t.Error("expected no-op when Allowed=true")
	}
	if ov != nil {
		t.Error("expected nil override when Allowed=true")
	}
}

func TestApplyOverrideToResult_NilResultNoOp(t *testing.T) {
	applied, ov := ApplyOverrideToResult(context.Background(), nil, nil, nil, "t", "o", "u@x.com", "")
	if applied {
		t.Error("expected no-op for nil result")
	}
	if ov != nil {
		t.Error("expected nil override for nil result")
	}
}

func TestApplyOverrideToResult_EmptyUserEmailNoOp(t *testing.T) {
	result := &PolicyEvaluationResult{
		Allowed: false,
		AppliedPoliciesDetail: []AppliedPolicyDetail{
			{PolicyID: "p-1", RiskLevel: "medium", AllowOverride: true},
		},
	}
	applied, ov := ApplyOverrideToResult(context.Background(), nil, nil, result, "t", "o", "", "")
	if applied {
		t.Error("expected no-op for empty user email")
	}
	if ov != nil {
		t.Error("expected nil override for empty user email")
	}
	if result.Allowed {
		t.Error("result.Allowed must stay false when no override applied")
	}
}

func TestApplyOverrideToResult_AllCriticalNoOp(t *testing.T) {
	result := &PolicyEvaluationResult{
		Allowed: false,
		AppliedPoliciesDetail: []AppliedPolicyDetail{
			{PolicyID: "p-1", RiskLevel: "critical", AllowOverride: true},
			{PolicyID: "p-2", RiskLevel: "high", AllowOverride: false},
		},
	}
	// nil db means no lookups happen; critical/non-overridable short-circuit
	applied, ov := ApplyOverrideToResult(context.Background(), nil, nil, result, "t", "o", "u@x.com", "")
	if applied {
		t.Error("expected no-op when all policies are critical/non-overridable")
	}
	if ov != nil {
		t.Error("expected nil override")
	}
	if result.Allowed {
		t.Error("result.Allowed must stay false")
	}
	if result.OverrideApplied {
		t.Error("OverrideApplied must stay false")
	}
}

func TestFindActiveOverride_NilDBReturnsNil(t *testing.T) {
	ov, err := FindActiveOverride(context.Background(), nil, "t", "u@x.com", "p-1", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if ov != nil {
		t.Errorf("expected nil override, got %+v", ov)
	}
}

func TestFindActiveOverride_EmptyUserReturnsNil(t *testing.T) {
	ov, err := FindActiveOverride(context.Background(), nil, "t", "", "p-1", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if ov != nil {
		t.Errorf("expected nil override for empty user")
	}
}

func TestFindActiveOverride_EmptyPolicyReturnsNil(t *testing.T) {
	ov, err := FindActiveOverride(context.Background(), nil, "t", "u@x.com", "", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if ov != nil {
		t.Errorf("expected nil override for empty policy")
	}
}

// TestSelectOverridablePolicy_SkipsCriticalButReturnsHighRisk verifies that a
// high-risk but overridable policy can be returned. The scoping rule in ADR-044
// is: "critical OR allow_override=false blocks override; everything else is
// eligible." Ensure high-risk doesn't accidentally block.
func TestSelectOverridablePolicy_SkipsCriticalButReturnsHighRisk(t *testing.T) {
	policies := []AppliedPolicyDetail{
		{PolicyID: "p-critical", RiskLevel: "critical", AllowOverride: true},
		{PolicyID: "p-high-ok", RiskLevel: "high", AllowOverride: true},
	}
	got := SelectOverridablePolicy(policies)
	if got == nil {
		t.Fatal("expected high-risk overridable policy, got nil")
	}
	if got.PolicyID != "p-high-ok" {
		t.Errorf("got %q, want 'p-high-ok'", got.PolicyID)
	}
}

// TestSelectOverridablePolicy_LowRiskOverridable verifies low-risk with
// allow_override=true is selected.
func TestSelectOverridablePolicy_LowRiskOverridable(t *testing.T) {
	policies := []AppliedPolicyDetail{
		{PolicyID: "p-low", RiskLevel: "low", AllowOverride: true},
	}
	got := SelectOverridablePolicy(policies)
	if got == nil {
		t.Fatal("expected low-risk policy to be overridable")
	}
}

// TestDynamicPolicy_IsOverridable_Critical locks in the ADR-044 invariant
// that critical-risk policies are never overridable, even when AllowOverride
// is true (the DB trigger forces it false, but the Go-side guard is defense
// in depth and matters for in-memory evaluation).
func TestDynamicPolicy_IsOverridable_Critical(t *testing.T) {
	p := &DynamicPolicy{RiskLevel: "critical", AllowOverride: true}
	if p.IsOverridable() {
		t.Error("critical-risk policy must never report IsOverridable=true")
	}
}

// TestDynamicPolicy_IsOverridable_NonCriticalRespectsFlag covers the normal
// path: IsOverridable echoes AllowOverride when risk is not critical.
func TestDynamicPolicy_IsOverridable_NonCriticalRespectsFlag(t *testing.T) {
	for _, tc := range []struct {
		name          string
		risk          string
		allowOverride bool
		want          bool
	}{
		{"high_allow", "high", true, true},
		{"high_deny", "high", false, false},
		{"medium_allow", "medium", true, true},
		{"low_allow", "low", true, true},
		{"low_deny", "low", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &DynamicPolicy{RiskLevel: tc.risk, AllowOverride: tc.allowOverride}
			if got := p.IsOverridable(); got != tc.want {
				t.Errorf("risk=%s allow=%v: got %v, want %v", tc.risk, tc.allowOverride, got, tc.want)
			}
		})
	}
}
