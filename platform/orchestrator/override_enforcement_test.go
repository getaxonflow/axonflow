// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
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

// TestApplyOverrideToResult_SegmentScopedHonorsOwnAllowOverride is the
// post-refinement contract test (#3052 follow-up, folded into #3239): a
// segment-scoped policy (SegmentID != "") now uses the SAME session-override
// contract as a tenant policy — ApplyOverrideToResult decides purely from
// AllowOverride/RiskLevel on the detail, with no SegmentID-based exclusion.
// An operational segment policy (allow_override=true, non-critical) IS
// queried and, on an active override, flips the result to allow. This
// restores runtime break-glass for segment policies that choose to allow it;
// a segment policy that wants a hard floor still gets one by shipping with
// allow_override=false or risk_level=critical (see the companion "still a
// floor" test below) — that is enforced per-policy, identically to a tenant
// policy, not by a segment-specific carve-out in this function.
func TestApplyOverrideToResult_SegmentScopedHonorsOwnAllowOverride(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expiry := time.Now().Add(time.Hour)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).
		WithArgs("tenant-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT id, policy_id, policy_type.*FROM policy_overrides`).
		WithArgs("pol-seg", "u@x", "tenant-1", "").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at"},
		).AddRow("ov-1", "pol-seg", "dynamic", "", "operational break-glass", expiry))
	mock.ExpectCommit()

	result := &PolicyEvaluationResult{
		Allowed: false,
		AppliedPoliciesDetail: []AppliedPolicyDetail{
			// Operational segment policy: allow_override=true, non-critical —
			// its own detail says it is overridable, exactly like a tenant policy.
			{PolicyID: "pol-seg", RiskLevel: "medium", AllowOverride: true, SegmentID: "seg-finance"},
		},
	}

	applied, ov := ApplyOverrideToResult(context.Background(), db, nil, result, "tenant-1", "tenant-1", "u@x", "")
	if !applied {
		t.Fatal("an operational segment-scoped policy (allow_override=true, non-critical) must honor an active session override")
	}
	if ov == nil || ov.ID != "ov-1" {
		t.Fatalf("expected the matched override to be returned, got %+v", ov)
	}
	if !result.Allowed {
		t.Fatal("result.Allowed must flip to true when the segment policy's own override is honored")
	}
	if !result.OverrideApplied {
		t.Fatal("OverrideApplied must be set")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected the override lookup to be issued for an overridable segment policy: %v", err)
	}
}

// TestApplyOverrideToResult_SegmentScopedStillAFloorWhenNotOverridable proves
// a segment policy still gets a hard floor under the per-policy contract —
// via its OWN allow_override=false or risk_level=critical — by proving
// NON-CONSULTATION: the override lookup must never even be ISSUED, not just
// "return nothing usable."
//
// R2-1 (round-2 review): the original version of this test used a nil db, on
// which FindActiveOverride short-circuits to (nil, nil) unconditionally. That
// meant if a future refactor accidentally dropped the
// `p.RiskLevel == "critical" || !p.AllowOverride` guard in
// ApplyOverrideToResult's loop, the lookup would still run, still get (nil,
// nil) from the nil-db short-circuit, and the test would STILL PASS — it had
// lost its discriminating power. Each subtest below wires a REAL sqlmock db
// with a FULLY PLANTED lookup — including a matching active override row
// that, if consulted, WOULD flip the result to allowed — and asserts the
// plant is left UNCONSUMED (mock.ExpectationsWereMet returns an error
// precisely because a planted expectation was never matched). If the guard
// is ever dropped, the code starts actually issuing this query against a
// live-shaped backend, consuming every expectation, ov becomes non-nil, and
// EVERY assertion below (including the "still a floor" ones) flips to
// failing.
func TestApplyOverrideToResult_SegmentScopedStillAFloorWhenNotOverridable(t *testing.T) {
	t.Run("allow_override=false", func(t *testing.T) {
		assertOverrideNeverConsultedForFloor(t, AppliedPolicyDetail{
			PolicyID: "pol-seg-hard-floor", RiskLevel: "medium", AllowOverride: false, SegmentID: "seg-finance",
		})
	})
	t.Run("critical risk", func(t *testing.T) {
		assertOverrideNeverConsultedForFloor(t, AppliedPolicyDetail{
			PolicyID: "pol-seg-critical", RiskLevel: "critical", AllowOverride: true, SegmentID: "seg-finance",
		})
	})
}

// assertOverrideNeverConsultedForFloor drives ApplyOverrideToResult with a
// single non-overridable/critical candidate against a real sqlmock db that
// has a full, matching, "would-flip-the-verdict" lookup PLANTED but never
// consumed. See the caller's doc for why this — and not a nil db — is the
// discriminating shape R2-1 asks for.
func assertOverrideNeverConsultedForFloor(t *testing.T, detail AppliedPolicyDetail) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expiry := time.Now().Add(time.Hour)
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config`).
		WithArgs("tenant-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT id, policy_id, policy_type.*FROM policy_overrides`).
		WithArgs(detail.PolicyID, "u@x", "tenant-1", "").
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at"},
		).AddRow("ov-must-never-be-returned", detail.PolicyID, "dynamic", "", "must never be honored", expiry))
	mock.ExpectCommit()

	result := &PolicyEvaluationResult{
		Allowed:               false,
		AppliedPoliciesDetail: []AppliedPolicyDetail{detail},
	}

	applied, ov := ApplyOverrideToResult(context.Background(), db, nil, result, "tenant-1", "tenant-1", "u@x", "")
	if applied {
		t.Fatal("a segment policy with allow_override=false or critical risk must stay a hard floor")
	}
	if ov != nil {
		t.Fatalf("expected nil override, got %+v", ov)
	}
	if result.Allowed {
		t.Fatal("result.Allowed must stay false for a non-overridable segment policy")
	}

	// The discriminating assertion: the fully-planted lookup above must have
	// gone UNCONSUMED. mock.ExpectationsWereMet returns an error precisely
	// when a planted expectation was never matched — so err == nil here
	// would mean the code actually issued (and got a hit from) the lookup,
	// i.e. the allow_override/critical guard was bypassed.
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Fatal("expected the override lookup to be UNISSUED for a non-overridable/critical candidate, but every planted expectation was consumed — the allow_override/critical guard was bypassed")
	}
}

func TestFindActiveOverride_NilDBReturnsNil(t *testing.T) {
	ov, err := FindActiveOverride(context.Background(), nil, "t", "t", "u@x.com", "p-1", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if ov != nil {
		t.Errorf("expected nil override, got %+v", ov)
	}
}

func TestFindActiveOverride_EmptyUserReturnsNil(t *testing.T) {
	ov, err := FindActiveOverride(context.Background(), nil, "t", "t", "", "p-1", "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if ov != nil {
		t.Errorf("expected nil override for empty user")
	}
}

func TestFindActiveOverride_EmptyPolicyReturnsNil(t *testing.T) {
	ov, err := FindActiveOverride(context.Background(), nil, "t", "t", "u@x.com", "", "")
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
