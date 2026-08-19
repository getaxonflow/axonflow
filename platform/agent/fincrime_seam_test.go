// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"axonflow/platform/agent/fincrime"
	sharedpolicy "axonflow/platform/shared/policy"
)

func fcApprovalResult() *fincrime.Result {
	return &fincrime.Result{
		RequiresApproval: true,
		Reasons:          []string{"fincrime risk score 0.910 at or above threshold 0.800 (model fincrime-fraud test-1) - routed to human review"},
		PolicyIDs:        []string{fincrime.PolicyIDMLFraudScore},
		PolicyNames:      []string{"FinCrime ML Fraud Score (Engine B, advisory)"},
		PolicyVersions:   map[string]string{fincrime.PolicyIDMLFraudScore: "test-1"},
		RiskScore:        map[string]interface{}{"overall": 0.91, "above_threshold": true},
		MLStatus:         fincrime.MLStatusScored,
	}
}

func TestApplyFinCrimeToDecideVerdict_NilIsPassthrough(t *testing.T) {
	obl := []DecisionObligation{{Type: ObligationRedactPII}}
	v, r, o, p := applyFinCrimeToDecideVerdict(nil, VerdictAllow, []string{"a"}, obl, []string{"p1"}, false)
	if v != VerdictAllow || len(r) != 1 || len(o) != 1 || len(p) != 1 {
		t.Fatalf("nil result must change nothing: %v %v %v %v", v, r, o, p)
	}
}

func TestApplyFinCrimeToDecideVerdict_EscalatesAllowToNeedsApproval(t *testing.T) {
	obl := []DecisionObligation{{Type: ObligationRedactPII}}
	v, r, o, p := applyFinCrimeToDecideVerdict(fcApprovalResult(), VerdictAllow, nil, obl, nil, false)
	if v != VerdictNeedsApproval {
		t.Fatalf("verdict = %q", v)
	}
	if len(o) != 0 {
		t.Fatal("needs_approval must carry no obligations (approver decides at queue exit)")
	}
	if len(r) != 1 {
		t.Fatalf("reasons = %v", r)
	}
	if len(p) != 1 || p[0] != fincrime.PolicyIDMLFraudScore {
		t.Fatalf("triggered policies = %v", p)
	}
}

func TestApplyFinCrimeToDecideVerdict_CommunityModeAutoAllows(t *testing.T) {
	// Mirrors mapPolicyResultToVerdict: HITL is enterprise-gated, so the
	// verdict stays allow in community mode (and the community fincrime stub
	// never produces a Result at all; this pins the double safety).
	v, _, o, p := applyFinCrimeToDecideVerdict(fcApprovalResult(), VerdictAllow, nil, []DecisionObligation{{Type: ObligationRedactPII}}, nil, true)
	if v != VerdictAllow {
		t.Fatalf("verdict = %q", v)
	}
	if len(o) != 1 {
		t.Fatal("obligations must be preserved when the verdict stays allow")
	}
	if len(p) != 1 {
		t.Fatal("attribution still recorded on the allow")
	}
}

func TestApplyFinCrimeToDecideVerdict_NeverTouchesDeny(t *testing.T) {
	v, r, _, p := applyFinCrimeToDecideVerdict(fcApprovalResult(), VerdictDeny, []string{"blocked"}, nil, []string{"sys_block"}, false)
	if v != VerdictDeny {
		t.Fatalf("verdict = %q; fincrime must never rewrite a deny", v)
	}
	if len(r) != 2 || len(p) != 2 {
		t.Fatalf("attribution must still append on deny: r=%v p=%v", r, p)
	}
	if p[0] != "sys_block" {
		t.Fatal("fincrime ids must append AFTER the blocking policy (identity slot preserved)")
	}
}

func TestApplyFinCrimeToDecideVerdict_AdvisoryScoreOnAllow(t *testing.T) {
	fc := fcApprovalResult()
	fc.RequiresApproval = false
	fc.Reasons = nil
	v, r, o, p := applyFinCrimeToDecideVerdict(fc, VerdictAllow, nil, []DecisionObligation{{Type: ObligationRedactPII}}, nil, false)
	if v != VerdictAllow || len(o) != 1 {
		t.Fatalf("below-threshold score must not change the verdict or obligations: %q %v", v, o)
	}
	if len(r) != 0 {
		t.Fatalf("no reasons expected: %v", r)
	}
	if len(p) != 1 {
		t.Fatal("scored allow still carries the ML attribution")
	}
}

func TestFinCrimeParametersFromContext(t *testing.T) {
	if got := finCrimeParametersFromContext(nil); got != nil {
		t.Fatalf("nil context: %v", got)
	}
	if got := finCrimeParametersFromContext(map[string]interface{}{"x-session-id": "s"}); got != nil {
		t.Fatalf("no fincrime keys must yield nil (bit-identical legacy call): %v", got)
	}
	txn := map[string]interface{}{"amount": 9300.0}
	cohort := map[string]interface{}{"txn_frequency_1h": 12.0}
	got := finCrimeParametersFromContext(map[string]interface{}{
		fincrime.TransactionContextKey: txn,
		fincrime.CohortContextKey:      cohort,
		"x-session-id":                 "s",
		"unrelated":                    map[string]interface{}{"a": 1},
	})
	if len(got) != 2 {
		t.Fatalf("exactly the two documented keys must lift: %v", got)
	}
	if _, ok := got[fincrime.TransactionContextKey]; !ok {
		t.Fatal("transaction key missing")
	}
	if _, ok := got[fincrime.CohortContextKey]; !ok {
		t.Fatal("cohort key missing")
	}
	// Cohort-only requests lift too.
	got = finCrimeParametersFromContext(map[string]interface{}{fincrime.CohortContextKey: cohort})
	if len(got) != 1 {
		t.Fatalf("cohort-only lift: %v", got)
	}
}

func TestCreateFinCrimeApproval_NilBridgeAndNonFinCrime(t *testing.T) {
	prev := fincrimeHITLBridge
	defer func() { fincrimeHITLBridge = prev }()
	fincrimeHITLBridge = nil
	if id := createFinCrimeApprovalForDecision(context.Background(), "org", "tenant", "client", "1", "q", fcApprovalResult(), nil); id != "" {
		t.Fatalf("nil bridge must be a no-op, got %q", id)
	}
	fincrimeHITLBridge = NewHITLBridge(&NoOpHITLService{})
	if id := createFinCrimeApprovalForDecision(context.Background(), "org", "tenant", "client", "1", "q", nil, nil); id != "" {
		t.Fatalf("no fincrime involvement must be a no-op, got %q", id)
	}
	// A needs_approval driven by a NON-fincrime policy (e.g. an EU AI Act
	// require_approval row) is untouched: its pre-existing semantics are
	// not this seam's to change.
	nonFincrime := &sharedpolicy.RequestResult{MatchedPolicies: []sharedpolicy.PolicyMatch{{
		PolicyID: "hitl_eu_ai_act", PolicyName: "EU AI Act HITL",
		Category: sharedpolicy.CategoryComplianceEUAIAct, Action: sharedpolicy.ActionRequireApproval,
	}}}
	if id := createFinCrimeApprovalForDecision(context.Background(), "org", "tenant", "client", "1", "q", nil, nonFincrime); id != "" {
		t.Fatalf("non-fincrime require_approval must not create an entry here, got %q", id)
	}
}

func TestCreateFinCrimeApproval_AttributesToDrivingPolicy(t *testing.T) {
	prev := fincrimeHITLBridge
	defer func() { fincrimeHITLBridge = prev }()
	rec := &recordingHITLService{}
	fincrimeHITLBridge = NewHITLBridge(rec)

	// Scorer-driven step-up attributes to the ML policy.
	if id := createFinCrimeApprovalForDecision(context.Background(), "org", "tenant", "client", "1", "pay invoice", fcApprovalResult(), nil); id == "" {
		t.Fatal("expected an approval id")
	}
	if rec.last.TriggeredPolicyID != fincrime.PolicyIDMLFraudScore {
		t.Fatalf("policy id = %q", rec.last.TriggeredPolicyID)
	}
	if rec.last.OrgID != "org" || rec.last.TenantID != "tenant" || rec.last.ClientID != "client" || rec.last.OriginalQuery != "pay invoice" {
		t.Fatalf("identity fields wrong: %+v", rec.last)
	}

	// Validation-driven step-up attributes to the protocol-integrity policy.
	fc := &fincrime.Result{
		RequiresApproval: true,
		Reasons:          []string{"fincrime context invalid - fincrime_transaction.amount: must be a number"},
		PolicyIDs:        []string{fincrime.PolicyIDMandatoryFields},
	}
	if id := createFinCrimeApprovalForDecision(context.Background(), "org", "tenant", "client", "1", "q", fc, nil); id == "" {
		t.Fatal("expected an approval id")
	}
	if rec.last.TriggeredPolicyID != fincrime.PolicyIDMandatoryFields {
		t.Fatalf("policy id = %q", rec.last.TriggeredPolicyID)
	}
	if rec.last.TriggerReason != fc.Reasons[0] {
		t.Fatalf("trigger reason = %q", rec.last.TriggerReason)
	}

	// Pack-row-driven step-up (no seam result): attributes to the first
	// fincrime require_approval match, so the needs_approval verdict is a
	// reviewable queue entry, never an unapprovable dead end.
	packDriven := &sharedpolicy.RequestResult{MatchedPolicies: []sharedpolicy.PolicyMatch{
		{PolicyID: "sys_pii_ssn", PolicyName: "SSN", Category: sharedpolicy.CategoryPIIUS, Action: sharedpolicy.ActionRedact},
		{PolicyID: "fincrime_structuring_pattern_stepup", PolicyName: "FinCrime: Structuring Pattern Step-Up",
			Category: sharedpolicy.CategoryFinCrime, Action: sharedpolicy.ActionRequireApproval},
	}}
	if id := createFinCrimeApprovalForDecision(context.Background(), "org", "tenant", "client", "1", "transfer leg", nil, packDriven); id == "" {
		t.Fatal("expected an approval id for the pack-driven step-up")
	}
	if rec.last.TriggeredPolicyID != "fincrime_structuring_pattern_stepup" {
		t.Fatalf("policy id = %q", rec.last.TriggeredPolicyID)
	}
}

// recordingHITLService captures the CreateApprovalRequest input for
// assertions and returns a stable approved-shaped row.
type recordingHITLService struct {
	last HITLCreateInput
}

func (r *recordingHITLService) CreateApprovalRequest(_ context.Context, input HITLCreateInput) (*HITLApprovalRequest, error) {
	r.last = input
	return (&NoOpHITLService{}).CreateApprovalRequest(context.Background(), input)
}

func (r *recordingHITLService) GetApprovalRequest(ctx context.Context, requestID uuid.UUID) (*HITLApprovalRequest, error) {
	return (&NoOpHITLService{}).GetApprovalRequest(ctx, requestID)
}
