// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestProjectStepGateToHTTP_NilStep verifies the legacy in-memory MAP flow path
// where no WCP step row exists. The projector must still return a well-formed
// response with workflow_id / plan_id / message / approval_id surfaced.
func TestProjectStepGateToHTTP_NilStep(t *testing.T) {
	resp := ProjectStepGateToHTTP("", "plan-42", nil,
		ApproverMeta{ApprovalID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		"Step approved", false)

	if resp.WorkflowID != "" {
		t.Errorf("WorkflowID = %q, want empty", resp.WorkflowID)
	}
	if resp.PlanID != "plan-42" {
		t.Errorf("PlanID = %q, want plan-42", resp.PlanID)
	}
	if resp.Message != "Step approved" {
		t.Errorf("Message = %q, want 'Step approved'", resp.Message)
	}
	if resp.ApprovalID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("ApprovalID = %q, want aaaaaaaa-...", resp.ApprovalID)
	}
	if resp.RetryContext.GateCount != 0 {
		t.Errorf("RetryContext.GateCount = %d, want 0 (no WCP state)", resp.RetryContext.GateCount)
	}
	if resp.StepID != "" {
		t.Errorf("StepID = %q, want empty (nil step)", resp.StepID)
	}
}

// TestProjectStepGateToHTTP_ApprovedStep asserts the happy-path projection for
// a step that was approved via the WCP queue: decision resolves to "allow",
// approved_by / approved_at populate from the step row, rejected_* stay empty,
// and retry_context mirrors the step counters.
func TestProjectStepGateToHTTP_ApprovedStep(t *testing.T) {
	approvedAt := time.Date(2026, 4, 22, 10, 30, 0, 0, time.UTC)
	firstAttempt := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	gateChecked := time.Date(2026, 4, 22, 10, 5, 0, 0, time.UTC)
	approved := ApprovalStatusApproved
	key := "pay-vendor-42"

	step := &WorkflowStep{
		WorkflowID:      "wf_abc",
		StepID:          "step-1",
		Decision:        GateDecisionRequireApproval,
		DecisionReason:  "High-value transfer requires oversight",
		ApprovalStatus:  &approved,
		ApprovedBy:      "fraud.analyst@banking.example",
		ApprovedAt:      &approvedAt,
		GateCount:       2,
		CompletionCount: 0,
		LastDecision:    GateDecisionRequireApproval,
		IdempotencyKey:  &key,
		FirstAttemptAt:  &firstAttempt,
		GateCheckedAt:   gateChecked,
		PoliciesMatched: json.RawMessage(`[{"policy_id":"p1","policy_name":"High-Value Wire","action":"require_approval"}]`),
	}

	resp := ProjectStepGateToHTTP("wf_abc", "plan-abc", step,
		ApproverMeta{ApprovalID: "318a270f-0000-0000-0000-000000000000"},
		"Step approved", false)

	if resp.Decision != GateDecisionAllow {
		t.Errorf("Decision = %q, want allow (approved require_approval → allow)", resp.Decision)
	}
	if !strings.HasPrefix(resp.Reason, "Approved:") {
		t.Errorf("Reason = %q, want 'Approved:' prefix", resp.Reason)
	}
	if resp.ApprovedBy != "fraud.analyst@banking.example" {
		t.Errorf("ApprovedBy = %q, want fraud.analyst@banking.example", resp.ApprovedBy)
	}
	if resp.ApprovedAt == nil || !resp.ApprovedAt.Equal(approvedAt) {
		t.Errorf("ApprovedAt = %v, want %v", resp.ApprovedAt, approvedAt)
	}
	if resp.RejectedBy != "" {
		t.Errorf("RejectedBy = %q, want empty on approval", resp.RejectedBy)
	}
	if resp.RejectedAt != nil {
		t.Errorf("RejectedAt = %v, want nil on approval", resp.RejectedAt)
	}
	if resp.RetryContext.GateCount != 2 {
		t.Errorf("RetryContext.GateCount = %d, want 2", resp.RetryContext.GateCount)
	}
	if resp.RetryContext.IdempotencyKey != "pay-vendor-42" {
		t.Errorf("RetryContext.IdempotencyKey = %q, want pay-vendor-42", resp.RetryContext.IdempotencyKey)
	}
	if len(resp.PoliciesMatched) != 1 || resp.PoliciesMatched[0].PolicyID != "p1" {
		t.Errorf("PoliciesMatched = %+v, want one policy with ID p1", resp.PoliciesMatched)
	}
}

// TestProjectStepGateToHTTP_RejectedStep mirrors the approved case but on the
// reject path: decision resolves to "block", rejected_by / rejected_at populate
// (approved_* stay empty), workflow is presumed aborted by the caller.
func TestProjectStepGateToHTTP_RejectedStep(t *testing.T) {
	rejectedAt := time.Date(2026, 4, 22, 11, 0, 0, 0, time.UTC)
	firstAttempt := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	rejected := ApprovalStatusRejected

	step := &WorkflowStep{
		WorkflowID:     "wf_xyz",
		StepID:         "step-2",
		Decision:       GateDecisionRequireApproval,
		DecisionReason: "PII leak risk",
		ApprovalStatus: &rejected,
		ApprovedBy:     "fraud.analyst@banking.example", // same column is reused on rejection
		ApprovedAt:     &rejectedAt,
		GateCount:      1,
		LastDecision:   GateDecisionRequireApproval,
		FirstAttemptAt: &firstAttempt,
		GateCheckedAt:  firstAttempt,
	}

	resp := ProjectStepGateToHTTP("wf_xyz", "", step, ApproverMeta{}, "Step rejected, workflow aborted", false)

	if resp.Decision != GateDecisionBlock {
		t.Errorf("Decision = %q, want block (rejected require_approval → block)", resp.Decision)
	}
	if !strings.HasPrefix(resp.Reason, "Rejected:") {
		t.Errorf("Reason = %q, want 'Rejected:' prefix", resp.Reason)
	}
	if resp.RejectedBy != "fraud.analyst@banking.example" {
		t.Errorf("RejectedBy = %q, want fraud.analyst@banking.example", resp.RejectedBy)
	}
	if resp.RejectedAt == nil || !resp.RejectedAt.Equal(rejectedAt) {
		t.Errorf("RejectedAt = %v, want %v", resp.RejectedAt, rejectedAt)
	}
	if resp.ApprovedBy != "" {
		t.Errorf("ApprovedBy = %q, want empty on rejection", resp.ApprovedBy)
	}
	if resp.ApprovedAt != nil {
		t.Errorf("ApprovedAt = %v, want nil on rejection", resp.ApprovedAt)
	}
}

// TestProjectStepGateToHTTP_ExpiredStep verifies the #2654 auto-timeout path:
// an expired require_approval step blocks like a reject, but is surfaced
// DISTINCTLY ("Expired" reason + status="expired"), and — because a timeout is
// not a human decision — neither approved_* NOR rejected_* identity is populated.
func TestProjectStepGateToHTTP_ExpiredStep(t *testing.T) {
	expiredAt := time.Date(2026, 4, 23, 11, 0, 0, 0, time.UTC)
	firstAttempt := time.Date(2026, 4, 22, 11, 0, 0, 0, time.UTC)
	expired := ApprovalStatusExpired

	step := &WorkflowStep{
		WorkflowID:     "wf_exp",
		StepID:         "step-3",
		Decision:       GateDecisionRequireApproval,
		DecisionReason: "PII leak risk",
		ApprovalStatus: &expired,
		ApprovedBy:     "system:auto-expired", // system actor marker, not a human reviewer
		ApprovedAt:     &expiredAt,
		GateCount:      1,
		LastDecision:   GateDecisionRequireApproval,
		FirstAttemptAt: &firstAttempt,
		GateCheckedAt:  firstAttempt,
	}

	resp := ProjectStepGateToHTTP("wf_exp", "", step, ApproverMeta{}, "Step expired, workflow aborted", false)

	if resp.Decision != GateDecisionBlock {
		t.Errorf("Decision = %q, want block (expired require_approval → block)", resp.Decision)
	}
	if !strings.HasPrefix(resp.Reason, "Expired") {
		t.Errorf("Reason = %q, want 'Expired' prefix", resp.Reason)
	}
	if resp.Status != "expired" {
		t.Errorf("Status mirror = %q, want 'expired'", resp.Status)
	}
	// A timeout is not a human rejection — RejectedBy/RejectedAt must stay empty
	// so the expiry is never attributed to a human reviewer.
	if resp.RejectedBy != "" {
		t.Errorf("RejectedBy = %q, want empty on expiry", resp.RejectedBy)
	}
	if resp.RejectedAt != nil {
		t.Errorf("RejectedAt = %v, want nil on expiry", resp.RejectedAt)
	}
	if resp.ApprovedBy != "" {
		t.Errorf("ApprovedBy = %q, want empty on expiry", resp.ApprovedBy)
	}
}

// TestProjectStepGateToHTTP_PendingStep verifies the edge case of projecting
// a step whose approval is still pending — neither approved_* nor rejected_*
// populate, and decision stays as require_approval.
func TestProjectStepGateToHTTP_PendingStep(t *testing.T) {
	pending := ApprovalStatusPending
	step := &WorkflowStep{
		WorkflowID:     "wf_p",
		StepID:         "step-p",
		Decision:       GateDecisionRequireApproval,
		ApprovalStatus: &pending,
		GateCount:      1,
		LastDecision:   GateDecisionRequireApproval,
	}

	resp := ProjectStepGateToHTTP("wf_p", "", step, ApproverMeta{}, "pending", false)

	if resp.Decision != GateDecisionRequireApproval {
		t.Errorf("Decision = %q, want require_approval", resp.Decision)
	}
	if resp.ApprovedBy != "" || resp.RejectedBy != "" {
		t.Errorf("ApprovedBy=%q RejectedBy=%q — both should be empty on pending",
			resp.ApprovedBy, resp.RejectedBy)
	}
}

// TestProjectStepGateToHTTP_AllowDecision verifies a non-approval step (plain
// allow) projects unchanged — no approval suffix, no status mutation.
func TestProjectStepGateToHTTP_AllowDecision(t *testing.T) {
	step := &WorkflowStep{
		WorkflowID:     "wf_a",
		StepID:         "step-a",
		Decision:       GateDecisionAllow,
		DecisionReason: "No policies configured",
		GateCount:      1,
	}

	resp := ProjectStepGateToHTTP("wf_a", "", step, ApproverMeta{}, "", false)

	if resp.Decision != GateDecisionAllow {
		t.Errorf("Decision = %q, want allow", resp.Decision)
	}
	if resp.Reason != "No policies configured" {
		t.Errorf("Reason = %q, want no-suffix passthrough", resp.Reason)
	}
}

// TestProjectStepGateToHTTP_ReasonPrefixEmptyOriginal covers the case where
// the step's original decision_reason is empty — the projector should still
// produce a coherent "Approved"/"Rejected" response without dangling ': ' text.
func TestProjectStepGateToHTTP_ReasonPrefixEmptyOriginal(t *testing.T) {
	approved := ApprovalStatusApproved
	rejected := ApprovalStatusRejected

	stepAppr := &WorkflowStep{
		StepID:         "s1",
		Decision:       GateDecisionRequireApproval,
		ApprovalStatus: &approved,
	}
	respAppr := ProjectStepGateToHTTP("wf", "", stepAppr, ApproverMeta{}, "", false)
	if respAppr.Reason != "Approved" {
		t.Errorf("empty-reason approved: Reason = %q, want 'Approved'", respAppr.Reason)
	}

	stepRej := &WorkflowStep{
		StepID:         "s2",
		Decision:       GateDecisionRequireApproval,
		ApprovalStatus: &rejected,
	}
	respRej := ProjectStepGateToHTTP("wf", "", stepRej, ApproverMeta{}, "", false)
	if respRej.Reason != "Rejected" {
		t.Errorf("empty-reason rejected: Reason = %q, want 'Rejected'", respRej.Reason)
	}
}

// TestProjectStepGateToHTTP_JSONFieldSet asserts the exact JSON field set
// matches HITLResponseFieldSet — the contract test at the orchestrator level
// depends on this baseline. A new field on StepGateHTTPResponse that doesn't
// add to HITLResponseFieldSet fails here, preventing silent drift.
func TestProjectStepGateToHTTP_JSONFieldSet(t *testing.T) {
	// Populate every field so none get omitempty-suppressed.
	approvedAt := time.Now()
	rejectedAt := approvedAt.Add(time.Minute)
	approved := ApprovalStatusApproved
	rejected := ApprovalStatusRejected

	approvedStep := &WorkflowStep{
		StepID:          "s",
		Decision:        GateDecisionRequireApproval,
		DecisionReason:  "policy match",
		ApprovalStatus:  &approved,
		ApprovedBy:      "a",
		ApprovedAt:      &approvedAt,
		GateCount:       1,
		FirstAttemptAt:  &approvedAt,
		GateCheckedAt:   approvedAt,
		PoliciesMatched: json.RawMessage(`[{"policy_id":"p"}]`),
	}
	resp := ProjectStepGateToHTTP("wf", "plan", approvedStep,
		ApproverMeta{ApprovalID: "aaaa"},
		"msg", false)

	rejStep := *approvedStep
	rejStep.ApprovalStatus = &rejected
	rejStep.ApprovedAt = &rejectedAt
	rejResp := ProjectStepGateToHTTP("wf", "plan", &rejStep,
		ApproverMeta{ApprovalID: "aaaa"}, "msg", false)

	assertFieldSet := func(t *testing.T, tag string, r StepGateHTTPResponse, wantField string, mustExist bool) {
		t.Helper()
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal %s: %v", tag, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal %s: %v", tag, err)
		}
		_, present := m[wantField]
		if mustExist && !present {
			t.Errorf("%s: expected field %q in JSON, keys=%v", tag, wantField, keys(m))
		}
	}

	// Split expected-present-on-which-path into two groups:
	// Approved/pending path should never surface rejected_*; rejected path should.
	mustOnApproved := []string{
		"workflow_id", "plan_id", "step_id", "status", "decision", "reason",
		"approval_status", "approval_id", "approved_by", "approved_at",
		"policies_matched", "retry_context", "message",
	}
	for _, f := range mustOnApproved {
		assertFieldSet(t, "approved-path", resp, f, true)
	}
	mustOnRejected := []string{
		"workflow_id", "plan_id", "step_id", "status", "decision", "reason",
		"approval_status", "approval_id", "rejected_by", "rejected_at",
		"policies_matched", "retry_context", "message",
	}
	for _, f := range mustOnRejected {
		assertFieldSet(t, "rejected-path", rejResp, f, true)
	}

	// HITLResponseFieldSet must be a superset of every field we actually emit.
	emitted := map[string]struct{}{}
	for _, m := range []StepGateHTTPResponse{resp, rejResp} {
		raw, _ := json.Marshal(m)
		var dm map[string]json.RawMessage
		_ = json.Unmarshal(raw, &dm)
		for k := range dm {
			emitted[k] = struct{}{}
		}
	}
	for f := range emitted {
		if !contains(HITLResponseFieldSet, f) {
			t.Errorf("emitted field %q is not in HITLResponseFieldSet — add it there",
				f)
		}
	}
}

// TestProjectStepGateToHTTP_LegacyStatusFieldMirror locks down the back-compat
// contract: pre-v7.4.0 callers reading a top-level `status` field from
// approve/reject responses must continue to see it populated as a mirror of
// `approval_status`. The platform projector populates it whenever the step
// row has an ApprovalStatus set; nil-ApprovalStatus steps (e.g. initial gate
// responses) legitimately omit it via omitempty.
func TestProjectStepGateToHTTP_LegacyStatusFieldMirror(t *testing.T) {
	approved := ApprovalStatusApproved
	rejected := ApprovalStatusRejected
	pending := ApprovalStatusPending

	cases := []struct {
		name       string
		status     *ApprovalStatus
		wantStatus string
	}{
		{"approved", &approved, "approved"},
		{"rejected", &rejected, "rejected"},
		{"pending", &pending, "pending"},
		{"nil-approval-status", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			step := &WorkflowStep{
				StepID:         "s",
				Decision:       GateDecisionRequireApproval,
				ApprovalStatus: tc.status,
				GateCount:      1,
			}
			resp := ProjectStepGateToHTTP("wf", "", step, ApproverMeta{}, "msg", false)
			if resp.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q — back-compat mirror of ApprovalStatus broken",
					resp.Status, tc.wantStatus)
			}

			// JSON round-trip — the legacy field must appear on the wire when populated
			// and be omitted (omitempty) when not.
			raw, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var m map[string]json.RawMessage
			_ = json.Unmarshal(raw, &m)
			_, present := m["status"]
			wantPresent := tc.wantStatus != ""
			if present != wantPresent {
				t.Errorf("status field presence=%v, want %v", present, wantPresent)
			}
		})
	}
}

func TestDeriveHITLApprovalID(t *testing.T) {
	a := DeriveHITLApprovalID("wf", "s")
	b := DeriveHITLApprovalID("wf", "s")
	if a == "" || a != b {
		t.Errorf("DeriveHITLApprovalID non-deterministic or empty: a=%q b=%q", a, b)
	}

	// Different step id → different UUID
	c := DeriveHITLApprovalID("wf", "s2")
	if a == c {
		t.Errorf("expected different UUIDs for different stepIDs, got %q twice", a)
	}

	// Empty inputs → empty
	if DeriveHITLApprovalID("", "s") != "" {
		t.Error("empty workflowID should return empty ID")
	}
	if DeriveHITLApprovalID("wf", "") != "" {
		t.Error("empty stepID should return empty ID")
	}
}

// Helpers -------------------------------------------------------------

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(s []string, target string) bool {
	for _, v := range s {
		if v == target {
			return true
		}
	}
	return false
}
