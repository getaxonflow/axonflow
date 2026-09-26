// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// #4249 (row 5698298886, ADR-067 Decision 5): a re-evaluation never clears an
// approval hold. A step whose row holds pending, rejected or expired refuses
// every gate call that would evaluate afresh (409 APPROVAL_HOLD, the row left
// as it was); the idempotent retry keeps returning the cached decision; a step
// with no hold, or an approved one, evaluates exactly as before. A checkpoint
// resume never reopens a workflow a rejection or an expiry aborted, and refuses
// before it resets the status. The upsert never writes a missing approval
// status over a hold.

// holdTestStep is the step every cell gates.
const holdTestStep = "step-held"

// seedStepRow gives holdTestStep a row in the given approval state on an
// in_progress workflow. "none" is a row with no approval status (an allowed
// step); the others are a require_approval row created by override, as MAP
// creates its holds, then moved to the status.
func seedStepRow(t *testing.T, svc *Service, repo *MockRepository, workflowID, state string) {
	t.Helper()
	ctx := context.Background()
	if state == "none" {
		allow := GateDecisionAllow
		if _, err := svc.StepGate(ctx, workflowID, holdTestStep, &StepGateRequest{StepType: StepTypeToolCall, GateOverride: &allow},
			"tenant-1", "org-1", "user-1", "client-1"); err != nil {
			t.Fatalf("seed an allowed row: %v", err)
		}
		return
	}
	requireApproval := GateDecisionRequireApproval
	if _, err := svc.StepGate(ctx, workflowID, holdTestStep, &StepGateRequest{StepType: StepTypeToolCall, GateOverride: &requireApproval},
		"tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("seed a held row: %v", err)
	}
	if state == string(ApprovalStatusPending) {
		return
	}
	// The status is written on the row directly, leaving the workflow
	// in_progress, so the gate reaches the rule rather than the terminal-state
	// refusal (RejectStep and the expiry sweeper also abort; those shapes are
	// the checkpoint cells below).
	if err := repo.UpdateStepApproval(ctx, workflowID, holdTestStep, ApprovalStatus(state), "reviewer@example.com", "seeded"); err != nil {
		t.Fatalf("seed status %s: %v", state, err)
	}
}

// stepRow reads holdTestStep's row.
func stepRow(t *testing.T, repo *MockRepository, workflowID string) WorkflowStep {
	t.Helper()
	row, err := repo.GetStepDecision(context.Background(), workflowID, holdTestStep)
	if err != nil || row == nil {
		t.Fatalf("read the row: (%v, %v)", row, err)
	}
	return *row
}

func statusOf(row WorkflowStep) string {
	if row.ApprovalStatus == nil {
		return "none"
	}
	return string(*row.ApprovalStatus)
}

// TestAReevaluationNeverClearsAnApprovalHold is the cell table: the existing
// row's approval state (none, pending, approved, rejected, expired) against the
// four call kinds. The evaluator answers allow, the answer that clears a hold
// when the rule is missing.
func TestAReevaluationNeverClearsAnApprovalHold(t *testing.T) {
	requireApproval := GateDecisionRequireApproval
	allow := GateDecisionAllow
	calls := []struct {
		name string
		req  StepGateRequest
	}{
		{"idempotent", StepGateRequest{StepType: StepTypeLLMCall}},
		{"reevaluate", StepGateRequest{StepType: StepTypeLLMCall, RetryPolicy: RetryPolicyReevaluate}},
		{"override require_approval", StepGateRequest{StepType: StepTypeLLMCall, GateOverride: &requireApproval}},
		{"override allow", StepGateRequest{StepType: StepTypeLLMCall, GateOverride: &allow}},
	}
	// want: "cached" (the cached decision, nothing evaluated), "evaluated" (a
	// fresh decision written), "refused" (ApprovalHoldError, row unchanged).
	want := map[string]map[string]string{
		"none":     {"idempotent": "cached", "reevaluate": "evaluated", "override require_approval": "evaluated", "override allow": "evaluated"},
		"pending":  {"idempotent": "cached", "reevaluate": "refused", "override require_approval": "refused", "override allow": "refused"},
		"approved": {"idempotent": "cached", "reevaluate": "evaluated", "override require_approval": "evaluated", "override allow": "evaluated"},
		"rejected": {"idempotent": "cached", "reevaluate": "refused", "override require_approval": "refused", "override allow": "refused"},
		"expired":  {"idempotent": "cached", "reevaluate": "refused", "override require_approval": "refused", "override allow": "refused"},
	}
	for _, state := range []string{"none", "pending", "approved", "rejected", "expired"} {
		for _, call := range calls {
			t.Run(state+"/"+call.name, func(t *testing.T) {
				counter := newCountingEvaluator(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
				svc, repo := setupTestService(counter)
				workflowID := createTestWorkflow(t, svc)
				seedStepRow(t, svc, repo, workflowID, state)
				before := stepRow(t, repo, workflowID)
				evaluationsBefore := counter.calls.Load()

				req := call.req
				resp, err := svc.StepGate(context.Background(), workflowID, holdTestStep, &req, "tenant-1", "org-1", "user-1", "client-1")
				after := stepRow(t, repo, workflowID)

				switch want[state][call.name] {
				case "refused":
					var hold *ApprovalHoldError
					if !errors.As(err, &hold) {
						t.Fatalf("StepGate = (%+v, %v), want an ApprovalHoldError", resp, err)
					}
					if hold.WorkflowID != workflowID || hold.StepID != holdTestStep || string(hold.Status) != state {
						t.Errorf("the refusal names %s/%s holding %s, want %s/%s holding %s", hold.WorkflowID, hold.StepID, hold.Status, workflowID, holdTestStep, state)
					}
					if msg := err.Error(); !strings.Contains(msg, holdTestStep) || !strings.Contains(msg, state) {
						t.Errorf("the refusal's message %q does not name the step and its hold", msg)
					}
					if statusOf(after) != state || after.Decision != before.Decision || after.DecisionReason != before.DecisionReason ||
						after.StepType != before.StepType || after.GateCount != before.GateCount || after.LastDecision != before.LastDecision {
						t.Errorf("the row moved: before %s/%s/%s gate_count=%d, after %s/%s/%s gate_count=%d",
							statusOf(before), before.Decision, before.StepType, before.GateCount, statusOf(after), after.Decision, after.StepType, after.GateCount)
					}
					if counter.calls.Load() != evaluationsBefore {
						t.Errorf("the evaluator ran on a refused re-evaluation")
					}
				case "cached":
					if err != nil || resp == nil || !resp.Cached {
						t.Fatalf("StepGate = (%+v, %v), want the cached decision", resp, err)
					}
					if statusOf(after) != state || after.Decision != before.Decision {
						t.Errorf("a cached retry moved the row: %s/%s -> %s/%s", statusOf(before), before.Decision, statusOf(after), after.Decision)
					}
				case "evaluated":
					if err != nil || resp == nil || resp.Cached {
						t.Fatalf("StepGate = (%+v, %v), want a fresh evaluation", resp, err)
					}
					if after.GateCount != before.GateCount+1 {
						t.Errorf("gate_count %d -> %d, want a fresh write", before.GateCount, after.GateCount)
					}
				}
			})
		}
	}
}

// A step that has never been gated evaluates as before: the rule needs a row.
func TestAFirstGateHasNoHoldToRefuse(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	workflowID := createTestWorkflow(t, svc)
	resp, err := svc.StepGate(context.Background(), workflowID, "fresh", &StepGateRequest{StepType: StepTypeLLMCall, RetryPolicy: RetryPolicyReevaluate},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil || resp.Decision != GateDecisionAllow || resp.Cached {
		t.Fatalf("first gate = (%+v, %v), want a fresh allow", resp, err)
	}
}

// The gate route answers the refusal 409 APPROVAL_HOLD in the triplet envelope,
// its message naming the step and the hold.
func TestTheGateRouteAnswersAnApprovalHold409(t *testing.T) {
	handler, svc, repo := setupTestHandlerWith(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "wf"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	seedStepRow(t, svc, repo, wf.WorkflowID, "pending")

	body, _ := json.Marshal(StepGateRequest{StepType: StepTypeLLMCall, RetryPolicy: RetryPolicyReevaluate})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+wf.WorkflowID+"/steps/"+holdTestStep+"/gate", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": holdTestStep})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	assertApprovalHold409(t, rr, holdTestStep, "pending")
	if got := statusOf(stepRow(t, repo, wf.WorkflowID)); got != "pending" {
		t.Errorf("approval_status after the refused call = %s, want pending", got)
	}
}

func assertApprovalHold409(t *testing.T, rr *httptest.ResponseRecorder, stepID, status string) {
	t.Helper()
	if rr.Code != http.StatusConflict {
		t.Fatalf("status %d body %s, want 409", rr.Code, rr.Body.String())
	}
	var body ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	if body.Code != ErrorCodeApprovalHold || body.Error != "approval_hold" {
		t.Errorf("code %q error %q, want %q and approval_hold", body.Code, body.Error, ErrorCodeApprovalHold)
	}
	if !strings.Contains(body.Message, "step "+stepID+" holds approval "+status) {
		t.Errorf("message %q does not name step %s holding %s", body.Message, stepID, status)
	}
}

// --- checkpoint resume ---

// resumeCase builds a workflow in a named shape and returns its id.
type resumeCase struct {
	name        string
	build       func(t *testing.T, svc *Service, repo *MockRepository) string
	wantRefusal string         // "" = resumes; else the held status named
	wantStatus  WorkflowStatus // the workflow's status after the call
}

func gate(t *testing.T, svc *Service, workflowID, stepID string, decision GateDecision) {
	t.Helper()
	d := decision
	if _, err := svc.StepGate(context.Background(), workflowID, stepID, &StepGateRequest{StepType: StepTypeToolCall, GateOverride: &d},
		"tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("gate %s: %v", stepID, err)
	}
}

func checkpointResumeCases() []resumeCase {
	return []resumeCase{
		{
			name: "aborted by a rejection",
			build: func(t *testing.T, svc *Service, _ *MockRepository) string {
				id := createTestWorkflow(t, svc)
				gate(t, svc, id, "s1", GateDecisionRequireApproval)
				if err := svc.RejectStep(context.Background(), id, "s1", "tenant-1", "org-1", "reviewer@example.com", "no"); err != nil {
					t.Fatalf("reject: %v", err)
				}
				return id
			},
			wantRefusal: "rejected", wantStatus: WorkflowStatusAborted,
		},
		{
			name: "aborted by an expiry",
			build: func(t *testing.T, svc *Service, repo *MockRepository) string {
				id := createTestWorkflow(t, svc)
				gate(t, svc, id, "s1", GateDecisionRequireApproval)
				// The sweeper's two writes (hitl_wcp_community.go): the step
				// expired, the workflow aborted.
				_ = repo.UpdateStepApproval(context.Background(), id, "s1", ApprovalStatusExpired, "system:auto-expired", "")
				_ = repo.Abort(context.Background(), id, "Step s1 auto-expired")
				return id
			},
			wantRefusal: "expired", wantStatus: WorkflowStatusAborted,
		},
		{
			name: "aborted while its checkpoint step is pending",
			build: func(t *testing.T, svc *Service, _ *MockRepository) string {
				id := createTestWorkflow(t, svc)
				gate(t, svc, id, "s1", GateDecisionRequireApproval)
				if err := svc.AbortWorkflow(context.Background(), id, "operator abort", "tenant-1", "org-1"); err != nil {
					t.Fatalf("abort: %v", err)
				}
				return id
			},
			wantRefusal: "pending", wantStatus: WorkflowStatusAborted,
		},
		{
			name: "aborted by a failure",
			build: func(t *testing.T, svc *Service, _ *MockRepository) string {
				id := createTestWorkflow(t, svc)
				gate(t, svc, id, "s1", GateDecisionAllow)
				if err := svc.AbortWorkflow(context.Background(), id, "the step failed", "tenant-1", "org-1"); err != nil {
					t.Fatalf("abort: %v", err)
				}
				return id
			},
			wantStatus: WorkflowStatusInProgress,
		},
		{
			name: "in_progress with its checkpoint step pending",
			build: func(t *testing.T, svc *Service, _ *MockRepository) string {
				id := createTestWorkflow(t, svc)
				gate(t, svc, id, "s1", GateDecisionRequireApproval)
				return id
			},
			wantRefusal: "pending", wantStatus: WorkflowStatusInProgress,
		},
		{
			name: "in_progress with no hold",
			build: func(t *testing.T, svc *Service, _ *MockRepository) string {
				id := createTestWorkflow(t, svc)
				gate(t, svc, id, "s1", GateDecisionAllow)
				return id
			},
			wantStatus: WorkflowStatusInProgress,
		},
	}
}

func TestACheckpointResumeNeverReopensAHold(t *testing.T) {
	for _, tc := range checkpointResumeCases() {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
			id := tc.build(t, svc, repo)
			before, _ := repo.GetByID(context.Background(), id)

			resp, err := svc.ResumeFromLastCheckpoint(context.Background(), id, "tenant-1", "org-1", "")
			after, _ := repo.GetByID(context.Background(), id)

			if tc.wantRefusal == "" {
				if err != nil || resp == nil {
					t.Fatalf("resume = (%+v, %v), want it to resume", resp, err)
				}
			} else {
				var hold *ApprovalHoldError
				if !errors.As(err, &hold) || string(hold.Status) != tc.wantRefusal || hold.StepID != "s1" {
					t.Fatalf("resume = (%+v, %v), want an ApprovalHoldError naming s1 holding %s", resp, err, tc.wantRefusal)
				}
				// The rows are as they were: the refusal came before any write.
				if len(after.Steps) != len(before.Steps) || statusOf(after.Steps[0]) != statusOf(before.Steps[0]) ||
					after.Steps[0].GateCount != before.Steps[0].GateCount {
					t.Errorf("the step row moved on a refused resume: %s gate_count=%d -> %s gate_count=%d",
						statusOf(before.Steps[0]), before.Steps[0].GateCount, statusOf(after.Steps[0]), after.Steps[0].GateCount)
				}
			}
			if after.Status != tc.wantStatus {
				t.Errorf("workflow status after the resume = %s, want %s", after.Status, tc.wantStatus)
			}
		})
	}
}

// Enterprise resumes from ANY checkpoint: an earlier step's checkpoint on a
// workflow a LATER step's rejection aborted is refused too, naming the rejected
// step, and the workflow stays aborted.
func TestResumingAnEarlierCheckpointAfterALaterRejectionIsRefused(t *testing.T) {
	svc, repo := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	ctx := context.Background()
	id := createTestWorkflow(t, svc)
	gate(t, svc, id, "s1", GateDecisionAllow)
	gate(t, svc, id, "s2", GateDecisionRequireApproval)
	if err := svc.RejectStep(ctx, id, "s2", "tenant-1", "org-1", "reviewer@example.com", "no"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	cps, _ := repo.ListCheckpoints(ctx, id)
	var s1 *Checkpoint
	for i := range cps {
		if cps[i].StepID == "s1" {
			s1 = &cps[i]
		}
	}
	if s1 == nil {
		t.Fatalf("no checkpoint for s1 in %+v", cps)
	}

	_, err := svc.ResumeFromCheckpoint(ctx, id, s1.ID, "tenant-1", "org-1", "")

	var hold *ApprovalHoldError
	if !errors.As(err, &hold) || hold.StepID != "s2" || hold.Status != ApprovalStatusRejected {
		t.Fatalf("resume from s1 = %v, want an ApprovalHoldError naming s2 rejected", err)
	}
	if wf, _ := repo.GetByID(ctx, id); wf.Status != WorkflowStatusAborted {
		t.Errorf("workflow status = %s, want aborted", wf.Status)
	}
}

// Both checkpoint-resume routes answer the refusal 409 APPROVAL_HOLD.
func TestTheCheckpointResumeRoutesAnswerAnApprovalHold409(t *testing.T) {
	handler, svc, repo := setupTestHandlerWith(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	ctx := context.Background()
	wf, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "wf"}, "tenant-1", "org-1", "user-1", "client-1")
	gate(t, svc, wf.WorkflowID, "s1", GateDecisionRequireApproval)
	if err := svc.RejectStep(ctx, wf.WorkflowID, "s1", "tenant-1", "org-1", "reviewer@example.com", "no"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	cp, _ := repo.GetLastResumableCheckpoint(ctx, wf.WorkflowID)
	if cp == nil {
		t.Fatalf("no resumable checkpoint")
	}

	routes := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		path string
		vars map[string]string
	}{
		{"last", handler.ResumeFromLastCheckpoint, "/api/v1/workflows/" + wf.WorkflowID + "/checkpoints/resume", map[string]string{"id": wf.WorkflowID}},
		{"by id", handler.ResumeFromCheckpoint, "/api/v1/workflows/" + wf.WorkflowID + "/checkpoints/" + strconv.FormatInt(cp.ID, 10) + "/resume",
			map[string]string{"id": wf.WorkflowID, "checkpoint_id": strconv.FormatInt(cp.ID, 10)}},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, route.path, nil)
			req = mux.SetURLVars(req, route.vars)
			req.Header.Set("X-Org-ID", "org-1")
			req.Header.Set("X-Tenant-ID", "tenant-1")
			rr := httptest.NewRecorder()
			route.call(rr, req)
			assertApprovalHold409(t, rr, "s1", "rejected")
			if got, _ := repo.GetByID(ctx, wf.WorkflowID); got.Status != WorkflowStatusAborted {
				t.Errorf("workflow status = %s, want aborted", got.Status)
			}
		})
	}
}

// --- the upsert, in the mock (the Postgres statement is proven alone in
// repository_integration_test.go) ---

func TestTheMockUpsertNeverMovesAHold(t *testing.T) {
	pending, approved := ApprovalStatusPending, ApprovalStatusApproved
	cases := []struct {
		name         string
		existing     string // "none" or an approval status; seeded tool_call require_approval (none: allow)
		incoming     *ApprovalStatus
		incomingDec  GateDecision
		wantStatus   string
		wantDecision GateDecision
		wantType     StepType // the held row keeps its step_type; a landed write carries llm_call
		wantApprover string
	}{
		{"nothing over pending", "pending", nil, GateDecisionAllow, "pending", GateDecisionRequireApproval, StepTypeToolCall, ""},
		{"nothing over rejected", "rejected", nil, GateDecisionAllow, "rejected", GateDecisionRequireApproval, StepTypeToolCall, "reviewer@example.com"},
		{"nothing over expired", "expired", nil, GateDecisionAllow, "expired", GateDecisionRequireApproval, StepTypeToolCall, "reviewer@example.com"},
		{"pending over rejected", "rejected", &pending, GateDecisionRequireApproval, "rejected", GateDecisionRequireApproval, StepTypeToolCall, "reviewer@example.com"},
		{"pending over expired", "expired", &pending, GateDecisionRequireApproval, "expired", GateDecisionRequireApproval, StepTypeToolCall, "reviewer@example.com"},
		{"approved over pending is kept (only a decision moves a hold)", "pending", &approved, GateDecisionAllow, "pending", GateDecisionRequireApproval, StepTypeToolCall, ""},
		{"pending over nothing", "none", &pending, GateDecisionRequireApproval, "pending", GateDecisionRequireApproval, StepTypeLLMCall, ""},
		{"nothing over approved", "approved", nil, GateDecisionAllow, "none", GateDecisionAllow, StepTypeLLMCall, "reviewer@example.com"},
		{"a new hold over approved clears the approver", "approved", &pending, GateDecisionRequireApproval, "pending", GateDecisionRequireApproval, StepTypeLLMCall, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := setupTestService(&fixedEvaluator{decision: GateDecisionAllow})
			id := createTestWorkflow(t, svc)
			seedStepRow(t, svc, repo, id, tc.existing)
			before := stepRow(t, repo, id)

			write := &WorkflowStep{WorkflowID: id, StepID: holdTestStep, StepType: StepTypeLLMCall, Decision: tc.incomingDec,
				DecisionReason: "rewrite", ApprovalStatus: tc.incoming, PoliciesMatched: []byte(`[{"policy_id":"from-the-racer"}]`)}
			if err := repo.AddStep(context.Background(), write); err != nil {
				t.Fatalf("AddStep: %v", err)
			}

			row := stepRow(t, repo, id)
			if statusOf(row) != tc.wantStatus || row.Decision != tc.wantDecision || row.StepType != tc.wantType || row.ApprovedBy != tc.wantApprover {
				t.Errorf("row = %s/%s/%s approved_by=%q, want %s/%s/%s approved_by=%q",
					statusOf(row), row.Decision, row.StepType, row.ApprovedBy, tc.wantStatus, tc.wantDecision, tc.wantType, tc.wantApprover)
			}
			if tc.wantType == StepTypeToolCall && (row.DecisionReason != before.DecisionReason || string(row.PoliciesMatched) != string(before.PoliciesMatched)) {
				t.Errorf("a kept hold took the write's reason %q / policies %s", row.DecisionReason, row.PoliciesMatched)
			}
		})
	}
}

// A re-hold of a row whose status is NULL but still names an approver (approve,
// then a re-evaluation that allowed) clears that approver: the new hold has not
// been approved by anyone.
func TestTheMockUpsertClearsAStaleApproverOnARehold(t *testing.T) {
	svc, repo := setupTestService(&fixedEvaluator{decision: GateDecisionAllow})
	id := createTestWorkflow(t, svc)
	seedStepRow(t, svc, repo, id, "approved")
	ctx := context.Background()
	if err := repo.AddStep(ctx, &WorkflowStep{WorkflowID: id, StepID: holdTestStep, StepType: StepTypeToolCall, Decision: GateDecisionAllow}); err != nil {
		t.Fatalf("allow write: %v", err)
	}
	if row := stepRow(t, repo, id); statusOf(row) != "none" || row.ApprovedBy != "reviewer@example.com" {
		t.Fatalf("PREMISE: after the allow the row = %s approved_by=%q, want none with the old approver", statusOf(row), row.ApprovedBy)
	}
	pending := ApprovalStatusPending
	if err := repo.AddStep(ctx, &WorkflowStep{WorkflowID: id, StepID: holdTestStep, StepType: StepTypeToolCall, Decision: GateDecisionRequireApproval, ApprovalStatus: &pending}); err != nil {
		t.Fatalf("re-hold: %v", err)
	}
	if row := stepRow(t, repo, id); statusOf(row) != "pending" || row.ApprovedBy != "" || row.ApprovedAt != nil {
		t.Errorf("after the re-hold the row = %s approved_by=%q approved_at=%v, want pending with no approver", statusOf(row), row.ApprovedBy, row.ApprovedAt)
	}
}

// A decision moves a row only out of pending (row 5699811652): after a
// rejection, a racing approval's write is refused and the row stays rejected.
func TestAnApprovalWriteMovesOnlyAPendingRow(t *testing.T) {
	svc, repo := setupTestService(&fixedEvaluator{decision: GateDecisionAllow})
	id := createTestWorkflow(t, svc)
	seedStepRow(t, svc, repo, id, "pending")
	ctx := context.Background()
	if err := svc.RejectStep(ctx, id, holdTestStep, "tenant-1", "org-1", "reviewer@example.com", "rejected in review"); err != nil {
		t.Fatalf("reject: %v", err)
	}

	err := repo.UpdateStepApproval(ctx, id, holdTestStep, ApprovalStatusApproved, "approver@example.com", "late")

	if err == nil || !strings.Contains(err.Error(), "step is not pending approval") || strings.Contains(err.Error(), "not found") {
		t.Errorf("the racing approval write = %v, want refused as not pending (and never read as not found)", err)
	}
	if got := statusOf(stepRow(t, repo, id)); got != "rejected" {
		t.Errorf("approval_status = %s, want rejected", got)
	}
	if err := svc.ApproveStep(ctx, id, holdTestStep, "tenant-1", "org-1", "approver@example.com", "late approve"); err == nil || !strings.Contains(err.Error(), "terminal state") {
		t.Errorf("ApproveStep on the rejection-aborted workflow = %v, want refused as terminal", err)
	}
}

// addStepFailingRepository fails every AddStep once armed.
type addStepFailingRepository struct {
	*MockRepository
	armed bool
}

func (r *addStepFailingRepository) AddStep(ctx context.Context, step *WorkflowStep) error {
	if r.armed {
		return errors.New("connection reset")
	}
	return r.MockRepository.AddStep(ctx, step)
}

// A resume refused AFTER the status reset (here the re-evaluation's write
// fails) restores the workflow to aborted: a refusal never leaves it running.
func TestARefusedResumeRestoresTheAbortedStatus(t *testing.T) {
	repo := &addStepFailingRepository{MockRepository: NewMockRepository()}
	svc := NewService(repo, &fixedEvaluator{decision: GateDecisionAllow}, &ServiceConfig{BaseURL: "https://portal.test"})
	id := createTestWorkflow(t, svc)
	ctx := context.Background()
	gate(t, svc, id, "s1", GateDecisionAllow)
	if err := svc.AbortWorkflow(ctx, id, "the step failed", "tenant-1", "org-1"); err != nil {
		t.Fatalf("abort: %v", err)
	}
	repo.armed = true

	_, err := svc.ResumeFromLastCheckpoint(ctx, id, "tenant-1", "org-1", "")

	if err == nil {
		t.Fatalf("resume with a failing write succeeded")
	}
	if wf, _ := repo.GetByID(ctx, id); wf.Status != WorkflowStatusAborted {
		t.Errorf("workflow status after the refused resume = %s, want aborted", wf.Status)
	}
}

// An aborted workflow with a held step OTHER than the checkpoint's refuses
// before the reset (the pending guard would refuse only after it).
func TestResumingAnAbortedWorkflowWithAnotherHeldStepIsRefusedBeforeTheReset(t *testing.T) {
	svc, repo := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	ctx := context.Background()
	id := createTestWorkflow(t, svc)
	gate(t, svc, id, "s1", GateDecisionAllow)
	gate(t, svc, id, "s2", GateDecisionRequireApproval)
	if err := svc.AbortWorkflow(ctx, id, "operator abort", "tenant-1", "org-1"); err != nil {
		t.Fatalf("abort: %v", err)
	}
	cps, _ := repo.ListCheckpoints(ctx, id)
	var s1 *Checkpoint
	for i := range cps {
		if cps[i].StepID == "s1" {
			s1 = &cps[i]
		}
	}
	if s1 == nil {
		t.Fatalf("no checkpoint for s1")
	}

	_, err := svc.ResumeFromCheckpoint(ctx, id, s1.ID, "tenant-1", "org-1", "")

	var hold *ApprovalHoldError
	if !errors.As(err, &hold) || hold.StepID != "s2" || hold.Status != ApprovalStatusPending {
		t.Fatalf("resume from s1 = %v, want an ApprovalHoldError naming s2 pending", err)
	}
	if wf, _ := repo.GetByID(ctx, id); wf.Status != WorkflowStatusAborted {
		t.Errorf("workflow status = %s, want aborted", wf.Status)
	}
}

// A gate for a new step is refused while ANY step of the workflow is pending,
// not only the last row: an earlier step held again by a re-evaluation keeps
// its step_index, so it is not last (#4249).
func TestAGateForANewStepIsRefusedWhileAnEarlierStepIsPending(t *testing.T) {
	svc, repo := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	ctx := context.Background()
	id := createTestWorkflow(t, svc)
	gate(t, svc, id, "s1", GateDecisionAllow)
	gate(t, svc, id, "s2", GateDecisionAllow)
	gate(t, svc, id, "s1", GateDecisionRequireApproval) // s1 has no hold, so it re-evaluates and is held
	if wf, _ := repo.GetByID(ctx, id); len(wf.Steps) != 2 || wf.Steps[len(wf.Steps)-1].StepID != "s2" || statusOf(stepRowOf(t, repo, id, "s1")) != "pending" {
		t.Fatalf("PREMISE: want s1 pending while s2 is the last row, got %+v", wf.Steps)
	}

	_, err := svc.StepGate(ctx, id, "s3", &StepGateRequest{StepType: StepTypeToolCall}, "tenant-1", "org-1", "user-1", "client-1")

	if err == nil || !strings.Contains(err.Error(), "workflow has pending approval for step s1") {
		t.Errorf("gate s3 = %v, want refused naming s1's pending approval", err)
	}
	if row, _ := repo.GetStepDecision(ctx, id, "s3"); row != nil {
		t.Errorf("a row was written for s3: %+v", row)
	}
}

func stepRowOf(t *testing.T, repo *MockRepository, workflowID, stepID string) WorkflowStep {
	t.Helper()
	row, err := repo.GetStepDecision(context.Background(), workflowID, stepID)
	if err != nil || row == nil {
		t.Fatalf("read %s: (%v, %v)", stepID, row, err)
	}
	return *row
}

// A workflow resume is refused while ANY step is pending, not only the last
// row (the same rule as the gate for another step).
func TestAWorkflowResumeIsRefusedWhileAnEarlierStepIsPending(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	id := createTestWorkflow(t, svc)
	gate(t, svc, id, "s1", GateDecisionAllow)
	gate(t, svc, id, "s2", GateDecisionAllow)
	gate(t, svc, id, "s1", GateDecisionRequireApproval)

	err := svc.ResumeWorkflow(context.Background(), id, "tenant-1", "org-1")

	if err == nil || !strings.Contains(err.Error(), "workflow has pending approval for step s1") {
		t.Errorf("ResumeWorkflow = %v, want refused naming s1's pending approval", err)
	}
}

// An approval never lands on a workflow that has ended, even when its step is
// still pending (an operator aborted the workflow while the approval waited),
// and the approve route answers 409 WORKFLOW_TERMINAL.
func TestAnApprovalOfAPendingStepOnAnAbortedWorkflowIsRefused(t *testing.T) {
	handler, svc, repo := setupTestHandlerWith(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	ctx := context.Background()
	wf, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "wf"}, "tenant-1", "org-1", "user-1", "client-1")
	gate(t, svc, wf.WorkflowID, "s1", GateDecisionRequireApproval)
	if err := svc.AbortWorkflow(ctx, wf.WorkflowID, "operator abort", "tenant-1", "org-1"); err != nil {
		t.Fatalf("abort: %v", err)
	}

	if err := svc.ApproveStep(ctx, wf.WorkflowID, "s1", "tenant-1", "org-1", "approver@example.com", "approved after review"); err == nil || !strings.Contains(err.Error(), "terminal state") {
		t.Errorf("ApproveStep = %v, want refused as terminal", err)
	}

	body, _ := json.Marshal(map[string]string{"comment": "approved after review"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+wf.WorkflowID+"/steps/s1/approve", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "s1"})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)
	var resp ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusConflict || resp.Code != "WORKFLOW_TERMINAL" {
		t.Errorf("approve route: status %d body %s, want 409 WORKFLOW_TERMINAL", rr.Code, rr.Body.String())
	}
	if row := stepRowOf(t, repo, wf.WorkflowID, "s1"); statusOf(row) != "pending" {
		t.Errorf("s1 = %s, want still pending", statusOf(row))
	}
}

// A rejected row on a workflow still in progress (its abort failed) refuses a
// resume from ANOTHER step's checkpoint: the whole workflow is checked, not only
// the checkpoint's step or an aborted workflow's steps.
func TestAResumeIsRefusedByARejectedStepOnAWorkflowStillInProgress(t *testing.T) {
	svc, repo := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	ctx := context.Background()
	id := createTestWorkflow(t, svc)
	gate(t, svc, id, "s0", GateDecisionAllow)
	gate(t, svc, id, "s1", GateDecisionRequireApproval)
	// The rejection's own write, without the abort that normally follows it.
	if err := repo.UpdateStepApproval(ctx, id, "s1", ApprovalStatusRejected, "reviewer@example.com", "no"); err != nil {
		t.Fatalf("reject write: %v", err)
	}
	cps, _ := repo.ListCheckpoints(ctx, id)
	var s0 *Checkpoint
	for i := range cps {
		if cps[i].StepID == "s0" {
			s0 = &cps[i]
		}
	}
	if s0 == nil {
		t.Fatalf("no checkpoint for s0")
	}

	_, err := svc.ResumeFromCheckpoint(ctx, id, s0.ID, "tenant-1", "org-1", "")

	var hold *ApprovalHoldError
	if !errors.As(err, &hold) || hold.StepID != "s1" || hold.Status != ApprovalStatusRejected {
		t.Errorf("resume from s0 = %v, want an ApprovalHoldError naming s1 rejected", err)
	}
}
