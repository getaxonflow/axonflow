// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4249 row 5701284807: a plan's steps run in order. The resume runs the
// plan's NEXT step, the lowest that has not run, and approves only that step's
// gate; a later step's gate, whoever wrote it, is read at its turn.
//
// #4249 row 5674231306: the plan routes answer a refused approval by the status
// the workflow step approve answers it with: an expired approval 409, an
// approval whose state cannot be read 503 (approveErrorStatus).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"

	"github.com/gorilla/mux"
)

// holdLaterStepAsAnotherCaller writes step_1_report's gate on the plan's own
// workflow as another caller of the workflow's gate route would: a hold, not
// the plan's executor's.
func holdLaterStepAsAnotherCaller(t *testing.T, f *realResumeFixture) {
	t.Helper()
	requireApproval := workflow_control.GateDecisionRequireApproval
	if _, err := workflowControlService.StepGate(context.Background(), f.workflowID, "step_1_report", &workflow_control.StepGateRequest{
		StepName: "report", StepType: workflow_control.StepTypeLLMCall, GateOverride: &requireApproval,
	}, "tenant_1", "org_1", "another-caller", "another-client"); err != nil {
		t.Fatalf("hold the later step as another caller: %v", err)
	}
	if row := f.row(t, "step_1_report"); approvalOf(row) != "pending" {
		t.Fatalf("PREMISE: the later gate is %s, want pending", approvalOf(row))
	}
}

// THE ROW, RUN IN ORDER: step 0 is approved (not run) and another caller holds
// step 1 first. The resume runs step 0, the plan's next step, and leaves the
// later gate as it is, to be read at its turn. It used to run step 1 and never
// step 0; round 0 of this fix refused for ever instead (a wedge).
func TestAResumeRunsTheApprovedEarlierStepBeforeALaterGateAnotherCallerWrote(t *testing.T) {
	f := executeRealPlan(t, "plan_order_pending_later", "confirm", nil)
	if err := workflowControlService.ApproveStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "approver@example.com", "ok"); err != nil {
		t.Fatalf("approve step 0: %v", err)
	}
	holdLaterStepAsAnotherCaller(t, f)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Fatalf("status %d ran %v body %s, want 200 running fetch, the plan's next step", w.Code, *f.ran, w.Body.String())
	}
	if row := f.row(t, "step_0_fetch"); row.CompletionCount != 1 {
		t.Errorf("step_0_fetch completion_count = %d, want 1", row.CompletionCount)
	}
	if row := f.row(t, "step_1_report"); approvalOf(row) != "pending" || row.CompletionCount != 0 {
		t.Errorf("step_1_report = %s completion %d, want the other caller's gate still pending and unrun", approvalOf(row), row.CompletionCount)
	}
}

// The same, with the later gate also APPROVED by the other caller: the resume
// still runs step 0 first and only step 0.
func TestAResumeRunsTheEarlierStepBeforeALaterGateAnotherCallerGatedAndApproved(t *testing.T) {
	f := executeRealPlan(t, "plan_order_approved_later", "confirm", nil)
	if err := workflowControlService.ApproveStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "approver@example.com", "ok"); err != nil {
		t.Fatalf("approve step 0: %v", err)
	}
	holdLaterStepAsAnotherCaller(t, f)
	if err := workflowControlService.ApproveStep(context.Background(), f.workflowID, "step_1_report", "tenant_1", "org_1", "another@example.com", "ok"); err != nil {
		t.Fatalf("approve step 1 as another caller: %v", err)
	}

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Fatalf("status %d ran %v body %s, want 200 running only fetch", w.Code, *f.ran, w.Body.String())
	}
	if row := f.row(t, "step_1_report"); row.CompletionCount != 0 {
		t.Errorf("step_1_report ran (completion %d) in the resume that ran step 0", row.CompletionCount)
	}
}

// HIGH-1: STEP MODE. Another caller holds step 1 before the first resume, whose
// step 0 runs ungated. The resume runs step 0 and records it; step 1 does not
// run; the other caller's gate is untouched. It used to run step 1, and step 0
// never ran.
func TestAStepModeResumeRunsItsFirstStepBeforeALaterGateAnotherCallerWrote(t *testing.T) {
	for _, approveLater := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "approved"}[approveLater], func(t *testing.T) {
			f := executeRealPlan(t, "plan_step_mode_later_"+map[bool]string{false: "pending", true: "approved"}[approveLater], "step", nil)
			// The plan was created after the upgrade's cut-over, so another
			// caller's later gate is not read as its first step having run.
			withStepModeCutover(t, time.Now().Add(-time.Hour), true)
			holdLaterStepAsAnotherCaller(t, f)
			if approveLater {
				if err := workflowControlService.ApproveStep(context.Background(), f.workflowID, "step_1_report", "tenant_1", "org_1", "another@example.com", "ok"); err != nil {
					t.Fatalf("approve step 1 as another caller: %v", err)
				}
			}

			w := resumeThePlan(t, f.planID)

			if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
				t.Fatalf("status %d ran %v body %s, want 200 running fetch, step mode's first step", w.Code, *f.ran, w.Body.String())
			}
			first := f.row(t, "step_0_fetch")
			if first == nil || first.DecisionReason != workflow_control.StepRunReasonStepModeFirstStep || first.CompletionCount != 1 {
				t.Errorf("step_0_fetch = %+v, want recorded (%s) and completed once", first, workflow_control.StepRunReasonStepModeFirstStep)
			}
			later := f.row(t, "step_1_report")
			if later.CompletionCount != 0 {
				t.Errorf("step_1_report ran (completion %d)", later.CompletionCount)
			}
			if !approveLater && approvalOf(later) != "pending" {
				t.Errorf("step_1_report = %s, want the other caller's gate still pending", approvalOf(later))
			}
		})
	}
}

// The rule on its own: the lowest step that has not run is the one that runs.
func TestPlanResumeStepIndexRunsTheLowestStepThatHasNotRun(t *testing.T) {
	var wf Workflow
	if err := json.Unmarshal([]byte(resumeHoldPlanDef), &wf); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	approved := workflow_control.ApprovalStatusApproved
	rows := &workflow_control.Workflow{WorkflowID: "wf", Status: workflow_control.WorkflowStatusInProgress, Steps: []workflow_control.WorkflowStep{
		{StepID: "step_0_fetch", ApprovalStatus: &approved},
		{StepID: "step_1_report", ApprovalStatus: &approved},
	}}
	if idx, refusal := planResumeStepIndex(wf.Spec.Steps, rows, "", false); refusal != nil || idx != 0 {
		t.Errorf("index %d refusal %+v, want step 0: it has not run", idx, refusal)
	}
	rows.Steps[0].CompletionCount = 1
	if idx, refusal := planResumeStepIndex(wf.Spec.Steps, rows, "", false); refusal != nil || idx != 1 {
		t.Errorf("index %d refusal %+v, want step 1 once step 0 has run", idx, refusal)
	}
}

// mirrorExpiry is a mirror resolver whose StepMirrorExpiry answer the test sets.
type mirrorExpiry struct {
	holdMirror
	expiresAt time.Time
	expired   bool
	found     bool
	err       error
}

func (m *mirrorExpiry) StepMirrorExpiry(context.Context, string, string, string, string) (time.Time, bool, bool, error) {
	return m.expiresAt, m.expired, m.found, m.err
}

// THROUGH THE REAL RESUME: an expired approval answers 409 and one whose state
// cannot be read 503, each naming its sentinel; the step stays pending and
// nothing runs. Before, the unreadable one answered 500.
func TestAPlanResumeAnswersARefusedApprovalByTheWorkflowApprovesStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mirror   *mirrorExpiry
		status   int
		sentinel string
	}{
		{"expired", &mirrorExpiry{expiresAt: time.Now().Add(-time.Minute), found: true}, http.StatusConflict, "approval_expired"},
		{"unreadable", &mirrorExpiry{err: errors.New("connection reset")}, http.StatusServiceUnavailable, "approval_state_unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := executeRealPlan(t, "plan_refused_approval_"+tc.name, "confirm", nil)
			workflowControlService.SetHITLMirrorResolver(tc.mirror)

			w := resumeThePlan(t, f.planID)

			if w.Code != tc.status {
				t.Fatalf("status %d body %s, want %d", w.Code, w.Body.String(), tc.status)
			}
			if msg, _ := decodeResume(t, w.Body.Bytes())["error"].(string); !strings.Contains(msg, tc.sentinel) {
				t.Errorf("the refusal %q does not carry %s", msg, tc.sentinel)
			}
			if row := f.row(t, "step_0_fetch"); approvalOf(row) != "pending" {
				t.Errorf("step_0_fetch = %s, want still pending", approvalOf(row))
			}
			if len(*f.ran) != 0 {
				t.Errorf("processors ran %v on a refused approval", *f.ran)
			}
		})
	}
}

// The plan-step approve route answers the same two refusals the same way. It
// answered both 409.
func TestThePlanStepApproveAnswersARefusedApprovalByTheWorkflowApprovesStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mirror   *mirrorExpiry
		status   int
		sentinel string
	}{
		{"expired", &mirrorExpiry{expiresAt: time.Now().Add(-time.Minute), found: true}, http.StatusConflict, "approval_expired"},
		{"unreadable", &mirrorExpiry{err: errors.New("connection reset")}, http.StatusServiceUnavailable, "approval_state_unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupHITLParityEnv(t, "plan_step_refused_"+tc.name)
			defer env.cleanup()
			env.wcpSvc.SetHITLMirrorResolver(tc.mirror)

			req := httptest.NewRequest(http.MethodPost,
				fmt.Sprintf("/api/v1/plans/%s/steps/%s/approve", env.planID, env.stepID), bytes.NewBufferString(`{"comment":"ok"}`))
			req = mux.SetURLVars(req, map[string]string{"id": env.planID, "step_id": env.stepID})
			req.Header.Set("X-User-ID", "u@example.com")
			req.Header.Set("X-Org-ID", "org-1")
			req.Header.Set("X-Tenant-ID", "tenant-1")
			req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
			rr := httptest.NewRecorder()
			mapStepApproveHandler(rr, req)

			if rr.Code != tc.status {
				t.Errorf("status %d body %s, want %d", rr.Code, rr.Body.String(), tc.status)
			}
			if !strings.Contains(rr.Body.String(), tc.sentinel) {
				t.Errorf("body %s does not carry %s", rr.Body.String(), tc.sentinel)
			}
		})
	}
}

// failingStepProcessor fails every step it is handed.
type failingStepProcessor struct{ ran *[]string }

func (p failingStepProcessor) ExecuteStep(_ context.Context, step WorkflowStep, _ map[string]interface{}, _ *WorkflowExecution) (map[string]interface{}, error) {
	*p.ran = append(*p.ran, step.Name)
	return nil, errors.New("upstream connector unavailable")
}

// FOUND BY THE CENSUS: a step whose processor fails is the resume's failure.
// ExecuteSingleStep returns it as a failed result with no error, and the resume
// read only the error, so it marked the failed step completed and gated the
// next step as if the step had run.
func TestAResumeWhoseStepFailsFailsThePlanAndDoesNotAdvance(t *testing.T) {
	f := executeRealPlan(t, "plan_step_fails", "confirm", nil)
	workflowEngine.stepProcessors["connector-call"] = failingStepProcessor{f.ran}

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d body %s, want 500: the step failed", w.Code, w.Body.String())
	}
	if msg, _ := decodeResume(t, w.Body.Bytes())["error"].(string); !strings.Contains(msg, "upstream connector unavailable") || !strings.Contains(msg, "fetch") {
		t.Errorf("the failure %q does not name the step and its error", msg)
	}
	if row := f.row(t, "step_0_fetch"); row.CompletionCount != 0 {
		t.Errorf("step_0_fetch completion_count = %d, want 0: a failed step was marked completed", row.CompletionCount)
	}
	if f.row(t, "step_1_report") != nil {
		t.Errorf("the next step was gated after a failed step")
	}
	if plan, _ := planService.GetPlan(context.Background(), f.planID, "org_1"); plan.Status != planning.PlanStatusFailed {
		t.Errorf("plan status = %s, want failed", plan.Status)
	}
}

// R3 round 2 MEDIUM-1: A STEP-RUN RECORD THAT IS NOT COMPLETED RUNS. The record
// is written before step mode's first step runs; a crash between the write and
// the run left it at completion 0, and every later resume refused it as an
// unapproved gate.
func TestAStepModeFirstStepRecordedButNeverRunIsRunByTheNextResume(t *testing.T) {
	f := executeRealPlan(t, "plan_record_no_run", "step", nil)
	if err := workflowControlService.RecordStepRun(context.Background(), workflow_control.StepRunRecord{
		WorkflowID: f.workflowID, StepID: "step_0_fetch", StepIndex: 1, StepName: "fetch", StepType: workflow_control.StepTypeConnectorCall,
		Reason: workflow_control.StepRunReasonStepModeFirstStep, TenantID: "tenant_1", OrgID: "org_1", UserID: "resumer",
	}); err != nil {
		t.Fatalf("write the record the crashed resume left: %v", err)
	}

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Fatalf("status %d ran %v body %s, want 200 running fetch once", w.Code, *f.ran, w.Body.String())
	}
	if row := f.row(t, "step_0_fetch"); row.CompletionCount != 1 {
		t.Errorf("step_0_fetch completion_count = %d, want 1", row.CompletionCount)
	}
}

// completionLosingRepository fails MarkStepCompleted once, when armed.
type completionLosingRepository struct {
	*workflow_control.MockRepository
	armed bool
}

func (r *completionLosingRepository) MarkStepCompleted(ctx context.Context, workflowID, stepID string, req *workflow_control.StepCompleteRequest) error {
	if r.armed {
		r.armed = false
		return errors.New("connection reset")
	}
	return r.MockRepository.MarkStepCompleted(ctx, workflowID, stepID, req)
}

// ...and a completion that could not be recorded is answered 500, naming it, not
// discarded; the next resume runs the step again (at-least-once) and completes.
func TestALostCompletionIsAnswered500AndTheNextResumeRunsTheStepAgain(t *testing.T) {
	var losing *completionLosingRepository
	f := executeRealPlan(t, "plan_completion_lost", "step", func(m *workflow_control.MockRepository) workflow_control.Repository {
		losing = &completionLosingRepository{MockRepository: m}
		return losing
	})
	losing.armed = true

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "completion could not be recorded") {
		t.Fatalf("resume 1: status %d body %s, want 500 naming the lost completion", w.Code, w.Body.String())
	}
	if strings.Join(*f.ran, ",") != "fetch" {
		t.Fatalf("resume 1 ran %v, want fetch", *f.ran)
	}

	w = resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch,fetch" {
		t.Fatalf("resume 2: status %d ran %v body %s, want 200 running fetch again", w.Code, *f.ran, w.Body.String())
	}
	if row := f.row(t, "step_0_fetch"); row.CompletionCount != 1 {
		t.Errorf("step_0_fetch completion_count = %d, want 1", row.CompletionCount)
	}
}
