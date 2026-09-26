// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

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

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
)

// #4249 (rows 5698298886 and 5699398978): a MAP plan resume runs the step whose
// gate row it approved, keyed on the row's step_id and never on the workflow's
// current_step_index, and it never runs a step past a gate row that is not
// approved. These tests gate through the REAL executors (ExecuteWithConfirm,
// ExecuteWithStep), so the rows carry the step_index StepGate really writes,
// unlike the hand-built fixture the resume tests used to share.

// resumeHoldPlanDef is a two-step plan: a connector call, then an LLM call.
const resumeHoldPlanDef = `{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"hold"},"spec":{"steps":[` +
	`{"name":"fetch","type":"connector-call"},` +
	`{"name":"report","type":"llm-call"}]}}`

// namingStepProcessor records the name of every step it runs.
type namingStepProcessor struct{ ran *[]string }

func (p namingStepProcessor) ExecuteStep(_ context.Context, step WorkflowStep, _ map[string]interface{}, _ *WorkflowExecution) (map[string]interface{}, error) {
	*p.ran = append(*p.ran, step.Name)
	return map[string]interface{}{"ok": true}, nil
}

// realResumeFixture holds a plan executed through the real executor.
type realResumeFixture struct {
	planID     string
	workflowID string
	repo       workflow_control.Repository
	mock       *workflow_control.MockRepository
	ran        *[]string
}

// executeRealPlan saves a plan, executes it in mode through the real executor
// over a mock repository (wrapped by wrap when non-nil), and installs the
// globals the resume handler reads.
func executeRealPlan(t *testing.T, planID, mode string, wrap func(*workflow_control.MockRepository) workflow_control.Repository) *realResumeFixture {
	t.Helper()
	return executeRealPlanBinding(t, planID, mode, wrap, true)
}

// executeRealPlanUnbound is a plan that began executing before the binding
// existed (#4249): its workflow is selected by the fallback.
func executeRealPlanUnbound(t *testing.T, planID, mode string) *realResumeFixture {
	t.Helper()
	return executeRealPlanBinding(t, planID, mode, nil, false)
}

func executeRealPlanBinding(t *testing.T, planID, mode string, wrap func(*workflow_control.MockRepository) workflow_control.Repository, bind bool) *realResumeFixture {
	t.Helper()
	oldPlans, oldExec, oldWCP, oldEngine := planService, mapWCPExecutor, workflowControlService, workflowEngine
	t.Cleanup(func() {
		planService, mapWCPExecutor, workflowControlService, workflowEngine = oldPlans, oldExec, oldWCP, oldEngine
	})
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	// A resumed step is decided when it runs (#4249 row 5666236540), and with no
	// enforcer wired that decision fails closed. These tests are about WHICH
	// step a resume runs, so the engine allows every step it is asked about.
	withMAPEngine(t, allowedStepVerdict())

	planRepo := planning.NewMockRepository()
	planService = planning.NewService(planRepo)
	plan := &planning.Plan{OrgID: "org_1", TenantID: "tenant_1", PlanID: planID, Query: "q", Domain: "generic",
		ExecutionMode: mode, Status: planning.PlanStatusPending, WorkflowDefinition: json.RawMessage(resumeHoldPlanDef), Version: 1}
	if err := planRepo.SavePlan(context.Background(), plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	// As GetPlanForExecution marks it: on this release with an empty binding,
	// or (bind=false) the pre-release shape, executing with no binding at all.
	if bind {
		if err := planRepo.MarkExecutingWithPendingBinding(context.Background(), planID); err != nil {
			t.Fatalf("mark executing: %v", err)
		}
	} else if err := planRepo.UpdatePlanStatusAtomic(context.Background(), planID, planning.PlanStatusPending, planning.PlanStatusExecuting); err != nil {
		t.Fatalf("mark executing: %v", err)
	}

	mock := workflow_control.NewMockRepository()
	var repo workflow_control.Repository = mock
	if wrap != nil {
		repo = wrap(mock)
	}
	svc := workflow_control.NewService(repo, nil, nil)
	workflowControlService = svc
	mapWCPExecutor = NewMAPWCPExecutor(svc, planService)

	var ran []string
	engine := NewWorkflowEngine()
	for _, stepType := range []string{"connector-call", "llm-call"} {
		engine.stepProcessors[stepType] = namingStepProcessor{&ran}
	}
	workflowEngine = engine

	var wf Workflow
	if err := json.Unmarshal([]byte(resumeHoldPlanDef), &wf); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	var res *MAPWCPExecutionResult
	var err error
	if mode == "confirm" {
		res, err = mapWCPExecutor.ExecuteWithConfirm(context.Background(), plan, &wf, "tenant_1", "org_1", "u", "c")
	} else {
		res, err = mapWCPExecutor.ExecuteWithStep(context.Background(), plan, &wf, "tenant_1", "org_1", "u", "c")
	}
	if err != nil {
		t.Fatalf("execute %s: %v", mode, err)
	}
	if bind {
		// What executePlanHandler does after the executor returns.
		if err := planService.BindExecutionWorkflow(context.Background(), planID, res.WorkflowID); err != nil {
			t.Fatalf("bind: %v", err)
		}
	}
	return &realResumeFixture{planID: planID, workflowID: res.WorkflowID, repo: repo, mock: mock, ran: &ran}
}

func (f *realResumeFixture) row(t *testing.T, stepID string) *workflow_control.WorkflowStep {
	t.Helper()
	row, err := f.mock.GetStepDecision(context.Background(), f.workflowID, stepID)
	if err != nil {
		t.Fatalf("read %s: %v", stepID, err)
	}
	return row
}

func approvalOf(row *workflow_control.WorkflowStep) string {
	if row == nil {
		return "<no row>"
	}
	if row.ApprovalStatus == nil {
		return "<none>"
	}
	return string(*row.ApprovalStatus)
}

func decodeResume(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return resp
}

// Confirm mode: the first resume approves step_0_fetch and runs fetch (not
// report), records the completion on step_0_fetch, and gates step_1_report
// pending. The second resume runs report and completes the plan.
func TestAConfirmModeResumeRunsTheStepItApproved(t *testing.T) {
	f := executeRealPlan(t, "plan_confirm_runs_approved", "confirm", nil)
	if row := f.row(t, "step_0_fetch"); approvalOf(row) != "pending" || row.StepIndex != 1 {
		t.Fatalf("the executor's first row = %s at index %d; the test expects the real gate's pending row at index 1",
			approvalOf(row), row.StepIndex)
	}

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK {
		t.Fatalf("resume 1: status %d body %s", w.Code, w.Body.String())
	}
	result, _ := decodeResume(t, w.Body.Bytes())["step_result"].(map[string]interface{})
	if result["step_name"] != "fetch" || result["step_index"] != float64(0) {
		t.Errorf("resume 1 ran %v at index %v, want fetch at 0", result["step_name"], result["step_index"])
	}
	if strings.Join(*f.ran, ",") != "fetch" {
		t.Errorf("processors ran %v, want [fetch]", *f.ran)
	}
	fetch := f.row(t, "step_0_fetch")
	if approvalOf(fetch) != "approved" || fetch.ApprovedBy == "" || fetch.CompletionCount != 1 {
		t.Errorf("step_0_fetch = %s approved_by=%v completion_count=%d, want approved by the resume actor and completed once",
			approvalOf(fetch), fetch.ApprovedBy, fetch.CompletionCount)
	}
	if next := f.row(t, "step_1_report"); approvalOf(next) != "pending" {
		t.Errorf("step_1_report = %s, want the next step gated pending", approvalOf(next))
	}

	w = resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || decodeResume(t, w.Body.Bytes())["status"] != "completed" {
		t.Fatalf("resume 2: status %d body %s, want 200 completed", w.Code, w.Body.String())
	}
	if strings.Join(*f.ran, ",") != "fetch,report" {
		t.Errorf("processors ran %v, want [fetch report]", *f.ran)
	}
	if report := f.row(t, "step_1_report"); approvalOf(report) != "approved" || report.CompletionCount != 1 {
		t.Errorf("step_1_report = %s completion_count=%d, want approved and completed", approvalOf(report), report.CompletionCount)
	}
}

// Step mode runs its first step ungated by design: with no gate rows at all the
// resume runs step 0 and gates step 1; the next resume approves and runs step 1.
func TestAStepModeResumeRunsItsUngatedFirstStepThenTheApprovedOne(t *testing.T) {
	f := executeRealPlan(t, "plan_step_first_ungated", "step", nil)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Fatalf("resume 1: status %d ran %v body %s, want 200 running fetch", w.Code, *f.ran, w.Body.String())
	}
	// #4249 row 5701284807: the ungated first step leaves a record before it
	// runs: an allow with no approval, naming why, completed once. It used to
	// leave no row, so "ran" and "never ran" were the same state.
	if row := f.row(t, "step_0_fetch"); row == nil || row.Decision != workflow_control.GateDecisionAllow ||
		row.ApprovalStatus != nil || row.DecisionReason != workflow_control.StepRunReasonStepModeFirstStep || row.CompletionCount != 1 {
		t.Errorf("step_0_fetch = %+v, want an allow recorded as %s with no approval, completed once", row, workflow_control.StepRunReasonStepModeFirstStep)
	}
	if next := f.row(t, "step_1_report"); approvalOf(next) != "pending" {
		t.Fatalf("step_1_report = %s, want pending", approvalOf(next))
	}

	w = resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch,report" {
		t.Errorf("resume 2: status %d ran %v body %s, want 200 running report", w.Code, *f.ran, w.Body.String())
	}
}

// A hold cleared by a path the service rule did not see (a direct write to the
// row) is refused: no step runs, nothing is completed, no next gate is written.
func TestAPlanResumeRefusesAStepWhoseHoldWasCleared(t *testing.T) {
	f := executeRealPlan(t, "plan_cleared_hold", "confirm", nil)
	if err := f.mock.SetStepApprovalForTest(f.workflowID, "step_0_fetch", nil, workflow_control.GateDecisionAllow); err != nil {
		t.Fatalf("clear the hold: %v", err)
	}

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusConflict {
		t.Fatalf("status %d body %s, want 409", w.Code, w.Body.String())
	}
	if msg := decodeResume(t, w.Body.Bytes())["error"]; !strings.Contains(msg.(string), "step step_0_fetch carries no approval") {
		t.Errorf("the refusal %q does not name step_0_fetch and its missing approval", msg)
	}
	if len(*f.ran) != 0 {
		t.Errorf("processors ran %v on a refused resume", *f.ran)
	}
	if row := f.row(t, "step_0_fetch"); row.CompletionCount != 0 || approvalOf(row) != "<none>" {
		t.Errorf("step_0_fetch = %s completion_count=%d, want untouched", approvalOf(row), row.CompletionCount)
	}
	if f.row(t, "step_1_report") != nil {
		t.Errorf("a next-step gate was written on a refused resume")
	}
	if plan, _ := planService.GetPlan(context.Background(), f.planID, "org_1"); plan.Status != planning.PlanStatusExecuting {
		t.Errorf("plan status = %s, want still executing", plan.Status)
	}
}

// A step approved before the resume (mapStepApproveHandler's path) has no
// pending row; the resume runs it as before.
func TestAPlanResumeRunsAStepApprovedBeforeTheResume(t *testing.T) {
	f := executeRealPlan(t, "plan_approved_before", "confirm", nil)
	if err := workflowControlService.ApproveStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "approver@example.com", "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Errorf("status %d ran %v body %s, want 200 running fetch", w.Code, *f.ran, w.Body.String())
	}
}

// getByIDFailingRepository fails every GetByID once armed.
type getByIDFailingRepository struct {
	*workflow_control.MockRepository
	armed bool
}

func (r *getByIDFailingRepository) GetByID(ctx context.Context, workflowID string) (*workflow_control.Workflow, error) {
	if r.armed {
		return nil, errors.New("connection reset")
	}
	return r.MockRepository.GetByID(ctx, workflowID)
}

// A gate-row read that fails runs nothing.
func TestAPlanResumeWhoseGateRowsCannotBeReadRunsNothing(t *testing.T) {
	var failing *getByIDFailingRepository
	// Unbound, so the workflow is selected by listing and the first GetByID
	// after the approve is the gate-row read. (A bound plan's selection reads
	// the workflow by id: its failure is the next test.)
	f := executeRealPlanBinding(t, "plan_read_fails", "confirm", func(m *workflow_control.MockRepository) workflow_control.Repository {
		failing = &getByIDFailingRepository{MockRepository: m}
		return failing
	}, false)
	// Approved beforehand, so the resume's own approve (which also reads the
	// workflow) does not run and the first GetByID is the gate-row read.
	if err := workflowControlService.ApproveStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "approver@example.com", "ok"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	failing.armed = true

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusInternalServerError || len(*f.ran) != 0 || !strings.Contains(w.Body.String(), "gate rows could not be read") {
		t.Errorf("status %d ran %v body %s, want 500 and nothing run", w.Code, *f.ran, w.Body.String())
	}
}

// A bound plan whose workflow cannot be read runs nothing.
func TestABoundPlanWhoseWorkflowCannotBeReadRunsNothing(t *testing.T) {
	var failing *getByIDFailingRepository
	f := executeRealPlan(t, "plan_bound_read_fails", "confirm", func(m *workflow_control.MockRepository) workflow_control.Repository {
		failing = &getByIDFailingRepository{MockRepository: m}
		return failing
	})
	failing.armed = true

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusInternalServerError || len(*f.ran) != 0 || !strings.Contains(w.Body.String(), "Failed to read the plan's workflow") {
		t.Errorf("status %d ran %v body %s, want 500 and nothing run", w.Code, *f.ran, w.Body.String())
	}
}

// planResumeStepIndex over hand-stated row sets: every rule, each on its own.
func TestPlanResumeStepIndexRules(t *testing.T) {
	steps := []WorkflowStep{{Name: "a", Type: "llm-call"}, {Name: "b", Type: "llm-call"}, {Name: "c", Type: "llm-call"}}
	approved, pending := workflow_control.ApprovalStatusApproved, workflow_control.ApprovalStatusPending
	rejected, expired := workflow_control.ApprovalStatusRejected, workflow_control.ApprovalStatusExpired
	row := func(id string, status *workflow_control.ApprovalStatus, completions int) workflow_control.WorkflowStep {
		return workflow_control.WorkflowStep{StepID: id, ApprovalStatus: status, CompletionCount: completions}
	}
	cases := []struct {
		name     string
		status   workflow_control.WorkflowStatus
		stepMode bool
		rows     []workflow_control.WorkflowStep
		approved string
		want     int
		refusal  string // substring; "" = runs want
	}{
		{"a step-mode workflow with no rows runs step 0", "", true, nil, "", 0, ""},
		{"a confirm-mode workflow with no rows refuses", "", false, nil, "", 0, "a confirm-mode workflow with no gate row"},
		{"the approved pending row runs", "", false, []workflow_control.WorkflowStep{row("step_0_a", &approved, 0)}, "step_0_a", 0, ""},
		{"an approved-before row runs", "", false, []workflow_control.WorkflowStep{row("step_0_a", &approved, 1), row("step_1_b", &approved, 0)}, "", 1, ""},
		// #4249 row 5701284807: the plan's steps run in order. These cases ran
		// the HIGHEST gated step, so an approved step_0_a that had not run was
		// skipped for step_1_b; the resume now runs the LOWEST step that has not
		// run, and reads a later row at its turn.
		{"the lowest approved step that has not run runs, not a later one", "", false,
			[]workflow_control.WorkflowStep{row("step_0_a", &approved, 0), row("step_1_b", &approved, 0)}, "", 0, ""},
		{"an approved earlier step the resume approved runs before a later approved one", "", false,
			[]workflow_control.WorkflowStep{row("step_0_a", &approved, 0), row("step_1_b", &approved, 0)}, "step_0_a", 0, ""},
		{"a later row the resume approved is not the plan's next step", "", false,
			[]workflow_control.WorkflowStep{row("step_0_a", &approved, 0), row("step_1_b", &approved, 0)}, "step_1_b", 0, "is not the plan's next step step_0_a"},
		{"a pending next step refuses, naming it; a later row is not read", "", false,
			[]workflow_control.WorkflowStep{row("step_0_a", &pending, 0), row("step_1_b", &approved, 0)}, "", 0, "step step_0_a holds approval pending"},
		{"a row with no approval refuses", "", false, []workflow_control.WorkflowStep{row("step_0_a", nil, 0)}, "", 0, "carries no approval"},
		{"a pending row refuses", "", false, []workflow_control.WorkflowStep{row("step_0_a", &approved, 1), row("step_1_b", &pending, 0)}, "", 0, "step_1_b holds approval pending"},
		{"a rejected row refuses", "", false, []workflow_control.WorkflowStep{row("step_0_a", &rejected, 0)}, "", 0, "holds approval rejected"},
		{"an expired row refuses", "", false, []workflow_control.WorkflowStep{row("step_0_a", &expired, 0)}, "", 0, "holds approval expired"},
		{"a next step with no gate row refuses", "", false, []workflow_control.WorkflowStep{row("step_0_a", &approved, 1)}, "", 0, "no gate row names a step"},
		{"a plan whose every step ran refuses", "", false,
			[]workflow_control.WorkflowStep{row("step_0_a", &approved, 1), row("step_1_b", &approved, 1), row("step_2_c", &approved, 1)}, "", 0, "has already run"},
		{"rows naming no plan step refuse", "", false, []workflow_control.WorkflowStep{row("step_9_z", &approved, 0)}, "", 0, "no gate row names a step"},
		{"an aborted workflow refuses even with an approved row", workflow_control.WorkflowStatusAborted, false,
			[]workflow_control.WorkflowStep{row("step_0_a", &approved, 0)}, "step_0_a", 0, "is aborted"},
		{"a step-mode aborted workflow with no rows refuses", workflow_control.WorkflowStatusAborted, true, nil, "", 0, "is aborted"},
		// #4249 row 5713229791: rule 2 reads only the plan's own step gates.
		{"a foreign row with no approval does not refuse", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", nil, 0), row("step_0_a", &approved, 0)}, "step_0_a", 0, ""},
		{"a foreign pending row does not refuse", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", &pending, 0), row("step_0_a", &approved, 0)}, "step_0_a", 0, ""},
		{"a foreign rejected row does not refuse", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", &rejected, 0), row("step_0_a", &approved, 0)}, "step_0_a", 0, ""},
		{"a foreign expired row does not refuse", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", &expired, 0), row("step_0_a", &approved, 0)}, "step_0_a", 0, ""},
		{"an own-step pending row beside a foreign row refuses", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", &approved, 0), row("step_0_a", &approved, 1), row("step_1_b", &pending, 0)}, "", 0, "step_1_b holds approval pending"},
		{"an own-step row with no approval beside a foreign row refuses", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", &approved, 0), row("step_0_a", nil, 0)}, "", 0, "step_0_a carries no approval"},
		{"an own-step rejected row beside a foreign row refuses", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", &approved, 0), row("step_0_a", &rejected, 0)}, "", 0, "step_0_a holds approval rejected"},
		{"an own-step expired row beside a foreign row refuses", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", &approved, 0), row("step_0_a", &expired, 0)}, "", 0, "step_0_a holds approval expired"},
		// #4249 row 5701284807: step mode's first step leaves a record when it
		// runs, so with no row for it, it has not run: another caller's rows do
		// not stop it running first (they refused it before).
		{"a step-mode workflow whose only rows are foreign runs its first step", "", true,
			[]workflow_control.WorkflowStep{row("tenant-probe", nil, 0)}, "", 0, ""},
		{"a step-mode workflow with a later own gate and no first-step record runs its first step", "", true,
			[]workflow_control.WorkflowStep{row("step_1_b", &pending, 0)}, "", 0, ""},
		{"a confirm-mode workflow whose only rows are foreign refuses", "", false,
			[]workflow_control.WorkflowStep{row("tenant-probe", nil, 0)}, "", 0, "no gate row names a step"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.status
			if status == "" {
				status = workflow_control.WorkflowStatusInProgress
			}
			wf := &workflow_control.Workflow{WorkflowID: "wf-rules", Status: status, Steps: tc.rows}
			got, refusal := planResumeStepIndex(steps, wf, tc.approved, tc.stepMode)
			if tc.refusal == "" {
				if refusal != nil || got != tc.want {
					t.Errorf("= (%d, %+v), want (%d, nil)", got, refusal, tc.want)
				}
				return
			}
			if refusal == nil || refusal.Status != http.StatusConflict || !strings.Contains(refusal.Message, tc.refusal) {
				t.Errorf("= (%d, %+v), want a 409 naming %q", got, refusal, tc.refusal)
			}
		})
	}
}

// createLookalike creates a workflow named like the plan's, as any caller of
// POST /api/v1/workflows can (row 5699811399).
func createLookalike(t *testing.T, name string) string {
	t.Helper()
	wf, err := workflowControlService.CreateWorkflow(context.Background(), &workflow_control.CreateWorkflowRequest{
		WorkflowName: name, Source: workflow_control.WorkflowSource("map"),
	}, "tenant_1", "org_1", "u", "c")
	if err != nil {
		t.Fatalf("create lookalike: %v", err)
	}
	return wf.WorkflowID
}

// A rejection aborts the executor's workflow and leaves the plan executing. A
// lookalike created afterwards does not make the resume run the rejected step:
// the aborted workflow of that name refuses the resume.
func TestALookalikeWorkflowDoesNotResumeARejectedBoundPlan(t *testing.T) {
	f := executeRealPlan(t, "plan_lookalike_after_reject", "confirm", nil)
	if err := workflowControlService.RejectStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "reviewer@example.com", "rejected in review"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	createLookalike(t, "map-confirm-"+f.planID)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusConflict || len(*f.ran) != 0 || !strings.Contains(w.Body.String(), "is aborted") {
		t.Errorf("status %d ran %v body %s, want 409 naming the aborted workflow and nothing run", w.Code, *f.ran, w.Body.String())
	}
}

// Two running workflows of an UNBOUND plan's name: the fallback does not choose.
func TestTwoRunningWorkflowsOfAnUnboundPlanRefuseTheResume(t *testing.T) {
	f := executeRealPlanUnbound(t, "plan_two_running", "confirm")
	createLookalike(t, "map-confirm-"+f.planID)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusConflict || len(*f.ran) != 0 || !strings.Contains(w.Body.String(), "2 running workflows") {
		t.Errorf("status %d ran %v body %s, want 409 naming 2 running workflows and nothing run", w.Code, *f.ran, w.Body.String())
	}
	if row := f.row(t, "step_0_fetch"); approvalOf(row) != "pending" {
		t.Errorf("step_0_fetch = %s, want still pending: the refusal comes before the approve", approvalOf(row))
	}
}

// The fallback selection reads past the first page: an unbound plan's aborted
// workflow, older than more than two pages of same-named lookalikes, still
// refuses.
func TestTheFallbackSelectionReadsEveryPage(t *testing.T) {
	f := executeRealPlanUnbound(t, "plan_many_pages", "confirm")
	if err := workflowControlService.RejectStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "reviewer@example.com", "rejected in review"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	for i := 0; i < 230; i++ {
		createLookalike(t, "map-confirm-"+f.planID)
	}

	_, refusal, err := selectPlanWorkflow(context.Background(), workflowControlService, planWorkflowName("confirm", f.planID), "tenant_1", "org_1")

	if err != nil || refusal == nil || refusal.Status != http.StatusConflict || !strings.Contains(refusal.Message, "is aborted") {
		t.Errorf("selection = (%+v, %v), want a 409 naming the aborted workflow", refusal, err)
	}
}

// A lookalike after a rejection does not resume an UNBOUND plan either: the
// fallback refuses on the aborted workflow of that name.
func TestALookalikeWorkflowDoesNotResumeARejectedUnboundPlan(t *testing.T) {
	f := executeRealPlanUnbound(t, "plan_lookalike_unbound", "confirm")
	if err := workflowControlService.RejectStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "reviewer@example.com", "rejected in review"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	createLookalike(t, "map-confirm-"+f.planID)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusConflict || len(*f.ran) != 0 || !strings.Contains(w.Body.String(), "is aborted") {
		t.Errorf("status %d ran %v body %s, want 409 naming the aborted workflow and nothing run", w.Code, *f.ran, w.Body.String())
	}
}

// An unbound plan with its one workflow resumes through the fallback as before.
func TestAnUnboundConfirmPlanResumesThroughTheFallback(t *testing.T) {
	f := executeRealPlanUnbound(t, "plan_unbound_runs", "confirm")

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Errorf("status %d ran %v body %s, want 200 running fetch", w.Code, *f.ran, w.Body.String())
	}
}

// A BOUND plan acts on its own workflow: a running lookalike of its name is not
// consulted, and the resume approves and runs the executor's step.
func TestABoundPlanResumesItsOwnWorkflowPastALookalike(t *testing.T) {
	f := executeRealPlan(t, "plan_bound_lookalike", "confirm", nil)
	lookalike := createLookalike(t, "map-confirm-"+f.planID)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Fatalf("status %d ran %v body %s, want 200 running fetch", w.Code, *f.ran, w.Body.String())
	}
	if row := f.row(t, "step_0_fetch"); approvalOf(row) != "approved" {
		t.Errorf("step_0_fetch = %s, want approved on the bound workflow", approvalOf(row))
	}
	if wf, _ := f.mock.GetByID(context.Background(), lookalike); len(wf.Steps) != 0 {
		t.Errorf("the lookalike gained %d gate rows, want none", len(wf.Steps))
	}
}

// A caller of another tenant in the same organization is refused (403) on a
// bound plan and an unbound one alike, and nothing runs.
func TestAResumeByAnotherTenantIsRefused(t *testing.T) {
	for _, bound := range []bool{true, false} {
		name := map[bool]string{true: "bound", false: "unbound"}[bound]
		t.Run(name, func(t *testing.T) {
			f := executeRealPlanBinding(t, "plan_other_tenant_"+name, "confirm", nil, bound)
			if _, err := workflowControlService.CreateWorkflow(context.Background(), &workflow_control.CreateWorkflowRequest{
				WorkflowName: "map-step-" + f.planID, Source: workflow_control.WorkflowSource("map"),
			}, "tenant_2", "org_1", "u2", "c2"); err != nil {
				t.Fatalf("lookalike: %v", err)
			}
			body, _ := json.Marshal(map[string]interface{}{"approved": true})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/"+f.planID+"/resume", bytes.NewReader(body))
			req.Header.Set("X-Org-ID", "org_1")
			req.Header.Set("X-Tenant-ID", "tenant_2")
			req = mux.SetURLVars(req, map[string]string{"id": f.planID})
			installProxyTokenValidator(t, proxyGuardTestSecret)
			req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
			w := httptest.NewRecorder()
			resumePlanHandler(w, req)

			// The message tells the tenant refusal from the withhold 403 a
			// decided step answers ("Step withheld by policy").
			if w.Code != http.StatusForbidden || len(*f.ran) != 0 || !strings.Contains(w.Body.String(), "this plan belongs to another tenant") {
				t.Errorf("status %d ran %v body %s, want 403 naming another tenant and nothing run", w.Code, *f.ran, w.Body.String())
			}
			if row := f.row(t, "step_0_fetch"); approvalOf(row) != "pending" {
				t.Errorf("step_0_fetch = %s, want still pending", approvalOf(row))
			}
		})
	}
}

// A plan that is not in confirm or step mode has no workflow to resume: a
// lookalike named for step mode does not make its steps run.
func TestAPlanNotInConfirmOrStepModeIsNotResumedThroughALookalike(t *testing.T) {
	f := executeRealPlanUnbound(t, "plan_sequential", "confirm")
	stored, _ := planService.GetPlan(context.Background(), f.planID, "org_1")
	stored.ExecutionMode = "sequential"
	createLookalike(t, "map-step-"+f.planID)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusConflict || len(*f.ran) != 0 || !strings.Contains(w.Body.String(), "execution mode") {
		t.Errorf("status %d ran %v body %s, want 409 naming the execution mode and nothing run", w.Code, *f.ran, w.Body.String())
	}
}

// The reject arm after the plan's workflow ended (a WCP-route rejection or an
// expiry) fails the plan and runs nothing, rather than leaving it executing.
func TestTheRejectArmFailsAPlanWhoseWorkflowEnded(t *testing.T) {
	f := executeRealPlan(t, "plan_reject_after_end", "confirm", nil)
	if err := workflowControlService.RejectStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "reviewer@example.com", "rejected in review"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	body, _ := json.Marshal(map[string]interface{}{"approved": false})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/"+f.planID+"/resume", bytes.NewReader(body))
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	req = mux.SetURLVars(req, map[string]string{"id": f.planID})
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	resumePlanHandler(w, req)

	if w.Code != http.StatusOK || decodeResume(t, w.Body.Bytes())["status"] != "rejected" || len(*f.ran) != 0 {
		t.Errorf("status %d ran %v body %s, want 200 rejected and nothing run", w.Code, *f.ran, w.Body.String())
	}
	if plan, _ := planService.GetPlan(context.Background(), f.planID, "org_1"); plan.Status != planning.PlanStatusFailed {
		t.Errorf("plan status = %s, want failed", plan.Status)
	}
}

// approveRefusingRepository refuses every approval write, as the pending-only
// statement does when a concurrent decision landed first.
type approveRefusingRepository struct {
	*workflow_control.MockRepository
}

func (r *approveRefusingRepository) UpdateStepApproval(ctx context.Context, workflowID, stepID string, status workflow_control.ApprovalStatus, by, comment string) error {
	return fmt.Errorf("step is not pending approval: %s/%s", workflowID, stepID)
}

// A resume whose own approval is refused answers 409, not a server error, and
// runs nothing.
func TestAResumeWhoseApprovalIsRefusedAnswersConflict(t *testing.T) {
	f := executeRealPlan(t, "plan_approve_refused", "confirm", func(m *workflow_control.MockRepository) workflow_control.Repository {
		return &approveRefusingRepository{MockRepository: m}
	})

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusConflict || len(*f.ran) != 0 {
		t.Errorf("status %d ran %v body %s, want 409 and nothing run", w.Code, *f.ran, w.Body.String())
	}
}

// A plan-level reject acts on the plan's BOUND workflow (row 5700138487): a
// newer lookalike whose metadata names the plan, holding the same step id, is
// not the one rejected.
func TestAPlanRouteRejectActsOnTheBoundWorkflowNotAForgedMetadataLookalike(t *testing.T) {
	env := setupMAPApproverEnv(t, "forged_metadata_reject")
	defer env.cleanup()
	ctx := context.Background()
	lookalike, err := workflowControlService.CreateWorkflow(ctx, &workflow_control.CreateWorkflowRequest{
		WorkflowName: "anything", Source: workflow_control.WorkflowSource("external"),
		Metadata: map[string]interface{}{"plan_id": env.planID, "execution_mode": "confirm"},
	}, "tenant-1", "org-1", "u", "c")
	if err != nil {
		t.Fatalf("lookalike: %v", err)
	}
	requireApproval := workflow_control.GateDecisionRequireApproval
	if _, err := workflowControlService.StepGate(ctx, lookalike.WorkflowID, env.stepID, &workflow_control.StepGateRequest{
		StepName: "step-name", StepType: workflow_control.StepTypeToolCall, GateOverride: &requireApproval,
	}, "tenant-1", "org-1", "u", "c"); err != nil {
		t.Fatalf("gate the lookalike: %v", err)
	}

	rr := httptest.NewRecorder()
	mapStepRejectHandler(rr, mapHITLRequest("reject", env.planID, env.stepID,
		`{"reason":"Rejected after full audit review"}`, map[string]string{"X-User-ID": "reviewer@example.com"}))

	if rr.Code != http.StatusOK {
		t.Fatalf("reject status = %d body=%s", rr.Code, rr.Body.String())
	}
	if real, _ := env.repo.GetStep(ctx, env.wfID, env.stepID); real == nil || real.ApprovalStatus == nil || *real.ApprovalStatus != workflow_control.ApprovalStatusRejected {
		t.Errorf("the bound workflow's step = %+v, want rejected", real)
	}
	if other, _ := env.repo.GetStep(ctx, lookalike.WorkflowID, env.stepID); other == nil || other.ApprovalStatus == nil || *other.ApprovalStatus != workflow_control.ApprovalStatusPending {
		t.Errorf("the lookalike's step = %+v, want untouched (pending)", other)
	}
}

// An approve that races a rejection cannot land (row 5699811652): the
// rejection moves the row out of pending, so the approval's write finds no
// pending row, and an approve of the aborted workflow is refused outright.
func TestAnApproveCannotLandAfterARejection(t *testing.T) {
	f := executeRealPlan(t, "plan_race", "confirm", nil)
	ctx := context.Background()
	if err := workflowControlService.RejectStep(ctx, f.workflowID, "step_0_fetch", "tenant_1", "org_1", "reviewer@example.com", "rejected in review"); err != nil {
		t.Fatalf("reject: %v", err)
	}

	// The approve's write, as it lands after its own pending read passed.
	writeErr := f.mock.UpdateStepApproval(ctx, f.workflowID, "step_0_fetch", workflow_control.ApprovalStatusApproved, "approver@example.com", "late approve")
	approveErr := workflowControlService.ApproveStep(ctx, f.workflowID, "step_0_fetch", "tenant_1", "org_1", "approver@example.com", "late approve")

	if writeErr == nil || !strings.Contains(writeErr.Error(), "not pending approval") {
		t.Errorf("the racing approval write = %v, want refused as not pending", writeErr)
	}
	if approveErr == nil || !strings.Contains(approveErr.Error(), "terminal state") {
		t.Errorf("ApproveStep on the aborted workflow = %v, want refused as terminal", approveErr)
	}
	if row := f.row(t, "step_0_fetch"); approvalOf(row) != "rejected" {
		t.Errorf("step_0_fetch = %s, want rejected", approvalOf(row))
	}
	w := resumeThePlan(t, f.planID)
	if w.Code != http.StatusConflict || len(*f.ran) != 0 {
		t.Errorf("resume after the race: status %d ran %v, want 409 and nothing run", w.Code, *f.ran)
	}
}

// Plan execute in confirm mode binds the workflow the executor created to the
// plan (row 5699811991), so the resume that follows acts on that workflow.
func TestPlanExecuteInConfirmModeBindsTheExecutorsWorkflow(t *testing.T) {
	previousPlans, previousExec, previousWCP, previousWorkflow, previousAudit := planService, mapWCPExecutor, workflowControlService, workflowEngine, auditLogger
	t.Cleanup(func() {
		planService, mapWCPExecutor, workflowControlService, workflowEngine, auditLogger = previousPlans, previousExec, previousWCP, previousWorkflow, previousAudit
	})
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	repo := planning.NewMockRepository()
	if err := repo.SavePlan(context.Background(), &planning.Plan{
		TenantID: "tenant_1", OrgID: "org_1", PlanID: "plan_execute_binds", Status: planning.PlanStatusPending,
		ExecutionMode: "confirm", StepCount: 2, Query: "fetch and report", Domain: "generic",
		WorkflowDefinition: json.RawMessage(resumeHoldPlanDef), ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	planService = planning.NewService(repo)
	wcp := workflow_control.NewService(workflow_control.NewMockRepository(), nil, nil)
	workflowControlService = wcp
	mapWCPExecutor = NewMAPWCPExecutor(wcp, planService)
	workflowEngine = NewWorkflowEngine()
	auditLogger = NewAuditLogger("")
	withRouteRequestEngine(t, allowedStepVerdict())

	body, _ := json.Marshal(PlanRequest{
		Query:   "run it",
		User:    UserContext{ID: 1, Email: "user@example.com"},
		Context: map[string]interface{}{"plan_id": "plan_execute_binds"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	executePlanHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s, want 200 awaiting approval", w.Code, w.Body.String())
	}
	workflowID, _ := decodeResume(t, w.Body.Bytes())["workflow_id"].(string)
	plan, err := planService.GetPlan(context.Background(), "plan_execute_binds", "org_1")
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	if workflowID == "" || plan.BoundWorkflowID() != workflowID {
		t.Errorf("plan bound to %q, response workflow %q: want the executor's workflow bound", plan.BoundWorkflowID(), workflowID)
	}
}

// resolvePlanWorkflow refuses a bound workflow that has ended, marked Ended.
// The resume's later layers would also refuse (planResumeStepIndex's terminal
// rule; ApproveStep's terminal refusal), so this is asserted on the function:
// the reject arm keys on Ended to fail the plan.
func TestResolvingABoundWorkflowThatEndedRefusesAsEnded(t *testing.T) {
	f := executeRealPlan(t, "plan_bound_ended", "confirm", nil)
	if err := workflowControlService.RejectStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "reviewer@example.com", "rejected in review"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	plan, err := planService.GetPlan(context.Background(), f.planID, "org_1")
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}

	wf, refusal, err := resolvePlanWorkflow(context.Background(), workflowControlService, plan, "tenant_1", "org_1")

	if err != nil || wf != nil || refusal == nil || !refusal.Ended || refusal.Status != http.StatusConflict || !strings.Contains(refusal.Message, f.workflowID) {
		t.Errorf("resolve = (%+v, %+v, %v), want an Ended 409 naming %s", wf, refusal, err, f.workflowID)
	}
}

// markBindingEmpty puts a plan back into the state between its executing mark
// and its bind: executing, binding recorded and still empty (row 5701284556).
func markBindingEmpty(t *testing.T, planID string) {
	t.Helper()
	stored, err := planService.GetPlan(context.Background(), planID, "org_1")
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	stored.ExecutionResult = json.RawMessage(`{"wcp_workflow_id":""}`)
}

// A plan still being set up (marked executing, not yet bound) is not resumed
// through a lookalike created in that window: the resume is refused and runs
// nothing.
func TestAPlanStillBeingSetUpIsNotResumedThroughALookalike(t *testing.T) {
	f := executeRealPlanUnbound(t, "plan_setup_window", "step")
	if err := f.mock.Delete(context.Background(), f.workflowID); err != nil {
		t.Fatalf("delete the executor's workflow: %v", err)
	}
	markBindingEmpty(t, f.planID)
	createLookalike(t, "map-step-"+f.planID)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusConflict || len(*f.ran) != 0 || !strings.Contains(w.Body.String(), "still being set up") {
		t.Errorf("status %d ran %v body %s, want 409 naming the set-up window and nothing run", w.Code, *f.ran, w.Body.String())
	}
}

// A plan whose executor fails before the bind is failed, so it never stays
// executing with an empty binding: its resume answers that it is not executing.
func TestAPlanWhoseExecutorFailsBeforeTheBindIsFailed(t *testing.T) {
	previousPlans, previousExec, previousWCP, previousWorkflow, previousAudit := planService, mapWCPExecutor, workflowControlService, workflowEngine, auditLogger
	t.Cleanup(func() {
		planService, mapWCPExecutor, workflowControlService, workflowEngine, auditLogger = previousPlans, previousExec, previousWCP, previousWorkflow, previousAudit
	})
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	repo := planning.NewMockRepository()
	if err := repo.SavePlan(context.Background(), &planning.Plan{
		TenantID: "tenant_1", OrgID: "org_1", PlanID: "plan_executor_fails", Status: planning.PlanStatusPending,
		ExecutionMode: "confirm", Query: "nothing to run", Domain: "generic",
		// No steps: ExecuteWithConfirm refuses "workflow has no steps" before any bind.
		WorkflowDefinition: json.RawMessage(`{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"empty"},"spec":{"steps":[]}}`),
		ExpiresAt:          time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	planService = planning.NewService(repo)
	wcp := workflow_control.NewService(workflow_control.NewMockRepository(), nil, nil)
	workflowControlService = wcp
	mapWCPExecutor = NewMAPWCPExecutor(wcp, planService)
	workflowEngine = NewWorkflowEngine()
	auditLogger = NewAuditLogger("")
	withRouteRequestEngine(t, allowedStepVerdict())

	body, _ := json.Marshal(PlanRequest{Query: "run it", User: UserContext{ID: 1, Email: "user@example.com"},
		Context: map[string]interface{}{"plan_id": "plan_executor_fails"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	executePlanHandler(w, req)

	if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), "workflow has no steps") {
		t.Fatalf("PREMISE: want the executor's own failure (workflow has no steps), got %d %s", w.Code, w.Body.String())
	}
	plan, _ := planService.GetPlan(context.Background(), "plan_executor_fails", "org_1")
	if plan.Status != planning.PlanStatusFailed {
		t.Errorf("plan status = %s, want failed", plan.Status)
	}
	if r := resumeThePlan(t, "plan_executor_fails"); r.Code != http.StatusBadRequest || !strings.Contains(r.Body.String(), "must be executing") {
		t.Errorf("resume after the failed execute: status %d body %s, want 400 naming that it is not executing", r.Code, r.Body.String())
	}
}

// selectingEveryWorkflowRepository ignores the list's name filter, as a list
// that did not apply it would.
type selectingEveryWorkflowRepository struct {
	*workflow_control.MockRepository
}

func (r *selectingEveryWorkflowRepository) List(ctx context.Context, opts workflow_control.ListWorkflowsOptions) ([]workflow_control.Workflow, int, error) {
	opts.WorkflowName = ""
	return r.MockRepository.List(ctx, opts)
}

// The fallback selects only a workflow named for the plan: a running map
// workflow of another name is never the plan's, even from a list that returns
// every map workflow of the tenant.
func TestTheFallbackNeverSelectsAWorkflowOfAnotherName(t *testing.T) {
	f := executeRealPlanBinding(t, "plan_other_name", "confirm", func(m *workflow_control.MockRepository) workflow_control.Repository {
		return &selectingEveryWorkflowRepository{MockRepository: m}
	}, false)
	if err := f.mock.Delete(context.Background(), f.workflowID); err != nil {
		t.Fatalf("delete the executor's workflow: %v", err)
	}
	createLookalike(t, "map-confirm-some-other-plan")

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusNotFound || len(*f.ran) != 0 {
		t.Errorf("status %d ran %v body %s, want 404 and nothing run", w.Code, *f.ran, w.Body.String())
	}
}

// A bound plan acts on the workflow its executor created, under the tenant
// that executed it: tenant B executing tenant A's plan binds B's workflow, B
// resumes it, A is refused 404, and a third tenant is refused 403.
func TestABoundPlanIsAuthorizedByItsBoundWorkflowsTenant(t *testing.T) {
	oldPlans, oldExec, oldWCP, oldEngine := planService, mapWCPExecutor, workflowControlService, workflowEngine
	t.Cleanup(func() {
		planService, mapWCPExecutor, workflowControlService, workflowEngine = oldPlans, oldExec, oldWCP, oldEngine
	})
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	// The resumed step is decided when it runs (#4249 row 5666236540); this test
	// is about which tenant may resume, so the engine allows the step.
	withMAPEngine(t, allowedStepVerdict())
	ctx := context.Background()
	planRepo := planning.NewMockRepository()
	planService = planning.NewService(planRepo)
	plan := &planning.Plan{OrgID: "org_1", TenantID: "tenant_1", PlanID: "plan_other_executor", Query: "q", Domain: "generic",
		ExecutionMode: "confirm", Status: planning.PlanStatusPending, WorkflowDefinition: json.RawMessage(resumeHoldPlanDef), Version: 1}
	if err := planRepo.SavePlan(ctx, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	if err := planRepo.MarkExecutingWithPendingBinding(ctx, plan.PlanID); err != nil {
		t.Fatalf("mark: %v", err)
	}
	mock := workflow_control.NewMockRepository()
	svc := workflow_control.NewService(mock, nil, nil)
	workflowControlService = svc
	mapWCPExecutor = NewMAPWCPExecutor(svc, planService)
	var ran []string
	engine := NewWorkflowEngine()
	for _, stepType := range []string{"connector-call", "llm-call"} {
		engine.stepProcessors[stepType] = namingStepProcessor{&ran}
	}
	workflowEngine = engine
	var wf Workflow
	_ = json.Unmarshal([]byte(resumeHoldPlanDef), &wf)
	res, err := mapWCPExecutor.ExecuteWithConfirm(ctx, plan, &wf, "tenant_2", "org_1", "u", "c")
	if err != nil {
		t.Fatalf("execute as tenant_2: %v", err)
	}
	if err := planService.BindExecutionWorkflow(ctx, plan.PlanID, res.WorkflowID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	resumeAs := func(tenant string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]interface{}{"approved": true})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/"+plan.PlanID+"/resume", bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org_1")
		req.Header.Set("X-Tenant-ID", tenant)
		req = mux.SetURLVars(req, map[string]string{"id": plan.PlanID})
		installProxyTokenValidator(t, proxyGuardTestSecret)
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		w := httptest.NewRecorder()
		resumePlanHandler(w, req)
		return w
	}

	if w := resumeAs("tenant_3"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "this plan belongs to another tenant") {
		t.Errorf("tenant_3: status %d body %s, want 403 naming another tenant, not a withheld step", w.Code, w.Body.String())
	}
	if w := resumeAs("tenant_1"); w.Code != http.StatusNotFound {
		t.Errorf("tenant_1 (the plan's tenant, not the executor's): status %d body %s, want 404", w.Code, w.Body.String())
	}
	if len(ran) != 0 {
		t.Fatalf("a refused resume ran %v", ran)
	}
	if w := resumeAs("tenant_2"); w.Code != http.StatusOK || strings.Join(ran, ",") != "fetch" {
		t.Errorf("tenant_2 (the executor's tenant): status %d ran %v body %s, want 200 running fetch", w.Code, ran, w.Body.String())
	}
}

// Plan-level approve and reject answer the selection's own refusals, and a plan
// not in confirm or step mode has no paused step: 404 (the in-memory flow it
// used to reach is retired, #4249 row 5774060413).
func TestPlanLevelDecisionsAnswerTheSelectionsRefusals(t *testing.T) {
	t.Run("another tenant is refused 403", func(t *testing.T) {
		env := setupMAPApproverEnv(t, "decide_other_tenant")
		defer env.cleanup()
		rr := httptest.NewRecorder()
		mapStepApproveHandler(rr, mapHITLRequest("approve", env.planID, env.stepID, `{"comment":"approved after review"}`,
			map[string]string{"X-User-ID": "reviewer@example.com", "X-Tenant-ID": "tenant-2"}))
		if rr.Code != http.StatusForbidden {
			t.Errorf("status %d body %s, want 403", rr.Code, rr.Body.String())
		}
		if row, _ := env.repo.GetStep(context.Background(), env.wfID, env.stepID); row == nil || row.ApprovalStatus == nil || *row.ApprovalStatus != workflow_control.ApprovalStatusPending {
			t.Errorf("step = %+v, want still pending", row)
		}
	})
	// Reject shares planWorkflowForDecision with approve, so it answers another
	// tenant the same 403 and leaves the step pending (#4434 round 1).
	t.Run("another tenant's reject is refused 403", func(t *testing.T) {
		env := setupMAPApproverEnv(t, "reject_other_tenant")
		defer env.cleanup()
		rr := httptest.NewRecorder()
		mapStepRejectHandler(rr, mapHITLRequest("reject", env.planID, env.stepID, `{"reason":"Rejected after full audit review"}`,
			map[string]string{"X-User-ID": "reviewer@example.com", "X-Tenant-ID": "tenant-2"}))
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "this plan belongs to another tenant") {
			t.Errorf("status %d body %s, want 403 naming another tenant", rr.Code, rr.Body.String())
		}
		if row, _ := env.repo.GetStep(context.Background(), env.wfID, env.stepID); row == nil || row.ApprovalStatus == nil || *row.ApprovalStatus != workflow_control.ApprovalStatusPending {
			t.Errorf("step = %+v, want still pending", row)
		}
	})
	t.Run("an ended workflow is refused 409", func(t *testing.T) {
		env := setupMAPApproverEnv(t, "decide_ended")
		defer env.cleanup()
		if err := workflowControlService.AbortWorkflow(context.Background(), env.wfID, "operator abort", "tenant-1", "org-1"); err != nil {
			t.Fatalf("abort: %v", err)
		}
		rr := httptest.NewRecorder()
		mapStepApproveHandler(rr, mapHITLRequest("approve", env.planID, env.stepID, `{"comment":"approved after review"}`,
			map[string]string{"X-User-ID": "reviewer@example.com"}))
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "is aborted") {
			t.Errorf("status %d body %s, want 409 naming the aborted workflow", rr.Code, rr.Body.String())
		}
	})
	t.Run("a plan still being set up is refused 409", func(t *testing.T) {
		env := setupMAPApproverEnv(t, "decide_setup")
		defer env.cleanup()
		stored, _ := planService.GetPlan(context.Background(), env.planID, "org-1")
		stored.ExecutionResult = json.RawMessage(`{"wcp_workflow_id":""}`)
		rr := httptest.NewRecorder()
		mapStepRejectHandler(rr, mapHITLRequest("reject", env.planID, env.stepID, `{"reason":"Rejected after full audit review"}`,
			map[string]string{"X-User-ID": "reviewer@example.com"}))
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "still being set up") {
			t.Errorf("status %d body %s, want 409 naming the set-up window", rr.Code, rr.Body.String())
		}
	})
	t.Run("a plan not in confirm or step mode has no paused step", func(t *testing.T) {
		env := setupMAPApproverEnv(t, "decide_sequential")
		defer env.cleanup()
		stored, _ := planService.GetPlan(context.Background(), env.planID, "org-1")
		stored.ExecutionMode = "sequential"
		rr := httptest.NewRecorder()
		mapStepApproveHandler(rr, mapHITLRequest("approve", env.planID, env.stepID, `{"comment":"approved after review"}`,
			map[string]string{"X-User-ID": "reviewer@example.com"}))
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "No paused execution") {
			t.Errorf("status %d body %s, want 404 no paused execution", rr.Code, rr.Body.String())
		}
	})
}

// While a plan executes, its execution_result holds the workflow binding, not a
// result, and is not projected; a completed plan's result is.
func TestTheBindingIsNotProjectedAsAnExecutionResult(t *testing.T) {
	executing := &planning.Plan{PlanID: "p1", Status: planning.PlanStatusExecuting, ExecutionMode: "confirm",
		ExecutionResult: json.RawMessage(`{"wcp_workflow_id":"wf_1"}`)}
	if _, present := planToExecutionStatus(executing).Metadata["execution_result"]; present {
		t.Errorf("an executing plan's binding was projected as execution_result")
	}
	completed := &planning.Plan{PlanID: "p2", Status: planning.PlanStatusCompleted, ExecutionMode: "confirm",
		ExecutionResult: json.RawMessage(`{"summary":"done"}`)}
	if _, present := planToExecutionStatus(completed).Metadata["execution_result"]; !present {
		t.Errorf("a completed plan's result was not projected")
	}
}

// The name fallback selects a plan's workflow by planWorkflowName, so each
// executor must name the workflow it creates by exactly those bytes.
func TestTheExecutorsNameTheirWorkflowByPlanWorkflowName(t *testing.T) {
	workflow := &Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{
		{Name: "fetch", Type: "connector-call"},
		{Name: "analyze", Type: "llm-call"},
	}}}
	for _, mode := range []string{"confirm", "step"} {
		t.Run(mode, func(t *testing.T) {
			wcpSvc := workflow_control.NewService(workflow_control.NewMockRepository(), nil, nil)
			executor := NewMAPWCPExecutor(wcpSvc, nil)
			plan := &planning.Plan{OrgID: "org-1", TenantID: "tenant-1", PlanID: "plan-name-" + mode, ExecutionMode: mode}
			execute := executor.ExecuteWithConfirm
			if mode == "step" {
				execute = executor.ExecuteWithStep
			}
			result, err := execute(context.Background(), plan, workflow, "tenant-1", "org-1", "user-1", "client-1")
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			created, err := wcpSvc.GetWorkflow(context.Background(), result.WorkflowID, "tenant-1", "org-1")
			if err != nil {
				t.Fatalf("get workflow: %v", err)
			}
			if want := planWorkflowName(mode, plan.PlanID); created.WorkflowName != want {
				t.Errorf("the %s executor named its workflow %q, want planWorkflowName %q", mode, created.WorkflowName, want)
			}
		})
	}
}

// addForeignGateRow writes a gate row under a step id that is not one of the
// plan's step gates, as another caller of the workflow's gate route can
// (#4249 row 5713229791). StepIndex 0 lists it before the plan's own rows. A
// row with no approval status is a policy allow; a pending one is a
// require_approval hold.
func (f *realResumeFixture) addForeignGateRow(t *testing.T, stepID string, status *workflow_control.ApprovalStatus) {
	t.Helper()
	decision := workflow_control.GateDecisionAllow
	if status != nil {
		decision = workflow_control.GateDecisionRequireApproval
	}
	row := &workflow_control.WorkflowStep{WorkflowID: f.workflowID, StepID: stepID, StepIndex: 0, StepName: "probe",
		StepType: workflow_control.StepTypeToolCall, Decision: decision, ApprovalStatus: status}
	if err := f.mock.AddStep(context.Background(), row); err != nil {
		t.Fatalf("add foreign row: %v", err)
	}
}

// A gate row a policy allowed under a foreign step id (no approval status) no
// longer makes the plan unresumable: the resume runs the plan's own approved
// step and answers the ignored row.
func TestAPlanResumeIsNotRefusedByAForeignAllowRow(t *testing.T) {
	f := executeRealPlan(t, "plan_foreign_allow_row", "confirm", nil)
	f.addForeignGateRow(t, "tenant-probe", nil)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Fatalf("status %d ran %v body %s, want 200 running fetch", w.Code, *f.ran, w.Body.String())
	}
	if got := decodeResume(t, w.Body.Bytes())["ignored_foreign_gate_rows"]; got != float64(1) {
		t.Errorf("ignored_foreign_gate_rows = %v, want 1", got)
	}
}

// A pending gate row under a foreign step id is neither approved by the resume
// nor waited on: the resume approves and runs the plan's own pending step.
func TestAPlanResumeNeitherApprovesNorWaitsOnAForeignPendingRow(t *testing.T) {
	pending := workflow_control.ApprovalStatusPending
	f := executeRealPlan(t, "plan_foreign_pending_row", "confirm", nil)
	f.addForeignGateRow(t, "tenant-probe", &pending)

	w := resumeThePlan(t, f.planID)

	if w.Code != http.StatusOK || strings.Join(*f.ran, ",") != "fetch" {
		t.Fatalf("status %d ran %v body %s, want 200 running fetch", w.Code, *f.ran, w.Body.String())
	}
	if got := approvalOf(f.row(t, "tenant-probe")); got != "pending" {
		t.Errorf("the foreign row = %s, want still pending (never approved by the resume)", got)
	}
	if got := approvalOf(f.row(t, "step_0_fetch")); got != "approved" {
		t.Errorf("step_0_fetch = %s, want approved by the resume", got)
	}
	if got := decodeResume(t, w.Body.Bytes())["ignored_foreign_gate_rows"]; got != float64(1) {
		t.Errorf("ignored_foreign_gate_rows = %v, want 1", got)
	}
}

// rejectThePlan sends a rejecting resume for planID.
func rejectThePlan(t *testing.T, planID string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"approved": false})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/"+planID+"/resume", bytes.NewReader(body))
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", "test-user")
	req = mux.SetURLVars(req, map[string]string{"id": planID})
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	resumePlanHandler(w, req)
	return w
}

// A rejecting resume with a foreign pending row rejects the plan's own pending
// step, never the foreign row, and fails the plan.
func TestAPlanRejectWithAForeignPendingRowRejectsNoneOfIt(t *testing.T) {
	pending := workflow_control.ApprovalStatusPending
	f := executeRealPlan(t, "plan_foreign_pending_reject", "confirm", nil)
	f.addForeignGateRow(t, "tenant-probe", &pending)

	w := rejectThePlan(t, f.planID)

	if w.Code != http.StatusOK || decodeResume(t, w.Body.Bytes())["status"] != "rejected" || len(*f.ran) != 0 {
		t.Fatalf("status %d ran %v body %s, want 200 rejected and nothing run", w.Code, *f.ran, w.Body.String())
	}
	if got := approvalOf(f.row(t, "tenant-probe")); got != "pending" {
		t.Errorf("the foreign row = %s, want still pending (never rejected by the resume)", got)
	}
	if got := approvalOf(f.row(t, "step_0_fetch")); got != "rejected" {
		t.Errorf("step_0_fetch = %s, want rejected", got)
	}
	stored, err := planService.GetPlan(context.Background(), f.planID, "org_1")
	if err != nil || stored.Status != planning.PlanStatusFailed {
		t.Errorf("plan = %+v (%v), want failed", stored, err)
	}
}

// A rejecting resume whose only pending row is foreign (the plan's own step is
// approved) rejects nothing: it falls to AbortWorkflow, which aborts the
// workflow and leaves the foreign row pending on it, and the plan fails. At
// base the resume rejected the foreign row with its own actor.
func TestAPlanRejectWhoseOnlyPendingRowIsForeignAbortsAndRejectsNothing(t *testing.T) {
	pending := workflow_control.ApprovalStatusPending
	f := executeRealPlan(t, "plan_foreign_only_pending_reject", "confirm", nil)
	if err := workflowControlService.ApproveStep(context.Background(), f.workflowID, "step_0_fetch", "tenant_1", "org_1", "approver@example.com", "approved before the reject"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	f.addForeignGateRow(t, "tenant-probe", &pending)

	w := rejectThePlan(t, f.planID)

	if w.Code != http.StatusOK || decodeResume(t, w.Body.Bytes())["status"] != "rejected" || len(*f.ran) != 0 {
		t.Fatalf("status %d ran %v body %s, want 200 rejected and nothing run", w.Code, *f.ran, w.Body.String())
	}
	if got := approvalOf(f.row(t, "tenant-probe")); got != "pending" {
		t.Errorf("the foreign row = %s, want still pending (never rejected by the resume)", got)
	}
	if got := approvalOf(f.row(t, "step_0_fetch")); got != "approved" {
		t.Errorf("step_0_fetch = %s, want still approved (nothing rejected)", got)
	}
	wf, err := workflowControlService.GetWorkflow(context.Background(), f.workflowID, "tenant_1", "org_1")
	if err != nil || wf.Status != workflow_control.WorkflowStatusAborted {
		t.Errorf("workflow = %+v (%v), want aborted", wf, err)
	}
	stored, err := planService.GetPlan(context.Background(), f.planID, "org_1")
	if err != nil || stored.Status != planning.PlanStatusFailed {
		t.Errorf("plan = %+v (%v), want failed", stored, err)
	}
}
