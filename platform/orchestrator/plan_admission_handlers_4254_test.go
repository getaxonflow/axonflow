// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4254: the plan handlers refuse a plan whose conditional step carries branch
// steps BEFORE any step runs, because those branch steps would execute with no
// decision. refuseUnpresentableSteps' own table test proves the refusal is
// computed, and the ordering test proves each handler calls it before it
// executes; these prove each handler HONOURS it. The mutation run found the
// gap: with the refusal's result ignored, a branched plan executed undecided
// and every other test stayed green.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
)

// branchedConditionalWorkflow is a plan whose middle step is a conditional
// carrying a branch step, between two ordinary steps.
const branchedConditionalWorkflow = `{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"branched"},"spec":{"steps":[` +
	`{"name":"draft","type":"llm-call"},` +
	`{"name":"check","type":"conditional","condition":"true","if_true":[{"name":"export","type":"connector-call"}]},` +
	`{"name":"notify","type":"connector-call"}]}}`

// withRecordingWorkflowEngine installs a workflow engine whose processors for
// every step type in branchedConditionalWorkflow record that a step ran.
func withRecordingWorkflowEngine(t *testing.T) *recordingStepProcessor {
	t.Helper()
	previous := workflowEngine
	processor := &recordingStepProcessor{}
	engine := NewWorkflowEngine()
	for _, stepType := range []string{"llm-call", "connector-call", "conditional"} {
		engine.stepProcessors[stepType] = processor
	}
	workflowEngine = engine
	t.Cleanup(func() { workflowEngine = previous })
	return processor
}

func TestPlanExecuteRefusesABranchedConditionalBeforeAnyStepRuns(t *testing.T) {
	previousPlans, previousAudit := planService, auditLogger
	t.Cleanup(func() { planService, auditLogger = previousPlans, previousAudit })
	repo := planning.NewMockRepository()
	if err := repo.SavePlan(context.Background(), &planning.Plan{
		TenantID:           "tenant_1",
		PlanID:             "plan_branched_execute",
		Status:             planning.PlanStatusPending,
		StepCount:          3,
		Query:              "draft and export",
		Domain:             "generic",
		OrgID:              "org_1",
		WorkflowDefinition: json.RawMessage(branchedConditionalWorkflow),
		ExpiresAt:          time.Now().Add(time.Hour),
		CreatedAt:          time.Now(),
	}); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	planService = planning.NewService(repo)
	rows := responsePlaneLogger()
	auditLogger = rows
	withRecordingRouteFacts(t, allowedStepVerdict())
	processor := withRecordingWorkflowEngine(t)
	before := ungovernableCount()

	body, _ := json.Marshal(PlanRequest{
		Query:   "run it",
		User:    UserContext{ID: 1, Email: "user@example.com"},
		Context: map[string]interface{}{"plan_id": "plan_branched_execute"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	w := httptest.NewRecorder()
	executePlanHandler(w, req)

	if processor.ran != 0 {
		t.Fatalf("%d step(s) ran for a plan whose conditional carries branch steps; want none", processor.ran)
	}
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Plan cannot be governed") {
		t.Errorf("status %d body %s; want 400 naming the plan as ungovernable", w.Code, w.Body.String())
	}
	plan, err := repo.GetPlan(context.Background(), "plan_branched_execute")
	if err != nil {
		t.Fatalf("read back the plan: %v", err)
	}
	if plan.Status != planning.PlanStatusFailed {
		t.Errorf("plan status = %s, want %s", plan.Status, planning.PlanStatusFailed)
	}
	assertUngovernableRecorded(t, rows, before)
}

func TestPlanResumeRefusesABranchedConditionalBeforeAnyStepRuns(t *testing.T) {
	cleanup := setupResumeTestWCPWithWorkflow(t, "plan_branched_resume", "confirm", branchedConditionalWorkflow)
	defer cleanup()
	processor := withRecordingWorkflowEngine(t)
	previousAudit := auditLogger
	t.Cleanup(func() { auditLogger = previousAudit })
	rows := responsePlaneLogger()
	auditLogger = rows
	before := ungovernableCount()

	body, _ := json.Marshal(map[string]interface{}{"approved": true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/plan_branched_resume/resume", bytes.NewReader(body))
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", "test-user")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_branched_resume"})
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	resumePlanHandler(w, req)

	if processor.ran != 0 {
		t.Fatalf("%d step(s) ran on resume for a plan whose conditional carries branch steps; want none", processor.ran)
	}
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Plan cannot be governed") {
		t.Errorf("status %d body %s; want 400 naming the plan as ungovernable", w.Code, w.Body.String())
	}
	plan, err := planService.GetPlan(context.Background(), "plan_branched_resume", "org_1")
	if err != nil {
		t.Fatalf("read back the plan: %v", err)
	}
	if plan.Status != planning.PlanStatusFailed {
		t.Errorf("plan status = %s, want %s", plan.Status, planning.PlanStatusFailed)
	}
	assertUngovernableRecorded(t, rows, before)

	// R3 B-M4: refused BEFORE the approve block, so the pending step is left
	// pending, and the workflow the plan was running is aborted.
	step, err := workflowControlService.GetStep(context.Background(), "wf-plan_branched_resume", "step_0_step1", "tenant_1", "org_1")
	if err != nil {
		t.Fatalf("read back the step: %v", err)
	}
	if step.ApprovalStatus == nil || *step.ApprovalStatus != workflow_control.ApprovalStatusPending {
		t.Errorf("the pending step's approval status is %v after the refusal; want it still pending, never approved", step.ApprovalStatus)
	}
	wf, err := workflowControlService.GetWorkflow(context.Background(), "wf-plan_branched_resume", "tenant_1", "org_1")
	if err != nil {
		t.Fatalf("read back the workflow: %v", err)
	}
	if wf.Status != workflow_control.WorkflowStatusAborted {
		t.Errorf("the workflow is %s after the refusal, want aborted", wf.Status)
	}
}
