// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// A CONDITIONAL CARRYING NO BRANCH STEPS IS NOT PRESENTED, ON EVERY MODE (R3 B-H1).
//
// It invokes nothing, so no gate is taken, no row is written and nothing runs for
// it, and the execution continues past it: in the HITL engine, in confirm mode,
// in step mode and on plan resume.

func branchlessConditional() WorkflowStep {
	return WorkflowStep{Name: "check", Type: "conditional", Condition: "true"}
}

func TestABranchlessConditionalIsNotPresentedInTheHITLEngine(t *testing.T) {
	d := withMAPEngine(t, allowedStepVerdict())
	rows := responsePlaneLogger()
	hitl, processor := mapHITLEngine(&recordingApprovalService{})
	hitl.SetAuditLogger(rows)
	conditional := &recordingStepProcessor{}
	hitl.engine.stepProcessors["conditional"] = conditional
	wf := Workflow{
		Metadata: WorkflowMetadata{Name: "branchless"},
		Spec:     WorkflowSpec{Steps: []WorkflowStep{{Name: "a", Type: "llm-call"}, branchlessConditional(), {Name: "b", Type: "llm-call"}}},
	}

	exec, err := hitl.ExecuteWithHITL(mapSubjectContext(), wf, map[string]interface{}{}, UserContext{OrgID: "org-map"})

	if err != nil || exec == nil || exec.Status != "completed" {
		t.Fatalf("execution = (%+v, %v), want completed past the conditional", exec, err)
	}
	if processor.ran != 2 || conditional.ran != 0 {
		t.Errorf("ran %d llm-call steps and %d conditional steps, want 2 and 0", processor.ran, conditional.ran)
	}
	if n := d.callCount(); n != 2 {
		t.Errorf("the engine decided %d steps, want the 2 presented ones", n)
	}
	if n := len(auditRowsWhere(rows, isMAPStepGateRow)); n != 2 {
		t.Errorf("%d step_gate rows written, want 2: the conditional writes none", n)
	}
}

func TestConfirmModeLeavesABranchlessConditionalOutOfTheGovernedSteps(t *testing.T) {
	executor := NewMAPWCPExecutor(workflow_control.NewService(workflow_control.NewMockRepository(), nil, nil), nil)
	plan := &planning.Plan{OrgID: "org_1", TenantID: "tenant_1", PlanID: "confirm-branchless", Domain: "test", Query: "q"}
	workflow := &Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{branchlessConditional(), {Name: "draft", Type: "llm-call"}}}}

	result, err := executor.ExecuteWithConfirm(context.Background(), plan, workflow, "t1", "o1", "u1", "c1")

	if err != nil {
		t.Fatalf("confirm mode refused a plan whose only unmapped step is a branchless conditional: %v", err)
	}
	if result.StepName != "draft" || result.TotalSteps != 1 {
		t.Errorf("gated %q of %d steps, want draft of 1", result.StepName, result.TotalSteps)
	}
}

func TestStepModeLeavesABranchlessConditionalOutOfTheGovernedSteps(t *testing.T) {
	executor := NewMAPWCPExecutor(workflow_control.NewService(workflow_control.NewMockRepository(), nil, nil), nil)
	plan := &planning.Plan{OrgID: "org_1", TenantID: "tenant_1", PlanID: "step-branchless", Domain: "test", Query: "q"}
	workflow := &Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{
		{Name: "fetch", Type: "connector-call"}, branchlessConditional(), {Name: "report", Type: "llm-call"},
	}}}

	result, err := executor.ExecuteWithStep(context.Background(), plan, workflow, "t1", "o1", "u1", "c1")

	if err != nil {
		t.Fatalf("step mode refused a plan whose only unmapped step is a branchless conditional: %v", err)
	}
	if result.TotalSteps != 2 || result.StepName != "report" {
		t.Errorf("step mode awaits %q of %d steps, want report of 2", result.StepName, result.TotalSteps)
	}
}

// branchlessResumeWorkflow is a plan whose middle step is a branchless conditional.
const branchlessResumeWorkflow = `{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"branchless"},"spec":{"steps":[` +
	`{"name":"step1","type":"llm-call"},` +
	`{"name":"check","type":"conditional","condition":"true"},` +
	`{"name":"notify","type":"connector-call"}]}}`

// Plan resume runs the approved step and gates the next PRESENTED step: the
// branchless conditional is skipped, never gated as an unmapped type.
func TestPlanResumeSkipsABranchlessConditional(t *testing.T) {
	cleanup := setupResumeTestWCPWithWorkflow(t, "plan_branchless_resume", "confirm", branchlessResumeWorkflow)
	defer cleanup()
	processor := withRecordingWorkflowEngine(t)

	w := resumeThePlan(t, "plan_branchless_resume")

	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s; want 200 awaiting the next presented step", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["next_step_name"] != "notify" || resp["status"] != "awaiting_approval" {
		t.Errorf("resume answered next_step_name=%v status=%v, want notify awaiting_approval", resp["next_step_name"], resp["status"])
	}
	if processor.ran != 1 {
		t.Errorf("%d steps ran, want only the approved step1", processor.ran)
	}
}

// resumeThePlan approves the plan's pending step through the resume route over
// an authenticated hop.
func resumeThePlan(t *testing.T, planID string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"approved": true})
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

// ungovernableCount is the counter a branched-conditional refusal moves.
func ungovernableCount() float64 {
	return promtestutil.ToFloat64(anchoredenforcer.Decisions.WithLabelValues(mapSeamScope.String(), anchoredenforcer.EngineAnchored, "unavailable", anchoredenforcer.CauseRequest))
}

// assertUngovernableRecorded asserts one blocked row under plane map naming
// request_unbuildable, and the counter moved by one (R3 B-M5).
func assertUngovernableRecorded(t *testing.T, rows *AuditLogger, before float64) {
	t.Helper()
	row := oneAuditRowWhere(t, rows, "the ungovernable refusal's blocked", isBlockedRow)
	if row.Plane != "map" || row.PolicyDetails["engine"] != anchoredenforcer.EngineAnchored {
		t.Errorf("the refusal's row has plane %q engine %v, want map and anchored", row.Plane, row.PolicyDetails["engine"])
	}
	if got := row.PolicyDetails["applied_policies"]; !reflect.DeepEqual(got, []string{anchoredenforcer.CauseRequest}) {
		t.Errorf("the refusal's row names %v, want [%s]", got, anchoredenforcer.CauseRequest)
	}
	if got := ungovernableCount() - before; got != 1 {
		t.Errorf("the counter moved by %v, want 1", got)
	}
}

// A workflow execute refused for a branched conditional writes its row and counts.
func TestWorkflowExecuteRecordsTheUngovernableRefusal(t *testing.T) {
	previousAudit := auditLogger
	t.Cleanup(func() { auditLogger = previousAudit })
	rows := responsePlaneLogger()
	auditLogger = rows
	before := ungovernableCount()

	var wf Workflow
	if err := json.Unmarshal([]byte(branchedConditionalWorkflow), &wf); err != nil {
		t.Fatalf("decode the fixture: %v", err)
	}
	body, _ := json.Marshal(map[string]interface{}{"workflow": wf, "input": map[string]interface{}{}, "user": UserContext{ID: 1, Email: "user@example.com"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	w := httptest.NewRecorder()
	executeWorkflowHandler(w, req)

	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Workflow cannot be governed") {
		t.Fatalf("status %d body %s; want 400 naming the workflow as ungovernable", w.Code, w.Body.String())
	}
	assertUngovernableRecorded(t, rows, before)
}
