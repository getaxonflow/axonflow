// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/shared/anchoredenforcer"
)

// #4249 row 5665091860: the admission refusal of a conditional carrying branch
// steps is lifted only where the engine presents every step: workflow execute,
// and plan execute outside confirm and step mode. Since #4382 that engine is the
// declarative one, whose step gate the orchestrator wires on every deployment,
// and AXONFLOW_HITL_ENABLED changes nothing. In confirm/step mode the admission
// still refuses before any step runs, and an engine with no step gate runs
// nothing.

// takenBranchWorkflow runs draft (answers status=approved), then a conditional on it
// whose taken branch holds an export connector call, then notify.
const takenBranchWorkflow = `{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"taken-branch"},"spec":{"steps":[` +
	`{"name":"draft","type":"llm-call"},` +
	`{"name":"check","type":"conditional","condition":"{{steps.draft.output.status}} == approved","if_true":[{"name":"export","type":"connector-call"}],"if_false":[{"name":"skipped","type":"llm-call"}]},` +
	`{"name":"notify","type":"connector-call"}]}}`

// withBranchEngine installs a workflow engine whose llm-call and connector-call
// steps run through a recording processor and whose conditional is the real
// ConditionalProcessor, with or without the plane's step gate, and the
// process's AXONFLOW_HITL_ENABLED value, for the test's lifetime.
func withBranchEngine(t *testing.T, enabled, withChecker bool) *branchEvents {
	t.Helper()
	previousWorkflow, previousEnabled := workflowEngine, hitlEnabled
	t.Cleanup(func() {
		workflowEngine, hitlEnabled = previousWorkflow, previousEnabled
	})
	log := &branchEvents{}
	engine := NewWorkflowEngine()
	for _, typ := range []string{"llm-call", "connector-call"} {
		engine.stepProcessors[typ] = recordingRunProcessor{log: log}
	}
	engine.stepProcessors["conditional"] = NewConditionalProcessor(engine)
	workflowEngine = engine
	hitlEnabled = enabled
	if withChecker {
		engine.SetStepGate(&MAPHITLPolicyChecker{}, auditLogger)
	}
	return log
}

// mapStepCalls are the anchored decisions the multi-agent plane made.
func mapStepCalls(d *stepGateEnforcerDouble) []anchoredenforcer.Call {
	d.mu.Lock()
	defer d.mu.Unlock()
	var calls []anchoredenforcer.Call
	for _, c := range d.calls {
		if c.Scope == mapSeamScope {
			calls = append(calls, c)
		}
	}
	return calls
}

func executeTakenBranchWorkflow(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	var wf Workflow
	if err := json.Unmarshal([]byte(takenBranchWorkflow), &wf); err != nil {
		t.Fatalf("decode: %v", err)
	}
	body, _ := json.Marshal(map[string]interface{}{"workflow": wf, "input": map[string]interface{}{},
		"user": UserContext{ID: 1, Email: "user@example.com", OrgID: "org_1", TenantID: "tenant_1"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	req.Header.Set("X-Client-ID", "client_1")
	w := httptest.NewRecorder()
	executeWorkflowHandler(w, req)
	return w
}

func TestWorkflowExecuteAdmitsABranchedConditionalOnlyWhereItsBranchStepsArePresented(t *testing.T) {
	previousAudit := auditLogger
	t.Cleanup(func() { auditLogger = previousAudit })
	auditLogger = responsePlaneLogger()

	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("AXONFLOW_HITL_ENABLED=%v: admitted, and the taken branch step is presented before it runs", enabled), func(t *testing.T) {
			log := withBranchEngine(t, enabled, true)
			d := withMAPEngine(t, allowedStepVerdict())

			w := executeTakenBranchWorkflow(t)

			if w.Code != http.StatusOK {
				t.Fatalf("status %d body %s, want 200", w.Code, w.Body.String())
			}
			if calls := mapStepCalls(d); len(calls) != 3 || strings.Join(log.all(), ",") != "run:draft,run:export,run:notify" {
				t.Errorf("%d map decisions, runs %v; want 3 decisions (draft, export, notify) and those three runs, the conditional and the untaken branch neither decided nor run", len(calls), log.all())
			}
		})
	}
	// An engine that decides nothing refuses a branched conditional at
	// admission, before its missing gate refuses everything else
	// (map_step_gate_4382_test.go).
	t.Run("an engine with no step gate: refused at admission, nothing runs", func(t *testing.T) {
		log := withBranchEngine(t, true, false)

		w := executeTakenBranchWorkflow(t)

		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Workflow cannot be governed") || len(log.all()) != 0 {
			t.Errorf("status %d runs %v body %s, want 400 naming the workflow as ungovernable and nothing run", w.Code, log.all(), w.Body.String())
		}
	})
}

func executeTakenBranchPlan(t *testing.T, planID, mode string) (*httptest.ResponseRecorder, *planning.MockRepository) {
	t.Helper()
	repo := planning.NewMockRepository()
	if err := repo.SavePlan(context.Background(), &planning.Plan{
		TenantID: "tenant_1", OrgID: "org_1", PlanID: planID, Status: planning.PlanStatusPending, StepCount: 3,
		ExecutionMode: mode, Query: "draft and export", Domain: "generic",
		WorkflowDefinition: json.RawMessage(takenBranchWorkflow), ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	planService = planning.NewService(repo)
	body, _ := json.Marshal(PlanRequest{Query: "run it", User: UserContext{ID: 1, Email: "user@example.com"},
		Context: map[string]interface{}{"plan_id": planID}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	w := httptest.NewRecorder()
	executePlanHandler(w, req)
	return w, repo
}

func TestPlanExecuteAdmitsABranchedConditionalOnlyOnItsPresentingHITLArm(t *testing.T) {
	previousPlans, previousAudit := planService, auditLogger
	t.Cleanup(func() { planService, auditLogger = previousPlans, previousAudit })
	auditLogger = responsePlaneLogger()

	// In parallel mode the conditional runs in one group with draft, before
	// draft's output exists, so it takes its other branch: the mode's own
	// semantics, unchanged by #4382. Every mode presents the branch step it takes.
	for _, tc := range []struct {
		mode    string
		enabled bool
		runs    string
	}{
		{"auto", true, "run:draft,run:export,run:notify"},
		{"auto", false, "run:draft,run:export,run:notify"},
		{"sequential", false, "run:draft,run:export,run:notify"},
		{"parallel", false, "run:draft,run:notify,run:skipped"},
		{"balanced", false, "run:draft,run:export,run:notify"},
	} {
		t.Run(fmt.Sprintf("%s mode, AXONFLOW_HITL_ENABLED=%v: admitted, and the taken branch step is presented before it runs", tc.mode, tc.enabled), func(t *testing.T) {
			log := withBranchEngine(t, tc.enabled, true)
			withRecordingRouteFacts(t, allowedStepVerdict())
			d := withMAPEngine(t, allowedStepVerdict())

			w, _ := executeTakenBranchPlan(t, fmt.Sprintf("plan_taken_branch_%s_%v", tc.mode, tc.enabled), tc.mode)

			if w.Code != http.StatusOK {
				t.Fatalf("status %d body %s, want 200", w.Code, w.Body.String())
			}
			runs := log.all()
			sort.Strings(runs)
			if calls := mapStepCalls(d); len(calls) != 3 || strings.Join(runs, ",") != tc.runs {
				t.Errorf("%d map decisions, runs %v; want 3 and %s", len(calls), log.all(), tc.runs)
			}
		})
	}
	t.Run("an engine with no step gate: refused at admission, nothing runs", func(t *testing.T) {
		log := withBranchEngine(t, true, false)
		withRecordingRouteFacts(t, allowedStepVerdict())

		w, repo := executeTakenBranchPlan(t, "plan_taken_branch_no_gate", "auto")

		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Plan cannot be governed") || len(log.all()) != 0 {
			t.Errorf("status %d runs %v body %s, want 400 naming the plan as ungovernable and nothing run", w.Code, log.all(), w.Body.String())
		}
		if plan, _ := repo.GetPlan(context.Background(), "plan_taken_branch_no_gate"); plan == nil || plan.Status != planning.PlanStatusFailed {
			t.Errorf("plan = %+v, want failed", plan)
		}
	})
	for _, tc := range []struct {
		name            string
		mode            string
		enabled, withCk bool
	}{
		{"confirm mode with a step gate", "confirm", true, true},
		{"step mode with a step gate", "step", false, true},
	} {
		t.Run(tc.name+": refused at admission, nothing runs", func(t *testing.T) {
			log := withBranchEngine(t, tc.enabled, tc.withCk)
			withRecordingRouteFacts(t, allowedStepVerdict())

			w, repo := executeTakenBranchPlan(t, "plan_taken_branch_"+strings.ReplaceAll(tc.name, " ", "_"), tc.mode)

			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Plan cannot be governed") || len(log.all()) != 0 {
				t.Errorf("status %d runs %v body %s, want 400 naming the plan as ungovernable and nothing run", w.Code, log.all(), w.Body.String())
			}
			if plan, _ := repo.GetPlan(context.Background(), "plan_taken_branch_"+strings.ReplaceAll(tc.name, " ", "_")); plan == nil || plan.Status != planning.PlanStatusFailed {
				t.Errorf("plan = %+v, want failed", plan)
			}
		})
	}
}
