// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4249 rows 5701303521 / 5774077156, master R3 round 1 on #4387: the route
// chokepoint where it meets the dispatch paths.

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"axonflow/platform/orchestrator/planning"
)

// HIGH-1: THE RESUMED STEP IS ROUTED FOR THE CALLER THAT RESUMED IT. With no
// email the execution read "membership established, no segments", and every
// segment-scoped route row was dropped on this path alone. An unvouched email
// reads "not established, every segment", so a segment row binds.
func TestAResumedStepsLLMCallTakesASegmentScopedRouteRow(t *testing.T) {
	p := routeProducerOver(t, routeTestRows(map[string]interface{}{
		"f": segmentRouteRow("f", routeTestOrg, "seg-finance", 100, "anthropic"),
	}), false)
	withLLMCallRouteSource(t, p, nil)
	withMAPEngine(t, allowedStepVerdict())
	router := newRecordingLLMRouter()
	engine := NewWorkflowEngine()
	engine.InitializeWithDependencies(router, nil)
	workflow := &Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{routeStep}}}
	ctx := withResumePrincipal(mapSubjectContext(), UserContext{Email: "bob@example.com"})

	res, err := (&MAPWCPExecutor{}).ExecuteSingleStep(ctx, &planning.Plan{PlanID: "plan-route-seg", OrgID: routeTestOrg, TenantID: "t-route"}, workflow, 0, nil, "u", engine)
	if err != nil || res == nil || res.Status != "completed" {
		t.Fatalf("ExecuteSingleStep = %+v, %v", res, err)
	}
	if len(router.handed) != 1 {
		t.Fatalf("router handed %d requests, want 1", len(router.handed))
	}
	if got := OrchestratorRequestToLLMContext(router.handed[0]).PolicyAllowedProviders; !reflect.DeepEqual(got, []string{"anthropic"}) {
		t.Errorf("a resumed step was handed allow-list %v, want [anthropic]: the segment-scoped row was dropped", got)
	}
}

// HIGH-2: A ROUTE REFUSAL IS A POLICY REFUSAL, NOT A FAILED STEP. A parallel
// group (the first two of three steps: groupStepsForExecution runs every step
// but the last in parallel) whose soft_failure_tolerance absorbs any failure
// still fails with it: the refused step's sibling, which the rows permit, is
// called once, and the third step never runs. Absorbed, the group would go on
// and the third step's call would reach the router too (R3 round 2, M-1).
func TestARouteRefusalFailsAParallelGroupWhateverItsTolerance(t *testing.T) {
	t0 := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	marker := "route-parallel-refused"
	rows := routeTestRows(map[string]interface{}{
		"x": routeRow("x", 100, t0, []PolicyCondition{{Field: "query", Operator: "contains", Value: marker}}, allowedProvidersConfig("anthropic")),
		"y": routeRow("y", 50, t0, []PolicyCondition{{Field: "query", Operator: "contains", Value: marker}}, allowedProvidersConfig("openai")),
	})
	withLLMCallRouteSource(t, routeProducerOver(t, rows, false), nil)
	router := newRecordingLLMRouter()
	engine := NewWorkflowEngine()
	engine.InitializeWithDependencies(router, nil)
	engine.SetStepGate(&allowEveryStep{}, nil)
	wf := Workflow{Metadata: WorkflowMetadata{Name: "route-parallel"}, Spec: WorkflowSpec{
		SoftFailureTolerance: "any",
		Steps: []WorkflowStep{
			{Name: "refused", Type: "llm-call", Prompt: marker + ": one"},
			{Name: "permitted", Type: "llm-call", Prompt: "two"},
			{Name: "last", Type: "llm-call", Prompt: "three"},
		},
	}}
	if groups := engine.groupStepsForExecution(wf.Spec.Steps, true); len(groups) != 2 || !groups[0].IsParallel || len(groups[0].Steps) != 2 {
		t.Fatalf("PREMISE: groups %+v; want the first two steps in one parallel group", groups)
	}

	exec, err := engine.ExecuteWorkflowWithParallelSupport(context.Background(), wf, map[string]interface{}{}, UserContext{OrgID: routeTestOrg}, true)

	var refusal *mapStepRefusal
	if !errors.As(err, &refusal) || refusal.code != mapStepRouteRefused || refusal.policy != reasonNoCompliantProvider {
		t.Fatalf("err = %v; want the route refusal, not absorbed by soft_failure_tolerance any", err)
	}
	if exec == nil || exec.Status != "failed" {
		t.Errorf("execution %+v; want failed", exec)
	}
	if len(router.handed) != 1 {
		t.Errorf("the router was called %d times, want once: the permitted sibling only, never the step after the refused group", len(router.handed))
	}
}

// ...and a conditional's BRANCH step keeps the refusal's type through the
// conditional's wrap (R3 round 2, M-2).
func TestARouteRefusalOnABranchStepKeepsItsType(t *testing.T) {
	withLLMCallRouteSource(t, &recordingRouteFacts{routes: routeEffects{Restricted: true, AllowedProviders: []string{}}}, nil)
	router := newRecordingLLMRouter()
	engine := NewWorkflowEngine()
	engine.InitializeWithDependencies(router, nil)
	engine.SetStepGate(&allowEveryStep{}, nil)
	wf := Workflow{Metadata: WorkflowMetadata{Name: "route-branch"}, Spec: WorkflowSpec{Steps: []WorkflowStep{
		{Name: "check", Type: "conditional", Condition: "never", IfFalse: []WorkflowStep{{Name: "branch", Type: "llm-call", Prompt: "p"}}},
	}}}

	_, err := engine.ExecuteWorkflowWithParallelSupport(context.Background(), wf, map[string]interface{}{}, UserContext{OrgID: routeTestOrg}, true)

	var refusal *mapStepRefusal
	if !errors.As(err, &refusal) || refusal.code != mapStepRouteRefused {
		t.Fatalf("err = %v (%T); want the branch step's route refusal, typed", err, err)
	}
	if len(router.handed) != 0 {
		t.Errorf("the router was called %d times", len(router.handed))
	}
}

// ...and the workflow execute route answers it 403 with its code, as it answers
// the plane's other step refusals, not 500 "Execution failed".
func TestTheWorkflowExecuteRouteAnswersARouteRefusal403(t *testing.T) {
	withLLMCallRouteSource(t, &recordingRouteFacts{routes: routeEffects{Restricted: true, AllowedProviders: []string{}}}, nil)
	previous := workflowEngine
	t.Cleanup(func() { workflowEngine = previous })
	router := newRecordingLLMRouter()
	engine := NewWorkflowEngine()
	engine.InitializeWithDependencies(router, nil)
	engine.SetStepGate(&allowEveryStep{}, nil)
	workflowEngine = engine

	w := postWorkflowBody(t, map[string]interface{}{
		"workflow": Workflow{Metadata: WorkflowMetadata{Name: "route-403"}, Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "draft", Type: "llm-call", Prompt: "p"}}}},
		"input":    map[string]interface{}{}, "user": UserContext{ID: 1, Email: "user@example.com"},
	})

	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s; want 403", w.Code, w.Body.String())
	}
	if b := decodeRefusal(t, w); b.Code != mapStepRouteRefused || b.Policy != reasonNoCompliantProvider {
		t.Errorf("refusal %+v; want %s naming %s", b, mapStepRouteRefused, reasonNoCompliantProvider)
	}
	if len(router.handed) != 0 {
		t.Errorf("the router was called %d times", len(router.handed))
	}
}

// MEDIUM-3: EVERY ROUTE REFUSAL WRITES ITS AUDIT ROW, as /api/v1/process
// records the same refusal: blocked, blocked_by route_layer, the reason, in the
// organization the call was made for.
func TestAnLLMCallRouteRefusalWritesItsAuditRow(t *testing.T) {
	previous := auditLogger
	t.Cleanup(func() { auditLogger = previous })
	for _, tc := range []struct {
		name   string
		routes routeEffects
		err    error
		reason string
	}{
		{"rows permit nothing", routeEffects{Restricted: true, AllowedProviders: []string{}}, nil, reasonNoCompliantProvider},
		{"route cannot be established", routeEffects{}, errDynamicFactsUnavailable, "segment_resolution_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := responsePlaneLogger()
			auditLogger = l
			withLLMCallRouteSource(t, &recordingRouteFacts{routes: tc.routes, err: tc.err}, nil)

			if _, err := llmStepRun(t, newRecordingLLMRouter(), routeStep); err == nil {
				t.Fatalf("PREMISE: the step was not refused")
			}

			row := oneAuditRowWhere(t, l, "the route refusal", anyRow)
			if row.PolicyDecision != "blocked" || row.PolicyDetails["blocked_by"] != blockedByRouteLayer {
				t.Errorf("row decision %q blocked_by %v; want blocked by %s", row.PolicyDecision, row.PolicyDetails["blocked_by"], blockedByRouteLayer)
			}
			if applied, _ := row.PolicyDetails["applied_policies"].([]string); !reflect.DeepEqual(applied, []string{tc.reason}) {
				t.Errorf("row applied_policies %v; want [%s]", row.PolicyDetails["applied_policies"], tc.reason)
			}
			if row.OrgID != routeTestOrg {
				t.Errorf("row org %q; want the plan's organization %s", row.OrgID, routeTestOrg)
			}
		})
	}
}
