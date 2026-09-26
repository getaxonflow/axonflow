// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4249 row 5701303521: a multi-agent plan's llm-call step takes the
// organization's route rows (applyLLMCallRoutes), as /api/v1/process does. The
// observable is what the router is handed, read through the adapter that turns
// it into the router's allow-list (OrchestratorRequestToLLMContext), and
// whether the router is called at all: never the verdict.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"axonflow/platform/orchestrator/planning"
)

// withLLMCallRouteSource installs src as the route fact source for the test's
// lifetime: the source /api/v1/process and applyLLMCallRoutes read.
func withLLMCallRouteSource(t *testing.T, src routeFactSource, err error) {
	t.Helper()
	previous := newRouteRequestFactProducer
	newRouteRequestFactProducer = func() (routeFactSource, error) { return src, err }
	resetRouteRequestFacts()
	t.Cleanup(func() {
		newRouteRequestFactProducer = previous
		resetRouteRequestFacts()
	})
}

// recordingLLMRouter records every request it is handed and serves each one.
type recordingLLMRouter struct {
	mockLLMRouterInterface
	handed []OrchestratorRequest
}

func newRecordingLLMRouter() *recordingLLMRouter {
	r := &recordingLLMRouter{}
	r.routeRequestFn = func(_ context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
		r.handed = append(r.handed, req)
		return &LLMResponse{Content: "a response long enough to pass every length check the processor makes on it"},
			&ProviderInfo{Provider: "stand-in"}, nil
	}
	return r
}

// llmStepRun runs one llm-call step through the processor, for the plan's user.
func llmStepRun(t *testing.T, router LLMRouterInterface, step WorkflowStep) (map[string]interface{}, error) {
	t.Helper()
	exec := &WorkflowExecution{ID: "wf-route", UserContext: UserContext{OrgID: routeTestOrg, TenantID: "t-route"}}
	return NewLLMCallProcessor(router).ExecuteStep(context.Background(), step, map[string]interface{}{}, exec)
}

var routeStep = WorkflowStep{Name: "draft", Type: "llm-call", Provider: "openai", Prompt: "summarise the quarter"}

// With no applying route row the request the router is handed carries no
// policy key: today's provider choice stands, byte for byte.
func TestAnLLMCallStepWithNoRouteRowsIsHandedTheRequestUnchanged(t *testing.T) {
	withLLMCallRouteSource(t, &recordingRouteFacts{}, nil)
	router := newRecordingLLMRouter()
	if _, err := llmStepRun(t, router, routeStep); err != nil {
		t.Fatalf("step: %v", err)
	}
	if len(router.handed) != 1 {
		t.Fatalf("router handed %d requests, want 1", len(router.handed))
	}
	for k := range router.handed[0].Context {
		if strings.HasPrefix(k, "policy_") {
			t.Errorf("a step with no route rows was handed %q", k)
		}
	}
}

// THE ROW: the organization's allow-list reaches the router for a plan step, and
// the step's own provider hint does not widen it.
func TestAnLLMCallStepIsHandedTheOrganizationsAllowedProviders(t *testing.T) {
	src := &recordingRouteFacts{routes: routeEffects{Restricted: true, AllowedProviders: []string{"anthropic"},
		PreferredProvider: "anthropic", RoutingReason: "eu residency"}}
	withLLMCallRouteSource(t, src, nil)
	router := newRecordingLLMRouter()
	if _, err := llmStepRun(t, router, routeStep); err != nil {
		t.Fatalf("step: %v", err)
	}
	if len(router.handed) != 1 {
		t.Fatalf("router handed %d requests, want 1", len(router.handed))
	}
	got := OrchestratorRequestToLLMContext(router.handed[0])
	if !reflect.DeepEqual(got.PolicyAllowedProviders, []string{"anthropic"}) {
		t.Errorf("router allow-list = %v, want [anthropic]: the step's call ignored the organization's route rows", got.PolicyAllowedProviders)
	}
	if got.PolicyPreferredProvider != "anthropic" || got.PolicyRoutingReason != "eu residency" {
		t.Errorf("router preference = %q (%q), want anthropic (eu residency)", got.PolicyPreferredProvider, got.PolicyRoutingReason)
	}
	// The route is decided over the call the step makes: its prompt, for the
	// plan's organization.
	if len(src.captured) != 1 || src.captured[0].Query != routeStep.Prompt || src.captured[0].User.OrgID != routeTestOrg {
		t.Errorf("route decided over %+v, want the step's prompt for %s", src.captured, routeTestOrg)
	}
}

// Route rows that permit nothing refuse the step BEFORE any provider is called,
// naming #4348's reason. An empty allow-list reaching the router would read as
// "unrestricted".
func TestAnLLMCallStepWhoseRouteRowsPermitNothingIsRefusedBeforeTheCall(t *testing.T) {
	for _, tc := range []struct {
		name   string
		routes routeEffects
		reason string
	}{
		{"disjoint rows", routeEffects{Restricted: true, AllowedProviders: []string{}}, reasonNoCompliantProvider},
		{"segment not established", routeEffects{Restricted: true, AllowedProviders: []string{}, SegmentNotEstablished: true}, reasonSegmentNotEstablished},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withLLMCallRouteSource(t, &recordingRouteFacts{routes: tc.routes}, nil)
			router := newRecordingLLMRouter()
			out, err := llmStepRun(t, router, routeStep)
			assertLLMCallRouteRefusal(t, out, err, tc.reason)
			if len(router.handed) != 0 {
				t.Errorf("the router was called %d times on rows that permit nothing", len(router.handed))
			}
		})
	}
}

// A route that cannot be established refuses the step (fail-closed): an outage
// is never an unrestricted call.
func TestAnLLMCallStepWhoseRouteCannotBeEstablishedIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		src     routeFactSource
		wireErr error
		reason  string
	}{
		{"segment resolution outage", &recordingRouteFacts{err: errDynamicFactsUnavailable}, nil, "segment_resolution_failed"},
		{"producer error", &recordingRouteFacts{err: errors.New("rows unreadable")}, nil, "decision_enforcement_unavailable"},
		{"source not wired", nil, errors.New("the dynamic policy engine is not wired"), "decision_enforcement_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withLLMCallRouteSource(t, tc.src, tc.wireErr)
			router := newRecordingLLMRouter()
			out, err := llmStepRun(t, router, routeStep)
			assertLLMCallRouteRefusal(t, out, err, tc.reason)
			if len(router.handed) != 0 {
				t.Errorf("the router was called %d times on a route that could not be established", len(router.handed))
			}
		})
	}
}

// A ROUTE ROW CONDITIONED ON CONTENT APPLIES TO THE PROMPT THE STEP SENDS, over
// the production producer: it steers when the prompt matches and not otherwise.
func TestAContentConditionedRouteRowAppliesToTheStepsPrompt(t *testing.T) {
	t0 := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	rows := routeTestRows(map[string]interface{}{
		"route-eu": routeRow("route-eu", 100, t0,
			[]PolicyCondition{{Field: "query", Operator: "contains", Value: "patient"}},
			allowedProvidersConfig("anthropic")),
	})
	withLLMCallRouteSource(t, routeProducerOver(t, rows, false), nil)

	router := newRecordingLLMRouter()
	matching := routeStep
	matching.Prompt = "summarise the patient notes"
	if _, err := llmStepRun(t, router, matching); err != nil {
		t.Fatalf("matching step: %v", err)
	}
	if _, err := llmStepRun(t, router, routeStep); err != nil {
		t.Fatalf("non-matching step: %v", err)
	}
	if len(router.handed) != 2 {
		t.Fatalf("router handed %d requests, want 2", len(router.handed))
	}
	if got := OrchestratorRequestToLLMContext(router.handed[0]).PolicyAllowedProviders; !reflect.DeepEqual(got, []string{"anthropic"}) {
		t.Errorf("a prompt the row's content condition matches was handed allow-list %v, want [anthropic]", got)
	}
	if got := OrchestratorRequestToLLMContext(router.handed[1]).PolicyAllowedProviders; len(got) != 0 {
		t.Errorf("CONTROL: a prompt the row does not match was handed allow-list %v, want none", got)
	}
}

// THE RESUME PATH: confirm and step mode run a later step through
// ExecuteSingleStep, which never re-runs the plan-level decision. The step's
// call still takes the rows.
func TestAStepRunByTheConfirmAndStepExecutorTakesTheRouteRows(t *testing.T) {
	src := &recordingRouteFacts{routes: routeEffects{Restricted: true, AllowedProviders: []string{"anthropic"}}}
	withLLMCallRouteSource(t, src, nil)
	router := newRecordingLLMRouter()
	engine := NewWorkflowEngine()
	engine.InitializeWithDependencies(router, nil)
	// The step is decided before it runs (#4360): an allowing engine, for the
	// credential the resume route installs.
	withMAPEngine(t, allowedStepVerdict())
	workflow := &Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "first", Type: "llm-call", Prompt: "a"}, routeStep}}}
	res, err := (&MAPWCPExecutor{}).ExecuteSingleStep(mapSubjectContext(), &planning.Plan{PlanID: "plan-route", OrgID: routeTestOrg, TenantID: "t-route"}, workflow, 1, nil, "u", engine)
	if err != nil || res == nil || res.Status == "failed" {
		t.Fatalf("ExecuteSingleStep = %+v, %v", res, err)
	}
	if len(router.handed) != 1 {
		t.Fatalf("router handed %d requests, want 1", len(router.handed))
	}
	if got := OrchestratorRequestToLLMContext(router.handed[0]).PolicyAllowedProviders; !reflect.DeepEqual(got, []string{"anthropic"}) {
		t.Errorf("a step run by the confirm/step executor was handed allow-list %v, want [anthropic]", got)
	}
	// The rows are selected for the plan's organization: an execution with no
	// organization would select none and call unrestricted.
	if len(src.captured) != 1 || src.captured[0].User.OrgID != routeTestOrg {
		t.Errorf("route decided over %+v, want the plan's organization %s", src.captured, routeTestOrg)
	}
}

// assertLLMCallRouteRefusal asserts a step failed with the route refusal naming
// reason, and produced no output.
func assertLLMCallRouteRefusal(t *testing.T, out map[string]interface{}, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the step ran (output %v), want it refused with %s", out, reason)
	}
	var refusal *llmCallRouteRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("step error = %v (%T), want an llmCallRouteRefusal", err, err)
	}
	if refusal.Reason != reason {
		t.Errorf("refusal reason = %q, want %q", refusal.Reason, reason)
	}
	// A policy refusal, typed as the plane's step refusal (R3 round 1 HIGH-2):
	// soft_failure_tolerance does not absorb it and the execute routes answer
	// it 403 with its code.
	var stepRefusal *mapStepRefusal
	if !errors.As(err, &stepRefusal) || stepRefusal.code != mapStepRouteRefused || stepRefusal.policy != reason {
		t.Errorf("step error %v (%T) is not the plane's step refusal with code %s naming %s", err, err, mapStepRouteRefused, reason)
	}
	if out != nil {
		t.Errorf("a refused step produced output %v", out)
	}
}

// #4249 row 5774077156: plan generation's two LLM calls take the requester's
// route rows, decided for the requester's organization while the call keeps the
// planner's identity.
func TestPlanGenerationsLLMCallsAreHandedTheRequestersAllowedProviders(t *testing.T) {
	src := &recordingRouteFacts{routes: routeEffects{Restricted: true, AllowedProviders: []string{"anthropic"}}}
	withLLMCallRouteSource(t, src, nil)
	router := newRecordingLLMRouter()
	_, err := NewPlanningEngine(router).GeneratePlan(context.Background(), PlanGenerationRequest{
		Query: "plan a trip", Domain: "travel", ExecutionMode: "auto", RequestID: "plan-route",
		User: UserContext{OrgID: routeTestOrg, TenantID: "t-route"}, Client: ClientContext{OrgID: routeTestOrg, TenantID: "t-route"},
	})
	if err != nil {
		t.Fatalf("GeneratePlan: %v", err)
	}
	if len(router.handed) != 2 {
		t.Fatalf("router handed %d requests, want the planner's 2 (analysis, workflow)", len(router.handed))
	}
	for i, handed := range router.handed {
		if got := OrchestratorRequestToLLMContext(handed).PolicyAllowedProviders; !reflect.DeepEqual(got, []string{"anthropic"}) {
			t.Errorf("planner call %d (%s) was handed allow-list %v, want [anthropic]", i, handed.RequestType, got)
		}
		if handed.User.TenantID != "system" || handed.Client.OrgID != "" {
			t.Errorf("planner call %d changed identity to user %+v client %+v: the call is still made as the planner", i, handed.User, handed.Client)
		}
	}
	if len(src.captured) != 2 {
		t.Fatalf("route decided %d times, want 2", len(src.captured))
	}
	for i, presented := range src.captured {
		if presented.Client.OrgID != routeTestOrg || presented.User.OrgID != routeTestOrg {
			t.Errorf("route %d decided for client %+v user %+v, want the requester's organization %s", i, presented.Client, presented.User, routeTestOrg)
		}
		if presented.Query != "plan a trip" {
			t.Errorf("route %d decided over %q, want the requester's query alone, not the planner's instructions around it", i, presented.Query)
		}
	}
}

// Rows that permit nothing refuse plan generation before any provider is called,
// and the refusal is NOT answered by the heuristic analysis or the template
// workflow, which exist for a provider that failed.
func TestPlanGenerationWhoseRouteRowsPermitNothingIsRefusedNotFallenBack(t *testing.T) {
	withLLMCallRouteSource(t, &recordingRouteFacts{routes: routeEffects{Restricted: true, AllowedProviders: []string{}}}, nil)
	router := newRecordingLLMRouter()
	workflow, err := NewPlanningEngine(router).GeneratePlan(context.Background(), PlanGenerationRequest{
		Query: "plan a trip", Domain: "travel", ExecutionMode: "auto", RequestID: "plan-route",
		Client: ClientContext{OrgID: routeTestOrg},
	})
	var refusal *llmCallRouteRefusal
	if !errors.As(err, &refusal) || refusal.Reason != reasonNoCompliantProvider {
		t.Fatalf("GeneratePlan = %v, %v; want refused with %s", workflow, err, reasonNoCompliantProvider)
	}
	if workflow != nil {
		t.Errorf("a refused plan generation returned a workflow: %+v", workflow)
	}
	if len(router.handed) != 0 {
		t.Errorf("the router was called %d times on rows that permit nothing", len(router.handed))
	}
}

// THROUGH THE REAL HANDLER: POST /api/v1/plan under rows that permit nothing
// answers 403 naming the reason, as /api/v1/process refuses the same route; the
// rows are selected for the organization the gateway stamped.
func TestThePlanRouteAnswersARouteRefusal403NamingTheReason(t *testing.T) {
	oldPlanning, oldWorkflow, oldPlans := planningEngine, workflowEngine, planService
	t.Cleanup(func() { planningEngine, workflowEngine, planService = oldPlanning, oldWorkflow, oldPlans })
	src := &recordingRouteFacts{routes: routeEffects{Restricted: true, AllowedProviders: []string{}}}
	withLLMCallRouteSource(t, src, nil)
	router := newRecordingLLMRouter()
	planningEngine = NewPlanningEngine(router)
	workflowEngine = NewWorkflowEngine()
	// A real (mock-backed) plan store: were the refusal lost, the handler would
	// go on to store the plan, and this cell must then fail, not nil-deref.
	planService = planning.NewService(planning.NewMockRepository())

	req := httptest.NewRequest("POST", "/api/v1/plan", strings.NewReader(`{"query":"plan a trip","user":{"id":1,"email":"test@example.com"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "plan-org")
	req.Header.Set("X-Tenant-ID", "plan-tenant")
	w := httptest.NewRecorder()
	planRequestHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d (body %s), want 403", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), reasonNoCompliantProvider) {
		t.Errorf("body %s does not name %s", w.Body.String(), reasonNoCompliantProvider)
	}
	if len(router.handed) != 0 {
		t.Errorf("the router was called %d times on rows that permit nothing", len(router.handed))
	}
	if len(src.captured) == 0 || src.captured[0].Client.OrgID != "plan-org" {
		t.Errorf("route decided for %+v, want the stamped organization plan-org", src.captured)
	}
}

// A confirm or step mode step whose call the rows refuse is WITHHELD, as the
// step decision's refusals are, so the resume answers 403 and fails the plan.
// As a failed step result it was marked completed and the plan went on.
func TestAConfirmAndStepStepRefusedByTheRouteRowsIsWithheld(t *testing.T) {
	withLLMCallRouteSource(t, &recordingRouteFacts{routes: routeEffects{Restricted: true, AllowedProviders: []string{}}}, nil)
	withMAPEngine(t, allowedStepVerdict())
	router := newRecordingLLMRouter()
	engine := NewWorkflowEngine()
	engine.InitializeWithDependencies(router, nil)
	workflow := &Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{routeStep}}}
	res, err := (&MAPWCPExecutor{}).ExecuteSingleStep(mapSubjectContext(), &planning.Plan{PlanID: "plan-route-refused", OrgID: routeTestOrg, TenantID: "t-route"}, workflow, 0, nil, "u", engine)
	var withheld *mapStepWithheldError
	if !errors.As(err, &withheld) || res != nil {
		t.Fatalf("ExecuteSingleStep = %+v, %v; want a withheld step", res, err)
	}
	if !strings.Contains(err.Error(), reasonNoCompliantProvider) {
		t.Errorf("the withhold %q does not name %s", err.Error(), reasonNoCompliantProvider)
	}
	if len(router.handed) != 0 {
		t.Errorf("the router was called %d times on rows that permit nothing", len(router.handed))
	}
}
