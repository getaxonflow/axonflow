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

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// #4249 row 5666236540: the multi-agent plane presents a step's content - its
// parts as written, the input it is passed, and what its processor will send,
// rendered by the function the processor sends it with - and the shipped
// content controls decide over it.

// withSeededMAPPlane installs the real shared enforcer and the map plane's
// producer, built by the production constructor, over the shipped dynamic rows.
func withSeededMAPPlane(t *testing.T) {
	t.Helper()
	installResponseEnforcer(t, respDocuments{}, nil)
	rows := seedDynamicRows(t)
	previous, previousEngine := newMAPFactProducer, dynamicPolicyEngine
	dynamicPolicyEngine = &mockPolicyEngineForHITL{}
	newMAPFactProducer = func() (*dynamicFactProducer, error) {
		p, err := previous()
		if err != nil {
			return nil, err
		}
		p.rows = fixedFactRows(rows)
		p.segments = func(context.Context, string, string) ([]string, bool) { return nil, true }
		return p, nil
	}
	resetMAPFacts()
	t.Cleanup(func() {
		newMAPFactProducer, dynamicPolicyEngine = previous, previousEngine
		resetMAPFacts()
	})
}

func decideMAPStep(t *testing.T, step WorkflowStep, content StepContent) *PolicyCheckResult {
	t.Helper()
	result, v := mapStepDecide(mapSubjectContext(), step, content, mapExecution())
	if v == nil || v.Decision == nil {
		t.Fatalf("PREMISE: no engine decision for %+v: %+v", step, result)
	}
	return result
}

func blockedByDebugRestriction(r *PolicyCheckResult) bool {
	return r != nil && !r.Allowed && strings.HasPrefix(r.PolicyID, debugRestrictControl)
}

// A pattern that exists only once the template and the value are joined is
// decided over the rendering: neither the prompt as written nor the input holds
// it.
func TestTheMAPPlaneDecidesAPatternSplitAcrossTemplateAndInput(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	withSeededMAPPlane(t)

	step := WorkflowStep{Name: "draft", Type: "llm-call", Prompt: "de{{input.rest}}"}
	content := StepContent{Input: map[string]interface{}{"rest": "bug the parser"}, Processor: NewLLMCallProcessor(nil)}
	query, err := mapStepContent(step, content, mapExecution())
	if err != nil {
		t.Fatal(err)
	}
	// The prompt as written and the rendering, one per line; neither the
	// written prompt nor the input value holds the pattern alone.
	if query != "de{{input.rest}}\ndebug the parser" {
		t.Fatalf("content %q; want the written prompt then its rendering", query)
	}
	if r := decideMAPStep(t, step, content); !blockedByDebugRestriction(r) {
		t.Fatalf("result %+v; want a block by %s", r, debugRestrictControl)
	}
}

// Whitespace inside a statement, a prompt or a rendered value is whitespace on
// the multi-agent plane too (R3 round 1 finding 1).
func TestTheMAPPlaneDecidesTenantIsolationAcrossWhitespace(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	withSeededMAPPlane(t)
	for _, sep := range []string{"\n", "\t"} {
		cases := map[string]struct {
			step    WorkflowStep
			content StepContent
		}{
			"statement":       {WorkflowStep{Name: "s", Type: "connector-call", Statement: "SELECT * FROM t WHERE tenant_id" + sep + "!= 2"}, StepContent{Processor: NewMCPConnectorProcessor()}},
			"rendered prompt": {WorkflowStep{Name: "s", Type: "llm-call", Prompt: "{{input.f}}"}, StepContent{Input: map[string]interface{}{"f": "tenant_id" + sep + "!= 2"}, Processor: NewLLMCallProcessor(nil)}},
			"api-call input":  {WorkflowStep{Name: "s", Type: "api-call"}, StepContent{Input: map[string]interface{}{"f": "tenant_id" + sep + "!= 2"}}},
		}
		for name, c := range cases {
			r := decideMAPStep(t, c.step, c.content)
			if r.Allowed || !strings.HasPrefix(r.PolicyID, tenantIsolationControl) {
				t.Errorf("%s with %q: %+v; want a block by %s", name, sep, r, tenantIsolationControl)
			}
		}
	}
}

// The engine's own bookkeeping in the input is never presented, and an
// llm-call presents its input only through what it renders (R3 round 1
// finding 5).
func TestTheMAPPlanePresentsOnlyWhatAStepSends(t *testing.T) {
	input := map[string]interface{}{"_policy_result": map[string]interface{}{"reason": "debug"}, "step_one_response": "debug notes", "q": "hello"}
	llm, err := mapStepContent(WorkflowStep{Name: "s", Type: "llm-call", Prompt: "{{input.q}}"}, StepContent{Input: input, Processor: NewLLMCallProcessor(nil)}, mapExecution())
	if err != nil || llm != "{{input.q}}\nhello" {
		t.Errorf("llm-call content %q, err %v; want the prompt and its rendering only", llm, err)
	}
	api, err := mapStepContent(WorkflowStep{Name: "s", Type: "api-call"}, StepContent{Input: input}, mapExecution())
	if err != nil || strings.Contains(api, "_policy_result") || !strings.Contains(api, "step_one_response\ndebug notes") {
		t.Errorf("api-call content %q, err %v; want the input it forwards, without the engine's _-prefixed keys", api, err)
	}
}

// Each raw part decides on its own, and a connector step's parameters are
// presented as they are sent.
func TestTheMAPPlaneDecidesOverEachPartOfAStep(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	withSeededMAPPlane(t)

	cases := map[string]struct {
		step    WorkflowStep
		content StepContent
	}{
		"prompt":    {WorkflowStep{Name: "s", Type: "llm-call", Prompt: "debug it"}, StepContent{Processor: NewLLMCallProcessor(nil)}},
		"statement": {WorkflowStep{Name: "s", Type: "connector-call", Statement: "SELECT * FROM t WHERE tenant_id != 2"}, StepContent{Processor: NewMCPConnectorProcessor()}},
		"parameter": {WorkflowStep{Name: "s", Type: "connector-call", Statement: "q", Parameters: map[string]interface{}{"mode": "debug"}}, StepContent{Processor: NewMCPConnectorProcessor()}},
		"input":     {WorkflowStep{Name: "s", Type: "connector-call", Statement: "q"}, StepContent{Input: map[string]interface{}{"x": "debug"}, Processor: NewMCPConnectorProcessor()}},
	}
	for name, c := range cases {
		r := decideMAPStep(t, c.step, c.content)
		if r.Allowed {
			t.Errorf("%s: the step was allowed; want it withheld by a content control", name)
		}
	}
	if r := decideMAPStep(t, WorkflowStep{Name: "s", Type: "llm-call", Prompt: "hello"}, StepContent{Processor: NewLLMCallProcessor(nil)}); !r.Allowed {
		t.Errorf("a harmless step was withheld: %+v", r)
	}
}

// A step with no content presents empty content; one with any presents it.
func TestTheMAPPlaneHandsTheEngineTheStepsContent(t *testing.T) {
	d := withMAPEngine(t, allowedStepVerdict())
	mapStepDecide(mapSubjectContext(), WorkflowStep{Name: "s", Type: "llm-call"}, StepContent{Processor: NewLLMCallProcessor(nil)}, mapExecution())
	if call := d.lastCall(t); call.Query != "" || !call.EmptyContent {
		t.Errorf("a step with no content: query %q empty %v; want empty content", call.Query, call.EmptyContent)
	}
	mapStepDecide(mapSubjectContext(), WorkflowStep{Name: "s", Type: "llm-call", Prompt: "p"}, StepContent{Processor: NewLLMCallProcessor(nil)}, mapExecution())
	call := d.lastCall(t)
	want := "p\np"
	if call.Query != want || call.EmptyContent {
		t.Errorf("query %q empty %v; want %s", call.Query, call.EmptyContent, want)
	}
}

// Content the encoder refuses is refused before the engine, never presented
// empty.
func TestMAPStepContentThatIsNotValidUTF8IsRefused(t *testing.T) {
	d := withMAPEngine(t, allowedStepVerdict())
	before := ungovernableCount()
	r, v := mapStepDecide(mapSubjectContext(), WorkflowStep{Name: "s", Type: "llm-call", Prompt: "{{input.x}}"},
		StepContent{Input: map[string]interface{}{"x": "debug \xff"}, Processor: NewLLMCallProcessor(nil)}, mapExecution())
	if v != nil || r == nil || r.Allowed || !strings.Contains(r.Reason, anchoredenforcer.CauseRequest) {
		t.Fatalf("result %+v verdict %v; want a block naming %s before the engine", r, v, anchoredenforcer.CauseRequest)
	}
	if n := d.callCount(); n != 0 {
		t.Errorf("the engine was called %d times", n)
	}
	if got := ungovernableCount() - before; got != 1 {
		t.Errorf("recorded %v refusal(s), want 1", got)
	}
}

// THE DRIFT GUARD: what a processor sends is what it renders.
type capturingLLMRouter struct {
	mockLLMRouterInterface
	queries []string
}

func (r *capturingLLMRouter) RouteRequest(_ context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
	r.queries = append(r.queries, req.Query)
	return &LLMResponse{Content: strings.Repeat("a long enough synthesised answer. ", 5)}, &ProviderInfo{Provider: "p", Model: "m"}, nil
}

type capturingConnector struct {
	mockConnector
	queries []*base.Query
}

func (c *capturingConnector) Query(ctx context.Context, q *base.Query) (*base.QueryResult, error) {
	c.queries = append(c.queries, q)
	return c.mockConnector.Query(ctx, q)
}

func TestWhatAStepProcessorSendsIsWhatItRenders(t *testing.T) {
	// An LLM call takes the organization's route rows; none apply here
	// (#4249 rows 5701303521, 5774077156).
	withLLMCallRouteSource(t, &recordingRouteFacts{}, nil)
	execution := &WorkflowExecution{
		ID:    "exec-drift",
		Input: map[string]interface{}{"region": "eu"},
		Steps: []StepExecution{{Name: "fetch", Status: "completed", Output: map[string]interface{}{"b": "two", "a": "one", "rows": "{{input.topic}}"}}},
	}
	input := map[string]interface{}{"topic": "flights {{input.city}}", "city": "Paris", "count": "3"}

	t.Run("llm-call, a synthesis step", func(t *testing.T) {
		router := &capturingLLMRouter{}
		p := NewLLMCallProcessor(router)
		step := WorkflowStep{Name: "final-summary", Type: "llm-call", Prompt: "Plan {{input.topic}} for {{steps.fetch.output.a}}"}
		parts := p.RenderStepContent(step, input, execution)
		if len(parts) != 1 {
			t.Fatalf("an llm-call renders %d parts, want its query", len(parts))
		}
		rendered := parts[0].(string)
		for i := 0; i < 20; i++ {
			if _, err := p.ExecuteStep(context.Background(), step, input, execution); err != nil {
				t.Fatal(err)
			}
		}
		if len(router.queries) != 20 {
			t.Fatalf("PREMISE: %d queries sent, want 20", len(router.queries))
		}
		for _, q := range router.queries {
			if q != rendered {
				t.Fatalf("sent %q; rendered %q", q, rendered)
			}
		}
		if !strings.Contains(rendered, "PREVIOUS STEP RESULTS") {
			t.Fatalf("PREMISE: the synthesis suffix is not in the rendering: %q", rendered)
		}
	})
	t.Run("connector-call", func(t *testing.T) {
		original := connectorRegistry
		t.Cleanup(func() { connectorRegistry = original })
		connectorRegistry = registry.NewRegistry()
		conn := &capturingConnector{mockConnector: mockConnector{name: "drift"}}
		if err := connectorRegistry.Register("drift", conn, &base.ConnectorConfig{Name: "drift"}); err != nil {
			t.Fatal(err)
		}
		p := NewMCPConnectorProcessor()
		step := WorkflowStep{Name: "q", Type: "connector-call", Connector: "drift", Statement: "search {{input.topic}}",
			Parameters: map[string]interface{}{"where": "{{workflow.input.region}}", "topic": "overridden by the input"}}
		parts := p.RenderStepContent(step, input, execution)
		if len(parts) != 2 {
			t.Fatalf("a connector-call renders %d parts, want its statement and parameters", len(parts))
		}
		want := map[string]interface{}{"statement": parts[0], "parameters": parts[1]}
		for i := 0; i < 20; i++ {
			if _, err := p.ExecuteStep(context.Background(), step, input, execution); err != nil {
				t.Fatal(err)
			}
		}
		if len(conn.queries) != 20 {
			t.Fatalf("PREMISE: %d queries sent, want 20", len(conn.queries))
		}
		for _, q := range conn.queries {
			sent := map[string]interface{}{"statement": q.Statement, "parameters": q.Parameters}
			a, _ := contract.ExactJSON(sent)
			b, _ := contract.ExactJSON(want)
			if string(a) != string(b) {
				t.Fatalf("sent %s; rendered %s", a, b)
			}
		}
	})
}

// The multi-agent workflow engine passes the checker the input it passes the
// step, prior outputs included, and the processor that runs it.
type recordingContentChecker struct{ contents []StepContent }

func (c *recordingContentChecker) CheckPolicy(_ context.Context, _ WorkflowStep, content StepContent, _ *WorkflowExecution) (*PolicyCheckResult, error) {
	c.contents = append(c.contents, content)
	return &PolicyCheckResult{Allowed: true, Action: "allow"}, nil
}

func TestTheWorkflowEnginePresentsTheInputItPassesTheStep(t *testing.T) {
	checker := &recordingContentChecker{}
	processor := &recordingStepProcessor{}
	engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"llm-call": processor}, storage: NewInMemoryWorkflowStorage()}
	engine.SetStepGate(checker, nil)
	wf := Workflow{Metadata: WorkflowMetadata{Name: "w"}, Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "one", Type: "llm-call"}, {Name: "two", Type: "llm-call"}}}}
	if _, err := engine.ExecuteWorkflow(context.Background(), wf, map[string]interface{}{"q": "v"}, UserContext{OrgID: "o"}); err != nil {
		t.Fatal(err)
	}
	if len(checker.contents) != 2 {
		t.Fatalf("%d checks, want 2", len(checker.contents))
	}
	if checker.contents[0].Processor != StepProcessor(processor) {
		t.Error("the checker was not handed the step's processor")
	}
	if checker.contents[1].Input["q"] != "v" || checker.contents[1].Input["step_one_ok"] != true {
		t.Errorf("the second step's presented input %v; want the workflow input and the first step's output", checker.contents[1].Input)
	}
}

// Rendering is deterministic: a value that itself holds a placeholder expands
// the same way every time.
func TestRenderingAStepIsDeterministic(t *testing.T) {
	p := NewLLMCallProcessor(nil)
	step := WorkflowStep{Name: "s", Type: "llm-call", Prompt: "{{input.a}} {{input.b}}"}
	input := map[string]interface{}{"a": "{{input.b}}", "b": "{{input.a}}", "c": "{{input.b}}"}
	first := p.RenderStepContent(step, input, &WorkflowExecution{})[0]
	for i := 0; i < 200; i++ {
		if again := p.RenderStepContent(step, input, &WorkflowExecution{})[0]; again != first {
			t.Fatalf("rendered %q then %q", first, again)
		}
	}
}

// STEP MODE: the one decision is at ExecuteSingleStep, for the context's
// subject in the plan's organization, over the input the step runs with.
func TestAStepModeStepIsDecidedWhenItRuns(t *testing.T) {
	// An LLM call takes the organization's route rows; none apply here
	// (#4249 rows 5701303521, 5774077156).
	withLLMCallRouteSource(t, &recordingRouteFacts{}, nil)
	plan := &planning.Plan{PlanID: "plan-step", OrgID: "org-map", TenantID: "tenant-map"}
	workflow := &Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "s", Type: "llm-call", Prompt: "{{input.q}}"}}}}

	t.Run("the decision carries the plan's organization and the content it runs with", func(t *testing.T) {
		d := withMAPEngine(t, allowedStepVerdict())
		processor := &recordingStepProcessor{}
		engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"llm-call": processor}}
		if _, err := NewMAPWCPExecutor(nil, nil).ExecuteSingleStep(mapSubjectContext(), plan, workflow, 0, map[string]interface{}{"q": "hi"}, "u", engine); err != nil {
			t.Fatal(err)
		}
		call := d.lastCall(t)
		if call.OrgID != "org-map" || call.Subject == nil || call.Query != "{{input.q}}\nq\nhi" {
			t.Errorf("call org %q subject %v query %q; want the plan's org, the context's subject, the run input", call.OrgID, call.Subject != nil, call.Query)
		}
		if processor.ran != 1 {
			t.Errorf("%d runs, want 1", processor.ran)
		}
	})
	// Each decision is the step's gate row (R3 round 1 finding 4): an allow, a
	// deny, and a challenge refused as approval_required.
	withRows := func(t *testing.T) *AuditLogger {
		t.Helper()
		previous := auditLogger
		t.Cleanup(func() { auditLogger = previous })
		rows := responsePlaneLogger()
		auditLogger = rows
		return rows
	}
	isStepGateRow := func(e *AuditEntry) bool { return e.Plane == "map" }
	t.Run("an allowed step's decision is its gate row", func(t *testing.T) {
		rows := withRows(t)
		withMAPEngine(t, allowedStepVerdict())
		engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"llm-call": &recordingStepProcessor{}}}
		if _, err := NewMAPWCPExecutor(nil, nil).ExecuteSingleStep(mapSubjectContext(), plan, workflow, 0, nil, "u", engine); err != nil {
			t.Fatal(err)
		}
		row := oneAuditRowWhere(t, rows, "the allowed step's gate", isStepGateRow)
		if row.PolicyDecision != "allowed" || row.PolicyDetails["engine"] != anchoredenforcer.EngineAnchored {
			t.Errorf("row decision %q engine %v; want allowed on the anchored engine", row.PolicyDecision, row.PolicyDetails["engine"])
		}
	})
	t.Run("a withheld step fails as a withhold, never runs, and is recorded", func(t *testing.T) {
		rows := withRows(t)
		withMAPEngine(t, stepGateVerdict(contract.StateDeny, contract.ReasonExplicitConstraint, contract.Determining{MatchedConstraints: []string{"c"}}))
		processor := &recordingStepProcessor{}
		engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"llm-call": processor}}
		_, err := NewMAPWCPExecutor(nil, nil).ExecuteSingleStep(mapSubjectContext(), plan, workflow, 0, nil, "u", engine)
		var withheld *mapStepWithheldError
		if !errors.As(err, &withheld) {
			t.Errorf("err %v; want a mapStepWithheldError", err)
		}
		if processor.ran != 0 {
			t.Errorf("a withheld step ran %d times", processor.ran)
		}
		if row := oneAuditRowWhere(t, rows, "the withheld step's gate", isStepGateRow); row.PolicyDecision != "blocked" {
			t.Errorf("row decision %q; want blocked", row.PolicyDecision)
		}
	})
	t.Run("a challenge is refused as approval_required and recorded", func(t *testing.T) {
		rows := withRows(t)
		withMAPEngine(t, heldStepVerdict())
		processor := &recordingStepProcessor{}
		engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"llm-call": processor}}
		_, err := NewMAPWCPExecutor(nil, nil).ExecuteSingleStep(mapSubjectContext(), plan, workflow, 0, nil, "u", engine)
		var withheld *mapStepWithheldError
		if !errors.As(err, &withheld) || withheld.result.Action != "block" || !strings.HasPrefix(withheld.result.Reason, string(contract.ReasonApprovalRequired)+":") || withheld.result.hold != nil {
			t.Fatalf("err %v; want a withhold as a block naming approval_required, with no hold", err)
		}
		if processor.ran != 0 {
			t.Errorf("a challenged step ran %d times", processor.ran)
		}
		if row := oneAuditRowWhere(t, rows, "the challenged step's gate", isStepGateRow); row.PolicyDecision != "blocked" {
			t.Errorf("row decision %q; want blocked", row.PolicyDecision)
		}
	})
	t.Run("an llm-call step is decided over the prompt it renders", func(t *testing.T) {
		d := withMAPEngine(t, allowedStepVerdict())
		router := &capturingLLMRouter{}
		engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"llm-call": NewLLMCallProcessor(router)}}
		if _, err := NewMAPWCPExecutor(nil, nil).ExecuteSingleStep(mapSubjectContext(), plan, workflow, 0, map[string]interface{}{"q": "hi", "_policy_result": "x"}, "u", engine); err != nil {
			t.Fatal(err)
		}
		if call := d.lastCall(t); call.Query != "{{input.q}}\nhi" {
			t.Errorf("query %q; want the written prompt and the rendering, and no input", call.Query)
		}
		if len(router.queries) != 1 || router.queries[0] != "hi" {
			t.Errorf("sent %v; want the rendering the decision was made over", router.queries)
		}
	})
	t.Run("a pattern the run input adds is caught on the real engine", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
		t.Setenv("ENVIRONMENT", "production")
		withSeededMAPPlane(t)
		processor := &recordingStepProcessor{}
		engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"llm-call": processor}}
		_, err := NewMAPWCPExecutor(nil, nil).ExecuteSingleStep(mapSubjectContext(), plan, workflow, 0, map[string]interface{}{"q": "please debug"}, "u", engine)
		if err == nil || !strings.Contains(err.Error(), "sys__dyn__debug__restrict") || processor.ran != 0 {
			t.Fatalf("err %v, ran %d; want the debug restriction to withhold the step", err, processor.ran)
		}
	})
}

// Plan resume decides the step for the credential that resumed it, in the
// plan's organization: a peer credential of the organization may resume a plan
// another submitted.
func TestPlanResumeDecidesTheStepForTheResumingCredential(t *testing.T) {
	cleanup := setupResumeTestWCPWithWorkflow(t, "plan_peer_client", "confirm", branchlessResumeWorkflow)
	defer cleanup()
	processor := withRecordingWorkflowEngine(t)
	d := withMAPEngine(t, allowedStepVerdict())
	plan, err := planService.GetPlan(context.Background(), "plan_peer_client", "org_1")
	if err != nil {
		t.Fatal(err)
	}
	plan.ClientID = "client-submitter"

	body, _ := json.Marshal(map[string]interface{}{"approved": true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/plan_peer_client/resume", bytes.NewReader(body))
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	req.Header.Set("X-Client-ID", "client-resumer")
	req.Header.Set("X-User-ID", "test-user")
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_peer_client"})
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	resumePlanHandler(w, req)

	if w.Code != http.StatusOK || processor.ran != 1 {
		t.Fatalf("status %d, %d step(s) ran, body %s; want 200 and the step run", w.Code, processor.ran, w.Body.String())
	}
	call := d.lastCall(t)
	subject := subjectOf(t, call, time.Now())
	principal := fmt.Sprintf("%+v", subject.Principal)
	if call.OrgID != "org_1" || subject.Principal.AuthenticatedOrgID != "org_1" || !strings.Contains(principal, "client-resumer") || strings.Contains(principal, "client-submitter") {
		t.Errorf("decided in org %q for %s; want org_1 for the resuming credential client-resumer", call.OrgID, principal)
	}
}

// A resumed step the policy withholds is answered 403, a refusal, not a 500.
func TestPlanResumeAnswersAWithheldStep403(t *testing.T) {
	cleanup := setupResumeTestWCPWithWorkflow(t, "plan_withheld", "confirm", branchlessResumeWorkflow)
	defer cleanup()
	processor := withRecordingWorkflowEngine(t)
	withMAPEngine(t, stepGateVerdict(contract.StateDeny, contract.ReasonExplicitConstraint, contract.Determining{MatchedConstraints: []string{"c"}}))
	w := resumeThePlan(t, "plan_withheld")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "withheld by policy") || processor.ran != 0 {
		t.Fatalf("status %d body %s, %d step(s) ran; want 403 withheld by policy and nothing run", w.Code, w.Body.String(), processor.ran)
	}
	wf, err := workflowControlService.GetWorkflow(context.Background(), "wf-plan_withheld", "tenant_1", "org_1")
	if err != nil || wf.Status != workflow_control.WorkflowStatusAborted {
		t.Errorf("workflow %+v, %v; want it aborted", wf, err)
	}
	plan, err := planService.GetPlan(context.Background(), "plan_withheld", "org_1")
	if err != nil || plan.Status != planning.PlanStatusFailed {
		t.Errorf("plan %+v, %v; want it failed", plan, err)
	}
}

// The held gates record the step's parts for the approver.
func TestAHeldConfirmGateRecordsTheStepsParts(t *testing.T) {
	cleanup := setupResumeTestWCPWithWorkflow(t, "plan_held_parts", "confirm", `{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"held"},"spec":{"steps":[`+
		`{"name":"step1","type":"llm-call","prompt":"first"},{"name":"step2","type":"llm-call","prompt":"second {{input.x}}"}]}}`)
	defer cleanup()
	withRecordingWorkflowEngine(t)
	withMAPEngine(t, allowedStepVerdict())
	if w := resumeThePlan(t, "plan_held_parts"); w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	resp, err := workflowControlService.GetWorkflow(context.Background(), "wf-plan_held_parts", "tenant_1", "org_1")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range resp.Steps {
		if s.StepName == "step2" {
			if !strings.Contains(string(s.StepInput), `"prompt":"second {{input.x}}"`) {
				t.Fatalf("the held gate recorded %s; want the step's prompt as written", s.StepInput)
			}
			return
		}
	}
	t.Fatalf("no held gate for step2 in %+v", resp.Steps)
}
