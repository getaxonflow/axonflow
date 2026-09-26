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
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/shared/anchoredenforcer"

	"github.com/gorilla/mux"
)

// #4382: the multi-agent execute routes decide every step on every deployment.
// Before it, POST /api/v1/workflows/execute and POST /api/v1/plan/execute
// (outside confirm and step mode) ran every step on the declarative engine with
// no decision unless AXONFLOW_HITL_ENABLED was "true", which no shipped
// deployment sets. The cells below run with the flag unset AND set, and answer
// the same.

// flagStates are the AXONFLOW_HITL_ENABLED values a cell runs under.
var flagStates = []bool{false, true}

func withHITLFlag(t *testing.T, enabled bool) {
	t.Helper()
	previous := hitlEnabled
	hitlEnabled = enabled
	t.Cleanup(func() { hitlEnabled = previous })
}

// withGovernedEngine installs, as the process's declarative engine, one whose
// function-call and llm-call steps run through a recording processor, with the
// plane's own step gate over rows, for the test's lifetime.
func withGovernedEngine(t *testing.T, rows *AuditLogger) *recordingStepProcessor {
	t.Helper()
	previous := workflowEngine
	t.Cleanup(func() { workflowEngine = previous })
	processor := &recordingStepProcessor{}
	engine := NewWorkflowEngine()
	engine.stepProcessors["function-call"] = processor
	engine.stepProcessors["llm-call"] = processor
	engine.SetStepGate(&MAPHITLPolicyChecker{}, rows)
	workflowEngine = engine
	return processor
}

// mapDenyVerdict is an explicit-constraint deny naming constraint.
func mapDenyVerdict(constraint string) anchoredenforcer.Verdict {
	return stepGateVerdict(contract.StateDeny, contract.ReasonExplicitConstraint, contract.Determining{MatchedConstraints: []string{constraint}})
}

// postWorkflow posts a one-step function-call workflow to the workflow execute
// handler with the headers the agent stamps.
func postWorkflow(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return postWorkflowBody(t, map[string]interface{}{
		"workflow": Workflow{Metadata: WorkflowMetadata{Name: "we-4382"}, Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "fn", Type: "function-call"}}}},
		"input":    map[string]interface{}{},
		"user":     UserContext{ID: 1, Email: "user@example.com"},
	})
}

// postWorkflowBody posts payload to the workflow execute handler with the
// headers the agent stamps.
func postWorkflowBody(t *testing.T, payload map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	req.Header.Set("X-Client-ID", "client_1")
	w := httptest.NewRecorder()
	executeWorkflowHandler(w, req)
	return w
}

// refusalBody is the 403 a refused step is answered with.
type refusalBody struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    string `json:"code"`
	Policy  string `json:"policy"`
	Reason  string `json:"reason"`
}

func decodeRefusal(t *testing.T, w *httptest.ResponseRecorder) refusalBody {
	t.Helper()
	var b refusalBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode the refusal %q: %v", w.Body.String(), err)
	}
	return b
}

func blockedMapRow(e *AuditEntry) bool { return e.PolicyDecision == "blocked" && e.Plane == "map" }

// A typed block on the action a step presents refuses the step before it runs,
// with 403 execution_blocked naming the constraint, and one blocked row on the
// map plane, with the flag unset and set.
func TestWorkflowExecuteRefusesAStepATypedBlockNamesWhateverTheFlagSays(t *testing.T) {
	for _, enabled := range flagStates {
		t.Run(fmt.Sprintf("AXONFLOW_HITL_ENABLED=%v", enabled), func(t *testing.T) {
			withHITLFlag(t, enabled)
			rows := responsePlaneLogger()
			processor := withGovernedEngine(t, rows)
			withMAPEngine(t, mapDenyVerdict("ceiling.no_tool_calls"))

			w := postWorkflow(t)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d body %s, want 403", w.Code, w.Body.String())
			}
			b := decodeRefusal(t, w)
			if b.Success || b.Code != mapStepExecutionBlocked || b.Policy != "ceiling.no_tool_calls" ||
				b.Error != "execution blocked by policy: ceiling.no_tool_calls" {
				t.Errorf("refusal = %+v, want code %s naming ceiling.no_tool_calls", b, mapStepExecutionBlocked)
			}
			if processor.ran != 0 {
				t.Errorf("the refused step ran %d times", processor.ran)
			}
			oneAuditRowWhere(t, rows, "the refused step's blocked map", blockedMapRow)
		})
	}
}

// A typed approval on the action a step presents is WITHHELD on every posture:
// 403 approval_requires_durable_record, nothing runs, and the reason points at
// confirm and step mode.
func TestWorkflowExecuteWithholdsAStepATypedApprovalHoldsWhateverTheFlagSays(t *testing.T) {
	for _, enabled := range flagStates {
		t.Run(fmt.Sprintf("AXONFLOW_HITL_ENABLED=%v", enabled), func(t *testing.T) {
			withHITLFlag(t, enabled)
			rows := responsePlaneLogger()
			processor := withGovernedEngine(t, rows)
			withMAPEngine(t, typedHoldVerdict("dec-4382-hold", typedApproval(time.Now().Add(time.Hour))))

			w := postWorkflow(t)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d body %s, want 403", w.Code, w.Body.String())
			}
			b := decodeRefusal(t, w)
			if b.Code != mapApprovalRequiresDurableRecord || !strings.Contains(b.Reason, "decision dec-4382-hold") ||
				!strings.Contains(b.Reason, "confirm or step mode") {
				t.Errorf("refusal = %+v, want code %s naming the decision and confirm or step mode", b, mapApprovalRequiresDurableRecord)
			}
			if processor.ran != 0 {
				t.Errorf("the withheld step ran %d times, want never", processor.ran)
			}
			oneAuditRowWhere(t, rows, "the withheld step's blocked map", blockedMapRow)
		})
	}
}

// With no requirement the step runs exactly as before: 200, the step ran once.
// The result's bytes are pinned against the ungated engine below
// (TestAnAllowedExecutionIsByteEqualToTheUngatedEngines).
func TestWorkflowExecuteRunsAnAllowedStepWhateverTheFlagSays(t *testing.T) {
	for _, enabled := range flagStates {
		t.Run(fmt.Sprintf("AXONFLOW_HITL_ENABLED=%v", enabled), func(t *testing.T) {
			withHITLFlag(t, enabled)
			rows := responsePlaneLogger()
			processor := withGovernedEngine(t, rows)
			d := withMAPEngine(t, allowedStepVerdict())

			w := postWorkflow(t)

			if w.Code != http.StatusOK || processor.ran != 1 {
				t.Fatalf("status %d ran %d body %s, want 200 and one run", w.Code, processor.ran, w.Body.String())
			}
			if calls := mapStepCalls(d); len(calls) != 1 || calls[0].Action != "tool.call" {
				t.Errorf("map decisions %+v, want one, on tool.call", calls)
			}
		})
	}
}

// scopedEnforcer answers each scope its own verdict, allowing any other: the
// plan route's once-per-request decision (wcp) and the per-step one (map) are
// separate.
type scopedEnforcer struct {
	mu    sync.Mutex
	by    map[legacycompile.EnforcementScope]anchoredenforcer.Verdict
	calls []anchoredenforcer.Call
}

func (e *scopedEnforcer) Evaluate(_ context.Context, call anchoredenforcer.Call) anchoredenforcer.Verdict {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, call)
	if v, ok := e.by[call.Scope]; ok {
		return v
	}
	return allowedStepVerdict()
}

// withScopedEnforcer installs, after the fact producers are in place, an
// enforcer that answers the map scope mapVerdict and every other scope allow.
func withScopedEnforcer(t *testing.T, mapVerdict anchoredenforcer.Verdict) *scopedEnforcer {
	t.Helper()
	e := &scopedEnforcer{by: map[legacycompile.EnforcementScope]anchoredenforcer.Verdict{mapSeamScope: mapVerdict}}
	previous := orchestratorEnforcerInstance.Load()
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: e})
	t.Cleanup(func() { orchestratorEnforcerInstance.Store(previous) })
	return e
}

// twoStepPlan is a plan whose two function-call steps run in one parallel group
// in parallel mode.
const twoStepPlan = `{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"plan-4382"},"spec":{"steps":[` +
	`{"name":"first","type":"function-call"},{"name":"second","type":"function-call"},{"name":"last","type":"function-call"}]}}`

func executePlan(t *testing.T, planID, mode string) (*httptest.ResponseRecorder, *planning.MockRepository) {
	t.Helper()
	repo := planning.NewMockRepository()
	if err := repo.SavePlan(context.Background(), &planning.Plan{
		TenantID: "tenant_1", OrgID: "org_1", PlanID: planID, Status: planning.PlanStatusPending, StepCount: 3,
		ExecutionMode: mode, Query: "run the functions", Domain: "generic",
		WorkflowDefinition: json.RawMessage(twoStepPlan), ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
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
	req.Header.Set("X-Client-ID", "client_1")
	w := httptest.NewRecorder()
	executePlanHandler(w, req)
	return w, repo
}

// On plan execute, in every mode the declarative engine runs, a typed block on
// the steps' action refuses the plan before any step runs: 403
// execution_blocked, and the plan fails. The route's own decision (wcp) allows.
func TestPlanExecuteRefusesAStepATypedBlockNamesInEveryModeWhateverTheFlagSays(t *testing.T) {
	previousPlans, previousAudit := planService, auditLogger
	t.Cleanup(func() { planService, auditLogger = previousPlans, previousAudit })
	auditLogger = responsePlaneLogger()
	for _, mode := range []string{"auto", "sequential", "parallel", "balanced"} {
		for _, enabled := range flagStates {
			t.Run(fmt.Sprintf("%s mode, AXONFLOW_HITL_ENABLED=%v", mode, enabled), func(t *testing.T) {
				withHITLFlag(t, enabled)
				processor := withGovernedEngine(t, auditLogger)
				withRecordingRouteFacts(t, allowedStepVerdict())
				withMAPEngine(t, allowedStepVerdict())
				e := withScopedEnforcer(t, mapDenyVerdict("ceiling.no_tool_calls"))
				planID := fmt.Sprintf("plan_4382_%s_%v", mode, enabled)

				w, repo := executePlan(t, planID, mode)

				if w.Code != http.StatusForbidden {
					t.Fatalf("status %d body %s, want 403", w.Code, w.Body.String())
				}
				if b := decodeRefusal(t, w); b.Code != mapStepExecutionBlocked || b.Policy != "ceiling.no_tool_calls" {
					t.Errorf("refusal = %+v, want code %s naming ceiling.no_tool_calls", b, mapStepExecutionBlocked)
				}
				if processor.ran != 0 {
					t.Errorf("%d step(s) ran, want none", processor.ran)
				}
				if plan, _ := repo.GetPlan(context.Background(), planID); plan == nil || plan.Status != planning.PlanStatusFailed {
					t.Errorf("plan = %+v, want failed", plan)
				}
				mapCalls := 0
				for _, c := range e.calls {
					if c.Scope == mapSeamScope {
						mapCalls++
					}
				}
				if mapCalls == 0 {
					t.Errorf("no step was decided on the map scope")
				}
			})
		}
	}
}

// blockNamed allows every step but the one it names, and records what it saw.
type blockNamed struct {
	mu      sync.Mutex
	name    string
	decided []string
}

func (c *blockNamed) CheckPolicy(_ context.Context, step WorkflowStep, _ StepContent, _ *WorkflowExecution) (*PolicyCheckResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decided = append(c.decided, step.Name)
	if step.Name == c.name {
		return &PolicyCheckResult{Action: "block", PolicyName: "ceiling.test", Reason: "blocked by name"}, nil
	}
	return &PolicyCheckResult{Allowed: true, Action: "allow"}, nil
}

// A parallel group is decided whole before any of its steps launches: a
// refusal of its second step runs neither, and nothing after it.
func TestAParallelGroupIsDecidedWholeBeforeAnyStepLaunches(t *testing.T) {
	processor := &recordingStepProcessor{}
	checker := &blockNamed{name: "second"}
	engine := NewWorkflowEngine()
	engine.stepProcessors["function-call"] = processor
	engine.SetStepGate(checker, nil)
	var wf Workflow
	if err := json.Unmarshal([]byte(twoStepPlan), &wf); err != nil {
		t.Fatalf("decode: %v", err)
	}

	exec, err := engine.ExecuteWorkflowWithParallelSupport(context.Background(), wf, map[string]interface{}{}, UserContext{OrgID: "org_1"}, true)

	var refusal *mapStepRefusal
	if !errors.As(err, &refusal) || refusal.code != mapStepExecutionBlocked {
		t.Fatalf("err = %v, want the step refusal", err)
	}
	if processor.ran != 0 {
		t.Errorf("%d step(s) ran; a refused group runs none of its steps", processor.ran)
	}
	if strings.Join(checker.decided, ",") != "first,second" {
		t.Errorf("decided %v, want first then second, and nothing after the refusal", checker.decided)
	}
	if exec == nil || exec.Status != "failed" || !strings.Contains(exec.Error, "ceiling.test") {
		t.Errorf("execution = %+v, want failed naming the policy", exec)
	}
	if stored, _ := engine.GetExecution(exec.ID); stored == nil || stored.Status != "failed" {
		t.Errorf("the stored execution = %+v, want it failed", stored)
	}
}

// Balanced mode reorders steps; a conditional's branch decisions are still
// recorded at its position in the workflow, not its position in a group.
func TestBalancedModeRecordsABranchDecisionAtTheConditionalsWorkflowPosition(t *testing.T) {
	log := &branchEvents{}
	audit := &capturingAuditLogger{}
	engine := NewWorkflowEngine()
	engine.stepProcessors["connector-call"] = recordingRunProcessor{log: log}
	engine.stepProcessors["llm-call"] = recordingRunProcessor{log: log}
	engine.SetStepGate(&allowEveryStep{}, audit)
	wf := Workflow{Metadata: WorkflowMetadata{Name: "balanced-4382"}, Spec: WorkflowSpec{Steps: []WorkflowStep{
		{Name: "draft", Type: "llm-call"},
		{Name: "check", Type: "conditional", Condition: "never", IfFalse: []WorkflowStep{{Name: "branch", Type: "llm-call"}}},
		{Name: "fetch", Type: "connector-call"},
	}}}

	if _, err := engine.ExecuteWorkflowBalanced(context.Background(), wf, map[string]interface{}{}, UserContext{OrgID: "org_1"}); err != nil {
		t.Fatalf("execute: %v", err)
	}

	rows := audit.rowsFor("branch")
	if len(rows) != 1 || rows[0].StepID != "1.if_false.0" {
		t.Errorf("the branch step's rows = %+v, want one at 1.if_false.0", rows)
	}
}

// replayCall is one call a recording replay recorder saw, with nothing that
// differs between two runs (ids, times, durations).
type replayCall struct {
	Method, Workflow, Step, Status, Error string
	Index, Total                          int
	Output                                string
}

type recordingReplay struct {
	mu    sync.Mutex
	calls []replayCall
}

func (r *recordingReplay) StartExecution(_ context.Context, _ string, workflowName string, totalSteps int, _, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, replayCall{Method: "start", Workflow: workflowName, Total: totalSteps})
	return nil
}

func (r *recordingReplay) RecordStep(_ context.Context, s *ReplaySnapshotInput) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, replayCall{Method: "step", Step: s.StepName, Status: s.Status, Index: s.StepIndex, Error: s.Error, Output: normalizedJSON(s.Output)})
	return nil
}

func (r *recordingReplay) CompleteExecution(_ context.Context, _ string, out json.RawMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, replayCall{Method: "complete", Output: normalizedJSON(out)})
	return nil
}

func (r *recordingReplay) FailExecution(_ context.Context, _ string, msg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, replayCall{Method: "fail", Error: msg})
	return nil
}

// volatileKeys differ between two runs of one workflow, as does every
// step_<name>_executed_at the engine merges into the next step's input.
var volatileKeys = map[string]bool{"id": true, "start_time": true, "end_time": true, "process_time": true, "executed_at": true}

func dropVolatile(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, val := range x {
			if !volatileKeys[k] && !strings.HasSuffix(k, "_executed_at") {
				out[k] = dropVolatile(val)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, val := range x {
			out[i] = dropVolatile(val)
		}
		return out
	}
	return v
}

func normalizedJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return "unparseable:" + string(raw)
	}
	out, _ := json.Marshal(dropVolatile(v))
	return string(out)
}

// pinFixture is a workflow whose steps produce output and whose spec resolves an
// output template from it, so the pin compares something.
func pinFixture() Workflow {
	return Workflow{
		Metadata: WorkflowMetadata{Name: "pin-4382"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "validate", Type: "function-call", Function: "data-validator"},
				{Name: "score", Type: "function-call", Function: "risk-calculator"},
				{Name: "moderate", Type: "function-call", Function: "auto-moderate"},
			},
			Output: map[string]string{"final_result": "{{steps.moderate.output.action}}", "risk": "{{steps.score.output.recommendation}}"},
		},
	}
}

// runPinned runs the fixture on a fresh engine, gated or not, in one mode, and
// returns the normalized execution, the replay calls and the stored execution.
func runPinned(t *testing.T, gated bool, mode string) (string, []replayCall, string) {
	t.Helper()
	engine := NewWorkflowEngine()
	replay := &recordingReplay{}
	engine.SetReplayRecorder(replay)
	if gated {
		engine.SetStepGate(&allowEveryStep{}, nil)
	}
	var exec *WorkflowExecution
	var err error
	switch mode {
	case "sequential":
		exec, err = engine.ExecuteWorkflow(context.Background(), pinFixture(), map[string]interface{}{}, UserContext{OrgID: "org_1", TenantID: "tenant_1"})
	case "parallel":
		exec, err = engine.ExecuteWorkflowWithParallelSupport(context.Background(), pinFixture(), map[string]interface{}{}, UserContext{OrgID: "org_1", TenantID: "tenant_1"}, true)
	case "balanced":
		exec, err = engine.ExecuteWorkflowBalanced(context.Background(), pinFixture(), map[string]interface{}{}, UserContext{OrgID: "org_1", TenantID: "tenant_1"})
	}
	if err != nil || exec == nil {
		t.Fatalf("%s gated=%v: (%v, %v)", mode, gated, exec, err)
	}
	raw, _ := json.Marshal(exec)
	stored, _ := engine.GetExecution(exec.ID)
	storedRaw, _ := json.Marshal(stored)
	return normalizedJSON(raw), replay.calls, normalizedJSON(storedRaw)
}

// With no requirement, the governed engine's result, its replay record and its
// stored execution are byte-equal to the ungated engine's, in every mode, on a
// fixture whose steps produce output and whose spec resolves templates from it.
func TestAnAllowedExecutionIsByteEqualToTheUngatedEngines(t *testing.T) {
	for _, mode := range []string{"sequential", "parallel", "balanced"} {
		t.Run(mode, func(t *testing.T) {
			ungated, ungatedReplay, ungatedStored := runPinned(t, false, mode)
			gated, gatedReplay, gatedStored := runPinned(t, true, mode)

			// The fixture is not empty: the pin compares resolved outputs.
			for _, want := range []string{`"final_result":"approved"`, `"risk":"auto-approve"`, `"validation_score":0.95`} {
				if !strings.Contains(ungated, want) {
					t.Fatalf("PREMISE: the ungated result %s does not carry %s, so the pin compares nothing", ungated, want)
				}
			}
			if len(ungatedReplay) < 5 {
				t.Fatalf("PREMISE: the ungated run made %d replay calls, want a start, three steps and a completion", len(ungatedReplay))
			}
			if gated != ungated {
				t.Errorf("result differs:\n gated   %s\n ungated %s", gated, ungated)
			}
			if !reflect.DeepEqual(gatedReplay, ungatedReplay) {
				t.Errorf("replay differs:\n gated   %+v\n ungated %+v", gatedReplay, ungatedReplay)
			}
			if gatedStored != ungatedStored || !strings.Contains(gatedStored, `"status":"completed"`) {
				t.Errorf("stored execution differs or is not completed:\n gated   %s\n ungated %s", gatedStored, ungatedStored)
			}
		})
	}
}

// A refused step fails the execution in storage and in replay, and records no
// step: it never ran.
func TestARefusedStepFailsTheExecutionInStorageAndReplay(t *testing.T) {
	engine := NewWorkflowEngine()
	replay := &recordingReplay{}
	engine.SetReplayRecorder(replay)
	engine.SetStepGate(&blockNamed{name: "score"}, nil)

	exec, err := engine.ExecuteWorkflow(context.Background(), pinFixture(), map[string]interface{}{}, UserContext{OrgID: "org_1"})

	var refusal *mapStepRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want the step refusal", err)
	}
	if len(exec.Steps) != 1 || exec.Steps[0].Name != "validate" {
		t.Errorf("steps %+v, want only validate, which ran before the refusal", exec.Steps)
	}
	last := replay.calls[len(replay.calls)-1]
	if last.Method != "fail" || !strings.Contains(last.Error, "ceiling.test") {
		t.Errorf("the last replay call = %+v, want the execution failed naming the policy", last)
	}
	for _, c := range replay.calls {
		if c.Method == "step" && c.Step == "score" {
			t.Errorf("replay recorded the refused step: %+v", c)
		}
	}
	if stored, _ := engine.GetExecution(exec.ID); stored == nil || stored.Status != "failed" {
		t.Errorf("the stored execution = %+v, want failed", stored)
	}
}

// The boot wiring decides every step on every posture, whatever the flag says.
func TestTheBootWiringDecidesEveryStepOnEveryPosture(t *testing.T) {
	previous := hitlEnabled
	t.Cleanup(func() { hitlEnabled = previous })
	for _, posture := range []string{"community", "enterprise", "community-saas", ""} {
		for _, flag := range []string{"", "true", "false"} {
			t.Run(fmt.Sprintf("DEPLOYMENT_MODE=%q AXONFLOW_HITL_ENABLED=%q", posture, flag), func(t *testing.T) {
				t.Setenv("DEPLOYMENT_MODE", posture)
				t.Setenv("AXONFLOW_HITL_ENABLED", flag)
				engine := NewWorkflowEngine()

				wireMultiAgentEngines(engine, nil)

				if !engine.PresentsSteps() {
					t.Fatalf("the declarative engine decides no step")
				}
				if _, ok := engine.stepGate.checker.(*MAPHITLPolicyChecker); !ok {
					t.Errorf("the step gate decides through %T, want the plane's MAPHITLPolicyChecker", engine.stepGate.checker)
				}
				if engine.stepGate.audit != nil {
					t.Errorf("a nil audit writer became %T", engine.stepGate.audit)
				}
			})
		}
	}
}

// With no step gate, nothing runs: 503 on both routes, the plan fails.
func TestAnEngineWithNoStepGateRunsNothing(t *testing.T) {
	previousWorkflow, previousPlans, previousAudit := workflowEngine, planService, auditLogger
	t.Cleanup(func() { workflowEngine, planService, auditLogger = previousWorkflow, previousPlans, previousAudit })
	auditLogger = responsePlaneLogger()
	processor := &recordingStepProcessor{}
	engine := NewWorkflowEngine()
	engine.stepProcessors["function-call"] = processor
	workflowEngine = engine
	withRecordingRouteFacts(t, allowedStepVerdict())

	if w := postWorkflow(t); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "step gate is not wired") {
		t.Errorf("workflow execute: status %d body %s, want 503 naming the missing step gate", w.Code, w.Body.String())
	}
	w, repo := executePlan(t, "plan_4382_no_gate", "auto")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "step gate is not wired") {
		t.Errorf("plan execute: status %d body %s, want 503 naming the missing step gate", w.Code, w.Body.String())
	}
	if plan, _ := repo.GetPlan(context.Background(), "plan_4382_no_gate"); plan == nil || plan.Status != planning.PlanStatusFailed {
		t.Errorf("plan = %+v, want failed", plan)
	}
	if processor.ran != 0 {
		t.Errorf("%d step(s) ran on an engine that decides nothing", processor.ran)
	}
}

// The execution status and plan approve/reject routes answer without the flag:
// customer stacks gain them (#4382). An unknown execution or plan is 404, never
// 503 "HITL not enabled". Since the in-memory pause was retired (#4249 row
// 5774060413) no execution has a hitl-status, and the route answers the body it
// answered for every id since #4382, byte for byte, until v12.0.0 removes it.
func TestTheHITLReadersAnswerWithoutTheFlag(t *testing.T) {
	withHITLFlag(t, false)
	withAuthnValidator(t)
	previousWCP, previousTier := workflowControlService, tierChecker
	t.Cleanup(func() {
		workflowControlService, tierChecker = previousWCP, previousTier
	})
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	hitlEnabled = false
	workflowControlService = nil

	status := httptest.NewRecorder()
	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/workflows/executions/wfe_unknown/hitl-status", nil), map[string]string{"id": "wfe_unknown"})
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	getHITLExecutionStatusHandler(status, req)
	const notFoundBody = `{"request_id":"","success":false,"error":"Execution not found","redacted":false,"policy_info":null,"provider_info":null,"processing_time":""}` + "\n"
	if status.Code != http.StatusNotFound || status.Body.String() != notFoundBody {
		t.Errorf("hitl-status: status %d body %q, want 404 %q", status.Code, status.Body.String(), notFoundBody)
	}

	for name, handler := range map[string]http.HandlerFunc{"approve": mapStepApproveHandler, "reject": mapStepRejectHandler} {
		rr := httptest.NewRecorder()
		r := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/api/v1/plans/plan_unknown/steps/step_1/"+name, bytes.NewReader([]byte(`{}`))),
			map[string]string{"id": "plan_unknown", "step_id": "step_1"})
		r.Header.Set("X-Org-ID", "org_1")
		r.Header.Set("X-Tenant-ID", "tenant_1")
		r.Header.Set("X-Axonflow-Proxy-Auth", validAuthnToken())
		handler(rr, r)
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "No paused execution") {
			t.Errorf("%s: status %d body %s, want 404 naming no paused execution", name, rr.Code, rr.Body.String())
		}
	}
}

// nestedBlockedWorkflow's step "inner" sits two conditionals deep: the outer
// conditional's taken branch is a conditional whose taken branch holds it.
func nestedBlockedWorkflow(extra ...WorkflowStep) Workflow {
	inner := WorkflowStep{Name: "middle", Type: "conditional", Condition: "never",
		IfFalse: []WorkflowStep{{Name: "inner", Type: "llm-call"}}}
	outer := WorkflowStep{Name: "outer", Type: "conditional", Condition: "never", IfFalse: []WorkflowStep{inner}}
	return Workflow{Metadata: WorkflowMetadata{Name: "nested-4382"}, Spec: WorkflowSpec{Steps: append([]WorkflowStep{outer}, extra...)}}
}

// R3 round 1, MEDIUM 1: a branch step refused two conditionals deep keeps its
// type through the outer processor's wrap (%w), so the route answers it 403
// execution_blocked, never 500.
func TestADepthTwoBranchRefusalIsAnswered403(t *testing.T) {
	withHITLFlag(t, false)
	previous := workflowEngine
	t.Cleanup(func() { workflowEngine = previous })
	processor := &recordingStepProcessor{}
	engine := NewWorkflowEngine()
	engine.stepProcessors["llm-call"] = processor
	engine.SetStepGate(&blockNamed{name: "inner"}, nil)
	workflowEngine = engine

	w := postWorkflowBody(t, map[string]interface{}{
		"workflow": nestedBlockedWorkflow(), "input": map[string]interface{}{}, "user": UserContext{ID: 1, Email: "user@example.com"},
	})

	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s; want 403", w.Code, w.Body.String())
	}
	if b := decodeRefusal(t, w); b.Code != mapStepExecutionBlocked || b.Policy != "ceiling.test" {
		t.Errorf("refusal %+v; want %s by ceiling.test", b, mapStepExecutionBlocked)
	}
	if processor.ran != 0 {
		t.Errorf("the refused step ran %d times", processor.ran)
	}
}

// ...and a parallel group whose soft_failure_tolerance absorbs any failure
// still fails with that refusal: a refusal is a decision, not a failure.
func TestADepthTwoBranchRefusalFailsAParallelGroupWhateverItsTolerance(t *testing.T) {
	processor := &recordingStepProcessor{}
	engine := NewWorkflowEngine()
	engine.stepProcessors["llm-call"] = processor
	engine.SetStepGate(&blockNamed{name: "inner"}, nil)
	wf := nestedBlockedWorkflow(WorkflowStep{Name: "sibling", Type: "llm-call"}, WorkflowStep{Name: "last", Type: "llm-call"})
	wf.Spec.SoftFailureTolerance = "any"

	exec, err := engine.ExecuteWorkflowWithParallelSupport(context.Background(), wf, map[string]interface{}{}, UserContext{OrgID: "o"}, true)

	var refusal *mapStepRefusal
	if !errors.As(err, &refusal) || refusal.code != mapStepExecutionBlocked {
		t.Fatalf("err = %v; want the step refusal, not absorbed by soft_failure_tolerance any", err)
	}
	if exec == nil || exec.Status != "failed" {
		t.Errorf("execution %+v; want failed", exec)
	}
	for _, s := range exec.Steps {
		if s.Name == "last" {
			t.Errorf("the step after the refused group ran")
		}
	}
}

// R3 round 1, L3: an orchestrator-direct call with no X-Client-ID has no
// credential subject, so its step is withheld 403 (subject_unverifiable), and
// nothing runs. No production caller sends it: the agent stamps all three.
func TestAWorkflowWithNoCredentialSubjectIsWithheld(t *testing.T) {
	// The real enforcer, which admits the subject through the identity plane;
	// a test double answers whatever it is told and never asks.
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	withHITLFlag(t, false)
	processor := withGovernedEngine(t, responsePlaneLogger())
	withSeededMAPPlane(t)
	body, _ := json.Marshal(map[string]interface{}{
		"workflow": Workflow{Metadata: WorkflowMetadata{Name: "no-subject-4382"}, Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "fn", Type: "function-call"}}}},
		"input":    map[string]interface{}{}, "user": UserContext{ID: 1, Email: "user@example.com"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	w := httptest.NewRecorder()
	executeWorkflowHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d body %s; want 403", w.Code, w.Body.String())
	}
	if b := decodeRefusal(t, w); b.Code != mapStepExecutionBlocked || !strings.Contains(b.Reason, anchoredenforcer.CauseSubjectUnverifiable) {
		t.Errorf("refusal %+v; want %s naming %s", b, mapStepExecutionBlocked, anchoredenforcer.CauseSubjectUnverifiable)
	}
	if processor.ran != 0 {
		t.Errorf("the withheld step ran %d times", processor.ran)
	}

	// CONTROL: the same call with the X-Client-ID the gateway stamps runs, so
	// the refusal above is the missing subject's.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/workflows/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	req.Header.Set("X-Client-ID", "client_1")
	w = httptest.NewRecorder()
	executeWorkflowHandler(w, req)
	if w.Code != http.StatusOK || processor.ran != 1 {
		t.Errorf("with X-Client-ID: status %d ran %d body %s; want 200 and one run", w.Code, processor.ran, w.Body.String())
	}
}
