// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/anchoredenforcer"
)

// #4249 row 5665091860: a multi-agent conditional step's branch steps are
// presented to the engine by their own type, before each runs, on the path that
// presents steps; with no gate on the context, a conditional carrying branch
// steps is refused and nothing runs.

// branchEvents is one ordered log of checks, runs and rows, so a test can
// assert that a step was decided BEFORE it ran.
type branchEvents struct {
	mu     sync.Mutex
	events []string
}

func (b *branchEvents) add(e string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, e)
}

func (b *branchEvents) all() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.events...)
}

func (b *branchEvents) index(e string) int {
	for i, got := range b.all() {
		if got == e {
			return i
		}
	}
	return -1
}

// recordingBranchChecker is a HITLPolicyChecker answering by step name
// (default allow) and recording each check; an entry of "error" makes the
// check return an error, and "nil" returns no result.
type recordingBranchChecker struct {
	log     *branchEvents
	answers map[string]string
}

func (c *recordingBranchChecker) CheckPolicy(_ context.Context, step WorkflowStep, _ StepContent, _ *WorkflowExecution) (*PolicyCheckResult, error) {
	c.log.add("check:" + step.Name + ":" + step.Type)
	switch answer := c.answers[step.Name]; answer {
	case "error":
		return nil, errors.New("engine unreachable")
	case "nil":
		return nil, nil
	case "block":
		return &PolicyCheckResult{Action: "block", PolicyID: "p-block", PolicyName: "block-tool", Reason: "the tool is blocked"}, nil
	case "require_approval":
		return &PolicyCheckResult{Action: "require_approval", PolicyID: "p-approve", PolicyName: "approve-tool", Reason: "needs approval",
			hold: &stepGateHold{decisionID: "dec-hold"}}, nil
	case "warn", "log", "frobnicate":
		return &PolicyCheckResult{Action: answer, Allowed: answer != "frobnicate", PolicyID: "p-" + answer, PolicyName: answer + "-tool"}, nil
	default:
		return &PolicyCheckResult{Action: "allow", Allowed: true, PolicyID: "p-allow", PolicyName: "allow-all"}, nil
	}
}

// recordingRunProcessor records each step it runs and answers status=approved,
// so a condition on a previous step's status can be driven true.
type recordingRunProcessor struct{ log *branchEvents }

func (p recordingRunProcessor) ExecuteStep(_ context.Context, step WorkflowStep, _ map[string]interface{}, _ *WorkflowExecution) (map[string]interface{}, error) {
	p.log.add("run:" + step.Name)
	return map[string]interface{}{"status": "approved"}, nil
}

// capturingAuditLogger keeps every workflow audit entry.
type capturingAuditLogger struct {
	mu      sync.Mutex
	entries []WorkflowAuditEntry
	log     *branchEvents
}

func (l *capturingAuditLogger) LogWorkflowOperation(_ context.Context, entry *WorkflowAuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, *entry)
	if l.log != nil {
		l.log.add("row:" + entry.StepName)
	}
}

func (l *capturingAuditLogger) rowsFor(stepName string) []WorkflowAuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var rows []WorkflowAuditEntry
	for _, e := range l.entries {
		if e.StepName == stepName {
			rows = append(rows, e)
		}
	}
	return rows
}

// branchFixture is the multi-agent workflow engine (the one every execute route
// runs since #4382) over a registry whose non-conditional types all run through
// one recording processor, gated when the test asks for a checker.
type branchFixture struct {
	log     *branchEvents
	checker *recordingBranchChecker
	audit   *capturingAuditLogger
	engine  *WorkflowEngine
}

func newBranchFixture(t *testing.T, answers map[string]string, withChecker bool) *branchFixture {
	t.Helper()
	log := &branchEvents{}
	engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{}, storage: NewInMemoryWorkflowStorage()}
	runner := recordingRunProcessor{log: log}
	for _, typ := range []string{"llm-call", "api-call", "connector-call", "function-call"} {
		engine.stepProcessors[typ] = runner
	}
	engine.stepProcessors["conditional"] = NewConditionalProcessor(engine)
	f := &branchFixture{log: log, checker: &recordingBranchChecker{log: log, answers: answers}, audit: &capturingAuditLogger{log: log}}
	if withChecker {
		engine.SetStepGate(f.checker, f.audit)
	}
	f.engine = engine
	return f
}

// approvedThen is a workflow whose first step answers status=approved, then a
// conditional on it with the given branches.
func approvedThen(ifTrue, ifFalse []WorkflowStep) Workflow {
	return Workflow{
		Metadata: WorkflowMetadata{Name: "branched"},
		Spec: WorkflowSpec{Steps: []WorkflowStep{
			{Name: "prev", Type: "function-call"},
			{Name: "decide", Type: "conditional", Condition: "{{steps.prev.output.status}} == approved", IfTrue: ifTrue, IfFalse: ifFalse},
		}},
	}
}

func (f *branchFixture) run(t *testing.T, wf Workflow) (*WorkflowExecution, error) {
	t.Helper()
	return f.engine.ExecuteWorkflow(context.Background(), wf, map[string]interface{}{}, UserContext{OrgID: "org-1", TenantID: "t-1", Email: "u@example.com"})
}

// (i) The taken branch's step is presented with its own type, before it runs;
// the untaken branch is not presented and does not run; its row carries the
// branch path.
func TestTheTakenBranchStepIsPresentedByItsOwnTypeBeforeItRuns(t *testing.T) {
	f := newBranchFixture(t, nil, true)
	wf := approvedThen(
		[]WorkflowStep{{Name: "call-api", Type: "api-call"}},
		[]WorkflowStep{{Name: "ask-llm", Type: "llm-call"}},
	)

	exec, err := f.run(t, wf)

	if err != nil || exec.Status != "completed" {
		t.Fatalf("execution = (%+v, %v), want completed", exec, err)
	}
	checked, ran := f.log.index("check:call-api:api-call"), f.log.index("run:call-api")
	if checked < 0 || ran < 0 || checked > ran {
		t.Errorf("events %v: want call-api checked as api-call BEFORE it ran", f.log.all())
	}
	if f.log.index("check:ask-llm:llm-call") >= 0 || f.log.index("run:ask-llm") >= 0 {
		t.Errorf("events %v: the untaken branch's step was presented or run", f.log.all())
	}
	if f.log.index("check:decide:conditional") >= 0 {
		t.Errorf("events %v: the conditional itself was presented", f.log.all())
	}
	rows := f.audit.rowsFor("call-api")
	if len(rows) != 1 || rows[0].StepID != "1.if_true.0" || rows[0].Metadata["branch_path"] != "1.if_true.0" || rows[0].Decision != "allow" || rows[0].Operation != "step_gate" {
		t.Errorf("call-api rows = %+v, want one allow step_gate row with StepID and branch_path 1.if_true.0", rows)
	}
	if len(f.audit.rowsFor("ask-llm")) != 0 {
		t.Errorf("the untaken branch's step has an audit row")
	}
}

// A top-level step's row is exactly the pre-change row: no StepID, no
// branch_path (3564 selects one row per step_name).
func TestATopLevelStepRowCarriesNoBranchPath(t *testing.T) {
	f := newBranchFixture(t, nil, true)
	if _, err := f.run(t, approvedThen([]WorkflowStep{{Name: "call-api", Type: "api-call"}}, nil)); err != nil {
		t.Fatalf("run: %v", err)
	}
	rows := f.audit.rowsFor("prev")
	if len(rows) != 1 {
		t.Fatalf("prev rows = %d, want 1", len(rows))
	}
	if rows[0].StepID != "" {
		t.Errorf("top-level StepID = %q, want empty", rows[0].StepID)
	}
	if _, present := rows[0].Metadata["branch_path"]; present || len(rows[0].Metadata) != 4 {
		t.Errorf("top-level metadata = %v, want exactly policy_id, policy_name, severity, step_type", rows[0].Metadata)
	}
}

// (ii) A block on a branch step is terminal: the step does not run, the
// execution fails, and the row carries the block and the branch path.
func TestABlockOnABranchStepFailsTheExecutionAndRecordsItsPath(t *testing.T) {
	f := newBranchFixture(t, map[string]string{"call-api": "block"}, true)
	wf := approvedThen([]WorkflowStep{{Name: "call-api", Type: "api-call"}, {Name: "after", Type: "function-call"}}, nil)

	exec, err := f.run(t, wf)

	if err == nil || exec.Status != "failed" || !strings.Contains(err.Error(), "1.if_true.0") {
		t.Fatalf("execution = (%v, %v), want failed naming 1.if_true.0", exec.Status, err)
	}
	if f.log.index("run:call-api") >= 0 || f.log.index("run:after") >= 0 {
		t.Errorf("events %v: a step ran after the block", f.log.all())
	}
	rows := f.audit.rowsFor("call-api")
	if len(rows) != 1 || rows[0].Decision != "block" || rows[0].StepID != "1.if_true.0" {
		t.Errorf("rows = %+v, want one block row at 1.if_true.0", rows)
	}
}

// (iii) A challenge on a branch step is withheld as approval_required: blocked
// before it runs.
func TestAChallengeOnABranchStepIsWithheldAsApprovalRequired(t *testing.T) {
	f := newBranchFixture(t, map[string]string{"call-api": "require_approval"}, true)
	wf := approvedThen([]WorkflowStep{{Name: "call-api", Type: "api-call"}}, nil)

	exec, err := f.run(t, wf)

	if err == nil || exec.Status != "failed" {
		t.Fatalf("execution = (%v, %v), want failed", exec.Status, err)
	}
	want := branchApprovalRequiredReason()
	rows := f.audit.rowsFor("call-api")
	if len(rows) != 1 || rows[0].Decision != "block" || rows[0].Reason != want {
		t.Errorf("rows = %+v, want one block row with reason %q", rows, want)
	}
	if f.log.index("run:call-api") >= 0 {
		t.Errorf("the challenged branch step ran")
	}
}

// An action the plane does not run a step on is a block, never a pass: the
// top-level loop has no such arm, so harmonising the branch gate with it would
// open this. warn and log run the step with no row, as at top level.
func TestABranchStepAnsweredAnUnknownActionIsBlockedAndWarnOrLogRuns(t *testing.T) {
	t.Run("an unknown action", func(t *testing.T) {
		f := newBranchFixture(t, map[string]string{"call-api": "frobnicate"}, true)
		exec, err := f.run(t, approvedThen([]WorkflowStep{{Name: "call-api", Type: "api-call"}}, nil))
		if err == nil || exec.Status != "failed" || f.log.index("run:call-api") >= 0 {
			t.Fatalf("execution = (%v, %v) events %v, want failed and the branch step not run", exec.Status, err, f.log.all())
		}
		rows := f.audit.rowsFor("call-api")
		if len(rows) != 1 || rows[0].Decision != "block" || rows[0].StepID != "1.if_true.0" || !strings.Contains(rows[0].Reason, `"frobnicate"`) {
			t.Errorf("rows = %+v, want one block row at 1.if_true.0 naming the action", rows)
		}
	})
	for _, answer := range []string{"warn", "log"} {
		t.Run(answer, func(t *testing.T) {
			f := newBranchFixture(t, map[string]string{"call-api": answer}, true)
			exec, err := f.run(t, approvedThen([]WorkflowStep{{Name: "call-api", Type: "api-call"}}, nil))
			if err != nil || exec.Status != "completed" || f.log.index("run:call-api") < 0 {
				t.Fatalf("execution = (%v, %v) events %v, want completed with the branch step run", exec.Status, err, f.log.all())
			}
			if rows := f.audit.rowsFor("call-api"); len(rows) != 0 {
				t.Errorf("rows = %+v, want none, as at top level", rows)
			}
		})
	}
}

// (iv) A nested conditional's branch step is presented; the nested conditional
// itself is not; the path names both levels.
func TestANestedConditionalsBranchStepIsPresented(t *testing.T) {
	f := newBranchFixture(t, nil, true)
	inner := WorkflowStep{Name: "inner", Type: "conditional", Condition: "{{steps.prev.output.status}} == approved",
		IfTrue: []WorkflowStep{{Name: "deep-api", Type: "api-call"}}}
	wf := approvedThen([]WorkflowStep{{Name: "first", Type: "function-call"}, inner}, nil)

	if _, err := f.run(t, wf); err != nil {
		t.Fatalf("run: %v", err)
	}
	if f.log.index("check:inner:conditional") >= 0 {
		t.Errorf("events %v: the nested conditional was presented", f.log.all())
	}
	checked, ran := f.log.index("check:deep-api:api-call"), f.log.index("run:deep-api")
	if checked < 0 || ran < 0 || checked > ran {
		t.Errorf("events %v: want deep-api checked before it ran", f.log.all())
	}
	if rows := f.audit.rowsFor("deep-api"); len(rows) != 1 || rows[0].StepID != "1.if_true.1.if_true.0" {
		t.Errorf("deep-api rows = %+v, want StepID 1.if_true.1.if_true.0", rows)
	}
}

// (v) With no gate on the context the processor refuses a conditional carrying
// branch steps with the v11.0.0 message and runs nothing: an engine without a
// checker, and the processor called directly.
func TestWithNoGateABranchedConditionalIsRefusedAndNothingRuns(t *testing.T) {
	t.Run("an HITL engine without a checker", func(t *testing.T) {
		f := newBranchFixture(t, nil, false)
		exec, err := f.run(t, approvedThen([]WorkflowStep{{Name: "call-api", Type: "api-call"}}, nil))
		if err == nil || exec.Status != "failed" || !strings.Contains(err.Error(), "a branch step is not presented to the policy engine") ||
			!strings.Contains(err.Error(), `conditional step "decide" (at 1)`) {
			t.Fatalf("execution = (%v, %v), want failed with the v11.0.0 refusal naming the conditional at position 1", exec.Status, err)
		}
		if f.log.index("run:call-api") >= 0 {
			t.Errorf("events %v: the branch step ran with no gate", f.log.all())
		}
	})
	t.Run("the processor called directly", func(t *testing.T) {
		log := &branchEvents{}
		engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"api-call": recordingRunProcessor{log: log}}}
		step := WorkflowStep{Name: "decide", Type: "conditional", Condition: "x == x", IfFalse: []WorkflowStep{{Name: "call-api", Type: "api-call"}}}
		_, err := NewConditionalProcessor(engine).ExecuteStep(context.Background(), step, map[string]interface{}{}, &WorkflowExecution{})
		if err == nil || !strings.Contains(err.Error(), "a branch step is not presented to the policy engine") || len(log.all()) != 0 {
			t.Errorf("= %v, events %v: want the v11.0.0 refusal and nothing run", err, log.all())
		}
	})
}

// A gate with no position refuses rather than recording unpathed rows.
func TestAGatedConditionalWithNoPositionIsRefused(t *testing.T) {
	log := &branchEvents{}
	engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"api-call": recordingRunProcessor{log: log}}}
	gate := (&recordingBranchGate{log: log}).gate()
	step := WorkflowStep{Name: "decide", Type: "conditional", Condition: "x == x", IfFalse: []WorkflowStep{{Name: "call-api", Type: "api-call"}}}

	_, err := NewConditionalProcessor(engine).ExecuteStep(withConditionalGate(context.Background(), gate), step, map[string]interface{}{}, &WorkflowExecution{})

	if !errors.Is(err, errConditionalPathMissing) || len(log.all()) != 0 {
		t.Errorf("= %v, events %v: want errConditionalPathMissing and nothing checked or run", err, log.all())
	}
}

// A check error, or no result, is a block whose reason carries the error; the
// branch step does not run.
func TestABranchCheckErrorOrNoResultIsABlock(t *testing.T) {
	for _, answer := range []string{"error", "nil"} {
		t.Run(answer, func(t *testing.T) {
			f := newBranchFixture(t, map[string]string{"call-api": answer}, true)
			exec, err := f.run(t, approvedThen([]WorkflowStep{{Name: "call-api", Type: "api-call"}}, nil))
			if err == nil || exec.Status != "failed" || f.log.index("run:call-api") >= 0 {
				t.Fatalf("execution = (%v, %v) events %v, want failed and the branch step not run", exec.Status, err, f.log.all())
			}
			rows := f.audit.rowsFor("call-api")
			if len(rows) != 1 || rows[0].Decision != "block" {
				t.Fatalf("rows = %+v, want one block row", rows)
			}
			if answer == "error" && !strings.Contains(rows[0].Reason, "engine unreachable") {
				t.Errorf("reason %q does not carry the check error", rows[0].Reason)
			}
		})
	}
}

// (vii) A conditional carrying no branch steps, top level or nested, is not
// presented and runs nothing.
func TestABranchlessConditionalInABranchIsNotPresented(t *testing.T) {
	f := newBranchFixture(t, nil, true)
	wf := approvedThen([]WorkflowStep{{Name: "empty", Type: "conditional", Condition: "x == x"}, {Name: "call-api", Type: "api-call"}}, nil)
	if _, err := f.run(t, wf); err != nil {
		t.Fatalf("run: %v", err)
	}
	if f.log.index("check:empty:conditional") >= 0 {
		t.Errorf("events %v: the branchless conditional was presented", f.log.all())
	}
	if rows := f.audit.rowsFor("call-api"); len(rows) != 1 || rows[0].StepID != "1.if_true.1" {
		t.Errorf("call-api rows = %+v, want StepID 1.if_true.1 (the branchless conditional keeps its index)", rows)
	}
}

// PresentsSteps is false for a nil engine and for one without a checker, and
// true only with one.
func TestPresentsStepsIsFalseForANilOrCheckerlessEngine(t *testing.T) {
	var nilEngine *WorkflowEngine
	if nilEngine.PresentsSteps() {
		t.Errorf("a nil engine presents steps")
	}
	ungated := NewWorkflowEngine()
	if ungated.PresentsSteps() {
		t.Errorf("an engine without a step gate presents steps")
	}
	checkerless := NewWorkflowEngine()
	checkerless.SetStepGate(nil, nil)
	if checkerless.PresentsSteps() {
		t.Errorf("an engine whose step gate has no checker presents steps")
	}
	gated := NewWorkflowEngine()
	gated.SetStepGate(&recordingBranchChecker{log: &branchEvents{}}, nil)
	if !gated.PresentsSteps() {
		t.Errorf("an engine with a checker does not present steps")
	}
}

// recordingBranchGate is a gate that allows every step, for tests about branch
// mechanics rather than decisions.
type recordingBranchGate struct{ log *branchEvents }

func (g *recordingBranchGate) gate() *conditionalGate {
	return &conditionalGate{
		check: func(_ context.Context, step WorkflowStep, _ map[string]interface{}, _ *WorkflowExecution) *PolicyCheckResult {
			if g.log != nil {
				g.log.add("check:" + step.Name + ":" + step.Type)
			}
			return &PolicyCheckResult{Action: "allow", Allowed: true}
		},
		audit: func(context.Context, WorkflowStep, *PolicyCheckResult, string) {},
	}
}

// Through the REAL MAP seam (MAPHITLPolicyChecker over the anchored enforcer):
// the branched conditional is not itself presented (it names no action and would
// be refused), and the taken branch's api-call is presented as a tool call, and
// runs after the allow.
func TestThroughTheRealMAPSeamABranchStepIsPresentedAsItsOwnAction(t *testing.T) {
	d := withMAPEngine(t, allowedStepVerdict())
	log := &branchEvents{}
	engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{}, storage: NewInMemoryWorkflowStorage()}
	for _, typ := range []string{"llm-call", "api-call", "function-call"} {
		engine.stepProcessors[typ] = recordingRunProcessor{log: log}
	}
	engine.stepProcessors["conditional"] = NewConditionalProcessor(engine)
	engine.SetStepGate(&MAPHITLPolicyChecker{}, nil)

	exec, err := engine.ExecuteWorkflow(mapSubjectContext(), approvedThen(
		[]WorkflowStep{{Name: "call-api", Type: "api-call"}},
		[]WorkflowStep{{Name: "ask-llm", Type: "llm-call"}},
	), map[string]interface{}{}, UserContext{OrgID: "org-map", TenantID: "tenant-map"})

	if err != nil || exec.Status != "completed" {
		t.Fatalf("execution = (%v, %v), want completed", exec.Status, err)
	}
	d.mu.Lock()
	calls := append([]anchoredenforcer.Call(nil), d.calls...)
	d.mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("the engine decided %d steps, want 2 (prev, call-api): %+v", len(calls), calls)
	}
	for i, want := range []string{mapStepActions["function-call"], mapStepActions["api-call"]} {
		if calls[i].ActionErr != nil || calls[i].Action != want {
			t.Errorf("decision %d action = %q (err %v), want %q", i, calls[i].Action, calls[i].ActionErr, want)
		}
	}
	if strings.Join(log.all(), ",") != "run:prev,run:call-api" {
		t.Errorf("runs = %v, want prev then call-api only", log.all())
	}
}

// onlyBranchedConditional is a workflow whose one step is a conditional on a
// value no step produced, so if_false is taken: every decision is the branch
// step's.
func onlyBranchedConditional() Workflow {
	return Workflow{Metadata: WorkflowMetadata{Name: "branched"}, Spec: WorkflowSpec{Steps: []WorkflowStep{{
		Name: "decide", Type: "conditional", Condition: "{{steps.never-ran.output.status}} == approved",
		IfTrue:  []WorkflowStep{{Name: "ask-llm", Type: "llm-call"}},
		IfFalse: []WorkflowStep{{Name: "call-api", Type: "api-call"}},
	}}}}
}

// realSeamBranch is one run of onlyBranchedConditional through
// MAPHITLPolicyChecker over an enforcer answering one verdict.
type realSeamBranch struct {
	exec  *WorkflowExecution
	err   error
	log   *branchEvents
	audit *capturingAuditLogger
}

func runRealSeamBranch(t *testing.T, verdict anchoredenforcer.Verdict) realSeamBranch {
	t.Helper()
	withMAPEngine(t, verdict)
	r := realSeamBranch{log: &branchEvents{}, audit: &capturingAuditLogger{}}
	engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{}, storage: NewInMemoryWorkflowStorage()}
	for _, typ := range []string{"llm-call", "api-call"} {
		engine.stepProcessors[typ] = recordingRunProcessor{log: r.log}
	}
	engine.stepProcessors["conditional"] = NewConditionalProcessor(engine)
	engine.SetStepGate(&MAPHITLPolicyChecker{}, r.audit)
	r.exec, r.err = engine.ExecuteWorkflow(mapSubjectContext(), onlyBranchedConditional(), map[string]interface{}{}, UserContext{OrgID: "org-map", TenantID: "tenant-map"})
	return r
}

func mapDecisionCount(verdict, reason string) float64 {
	return promtestutil.ToFloat64(anchoredenforcer.Decisions.WithLabelValues(mapSeamScope.String(), anchoredenforcer.EngineAnchored, verdict, reason))
}

// Through the REAL MAP seam, a constraint's deny on the taken branch step blocks
// it before it runs, naming the constraint and the branch position (the error
// suite 3297 [14] reads).
func TestThroughTheRealMAPSeamADenyOnABranchStepBlocksItNamingTheConstraint(t *testing.T) {
	r := runRealSeamBranch(t, routeDenyVerdict("ceiling.branch_tool_call"))

	if r.err == nil || r.exec.Status != "failed" || !strings.Contains(r.err.Error(), "branch step call-api (0.if_false.0) blocked by policy ceiling.branch_tool_call") {
		t.Fatalf("execution = (%v, %v), want failed: branch step call-api (0.if_false.0) blocked by policy ceiling.branch_tool_call", r.exec.Status, r.err)
	}
	if len(r.log.all()) != 0 {
		t.Errorf("events %v: a step ran under the deny", r.log.all())
	}
	if rows := r.audit.rowsFor("call-api"); len(rows) != 1 || rows[0].Decision != "block" || rows[0].StepID != "0.if_false.0" {
		t.Errorf("rows = %+v, want one block row at 0.if_false.0", rows)
	}
	if len(r.audit.rowsFor("ask-llm")) != 0 {
		t.Errorf("the untaken branch's step has an audit row")
	}
}

// Through the REAL MAP seam, a challenge on a branch step is withheld by the
// seam itself: counted as a deny for approval_required (never needs_approval,
// which would count a hold that does not exist), refused with the branch
// sentence, and nothing runs.
func TestThroughTheRealMAPSeamAChallengeOnABranchStepIsCountedAndRefusedAsWithheld(t *testing.T) {
	approvalRequired := string(contract.ReasonApprovalRequired)
	deniesBefore := mapDecisionCount("deny", approvalRequired)
	heldBefore := mapDecisionCount("needs_approval", approvalRequired)

	r := runRealSeamBranch(t, heldStepVerdict())

	if r.err == nil || r.exec.Status != "failed" {
		t.Fatalf("execution = (%v, %v), want failed", r.exec.Status, r.err)
	}
	if len(r.log.all()) != 0 {
		t.Errorf("events %v: want nothing run", r.log.all())
	}
	if got := mapDecisionCount("deny", approvalRequired) - deniesBefore; got != 1 {
		t.Errorf("map deny/approval_required moved by %v, want 1", got)
	}
	if got := mapDecisionCount("needs_approval", approvalRequired) - heldBefore; got != 0 {
		t.Errorf("map needs_approval moved by %v for a branch step that cannot be held, want 0", got)
	}
	rows := r.audit.rowsFor("call-api")
	if len(rows) != 1 || rows[0].Decision != "block" || rows[0].StepID != "0.if_false.0" || rows[0].Reason != branchApprovalRequiredReason() {
		t.Errorf("rows = %+v, want one block row at 0.if_false.0 with reason %q", rows, branchApprovalRequiredReason())
	}
}

// A top-level challenge through the same seam is still a hold, counted as
// needs_approval: the branch flag is set only by the branch gate.
func TestThroughTheRealMAPSeamATopLevelChallengeIsStillCountedAsAHold(t *testing.T) {
	approvalRequired := string(contract.ReasonApprovalRequired)
	heldBefore := mapDecisionCount("needs_approval", approvalRequired)
	withMAPEngine(t, heldStepVerdict())

	pr, err := (&MAPHITLPolicyChecker{}).CheckPolicy(mapSubjectContext(), WorkflowStep{Name: "call-api", Type: "api-call"}, StepContent{}, mapExecution())

	if err != nil || pr == nil || pr.Action != "require_approval" || pr.hold == nil {
		t.Fatalf("= (%+v, %v), want a require_approval with a hold", pr, err)
	}
	if got := mapDecisionCount("needs_approval", approvalRequired) - heldBefore; got != 1 {
		t.Errorf("map needs_approval moved by %v, want 1", got)
	}
}

// A plan's timeout counts the steps a conditional can run: one conditional
// whose larger branch holds N steps is sized as N top-level steps.
func TestAPlansTimeoutCountsAConditionalsBranchSteps(t *testing.T) {
	steps := func(n int) []WorkflowStep {
		out := make([]WorkflowStep, n)
		for i := range out {
			out[i] = WorkflowStep{Name: fmt.Sprintf("s%d", i), Type: "api-call"}
		}
		return out
	}
	branched := Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "decide", Type: "conditional", IfTrue: steps(7), IfFalse: steps(2)}}}}
	flat := Workflow{Spec: WorkflowSpec{Steps: steps(7)}}
	if got, want := planWorkflowTimeout(branched), planWorkflowTimeout(flat); got != want || got <= 60*time.Second {
		t.Errorf("a conditional with 7 branch steps gets %v, want %v (7 top-level steps)", got, want)
	}
	nested := []WorkflowStep{{Name: "outer", Type: "conditional",
		IfFalse: []WorkflowStep{{Name: "inner", Type: "conditional", IfTrue: steps(5)}, {Name: "after", Type: "api-call"}}}}
	if got := (*ConditionalProcessor)(nil).runnableStepCount(nested); got != 6 {
		t.Errorf("nested runnable steps = %d, want 6", got)
	}
	if got := (*ConditionalProcessor)(nil).runnableStepCount([]WorkflowStep{{Name: "empty", Type: "conditional"}, {Name: "a", Type: "api-call"}}); got != 2 {
		t.Errorf("a branchless conditional and one step count %d, want 2", got)
	}
}

// A conditional's branch step records follow the conditional's own record, and
// each keeps its name and status: the conditional's result is written to its own
// record, not to the last branch step's.
func TestAConditionalsStepRecordsKeepEachBranchStep(t *testing.T) {
	f := newBranchFixture(t, nil, true)
	wf := approvedThen([]WorkflowStep{{Name: "export-a", Type: "api-call"}, {Name: "export-b", Type: "api-call"}}, nil)
	wf.Spec.Steps = append(wf.Spec.Steps, WorkflowStep{Name: "notify", Type: "connector-call"})

	exec, err := f.run(t, wf)

	if err != nil || exec.Status != "completed" {
		t.Fatalf("execution = (%v, %v), want completed", exec.Status, err)
	}
	var got []string
	for _, s := range exec.Steps {
		got = append(got, s.Name+":"+s.Status)
	}
	want := "prev:completed,decide:completed,export-a:completed,export-b:completed,notify:completed"
	if strings.Join(got, ",") != want {
		t.Errorf("step records = %v, want %s", got, want)
	}
}

// At a branch position the seam's order holds: an approval that has already
// expired answers approval_expired, counted as such, and is not re-answered as
// a withheld approval_required.
func TestAtABranchPositionAnExpiredChallengeStaysApprovalExpired(t *testing.T) {
	expired, required := string(contract.ReasonApprovalExpired), string(contract.ReasonApprovalRequired)
	expiredBefore, requiredBefore := mapDecisionCount("deny", expired), mapDecisionCount("deny", required)
	verdict := heldStepVerdict()
	verdict.Decision.Approval.ExpiresAt = time.Now().Add(-time.Minute)
	withMAPEngine(t, verdict)

	pr, err := (&MAPHITLPolicyChecker{}).CheckPolicy(withBranchPosition(mapSubjectContext()), WorkflowStep{Name: "call-api", Type: "api-call"}, StepContent{}, mapExecution())

	if err != nil || pr == nil || pr.Action != "block" || pr.PolicyName != expired || pr.hold != nil {
		t.Fatalf("= (%+v, %v), want a block named %s with no hold", pr, err, expired)
	}
	if got := mapDecisionCount("deny", expired) - expiredBefore; got != 1 {
		t.Errorf("map deny/approval_expired moved by %v, want 1", got)
	}
	if got := mapDecisionCount("deny", required) - requiredBefore; got != 0 {
		t.Errorf("map deny/approval_required moved by %v, want 0", got)
	}
}

// A withheld branch challenge that names no deciding policy is named by its
// reason code.
func TestAWithheldBranchChallengeNamingNoPolicyIsNamedApprovalRequired(t *testing.T) {
	withMAPEngine(t, stepGateVerdict(contract.StateChallenge, contract.ReasonApprovalRequired, contract.Determining{}))

	pr, err := (&MAPHITLPolicyChecker{}).CheckPolicy(withBranchPosition(mapSubjectContext()), WorkflowStep{Name: "call-api", Type: "api-call"}, StepContent{}, mapExecution())

	if err != nil || pr == nil || pr.Action != "block" || pr.PolicyName != string(contract.ReasonApprovalRequired) || pr.Reason != branchApprovalRequiredReason() {
		t.Fatalf("= (%+v, %v), want a block named approval_required with the branch sentence", pr, err)
	}
}

// Brief §2.5: a branch step of a type the plane names no action for is refused
// through actionForMAPStep, exactly as a top-level step is: the REAL enforcer
// answers the action error as request_unbuildable, the branch step is blocked
// before it runs, and its row is written at the branch path. The type IS
// registered with a step processor, so what refuses it is the action map, never
// a missing processor.
func TestThroughTheRealMAPSeamABranchStepOfAnUnmappedTypeIsRefusedAsUnbuildable(t *testing.T) {
	const unmapped = "made-up-type"
	if _, named := mapStepActions[unmapped]; named {
		t.Fatalf("PREMISE: %q is in mapStepActions", unmapped)
	}
	withMAPEngine(t, allowedStepVerdict())
	enforcer := stepDecisionEnforcer(t)
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: enforcer})

	log := &branchEvents{}
	audit := &capturingAuditLogger{}
	engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{}, storage: NewInMemoryWorkflowStorage()}
	for _, typ := range []string{"llm-call", unmapped} {
		engine.stepProcessors[typ] = recordingRunProcessor{log: log}
	}
	engine.stepProcessors["conditional"] = NewConditionalProcessor(engine)
	engine.SetStepGate(&MAPHITLPolicyChecker{}, audit)
	wf := Workflow{Metadata: WorkflowMetadata{Name: "branched"}, Spec: WorkflowSpec{Steps: []WorkflowStep{{
		Name: "decide", Type: "conditional", Condition: "{{steps.never-ran.output.status}} == approved",
		IfTrue:  []WorkflowStep{{Name: "ask-llm", Type: "llm-call"}},
		IfFalse: []WorkflowStep{{Name: "custom", Type: unmapped}},
	}}}}

	exec, err := engine.ExecuteWorkflow(mapSubjectContext(), wf, map[string]interface{}{}, UserContext{OrgID: "org-map", TenantID: "tenant-map"})

	if err == nil || exec.Status != "failed" || !strings.Contains(err.Error(), "branch step custom (0.if_false.0)") || !strings.Contains(err.Error(), anchoredenforcer.CauseRequest) {
		t.Fatalf("execution = (%v, %v), want failed: branch step custom (0.if_false.0) refused naming %s", exec.Status, err, anchoredenforcer.CauseRequest)
	}
	if len(log.all()) != 0 {
		t.Errorf("runs = %v, want none", log.all())
	}
	rows := audit.rowsFor("custom")
	if len(rows) != 1 || rows[0].Decision != "block" || rows[0].StepID != "0.if_false.0" || !strings.Contains(rows[0].Reason, anchoredenforcer.CauseRequest) {
		t.Errorf("rows = %+v, want one block row at 0.if_false.0 naming %s", rows, anchoredenforcer.CauseRequest)
	}
}
