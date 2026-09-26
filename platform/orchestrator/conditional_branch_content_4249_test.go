// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"axonflow/platform/decision/contract"
)

// #4249 row 5666236540 x row 5665091860: a conditional's branch step is decided
// with its content, as a top-level step is - the input it runs with and the
// processor that runs it (stepContentFor) - through the gate the engine's
// execution carries (mapStepGate.conditionalGate). A branch step decided with
// StepContent{} would present only its written parts: for a step that writes
// none, only its type.

// contentRecordingChecker records the StepContent each step is decided with,
// and allows it.
type contentRecordingChecker struct {
	mu       sync.Mutex
	contents map[string]StepContent
}

func (c *contentRecordingChecker) CheckPolicy(_ context.Context, step WorkflowStep, content StepContent, _ *WorkflowExecution) (*PolicyCheckResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The engine writes each step's output into the same input map after the
	// step runs, so the input is copied as it was when the step was decided.
	copied := make(map[string]interface{}, len(content.Input))
	for k, v := range content.Input {
		copied[k] = v
	}
	content.Input = copied
	c.contents[step.Name] = content
	return &PolicyCheckResult{Action: "allow", Allowed: true, PolicyID: "p-allow", PolicyName: "allow-all"}, nil
}

// inputRecordingProcessor records the input each step runs with. It is used by
// pointer, so the processor a step is decided with compares by identity.
type inputRecordingProcessor struct {
	mu     *sync.Mutex
	inputs map[string]map[string]interface{}
}

func (p *inputRecordingProcessor) ExecuteStep(_ context.Context, step WorkflowStep, input map[string]interface{}, _ *WorkflowExecution) (map[string]interface{}, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make(map[string]interface{}, len(input))
	for k, v := range input {
		copied[k] = v
	}
	p.inputs[step.Name] = copied
	return map[string]interface{}{"status": "done"}, nil
}

const branchContentMarker = "please debug the status page"

func TestABranchStepIsDecidedWithTheInputItRunsWithAndItsProcessor(t *testing.T) {
	checker := &contentRecordingChecker{contents: map[string]StepContent{}}
	runner := &inputRecordingProcessor{mu: &sync.Mutex{}, inputs: map[string]map[string]interface{}{}}
	engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{"llm-call": runner, "api-call": runner}, storage: NewInMemoryWorkflowStorage()}
	engine.stepProcessors["conditional"] = NewConditionalProcessor(engine)
	engine.SetStepGate(checker, nil)

	exec, err := engine.ExecuteWorkflow(context.Background(), onlyBranchedConditional(), map[string]interface{}{"note": branchContentMarker}, UserContext{OrgID: "org-1", TenantID: "t-1"})
	if err != nil || exec.Status != "completed" {
		t.Fatalf("PREMISE: execution = (%v, %v), want completed", exec.Status, err)
	}

	ran, ok := runner.inputs["call-api"]
	if !ok {
		t.Fatalf("PREMISE: the taken branch step call-api did not run (ran %v)", runner.inputs)
	}
	got, ok := checker.contents["call-api"]
	if !ok {
		t.Fatalf("the branch step call-api was never decided (decided %v)", checker.contents)
	}
	if got.Input["note"] != branchContentMarker || !reflect.DeepEqual(got.Input, ran) {
		t.Errorf("the branch step was decided with input %v; want the input it ran with, %v", got.Input, ran)
	}
	if got.Processor == nil || got.Processor != engine.stepProcessors["api-call"] {
		t.Errorf("the branch step was decided with processor %T; want the api-call processor that runs it", got.Processor)
	}
	if _, decided := checker.contents["ask-llm"]; decided {
		t.Error("the untaken branch's step was decided")
	}
}

// Through the REAL MAP seam, the branch step presents its input as content: the
// engine is asked over it, not over an empty step. With StepContent{} the same
// step (no prompt, statement or parameters) presents "" and EmptyContent, which
// is the type alone.
func TestThroughTheRealMAPSeamABranchStepPresentsItsInputNotOnlyItsType(t *testing.T) {
	d := withMAPEngine(t, stepGateVerdict(contract.StateAllow, "", contract.Determining{}))
	engine := &WorkflowEngine{stepProcessors: map[string]StepProcessor{}, storage: NewInMemoryWorkflowStorage()}
	for _, typ := range []string{"llm-call", "api-call"} {
		engine.stepProcessors[typ] = recordingRunProcessor{log: &branchEvents{}}
	}
	engine.stepProcessors["conditional"] = NewConditionalProcessor(engine)
	engine.SetStepGate(&MAPHITLPolicyChecker{}, nil)

	exec, err := engine.ExecuteWorkflow(mapSubjectContext(), onlyBranchedConditional(), map[string]interface{}{"note": branchContentMarker}, UserContext{OrgID: "org-map", TenantID: "tenant-map"})
	if err != nil || exec.Status != "completed" {
		t.Fatalf("PREMISE: execution = (%v, %v), want completed", exec.Status, err)
	}
	if d.callCount() != 1 {
		t.Fatalf("the enforcer was called %d times; want once, for the branch step", d.callCount())
	}
	call := d.lastCall(t)
	if call.EmptyContent || !strings.Contains(call.Query, branchContentMarker) {
		t.Errorf("the branch step was presented as %q (empty content %v); want its input, carrying %q", call.Query, call.EmptyContent, branchContentMarker)
	}

	// The contrast the cell guards: the same step decided with StepContent{}.
	empty, err := mapStepContent(WorkflowStep{Name: "call-api", Type: "api-call"}, StepContent{}, mapExecution())
	if err != nil || empty != "" {
		t.Fatalf("PREMISE: a branch step with no content presents %q (%v); want \"\", its type alone", empty, err)
	}
}
