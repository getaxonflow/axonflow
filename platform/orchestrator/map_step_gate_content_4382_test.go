// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
)

// #4382 (R3 round 1, HIGH): the declarative engine presents each step's content
// exactly as the HITL engine did (#4360): the input the executor passes the
// step, and the processor that will run it, built by the one builder both
// executors call (stepContentFor). A step that presented nothing would be
// decided on nothing by every content control on the multi-agent plane.

// Every mode of the declarative engine hands the checker the input it passes
// the step, prior outputs included, and the step's processor.
func TestTheDeclarativeEnginePresentsTheInputItPassesTheStepInEveryMode(t *testing.T) {
	wf := Workflow{Metadata: WorkflowMetadata{Name: "w"}, Spec: WorkflowSpec{Steps: []WorkflowStep{
		{Name: "one", Type: "llm-call"}, {Name: "two", Type: "llm-call"}, {Name: "three", Type: "llm-call"},
	}}}
	run := map[string]func(e *WorkflowEngine) error{
		"sequential": func(e *WorkflowEngine) error {
			_, err := e.ExecuteWorkflow(context.Background(), wf, map[string]interface{}{"q": "v"}, UserContext{OrgID: "o"})
			return err
		},
		"sequential group": func(e *WorkflowEngine) error {
			_, err := e.ExecuteWorkflowWithParallelSupport(context.Background(), wf, map[string]interface{}{"q": "v"}, UserContext{OrgID: "o"}, false)
			return err
		},
		"parallel group": func(e *WorkflowEngine) error {
			_, err := e.ExecuteWorkflowWithParallelSupport(context.Background(), wf, map[string]interface{}{"q": "v"}, UserContext{OrgID: "o"}, true)
			return err
		},
	}
	for mode, execute := range run {
		t.Run(mode, func(t *testing.T) {
			checker := &recordingContentChecker{}
			processor := &recordingStepProcessor{}
			engine := NewWorkflowEngine()
			engine.stepProcessors["llm-call"] = processor
			engine.SetStepGate(checker, nil)

			if err := execute(engine); err != nil {
				t.Fatal(err)
			}
			if len(checker.contents) != 3 {
				t.Fatalf("%d checks, want 3", len(checker.contents))
			}
			for i, c := range checker.contents {
				if c.Processor != StepProcessor(processor) || c.Input["q"] != "v" {
					t.Errorf("check %d presented processor %T and input %v; want the step's processor and the workflow input", i, c.Processor, c.Input)
				}
			}
			// The last step runs after the others in every mode (parallel mode
			// holds it back as the synthesis), so it is presented their output.
			if last := checker.contents[2]; last.Input["step_one_ok"] != true || last.Input["step_two_ok"] != true {
				t.Errorf("the last step's presented input %v; want the earlier steps' output", last.Input)
			}
		})
	}
}

// A conditional's branch step presents the input it will run with too.
func TestTheDeclarativeEnginePresentsABranchStepsInput(t *testing.T) {
	checker := &recordingContentChecker{}
	processor := &recordingStepProcessor{}
	engine := NewWorkflowEngine()
	engine.stepProcessors["llm-call"] = processor
	engine.SetStepGate(checker, nil)
	wf := Workflow{Metadata: WorkflowMetadata{Name: "w"}, Spec: WorkflowSpec{Steps: []WorkflowStep{
		{Name: "check", Type: "conditional", Condition: "never", IfFalse: []WorkflowStep{{Name: "branch", Type: "llm-call"}}},
	}}}

	if _, err := engine.ExecuteWorkflow(context.Background(), wf, map[string]interface{}{"q": "v"}, UserContext{OrgID: "o"}); err != nil {
		t.Fatal(err)
	}
	if len(checker.contents) != 1 || checker.contents[0].Input["q"] != "v" || checker.contents[0].Processor != StepProcessor(processor) {
		t.Errorf("branch checks %+v; want one presenting the workflow input and the step's processor", checker.contents)
	}
}

// Through the route, on the real anchored engine with the shipped rows: a step
// whose INPUT a shipped content control matches is refused 403
// execution_blocked before it runs. The same step with the same input, decided
// by an engine that holds no control over it, runs.
func TestWorkflowExecuteDecidesAStepOverItsInput(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	body := func() map[string]interface{} {
		return map[string]interface{}{
			"workflow": Workflow{Metadata: WorkflowMetadata{Name: "content-4382"}, Spec: WorkflowSpec{Steps: []WorkflowStep{
				{Name: "summarise", Type: "llm-call", Prompt: "summarise the note"},
			}}},
			"input": map[string]interface{}{"note": "debug the parser"},
			"user":  UserContext{ID: 1, Email: "user@example.com"},
		}
	}

	t.Run("a shipped content control matches the input: refused", func(t *testing.T) {
		withHITLFlag(t, false)
		processor := withGovernedEngine(t, responsePlaneLogger())
		withSeededMAPPlane(t)

		w := postWorkflowBody(t, body())

		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d body %s; want 403", w.Code, w.Body.String())
		}
		b := decodeRefusal(t, w)
		if b.Code != mapStepExecutionBlocked || !strings.HasPrefix(b.Policy, debugRestrictControl) {
			t.Errorf("refusal %+v; want %s by %s", b, mapStepExecutionBlocked, debugRestrictControl)
		}
		if processor.ran != 0 {
			t.Errorf("the refused step ran %d times", processor.ran)
		}
	})
	t.Run("no control over it: the same input runs", func(t *testing.T) {
		withHITLFlag(t, false)
		processor := withGovernedEngine(t, responsePlaneLogger())
		withMAPEngine(t, allowedStepVerdict())

		w := postWorkflowBody(t, body())

		if w.Code != http.StatusOK || processor.ran != 1 {
			t.Errorf("status %d ran %d body %s; want 200 and one run", w.Code, processor.ran, w.Body.String())
		}
	})
}
