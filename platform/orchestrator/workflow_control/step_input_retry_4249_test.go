// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// #4249 row 5666236540: a step's input is the content its decision was made
// over, so an idempotent retry presenting other input is refused, never served
// the cached decision.

func gateStep(t *testing.T, svc *Service, workflowID string, req *StepGateRequest) (*StepGateResponse, error) {
	t.Helper()
	return svc.StepGate(context.Background(), workflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
}

func TestAnIdempotentRetryWithOtherStepInputIsRefused(t *testing.T) {
	_, svc, _ := setupTestHandlerWith(allowingPolicyEvaluator{})
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "retry"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatal(err)
	}
	first := &StepGateRequest{StepName: "s", StepType: StepTypeLLMCall, StepInput: map[string]interface{}{"prompt": "summarise", "n": 1}}
	if _, err := gateStep(t, svc, wf.WorkflowID, first); err != nil {
		t.Fatal(err)
	}

	// The same input, in another key order: the cached decision.
	same := &StepGateRequest{StepName: "s", StepType: StepTypeLLMCall, StepInput: map[string]interface{}{"n": 1, "prompt": "summarise"}}
	resp, err := gateStep(t, svc, wf.WorkflowID, same)
	if err != nil || resp == nil || resp.Decision != GateDecisionAllow {
		t.Fatalf("a retry with the same input: %+v, %v; want the cached allow", resp, err)
	}

	for name, input := range map[string]map[string]interface{}{
		"changed value": {"prompt": "please debug", "n": 1},
		"added key":     {"prompt": "summarise", "n": 1, "x": "y"},
		"no input":      nil,
	} {
		retry := &StepGateRequest{StepName: "s", StepType: StepTypeLLMCall, StepInput: input}
		resp, err := gateStep(t, svc, wf.WorkflowID, retry)
		var mismatch *StepInputMismatchError
		if !errors.As(err, &mismatch) || resp != nil {
			t.Errorf("%s: %+v, %v; want a StepInputMismatchError and no decision", name, resp, err)
		}
	}

	// reevaluate decides the new input afresh.
	fresh := &StepGateRequest{StepName: "s", StepType: StepTypeLLMCall, RetryPolicy: RetryPolicyReevaluate, StepInput: map[string]interface{}{"prompt": "other"}}
	if _, err := gateStep(t, svc, wf.WorkflowID, fresh); err != nil {
		t.Errorf("a reevaluate retry with other input: %v; want a fresh decision", err)
	}
}

func TestTheStepGateAnswersAStepInputMismatch409(t *testing.T) {
	handler, svc, _ := setupTestHandlerWith(allowingPolicyEvaluator{})
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "retry-http"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatal(err)
	}
	gate := func(input map[string]interface{}) *httptest.ResponseRecorder {
		body, _ := json.Marshal(StepGateRequest{StepName: "s", StepType: StepTypeLLMCall, StepInput: input})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+wf.WorkflowID+"/steps/step-1/gate", bytes.NewReader(body))
		req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "step-1"})
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		rr := httptest.NewRecorder()
		handler.StepGate(rr, req)
		return rr
	}
	if rr := gate(map[string]interface{}{"prompt": "summarise"}); rr.Code != http.StatusOK {
		t.Fatalf("first gate %d %s", rr.Code, rr.Body.String())
	}
	rr := gate(map[string]interface{}{"prompt": "please debug"})
	var env APIErrorResponse
	if rr.Code != http.StatusConflict || json.Unmarshal(rr.Body.Bytes(), &env) != nil || env.Error.Code != ErrorCodeStepInputMismatch || env.Error.Details.StepID != "step-1" {
		t.Fatalf("retry with other input answered %d %s; want 409 %s", rr.Code, rr.Body.String(), ErrorCodeStepInputMismatch)
	}
}

// racingRepository answers the read-back after a first gate's upsert with the
// row a concurrent call with other content wrote.
type racingRepository struct {
	*MockRepository
	reads  int
	racing *WorkflowStep
}

func (r *racingRepository) GetStepDecision(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	r.reads++
	if r.reads == 2 {
		row := *r.racing
		return &row, nil
	}
	return r.MockRepository.GetStepDecision(ctx, workflowID, stepID)
}

// Two first gates race on one step: the persisted decision is the other call's,
// over other input. This call is refused, never answered with that decision.
func TestARacingFirstGateWithOtherInputIsRefused(t *testing.T) {
	blocked := blockingPolicyEvaluator{}
	repo := &racingRepository{MockRepository: NewMockRepository(), racing: &WorkflowStep{
		StepID: "step-1", Decision: GateDecisionAllow, StepInput: json.RawMessage(`{"prompt":"summarise"}`),
	}}
	svc := NewService(repo, blocked, nil)
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "race"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := gateStep(t, svc, wf.WorkflowID, &StepGateRequest{StepName: "s", StepType: StepTypeLLMCall, StepInput: map[string]interface{}{"prompt": "please debug"}})
	var mismatch *StepInputMismatchError
	if !errors.As(err, &mismatch) || resp != nil {
		t.Fatalf("%+v, %v; want a StepInputMismatchError, never the racing call's allow", resp, err)
	}
}

// A racer that presents no tool context, reading back another call's decision
// before that call's gate checkpoint has landed, is refused: an absent stored
// tool context says nothing about what that decision was made over (master R3
// round 2). The served same-content race is
// TestARacingFirstGateWithOtherToolInputIsRefused's control.
func TestARacingFirstGateWithNoToolContextAndNoCheckpointIsRefused(t *testing.T) {
	repo := &racingRepository{MockRepository: NewMockRepository(), racing: &WorkflowStep{
		StepID: "step-1", Decision: GateDecisionAllow, StepInput: json.RawMessage(`{"prompt":"please debug"}`),
	}}
	svc := NewService(repo, blockingPolicyEvaluator{}, nil)
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "race-no-tool"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := gateStep(t, svc, wf.WorkflowID, &StepGateRequest{StepName: "s", StepType: StepTypeLLMCall, StepInput: map[string]interface{}{"prompt": "please debug"}})
	var mismatch *StepInputMismatchError
	if !errors.As(err, &mismatch) || resp != nil {
		t.Fatalf("%+v, %v; want a StepInputMismatchError, never the racing call's allow", resp, err)
	}
}

type blockingPolicyEvaluator struct{}

func (blockingPolicyEvaluator) EvaluateStepGate(context.Context, *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{Decision: GateDecisionBlock, Reason: "blocked by the test double"}
}

// #4249 row 5706152777: a tool step's tool context is content too, so an
// idempotent retry or a racing first gate with another tool context is refused.

func toolGate(input string) *StepGateRequest {
	return &StepGateRequest{StepName: "t", StepType: StepTypeToolCall, StepInput: map[string]interface{}{"q": "x"},
		ToolContext: &ToolContext{ToolName: "shell", ToolInput: map[string]interface{}{"cmd": input}}}
}

func TestAnIdempotentRetryWithOtherToolInputIsRefused(t *testing.T) {
	_, svc, _ := setupTestHandlerWith(allowingPolicyEvaluator{})
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "tool-retry"}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateStep(t, svc, wf.WorkflowID, toolGate("ls")); err != nil {
		t.Fatal(err)
	}
	if resp, err := gateStep(t, svc, wf.WorkflowID, toolGate("ls")); err != nil || resp.Decision != GateDecisionAllow {
		t.Fatalf("a retry with the same tool input: %+v, %v; want the cached allow", resp, err)
	}
	var mismatch *StepInputMismatchError
	for name, req := range map[string]*StepGateRequest{
		"other tool input": toolGate("please debug"),
		"no tool context":  {StepName: "t", StepType: StepTypeToolCall, StepInput: map[string]interface{}{"q": "x"}},
		"other tool name":  {StepName: "t", StepType: StepTypeToolCall, StepInput: map[string]interface{}{"q": "x"}, ToolContext: &ToolContext{ToolName: "other", ToolInput: map[string]interface{}{"cmd": "ls"}}},
	} {
		resp, err := gateStep(t, svc, wf.WorkflowID, req)
		if !errors.As(err, &mismatch) || resp != nil {
			t.Errorf("%s: %+v, %v; want a StepInputMismatchError and no decision", name, resp, err)
		}
	}

	// reevaluate decides the other tool input afresh and records it, so a later
	// idempotent retry is compared with it.
	fresh := toolGate("pwd")
	fresh.RetryPolicy = RetryPolicyReevaluate
	if _, err := gateStep(t, svc, wf.WorkflowID, fresh); err != nil {
		t.Fatalf("reevaluate with other tool input: %v", err)
	}
	if resp, err := gateStep(t, svc, wf.WorkflowID, toolGate("pwd")); err != nil || resp == nil {
		t.Errorf("an idempotent retry with the reevaluated tool input: %+v, %v; want the cached decision", resp, err)
	}
	if _, err := gateStep(t, svc, wf.WorkflowID, toolGate("ls")); !errors.As(err, &mismatch) {
		t.Errorf("an idempotent retry with the superseded tool input: %v; want a StepInputMismatchError", err)
	}
}

// racingToolRepository is racingRepository whose racing call also wrote its gate
// checkpoint, with its own tool context.
type racingToolRepository struct {
	racingRepository
	racingTool json.RawMessage
}

func (r *racingToolRepository) GetStepDecision(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	return r.racingRepository.GetStepDecision(ctx, workflowID, stepID)
}

func (r *racingToolRepository) ListCheckpoints(ctx context.Context, workflowID string) ([]Checkpoint, error) {
	if r.reads >= 2 {
		return []Checkpoint{{WorkflowID: workflowID, StepID: "step-1", ToolContext: r.racingTool}}, nil
	}
	return r.MockRepository.ListCheckpoints(ctx, workflowID)
}

func TestARacingFirstGateWithOtherToolInputIsRefused(t *testing.T) {
	race := func(tool string) (*StepGateResponse, error) {
		repo := &racingToolRepository{
			racingRepository: racingRepository{MockRepository: NewMockRepository(), racing: &WorkflowStep{
				StepID: "step-1", Decision: GateDecisionAllow, StepInput: json.RawMessage(`{"q":"x"}`),
			}},
			racingTool: json.RawMessage(`{"tool_name":"shell","tool_input":{"cmd":"` + tool + `"}}`),
		}
		svc := NewService(repo, blockingPolicyEvaluator{}, nil)
		wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "tool-race"}, "tenant-1", "org-1", "user-1", "client-1")
		if err != nil {
			t.Fatal(err)
		}
		return gateStep(t, svc, wf.WorkflowID, toolGate("please debug"))
	}
	var mismatch *StepInputMismatchError
	if resp, err := race("ls"); !errors.As(err, &mismatch) || resp != nil {
		t.Errorf("a race whose persisted gate carried other tool input: %+v, %v; want a StepInputMismatchError", resp, err)
	}
	if resp, err := race("please debug"); err != nil || resp == nil || resp.Decision != GateDecisionAllow {
		t.Errorf("CONTROL: a race over the same tool input: %+v, %v; want the persisted allow", resp, err)
	}
}
