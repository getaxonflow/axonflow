// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"

	"axonflow/platform/orchestrator/workflow_control"
)

func TestConfirmModeEvaluator_AlwaysRequiresApproval(t *testing.T) {
	evaluator := &ConfirmModeEvaluator{}
	ctx := context.Background()
	step := &workflow_control.StepGateContext{}

	for i := 0; i < 3; i++ {
		result := evaluator.EvaluateStepGate(ctx, step)
		if result.Decision != workflow_control.GateDecisionRequireApproval {
			t.Errorf("call %d: expected decision %q, got %q",
				i+1, workflow_control.GateDecisionRequireApproval, result.Decision)
		}
	}
}

func TestConfirmModeEvaluator_PolicyID(t *testing.T) {
	evaluator := &ConfirmModeEvaluator{}
	ctx := context.Background()
	step := &workflow_control.StepGateContext{}

	result := evaluator.EvaluateStepGate(ctx, step)

	if len(result.PolicyIDs) != 1 {
		t.Fatalf("expected 1 policy ID, got %d", len(result.PolicyIDs))
	}
	if result.PolicyIDs[0] != "map-confirm-mode" {
		t.Errorf("expected policy ID %q, got %q", "map-confirm-mode", result.PolicyIDs[0])
	}
}

func TestConfirmModeEvaluator_Reason(t *testing.T) {
	evaluator := &ConfirmModeEvaluator{}
	ctx := context.Background()
	step := &workflow_control.StepGateContext{}

	result := evaluator.EvaluateStepGate(ctx, step)

	expected := "MAP confirm mode: all steps require explicit approval"
	if result.Reason != expected {
		t.Errorf("expected reason %q, got %q", expected, result.Reason)
	}
}

func TestStepModeEvaluator_FirstStepAllowed(t *testing.T) {
	evaluator := &StepModeEvaluator{}
	ctx := context.Background()
	step := &workflow_control.StepGateContext{}

	result := evaluator.EvaluateStepGate(ctx, step)

	if result.Decision != workflow_control.GateDecisionAllow {
		t.Errorf("expected first step decision %q, got %q",
			workflow_control.GateDecisionAllow, result.Decision)
	}
	if result.Reason != "MAP step mode: first step auto-allowed" {
		t.Errorf("expected reason %q, got %q",
			"MAP step mode: first step auto-allowed", result.Reason)
	}
}

func TestStepModeEvaluator_SubsequentStepsRequireApproval(t *testing.T) {
	evaluator := &StepModeEvaluator{}
	ctx := context.Background()
	step := &workflow_control.StepGateContext{}

	// Consume the first step (auto-allowed).
	_ = evaluator.EvaluateStepGate(ctx, step)

	// Second and third calls must require approval.
	for i := 2; i <= 3; i++ {
		result := evaluator.EvaluateStepGate(ctx, step)
		if result.Decision != workflow_control.GateDecisionRequireApproval {
			t.Errorf("step %d: expected decision %q, got %q",
				i, workflow_control.GateDecisionRequireApproval, result.Decision)
		}
		if result.Reason != "MAP step mode: step requires approval to continue" {
			t.Errorf("step %d: expected reason %q, got %q",
				i, "MAP step mode: step requires approval to continue", result.Reason)
		}
	}
}

func TestStepModeEvaluator_PolicyID(t *testing.T) {
	evaluator := &StepModeEvaluator{}
	ctx := context.Background()
	step := &workflow_control.StepGateContext{}

	// Check policy ID on the first step (allow).
	result := evaluator.EvaluateStepGate(ctx, step)
	if len(result.PolicyIDs) != 1 {
		t.Fatalf("first step: expected 1 policy ID, got %d", len(result.PolicyIDs))
	}
	if result.PolicyIDs[0] != "map-step-mode" {
		t.Errorf("first step: expected policy ID %q, got %q", "map-step-mode", result.PolicyIDs[0])
	}

	// Check policy ID on the second step (require_approval).
	result = evaluator.EvaluateStepGate(ctx, step)
	if len(result.PolicyIDs) != 1 {
		t.Fatalf("second step: expected 1 policy ID, got %d", len(result.PolicyIDs))
	}
	if result.PolicyIDs[0] != "map-step-mode" {
		t.Errorf("second step: expected policy ID %q, got %q", "map-step-mode", result.PolicyIDs[0])
	}
}

func TestStepModeEvaluator_Reset(t *testing.T) {
	evaluator := &StepModeEvaluator{}
	ctx := context.Background()
	step := &workflow_control.StepGateContext{}

	// Consume two steps: first auto-allowed, second requires approval
	result1 := evaluator.EvaluateStepGate(ctx, step)
	if result1.Decision != workflow_control.GateDecisionAllow {
		t.Fatalf("step 1: expected allow, got %q", result1.Decision)
	}
	result2 := evaluator.EvaluateStepGate(ctx, step)
	if result2.Decision != workflow_control.GateDecisionRequireApproval {
		t.Fatalf("step 2: expected require_approval, got %q", result2.Decision)
	}

	// Reset — should go back to step 0
	evaluator.Reset()

	// After reset, first step should be auto-allowed again
	result3 := evaluator.EvaluateStepGate(ctx, step)
	if result3.Decision != workflow_control.GateDecisionAllow {
		t.Errorf("after reset: expected allow, got %q", result3.Decision)
	}
}

func TestStepModeEvaluator_MultipleSteps(t *testing.T) {
	evaluator := &StepModeEvaluator{}
	ctx := context.Background()
	step := &workflow_control.StepGateContext{}

	expectedDecisions := []workflow_control.GateDecision{
		workflow_control.GateDecisionAllow,
		workflow_control.GateDecisionRequireApproval,
		workflow_control.GateDecisionRequireApproval,
		workflow_control.GateDecisionRequireApproval,
		workflow_control.GateDecisionRequireApproval,
	}

	for i, expected := range expectedDecisions {
		result := evaluator.EvaluateStepGate(ctx, step)
		if result.Decision != expected {
			t.Errorf("step %d: expected decision %q, got %q",
				i+1, expected, result.Decision)
		}
	}
}
