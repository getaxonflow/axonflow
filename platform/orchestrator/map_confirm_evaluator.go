// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"sync"

	"axonflow/platform/orchestrator/workflow_control"
)

// ConfirmModeEvaluator is a policy evaluator for MAP confirm mode.
// Every step requires explicit approval before execution.
type ConfirmModeEvaluator struct{}

// EvaluateStepGate always returns require_approval for confirm mode.
func (e *ConfirmModeEvaluator) EvaluateStepGate(ctx context.Context, step *workflow_control.StepGateContext) *workflow_control.StepGateEvaluation {
	return &workflow_control.StepGateEvaluation{
		Decision:          workflow_control.GateDecisionRequireApproval,
		Reason:            "MAP confirm mode: all steps require explicit approval",
		PolicyIDs: []string{"map-confirm-mode"},
	}
}

// StepModeEvaluator is a policy evaluator for MAP step mode.
// The first step is auto-allowed; subsequent steps require approval.
// Thread-safe: uses mutex to protect currentStep counter.
//
// NOTE: currentStep is an internal counter that increments on each EvaluateStepGate call.
// If the evaluator is called multiple times for the same step (retry/reconnect), the counter
// will be incorrect. Future improvement: pass step index via StepGateContext instead.
type StepModeEvaluator struct {
	mu          sync.Mutex
	currentStep int
}

// EvaluateStepGate allows the first step, requires approval for subsequent steps.
func (e *StepModeEvaluator) EvaluateStepGate(ctx context.Context, step *workflow_control.StepGateContext) *workflow_control.StepGateEvaluation {
	e.mu.Lock()
	e.currentStep++
	stepNum := e.currentStep
	e.mu.Unlock()

	if stepNum == 1 {
		return &workflow_control.StepGateEvaluation{
			Decision:          workflow_control.GateDecisionAllow,
			Reason:            "MAP step mode: first step auto-allowed",
			PolicyIDs: []string{"map-step-mode"},
		}
	}

	return &workflow_control.StepGateEvaluation{
		Decision:          workflow_control.GateDecisionRequireApproval,
		Reason:            "MAP step mode: step requires approval to continue",
		PolicyIDs: []string{"map-step-mode"},
	}
}

// Reset resets the step counter so the evaluator can be reused for a new plan.
func (e *StepModeEvaluator) Reset() {
	e.mu.Lock()
	e.currentStep = 0
	e.mu.Unlock()
}
