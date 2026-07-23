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
		Decision:  workflow_control.GateDecisionRequireApproval,
		Reason:    "MAP confirm mode: all steps require explicit approval",
		PolicyIDs: []string{"map-confirm-mode"},
	}
}

// StepModeEvaluator is a policy evaluator for MAP step mode.
// The first step is auto-allowed; subsequent steps require approval.
// Thread-safe and idempotent: tracks evaluated steps by (workflowID, stepID) key.
// Retries for the same step return the cached decision without advancing the counter.
type StepModeEvaluator struct {
	mu           sync.Mutex
	evaluatedMap sync.Map // key: "workflowID:stepID" -> *StepGateEvaluation
	currentStep  int
}

// EvaluateStepGate allows the first step, requires approval for subsequent steps.
// Idempotent: calling with the same (workflowID, stepID) returns the cached decision.
// If workflowID/stepID are empty, falls back to non-idempotent counter behavior.
func (e *StepModeEvaluator) EvaluateStepGate(ctx context.Context, step *workflow_control.StepGateContext) *workflow_control.StepGateEvaluation {
	key := step.WorkflowID + ":" + step.StepID
	useCache := step.WorkflowID != "" && step.StepID != ""

	// Return cached decision if this step was already evaluated (idempotent retry)
	if useCache {
		if cached, ok := e.evaluatedMap.Load(key); ok {
			return cached.(*workflow_control.StepGateEvaluation)
		}
	}

	e.mu.Lock()
	// Double-check after acquiring lock
	if useCache {
		if cached, ok := e.evaluatedMap.Load(key); ok {
			e.mu.Unlock()
			return cached.(*workflow_control.StepGateEvaluation)
		}
	}
	e.currentStep++
	stepNum := e.currentStep
	e.mu.Unlock()

	var result *workflow_control.StepGateEvaluation
	if stepNum == 1 {
		result = &workflow_control.StepGateEvaluation{
			Decision:  workflow_control.GateDecisionAllow,
			Reason:    "MAP step mode: first step auto-allowed",
			PolicyIDs: []string{"map-step-mode"},
		}
	} else {
		result = &workflow_control.StepGateEvaluation{
			Decision:  workflow_control.GateDecisionRequireApproval,
			Reason:    "MAP step mode: step requires approval to continue",
			PolicyIDs: []string{"map-step-mode"},
		}
	}

	if useCache {
		e.evaluatedMap.Store(key, result)
	}
	return result
}

// Reset resets the step counter and cached decisions so the evaluator can be reused.
func (e *StepModeEvaluator) Reset() {
	e.mu.Lock()
	e.currentStep = 0
	e.mu.Unlock()
	e.evaluatedMap = sync.Map{}
}
