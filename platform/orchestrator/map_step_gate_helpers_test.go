// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "context"

// allowEveryStep is a checker that allows every step and records what it was
// shown. Handler tests whose subject is not the decision (tenancy, identity
// binding) run on an engine that decides every step (#4382) through it.
type allowEveryStep struct{ presented []string }

func (c *allowEveryStep) CheckPolicy(_ context.Context, step WorkflowStep, _ StepContent, _ *WorkflowExecution) (*PolicyCheckResult, error) {
	c.presented = append(c.presented, step.Name)
	return &PolicyCheckResult{Allowed: true, Action: "allow", Reason: "test: every step is allowed"}, nil
}

// newGovernedWorkflowEngine is NewWorkflowEngine with the step gate the
// orchestrator wires at boot, deciding through checker, with no audit writer.
func newGovernedWorkflowEngine(checker HITLPolicyChecker) *WorkflowEngine {
	engine := NewWorkflowEngine()
	engine.SetStepGate(checker, nil)
	return engine
}
