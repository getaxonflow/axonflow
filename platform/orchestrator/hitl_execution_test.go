// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"
)

// MockPolicyChecker is a test mock for HITLPolicyChecker.
type MockPolicyChecker struct {
	results map[string]*PolicyCheckResult
	err     error
}

func NewMockPolicyChecker() *MockPolicyChecker {
	return &MockPolicyChecker{
		results: make(map[string]*PolicyCheckResult),
	}
}

func (m *MockPolicyChecker) SetResult(stepName string, result *PolicyCheckResult) {
	m.results[stepName] = result
}

func (m *MockPolicyChecker) SetError(err error) {
	m.err = err
}

func (m *MockPolicyChecker) CheckPolicy(ctx context.Context, step WorkflowStep, _ StepContent, execution *WorkflowExecution) (*PolicyCheckResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if result, ok := m.results[step.Name]; ok {
		return result, nil
	}
	return &PolicyCheckResult{Allowed: true}, nil
}

func TestPolicyCheckResult_Actions(t *testing.T) {
	actions := []string{"block", "require_approval", "warn", "log"}

	for _, action := range actions {
		result := &PolicyCheckResult{
			Allowed:    action != "block" && action != "require_approval",
			Action:     action,
			PolicyID:   "test-policy",
			PolicyName: "Test Policy",
			Reason:     "Test reason",
			Severity:   "high",
		}

		if result.Action != action {
			t.Errorf("Expected action '%s', got '%s'", action, result.Action)
		}
	}
}
