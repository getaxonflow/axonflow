// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"

	"axonflow/platform/orchestrator/workflow_control"
)

// mockPolicyEngineForWCP implements the dynamic policy engine interface for testing
type mockPolicyEngineForWCP struct {
	result   *PolicyEvaluationResult
	lastReq  OrchestratorRequest
	callCount int
}

func (m *mockPolicyEngineForWCP) EvaluateDynamicPolicies(ctx context.Context, req OrchestratorRequest) *PolicyEvaluationResult {
	m.lastReq = req
	m.callCount++
	if m.result != nil {
		return m.result
	}
	return &PolicyEvaluationResult{
		Allowed:         true,
		AppliedPolicies: []string{},
	}
}

func (m *mockPolicyEngineForWCP) ListActivePolicies() []DynamicPolicy {
	return []DynamicPolicy{}
}

func (m *mockPolicyEngineForWCP) IsHealthy() bool {
	return true
}

func TestWCPPolicyAdapter_EvaluateStepGate_Allow(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{"pii-detection"},
			RiskScore:       0.1,
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID:   "wf_123",
		WorkflowName: "test-workflow",
		Source:       workflow_control.WorkflowSourceLangGraph,
		StepID:       "step_1",
		StepName:     "generate_code",
		StepType:     workflow_control.StepTypeLLMCall,
		Model:        "gpt-4",
		Provider:     "openai",
		TenantID:     "tenant_1",
		OrgID:        "org_1",
	}

	result := adapter.EvaluateStepGate(context.Background(), stepCtx)

	if result.Decision != workflow_control.GateDecisionAllow {
		t.Errorf("Expected decision=allow, got %s", result.Decision)
	}

	if len(result.PolicyIDs) != 1 || result.PolicyIDs[0] != "pii-detection" {
		t.Errorf("Expected PolicyIDs=[pii-detection], got %v", result.PolicyIDs)
	}

	// Verify the request was converted correctly
	if mockEngine.lastReq.RequestType != "workflow_step_gate" {
		t.Errorf("Expected RequestType=workflow_step_gate, got %s", mockEngine.lastReq.RequestType)
	}

	if mockEngine.lastReq.Client.TenantID != "tenant_1" {
		t.Errorf("Expected TenantID=tenant_1, got %s", mockEngine.lastReq.Client.TenantID)
	}
}

func TestWCPPolicyAdapter_EvaluateStepGate_Block(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"sqli-prevention", "code-injection-block"},
			RiskScore:       0.95,
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID:   "wf_456",
		WorkflowName: "code-gen-workflow",
		StepID:       "step_2",
		StepName:     "execute_query",
		StepType:     workflow_control.StepTypeToolCall,
		StepInput: map[string]interface{}{
			"query": "DROP TABLE users",
		},
	}

	result := adapter.EvaluateStepGate(context.Background(), stepCtx)

	if result.Decision != workflow_control.GateDecisionBlock {
		t.Errorf("Expected decision=block, got %s", result.Decision)
	}

	if result.Reason != "Step blocked by policy" {
		t.Errorf("Expected reason='Step blocked by policy', got %s", result.Reason)
	}

	if len(result.PoliciesMatched) != 2 {
		t.Errorf("Expected 2 policies matched, got %d", len(result.PoliciesMatched))
	}
}

func TestWCPPolicyAdapter_EvaluateStepGate_RequireApproval(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"high-risk-approval"},
			RequiredActions: []string{"require_approval"},
			RiskScore:       0.8,
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_789",
		StepID:     "step_3",
		StepName:   "deploy_code",
		StepType:   workflow_control.StepTypeConnectorCall,
	}

	result := adapter.EvaluateStepGate(context.Background(), stepCtx)

	if result.Decision != workflow_control.GateDecisionRequireApproval {
		t.Errorf("Expected decision=require_approval, got %s", result.Decision)
	}

	if result.Reason != "Step requires human approval" {
		t.Errorf("Expected reason='Step requires human approval', got %s", result.Reason)
	}
}

func TestWCPPolicyAdapter_EvaluateStepGate_NilEngine(t *testing.T) {
	adapter := NewWCPPolicyAdapter(nil)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_nil",
		StepID:     "step_nil",
		StepName:   "test_step",
		StepType:   workflow_control.StepTypeLLMCall,
	}

	result := adapter.EvaluateStepGate(context.Background(), stepCtx)

	if result.Decision != workflow_control.GateDecisionAllow {
		t.Errorf("Expected decision=allow when engine is nil, got %s", result.Decision)
	}

	if result.Reason != "No policy engine configured" {
		t.Errorf("Expected reason='No policy engine configured', got %s", result.Reason)
	}
}

func TestWCPPolicyAdapter_ConvertStepInput(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{},
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID:   "wf_input_test",
		WorkflowName: "input-test-workflow",
		StepID:       "step_input",
		StepName:     "test_step",
		StepType:     workflow_control.StepTypeLLMCall,
		Model:        "claude-3",
		Provider:     "anthropic",
		StepInput: map[string]interface{}{
			"query":       "What is PII?",
			"temperature": 0.7,
		},
	}

	adapter.EvaluateStepGate(context.Background(), stepCtx)

	// Verify step input was merged into context
	ctx := mockEngine.lastReq.Context
	if ctx["step_input.query"] != "What is PII?" {
		t.Errorf("Expected step_input.query='What is PII?', got %v", ctx["step_input.query"])
	}

	if ctx["workflow_name"] != "input-test-workflow" {
		t.Errorf("Expected workflow_name='input-test-workflow', got %v", ctx["workflow_name"])
	}

	if ctx["model"] != "claude-3" {
		t.Errorf("Expected model='claude-3', got %v", ctx["model"])
	}
}

func TestWCPPolicyAdapter_HumanReviewAction(t *testing.T) {
	// Test that "human_review" action also triggers require_approval
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"sensitive-data-review"},
			RequiredActions: []string{"human_review"},
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_review",
		StepID:     "step_review",
		StepType:   workflow_control.StepTypeHumanTask,
	}

	result := adapter.EvaluateStepGate(context.Background(), stepCtx)

	if result.Decision != workflow_control.GateDecisionRequireApproval {
		t.Errorf("Expected decision=require_approval for human_review action, got %s", result.Decision)
	}
}
