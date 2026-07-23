// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"testing"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	sharedaudit "axonflow/platform/shared/audit"

	"github.com/google/uuid"
)

// mockPolicyEngineForWCP implements the dynamic policy engine interface for testing
type mockPolicyEngineForWCP struct {
	result    *PolicyEvaluationResult
	lastReq   OrchestratorRequest
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
		Model:        "claude-sonnet-4",
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

	if ctx["model"] != "claude-sonnet-4" {
		t.Errorf("Expected model='claude-sonnet-4', got %v", ctx["model"])
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

// --- Tests for SetHITLApproval ---

// mockHITLApprovalCreator implements HITLApprovalCreator for testing
type mockHITLApprovalCreator struct {
	lastReq   *HITLApprovalRequest
	resp      *HITLApprovalResponse
	err       error
	callCount int
}

func (m *mockHITLApprovalCreator) CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error) {
	m.lastReq = req
	m.callCount++
	return m.resp, m.err
}

func TestSetHITLApproval(t *testing.T) {
	adapter := NewWCPPolicyAdapter(nil)

	// Initially nil
	if adapter.hitlApproval != nil {
		t.Errorf("Expected hitlApproval to be nil initially")
	}

	mock := &mockHITLApprovalCreator{}
	adapter.SetHITLApproval(mock)

	if adapter.hitlApproval != mock {
		t.Errorf("Expected hitlApproval to be set to mock")
	}

	// Setting nil clears it
	adapter.SetHITLApproval(nil)
	if adapter.hitlApproval != nil {
		t.Errorf("Expected hitlApproval to be nil after setting nil")
	}
}

// --- Tests for createHITLApproval ---

func TestCreateHITLApproval_Success(t *testing.T) {
	approvalID := uuid.New()
	mock := &mockHITLApprovalCreator{
		resp: &HITLApprovalResponse{
			ApprovalID: approvalID,
			Status:     "pending",
		},
	}

	engine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"high-risk-approval"},
			RequiredActions: []string{"require_approval"},
			RiskScore:       0.9,
		},
	}

	adapter := NewWCPPolicyAdapter(engine)
	adapter.SetHITLApproval(mock)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID:   "wf_hitl_1",
		WorkflowName: "hitl-workflow",
		StepID:       "step_hitl_1",
		StepName:     "deploy_production",
		StepType:     workflow_control.StepTypeConnectorCall,
		StepIndex:    2,
		Model:        "gpt-4",
		Provider:     "openai",
		OrgID:        "org_hitl",
		TenantID:     "tenant_hitl",
		ClientID:     "client_hitl",
		UserID:       "user_hitl",
	}

	result := adapter.EvaluateStepGate(context.Background(), stepCtx)

	// Should have require_approval decision
	if result.Decision != workflow_control.GateDecisionRequireApproval {
		t.Errorf("Expected decision=require_approval, got %s", result.Decision)
	}

	// ApprovalID should be set
	if result.ApprovalID != approvalID.String() {
		t.Errorf("Expected ApprovalID=%s, got %s", approvalID.String(), result.ApprovalID)
	}

	// Verify the HITL request was built correctly
	if mock.callCount != 1 {
		t.Fatalf("Expected 1 call to CreateApproval, got %d", mock.callCount)
	}
	if mock.lastReq.OrgID != "org_hitl" {
		t.Errorf("Expected OrgID=org_hitl, got %s", mock.lastReq.OrgID)
	}
	if mock.lastReq.TenantID != "tenant_hitl" {
		t.Errorf("Expected TenantID=tenant_hitl, got %s", mock.lastReq.TenantID)
	}
	if mock.lastReq.ClientID != "client_hitl" {
		t.Errorf("Expected ClientID=client_hitl, got %s", mock.lastReq.ClientID)
	}
	if mock.lastReq.UserID != "user_hitl" {
		t.Errorf("Expected UserID=user_hitl, got %s", mock.lastReq.UserID)
	}
	if mock.lastReq.ExecutionID != "wf_hitl_1" {
		t.Errorf("Expected ExecutionID=wf_hitl_1, got %s", mock.lastReq.ExecutionID)
	}
	if mock.lastReq.StepName != "deploy_production" {
		t.Errorf("Expected StepName=deploy_production, got %s", mock.lastReq.StepName)
	}
	if mock.lastReq.StepType != string(workflow_control.StepTypeConnectorCall) {
		t.Errorf("Expected StepType=%s, got %s", workflow_control.StepTypeConnectorCall, mock.lastReq.StepType)
	}
	if mock.lastReq.PolicyName != "high-risk-approval" {
		t.Errorf("Expected PolicyName=high-risk-approval, got %s", mock.lastReq.PolicyName)
	}
	// RiskScore=0.9 → severity derived as "critical" (≥0.8 threshold)
	if mock.lastReq.Severity != "critical" {
		t.Errorf("Expected Severity=critical (risk_score=0.9), got %s", mock.lastReq.Severity)
	}
}

func TestCreateHITLApproval_ExplicitSeverityFromPolicy(t *testing.T) {
	approvalID := uuid.New()
	mock := &mockHITLApprovalCreator{
		resp: &HITLApprovalResponse{
			ApprovalID: approvalID,
			Status:     "pending",
		},
	}

	// Policy explicitly sets severity="low" even with high risk score
	engine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"low-risk-review"},
			RequiredActions: []string{"require_approval"},
			RiskScore:       0.9,
			Severity:        "low", // Explicit from policy config
		},
	}

	adapter := NewWCPPolicyAdapter(engine)
	adapter.SetHITLApproval(mock)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_sev_1",
		StepID:     "step_sev_1",
		StepType:   workflow_control.StepTypeToolCall,
		TenantID:   "tenant-1",
		OrgID:      "org-1",
	}

	adapter.EvaluateStepGate(context.Background(), stepCtx)

	// Explicit severity from policy should override risk score
	if mock.lastReq.Severity != "low" {
		t.Errorf("Expected explicit Severity=low, got %s", mock.lastReq.Severity)
	}
}

func TestCreateHITLApproval_RiskScoreSeverityMapping(t *testing.T) {
	tests := []struct {
		name     string
		risk     float64
		expected string
	}{
		{"low risk", 0.1, "low"},
		{"medium risk", 0.4, "medium"},
		{"high risk", 0.6, "high"},
		{"critical risk", 0.9, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			approvalID := uuid.New()
			mock := &mockHITLApprovalCreator{
				resp: &HITLApprovalResponse{ApprovalID: approvalID, Status: "pending"},
			}

			engine := &mockPolicyEngineForWCP{
				result: &PolicyEvaluationResult{
					Allowed:         false,
					AppliedPolicies: []string{"test-policy"},
					RequiredActions: []string{"require_approval"},
					RiskScore:       tt.risk,
					// No explicit Severity — use risk score fallback
				},
			}

			adapter := NewWCPPolicyAdapter(engine)
			adapter.SetHITLApproval(mock)

			stepCtx := &workflow_control.StepGateContext{
				WorkflowID: "wf_risk_1",
				StepID:     "step_risk_1",
				StepType:   workflow_control.StepTypeToolCall,
				TenantID:   "tenant-1",
				OrgID:      "org-1",
			}

			adapter.EvaluateStepGate(context.Background(), stepCtx)

			if mock.lastReq.Severity != tt.expected {
				t.Errorf("risk=%.1f: expected severity=%s, got %s", tt.risk, tt.expected, mock.lastReq.Severity)
			}
		})
	}
}

func TestCreateHITLApproval_Error(t *testing.T) {
	mock := &mockHITLApprovalCreator{
		resp: nil,
		err:  fmt.Errorf("approval service unavailable"),
	}

	engine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"high-risk-approval"},
			RequiredActions: []string{"require_approval"},
		},
	}

	adapter := NewWCPPolicyAdapter(engine)
	adapter.SetHITLApproval(mock)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_hitl_err",
		StepID:     "step_hitl_err",
		StepName:   "deploy_production",
		StepType:   workflow_control.StepTypeConnectorCall,
	}

	result := adapter.EvaluateStepGate(context.Background(), stepCtx)

	// Decision should still be require_approval even if HITL creation fails
	if result.Decision != workflow_control.GateDecisionRequireApproval {
		t.Errorf("Expected decision=require_approval, got %s", result.Decision)
	}

	// ApprovalID should be empty since creation failed
	if result.ApprovalID != "" {
		t.Errorf("Expected empty ApprovalID on error, got %s", result.ApprovalID)
	}

	if mock.callCount != 1 {
		t.Errorf("Expected 1 call to CreateApproval, got %d", mock.callCount)
	}
}

func TestCreateHITLApproval_NilApprovalService(t *testing.T) {
	adapter := NewWCPPolicyAdapter(nil)
	// hitlApproval is nil, so createHITLApproval should return uuid.Nil

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_nil_hitl",
		StepID:     "step_nil_hitl",
		StepType:   workflow_control.StepTypeLLMCall,
	}

	result := &PolicyEvaluationResult{
		Allowed:         false,
		AppliedPolicies: []string{"test-policy"},
	}

	id := adapter.createHITLApproval(context.Background(), stepCtx, result)
	if id != uuid.Nil {
		t.Errorf("Expected uuid.Nil when hitlApproval is nil, got %s", id)
	}
}

func TestCreateHITLApproval_NoPolicies(t *testing.T) {
	approvalID := uuid.New()
	mock := &mockHITLApprovalCreator{
		resp: &HITLApprovalResponse{
			ApprovalID: approvalID,
			Status:     "pending",
		},
	}

	adapter := NewWCPPolicyAdapter(nil)
	adapter.SetHITLApproval(mock)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_no_policies",
		StepID:     "step_1",
		StepName:   "test_step",
		StepType:   workflow_control.StepTypeLLMCall,
	}

	result := &PolicyEvaluationResult{
		Allowed:         false,
		AppliedPolicies: []string{}, // No policies
	}

	id := adapter.createHITLApproval(context.Background(), stepCtx, result)
	if id != approvalID {
		t.Errorf("Expected approvalID=%s, got %s", approvalID, id)
	}

	// When no policies, policyName should be "unknown"
	if mock.lastReq.PolicyName != "unknown" {
		t.Errorf("Expected PolicyName=unknown when no policies, got %s", mock.lastReq.PolicyName)
	}
	if mock.lastReq.PolicyID != "" {
		t.Errorf("Expected PolicyID='' when no policies, got %s", mock.lastReq.PolicyID)
	}
}

// --- Tests for ToolContext propagation (#1243) ---

func TestWCPPolicyAdapter_ToolContext_Propagation(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{},
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID:   "wf_tool_1",
		WorkflowName: "tool-test-workflow",
		StepID:       "step_tool_1",
		StepName:     "tools/web_search",
		StepType:     workflow_control.StepTypeToolCall,
		Model:        "claude-sonnet-4",
		Provider:     "anthropic",
		TenantID:     "tenant_1",
		OrgID:        "org_1",
		ToolContext: &workflow_control.ToolContext{
			ToolName: "web_search",
			ToolType: "function",
			ToolInput: map[string]interface{}{
				"query":       "AxonFlow governance",
				"max_results": 10,
			},
		},
	}

	adapter.EvaluateStepGate(context.Background(), stepCtx)

	ctx := mockEngine.lastReq.Context
	if ctx["tool_name"] != "web_search" {
		t.Errorf("Expected tool_name='web_search', got %v", ctx["tool_name"])
	}
	if ctx["tool_type"] != "function" {
		t.Errorf("Expected tool_type='function', got %v", ctx["tool_type"])
	}
	if ctx["tool_input.query"] != "AxonFlow governance" {
		t.Errorf("Expected tool_input.query='AxonFlow governance', got %v", ctx["tool_input.query"])
	}
	if ctx["tool_input.max_results"] != 10 {
		t.Errorf("Expected tool_input.max_results=10, got %v", ctx["tool_input.max_results"])
	}
}

func TestWCPPolicyAdapter_ToolContext_NilDoesNotInjectKeys(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{},
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_tool_nil",
		StepID:     "step_1",
		StepName:   "generate_code",
		StepType:   workflow_control.StepTypeLLMCall,
		// ToolContext is nil
	}

	adapter.EvaluateStepGate(context.Background(), stepCtx)

	ctx := mockEngine.lastReq.Context
	if _, exists := ctx["tool_name"]; exists {
		t.Error("Expected tool_name to NOT exist when ToolContext is nil")
	}
	if _, exists := ctx["tool_type"]; exists {
		t.Error("Expected tool_type to NOT exist when ToolContext is nil")
	}
}

func TestWCPPolicyAdapter_ToolContext_EmptyToolType(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{},
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_tool_notype",
		StepID:     "step_1",
		StepName:   "tools/sql_query",
		StepType:   workflow_control.StepTypeToolCall,
		ToolContext: &workflow_control.ToolContext{
			ToolName: "sql_query",
			// ToolType is empty — should NOT inject tool_type key
		},
	}

	adapter.EvaluateStepGate(context.Background(), stepCtx)

	ctx := mockEngine.lastReq.Context
	if ctx["tool_name"] != "sql_query" {
		t.Errorf("Expected tool_name='sql_query', got %v", ctx["tool_name"])
	}
	if _, exists := ctx["tool_type"]; exists {
		t.Error("Expected tool_type to NOT exist when ToolType is empty")
	}
}

func TestWCPPolicyAdapter_ToolContext_MCP(t *testing.T) {
	mockEngine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{"mcp-tool-policy"},
		},
	}

	adapter := NewWCPPolicyAdapter(mockEngine)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID: "wf_tool_mcp",
		StepID:     "step_mcp",
		StepName:   "tools/database_query",
		StepType:   workflow_control.StepTypeToolCall,
		ToolContext: &workflow_control.ToolContext{
			ToolName: "database_query",
			ToolType: "mcp",
			ToolInput: map[string]interface{}{
				"sql": "SELECT * FROM users WHERE active = true",
			},
		},
	}

	adapter.EvaluateStepGate(context.Background(), stepCtx)

	ctx := mockEngine.lastReq.Context
	if ctx["tool_name"] != "database_query" {
		t.Errorf("Expected tool_name='database_query', got %v", ctx["tool_name"])
	}
	if ctx["tool_type"] != "mcp" {
		t.Errorf("Expected tool_type='mcp', got %v", ctx["tool_type"])
	}
	if ctx["tool_input.sql"] != "SELECT * FROM users WHERE active = true" {
		t.Errorf("Expected tool_input.sql, got %v", ctx["tool_input.sql"])
	}
}

func TestCreateHITLApproval_WithToolContext(t *testing.T) {
	approvalID := uuid.New()
	mock := &mockHITLApprovalCreator{
		resp: &HITLApprovalResponse{
			ApprovalID: approvalID,
			Status:     "pending",
		},
	}

	engine := &mockPolicyEngineForWCP{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"tool-restriction"},
			RequiredActions: []string{"require_approval"},
		},
	}

	adapter := NewWCPPolicyAdapter(engine)
	adapter.SetHITLApproval(mock)

	stepCtx := &workflow_control.StepGateContext{
		WorkflowID:   "wf_hitl_tool",
		WorkflowName: "tool-approval-workflow",
		StepID:       "step_tool_hitl",
		StepName:     "tools/code_executor",
		StepType:     workflow_control.StepTypeToolCall,
		OrgID:        "org_1",
		TenantID:     "tenant_1",
		ToolContext: &workflow_control.ToolContext{
			ToolName: "code_executor",
			ToolType: "function",
		},
	}

	result := adapter.EvaluateStepGate(context.Background(), stepCtx)

	if result.Decision != workflow_control.GateDecisionRequireApproval {
		t.Errorf("Expected decision=require_approval, got %s", result.Decision)
	}

	// Verify tool context was included in HITL request context
	if mock.lastReq.RequestContext["tool_name"] != "code_executor" {
		t.Errorf("Expected HITL request tool_name='code_executor', got %v", mock.lastReq.RequestContext["tool_name"])
	}
	if mock.lastReq.RequestContext["tool_type"] != "function" {
		t.Errorf("Expected HITL request tool_type='function', got %v", mock.lastReq.RequestContext["tool_type"])
	}
}

// --- Tests for NewWCPAuditAdapter and LogWorkflowOperation ---

func TestNewWCPAuditAdapter(t *testing.T) {
	// Test with nil auditLogger
	adapter := NewWCPAuditAdapter(nil)
	if adapter == nil {
		t.Fatal("Expected non-nil adapter even with nil auditLogger")
	}
	if adapter.auditLogger != nil {
		t.Errorf("Expected auditLogger to be nil")
	}
}

func TestWCPAuditAdapter_LogWorkflowOperation_NilAuditLogger(t *testing.T) {
	adapter := NewWCPAuditAdapter(nil)

	entry := &workflow_control.WorkflowAuditEntry{
		WorkflowID:   "wf_audit_1",
		WorkflowName: "test-workflow",
		StepID:       "step_1",
		StepName:     "generate",
		Operation:    "step_gate",
		Decision:     "allow",
		Reason:       "No matching policies",
		TenantID:     "tenant_1",
		ClientID:     "client_1",
		UserID:       "user_1",
	}

	// Should not panic with nil auditLogger
	adapter.LogWorkflowOperation(context.Background(), entry)
}

func TestWCPAuditAdapter_LogWorkflowOperation_NilEntry(t *testing.T) {
	adapter := NewWCPAuditAdapter(nil)

	// Should not panic with nil entry
	adapter.LogWorkflowOperation(context.Background(), nil)
}

func TestWCPAuditAdapter_LogWorkflowOperation_BothNil(t *testing.T) {
	adapter := NewWCPAuditAdapter(nil)

	// Should not panic with both nil
	adapter.LogWorkflowOperation(context.Background(), nil)
}

// --- Tests for NewMAPAuditAdapter and LogPlanOperation ---

func TestNewMAPAuditAdapter(t *testing.T) {
	// Test with nil auditLogger
	adapter := NewMAPAuditAdapter(nil)
	if adapter == nil {
		t.Fatal("Expected non-nil adapter even with nil auditLogger")
	}
	if adapter.auditLogger != nil {
		t.Errorf("Expected auditLogger to be nil")
	}
}

func TestMAPAuditAdapter_LogPlanOperation_NilAuditLogger(t *testing.T) {
	adapter := NewMAPAuditAdapter(nil)

	entry := &planning.PlanAuditEntry{
		PlanID:    "plan_1",
		Query:     "What are the risks?",
		Domain:    "risk-assessment",
		Operation: "created",
		Status:    "pending",
		StepCount: 3,
		TenantID:  "tenant_1",
		OrgID:     "org_1",
		ClientID:  "client_1",
		UserID:    "user_1",
		Metadata: map[string]interface{}{
			"source": "api",
		},
	}

	// Should not panic with nil auditLogger
	adapter.LogPlanOperation(context.Background(), entry)
}

func TestMAPAuditAdapter_LogPlanOperation_NilEntry(t *testing.T) {
	adapter := NewMAPAuditAdapter(nil)

	// Should not panic with nil entry
	adapter.LogPlanOperation(context.Background(), nil)
}

func TestMAPAuditAdapter_LogPlanOperation_BothNil(t *testing.T) {
	adapter := NewMAPAuditAdapter(nil)

	// Should not panic with both nil
	adapter.LogPlanOperation(context.Background(), nil)
}

func TestWCPAuditAdapter_LogWorkflowOperation_WithAuditLogger(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	adapter := NewWCPAuditAdapter(logger)

	entry := &workflow_control.WorkflowAuditEntry{
		WorkflowID:   "wf_audit_full",
		WorkflowName: "full-test-workflow",
		StepID:       "step_1",
		StepName:     "generate_response",
		Operation:    "step_gate",
		Decision:     "block",
		Reason:       "SQLi detected",
		TenantID:     "tenant_full",
		ClientID:     "client_full",
		UserID:       "user_full",
		Metadata: map[string]interface{}{
			"risk_score": 0.95,
		},
	}

	adapter.LogWorkflowOperation(context.Background(), entry)

	// Verify the audit entry was enqueued
	select {
	case auditEntry := <-logger.auditQueue:
		if auditEntry.RequestType != "workflow_step_gate" {
			t.Errorf("Expected request type 'workflow_step_gate', got %q", auditEntry.RequestType)
		}
		if auditEntry.PolicyDecision != "blocked" {
			t.Errorf("Expected policy decision 'blocked', got %q", auditEntry.PolicyDecision)
		}
		if auditEntry.TenantID != "tenant_full" {
			t.Errorf("Expected tenant ID 'tenant_full', got %q", auditEntry.TenantID)
		}
		if auditEntry.ClientID != "client_full" {
			t.Errorf("Expected client ID 'client_full', got %q", auditEntry.ClientID)
		}
	default:
		t.Error("Expected audit entry to be enqueued")
	}
}

func TestWCPAuditAdapter_LogWorkflowOperation_RequireApproval(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	adapter := NewWCPAuditAdapter(logger)

	entry := &workflow_control.WorkflowAuditEntry{
		WorkflowID:   "wf_approval",
		WorkflowName: "approval-workflow",
		Operation:    "step_gate",
		Decision:     "require_approval",
		Reason:       "High risk step",
		TenantID:     "tenant_1",
		ClientID:     "client_1",
	}

	adapter.LogWorkflowOperation(context.Background(), entry)

	select {
	case auditEntry := <-logger.auditQueue:
		// #2638: require_approval maps to the canonical 'needs_approval', NOT the
		// off-set 'pending_approval' this writer historically emitted (which the
		// migration-123 CHECK rejects). See workflowAuditDecision.
		if auditEntry.PolicyDecision != sharedaudit.DecisionNeedsApproval {
			t.Errorf("Expected policy decision %q, got %q", sharedaudit.DecisionNeedsApproval, auditEntry.PolicyDecision)
		}
	default:
		t.Error("Expected audit entry to be enqueued")
	}
}

func TestWCPAuditAdapter_LogWorkflowOperation_AllowDecision(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	adapter := NewWCPAuditAdapter(logger)

	entry := &workflow_control.WorkflowAuditEntry{
		WorkflowID:   "wf_allow",
		WorkflowName: "allow-workflow",
		Operation:    "step_gate",
		Decision:     "allow",
		Reason:       "No matching policies",
		TenantID:     "tenant_1",
	}

	adapter.LogWorkflowOperation(context.Background(), entry)

	select {
	case auditEntry := <-logger.auditQueue:
		if auditEntry.PolicyDecision != "allowed" {
			t.Errorf("Expected policy decision 'allowed', got %q", auditEntry.PolicyDecision)
		}
	default:
		t.Error("Expected audit entry to be enqueued")
	}
}

func TestMAPAuditAdapter_LogPlanOperation_WithAuditLogger(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	adapter := NewMAPAuditAdapter(logger)

	entry := &planning.PlanAuditEntry{
		PlanID:    "plan_full",
		Query:     "Plan a trip to Paris",
		Domain:    "travel",
		Operation: "created",
		Status:    "pending",
		StepCount: 5,
		TenantID:  "tenant_full",
		OrgID:     "org_full",
		ClientID:  "client_full",
		UserID:    "user_full",
		Metadata: map[string]interface{}{
			"source": "api",
		},
	}

	adapter.LogPlanOperation(context.Background(), entry)

	select {
	case auditEntry := <-logger.auditQueue:
		if auditEntry.RequestType != "plan_created" {
			t.Errorf("Expected request type 'plan_created', got %q", auditEntry.RequestType)
		}
		if auditEntry.PolicyDecision != "allowed" {
			t.Errorf("Expected policy decision 'allowed', got %q", auditEntry.PolicyDecision)
		}
		if auditEntry.TenantID != "tenant_full" {
			t.Errorf("Expected tenant ID 'tenant_full', got %q", auditEntry.TenantID)
		}
		if auditEntry.Query != "Plan a trip to Paris" {
			t.Errorf("Expected query 'Plan a trip to Paris', got %q", auditEntry.Query)
		}
	default:
		t.Error("Expected audit entry to be enqueued")
	}
}

func TestMAPAuditAdapter_LogPlanOperation_FailedOperation(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	adapter := NewMAPAuditAdapter(logger)

	entry := &planning.PlanAuditEntry{
		PlanID:    "plan_failed",
		Query:     "Plan something",
		Domain:    "general",
		Operation: "failed",
		Status:    "error",
		StepCount: 0,
		ErrorMsg:  "LLM provider unavailable",
		TenantID:  "tenant_1",
		OrgID:     "org_1",
		ClientID:  "client_1",
	}

	adapter.LogPlanOperation(context.Background(), entry)

	select {
	case auditEntry := <-logger.auditQueue:
		if auditEntry.RequestType != "plan_failed" {
			t.Errorf("Expected request type 'plan_failed', got %q", auditEntry.RequestType)
		}
		if auditEntry.PolicyDecision != "error" {
			t.Errorf("Expected policy decision 'error', got %q", auditEntry.PolicyDecision)
		}
	default:
		t.Error("Expected audit entry to be enqueued")
	}
}
