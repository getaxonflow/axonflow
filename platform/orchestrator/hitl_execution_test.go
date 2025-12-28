// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
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

func (m *MockPolicyChecker) CheckPolicy(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) (*PolicyCheckResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if result, ok := m.results[step.Name]; ok {
		return result, nil
	}
	return &PolicyCheckResult{Allowed: true}, nil
}

// MockApprovalService is a test mock for HITLApprovalService.
type MockApprovalService struct {
	approvals map[uuid.UUID]*HITLApprovalResponse
	createErr error
	getErr    error
}

func NewMockApprovalService() *MockApprovalService {
	return &MockApprovalService{
		approvals: make(map[uuid.UUID]*HITLApprovalResponse),
	}
}

func (m *MockApprovalService) CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}

	id := uuid.New()
	resp := &HITLApprovalResponse{
		ApprovalID: id,
		Status:     "pending",
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	m.approvals[id] = resp
	return resp, nil
}

func (m *MockApprovalService) GetApproval(ctx context.Context, approvalID uuid.UUID) (*HITLApprovalResponse, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if resp, ok := m.approvals[approvalID]; ok {
		return resp, nil
	}
	return nil, nil
}

func (m *MockApprovalService) SetApprovalStatus(approvalID uuid.UUID, status string) {
	if resp, ok := m.approvals[approvalID]; ok {
		resp.Status = status
	}
}

func TestHITLWorkflowExecution_StatusConstants(t *testing.T) {
	tests := []struct {
		constant string
		expected string
	}{
		{StatusPaused, "paused"},
		{StatusApproved, "approved"},
		{StatusRejected, "rejected"},
		{StatusExpired, "expired"},
	}

	for _, tt := range tests {
		if tt.constant != tt.expected {
			t.Errorf("Expected %s, got %s", tt.expected, tt.constant)
		}
	}
}

func TestNewHITLWorkflowEngine(t *testing.T) {
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}
	checker := NewMockPolicyChecker()
	approval := NewMockApprovalService()

	hitlEngine := NewHITLWorkflowEngine(engine, checker, approval)

	if hitlEngine == nil {
		t.Fatal("Expected non-nil HITL engine")
	}
	if hitlEngine.engine == nil {
		t.Fatal("Expected non-nil base engine")
	}
	if hitlEngine.policyChecker == nil {
		t.Fatal("Expected non-nil policy checker")
	}
	if hitlEngine.approvalService == nil {
		t.Fatal("Expected non-nil approval service")
	}
}

func TestHITLWorkflowEngine_PauseForApproval(t *testing.T) {
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    false,
		Action:     "require_approval",
		PolicyID:   "policy-123",
		PolicyName: "High Risk Query",
		Reason:     "Query requires human oversight",
		Severity:   "high",
	})

	approval := NewMockApprovalService()
	hitlEngine := NewHITLWorkflowEngine(engine, checker, approval)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "test-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{TenantID: "tenant-1"}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exec == nil {
		t.Fatal("Expected non-nil execution")
	}
	if exec.Status != StatusPaused {
		t.Errorf("Expected status 'paused', got '%s'", exec.Status)
	}
	if exec.ApprovalID == uuid.Nil {
		t.Error("Expected non-nil approval ID")
	}
	if exec.PausedAtStep != 0 {
		t.Errorf("Expected paused at step 0, got %d", exec.PausedAtStep)
	}
}

func TestHITLWorkflowEngine_BlockedByPolicy(t *testing.T) {
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    false,
		Action:     "block",
		PolicyID:   "policy-456",
		PolicyName: "SQL Injection",
		Reason:     "SQL injection detected",
		Severity:   "critical",
	})

	hitlEngine := NewHITLWorkflowEngine(engine, checker, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "test-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)

	if err == nil {
		t.Fatal("Expected error for blocked execution")
	}
	if exec.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", exec.Status)
	}
}

func TestHITLWorkflowEngine_ResumeExecution(t *testing.T) {
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}

	approval := NewMockApprovalService()
	hitlEngine := NewHITLWorkflowEngine(engine, nil, approval)

	approvalID := uuid.New()
	approval.approvals[approvalID] = &HITLApprovalResponse{
		ApprovalID: approvalID,
		Status:     "approved",
	}

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-1",
			Status: StatusPaused,
			Steps:  make([]StepExecution, 0),
		},
		ApprovalID:   approvalID,
		PausedAtStep: 0,
	}

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "test-workflow"},
		Spec:     WorkflowSpec{Steps: []WorkflowStep{}},
	}

	ctx := context.Background()

	resumedExec, err := hitlEngine.ResumeExecution(ctx, exec, workflow, make(map[string]interface{}))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resumedExec.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", resumedExec.Status)
	}
	if resumedExec.ResumedAt == nil {
		t.Error("Expected ResumedAt to be set")
	}
	if resumedExec.ApprovalStatus != "approved" {
		t.Errorf("Expected approval status 'approved', got '%s'", resumedExec.ApprovalStatus)
	}
}

func TestHITLWorkflowEngine_ResumeNotPaused(t *testing.T) {
	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-1",
			Status: "running",
		},
	}

	ctx := context.Background()
	workflow := Workflow{}

	_, err := hitlEngine.ResumeExecution(ctx, exec, workflow, nil)

	if err == nil {
		t.Fatal("Expected error when resuming non-paused execution")
	}
}

func TestHITLWorkflowEngine_AbortExecution(t *testing.T) {
	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-1",
			Status: StatusPaused,
		},
	}

	ctx := context.Background()

	abortedExec, err := hitlEngine.AbortExecution(ctx, exec, "User rejected")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if abortedExec.Status != "aborted" {
		t.Errorf("Expected status 'aborted', got '%s'", abortedExec.Status)
	}
	if abortedExec.EndTime == nil {
		t.Error("Expected EndTime to be set")
	}
}

func TestHITLWorkflowEngine_AbortNotPaused(t *testing.T) {
	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-1",
			Status: "completed",
		},
	}

	ctx := context.Background()

	_, err := hitlEngine.AbortExecution(ctx, exec, "test")

	if err == nil {
		t.Fatal("Expected error when aborting non-paused execution")
	}
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

func TestHITLExecutionStatus(t *testing.T) {
	status := &HITLExecutionStatus{
		ExecutionID:    "exec-123",
		Status:         StatusPaused,
		ApprovalID:     uuid.New(),
		ApprovalStatus: "pending",
		PausedAtStep:   2,
		PausedReason:   "Requires approval",
	}

	if status.ExecutionID != "exec-123" {
		t.Errorf("Unexpected ExecutionID: %s", status.ExecutionID)
	}
	if status.Status != StatusPaused {
		t.Errorf("Unexpected Status: %s", status.Status)
	}
	if status.PausedAtStep != 2 {
		t.Errorf("Unexpected PausedAtStep: %d", status.PausedAtStep)
	}
}
