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

func TestHITLWorkflowEngine_WarnAction(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{"result": "done"},
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"test-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    true,
		Action:     "warn",
		PolicyID:   "policy-warn",
		PolicyName: "Warning Policy",
		Reason:     "Sensitive data access",
		Severity:   "medium",
	})

	hitlEngine := NewHITLWorkflowEngine(engine, checker, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "warn-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "test-step"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Warn action should allow execution to continue and complete
	if exec.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", exec.Status)
	}
}

func TestHITLWorkflowEngine_LogAction(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{"result": "logged"},
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"test-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    true,
		Action:     "log",
		PolicyID:   "policy-log",
		PolicyName: "Audit Policy",
		Reason:     "Access recorded",
		Severity:   "low",
	})

	hitlEngine := NewHITLWorkflowEngine(engine, checker, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "log-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "test-step"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Log action should allow execution to continue and complete
	if exec.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", exec.Status)
	}
}

func TestHITLWorkflowEngine_NoPolicyChecker(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{"result": "no-checker"},
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"test-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	// Create engine without policy checker
	hitlEngine := NewHITLWorkflowEngine(engine, nil, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "no-checker-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "test-step"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Without policy checker, execution should complete
	if exec.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", exec.Status)
	}
}

func TestHITLWorkflowEngine_PolicyCheckError(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{"result": "policy-error"},
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"test-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	checker.SetError(context.DeadlineExceeded) // Simulate policy check error

	hitlEngine := NewHITLWorkflowEngine(engine, checker, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "policy-error-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "test-step"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)

	// Fail-open design: policy check errors should not block execution
	if err != nil {
		t.Fatalf("Unexpected error (should fail-open): %v", err)
	}
	if exec.Status != "completed" {
		t.Errorf("Expected status 'completed' (fail-open), got '%s'", exec.Status)
	}
}

func TestHITLWorkflowEngine_MultipleSteps(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{"result": "success"},
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"test-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	hitlEngine := NewHITLWorkflowEngine(engine, nil, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "multi-step-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "test-step"},
				{Name: "step2", Type: "test-step"},
				{Name: "step3", Type: "test-step"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exec.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", exec.Status)
	}
	if len(exec.Steps) != 3 {
		t.Errorf("Expected 3 steps executed, got %d", len(exec.Steps))
	}
	// Check that step outputs are propagated
	if exec.EndTime == nil {
		t.Error("Expected EndTime to be set")
	}
}

func TestHITLWorkflowEngine_StepFailure(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		err: context.DeadlineExceeded,
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"failing-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	hitlEngine := NewHITLWorkflowEngine(engine, nil, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "failing-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "failing-step"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)

	if err == nil {
		t.Fatal("Expected error for step failure")
	}
	if exec.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", exec.Status)
	}
	if exec.Error == "" {
		t.Error("Expected non-empty error message")
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

func TestHITLWorkflowEngine_ResumeExecution_ApprovalError(t *testing.T) {
	approval := NewMockApprovalService()
	approval.getErr = context.DeadlineExceeded // Simulate approval service error

	hitlEngine := NewHITLWorkflowEngine(nil, nil, approval)

	approvalID := uuid.New()
	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-approval-err",
			Status: StatusPaused,
		},
		ApprovalID:   approvalID,
		PausedAtStep: 0,
	}

	ctx := context.Background()
	workflow := Workflow{}

	_, err := hitlEngine.ResumeExecution(ctx, exec, workflow, nil)

	if err == nil {
		t.Fatal("Expected error when approval service fails")
	}
}

func TestHITLWorkflowEngine_ResumeExecution_NotApproved(t *testing.T) {
	approval := NewMockApprovalService()
	approvalID := uuid.New()
	approval.approvals[approvalID] = &HITLApprovalResponse{
		ApprovalID: approvalID,
		Status:     "rejected", // Not approved
	}

	hitlEngine := NewHITLWorkflowEngine(nil, nil, approval)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-rejected",
			Status: StatusPaused,
		},
		ApprovalID:   approvalID,
		PausedAtStep: 0,
	}

	ctx := context.Background()
	workflow := Workflow{}

	_, err := hitlEngine.ResumeExecution(ctx, exec, workflow, nil)

	if err == nil {
		t.Fatal("Expected error when approval is rejected")
	}
}

func TestHITLWorkflowEngine_ResumeExecution_Overridden(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{"result": "overridden"},
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"test-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	approval := NewMockApprovalService()
	approvalID := uuid.New()
	approval.approvals[approvalID] = &HITLApprovalResponse{
		ApprovalID: approvalID,
		Status:     "overridden", // Admin override
	}

	hitlEngine := NewHITLWorkflowEngine(engine, nil, approval)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-overridden",
			Status: StatusPaused,
			Steps:  make([]StepExecution, 0),
		},
		ApprovalID:   approvalID,
		PausedAtStep: 0,
	}

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "override-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "test-step"},
			},
		},
	}

	ctx := context.Background()

	resumedExec, err := hitlEngine.ResumeExecution(ctx, exec, workflow, make(map[string]interface{}))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resumedExec.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", resumedExec.Status)
	}
	if resumedExec.ApprovalStatus != "overridden" {
		t.Errorf("Expected approval status 'overridden', got '%s'", resumedExec.ApprovalStatus)
	}
}

func TestHITLWorkflowEngine_ResumeExecution_WithSteps(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{"result": "resumed"},
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"test-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	approval := NewMockApprovalService()
	approvalID := uuid.New()
	approval.approvals[approvalID] = &HITLApprovalResponse{
		ApprovalID: approvalID,
		Status:     "approved",
	}

	hitlEngine := NewHITLWorkflowEngine(engine, nil, approval)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-with-steps",
			Status: StatusPaused,
			Steps:  make([]StepExecution, 0),
		},
		ApprovalID:   approvalID,
		PausedAtStep: 1, // Resume from step 1
	}

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "multi-step-resume"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step0", Type: "test-step"},
				{Name: "step1", Type: "test-step"},
				{Name: "step2", Type: "test-step"},
			},
		},
	}

	ctx := context.Background()
	input := make(map[string]interface{})

	resumedExec, err := hitlEngine.ResumeExecution(ctx, exec, workflow, input)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resumedExec.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", resumedExec.Status)
	}
	// Should execute steps 1 and 2 (2 steps)
	if len(resumedExec.Steps) != 2 {
		t.Errorf("Expected 2 steps executed, got %d", len(resumedExec.Steps))
	}
}

func TestHITLWorkflowEngine_ResumeExecution_StepFailure(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		err: context.DeadlineExceeded,
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"failing-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	approval := NewMockApprovalService()
	approvalID := uuid.New()
	approval.approvals[approvalID] = &HITLApprovalResponse{
		ApprovalID: approvalID,
		Status:     "approved",
	}

	hitlEngine := NewHITLWorkflowEngine(engine, nil, approval)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-step-fail",
			Status: StatusPaused,
			Steps:  make([]StepExecution, 0),
		},
		ApprovalID:   approvalID,
		PausedAtStep: 0,
	}

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "failing-resume"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "failing-step"},
			},
		},
	}

	ctx := context.Background()

	resumedExec, err := hitlEngine.ResumeExecution(ctx, exec, workflow, make(map[string]interface{}))

	if err == nil {
		t.Fatal("Expected error for step failure")
	}
	if resumedExec.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", resumedExec.Status)
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

// =============================================================================
// SaveExecution and GetExecutionStatus Tests (Issue #1071 - Tech Debt)
// =============================================================================

func TestHITLWorkflowEngine_SaveExecution(t *testing.T) {
	// Clear the execution store for clean test
	executionStoreMutex.Lock()
	executionStore = make(map[string]*HITLWorkflowExecution)
	executionStoreMutex.Unlock()

	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:           "test-exec-save-1",
			WorkflowName: "test-workflow",
			Status:       StatusPaused,
		},
		ApprovalID:     uuid.New(),
		ApprovalStatus: "pending",
		PausedAtStep:   1,
		PausedReason:   "Requires approval",
	}

	// Save the execution
	hitlEngine.SaveExecution(exec)

	// Verify it was saved
	executionStoreMutex.RLock()
	saved, exists := executionStore["test-exec-save-1"]
	executionStoreMutex.RUnlock()

	if !exists {
		t.Fatal("Expected execution to be saved")
	}
	if saved.Status != StatusPaused {
		t.Errorf("Expected status 'paused', got '%s'", saved.Status)
	}
	if saved.PausedReason != "Requires approval" {
		t.Errorf("Expected paused reason 'Requires approval', got '%s'", saved.PausedReason)
	}
}

func TestHITLWorkflowEngine_SaveExecution_NilExecution(t *testing.T) {
	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)

	// Should not panic
	hitlEngine.SaveExecution(nil)
}

func TestHITLWorkflowEngine_SaveExecution_NilWorkflowExecution(t *testing.T) {
	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: nil,
	}

	// Should not panic
	hitlEngine.SaveExecution(exec)
}

func TestHITLWorkflowEngine_GetExecutionStatus(t *testing.T) {
	// Clear and populate the execution store
	executionStoreMutex.Lock()
	executionStore = make(map[string]*HITLWorkflowExecution)
	approvalID := uuid.New()
	executionStore["test-exec-get-1"] = &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-exec-get-1",
			Status: StatusPaused,
		},
		ApprovalID:     approvalID,
		ApprovalStatus: "pending",
		PausedAtStep:   2,
		PausedReason:   "High risk query",
	}
	executionStoreMutex.Unlock()

	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)
	ctx := context.Background()

	status, err := hitlEngine.GetExecutionStatus(ctx, "test-exec-get-1")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status == nil {
		t.Fatal("Expected non-nil status")
	}
	if status.ExecutionID != "test-exec-get-1" {
		t.Errorf("Expected execution ID 'test-exec-get-1', got '%s'", status.ExecutionID)
	}
	if status.Status != StatusPaused {
		t.Errorf("Expected status 'paused', got '%s'", status.Status)
	}
	if status.ApprovalID != approvalID {
		t.Errorf("Expected approval ID %v, got %v", approvalID, status.ApprovalID)
	}
	if status.ApprovalStatus != "pending" {
		t.Errorf("Expected approval status 'pending', got '%s'", status.ApprovalStatus)
	}
	if status.PausedAtStep != 2 {
		t.Errorf("Expected paused at step 2, got %d", status.PausedAtStep)
	}
	if status.PausedReason != "High risk query" {
		t.Errorf("Expected paused reason 'High risk query', got '%s'", status.PausedReason)
	}
}

func TestHITLWorkflowEngine_GetExecutionStatus_NotFound(t *testing.T) {
	// Clear the execution store
	executionStoreMutex.Lock()
	executionStore = make(map[string]*HITLWorkflowExecution)
	executionStoreMutex.Unlock()

	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)
	ctx := context.Background()

	status, err := hitlEngine.GetExecutionStatus(ctx, "nonexistent-exec")

	if err != ErrExecutionNotFound {
		t.Errorf("Expected ErrExecutionNotFound, got %v", err)
	}
	if status != nil {
		t.Error("Expected nil status for not found execution")
	}
}

func TestHITLWorkflowEngine_SaveAndGetExecution_Integration(t *testing.T) {
	// Clear the execution store
	executionStoreMutex.Lock()
	executionStore = make(map[string]*HITLWorkflowExecution)
	executionStoreMutex.Unlock()

	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)
	ctx := context.Background()

	approvalID := uuid.New()
	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:           "test-exec-integration",
			WorkflowName: "integration-workflow",
			Status:       StatusPaused,
		},
		ApprovalID:     approvalID,
		ApprovalStatus: "pending",
		PausedAtStep:   3,
		PausedReason:   "Budget limit exceeded",
	}

	// Save the execution
	hitlEngine.SaveExecution(exec)

	// Get the status
	status, err := hitlEngine.GetExecutionStatus(ctx, "test-exec-integration")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if status.ExecutionID != "test-exec-integration" {
		t.Errorf("Expected execution ID 'test-exec-integration', got '%s'", status.ExecutionID)
	}
	if status.Status != StatusPaused {
		t.Errorf("Expected status 'paused', got '%s'", status.Status)
	}
	if status.ApprovalID != approvalID {
		t.Errorf("Expected approval ID %v, got %v", approvalID, status.ApprovalID)
	}
}

// MockStepProcessor implements StepProcessor for testing executeStep
type MockStepProcessor struct {
	output map[string]interface{}
	err    error
}

func (m *MockStepProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

func TestHITLWorkflowEngine_ExecuteStep_Success(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{
			"result": "success",
			"count":  42,
		},
	}

	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"mock-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}
	hitlEngine := NewHITLWorkflowEngine(engine, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "exec-step-test",
			Status: "running",
			Steps:  make([]StepExecution, 0),
		},
	}

	step := WorkflowStep{
		Name: "test-step",
		Type: "mock-step",
	}

	ctx := context.Background()
	input := make(map[string]interface{})

	stepExec, err := hitlEngine.executeStep(ctx, step, input, exec)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if stepExec == nil {
		t.Fatal("Expected non-nil step execution")
	}
	if stepExec.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", stepExec.Status)
	}
	if stepExec.Output["result"] != "success" {
		t.Errorf("Expected output result 'success', got '%v'", stepExec.Output["result"])
	}
}

func TestHITLWorkflowEngine_ExecuteStep_UnknownType(t *testing.T) {
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}
	hitlEngine := NewHITLWorkflowEngine(engine, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "exec-unknown-type",
			Status: "running",
			Steps:  make([]StepExecution, 0),
		},
	}

	step := WorkflowStep{
		Name: "test-step",
		Type: "unknown-type",
	}

	ctx := context.Background()
	input := make(map[string]interface{})

	stepExec, err := hitlEngine.executeStep(ctx, step, input, exec)

	if err == nil {
		t.Fatal("Expected error for unknown step type")
	}
	if stepExec.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", stepExec.Status)
	}
}

func TestHITLWorkflowEngine_ExecuteStep_ProcessorError(t *testing.T) {
	mockProcessor := &MockStepProcessor{
		err: context.DeadlineExceeded,
	}

	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"error-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}
	hitlEngine := NewHITLWorkflowEngine(engine, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "exec-error-test",
			Status: "running",
			Steps:  make([]StepExecution, 0),
		},
	}

	step := WorkflowStep{
		Name: "error-step",
		Type: "error-step",
	}

	ctx := context.Background()
	input := make(map[string]interface{})

	stepExec, err := hitlEngine.executeStep(ctx, step, input, exec)

	if err == nil {
		t.Fatal("Expected error from processor")
	}
	if stepExec.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", stepExec.Status)
	}
	if stepExec.Error == "" {
		t.Error("Expected non-empty error message")
	}
}
