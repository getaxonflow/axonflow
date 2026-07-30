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
			// #3067: the store is keyed by the owning org, so an execution
			// needs the identity the handlers overlay from the auth headers.
			UserContext: UserContext{OrgID: "org-save"},
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
	saved, exists := executionStore[hitlStoreKey("org-save", "test-exec-save-1")]
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
	executionStore[hitlStoreKey("org-get", "test-exec-get-1")] = &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:          "test-exec-get-1",
			Status:      StatusPaused,
			UserContext: UserContext{OrgID: "org-get"},
		},
		ApprovalID:     approvalID,
		ApprovalStatus: "pending",
		PausedAtStep:   2,
		PausedReason:   "High risk query",
	}
	executionStoreMutex.Unlock()

	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)
	ctx := context.Background()

	status, err := hitlEngine.GetExecutionStatusForScope(ctx, "org-get", "test-exec-get-1")

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

	status, err := hitlEngine.GetExecutionStatusForScope(ctx, "org-get", "nonexistent-exec")

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
			// #3067: the store is keyed by the owning org.
			UserContext: UserContext{OrgID: "org-integration"},
		},
		ApprovalID:     approvalID,
		ApprovalStatus: "pending",
		PausedAtStep:   3,
		PausedReason:   "Budget limit exceeded",
	}

	// Save the execution
	hitlEngine.SaveExecution(exec)

	// Get the status
	status, err := hitlEngine.GetExecutionStatusForScope(ctx, "org-integration", "test-exec-integration")

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

// =============================================================================
// AbortExecution Coverage Tests
// =============================================================================

func TestHITLWorkflowEngine_AbortExecution_WithApprovalService(t *testing.T) {
	// Test aborting a paused execution that has an approval service and a non-nil approval ID.
	// This covers the branch where approvalService != nil && exec.ApprovalID != uuid.Nil.
	approval := NewMockApprovalService()
	approvalID := uuid.New()
	approval.approvals[approvalID] = &HITLApprovalResponse{
		ApprovalID: approvalID,
		Status:     "rejected",
	}

	hitlEngine := NewHITLWorkflowEngine(nil, nil, approval)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-abort-with-approval",
			Status: StatusPaused,
		},
		ApprovalID:   approvalID,
		PausedAtStep: 1,
	}

	ctx := context.Background()

	abortedExec, err := hitlEngine.AbortExecution(ctx, exec, "Reviewer rejected the request")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if abortedExec.Status != "aborted" {
		t.Errorf("Expected status 'aborted', got '%s'", abortedExec.Status)
	}
	if abortedExec.EndTime == nil {
		t.Error("Expected EndTime to be set")
	}
	if abortedExec.Error != "Execution aborted: Reviewer rejected the request" {
		t.Errorf("Unexpected error message: %s", abortedExec.Error)
	}
	// The approval status should be synced from the approval service
	if abortedExec.ApprovalStatus != "rejected" {
		t.Errorf("Expected approval status 'rejected', got '%s'", abortedExec.ApprovalStatus)
	}
}

func TestHITLWorkflowEngine_AbortExecution_ApprovalServiceGetError(t *testing.T) {
	// Test aborting when the approval service returns an error on GetApproval.
	// The code uses `approval, _ := ...` so the error is ignored and approval is nil.
	// This covers the branch where approval is nil after GetApproval.
	approval := NewMockApprovalService()
	approval.getErr = context.DeadlineExceeded // Force GetApproval to fail

	approvalID := uuid.New()
	hitlEngine := NewHITLWorkflowEngine(nil, nil, approval)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-abort-get-error",
			Status: StatusPaused,
		},
		ApprovalID:   approvalID,
		PausedAtStep: 0,
	}

	ctx := context.Background()

	abortedExec, err := hitlEngine.AbortExecution(ctx, exec, "Timeout abort")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if abortedExec.Status != "aborted" {
		t.Errorf("Expected status 'aborted', got '%s'", abortedExec.Status)
	}
	// ApprovalStatus should remain empty since GetApproval returned an error
	if abortedExec.ApprovalStatus != "" {
		t.Errorf("Expected empty approval status, got '%s'", abortedExec.ApprovalStatus)
	}
}

func TestHITLWorkflowEngine_AbortExecution_NilApprovalID(t *testing.T) {
	// Test aborting when the approval service exists but the execution has
	// a nil (uuid.Nil) approval ID. This skips the GetApproval call.
	approval := NewMockApprovalService()
	hitlEngine := NewHITLWorkflowEngine(nil, nil, approval)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-abort-nil-approval-id",
			Status: StatusPaused,
		},
		ApprovalID:   uuid.Nil, // Nil approval ID
		PausedAtStep: 0,
	}

	ctx := context.Background()

	abortedExec, err := hitlEngine.AbortExecution(ctx, exec, "Admin abort")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if abortedExec.Status != "aborted" {
		t.Errorf("Expected status 'aborted', got '%s'", abortedExec.Status)
	}
	if abortedExec.ApprovalStatus != "" {
		t.Errorf("Expected empty approval status (skipped), got '%s'", abortedExec.ApprovalStatus)
	}
}

func TestHITLWorkflowEngine_AbortExecution_RunningStatus(t *testing.T) {
	// Test aborting an execution with "running" status (not paused).
	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-abort-running",
			Status: "running",
		},
	}

	ctx := context.Background()
	_, err := hitlEngine.AbortExecution(ctx, exec, "test")
	if err == nil {
		t.Fatal("Expected error when aborting a running (non-paused) execution")
	}
	if err.Error() != "execution is not paused, status: running" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestHITLWorkflowEngine_AbortExecution_FailedStatus(t *testing.T) {
	// Test aborting an execution with "failed" status (not paused).
	hitlEngine := NewHITLWorkflowEngine(nil, nil, nil)

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-abort-failed",
			Status: "failed",
		},
	}

	ctx := context.Background()
	_, err := hitlEngine.AbortExecution(ctx, exec, "test")
	if err == nil {
		t.Fatal("Expected error when aborting a failed execution")
	}
}

func TestHITLWorkflowEngine_AbortExecution_ApprovalGetReturnsNil(t *testing.T) {
	// Test aborting when GetApproval succeeds but returns nil response.
	// The MockApprovalService.GetApproval returns nil for unknown IDs (no error).
	approval := NewMockApprovalService()
	hitlEngine := NewHITLWorkflowEngine(nil, nil, approval)

	unknownApprovalID := uuid.New()
	// Do NOT add this ID to approval.approvals, so GetApproval returns nil, nil.
	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:     "test-abort-nil-response",
			Status: StatusPaused,
		},
		ApprovalID:   unknownApprovalID,
		PausedAtStep: 0,
	}

	ctx := context.Background()

	abortedExec, err := hitlEngine.AbortExecution(ctx, exec, "Unknown approval")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if abortedExec.Status != "aborted" {
		t.Errorf("Expected status 'aborted', got '%s'", abortedExec.Status)
	}
	// Approval is nil, so ApprovalStatus should NOT be updated
	if abortedExec.ApprovalStatus != "" {
		t.Errorf("Expected empty approval status when approval response is nil, got '%s'", abortedExec.ApprovalStatus)
	}
}

// =============================================================================
// pauseForApproval Coverage Tests
// =============================================================================

func TestHITLWorkflowEngine_PauseForApproval_NilApprovalService(t *testing.T) {
	// Test pauseForApproval when the approval service is nil.
	// The execution should still be paused but no approval ID is set.
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    false,
		Action:     "require_approval",
		PolicyID:   "policy-nil-svc",
		PolicyName: "Nil Service Policy",
		Reason:     "Tests nil approval service path",
		Severity:   "medium",
	})

	// Create engine without approval service (nil)
	hitlEngine := NewHITLWorkflowEngine(engine, checker, nil)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "nil-approval-svc-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{TenantID: "tenant-nil"}

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
	// ApprovalID should be uuid.Nil since no approval service was used
	if exec.ApprovalID != uuid.Nil {
		t.Errorf("Expected nil approval ID, got %v", exec.ApprovalID)
	}
	// PausedReason should still be set
	if exec.PausedReason == "" {
		t.Error("Expected non-empty paused reason")
	}
	if exec.ApprovalStatus != "" {
		t.Errorf("Expected empty approval status, got '%s'", exec.ApprovalStatus)
	}
}

func TestHITLWorkflowEngine_PauseForApproval_CreateApprovalError(t *testing.T) {
	// Test pauseForApproval when CreateApproval returns an error.
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    false,
		Action:     "require_approval",
		PolicyID:   "policy-create-err",
		PolicyName: "Create Error Policy",
		Reason:     "Tests create approval error path",
		Severity:   "high",
	})

	approval := NewMockApprovalService()
	approval.createErr = context.DeadlineExceeded // Force CreateApproval to fail

	hitlEngine := NewHITLWorkflowEngine(engine, checker, approval)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "create-error-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{TenantID: "tenant-err", ID: 42}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)
	if err == nil {
		t.Fatal("Expected error when CreateApproval fails")
	}
	if exec == nil {
		t.Fatal("Expected non-nil execution even on error")
	}
	// Status should be paused (set before CreateApproval call)
	if exec.Status != StatusPaused {
		t.Errorf("Expected status 'paused', got '%s'", exec.Status)
	}
	// Error should mention the failure
	if exec.Error == "" {
		t.Error("Expected non-empty error message")
	}
	// ApprovalID should be uuid.Nil since CreateApproval failed
	if exec.ApprovalID != uuid.Nil {
		t.Errorf("Expected nil approval ID on create error, got %v", exec.ApprovalID)
	}
}

func TestHITLWorkflowEngine_PauseForApproval_PausedReasonFormat(t *testing.T) {
	// Verify the paused reason format includes the policy name and reason.
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	checker.SetResult("step1", &PolicyCheckResult{
		Allowed:    false,
		Action:     "require_approval",
		PolicyID:   "policy-reason-fmt",
		PolicyName: "Budget Limit",
		Reason:     "Exceeds $1000 threshold",
		Severity:   "high",
	})

	approval := NewMockApprovalService()
	hitlEngine := NewHITLWorkflowEngine(engine, checker, approval)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "reason-format-workflow"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{TenantID: "tenant-fmt", ID: 7}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedReason := "Policy Budget Limit requires human approval: Exceeds $1000 threshold"
	if exec.PausedReason != expectedReason {
		t.Errorf("PausedReason = %q, want %q", exec.PausedReason, expectedReason)
	}
	if exec.PausedAtStep != 0 {
		t.Errorf("PausedAtStep = %d, want 0", exec.PausedAtStep)
	}
}

func TestHITLWorkflowEngine_PauseForApproval_MultiStepPauseAtSecond(t *testing.T) {
	// Test that pausing at the second step correctly records PausedAtStep = 1.
	mockProcessor := &MockStepProcessor{
		output: map[string]interface{}{"result": "success"},
	}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"test-step": mockProcessor,
		},
		storage: NewInMemoryWorkflowStorage(),
	}

	checker := NewMockPolicyChecker()
	// Only the second step requires approval
	checker.SetResult("step2", &PolicyCheckResult{
		Allowed:    false,
		Action:     "require_approval",
		PolicyID:   "policy-step2",
		PolicyName: "Step2 Policy",
		Reason:     "Second step needs approval",
		Severity:   "medium",
	})

	approval := NewMockApprovalService()
	hitlEngine := NewHITLWorkflowEngine(engine, checker, approval)

	workflow := Workflow{
		Metadata: WorkflowMetadata{Name: "multi-step-pause"},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "test-step"},
				{Name: "step2", Type: "test-step"},
				{Name: "step3", Type: "test-step"},
			},
		},
	}

	ctx := context.Background()
	user := UserContext{TenantID: "tenant-multi"}

	exec, err := hitlEngine.ExecuteWithHITL(ctx, workflow, make(map[string]interface{}), user)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exec.Status != StatusPaused {
		t.Errorf("Expected status 'paused', got '%s'", exec.Status)
	}
	if exec.PausedAtStep != 1 {
		t.Errorf("Expected paused at step 1, got %d", exec.PausedAtStep)
	}
	// Step 1 should have been executed before pause
	if len(exec.Steps) != 1 {
		t.Errorf("Expected 1 step executed before pause, got %d", len(exec.Steps))
	}
}
