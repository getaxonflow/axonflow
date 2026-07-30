// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"testing"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
)

// mockStepProcessor is a configurable mock for the StepProcessor interface.
type mockStepProcessor struct {
	output map[string]interface{}
	err    error
	called bool
}

func (m *mockStepProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	m.called = true
	return m.output, m.err
}

func TestIntPtr(t *testing.T) {
	tests := []struct {
		name  string
		input int
		want  int
	}{
		{"zero", 0, 0},
		{"positive", 5, 5},
		{"negative", -3, -3},
		{"large", 1000000, 1000000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intPtr(tt.input)
			if got == nil {
				t.Fatal("intPtr returned nil")
			}
			if *got != tt.want {
				t.Errorf("intPtr(%d) = %d, want %d", tt.input, *got, tt.want)
			}
		})
	}

	// Verify that each call returns a distinct pointer
	t.Run("distinct_pointers", func(t *testing.T) {
		p1 := intPtr(42)
		p2 := intPtr(42)
		if p1 == p2 {
			t.Error("intPtr should return distinct pointers for separate calls")
		}
	})
}

func TestMapStepTypeToWCP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected workflow_control.StepType
	}{
		{"llm_call", "llm-call", workflow_control.StepTypeLLMCall},
		{"connector_call", "connector-call", workflow_control.StepTypeConnectorCall},
		{"empty_string_defaults_to_tool_call", "", workflow_control.StepTypeToolCall},
		{"unknown_defaults_to_tool_call", "unknown", workflow_control.StepTypeToolCall},
		{"arbitrary_string_defaults_to_tool_call", "some-random-type", workflow_control.StepTypeToolCall},
		{"tool_call_literal_defaults_to_tool_call", "tool-call", workflow_control.StepTypeToolCall},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapStepTypeToWCP(tt.input)
			if got != tt.expected {
				t.Errorf("mapStepTypeToWCP(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNewMAPWCPExecutor(t *testing.T) {
	t.Run("with_nil_services", func(t *testing.T) {
		executor := NewMAPWCPExecutor(nil, nil)
		if executor == nil {
			t.Fatal("NewMAPWCPExecutor returned nil")
		}
		if executor.wcpService != nil {
			t.Error("wcpService should be nil when passed nil")
		}
		if executor.planService != nil {
			t.Error("planService should be nil when passed nil")
		}
	})

	t.Run("with_services", func(t *testing.T) {
		wcpSvc := &workflow_control.Service{}
		planSvc := &planning.Service{}

		executor := NewMAPWCPExecutor(wcpSvc, planSvc)
		if executor == nil {
			t.Fatal("NewMAPWCPExecutor returned nil")
		}
		if executor.wcpService != wcpSvc {
			t.Error("wcpService was not set correctly")
		}
		if executor.planService != planSvc {
			t.Error("planService was not set correctly")
		}
	})
}

func TestMAPWCPExecutor_ExecuteWithConfirm_NilService(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{
		OrgID:    "org_1",
		TenantID: "tenant_1",
		PlanID:   "test-plan-1",
		Domain:   "test",
		Query:    "test query",
	}

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}

	result, err := executor.ExecuteWithConfirm(ctx, plan, workflow, "tenant-1", "org-1", "user-1", "client-1")

	if err == nil {
		t.Fatal("expected error when wcpService is nil")
	}
	if result != nil {
		t.Error("expected nil result when wcpService is nil")
	}
	if err.Error() != "WCP service not available" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestMAPWCPExecutor_ExecuteWithStep_NilService(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{
		OrgID:    "org_1",
		TenantID: "tenant_1",
		PlanID:   "test-plan-2",
		Domain:   "test",
		Query:    "test query",
	}

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}

	result, err := executor.ExecuteWithStep(ctx, plan, workflow, "tenant-1", "org-1", "user-1", "client-1")

	if err == nil {
		t.Fatal("expected error when wcpService is nil")
	}
	if result != nil {
		t.Error("expected nil result when wcpService is nil")
	}
	if err.Error() != "WCP service not available" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestMAPWCPExecutionResult_Fields(t *testing.T) {
	result := &MAPWCPExecutionResult{
		PlanID:       "plan-abc",
		WorkflowID:   "wf-123",
		Status:       "awaiting_approval",
		CurrentStep:  2,
		TotalSteps:   5,
		StepName:     "validate_input",
		ApprovalInfo: map[string]string{"url": "https://example.com/approve"},
	}

	if result.PlanID != "plan-abc" {
		t.Errorf("PlanID = %s, want plan-abc", result.PlanID)
	}
	if result.WorkflowID != "wf-123" {
		t.Errorf("WorkflowID = %s, want wf-123", result.WorkflowID)
	}
	if result.Status != "awaiting_approval" {
		t.Errorf("Status = %s, want awaiting_approval", result.Status)
	}
	if result.CurrentStep != 2 {
		t.Errorf("CurrentStep = %d, want 2", result.CurrentStep)
	}
	if result.TotalSteps != 5 {
		t.Errorf("TotalSteps = %d, want 5", result.TotalSteps)
	}
	if result.StepName != "validate_input" {
		t.Errorf("StepName = %s, want validate_input", result.StepName)
	}
	if result.ApprovalInfo == nil {
		t.Error("ApprovalInfo should not be nil")
	}
}

func TestMAPWCPExecutionResult_OmitEmptyApprovalInfo(t *testing.T) {
	result := &MAPWCPExecutionResult{
		PlanID:     "plan-no-approval",
		WorkflowID: "wf-456",
		Status:     "executing_first_step",
	}

	if result.ApprovalInfo != nil {
		t.Error("ApprovalInfo should be nil when not set")
	}
}

// TestMAPWCPExecutor_ExecuteWithConfirm_Success tests the full confirm mode path
// using a real WCP service with a mock repository.
func TestMAPWCPExecutor_ExecuteWithConfirm_Success(t *testing.T) {
	mockRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(mockRepo, nil, nil)
	planSvc := &planning.Service{}

	executor := NewMAPWCPExecutor(wcpSvc, planSvc)
	ctx := context.Background()

	plan := &planning.Plan{
		OrgID:    "org_1",
		TenantID: "tenant_1",
		PlanID:   "confirm-plan-1",
		Domain:   "travel",
		Query:    "book a flight",
	}

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "search-flights", Type: "connector-call"},
				{Name: "analyze-options", Type: "llm-call"},
				{Name: "synthesize", Type: "llm-call"},
			},
		},
	}

	result, err := executor.ExecuteWithConfirm(ctx, plan, workflow, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PlanID != "confirm-plan-1" {
		t.Errorf("PlanID = %q, want %q", result.PlanID, "confirm-plan-1")
	}
	if result.WorkflowID == "" {
		t.Error("WorkflowID should not be empty")
	}
	if result.Status != "awaiting_approval" {
		t.Errorf("Status = %q, want %q", result.Status, "awaiting_approval")
	}
	if result.CurrentStep != 0 {
		t.Errorf("CurrentStep = %d, want 0", result.CurrentStep)
	}
	if result.TotalSteps != 3 {
		t.Errorf("TotalSteps = %d, want 3", result.TotalSteps)
	}
	if result.StepName != "search-flights" {
		t.Errorf("StepName = %q, want %q", result.StepName, "search-flights")
	}
	if result.ApprovalInfo == nil {
		t.Error("ApprovalInfo should not be nil")
	}
}

// TestMAPWCPExecutor_ExecuteWithConfirm_SingleStep tests confirm mode with a single step.
func TestMAPWCPExecutor_ExecuteWithConfirm_SingleStep(t *testing.T) {
	mockRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(mockRepo, nil, nil)

	executor := NewMAPWCPExecutor(wcpSvc, nil)
	ctx := context.Background()

	plan := &planning.Plan{
		OrgID:    "org_1",
		TenantID: "tenant_1",
		PlanID:   "confirm-single-1",
		Domain:   "test",
		Query:    "single step",
	}

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "only-step", Type: "tool-call"},
			},
		},
	}

	result, err := executor.ExecuteWithConfirm(ctx, plan, workflow, "t1", "o1", "u1", "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalSteps != 1 {
		t.Errorf("TotalSteps = %d, want 1", result.TotalSteps)
	}
	if result.StepName != "only-step" {
		t.Errorf("StepName = %q, want %q", result.StepName, "only-step")
	}
}

// TestMAPWCPExecutor_ExecuteWithStep_Success tests the full step mode path.
func TestMAPWCPExecutor_ExecuteWithStep_Success(t *testing.T) {
	mockRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(mockRepo, nil, nil)

	executor := NewMAPWCPExecutor(wcpSvc, nil)
	ctx := context.Background()

	plan := &planning.Plan{
		OrgID:    "org_1",
		TenantID: "tenant_1",
		PlanID:   "step-plan-1",
		Domain:   "finance",
		Query:    "analyze portfolio",
	}

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-data", Type: "connector-call"},
				{Name: "analyze", Type: "llm-call"},
				{Name: "report", Type: "llm-call"},
			},
		},
	}

	result, err := executor.ExecuteWithStep(ctx, plan, workflow, "tenant-2", "org-2", "user-2", "client-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PlanID != "step-plan-1" {
		t.Errorf("PlanID = %q, want %q", result.PlanID, "step-plan-1")
	}
	if result.WorkflowID == "" {
		t.Error("WorkflowID should not be empty")
	}
	// With multiple steps, step mode should pause at step 1
	if result.Status != "awaiting_approval" {
		t.Errorf("Status = %q, want %q", result.Status, "awaiting_approval")
	}
	if result.CurrentStep != 1 {
		t.Errorf("CurrentStep = %d, want 1", result.CurrentStep)
	}
	if result.TotalSteps != 3 {
		t.Errorf("TotalSteps = %d, want 3", result.TotalSteps)
	}
	if result.StepName != "analyze" {
		t.Errorf("StepName = %q, want %q", result.StepName, "analyze")
	}
}

// TestMAPWCPExecutor_ExecuteWithStep_SingleStep tests step mode with only one step.
// With a single step, no subsequent approval is needed.
func TestMAPWCPExecutor_ExecuteWithStep_SingleStep(t *testing.T) {
	mockRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(mockRepo, nil, nil)

	executor := NewMAPWCPExecutor(wcpSvc, nil)
	ctx := context.Background()

	plan := &planning.Plan{
		OrgID:    "org_1",
		TenantID: "tenant_1",
		PlanID:   "step-single-1",
		Domain:   "test",
		Query:    "single step",
	}

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "only-step", Type: "function-call"},
			},
		},
	}

	result, err := executor.ExecuteWithStep(ctx, plan, workflow, "t1", "o1", "u1", "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With only one step, first step auto-executes and there's nothing to await
	if result.Status != "executing_first_step" {
		t.Errorf("Status = %q, want %q", result.Status, "executing_first_step")
	}
	if result.CurrentStep != 0 {
		t.Errorf("CurrentStep = %d, want 0", result.CurrentStep)
	}
	if result.StepName != "only-step" {
		t.Errorf("StepName = %q, want %q", result.StepName, "only-step")
	}
}

// TestExecuteSingleStep_NilEngine tests that ExecuteSingleStep returns error with nil engine.
func TestExecuteSingleStep_NilEngine(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "test-exec-1"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}

	_, err := executor.ExecuteSingleStep(ctx, plan, workflow, 0, nil, "user", nil)
	if err == nil {
		t.Fatal("expected error when engine is nil")
	}
	if err.Error() != "workflow engine not available" {
		t.Errorf("error = %q, want %q", err.Error(), "workflow engine not available")
	}
}

// TestExecuteSingleStep_OutOfRange tests that ExecuteSingleStep rejects invalid step indices.
func TestExecuteSingleStep_OutOfRange(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "test-exec-2"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
				{Name: "step2", Type: "tool-call"},
			},
		},
	}

	tests := []struct {
		name      string
		stepIndex int
	}{
		{"negative", -1},
		{"equal_to_length", 2},
		{"greater_than_length", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executor.ExecuteSingleStep(ctx, plan, workflow, tt.stepIndex, nil, "user", nil)
			if err == nil {
				t.Fatal("expected error for out-of-range step index")
			}
		})
	}
}

// TestStepExecutionResult_Fields tests the StepExecutionResult struct fields.
func TestStepExecutionResult_Fields(t *testing.T) {
	result := &StepExecutionResult{
		StepIndex: 2,
		StepName:  "analyze-data",
		Status:    "completed",
		Output:    map[string]string{"key": "value"},
	}

	if result.StepIndex != 2 {
		t.Errorf("StepIndex = %d, want 2", result.StepIndex)
	}
	if result.StepName != "analyze-data" {
		t.Errorf("StepName = %q, want %q", result.StepName, "analyze-data")
	}
	if result.Status != "completed" {
		t.Errorf("Status = %q, want %q", result.Status, "completed")
	}
	if result.Error != "" {
		t.Errorf("Error should be empty, got %q", result.Error)
	}

	// Test failed result
	failedResult := &StepExecutionResult{
		StepIndex: 0,
		StepName:  "fetch",
		Status:    "failed",
		Error:     "connection timeout",
	}
	if failedResult.Status != "failed" {
		t.Errorf("Status = %q, want %q", failedResult.Status, "failed")
	}
	if failedResult.Error != "connection timeout" {
		t.Errorf("Error = %q, want %q", failedResult.Error, "connection timeout")
	}
}

// TestExecuteSingleStep_MissingProcessor tests that ExecuteSingleStep returns a
// failed StepExecutionResult (not an error) when no processor exists for the step type.
func TestExecuteSingleStep_MissingProcessor(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "test-missing-proc"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "custom-step", Type: "nonexistent-type"},
			},
		},
	}

	// Engine with no processors registered for "nonexistent-type"
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{},
	}

	result, err := executor.ExecuteSingleStep(ctx, plan, workflow, 0, nil, "user", engine)
	if err != nil {
		t.Fatalf("unexpected error (missing processor should not return error): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Status != "failed" {
		t.Errorf("Status = %q, want %q", result.Status, "failed")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
	if result.StepIndex != 0 {
		t.Errorf("StepIndex = %d, want 0", result.StepIndex)
	}
	if result.StepName != "custom-step" {
		t.Errorf("StepName = %q, want %q", result.StepName, "custom-step")
	}
}

// TestExecuteSingleStep_SuccessfulExecution tests successful step execution
// with a mock StepProcessor that returns output.
func TestExecuteSingleStep_SuccessfulExecution(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "test-success-exec"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-data", Type: "connector-call"},
				{Name: "analyze", Type: "llm-call"},
				{Name: "synthesize", Type: "llm-call"},
			},
		},
	}

	mockProc := &mockStepProcessor{
		output: map[string]interface{}{
			"response": "analysis complete",
			"tokens":   150,
		},
	}

	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"llm-call": mockProc,
		},
	}

	result, err := executor.ExecuteSingleStep(ctx, plan, workflow, 1, nil, "user", engine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !mockProc.called {
		t.Error("expected processor to be called")
	}
	if result.Status != "completed" {
		t.Errorf("Status = %q, want %q", result.Status, "completed")
	}
	if result.StepIndex != 1 {
		t.Errorf("StepIndex = %d, want 1", result.StepIndex)
	}
	if result.StepName != "analyze" {
		t.Errorf("StepName = %q, want %q", result.StepName, "analyze")
	}

	// Verify output is passed through
	outputMap, ok := result.Output.(map[string]interface{})
	if !ok {
		t.Fatalf("Output type = %T, want map[string]interface{}", result.Output)
	}
	if outputMap["response"] != "analysis complete" {
		t.Errorf("Output[response] = %v, want %q", outputMap["response"], "analysis complete")
	}
	if result.Error != "" {
		t.Errorf("Error should be empty, got %q", result.Error)
	}
}

// TestExecuteSingleStep_ProcessorReturnsError tests that a processor error
// results in a failed StepExecutionResult (returned without a Go-level error).
func TestExecuteSingleStep_ProcessorReturnsError(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "test-proc-error"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "failing-step", Type: "connector-call"},
			},
		},
	}

	mockProc := &mockStepProcessor{
		output: nil,
		err:    fmt.Errorf("connection refused: database unavailable"),
	}

	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"connector-call": mockProc,
		},
	}

	result, err := executor.ExecuteSingleStep(ctx, plan, workflow, 0, nil, "user", engine)
	if err != nil {
		t.Fatalf("unexpected Go-level error (should be nil): %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !mockProc.called {
		t.Error("expected processor to be called")
	}
	if result.Status != "failed" {
		t.Errorf("Status = %q, want %q", result.Status, "failed")
	}
	if result.Error != "connection refused: database unavailable" {
		t.Errorf("Error = %q, want %q", result.Error, "connection refused: database unavailable")
	}
	if result.StepIndex != 0 {
		t.Errorf("StepIndex = %d, want 0", result.StepIndex)
	}
	if result.StepName != "failing-step" {
		t.Errorf("StepName = %q, want %q", result.StepName, "failing-step")
	}
	if result.Output != nil {
		t.Errorf("Output should be nil for failed step, got %v", result.Output)
	}
}

// TestExecuteSingleStep_WithExecContext tests that execution context is
// correctly passed to the step processor as input.
func TestExecuteSingleStep_WithExecContext(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "test-context-pass"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "contextual-step", Type: "llm-call"},
			},
		},
	}

	var receivedInput map[string]interface{}
	mockProc := &mockStepProcessor{
		output: map[string]interface{}{"result": "ok"},
	}

	// Override ExecuteStep to capture input
	captureProc := &inputCapturingProcessor{
		output:     map[string]interface{}{"result": "ok"},
		capturedFn: func(input map[string]interface{}) { receivedInput = input },
	}

	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"llm-call": captureProc,
		},
	}

	execContext := map[string]interface{}{
		"previous_output": "flight data",
		"step_count":      3,
	}

	result, err := executor.ExecuteSingleStep(ctx, plan, workflow, 0, execContext, "user", engine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "completed" {
		t.Errorf("Status = %q, want %q", result.Status, "completed")
	}
	_ = mockProc // suppress unused warning

	// Verify the exec context was passed through
	if receivedInput == nil {
		t.Fatal("expected input to be captured by processor")
	}
	if receivedInput["previous_output"] != "flight data" {
		t.Errorf("input[previous_output] = %v, want %q", receivedInput["previous_output"], "flight data")
	}
	if receivedInput["step_count"] != 3 {
		t.Errorf("input[step_count] = %v, want 3", receivedInput["step_count"])
	}
}

// inputCapturingProcessor captures the input passed to ExecuteStep for verification.
type inputCapturingProcessor struct {
	output     map[string]interface{}
	err        error
	capturedFn func(map[string]interface{})
}

func (p *inputCapturingProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	if p.capturedFn != nil {
		p.capturedFn(input)
	}
	return p.output, p.err
}

// TestExecuteSingleStep_NilExecContext tests that nil execContext doesn't cause panic.
func TestExecuteSingleStep_NilExecContext(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "test-nil-context"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "simple-step", Type: "function-call"},
			},
		},
	}

	mockProc := &mockStepProcessor{
		output: map[string]interface{}{"status": "done"},
	}

	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"function-call": mockProc,
		},
	}

	result, err := executor.ExecuteSingleStep(ctx, plan, workflow, 0, nil, "user", engine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "completed" {
		t.Errorf("Status = %q, want %q", result.Status, "completed")
	}
}

// TestExecuteSingleStep_LastStepIndex tests executing the last step in a multi-step workflow.
func TestExecuteSingleStep_LastStepIndex(t *testing.T) {
	executor := NewMAPWCPExecutor(nil, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "test-last-step"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step-0", Type: "connector-call"},
				{Name: "step-1", Type: "llm-call"},
				{Name: "step-2", Type: "llm-call"},
			},
		},
	}

	mockProc := &mockStepProcessor{
		output: map[string]interface{}{"final": true},
	}

	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{
			"llm-call": mockProc,
		},
	}

	result, err := executor.ExecuteSingleStep(ctx, plan, workflow, 2, nil, "user", engine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StepIndex != 2 {
		t.Errorf("StepIndex = %d, want 2", result.StepIndex)
	}
	if result.StepName != "step-2" {
		t.Errorf("StepName = %q, want %q", result.StepName, "step-2")
	}
	if result.Status != "completed" {
		t.Errorf("Status = %q, want %q", result.Status, "completed")
	}
}

// TestExecuteWithConfirm_EmptySteps tests that ExecuteWithConfirm returns error for empty steps.
func TestExecuteWithConfirm_EmptySteps(t *testing.T) {
	mockRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(mockRepo, nil, nil)

	executor := NewMAPWCPExecutor(wcpSvc, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "empty-confirm"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{},
		},
	}

	_, err := executor.ExecuteWithConfirm(ctx, plan, workflow, "t", "o", "u", "c")
	if err == nil {
		t.Fatal("expected error for empty steps")
	}
	if err.Error() != "workflow has no steps" {
		t.Errorf("error = %q, want %q", err.Error(), "workflow has no steps")
	}
}

// TestExecuteWithStep_EmptySteps tests that ExecuteWithStep returns error for empty steps.
func TestExecuteWithStep_EmptySteps(t *testing.T) {
	mockRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(mockRepo, nil, nil)

	executor := NewMAPWCPExecutor(wcpSvc, nil)
	ctx := context.Background()

	plan := &planning.Plan{PlanID: "empty-step"}
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{},
		},
	}

	_, err := executor.ExecuteWithStep(ctx, plan, workflow, "t", "o", "u", "c")
	if err == nil {
		t.Fatal("expected error for empty steps")
	}
	if err.Error() != "workflow has no steps" {
		t.Errorf("error = %q, want %q", err.Error(), "workflow has no steps")
	}
}

// TestExecuteWithStep_TwoSteps tests step mode with exactly two steps.
func TestExecuteWithStep_TwoSteps(t *testing.T) {
	mockRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(mockRepo, nil, nil)

	executor := NewMAPWCPExecutor(wcpSvc, nil)
	ctx := context.Background()

	plan := &planning.Plan{
		OrgID:    "org_1",
		TenantID: "tenant_1",
		PlanID:   "step-two-1",
		Domain:   "test",
		Query:    "two steps",
	}

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "first", Type: "connector-call"},
				{Name: "second", Type: "llm-call"},
			},
		},
	}

	result, err := executor.ExecuteWithStep(ctx, plan, workflow, "t1", "o1", "u1", "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != "awaiting_approval" {
		t.Errorf("Status = %q, want %q", result.Status, "awaiting_approval")
	}
	if result.CurrentStep != 1 {
		t.Errorf("CurrentStep = %d, want 1", result.CurrentStep)
	}
	if result.StepName != "second" {
		t.Errorf("StepName = %q, want %q", result.StepName, "second")
	}
	if result.TotalSteps != 2 {
		t.Errorf("TotalSteps = %d, want 2", result.TotalSteps)
	}
}
