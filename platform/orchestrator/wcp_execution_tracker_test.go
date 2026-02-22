// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/execution"
)

func TestMapWCPStepType(t *testing.T) {
	tests := []struct {
		name     string
		input    workflow_control.StepType
		expected execution.StepType
	}{
		{"llm_call", workflow_control.StepTypeLLMCall, execution.StepTypeLLMCall},
		{"tool_call", workflow_control.StepTypeToolCall, execution.StepTypeToolCall},
		{"connector_call", workflow_control.StepTypeConnectorCall, execution.StepTypeConnectorCall},
		{"human_task", workflow_control.StepTypeHumanTask, execution.StepTypeHumanTask},
		{"unknown maps to action", workflow_control.StepType("unknown"), execution.StepTypeAction},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapWCPStepType(tt.input)
			if result != tt.expected {
				t.Errorf("mapWCPStepType(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMapWCPStepDecisionToStatus(t *testing.T) {
	pending := workflow_control.ApprovalStatusPending
	approved := workflow_control.ApprovalStatusApproved
	rejected := workflow_control.ApprovalStatusRejected

	tests := []struct {
		name           string
		decision       workflow_control.GateDecision
		approvalStatus *workflow_control.ApprovalStatus
		expected       execution.StepStatusValue
	}{
		{"allow maps to running", workflow_control.GateDecisionAllow, nil, execution.StepStatusRunning},
		{"block maps to blocked", workflow_control.GateDecisionBlock, nil, execution.StepStatusBlocked},
		{"require_approval with nil status", workflow_control.GateDecisionRequireApproval, nil, execution.StepStatusApproval},
		{"require_approval pending", workflow_control.GateDecisionRequireApproval, &pending, execution.StepStatusApproval},
		{"require_approval approved", workflow_control.GateDecisionRequireApproval, &approved, execution.StepStatusRunning},
		{"require_approval rejected", workflow_control.GateDecisionRequireApproval, &rejected, execution.StepStatusFailed},
		{"unknown decision maps to pending", workflow_control.GateDecision("unknown"), nil, execution.StepStatusPending},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapWCPStepDecisionToStatus(tt.decision, tt.approvalStatus)
			if result != tt.expected {
				t.Errorf("mapWCPStepDecisionToStatus(%s, %v) = %s, want %s",
					tt.decision, tt.approvalStatus, result, tt.expected)
			}
		})
	}
}

func TestMapWCPStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    workflow_control.WorkflowStatus
		expected execution.ExecutionStatusValue
	}{
		{"in_progress maps to running", workflow_control.WorkflowStatusInProgress, execution.StatusRunning},
		{"completed maps to completed", workflow_control.WorkflowStatusCompleted, execution.StatusCompleted},
		{"failed maps to failed", workflow_control.WorkflowStatusFailed, execution.StatusFailed},
		{"aborted maps to aborted", workflow_control.WorkflowStatusAborted, execution.StatusAborted},
		{"unknown maps to pending", workflow_control.WorkflowStatus("unknown"), execution.StatusPending},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapWCPStatus(tt.input)
			if result != tt.expected {
				t.Errorf("mapWCPStatus(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestWorkflowToExecutionStatus(t *testing.T) {
	now := time.Now()
	completedAt := now.Add(30 * time.Second)
	stepCompletedAt := now.Add(10 * time.Second)
	totalSteps := 3

	t.Run("basic workflow conversion", func(t *testing.T) {
		workflow := &workflow_control.Workflow{
			WorkflowID:       "wf_abc123",
			WorkflowName:     "Test Workflow",
			Source:           workflow_control.WorkflowSourceLangGraph,
			Status:           workflow_control.WorkflowStatusInProgress,
			CurrentStepIndex: 1,
			TotalSteps:       &totalSteps,
			TenantID:         "tenant_1",
			OrgID:            "org_1",
			UserID:           "user_1",
			ClientID:         "client_1",
			StartedAt:        now,
			CreatedAt:        now,
			UpdatedAt:        now,
			Steps: []workflow_control.WorkflowStep{
				{
					StepID:          "step_1",
					StepIndex:       0,
					StepName:        "analyze",
					StepType:        workflow_control.StepTypeLLMCall,
					Decision:        workflow_control.GateDecisionAllow,
					GateCheckedAt:   now,
					StepCompletedAt: &stepCompletedAt,
					Model:           "gpt-4",
					Provider:        "openai",
				},
				{
					StepID:        "step_2",
					StepIndex:     1,
					StepName:      "process",
					StepType:      workflow_control.StepTypeToolCall,
					Decision:      workflow_control.GateDecisionAllow,
					GateCheckedAt: now.Add(10 * time.Second),
				},
			},
		}

		result := workflowToExecutionStatus(workflow)

		if result.ExecutionID != "wf_abc123" {
			t.Errorf("ExecutionID = %s, want wf_abc123", result.ExecutionID)
		}
		if result.ExecutionType != execution.ExecutionTypeWCP {
			t.Errorf("ExecutionType = %s, want %s", result.ExecutionType, execution.ExecutionTypeWCP)
		}
		if result.Name != "Test Workflow" {
			t.Errorf("Name = %s, want Test Workflow", result.Name)
		}
		if result.Source != "langgraph" {
			t.Errorf("Source = %s, want langgraph", result.Source)
		}
		if result.Status != execution.StatusRunning {
			t.Errorf("Status = %s, want %s", result.Status, execution.StatusRunning)
		}
		if result.TotalSteps != 3 {
			t.Errorf("TotalSteps = %d, want 3", result.TotalSteps)
		}
		if len(result.Steps) != 2 {
			t.Errorf("Steps count = %d, want 2", len(result.Steps))
		}

		// Check first step (completed)
		if result.Steps[0].Status != execution.StepStatusCompleted {
			t.Errorf("Steps[0].Status = %s, want %s", result.Steps[0].Status, execution.StepStatusCompleted)
		}
		if result.Steps[0].Model != "gpt-4" {
			t.Errorf("Steps[0].Model = %s, want gpt-4", result.Steps[0].Model)
		}

		// Check second step (running)
		if result.Steps[1].Status != execution.StepStatusRunning {
			t.Errorf("Steps[1].Status = %s, want %s", result.Steps[1].Status, execution.StepStatusRunning)
		}

		// Check progress
		// 1 completed out of 3 total = 33.33%
		expectedProgress := float64(1) / float64(3) * 100
		if result.ProgressPercent != expectedProgress {
			t.Errorf("ProgressPercent = %f, want %f", result.ProgressPercent, expectedProgress)
		}

		// Check metadata
		if result.Metadata["workflow_id"] != "wf_abc123" {
			t.Errorf("Metadata[workflow_id] = %v, want wf_abc123", result.Metadata["workflow_id"])
		}
	})

	t.Run("completed workflow", func(t *testing.T) {
		totalSteps := 2
		workflow := &workflow_control.Workflow{
			WorkflowID:       "wf_completed",
			WorkflowName:     "Completed Workflow",
			Source:           workflow_control.WorkflowSourceCrewAI,
			Status:           workflow_control.WorkflowStatusCompleted,
			CurrentStepIndex: 2,
			TotalSteps:       &totalSteps,
			StartedAt:        now,
			CompletedAt:      &completedAt,
			CreatedAt:        now,
			UpdatedAt:        completedAt,
			Steps: []workflow_control.WorkflowStep{
				{
					StepID:          "s1",
					StepIndex:       0,
					Decision:        workflow_control.GateDecisionAllow,
					GateCheckedAt:   now,
					StepCompletedAt: &stepCompletedAt,
				},
				{
					StepID:          "s2",
					StepIndex:       1,
					Decision:        workflow_control.GateDecisionAllow,
					GateCheckedAt:   stepCompletedAt,
					StepCompletedAt: &completedAt,
				},
			},
		}

		result := workflowToExecutionStatus(workflow)

		if result.Status != execution.StatusCompleted {
			t.Errorf("Status = %s, want %s", result.Status, execution.StatusCompleted)
		}
		if result.ProgressPercent != 100 {
			t.Errorf("ProgressPercent = %f, want 100", result.ProgressPercent)
		}
		if result.CompletedAt == nil {
			t.Error("CompletedAt should not be nil")
		}
	})

	t.Run("workflow with pending approval", func(t *testing.T) {
		pending := workflow_control.ApprovalStatusPending
		workflow := &workflow_control.Workflow{
			WorkflowID:       "wf_approval",
			WorkflowName:     "Approval Workflow",
			Source:           workflow_control.WorkflowSourceExternal,
			Status:           workflow_control.WorkflowStatusInProgress,
			CurrentStepIndex: 0,
			StartedAt:        now,
			CreatedAt:        now,
			UpdatedAt:        now,
			Steps: []workflow_control.WorkflowStep{
				{
					StepID:         "s1",
					StepIndex:      0,
					StepName:       "approval_step",
					Decision:       workflow_control.GateDecisionRequireApproval,
					ApprovalStatus: &pending,
					GateCheckedAt:  now,
				},
			},
		}

		result := workflowToExecutionStatus(workflow)

		if result.Steps[0].Status != execution.StepStatusApproval {
			t.Errorf("Steps[0].Status = %s, want %s", result.Steps[0].Status, execution.StepStatusApproval)
		}
	})

	t.Run("workflow with blocked step", func(t *testing.T) {
		workflow := &workflow_control.Workflow{
			WorkflowID:       "wf_blocked",
			WorkflowName:     "Blocked Workflow",
			Source:           workflow_control.WorkflowSourceLangChain,
			Status:           workflow_control.WorkflowStatusInProgress,
			CurrentStepIndex: 0,
			StartedAt:        now,
			CreatedAt:        now,
			UpdatedAt:        now,
			Steps: []workflow_control.WorkflowStep{
				{
					StepID:        "s1",
					StepIndex:     0,
					StepName:      "blocked_step",
					Decision:      workflow_control.GateDecisionBlock,
					GateCheckedAt: now,
				},
			},
		}

		result := workflowToExecutionStatus(workflow)

		if result.Steps[0].Status != execution.StepStatusBlocked {
			t.Errorf("Steps[0].Status = %s, want %s", result.Steps[0].Status, execution.StepStatusBlocked)
		}
	})

	t.Run("empty workflow", func(t *testing.T) {
		workflow := &workflow_control.Workflow{
			WorkflowID:   "wf_empty",
			WorkflowName: "Empty Workflow",
			Source:       workflow_control.WorkflowSourceExternal,
			Status:       workflow_control.WorkflowStatusInProgress,
			StartedAt:    now,
			CreatedAt:    now,
			UpdatedAt:    now,
			Steps:        []workflow_control.WorkflowStep{},
		}

		result := workflowToExecutionStatus(workflow)

		if len(result.Steps) != 0 {
			t.Errorf("Steps count = %d, want 0", len(result.Steps))
		}
		if result.ProgressPercent != 0 {
			t.Errorf("ProgressPercent = %f, want 0", result.ProgressPercent)
		}
	})
}

func TestNewWCPExecutionTracker(t *testing.T) {
	repo := NewMockMAPRepository() // Reuse the mock from MAP tests (same package)

	tracker := NewWCPExecutionTracker(repo, nil)

	if tracker == nil {
		t.Error("NewWCPExecutionTracker returned nil")
	}
	if tracker.BaseExecutionTracker == nil {
		t.Error("BaseExecutionTracker should not be nil")
	}
	if tracker.wcpService != nil {
		t.Error("wcpService should be nil when passed nil")
	}
}

func TestWCPExecutionTracker_StartWorkflowExecution(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	totalSteps := 3
	now := time.Now()

	workflow := &workflow_control.Workflow{
		WorkflowID:       "wf_test123",
		WorkflowName:     "Test Workflow",
		Source:           workflow_control.WorkflowSourceLangGraph,
		Status:           workflow_control.WorkflowStatusInProgress,
		CurrentStepIndex: 0,
		TotalSteps:       &totalSteps,
		TenantID:         "tenant_1",
		OrgID:            "org_1",
		UserID:           "user_1",
		ClientID:         "client_1",
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
		Steps:            []workflow_control.WorkflowStep{},
	}

	status, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution failed: %v", err)
	}

	if status == nil {
		t.Fatal("StartWorkflowExecution returned nil status")
	}
	if status.ExecutionType != execution.ExecutionTypeWCP {
		t.Errorf("ExecutionType = %s, want %s", status.ExecutionType, execution.ExecutionTypeWCP)
	}
	if status.Name != "Test Workflow" {
		t.Errorf("Name = %s, want Test Workflow", status.Name)
	}
	if status.TotalSteps != 3 {
		t.Errorf("TotalSteps = %d, want 3", status.TotalSteps)
	}
	// Note: StartExecution initializes with StatusPending, not StatusRunning
	// The status transitions to Running when a step starts
	if status.Status != execution.StatusPending {
		t.Errorf("Status = %s, want %s", status.Status, execution.StatusPending)
	}
	if status.Metadata["workflow_id"] != "wf_test123" {
		t.Errorf("Metadata[workflow_id] = %v, want wf_test123", status.Metadata["workflow_id"])
	}
}

func TestWCPExecutionTracker_SyncWorkflowStatus(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	// First, create a workflow execution
	totalSteps := 2
	now := time.Now()
	workflow := &workflow_control.Workflow{
		WorkflowID:       "wf_sync_test",
		WorkflowName:     "Sync Test",
		Source:           workflow_control.WorkflowSourceExternal,
		Status:           workflow_control.WorkflowStatusInProgress,
		TotalSteps:       &totalSteps,
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution failed: %v", err)
	}

	t.Run("sync completed status", func(t *testing.T) {
		err := tracker.SyncWorkflowStatus(ctx, "wf_sync_test", workflow_control.WorkflowStatusCompleted, "")
		if err != nil {
			t.Errorf("SyncWorkflowStatus failed: %v", err)
		}

		// Verify status was updated
		status, err := tracker.GetWorkflowStatus(ctx, "wf_sync_test")
		if err != nil {
			t.Errorf("GetWorkflowStatus failed: %v", err)
		}
		if status.Status != execution.StatusCompleted {
			t.Errorf("Status = %s, want %s", status.Status, execution.StatusCompleted)
		}
	})
}

func TestWCPExecutionTracker_GetWorkflowStatus_NotFound(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Try to get a workflow that doesn't exist (no WCP service configured)
	_, err := tracker.GetWorkflowStatus(ctx, "wf_nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent workflow")
	}
}

// --- Tests for On* delegator methods, syncStepCompleted, and SyncStepGate ---

// newTestWorkflow creates a simple in-progress workflow for test helpers.
func newTestWorkflow(id string) *workflow_control.Workflow {
	totalSteps := 3
	now := time.Now()
	return &workflow_control.Workflow{
		WorkflowID:       id,
		WorkflowName:     "Test Workflow " + id,
		Source:           workflow_control.WorkflowSourceLangGraph,
		Status:           workflow_control.WorkflowStatusInProgress,
		CurrentStepIndex: 0,
		TotalSteps:       &totalSteps,
		TenantID:         "tenant_1",
		OrgID:            "org_1",
		UserID:           "user_1",
		ClientID:         "client_1",
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
		Steps:            []workflow_control.WorkflowStep{},
	}
}

func TestOnWorkflowCreated(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	workflow := newTestWorkflow("wf_on_created")

	err := tracker.OnWorkflowCreated(ctx, workflow)
	if err != nil {
		t.Fatalf("OnWorkflowCreated() error = %v", err)
	}

	// Verify the execution was created by looking it up via GetWorkflowStatus
	status, err := tracker.GetWorkflowStatus(ctx, "wf_on_created")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}
	if status.ExecutionType != execution.ExecutionTypeWCP {
		t.Errorf("ExecutionType = %s, want %s", status.ExecutionType, execution.ExecutionTypeWCP)
	}
	if status.Name != "Test Workflow wf_on_created" {
		t.Errorf("Name = %s, want 'Test Workflow wf_on_created'", status.Name)
	}
	if status.TotalSteps != 3 {
		t.Errorf("TotalSteps = %d, want 3", status.TotalSteps)
	}
	if status.Metadata["workflow_id"] != "wf_on_created" {
		t.Errorf("Metadata[workflow_id] = %v, want wf_on_created", status.Metadata["workflow_id"])
	}
}

func TestOnWorkflowCompleted(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	// First create an execution
	workflow := newTestWorkflow("wf_on_completed")
	if err := tracker.OnWorkflowCreated(ctx, workflow); err != nil {
		t.Fatalf("OnWorkflowCreated() error = %v", err)
	}

	// Now call OnWorkflowCompleted
	err := tracker.OnWorkflowCompleted(ctx, "wf_on_completed")
	if err != nil {
		t.Fatalf("OnWorkflowCompleted() error = %v", err)
	}

	// Verify status is completed
	status, err := tracker.GetWorkflowStatus(ctx, "wf_on_completed")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}
	if status.Status != execution.StatusCompleted {
		t.Errorf("Status = %s, want %s", status.Status, execution.StatusCompleted)
	}
}

func TestOnWorkflowFailed(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Create an execution
	workflow := newTestWorkflow("wf_on_failed")
	if err := tracker.OnWorkflowCreated(ctx, workflow); err != nil {
		t.Fatalf("OnWorkflowCreated() error = %v", err)
	}

	// Call OnWorkflowFailed
	err := tracker.OnWorkflowFailed(ctx, "wf_on_failed", "step timeout")
	if err != nil {
		t.Fatalf("OnWorkflowFailed() error = %v", err)
	}

	// Verify status is failed
	status, err := tracker.GetWorkflowStatus(ctx, "wf_on_failed")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}
	if status.Status != execution.StatusFailed {
		t.Errorf("Status = %s, want %s", status.Status, execution.StatusFailed)
	}
	if status.Error != "step timeout" {
		t.Errorf("Error = %s, want 'step timeout'", status.Error)
	}
}

func TestOnWorkflowAborted(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Create an execution
	workflow := newTestWorkflow("wf_on_aborted")
	if err := tracker.OnWorkflowCreated(ctx, workflow); err != nil {
		t.Fatalf("OnWorkflowCreated() error = %v", err)
	}

	// Call OnWorkflowAborted
	err := tracker.OnWorkflowAborted(ctx, "wf_on_aborted", "user cancelled")
	if err != nil {
		t.Fatalf("OnWorkflowAborted() error = %v", err)
	}

	// Verify status is cancelled (CancelExecution maps Aborted -> Cancelled)
	status, err := tracker.GetWorkflowStatus(ctx, "wf_on_aborted")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}
	if status.Status != execution.StatusCancelled {
		t.Errorf("Status = %s, want %s", status.Status, execution.StatusCancelled)
	}
}

func TestOnWorkflowCompleted_NoExecution(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Call OnWorkflowCompleted for a workflow that has no unified execution
	// Should return nil (no error) since SyncWorkflowStatus returns nil for missing executions
	err := tracker.OnWorkflowCompleted(ctx, "wf_nonexistent")
	if err != nil {
		t.Errorf("OnWorkflowCompleted() for missing execution should not error, got: %v", err)
	}
}

func TestOnWorkflowFailed_NoExecution(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	err := tracker.OnWorkflowFailed(ctx, "wf_nonexistent", "some error")
	if err != nil {
		t.Errorf("OnWorkflowFailed() for missing execution should not error, got: %v", err)
	}
}

func TestOnWorkflowAborted_NoExecution(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	err := tracker.OnWorkflowAborted(ctx, "wf_nonexistent", "abort reason")
	if err != nil {
		t.Errorf("OnWorkflowAborted() for missing execution should not error, got: %v", err)
	}
}

func TestSyncStepCompleted(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	now := time.Now()

	// Create a workflow with one step
	totalSteps := 2
	workflow := &workflow_control.Workflow{
		WorkflowID:       "wf_step_completed",
		WorkflowName:     "Step Completed Test",
		Source:           workflow_control.WorkflowSourceLangGraph,
		Status:           workflow_control.WorkflowStatusInProgress,
		TotalSteps:       &totalSteps,
		StartedAt:        now,
		CreatedAt:        now,
		UpdatedAt:        now,
		Steps: []workflow_control.WorkflowStep{
			{
				StepID:        "step_1",
				StepIndex:     0,
				StepName:      "analyze",
				StepType:      workflow_control.StepTypeLLMCall,
				Decision:      workflow_control.GateDecisionAllow,
				GateCheckedAt: now,
				Model:         "gpt-4",
				Provider:      "openai",
			},
		},
	}

	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution() error = %v", err)
	}

	// Call syncStepCompleted (via OnStepCompleted) with nil metrics
	err = tracker.OnStepCompleted(ctx, "wf_step_completed", "step_1", nil)
	if err != nil {
		t.Fatalf("OnStepCompleted() error = %v", err)
	}

	// Verify the step is completed
	status, err := tracker.GetWorkflowStatus(ctx, "wf_step_completed")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}

	if len(status.Steps) == 0 {
		t.Fatal("Expected at least 1 step")
	}

	foundCompleted := false
	for _, step := range status.Steps {
		if step.StepID == "step_1" && step.Status == execution.StepStatusCompleted {
			foundCompleted = true
			break
		}
	}
	if !foundCompleted {
		t.Error("step_1 should have status completed")
	}
}

func TestSyncStepCompleted_NotFound(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Call syncStepCompleted for a workflow that has no unified execution
	err := tracker.syncStepCompleted(ctx, "wf_nonexistent", "step_1", nil)
	if err != nil {
		t.Errorf("syncStepCompleted() for missing execution should return nil, got: %v", err)
	}
}

func TestSyncStepGate(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	now := time.Now()

	// Create a workflow (no steps initially)
	workflow := newTestWorkflow("wf_step_gate")
	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution() error = %v", err)
	}

	// Call SyncStepGate to add a step
	step := &workflow_control.WorkflowStep{
		StepID:        "gate_step_1",
		StepIndex:     0,
		StepName:      "review_input",
		StepType:      workflow_control.StepTypeLLMCall,
		Decision:      workflow_control.GateDecisionAllow,
		GateCheckedAt: now,
		Model:         "gpt-4o",
		Provider:      "openai",
	}

	err = tracker.SyncStepGate(ctx, "wf_step_gate", step)
	if err != nil {
		t.Fatalf("SyncStepGate() error = %v", err)
	}

	// Verify the step was added
	status, err := tracker.GetWorkflowStatus(ctx, "wf_step_gate")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}

	if len(status.Steps) == 0 {
		t.Fatal("Expected at least 1 step after SyncStepGate")
	}

	found := false
	for _, s := range status.Steps {
		if s.StepID == "gate_step_1" {
			found = true
			if s.StepName != "review_input" {
				t.Errorf("Step name = %s, want review_input", s.StepName)
			}
			if s.StepType != execution.StepTypeLLMCall {
				t.Errorf("Step type = %s, want %s", s.StepType, execution.StepTypeLLMCall)
			}
			if s.Model != "gpt-4o" {
				t.Errorf("Step model = %s, want gpt-4o", s.Model)
			}
			if s.Provider != "openai" {
				t.Errorf("Step provider = %s, want openai", s.Provider)
			}
			break
		}
	}
	if !found {
		t.Error("gate_step_1 not found in execution steps")
	}
}

func TestSyncStepGate_NotFound(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	step := &workflow_control.WorkflowStep{
		StepID:        "gate_step_1",
		StepIndex:     0,
		StepName:      "review_input",
		StepType:      workflow_control.StepTypeLLMCall,
		Decision:      workflow_control.GateDecisionAllow,
		GateCheckedAt: time.Now(),
	}

	// Call SyncStepGate for a workflow that has no unified execution
	err := tracker.SyncStepGate(ctx, "wf_nonexistent", step)
	if err != nil {
		t.Errorf("SyncStepGate() for missing execution should return nil, got: %v", err)
	}
}

func TestOnStepGate(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	now := time.Now()

	// Create a workflow
	workflow := newTestWorkflow("wf_on_step_gate")
	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution() error = %v", err)
	}

	// Call OnStepGate (should delegate to SyncStepGate)
	step := &workflow_control.WorkflowStep{
		StepID:        "on_gate_step_1",
		StepIndex:     0,
		StepName:      "policy_check",
		StepType:      workflow_control.StepTypeToolCall,
		Decision:      workflow_control.GateDecisionBlock,
		GateCheckedAt: now,
	}

	err = tracker.OnStepGate(ctx, "wf_on_step_gate", step)
	if err != nil {
		t.Fatalf("OnStepGate() error = %v", err)
	}

	// Verify the step was added
	status, err := tracker.GetWorkflowStatus(ctx, "wf_on_step_gate")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}

	found := false
	for _, s := range status.Steps {
		if s.StepID == "on_gate_step_1" {
			found = true
			if s.StepType != execution.StepTypeToolCall {
				t.Errorf("Step type = %s, want %s", s.StepType, execution.StepTypeToolCall)
			}
			break
		}
	}
	if !found {
		t.Error("on_gate_step_1 not found in execution steps after OnStepGate")
	}
}

func TestSyncStepGate_WithBlockedDecision(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	now := time.Now()

	// Create a workflow
	workflow := newTestWorkflow("wf_blocked_gate")
	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution() error = %v", err)
	}

	// Add a step with block decision
	step := &workflow_control.WorkflowStep{
		StepID:        "blocked_step_1",
		StepIndex:     0,
		StepName:      "blocked_action",
		StepType:      workflow_control.StepTypeConnectorCall,
		Decision:      workflow_control.GateDecisionBlock,
		GateCheckedAt: now,
	}

	err = tracker.SyncStepGate(ctx, "wf_blocked_gate", step)
	if err != nil {
		t.Fatalf("SyncStepGate() error = %v", err)
	}

	// Verify step was added (note: AddStep sets status to pending regardless of input)
	status, err := tracker.GetWorkflowStatus(ctx, "wf_blocked_gate")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}

	found := false
	for _, s := range status.Steps {
		if s.StepID == "blocked_step_1" {
			found = true
			if s.StepType != execution.StepTypeConnectorCall {
				t.Errorf("Step type = %s, want %s", s.StepType, execution.StepTypeConnectorCall)
			}
			break
		}
	}
	if !found {
		t.Error("blocked_step_1 not found in execution steps")
	}
}

func TestSyncStepGate_WithApprovalRequired(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	now := time.Now()
	pendingApproval := workflow_control.ApprovalStatusPending

	// Create a workflow
	workflow := newTestWorkflow("wf_approval_gate")
	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution() error = %v", err)
	}

	// Add a step that requires approval
	step := &workflow_control.WorkflowStep{
		StepID:         "approval_step_1",
		StepIndex:      0,
		StepName:       "needs_approval",
		StepType:       workflow_control.StepTypeHumanTask,
		Decision:       workflow_control.GateDecisionRequireApproval,
		ApprovalStatus: &pendingApproval,
		GateCheckedAt:  now,
	}

	err = tracker.SyncStepGate(ctx, "wf_approval_gate", step)
	if err != nil {
		t.Fatalf("SyncStepGate() error = %v", err)
	}

	// Verify step was added
	status, err := tracker.GetWorkflowStatus(ctx, "wf_approval_gate")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}

	found := false
	for _, s := range status.Steps {
		if s.StepID == "approval_step_1" {
			found = true
			if s.StepType != execution.StepTypeHumanTask {
				t.Errorf("Step type = %s, want %s", s.StepType, execution.StepTypeHumanTask)
			}
			break
		}
	}
	if !found {
		t.Error("approval_step_1 not found in execution steps")
	}
}

func TestSyncStepGate_WithZeroGateCheckedAt(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Create a workflow
	workflow := newTestWorkflow("wf_zero_gate_time")
	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution() error = %v", err)
	}

	// Add a step with zero GateCheckedAt (StartedAt should not be set)
	step := &workflow_control.WorkflowStep{
		StepID:   "zero_time_step",
		StepName: "no_gate_time",
		StepType: workflow_control.StepTypeLLMCall,
		Decision: workflow_control.GateDecisionAllow,
		// GateCheckedAt is zero value
	}

	err = tracker.SyncStepGate(ctx, "wf_zero_gate_time", step)
	if err != nil {
		t.Fatalf("SyncStepGate() error = %v", err)
	}

	status, err := tracker.GetWorkflowStatus(ctx, "wf_zero_gate_time")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}

	for _, s := range status.Steps {
		if s.StepID == "zero_time_step" {
			if s.StartedAt != nil {
				t.Error("StartedAt should be nil when GateCheckedAt is zero")
			}
			return
		}
	}
	t.Error("zero_time_step not found in execution steps")
}

func TestOnStepCompleted_ThenOnWorkflowCompleted(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	now := time.Now()

	// Create a workflow with a step
	totalSteps := 1
	workflow := &workflow_control.Workflow{
		WorkflowID:   "wf_full_lifecycle",
		WorkflowName: "Full Lifecycle Test",
		Source:       workflow_control.WorkflowSourceCrewAI,
		Status:       workflow_control.WorkflowStatusInProgress,
		TotalSteps:   &totalSteps,
		StartedAt:    now,
		CreatedAt:    now,
		UpdatedAt:    now,
		Steps: []workflow_control.WorkflowStep{
			{
				StepID:        "lifecycle_step_1",
				StepIndex:     0,
				StepName:      "process",
				StepType:      workflow_control.StepTypeLLMCall,
				Decision:      workflow_control.GateDecisionAllow,
				GateCheckedAt: now,
			},
		},
	}

	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution() error = %v", err)
	}

	// Complete the step (nil metrics)
	err = tracker.OnStepCompleted(ctx, "wf_full_lifecycle", "lifecycle_step_1", nil)
	if err != nil {
		t.Fatalf("OnStepCompleted() error = %v", err)
	}

	// Complete the workflow
	err = tracker.OnWorkflowCompleted(ctx, "wf_full_lifecycle")
	if err != nil {
		t.Fatalf("OnWorkflowCompleted() error = %v", err)
	}

	// Verify final state
	status, err := tracker.GetWorkflowStatus(ctx, "wf_full_lifecycle")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}

	if status.Status != execution.StatusCompleted {
		t.Errorf("Status = %s, want %s", status.Status, execution.StatusCompleted)
	}

	// Verify step is completed
	for _, s := range status.Steps {
		if s.StepID == "lifecycle_step_1" {
			if s.Status != execution.StepStatusCompleted {
				t.Errorf("Step status = %s, want %s", s.Status, execution.StepStatusCompleted)
			}
			return
		}
	}
	t.Error("lifecycle_step_1 not found in execution steps")
}

func TestOnStepCompletedWithMetrics(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewWCPExecutionTracker(repo, nil)
	ctx := context.Background()

	now := time.Now()

	// Create a workflow with one step
	totalSteps := 1
	workflow := &workflow_control.Workflow{
		WorkflowID:   "wf_metrics_test",
		WorkflowName: "Metrics Test",
		Source:       workflow_control.WorkflowSourceLangGraph,
		Status:       workflow_control.WorkflowStatusInProgress,
		TotalSteps:   &totalSteps,
		StartedAt:    now,
		CreatedAt:    now,
		UpdatedAt:    now,
		Steps: []workflow_control.WorkflowStep{
			{
				StepID:        "step_m1",
				StepIndex:     0,
				StepName:      "generate",
				StepType:      workflow_control.StepTypeLLMCall,
				Decision:      workflow_control.GateDecisionAllow,
				GateCheckedAt: now,
				Model:         "gpt-4o",
				Provider:      "openai",
			},
		},
	}

	_, err := tracker.StartWorkflowExecution(ctx, workflow)
	if err != nil {
		t.Fatalf("StartWorkflowExecution() error = %v", err)
	}

	// Complete the step with post-execution metrics
	tokensIn := 200
	tokensOut := 75
	costUSD := 0.005
	metrics := &workflow_control.StepCompleteRequest{
		TokensIn:  &tokensIn,
		TokensOut: &tokensOut,
		CostUSD:   &costUSD,
		Output:    map[string]interface{}{"result": "success"},
	}

	err = tracker.OnStepCompleted(ctx, "wf_metrics_test", "step_m1", metrics)
	if err != nil {
		t.Fatalf("OnStepCompleted() error = %v", err)
	}

	// Verify the step is completed with metrics
	status, err := tracker.GetWorkflowStatus(ctx, "wf_metrics_test")
	if err != nil {
		t.Fatalf("GetWorkflowStatus() error = %v", err)
	}

	found := false
	for _, s := range status.Steps {
		if s.StepID == "step_m1" {
			found = true
			if s.Status != execution.StepStatusCompleted {
				t.Errorf("Step status = %s, want %s", s.Status, execution.StepStatusCompleted)
			}
			if s.TokensIn == nil || *s.TokensIn != 200 {
				t.Errorf("TokensIn = %v, want 200", s.TokensIn)
			}
			if s.TokensOut == nil || *s.TokensOut != 75 {
				t.Errorf("TokensOut = %v, want 75", s.TokensOut)
			}
			if s.CostUSD == nil || *s.CostUSD != 0.005 {
				t.Errorf("CostUSD = %v, want 0.005", s.CostUSD)
			}
			break
		}
	}
	if !found {
		t.Error("step_m1 not found in execution steps")
	}
}

func TestIsWCPNotFoundError(t *testing.T) {
	t.Run("workflow not found error returns true", func(t *testing.T) {
		err := workflow_control.ErrWorkflowNotFound
		if !isWCPNotFoundError(err) {
			t.Error("expected isWCPNotFoundError to return true for ErrWorkflowNotFound")
		}
	})

	t.Run("generic error returns false", func(t *testing.T) {
		err := context.DeadlineExceeded
		if isWCPNotFoundError(err) {
			t.Error("expected isWCPNotFoundError to return false for generic error")
		}
	})

	t.Run("nil error returns false", func(t *testing.T) {
		if isWCPNotFoundError(nil) {
			t.Error("expected isWCPNotFoundError to return false for nil error")
		}
	})
}
