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
