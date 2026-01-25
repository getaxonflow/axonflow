// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"

	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/execution"
)

// WCPExecutionTracker adapts WCP workflow operations to the unified ExecutionTracker interface.
// This enables consistent status tracking across MAP plans and WCP workflows.
type WCPExecutionTracker struct {
	*execution.BaseExecutionTracker
	wcpService *workflow_control.Service
}

// NewWCPExecutionTracker creates a new WCP-specific execution tracker.
func NewWCPExecutionTracker(repo execution.ExecutionRepository, wcpService *workflow_control.Service) *WCPExecutionTracker {
	return &WCPExecutionTracker{
		BaseExecutionTracker: execution.NewBaseExecutionTracker(repo),
		wcpService:           wcpService,
	}
}

// StartWorkflowExecution creates a unified execution record from a WCP workflow.
// This is called when a workflow is created via the WCP API.
func (t *WCPExecutionTracker) StartWorkflowExecution(ctx context.Context, workflow *workflow_control.Workflow) (*execution.ExecutionStatus, error) {
	// Create steps from workflow steps if available
	steps := make([]execution.StepStatus, len(workflow.Steps))
	for i, step := range workflow.Steps {
		steps[i] = execution.StepStatus{
			StepID:    step.StepID,
			StepIndex: step.StepIndex,
			StepName:  step.StepName,
			StepType:  mapWCPStepType(step.StepType),
			Status:    mapWCPStepDecisionToStatus(step.Decision, step.ApprovalStatus),
			Model:     step.Model,
			Provider:  step.Provider,
		}
		if !step.GateCheckedAt.IsZero() {
			t := step.GateCheckedAt
			steps[i].StartedAt = &t
		}
		if step.StepCompletedAt != nil {
			steps[i].EndedAt = step.StepCompletedAt
		}
	}

	totalSteps := 0
	if workflow.TotalSteps != nil {
		totalSteps = *workflow.TotalSteps
	}

	req := execution.CreateExecutionRequest{
		ExecutionType: execution.ExecutionTypeWCP,
		Name:          workflow.WorkflowName,
		Source:        string(workflow.Source),
		TotalSteps:    totalSteps,
		TenantID:      workflow.TenantID,
		OrgID:         workflow.OrgID,
		UserID:        workflow.UserID,
		ClientID:      workflow.ClientID,
		Metadata: map[string]interface{}{
			"workflow_id": workflow.WorkflowID,
			"source":      workflow.Source,
		},
	}

	// Start tracking
	exec, err := t.StartExecution(ctx, req)
	if err != nil {
		return nil, err
	}

	// Add any existing steps
	for _, step := range steps {
		if err := t.AddStep(ctx, exec.ExecutionID, step); err != nil {
			return nil, fmt.Errorf("failed to add step %s: %w", step.StepID, err)
		}
	}

	return t.GetStatus(ctx, exec.ExecutionID)
}

// GetWorkflowStatus retrieves the unified execution status for a WCP workflow.
// It combines workflow metadata with step-level execution details.
func (t *WCPExecutionTracker) GetWorkflowStatus(ctx context.Context, workflowID string) (*execution.ExecutionStatus, error) {
	// First, try to find execution by workflow_id in metadata
	req := execution.ListExecutionsRequest{
		ExecutionType: ptrExecutionType(execution.ExecutionTypeWCP),
		Limit:         100, // Search through recent executions
	}
	resp, err := t.ListExecutions(ctx, req)
	if err != nil {
		return nil, err
	}

	// Search for execution with matching workflow_id
	for _, exec := range resp.Executions {
		if metadata, ok := exec.Metadata["workflow_id"].(string); ok && metadata == workflowID {
			return t.GetStatus(ctx, exec.ExecutionID)
		}
	}

	// If no unified execution found, fall back to WCP service and create a status response
	if t.wcpService == nil {
		return nil, fmt.Errorf("workflow not found: %s (no WCP service available)", workflowID)
	}

	workflow, err := t.wcpService.GetWorkflow(ctx, workflowID)
	if err != nil {
		return nil, fmt.Errorf("workflow not found: %w", err)
	}

	// Convert workflow to ExecutionStatus for backward compatibility
	return workflowToExecutionStatus(workflow), nil
}

// SyncWorkflowStatus updates the unified execution tracker based on workflow status changes.
// This is called when workflow status changes through the WCP service.
func (t *WCPExecutionTracker) SyncWorkflowStatus(ctx context.Context, workflowID string, workflowStatus workflow_control.WorkflowStatus, errorMsg string) error {
	// Find the execution for this workflow
	req := execution.ListExecutionsRequest{
		ExecutionType: ptrExecutionType(execution.ExecutionTypeWCP),
		Limit:         100,
	}
	resp, err := t.ListExecutions(ctx, req)
	if err != nil {
		return err
	}

	var executionID string
	for _, exec := range resp.Executions {
		if metadata, ok := exec.Metadata["workflow_id"].(string); ok && metadata == workflowID {
			executionID = exec.ExecutionID
			break
		}
	}

	if executionID == "" {
		// No unified execution exists for this workflow - this is fine for legacy workflows
		return nil
	}

	// Update status based on workflow status
	switch workflowStatus {
	case workflow_control.WorkflowStatusCompleted:
		return t.CompleteExecution(ctx, executionID, nil)
	case workflow_control.WorkflowStatusFailed:
		return t.FailExecution(ctx, executionID, fmt.Errorf("%s", errorMsg))
	case workflow_control.WorkflowStatusAborted:
		return t.CancelExecution(ctx, executionID, "workflow aborted")
	}

	return nil
}

// --- WorkflowExecutionTracker Interface Implementation ---
// These methods implement workflow_control.WorkflowExecutionTracker interface

// OnWorkflowCreated implements WorkflowExecutionTracker.OnWorkflowCreated
func (t *WCPExecutionTracker) OnWorkflowCreated(ctx context.Context, workflow *workflow_control.Workflow) error {
	_, err := t.StartWorkflowExecution(ctx, workflow)
	return err
}

// OnStepGate implements WorkflowExecutionTracker.OnStepGate
func (t *WCPExecutionTracker) OnStepGate(ctx context.Context, workflowID string, step *workflow_control.WorkflowStep) error {
	return t.SyncStepGate(ctx, workflowID, step)
}

// OnStepCompleted implements WorkflowExecutionTracker.OnStepCompleted
func (t *WCPExecutionTracker) OnStepCompleted(ctx context.Context, workflowID string, stepID string) error {
	return t.syncStepCompleted(ctx, workflowID, stepID)
}

// OnWorkflowCompleted implements WorkflowExecutionTracker.OnWorkflowCompleted
func (t *WCPExecutionTracker) OnWorkflowCompleted(ctx context.Context, workflowID string) error {
	return t.SyncWorkflowStatus(ctx, workflowID, workflow_control.WorkflowStatusCompleted, "")
}

// OnWorkflowFailed implements WorkflowExecutionTracker.OnWorkflowFailed
func (t *WCPExecutionTracker) OnWorkflowFailed(ctx context.Context, workflowID string, reason string) error {
	return t.SyncWorkflowStatus(ctx, workflowID, workflow_control.WorkflowStatusFailed, reason)
}

// OnWorkflowAborted implements WorkflowExecutionTracker.OnWorkflowAborted
func (t *WCPExecutionTracker) OnWorkflowAborted(ctx context.Context, workflowID string, reason string) error {
	return t.SyncWorkflowStatus(ctx, workflowID, workflow_control.WorkflowStatusAborted, reason)
}

// syncStepCompleted updates the step status when a step is marked completed.
func (t *WCPExecutionTracker) syncStepCompleted(ctx context.Context, workflowID string, stepID string) error {
	// Find the execution for this workflow
	req := execution.ListExecutionsRequest{
		ExecutionType: ptrExecutionType(execution.ExecutionTypeWCP),
		Limit:         100,
	}
	resp, err := t.ListExecutions(ctx, req)
	if err != nil {
		return err
	}

	var executionID string
	for _, exec := range resp.Executions {
		if metadata, ok := exec.Metadata["workflow_id"].(string); ok && metadata == workflowID {
			executionID = exec.ExecutionID
			break
		}
	}

	if executionID == "" {
		// No unified execution exists
		return nil
	}

	// Complete the step
	return t.CompleteStep(ctx, executionID, stepID, nil)
}

// SyncStepGate updates the unified execution tracker when a step gate is checked.
func (t *WCPExecutionTracker) SyncStepGate(ctx context.Context, workflowID string, step *workflow_control.WorkflowStep) error {
	// Find the execution for this workflow
	req := execution.ListExecutionsRequest{
		ExecutionType: ptrExecutionType(execution.ExecutionTypeWCP),
		Limit:         100,
	}
	resp, err := t.ListExecutions(ctx, req)
	if err != nil {
		return err
	}

	var executionID string
	for _, exec := range resp.Executions {
		if metadata, ok := exec.Metadata["workflow_id"].(string); ok && metadata == workflowID {
			executionID = exec.ExecutionID
			break
		}
	}

	if executionID == "" {
		// No unified execution exists
		return nil
	}

	// Add the step to the execution
	stepStatus := execution.StepStatus{
		StepID:    step.StepID,
		StepIndex: step.StepIndex,
		StepName:  step.StepName,
		StepType:  mapWCPStepType(step.StepType),
		Status:    mapWCPStepDecisionToStatus(step.Decision, step.ApprovalStatus),
		Model:     step.Model,
		Provider:  step.Provider,
	}
	if !step.GateCheckedAt.IsZero() {
		t := step.GateCheckedAt
		stepStatus.StartedAt = &t
	}

	return t.AddStep(ctx, executionID, stepStatus)
}

// --- Helper Functions ---

// mapWCPStepType converts WCP step types to unified step types.
func mapWCPStepType(stepType workflow_control.StepType) execution.StepType {
	switch stepType {
	case workflow_control.StepTypeLLMCall:
		return execution.StepTypeLLMCall
	case workflow_control.StepTypeToolCall:
		return execution.StepTypeToolCall
	case workflow_control.StepTypeConnectorCall:
		return execution.StepTypeConnectorCall
	case workflow_control.StepTypeHumanTask:
		return execution.StepTypeHumanTask
	default:
		return execution.StepTypeAction
	}
}

// mapWCPStepDecisionToStatus converts WCP gate decisions to step status.
func mapWCPStepDecisionToStatus(decision workflow_control.GateDecision, approvalStatus *workflow_control.ApprovalStatus) execution.StepStatusValue {
	switch decision {
	case workflow_control.GateDecisionAllow:
		return execution.StepStatusRunning
	case workflow_control.GateDecisionBlock:
		return execution.StepStatusBlocked
	case workflow_control.GateDecisionRequireApproval:
		if approvalStatus != nil {
			switch *approvalStatus {
			case workflow_control.ApprovalStatusApproved:
				return execution.StepStatusRunning
			case workflow_control.ApprovalStatusRejected:
				return execution.StepStatusFailed
			default:
				return execution.StepStatusApproval
			}
		}
		return execution.StepStatusApproval
	default:
		return execution.StepStatusPending
	}
}

// mapWCPStatus converts WCP workflow status to unified execution status.
func mapWCPStatus(status workflow_control.WorkflowStatus) execution.ExecutionStatusValue {
	switch status {
	case workflow_control.WorkflowStatusInProgress:
		return execution.StatusRunning
	case workflow_control.WorkflowStatusCompleted:
		return execution.StatusCompleted
	case workflow_control.WorkflowStatusFailed:
		return execution.StatusFailed
	case workflow_control.WorkflowStatusAborted:
		return execution.StatusAborted
	default:
		return execution.StatusPending
	}
}

// workflowToExecutionStatus converts a WCP Workflow to ExecutionStatus for backward compatibility.
func workflowToExecutionStatus(workflow *workflow_control.Workflow) *execution.ExecutionStatus {
	status := mapWCPStatus(workflow.Status)

	// Calculate progress
	completedSteps := 0
	for _, step := range workflow.Steps {
		if step.StepCompletedAt != nil {
			completedSteps++
		}
	}

	totalSteps := len(workflow.Steps)
	if workflow.TotalSteps != nil && *workflow.TotalSteps > totalSteps {
		totalSteps = *workflow.TotalSteps
	}

	var progressPercent float64
	if totalSteps > 0 {
		progressPercent = float64(completedSteps) / float64(totalSteps) * 100
	}

	// Convert workflow steps to execution steps
	steps := make([]execution.StepStatus, len(workflow.Steps))
	for i, step := range workflow.Steps {
		stepStatus := mapWCPStepDecisionToStatus(step.Decision, step.ApprovalStatus)
		if step.StepCompletedAt != nil {
			stepStatus = execution.StepStatusCompleted
		}

		steps[i] = execution.StepStatus{
			StepID:    step.StepID,
			StepIndex: step.StepIndex,
			StepName:  step.StepName,
			StepType:  mapWCPStepType(step.StepType),
			Status:    stepStatus,
			Model:     step.Model,
			Provider:  step.Provider,
		}
		if !step.GateCheckedAt.IsZero() {
			t := step.GateCheckedAt
			steps[i].StartedAt = &t
		}
		if step.StepCompletedAt != nil {
			steps[i].EndedAt = step.StepCompletedAt
		}
	}

	exec := &execution.ExecutionStatus{
		ExecutionID:      workflow.WorkflowID, // Use workflow ID as execution ID for backward compat
		ExecutionType:    execution.ExecutionTypeWCP,
		Name:             workflow.WorkflowName,
		Source:           string(workflow.Source),
		Status:           status,
		CurrentStepIndex: workflow.CurrentStepIndex,
		TotalSteps:       totalSteps,
		ProgressPercent:  progressPercent,
		StartedAt:        workflow.StartedAt,
		CompletedAt:      workflow.CompletedAt,
		Steps:            steps,
		TenantID:         workflow.TenantID,
		OrgID:            workflow.OrgID,
		UserID:           workflow.UserID,
		ClientID:         workflow.ClientID,
		Metadata: map[string]interface{}{
			"workflow_id": workflow.WorkflowID,
			"source":      workflow.Source,
		},
		CreatedAt: workflow.CreatedAt,
		UpdatedAt: workflow.UpdatedAt,
	}

	exec.Duration = exec.CalculateDuration()

	return exec
}
