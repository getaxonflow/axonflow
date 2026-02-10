// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/shared/execution"
)

// MAPExecutionTracker adapts MAP planning operations to the unified ExecutionTracker interface.
// This enables consistent status tracking across MAP plans and WCP workflows.
type MAPExecutionTracker struct {
	*execution.BaseExecutionTracker
	planService *planning.Service
}

// NewMAPExecutionTracker creates a new MAP-specific execution tracker.
func NewMAPExecutionTracker(repo execution.ExecutionRepository, planService *planning.Service) *MAPExecutionTracker {
	return &MAPExecutionTracker{
		BaseExecutionTracker: execution.NewBaseExecutionTracker(repo),
		planService:          planService,
	}
}

// StartPlanExecution creates a unified execution record from a plan.
// This is called when a plan is about to be executed.
func (t *MAPExecutionTracker) StartPlanExecution(ctx context.Context, plan *planning.Plan) (*execution.ExecutionStatus, error) {
	// Parse workflow definition to extract step information
	var workflow Workflow
	if err := json.Unmarshal(plan.WorkflowDefinition, &workflow); err != nil {
		return nil, fmt.Errorf("failed to parse workflow definition: %w", err)
	}

	// Create steps from workflow definition
	steps := make([]execution.StepStatus, len(workflow.Spec.Steps))
	for i, step := range workflow.Spec.Steps {
		steps[i] = execution.StepStatus{
			StepID:    fmt.Sprintf("step_%d_%s", i, step.Name),
			StepIndex: i,
			StepName:  step.Name,
			StepType:  mapStepType(step.Type),
			Status:    execution.StepStatusPending,
			Model:     step.Model,
			Provider:  step.Provider,
		}
	}

	req := execution.CreateExecutionRequest{
		ExecutionType: execution.ExecutionTypeMAP,
		Name:          plan.Query,
		Source:        plan.Domain,
		TotalSteps:    plan.StepCount,
		TenantID:      plan.TenantID,
		OrgID:         plan.OrgID,
		UserID:        plan.UserID,
		ClientID:      plan.ClientID,
		Metadata: map[string]interface{}{
			"plan_id":            plan.PlanID,
			"complexity":         plan.Complexity,
			"parallel":           plan.Parallel,
			"estimated_duration": plan.EstimatedDuration,
			"execution_mode":     plan.ExecutionMode,
			"expires_at":         plan.ExpiresAt,
		},
	}

	// Start tracking
	exec, err := t.StartExecution(ctx, req)
	if err != nil {
		return nil, err
	}

	// Add the steps
	for _, step := range steps {
		if err := t.AddStep(ctx, exec.ExecutionID, step); err != nil {
			return nil, fmt.Errorf("failed to add step %s: %w", step.StepID, err)
		}
	}

	return t.GetStatus(ctx, exec.ExecutionID)
}

// GetPlanStatus retrieves the unified execution status for a plan.
// It combines plan metadata with step-level execution details.
func (t *MAPExecutionTracker) GetPlanStatus(ctx context.Context, planID string) (*execution.ExecutionStatus, error) {
	// First, try to find execution by plan_id in metadata
	req := execution.ListExecutionsRequest{
		ExecutionType: ptrExecutionType(execution.ExecutionTypeMAP),
		Limit:         100, // Search through recent executions
	}
	resp, err := t.ListExecutions(ctx, req)
	if err != nil {
		return nil, err
	}

	// Search for execution with matching plan_id
	for _, exec := range resp.Executions {
		if metadata, ok := exec.Metadata["plan_id"].(string); ok && metadata == planID {
			return t.GetStatus(ctx, exec.ExecutionID)
		}
	}

	// If no unified execution found, fall back to plan service and create a status response
	if t.planService == nil {
		return nil, fmt.Errorf("plan not found: %s (no plan service available)", planID)
	}

	plan, err := t.planService.GetPlan(ctx, planID)
	if err != nil {
		return nil, fmt.Errorf("plan not found: %w", err)
	}

	// Convert plan to ExecutionStatus for backward compatibility
	return planToExecutionStatus(plan), nil
}

// SyncPlanStatus updates the unified execution tracker based on plan status changes.
// This is called when plan status changes through the planning service.
func (t *MAPExecutionTracker) SyncPlanStatus(ctx context.Context, planID string, planStatus planning.PlanStatus, errorMsg string) error {
	// Find the execution for this plan
	req := execution.ListExecutionsRequest{
		ExecutionType: ptrExecutionType(execution.ExecutionTypeMAP),
		Limit:         100,
	}
	resp, err := t.ListExecutions(ctx, req)
	if err != nil {
		return err
	}

	var executionID string
	for _, exec := range resp.Executions {
		if metadata, ok := exec.Metadata["plan_id"].(string); ok && metadata == planID {
			executionID = exec.ExecutionID
			break
		}
	}

	if executionID == "" {
		// No unified execution exists for this plan - this is fine for legacy plans
		return nil
	}

	// Update status based on plan status
	switch planStatus {
	case planning.PlanStatusCompleted:
		return t.CompleteExecution(ctx, executionID, nil)
	case planning.PlanStatusFailed:
		return t.FailExecution(ctx, executionID, fmt.Errorf("%s", errorMsg))
	case planning.PlanStatusExpired:
		// Note: We use CompleteExecution but the status is determined by the repo
		// This could be enhanced to support StatusExpired directly
		return t.CompleteExecution(ctx, executionID, nil)
	case planning.PlanStatusCancelled:
		reason := errorMsg
		if reason == "" {
			reason = "plan cancelled"
		}
		return t.CancelExecution(ctx, executionID, reason)
	}

	return nil
}

// --- Helper Functions ---

// mapStepType converts workflow step types to unified step types.
func mapStepType(stepType string) execution.StepType {
	switch stepType {
	case "llm-call":
		return execution.StepTypeLLMCall
	case "tool-call", "function":
		return execution.StepTypeToolCall
	case "connector-call":
		return execution.StepTypeConnectorCall
	case "human-task", "human":
		return execution.StepTypeHumanTask
	case "synthesis":
		return execution.StepTypeSynthesis
	default:
		return execution.StepTypeAction
	}
}

// planToExecutionStatus converts a Plan to ExecutionStatus for backward compatibility.
func planToExecutionStatus(plan *planning.Plan) *execution.ExecutionStatus {
	status := mapPlanStatus(plan.Status)

	// Calculate progress
	completedSteps := 0
	if plan.Status == planning.PlanStatusCompleted {
		completedSteps = plan.StepCount
	}

	var progressPercent float64
	if plan.StepCount > 0 {
		progressPercent = float64(completedSteps) / float64(plan.StepCount) * 100
	}

	// Parse workflow steps if available
	var steps []execution.StepStatus
	if len(plan.WorkflowDefinition) > 0 {
		var workflow Workflow
		if err := json.Unmarshal(plan.WorkflowDefinition, &workflow); err == nil {
			steps = make([]execution.StepStatus, len(workflow.Spec.Steps))
			for i, step := range workflow.Spec.Steps {
				stepStatus := execution.StepStatusPending
				if i < completedSteps {
					stepStatus = execution.StepStatusCompleted
				}

				steps[i] = execution.StepStatus{
					StepID:    fmt.Sprintf("step_%d_%s", i, step.Name),
					StepIndex: i,
					StepName:  step.Name,
					StepType:  mapStepType(step.Type),
					Status:    stepStatus,
					Model:     step.Model,
					Provider:  step.Provider,
				}
			}
		}
	}

	var completedAt *time.Time
	if status == execution.StatusCompleted || status == execution.StatusFailed || status == execution.StatusExpired || status == execution.StatusCancelled {
		t := plan.UpdatedAt
		completedAt = &t
	}

	metadata := map[string]interface{}{
		"plan_id":            plan.PlanID,
		"complexity":         plan.Complexity,
		"parallel":           plan.Parallel,
		"estimated_duration": plan.EstimatedDuration,
		"execution_mode":     plan.ExecutionMode,
		"expires_at":         plan.ExpiresAt,
		"version":            plan.Version,
	}

	// Preserve execution_result and workflow_definition for legacy path enrichment
	if len(plan.ExecutionResult) > 0 {
		metadata["execution_result"] = plan.ExecutionResult
	}
	if len(plan.WorkflowDefinition) > 0 {
		metadata["workflow_definition"] = plan.WorkflowDefinition
	}

	exec := &execution.ExecutionStatus{
		ExecutionID:      plan.PlanID, // Use plan ID as execution ID for backward compat
		ExecutionType:    execution.ExecutionTypeMAP,
		Name:             plan.Query,
		Source:           plan.Domain,
		Status:           status,
		CurrentStepIndex: completedSteps,
		TotalSteps:       plan.StepCount,
		ProgressPercent:  progressPercent,
		StartedAt:        plan.CreatedAt,
		CompletedAt:      completedAt,
		Steps:            steps,
		Error:            plan.ErrorMessage,
		TenantID:         plan.TenantID,
		OrgID:            plan.OrgID,
		UserID:           plan.UserID,
		ClientID:         plan.ClientID,
		Metadata:         metadata,
		CreatedAt:        plan.CreatedAt,
		UpdatedAt:        plan.UpdatedAt,
	}

	exec.Duration = exec.CalculateDuration()

	return exec
}

// mapPlanStatus converts planning status to unified execution status.
func mapPlanStatus(status planning.PlanStatus) execution.ExecutionStatusValue {
	switch status {
	case planning.PlanStatusPending:
		return execution.StatusPending
	case planning.PlanStatusExecuting:
		return execution.StatusRunning
	case planning.PlanStatusCompleted:
		return execution.StatusCompleted
	case planning.PlanStatusFailed:
		return execution.StatusFailed
	case planning.PlanStatusExpired:
		return execution.StatusExpired
	case planning.PlanStatusCancelled:
		return execution.StatusCancelled
	default:
		return execution.StatusPending
	}
}

// ptrExecutionType returns a pointer to the execution type.
func ptrExecutionType(t execution.ExecutionType) *execution.ExecutionType {
	return &t
}
