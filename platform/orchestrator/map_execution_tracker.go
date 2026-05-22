// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
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
	// Direct lookup by plan_id metadata using indexed query (Bug C fix)
	exec, err := t.BaseExecutionTracker.GetRepo().GetByPlanID(ctx, planID)
	if err == nil {
		return t.GetStatus(ctx, exec.ExecutionID)
	}
	if !errors.Is(err, execution.ErrExecutionNotFound) {
		return nil, fmt.Errorf("plan %s lookup failed: %w", planID, err)
	}

	// If no unified execution found, fall back to plan service and create a status response
	if t.planService == nil {
		return nil, fmt.Errorf("plan %s: %w", planID, execution.ErrExecutionNotFound)
	}

	plan, err := t.planService.GetPlan(ctx, planID)
	if err != nil {
		if errors.Is(err, planning.ErrPlanNotFound) {
			return nil, fmt.Errorf("plan %s: %w", planID, execution.ErrExecutionNotFound)
		}
		return nil, fmt.Errorf("plan %s lookup failed: %w", planID, err)
	}

	// Convert plan to ExecutionStatus for backward compatibility
	return planToExecutionStatus(plan), nil
}

// SyncPlanStatus updates the unified execution tracker based on plan status changes.
// This is called when plan status changes through the planning service.
func (t *MAPExecutionTracker) SyncPlanStatus(ctx context.Context, planID string, planStatus planning.PlanStatus, errorMsg string) error {
	// Direct lookup by plan_id metadata using indexed query (Bug C fix)
	exec, err := t.BaseExecutionTracker.GetRepo().GetByPlanID(ctx, planID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			// No unified execution exists for this plan - this is fine for legacy plans
			return nil
		}
		return fmt.Errorf("sync plan %s: %w", planID, err)
	}

	executionID := exec.ExecutionID

	// Update status based on plan status
	switch planStatus {
	case planning.PlanStatusCompleted:
		return t.CompleteExecution(ctx, executionID, nil)
	case planning.PlanStatusFailed:
		return t.FailExecution(ctx, executionID, fmt.Errorf("%s", errorMsg))
	case planning.PlanStatusExpired:
		// Bug D fix: expired plans get "expired" status, not "completed".
		// v9 Phase 8 #2384 PR-C1: ExpireExecution now requires orgID + tenantID
		// for RLS scoping (mig 042 execution_history). exec was fetched above.
		return t.BaseExecutionTracker.GetRepo().ExpireExecution(ctx, exec.OrgID, exec.TenantID, executionID, nil)
	case planning.PlanStatusCancelled:
		reason := errorMsg
		if reason == "" {
			reason = "plan cancelled"
		}
		return t.CancelExecution(ctx, executionID, reason)
	}

	return nil
}

// SyncStepResults updates step-level data (status, provider, model, tokens, cost) from
// workflow execution results. This bridges the gap where MAP executions track overall
// plan status but never record per-step details to the unified execution tracker.
func (t *MAPExecutionTracker) SyncStepResults(ctx context.Context, planID string, steps []StepExecution, costEstimator PlanCostEstimator) error {
	if len(steps) == 0 {
		return nil
	}

	// Look up unified execution by plan ID
	exec, err := t.BaseExecutionTracker.GetRepo().GetByPlanID(ctx, planID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			// No unified execution exists — legacy plan, skip silently
			return nil
		}
		return fmt.Errorf("sync step results for plan %s: %w", planID, err)
	}

	// Get current execution state with steps
	status, err := t.GetStatus(ctx, exec.ExecutionID)
	if err != nil {
		return fmt.Errorf("get execution status for plan %s: %w", planID, err)
	}

	// Build step name -> index map for stable matching
	stepIndexByName := make(map[string]int, len(status.Steps))
	for i := range status.Steps {
		if status.Steps[i].StepName != "" {
			stepIndexByName[status.Steps[i].StepName] = i
		}
	}

	// Update each step from the workflow execution results
	var totalCostUSD float64
	for i, stepExec := range steps {
		stepIndex := -1
		if stepExec.Name != "" {
			if idx, ok := stepIndexByName[stepExec.Name]; ok {
				stepIndex = idx
			}
		}
		if stepIndex == -1 {
			if i >= len(status.Steps) {
				break
			}
			stepIndex = i
		}

		// Map step status
		switch stepExec.Status {
		case "completed":
			status.Steps[stepIndex].Status = execution.StepStatusCompleted
		case "failed":
			status.Steps[stepIndex].Status = execution.StepStatusFailed
		case "skipped":
			status.Steps[stepIndex].Status = execution.StepStatusSkipped
		case "running":
			status.Steps[stepIndex].Status = execution.StepStatusRunning
		}

		// Set timing
		if !stepExec.StartTime.IsZero() {
			status.Steps[stepIndex].StartedAt = &stepExec.StartTime
		}
		if stepExec.EndTime != nil {
			status.Steps[stepIndex].EndedAt = stepExec.EndTime
			if !stepExec.StartTime.IsZero() {
				duration := stepExec.EndTime.Sub(stepExec.StartTime)
				status.Steps[stepIndex].Duration = duration.String()
			}
		}

		// Set error
		if stepExec.Error != "" {
			status.Steps[stepIndex].Error = stepExec.Error
		}

		// Extract provider, model, tokens from output (same pattern as workflow_engine.go recordStepSnapshot)
		if stepExec.Output != nil {
			if p, ok := stepExec.Output["provider"].(string); ok {
				status.Steps[stepIndex].Provider = p
			}
			if m, ok := stepExec.Output["model"].(string); ok {
				status.Steps[stepIndex].Model = m
			}

			var tokensIn, tokensOut int
			switch tok := stepExec.Output["tokens_used"].(type) {
			case int:
				tokensIn = tok / 2
				tokensOut = tok - tokensIn
			case float64:
				total := int(tok)
				tokensIn = total / 2
				tokensOut = total - tokensIn
			case json.Number:
				if total, err := tok.Int64(); err == nil {
					tokensIn = int(total) / 2
					tokensOut = int(total) - tokensIn
				}
			}

			if tokensIn+tokensOut > 0 {
				status.Steps[stepIndex].TokensIn = &tokensIn
				status.Steps[stepIndex].TokensOut = &tokensOut

				// Calculate per-step cost
				if costEstimator != nil {
					costUSD := costEstimator.EstimateCost(
						status.Steps[stepIndex].Provider, status.Steps[stepIndex].Model,
						tokensIn, tokensOut,
					)
					status.Steps[stepIndex].CostUSD = &costUSD
					totalCostUSD += costUSD
				}
			}
		}
	}

	// Update steps in a single DB call.
	// v9 Phase 8 #2384 PR-C1: orgID + tenantID required for RLS scoping (mig 042).
	if err := t.BaseExecutionTracker.GetRepo().UpdateSteps(ctx, exec.OrgID, exec.TenantID, exec.ExecutionID, status.Steps); err != nil {
		return fmt.Errorf("update steps for plan %s: %w", planID, err)
	}

	// Update actual cost if we calculated any
	if totalCostUSD > 0 {
		_ = t.BaseExecutionTracker.GetRepo().UpdateCost(ctx, exec.OrgID, exec.TenantID, exec.ExecutionID, nil, &totalCostUSD)
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
