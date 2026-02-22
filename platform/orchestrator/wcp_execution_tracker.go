// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/execution"
)

// isWCPNotFoundError returns true if err represents a workflow-not-found condition.
func isWCPNotFoundError(err error) bool {
	return workflow_control.IsNotFoundError(err)
}

// WCPExecutionTracker adapts WCP workflow operations to the unified ExecutionTracker interface.
// This enables consistent status tracking across MAP plans and WCP workflows.
type WCPExecutionTracker struct {
	*execution.BaseExecutionTracker
	wcpService    *workflow_control.Service
	costEstimator PlanCostEstimator
}

// NewWCPExecutionTracker creates a new WCP-specific execution tracker.
func NewWCPExecutionTracker(repo execution.ExecutionRepository, wcpService *workflow_control.Service) *WCPExecutionTracker {
	return &WCPExecutionTracker{
		BaseExecutionTracker: execution.NewBaseExecutionTracker(repo),
		wcpService:           wcpService,
	}
}

// SetCostEstimator sets the pricing config for per-step cost estimation.
func (t *WCPExecutionTracker) SetCostEstimator(ce PlanCostEstimator) {
	t.costEstimator = ce
}

// StartWorkflowExecution creates a unified execution record from a WCP workflow.
// This is called when a workflow is created via the WCP API.
func (t *WCPExecutionTracker) StartWorkflowExecution(ctx context.Context, workflow *workflow_control.Workflow) (*execution.ExecutionStatus, error) {
	// Create steps from workflow steps if available
	steps := make([]execution.StepStatus, len(workflow.Steps))
	for i, step := range workflow.Steps {
		steps[i] = execution.StepStatus{
			StepID:          step.StepID,
			StepIndex:       step.StepIndex,
			StepName:        step.StepName,
			StepType:        mapWCPStepType(step.StepType),
			Status:          mapWCPStepDecisionToStatus(step.Decision, step.ApprovalStatus),
			Decision:        mapWCPGateDecision(step.Decision),
			DecisionReason:  step.DecisionReason,
			PoliciesMatched: extractPolicyNames(step.PoliciesMatched),
			ApprovalStatus:  mapWCPApprovalStatus(step.ApprovalStatus),
			ApprovedBy:      step.ApprovedBy,
			Model:           step.Model,
			Provider:        step.Provider,
			TokensIn:        step.TokensIn,
			TokensOut:       step.TokensOut,
			CostUSD:         step.CostUSD,
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
	// Look up execution by workflow_id metadata (indexed lookup)
	exec, err := t.findExecutionByWorkflowID(ctx, workflowID)
	if err == nil {
		return t.GetStatus(ctx, exec.ExecutionID)
	}
	if !errors.Is(err, execution.ErrExecutionNotFound) {
		return nil, err
	}

	// If no unified execution found, fall back to WCP service and create a status response
	if t.wcpService == nil {
		return nil, fmt.Errorf("workflow %s: %w", workflowID, execution.ErrExecutionNotFound)
	}

	workflow, err := t.wcpService.GetWorkflow(ctx, workflowID)
	if err != nil {
		if isWCPNotFoundError(err) {
			return nil, fmt.Errorf("workflow %s: %w", workflowID, execution.ErrExecutionNotFound)
		}
		return nil, fmt.Errorf("workflow %s lookup failed: %w", workflowID, err)
	}

	// Convert workflow to ExecutionStatus for backward compatibility
	return workflowToExecutionStatus(workflow), nil
}

// SyncWorkflowStatus updates the unified execution tracker based on workflow status changes.
// This is called when workflow status changes through the WCP service.
func (t *WCPExecutionTracker) SyncWorkflowStatus(ctx context.Context, workflowID string, workflowStatus workflow_control.WorkflowStatus, errorMsg string) error {
	exec, err := t.findExecutionByWorkflowID(ctx, workflowID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			// No unified execution exists for this workflow - fine for legacy workflows
			return nil
		}
		return err
	}

	executionID := exec.ExecutionID

	// Update status based on workflow status
	switch workflowStatus {
	case workflow_control.WorkflowStatusCompleted:
		// Before completing execution, finalize any steps still in "running" state.
		// CompleteExecution only sets the overall status — it doesn't touch step records.
		status, getErr := t.GetStatus(ctx, executionID)
		if getErr == nil && len(status.Steps) > 0 {
			now := time.Now()
			changed := false
			for i := range status.Steps {
				if status.Steps[i].Status == execution.StepStatusRunning {
					status.Steps[i].Status = execution.StepStatusCompleted
					status.Steps[i].EndedAt = &now
					status.Steps[i].Duration = status.Steps[i].CalculateDuration()
					changed = true
				}
			}
			if changed {
				_ = t.GetRepo().UpdateSteps(ctx, executionID, status.Steps)
			}
		}
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
func (t *WCPExecutionTracker) OnStepCompleted(ctx context.Context, workflowID string, stepID string, metrics *workflow_control.StepCompleteRequest) error {
	return t.syncStepCompleted(ctx, workflowID, stepID, metrics)
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
func (t *WCPExecutionTracker) syncStepCompleted(ctx context.Context, workflowID string, stepID string, metrics *workflow_control.StepCompleteRequest) error {
	exec, err := t.findExecutionByWorkflowID(ctx, workflowID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			return nil
		}
		return err
	}

	// Build result map from metrics for the base tracker
	var result map[string]interface{}
	if metrics != nil {
		result = make(map[string]interface{})
		if metrics.TokensIn != nil {
			result["tokens_in"] = *metrics.TokensIn
		}
		if metrics.TokensOut != nil {
			result["tokens_out"] = *metrics.TokensOut
		}
		if metrics.CostUSD != nil {
			result["cost_usd"] = *metrics.CostUSD
		}
		if metrics.Output != nil {
			result["output"] = metrics.Output
		}
	}

	return t.CompleteStep(ctx, exec.ExecutionID, stepID, result)
}

// SyncStepGate updates the unified execution tracker when a step gate is checked.
func (t *WCPExecutionTracker) SyncStepGate(ctx context.Context, workflowID string, step *workflow_control.WorkflowStep) error {
	exec, err := t.findExecutionByWorkflowID(ctx, workflowID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			return nil
		}
		return err
	}

	executionID := exec.ExecutionID

	// Add the step to the execution
	stepStatus := execution.StepStatus{
		StepID:          step.StepID,
		StepIndex:       step.StepIndex,
		StepName:        step.StepName,
		StepType:        mapWCPStepType(step.StepType),
		Status:          mapWCPStepDecisionToStatus(step.Decision, step.ApprovalStatus),
		Decision:        mapWCPGateDecision(step.Decision),
		DecisionReason:  step.DecisionReason,
		PoliciesMatched: extractPolicyNames(step.PoliciesMatched),
		ApprovalStatus:  mapWCPApprovalStatus(step.ApprovalStatus),
		ApprovedBy:      step.ApprovedBy,
		Model:           step.Model,
		Provider:        step.Provider,
		TokensIn:        step.TokensIn,
		TokensOut:       step.TokensOut,
		CostUSD:         step.CostUSD,
	}

	// Estimate cost from tokens + pricing config when cost is not provided by the client
	if stepStatus.CostUSD == nil && t.costEstimator != nil && step.Provider != "" && step.Model != "" {
		tokensIn, tokensOut := 0, 0
		if step.TokensIn != nil {
			tokensIn = *step.TokensIn
		}
		if step.TokensOut != nil {
			tokensOut = *step.TokensOut
		}
		if tokensIn > 0 || tokensOut > 0 {
			cost := t.costEstimator.EstimateCost(step.Provider, step.Model, tokensIn, tokensOut)
			if cost > 0 {
				stepStatus.CostUSD = &cost
			}
		}
	}

	if !step.GateCheckedAt.IsZero() {
		t := step.GateCheckedAt
		stepStatus.StartedAt = &t
	}

	return t.AddStep(ctx, executionID, stepStatus)
}

// findExecutionByWorkflowID looks up a unified execution record by workflow_id metadata.
// Returns ErrExecutionNotFound if no execution exists for this workflow.
func (t *WCPExecutionTracker) findExecutionByWorkflowID(ctx context.Context, workflowID string) (*execution.ExecutionStatus, error) {
	return t.GetRepo().GetByMetadata(ctx, "workflow_id", workflowID)
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

// extractPolicyNames extracts policy name strings from WCP's json.RawMessage policies_matched.
// WCP stores policies as []PolicyMatch objects; the unified schema uses []string.
func extractPolicyNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var policies []workflow_control.PolicyMatch
	if err := json.Unmarshal(raw, &policies); err != nil {
		return nil
	}
	names := make([]string, 0, len(policies))
	for _, p := range policies {
		name := p.PolicyName
		if name == "" {
			name = p.PolicyID
		}
		if name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// mapWCPGateDecision converts a WCP gate decision string to the unified GateDecision type.
func mapWCPGateDecision(d workflow_control.GateDecision) execution.GateDecision {
	switch d {
	case workflow_control.GateDecisionAllow:
		return execution.GateDecisionAllow
	case workflow_control.GateDecisionBlock:
		return execution.GateDecisionBlock
	case workflow_control.GateDecisionRequireApproval:
		return execution.GateDecisionRequireApproval
	default:
		return ""
	}
}

// mapWCPApprovalStatus converts a WCP approval status to the unified ApprovalStatus type.
func mapWCPApprovalStatus(s *workflow_control.ApprovalStatus) *execution.ApprovalStatus {
	if s == nil {
		return nil
	}
	var mapped execution.ApprovalStatus
	switch *s {
	case workflow_control.ApprovalStatusPending:
		mapped = execution.ApprovalStatusPending
	case workflow_control.ApprovalStatusApproved:
		mapped = execution.ApprovalStatusApproved
	case workflow_control.ApprovalStatusRejected:
		mapped = execution.ApprovalStatusRejected
	default:
		return nil
	}
	return &mapped
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
			StepID:          step.StepID,
			StepIndex:       step.StepIndex,
			StepName:        step.StepName,
			StepType:        mapWCPStepType(step.StepType),
			Status:          stepStatus,
			Decision:        mapWCPGateDecision(step.Decision),
			DecisionReason:  step.DecisionReason,
			PoliciesMatched: extractPolicyNames(step.PoliciesMatched),
			ApprovalStatus:  mapWCPApprovalStatus(step.ApprovalStatus),
			ApprovedBy:      step.ApprovedBy,
			Model:           step.Model,
			Provider:        step.Provider,
			TokensIn:        step.TokensIn,
			TokensOut:       step.TokensOut,
			CostUSD:         step.CostUSD,
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
