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
	for i := range workflow.Steps {
		step := workflow.Steps[i]
		approvedBy, approvedAt, rejectedBy, rejectedAt := projectApproverIdentity(&step)
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
			ApprovedBy:      approvedBy,
			ApprovedAt:      approvedAt,
			RejectedBy:      rejectedBy,
			RejectedAt:      rejectedAt,
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
		status, gerr := t.GetStatus(ctx, exec.ExecutionID)
		if gerr != nil {
			return nil, gerr
		}
		// Reconcile cached step snapshots against the current workflow_steps
		// state on every read. The cache was written at /gate time
		// (approval_status=pending) and pre-v7.4.1 approve/reject paths did
		// not re-sync it. Without this merge, historical workflows
		// approved/rejected before the fix deployed would forever show
		// "Approval: pending" on the portal timeline. Best-effort — a WCP
		// fetch failure falls back to the cached snapshot.
		if t.wcpService != nil && len(status.Steps) > 0 {
			// #3065: named unscoped read — this reconciliation holds no
			// request scope, and the result is authorized by the HTTP layer
			// (UnifiedExecutionHandler.checkTenantOwnership) before it reaches
			// a client. The old GetWorkflow(ctx, id, "", "") relied on an
			// empty-string bypass that is now a denial.
			if wf, werr := t.wcpService.GetWorkflowUnscoped(ctx, workflowID); werr == nil && wf != nil {
				reconcileStepApprovals(status.Steps, wf.Steps)
			}
		}
		return status, nil
	}
	if !errors.Is(err, execution.ErrExecutionNotFound) {
		return nil, err
	}

	// If no unified execution found, fall back to WCP service and create a status response
	if t.wcpService == nil {
		return nil, fmt.Errorf("workflow %s: %w", workflowID, execution.ErrExecutionNotFound)
	}

	// Tenant/org scoping is enforced at the handler layer via
	// checkTenantOwnership after resolveExecution returns. #3065: the raw
	// fetch now goes through the explicitly named unscoped accessor rather
	// than an empty-string bypass of the scoped one.
	workflow, err := t.wcpService.GetWorkflowUnscoped(ctx, workflowID)
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
				// v9 Phase 8 #2384 PR-C1: scope-wrap UpdateSteps via the already-fetched status.
				_ = t.GetRepo().UpdateSteps(ctx, status.OrgID, status.TenantID, executionID, status.Steps)
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

// OnStepApproval implements WorkflowExecutionTracker.OnStepApproval. Updates
// the step in place rather than appending — the gate already appended a
// snapshot with approval_status=pending; approve/reject needs to overwrite
// that, not create a second entry.
func (t *WCPExecutionTracker) OnStepApproval(ctx context.Context, workflowID string, step *workflow_control.WorkflowStep) error {
	return t.SyncStepApproval(ctx, workflowID, step)
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
// SyncStepApproval updates the approval status + approver identity on the
// unified execution record in place (does not append a new step). Called
// from workflow_control.Service.ApproveStep / RejectStep so
// `/api/v1/unified/executions/{id}` reflects the post-terminal state
// instead of the stale "pending" snapshot AddStep recorded when /gate
// first fired. Without this the portal timeline keeps showing "Approval:
// pending" even after the approver clicks Approve.
func (t *WCPExecutionTracker) SyncStepApproval(ctx context.Context, workflowID string, step *workflow_control.WorkflowStep) error {
	exec, err := t.findExecutionByWorkflowID(ctx, workflowID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			return nil
		}
		return err
	}
	fresh, err := t.GetStatus(ctx, exec.ExecutionID)
	if err != nil {
		return err
	}

	approvedBy, approvedAt, rejectedBy, rejectedAt := projectApproverIdentity(step)
	newStatus := mapWCPStepDecisionToStatus(step.Decision, step.ApprovalStatus)

	found := false
	for i := range fresh.Steps {
		if fresh.Steps[i].StepID != step.StepID {
			continue
		}
		fresh.Steps[i].ApprovalStatus = mapWCPApprovalStatus(step.ApprovalStatus)
		fresh.Steps[i].ApprovedBy = approvedBy
		fresh.Steps[i].ApprovedAt = approvedAt
		fresh.Steps[i].RejectedBy = rejectedBy
		fresh.Steps[i].RejectedAt = rejectedAt
		fresh.Steps[i].Status = newStatus
		found = true
		break
	}
	if !found {
		// Step not present yet (edge case — approval without a prior gate
		// sync). Fall back to AddStep so the portal still sees something.
		return t.SyncStepGate(ctx, workflowID, step)
	}

	fresh.UpdatedAt = time.Now()
	// v9 Phase 8 #2384 PR-C1: pass orgID + tenantID for RLS scoping (mig 042).
	return t.GetRepo().UpdateSteps(ctx, fresh.OrgID, fresh.TenantID, exec.ExecutionID, fresh.Steps)
}

func (t *WCPExecutionTracker) SyncStepGate(ctx context.Context, workflowID string, step *workflow_control.WorkflowStep) error {
	exec, err := t.findExecutionByWorkflowID(ctx, workflowID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			return nil
		}
		return err
	}

	executionID := exec.ExecutionID

	approvedBy, approvedAt, rejectedBy, rejectedAt := projectApproverIdentity(step)
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
		ApprovedBy:      approvedBy,
		ApprovedAt:      approvedAt,
		RejectedBy:      rejectedBy,
		RejectedAt:      rejectedAt,
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
			case workflow_control.ApprovalStatusRejected,
				workflow_control.ApprovalStatusExpired:
				// Both are terminal "not approved" outcomes (the workflow is
				// aborted). Expired (auto-timeout) must NOT fall through to
				// StepStatusApproval, which would wrongly show a timed-out step
				// as still awaiting approval (#2654).
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

// projectApproverIdentity splits the shared workflow_steps.approved_by /
// approved_at column into the unified (ApprovedBy, ApprovedAt, RejectedBy,
// RejectedAt) tuple based on terminal approval status. Mirrors
// workflow_control.ProjectStepGateToHTTP so the portal execution timeline
// and the WCP HTTP response agree on which field carries the reviewer
// identity. Returns zero values when approval status is nil or pending.
// reconcileStepApprovals merges fresh workflow_steps approval state into a
// cached unified-execution step slice. Updates approval_status,
// approved_by/approved_at, rejected_by/rejected_at, and step status in place.
// Called on every /api/v1/unified/executions read so historical workflows
// approved/rejected before v7.4.1 shipped reflect their terminal state —
// without this, cached pending snapshots never update. Matches on step_id;
// steps present in the cache but absent from the fresh rows are left
// untouched (protects against partial WCP state).
func reconcileStepApprovals(cached []execution.StepStatus, fresh []workflow_control.WorkflowStep) {
	if len(cached) == 0 || len(fresh) == 0 {
		return
	}
	freshByID := make(map[string]*workflow_control.WorkflowStep, len(fresh))
	for i := range fresh {
		freshByID[fresh[i].StepID] = &fresh[i]
	}
	for i := range cached {
		fs, ok := freshByID[cached[i].StepID]
		if !ok || fs == nil {
			continue
		}
		approvedBy, approvedAt, rejectedBy, rejectedAt := projectApproverIdentity(fs)
		cached[i].ApprovalStatus = mapWCPApprovalStatus(fs.ApprovalStatus)
		cached[i].ApprovedBy = approvedBy
		cached[i].ApprovedAt = approvedAt
		cached[i].RejectedBy = rejectedBy
		cached[i].RejectedAt = rejectedAt
		// Preserve StepStatusCompleted when a step has already finished so
		// the cached completion timestamps don't get clobbered.
		if cached[i].Status != execution.StepStatusCompleted {
			cached[i].Status = mapWCPStepDecisionToStatus(fs.Decision, fs.ApprovalStatus)
		}
	}
}

func projectApproverIdentity(step *workflow_control.WorkflowStep) (approvedBy string, approvedAt *time.Time, rejectedBy string, rejectedAt *time.Time) {
	if step == nil || step.ApprovalStatus == nil {
		return
	}
	switch *step.ApprovalStatus {
	case workflow_control.ApprovalStatusApproved:
		approvedBy = step.ApprovedBy
		approvedAt = step.ApprovedAt
	case workflow_control.ApprovalStatusRejected:
		rejectedBy = step.ApprovedBy
		rejectedAt = step.ApprovedAt
		// ApprovalStatusExpired intentionally has no case: an auto-timeout has no
		// human actor, so neither approved_* nor rejected_* identity is populated —
		// the expiry must never be attributed to a human reviewer (#2654).
	}
	return
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
	case workflow_control.ApprovalStatusExpired:
		// #2654: surface the auto-timeout distinctly in the unified status
		// surface rather than collapsing it to nil (which would hide the
		// expired-vs-rejected distinction at the step approval_status level).
		mapped = execution.ApprovalStatusExpired
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
	for i := range workflow.Steps {
		step := workflow.Steps[i]
		stepStatus := mapWCPStepDecisionToStatus(step.Decision, step.ApprovalStatus)
		if step.StepCompletedAt != nil {
			stepStatus = execution.StepStatusCompleted
		}
		approvedBy, approvedAt, rejectedBy, rejectedAt := projectApproverIdentity(&step)

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
			ApprovedBy:      approvedBy,
			ApprovedAt:      approvedAt,
			RejectedBy:      rejectedBy,
			RejectedAt:      rejectedAt,
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
