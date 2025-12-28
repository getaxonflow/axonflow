// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// HITL-Aware Workflow Execution
// Enables pause/resume for require_approval policy action

package orchestrator

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// HITL execution status constants
const (
	// StatusPaused indicates execution is waiting for human approval.
	StatusPaused = "paused"
	// StatusApproved indicates human approval was granted.
	StatusApproved = "approved"
	// StatusRejected indicates human rejection.
	StatusRejected = "rejected"
	// StatusExpired indicates approval request expired.
	StatusExpired = "expired"
)

// HITLWorkflowExecution extends WorkflowExecution with HITL support.
type HITLWorkflowExecution struct {
	*WorkflowExecution

	// ApprovalID is the UUID of the pending HITL approval request.
	ApprovalID uuid.UUID `json:"approval_id,omitempty"`

	// ApprovalStatus is the current status of the approval.
	ApprovalStatus string `json:"approval_status,omitempty"`

	// PausedAtStep is the index of the step where execution was paused.
	PausedAtStep int `json:"paused_at_step,omitempty"`

	// PausedReason explains why execution was paused.
	PausedReason string `json:"paused_reason,omitempty"`

	// ResumedAt is when execution was resumed after approval.
	ResumedAt *time.Time `json:"resumed_at,omitempty"`
}

// HITLStepExecution extends StepExecution with HITL support.
type HITLStepExecution struct {
	StepExecution

	// RequiredApproval indicates this step triggered require_approval.
	RequiredApproval bool `json:"required_approval,omitempty"`

	// ApprovalID is the UUID of the approval request for this step.
	ApprovalID uuid.UUID `json:"approval_id,omitempty"`
}

// PolicyCheckResult represents the result of a pre-step policy check.
type PolicyCheckResult struct {
	Allowed    bool
	Action     string // block, require_approval, warn, log
	PolicyID   string
	PolicyName string
	Reason     string
	Severity   string
}

// HITLPolicyChecker is the interface for checking policies before step execution.
type HITLPolicyChecker interface {
	CheckPolicy(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) (*PolicyCheckResult, error)
}

// HITLApprovalService is the interface for creating and managing HITL approvals.
type HITLApprovalService interface {
	CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error)
	GetApproval(ctx context.Context, approvalID uuid.UUID) (*HITLApprovalResponse, error)
}

// HITLApprovalRequest contains data for creating an HITL approval.
type HITLApprovalRequest struct {
	OrgID          string
	TenantID       string
	ClientID       string
	UserID         string
	ExecutionID    string
	StepName       string
	StepType       string
	PolicyID       string
	PolicyName     string
	TriggerReason  string
	Severity       string
	RequestContext map[string]interface{}
}

// HITLApprovalResponse contains the approval details.
type HITLApprovalResponse struct {
	ApprovalID uuid.UUID
	Status     string // pending, approved, rejected, expired
	ReviewerID string
	Comment    string
	CreatedAt  time.Time
	ReviewedAt *time.Time
	ExpiresAt  time.Time
}

// HITLWorkflowEngine wraps WorkflowEngine with HITL support.
type HITLWorkflowEngine struct {
	engine          *WorkflowEngine
	policyChecker   HITLPolicyChecker
	approvalService HITLApprovalService
}

// NewHITLWorkflowEngine creates a new HITL-aware workflow engine.
func NewHITLWorkflowEngine(engine *WorkflowEngine, checker HITLPolicyChecker, approval HITLApprovalService) *HITLWorkflowEngine {
	return &HITLWorkflowEngine{
		engine:          engine,
		policyChecker:   checker,
		approvalService: approval,
	}
}

// ExecuteWithHITL executes a workflow with HITL pause/resume support.
func (e *HITLWorkflowEngine) ExecuteWithHITL(ctx context.Context, workflow Workflow, input map[string]interface{}, user UserContext) (*HITLWorkflowExecution, error) {
	baseExec, err := e.createExecution(workflow, input, user)
	if err != nil {
		return nil, err
	}

	hitlExec := &HITLWorkflowExecution{
		WorkflowExecution: baseExec,
	}

	for i, step := range workflow.Spec.Steps {
		if e.policyChecker != nil {
			policyResult, err := e.policyChecker.CheckPolicy(ctx, step, baseExec)
			if err != nil {
				// DESIGN DECISION: Fail-open for availability.
				// Policy check errors should not block workflow execution.
				// This prioritizes availability over strict enforcement.
				// For fail-closed behavior, configure the policy checker to return
				// a blocking PolicyCheckResult on error instead of returning an error.
				log.Printf("[HITL] WARNING: Policy check error for step %s: %v - proceeding with execution (fail-open)", step.Name, err)
			} else if policyResult != nil {
				switch policyResult.Action {
				case "block":
					hitlExec.Status = "failed"
					hitlExec.Error = fmt.Sprintf("Blocked by policy %s: %s", policyResult.PolicyName, policyResult.Reason)
					return hitlExec, fmt.Errorf("execution blocked by policy: %s", policyResult.PolicyName)

				case "require_approval":
					return e.pauseForApproval(ctx, hitlExec, i, step, policyResult, user)

				case "warn":
					log.Printf("[HITL] Warning for step %s: Policy %s triggered - %s",
						step.Name, policyResult.PolicyName, policyResult.Reason)

				case "log":
					log.Printf("[HITL] Audit: Step %s triggered policy %s",
						step.Name, policyResult.PolicyName)
				}
			}
		}

		stepExec, err := e.executeStep(ctx, step, input, hitlExec)
		if err != nil {
			hitlExec.Status = "failed"
			hitlExec.Error = err.Error()
			return hitlExec, err
		}

		if stepExec.Output != nil {
			for key, value := range stepExec.Output {
				input[fmt.Sprintf("step_%s_%s", step.Name, key)] = value
			}
		}
	}

	hitlExec.Status = "completed"
	now := time.Now()
	hitlExec.EndTime = &now

	return hitlExec, nil
}

// pauseForApproval pauses execution and creates an HITL approval request.
func (e *HITLWorkflowEngine) pauseForApproval(
	ctx context.Context,
	exec *HITLWorkflowExecution,
	stepIndex int,
	step WorkflowStep,
	policyResult *PolicyCheckResult,
	user UserContext,
) (*HITLWorkflowExecution, error) {
	exec.Status = StatusPaused
	exec.PausedAtStep = stepIndex
	exec.PausedReason = fmt.Sprintf("Policy %s requires human approval: %s",
		policyResult.PolicyName, policyResult.Reason)

	if e.approvalService != nil {
		req := &HITLApprovalRequest{
			TenantID:      user.TenantID,
			UserID:        fmt.Sprintf("%d", user.ID),
			ExecutionID:   exec.ID,
			StepName:      step.Name,
			StepType:      step.Type,
			PolicyID:      policyResult.PolicyID,
			PolicyName:    policyResult.PolicyName,
			TriggerReason: policyResult.Reason,
			Severity:      policyResult.Severity,
		}

		resp, err := e.approvalService.CreateApproval(ctx, req)
		if err != nil {
			log.Printf("[HITL] Failed to create approval request: %v", err)
			exec.Error = fmt.Sprintf("Failed to create approval: %v", err)
			return exec, err
		}

		exec.ApprovalID = resp.ApprovalID
		exec.ApprovalStatus = resp.Status
	}

	log.Printf("[HITL] Execution %s paused at step %d (%s) - awaiting approval %s",
		exec.ID, stepIndex, step.Name, exec.ApprovalID)

	return exec, nil
}

// ResumeExecution resumes a paused execution after approval.
func (e *HITLWorkflowEngine) ResumeExecution(ctx context.Context, exec *HITLWorkflowExecution, workflow Workflow, input map[string]interface{}) (*HITLWorkflowExecution, error) {
	if exec.Status != StatusPaused {
		return nil, fmt.Errorf("execution is not paused, status: %s", exec.Status)
	}

	if e.approvalService != nil && exec.ApprovalID != uuid.Nil {
		approval, err := e.approvalService.GetApproval(ctx, exec.ApprovalID)
		if err != nil {
			return nil, fmt.Errorf("failed to get approval status: %w", err)
		}

		if approval.Status != "approved" && approval.Status != "overridden" {
			return nil, fmt.Errorf("cannot resume: approval status is %s", approval.Status)
		}

		exec.ApprovalStatus = approval.Status
	}

	now := time.Now()
	exec.ResumedAt = &now
	exec.Status = "running"

	log.Printf("[HITL] Resuming execution %s from step %d", exec.ID, exec.PausedAtStep)

	for i := exec.PausedAtStep; i < len(workflow.Spec.Steps); i++ {
		step := workflow.Spec.Steps[i]

		stepExec, err := e.executeStep(ctx, step, input, exec)
		if err != nil {
			exec.Status = "failed"
			exec.Error = err.Error()
			return exec, err
		}

		if stepExec.Output != nil {
			for key, value := range stepExec.Output {
				input[fmt.Sprintf("step_%s_%s", step.Name, key)] = value
			}
		}
	}

	exec.Status = "completed"
	endTime := time.Now()
	exec.EndTime = &endTime

	return exec, nil
}

// AbortExecution aborts a paused execution after rejection.
func (e *HITLWorkflowEngine) AbortExecution(ctx context.Context, exec *HITLWorkflowExecution, reason string) (*HITLWorkflowExecution, error) {
	if exec.Status != StatusPaused {
		return nil, fmt.Errorf("execution is not paused, status: %s", exec.Status)
	}

	exec.Status = "aborted"
	now := time.Now()
	exec.EndTime = &now
	exec.Error = fmt.Sprintf("Execution aborted: %s", reason)

	if e.approvalService != nil && exec.ApprovalID != uuid.Nil {
		approval, _ := e.approvalService.GetApproval(ctx, exec.ApprovalID)
		if approval != nil {
			exec.ApprovalStatus = approval.Status
		}
	}

	log.Printf("[HITL] Execution %s aborted: %s", exec.ID, reason)

	return exec, nil
}

// createExecution creates a new workflow execution.
func (e *HITLWorkflowEngine) createExecution(workflow Workflow, input map[string]interface{}, user UserContext) (*WorkflowExecution, error) {
	return &WorkflowExecution{
		ID:           fmt.Sprintf("wf_%d_%s", time.Now().Unix(), generateRandomString(8)),
		WorkflowName: workflow.Metadata.Name,
		Status:       "running",
		Input:        input,
		Output:       make(map[string]interface{}),
		Steps:        make([]StepExecution, 0),
		StartTime:    time.Now(),
		UserContext:  user,
	}, nil
}

// executeStep executes a single workflow step.
func (e *HITLWorkflowEngine) executeStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, exec *HITLWorkflowExecution) (*StepExecution, error) {
	stepExec := StepExecution{
		Name:      step.Name,
		Status:    "running",
		StartTime: time.Now(),
		Input:     input,
	}

	exec.Steps = append(exec.Steps, stepExec)

	processor, exists := e.engine.stepProcessors[step.Type]
	if !exists {
		stepExec.Status = "failed"
		stepExec.Error = fmt.Sprintf("unknown step type: %s", step.Type)
		exec.Steps[len(exec.Steps)-1] = stepExec
		return &stepExec, fmt.Errorf("unknown step type: %s", step.Type)
	}

	output, err := processor.ExecuteStep(ctx, step, input, exec.WorkflowExecution)
	now := time.Now()
	stepExec.EndTime = &now
	stepExec.ProcessTime = now.Sub(stepExec.StartTime).String()

	if err != nil {
		stepExec.Status = "failed"
		stepExec.Error = err.Error()
		exec.Steps[len(exec.Steps)-1] = stepExec
		return &stepExec, err
	}

	stepExec.Status = "completed"
	stepExec.Output = output
	exec.Steps[len(exec.Steps)-1] = stepExec

	log.Printf("[HITL] Completed step: %s in %s", step.Name, stepExec.ProcessTime)

	return &stepExec, nil
}

// GetExecutionStatus returns the current status of an execution including HITL state.
// TODO(hitl): Implement execution status lookup from storage.
// This requires an ExecutionStorage interface to persist and retrieve HITL executions.
// Current implementation returns "unknown" as a placeholder.
// Implementation should:
// 1. Look up execution by ID from storage
// 2. Return current status, approval ID, and paused step info
// 3. Return ErrExecutionNotFound if execution doesn't exist
func (e *HITLWorkflowEngine) GetExecutionStatus(ctx context.Context, executionID string) (*HITLExecutionStatus, error) {
	// Placeholder implementation - requires ExecutionStorage integration
	return &HITLExecutionStatus{
		ExecutionID: executionID,
		Status:      "unknown",
	}, nil
}

// HITLExecutionStatus represents the current status of an HITL execution.
type HITLExecutionStatus struct {
	ExecutionID    string    `json:"execution_id"`
	Status         string    `json:"status"`
	ApprovalID     uuid.UUID `json:"approval_id,omitempty"`
	ApprovalStatus string    `json:"approval_status,omitempty"`
	PausedAtStep   int       `json:"paused_at_step,omitempty"`
	PausedReason   string    `json:"paused_reason,omitempty"`
}
