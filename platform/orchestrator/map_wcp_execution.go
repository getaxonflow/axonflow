// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"log"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
)

// MAPWCPExecutor handles MAP plan execution in confirm/step mode using WCP infrastructure.
type MAPWCPExecutor struct {
	wcpService  *workflow_control.Service
	planService *planning.Service
}

// NewMAPWCPExecutor creates a new executor for WCP-backed MAP execution.
func NewMAPWCPExecutor(wcpService *workflow_control.Service, planService *planning.Service) *MAPWCPExecutor {
	return &MAPWCPExecutor{
		wcpService:  wcpService,
		planService: planService,
	}
}

// intPtr is a helper to create a pointer to an int
func intPtr(n int) *int {
	return &n
}

// mapStepTypeToWCP converts workflow step types to WCP step types
func mapStepTypeToWCP(stepType string) workflow_control.StepType {
	switch stepType {
	case "llm-call":
		return workflow_control.StepTypeLLMCall
	case "connector-call":
		return workflow_control.StepTypeConnectorCall
	default:
		return workflow_control.StepTypeToolCall
	}
}

// ExecuteWithConfirm executes a MAP plan in confirm mode.
// Each step creates a WCP workflow with require_approval gate.
// The client must approve each step before it executes.
// Returns immediately with status "awaiting_approval".
func (e *MAPWCPExecutor) ExecuteWithConfirm(ctx context.Context, plan *planning.Plan, workflow *Workflow, tenantID, orgID, userID, clientID string) (*MAPWCPExecutionResult, error) {
	if e.wcpService == nil {
		return nil, fmt.Errorf("WCP service not available")
	}

	if len(workflow.Spec.Steps) == 0 {
		return nil, fmt.Errorf("workflow has no steps")
	}

	log.Printf("[MAP-WCP] Starting confirm mode execution for plan %s (%d steps)", plan.PlanID, len(workflow.Spec.Steps))

	totalSteps := len(workflow.Spec.Steps)

	// Create a WCP workflow to track the MAP plan
	wcpWorkflow, err := e.wcpService.CreateWorkflow(ctx, &workflow_control.CreateWorkflowRequest{
		WorkflowName: fmt.Sprintf("map-confirm-%s", plan.PlanID),
		TotalSteps:   intPtr(totalSteps),
		Source:       "map",
		Metadata: map[string]interface{}{
			"plan_id":        plan.PlanID,
			"execution_mode": "confirm",
			"domain":         plan.Domain,
			"query":          plan.Query,
		},
	}, tenantID, orgID, userID, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to create WCP workflow for confirm mode: %w", err)
	}

	// Gate the first step with require_approval (confirm mode = every step needs approval)
	firstStep := workflow.Spec.Steps[0]
	requireApproval := workflow_control.GateDecisionRequireApproval
	gateResp, err := e.wcpService.StepGate(ctx, wcpWorkflow.WorkflowID, fmt.Sprintf("step_0_%s", firstStep.Name), &workflow_control.StepGateRequest{
		StepName:     firstStep.Name,
		StepType:     mapStepTypeToWCP(firstStep.Type),
		GateOverride: &requireApproval,
	}, tenantID, orgID, userID, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to gate first step: %w", err)
	}

	return &MAPWCPExecutionResult{
		PlanID:      plan.PlanID,
		WorkflowID:  wcpWorkflow.WorkflowID,
		Status:      "awaiting_approval",
		CurrentStep: 0,
		TotalSteps:  totalSteps,
		StepName:    firstStep.Name,
		ApprovalInfo: gateResp,
	}, nil
}

// ExecuteWithStep executes a MAP plan in step mode.
// The first step auto-executes; subsequent steps pause for approval.
func (e *MAPWCPExecutor) ExecuteWithStep(ctx context.Context, plan *planning.Plan, workflow *Workflow, tenantID, orgID, userID, clientID string) (*MAPWCPExecutionResult, error) {
	if e.wcpService == nil {
		return nil, fmt.Errorf("WCP service not available")
	}

	if len(workflow.Spec.Steps) == 0 {
		return nil, fmt.Errorf("workflow has no steps")
	}

	log.Printf("[MAP-WCP] Starting step mode execution for plan %s (%d steps)", plan.PlanID, len(workflow.Spec.Steps))

	totalSteps := len(workflow.Spec.Steps)

	// Create a WCP workflow
	wcpWorkflow, err := e.wcpService.CreateWorkflow(ctx, &workflow_control.CreateWorkflowRequest{
		WorkflowName: fmt.Sprintf("map-step-%s", plan.PlanID),
		TotalSteps:   intPtr(totalSteps),
		Source:       "map",
		Metadata: map[string]interface{}{
			"plan_id":        plan.PlanID,
			"execution_mode": "step",
			"domain":         plan.Domain,
			"query":          plan.Query,
		},
	}, tenantID, orgID, userID, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to create WCP workflow for step mode: %w", err)
	}

	// First step is auto-allowed in step mode
	result := &MAPWCPExecutionResult{
		PlanID:      plan.PlanID,
		WorkflowID:  wcpWorkflow.WorkflowID,
		Status:      "executing_first_step",
		CurrentStep: 0,
		TotalSteps:  totalSteps,
		StepName:    workflow.Spec.Steps[0].Name,
	}

	// If there's a second step, it will need approval
	if totalSteps > 1 {
		result.Status = "awaiting_approval"
		result.CurrentStep = 1
		result.StepName = workflow.Spec.Steps[1].Name
	}

	return result, nil
}

// StepExecutionResult contains the result of a single MAP step execution.
type StepExecutionResult struct {
	StepIndex int         `json:"step_index"`
	StepName  string      `json:"step_name"`
	Status    string      `json:"status"` // completed, failed
	Output    interface{} `json:"output,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// ExecuteSingleStep executes a single MAP plan step using the workflow engine.
func (e *MAPWCPExecutor) ExecuteSingleStep(ctx context.Context, plan *planning.Plan, workflow *Workflow, stepIndex int, execContext map[string]interface{}, user string, engine *WorkflowEngine) (*StepExecutionResult, error) {
	if stepIndex < 0 || stepIndex >= len(workflow.Spec.Steps) {
		return nil, fmt.Errorf("step index %d out of range (0-%d)", stepIndex, len(workflow.Spec.Steps)-1)
	}

	step := workflow.Spec.Steps[stepIndex]
	log.Printf("[MAP-WCP] Executing step %d/%d: %s (type=%s)", stepIndex+1, len(workflow.Spec.Steps), step.Name, step.Type)

	if engine == nil {
		return nil, fmt.Errorf("workflow engine not available")
	}

	// Execute the step using the workflow engine's step processor
	processor, exists := engine.stepProcessors[step.Type]
	if !exists {
		return &StepExecutionResult{
			StepIndex: stepIndex,
			StepName:  step.Name,
			Status:    "failed",
			Error:     fmt.Sprintf("no processor found for step type %q", step.Type),
		}, nil
	}

	// Build step input
	input := make(map[string]interface{})
	if execContext != nil {
		for k, v := range execContext {
			input[k] = v
		}
	}

	// Execute via processor
	workflowExec := &WorkflowExecution{
		ID:     plan.PlanID,
		Status: "running",
	}
	output, execErr := processor.ExecuteStep(ctx, step, input, workflowExec)

	result := &StepExecutionResult{
		StepIndex: stepIndex,
		StepName:  step.Name,
	}
	if execErr != nil {
		result.Status = "failed"
		result.Error = execErr.Error()
	} else {
		result.Status = "completed"
		result.Output = output
	}

	return result, nil
}

// MAPWCPExecutionResult contains the result of a WCP-backed MAP execution
type MAPWCPExecutionResult struct {
	PlanID       string      `json:"plan_id"`
	WorkflowID   string      `json:"workflow_id"`
	Status       string      `json:"status"` // awaiting_approval, executing_first_step, completed
	CurrentStep  int         `json:"current_step"`
	TotalSteps   int         `json:"total_steps"`
	StepName     string      `json:"step_name"`
	ApprovalInfo interface{} `json:"approval_info,omitempty"`
}
