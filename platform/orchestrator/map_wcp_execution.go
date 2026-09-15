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

// mapStepTypeToWCP is the workflow-control step type a multi-agent step is
// gated as, or the refusal naming a type the multi-agent map does not name.
//
// It used to default EVERY unnamed type to tool_call, so a step type nobody had
// mapped reached the workflow control plane's gate wearing one, and was
// governed as a tool call (#4254). The table it reads is the same contract that
// decides which shipped action the step is presented as
// (step_action_admission.go), so the two cannot disagree about which tokens the
// plane knows.
func mapStepTypeToWCP(stepType string) (workflow_control.StepType, error) {
	gateType, named := mapStepGateTypes[stepType]
	if !named {
		return "", fmt.Errorf("the multi-agent plane gates no step of type %q on the workflow control plane", stepType)
	}
	return gateType, nil
}

// ExecuteWithConfirm executes a MAP plan in confirm mode.
// Each step creates a WCP workflow with require_approval gate.
// The client must approve each step before it executes.
// Returns immediately with status "awaiting_approval".
func (e *MAPWCPExecutor) ExecuteWithConfirm(ctx context.Context, plan *planning.Plan, workflow *Workflow, tenantID, orgID, userID, clientID string) (*MAPWCPExecutionResult, error) {
	if e.wcpService == nil {
		return nil, fmt.Errorf("WCP service not available")
	}

	// #4254 (R3 B-H1): a conditional carrying no branch steps is not presented,
	// so it is left out of the steps this mode gates and runs.
	steps := presentedSteps(workflow.Spec.Steps)

	if len(steps) == 0 {
		return nil, fmt.Errorf("workflow has no steps")
	}

	log.Printf("[MAP-WCP] Starting confirm mode execution for plan %s (%d steps)", plan.PlanID, len(steps))

	totalSteps := len(steps)

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
	firstStep := steps[0]
	gateType, err := mapStepTypeToWCP(firstStep.Type)
	if err != nil {
		return nil, err
	}
	requireApproval := workflow_control.GateDecisionRequireApproval
	gateResp, err := e.wcpService.StepGate(ctx, wcpWorkflow.WorkflowID, fmt.Sprintf("step_0_%s", firstStep.Name), &workflow_control.StepGateRequest{
		StepName:     firstStep.Name,
		StepType:     gateType,
		GateOverride: &requireApproval,
	}, tenantID, orgID, userID, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to gate first step: %w", err)
	}

	return &MAPWCPExecutionResult{
		PlanID:       plan.PlanID,
		WorkflowID:   wcpWorkflow.WorkflowID,
		Status:       "awaiting_approval",
		CurrentStep:  0,
		TotalSteps:   totalSteps,
		StepName:     firstStep.Name,
		ApprovalInfo: gateResp,
	}, nil
}

// ExecuteWithStep executes a MAP plan in step mode.
// The first step auto-executes; subsequent steps pause for approval.
func (e *MAPWCPExecutor) ExecuteWithStep(ctx context.Context, plan *planning.Plan, workflow *Workflow, tenantID, orgID, userID, clientID string) (*MAPWCPExecutionResult, error) {
	if e.wcpService == nil {
		return nil, fmt.Errorf("WCP service not available")
	}

	// #4254 (R3 B-H1): a conditional carrying no branch steps is not presented,
	// so it is left out of the steps this mode gates and runs.
	steps := presentedSteps(workflow.Spec.Steps)

	if len(steps) == 0 {
		return nil, fmt.Errorf("workflow has no steps")
	}

	// #4254 (R3): step mode runs its first step without a gate, so the first
	// step's type is checked against the map here, as confirm mode's gate checks
	// it. An unmapped type stops the plan, naming the token, before a workflow is
	// created for it.
	if _, err := mapStepTypeToWCP(steps[0].Type); err != nil {
		return nil, err
	}

	log.Printf("[MAP-WCP] Starting step mode execution for plan %s (%d steps)", plan.PlanID, len(steps))

	totalSteps := len(steps)

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
		StepName:    steps[0].Name,
	}

	// If there's a second step, it will need approval
	if totalSteps > 1 {
		result.Status = "awaiting_approval"
		result.CurrentStep = 1
		result.StepName = steps[1].Name
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
