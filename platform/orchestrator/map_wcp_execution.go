// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log"

	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
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
		WorkflowName: planWorkflowName("confirm", plan.PlanID),
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
	gateResp, err := e.wcpService.StepGate(ctx, wcpWorkflow.WorkflowID, mapStepGateID(0, firstStep), &workflow_control.StepGateRequest{
		StepName: firstStep.Name,
		StepType: gateType,
		// The hold is the override: no policy is asked here. The step's parts
		// are recorded for the approver; the engine decides the step when it
		// runs (ExecuteSingleStep).
		StepInput:    mapHeldStepInput(firstStep),
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
		WorkflowName: planWorkflowName("step", plan.PlanID),
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
	Status    string      `json:"status"` // StepResultCompleted or StepResultFailed
	Output    interface{} `json:"output,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// mapStepWithheldError is a confirm or step mode step the policy engine did not
// allow. The resume route answers it 403, a policy refusal, not a failure.
type mapStepWithheldError struct {
	step   string
	result *PolicyCheckResult
}

func (e *mapStepWithheldError) Error() string {
	return fmt.Sprintf("step %q withheld by policy: %s (%s): %s", e.step, e.result.Action, e.result.PolicyName, e.result.Reason)
}

// stepModeApprovalRequiredReason is the refusal of a policy challenge on a
// confirm or step mode step.
func stepModeApprovalRequiredReason() string {
	return string(contract.ReasonApprovalRequired) + ": the policy engine requires an approval for this step, and a confirm or step mode step is decided when it runs, after its hold was released, so it is refused rather than held again"
}

// auditStepModeDecision records a confirm or step mode step's decision as its
// step-gate row, built by the HITL engine's builder (stepGateEntry), with the
// anchored decision under plane "map" and the plan's execution mode.
func auditStepModeDecision(ctx context.Context, plan *planning.Plan, workflow *Workflow, step WorkflowStep, pr *PolicyCheckResult) {
	if auditLogger == nil || pr == nil {
		return
	}
	entry := stepGateEntry(plan.PlanID, workflow.Metadata.Name, step, pr, UserContext{TenantID: plan.TenantID, OrgID: plan.OrgID}, "")
	entry.Metadata["execution_mode"] = plan.ExecutionMode
	auditLogger.LogWorkflowOperation(ctx, entry)
}

// nonNilInput is m, or an empty map when m is nil, so a held step's recorded
// parameters are always an object.
func nonNilInput(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return map[string]interface{}{}
	}
	return m
}

// mapHeldStepInput is what a held confirm or step mode gate records of a step:
// its prompt, statement and parameters as written.
func mapHeldStepInput(step WorkflowStep) map[string]interface{} {
	return map[string]interface{}{
		"prompt":     step.Prompt,
		"statement":  step.Statement,
		"parameters": nonNilInput(step.Parameters),
	}
}

// A StepExecutionResult's Status: the executor sets them and the resume reads
// them, so a reader never compares against a spelling the executor does not
// write.
const (
	StepResultCompleted = "completed"
	StepResultFailed    = "failed"
)

// resumePrincipalKey carries the caller that resumed a confirm or step mode
// plan, as the resume route binds it (applyAuthoritativePrincipal).
type resumePrincipalKey struct{}

// withResumePrincipal installs the resuming caller ExecuteSingleStep decides and
// routes the step for.
func withResumePrincipal(ctx context.Context, principal UserContext) context.Context {
	return context.WithValue(ctx, resumePrincipalKey{}, principal)
}

func resumePrincipalFrom(ctx context.Context) (UserContext, bool) {
	principal, ok := ctx.Value(resumePrincipalKey{}).(UserContext)
	return principal, ok
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
			Status:    StepResultFailed,
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

	// THE STEP IS DECIDED HERE, over the content it will send (#4249 row
	// 5666236540). Confirm and step mode hold every step by an override that
	// asks no policy, so this is the one decision these modes make, and it is
	// made after the approval and immediately before the step runs, over the
	// input it runs with. It is decided for the subject the caller's context
	// carries, in the plan's organization and tenant, and recorded as the
	// step's gate row (PRD v11 §5.7). Anything but an allow fails the step as a
	// withhold (mapStepWithheldError). A challenge is refused as
	// approval_required: the approval this mode already took was the
	// override's, not the policy's, and a policy approval has no hold to wait
	// in at this point.
	// The step is decided, and its LLM call routed, for the caller that resumed
	// it (withResumePrincipal): its email and role as the route binds them, in
	// the plan's organization and tenant. With no email the execution presented
	// "membership established, no segments", so an organization's
	// segment-scoped route rows were dropped on this path alone (#4249 row
	// 5701303521, R3 round 1 HIGH-1); it now presents what the other plan routes
	// present for the same caller.
	stepUser := UserContext{OrgID: plan.OrgID, TenantID: plan.TenantID}
	if resumer, ok := resumePrincipalFrom(ctx); ok {
		stepUser.Email, stepUser.Role = resumer.Email, resumer.Role
	}
	workflowExec := &WorkflowExecution{
		ID:          plan.PlanID,
		Status:      "running",
		UserContext: stepUser,
	}
	decision := mapStepPolicyCheck(ctx, step, StepContent{Input: input, Processor: processor}, workflowExec)
	switch {
	case decision == nil:
		decision = mapStepBlocked(anchoredenforcer.CauseEvaluation, "the policy check returned no decision for the step, so it is refused")
		auditStepModeDecision(ctx, plan, workflow, step, decision)
		return nil, &mapStepWithheldError{step: step.Name, result: decision}
	case decision.Action == "require_approval":
		withheld := *decision
		withheld.Action, withheld.Allowed, withheld.hold = "block", false, nil
		withheld.Reason = stepModeApprovalRequiredReason()
		auditStepModeDecision(ctx, plan, workflow, step, &withheld)
		return nil, &mapStepWithheldError{step: step.Name, result: &withheld}
	case !decision.Allowed:
		auditStepModeDecision(ctx, plan, workflow, step, decision)
		return nil, &mapStepWithheldError{step: step.Name, result: decision}
	}
	auditStepModeDecision(ctx, plan, workflow, step, decision)
	output, execErr := processor.ExecuteStep(ctx, step, input, workflowExec)
	// A step's LLM call refused by the organization's route rows is a policy
	// refusal, answered as the step decision's own refusals are (#4249 row
	// 5701303521). As a failed step result it would be marked completed by the
	// resume, and the plan would go on as if the call had been made.
	var routeRefusal *llmCallRouteRefusal
	if errors.As(execErr, &routeRefusal) {
		return nil, &mapStepWithheldError{step: step.Name, result: mapStepBlocked(routeRefusal.Reason, routeRefusal.Error())}
	}

	result := &StepExecutionResult{
		StepIndex: stepIndex,
		StepName:  step.Name,
	}
	if execErr != nil {
		result.Status = StepResultFailed
		result.Error = execErr.Error()
	} else {
		result.Status = StepResultCompleted
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

// mapStepGateID is the workflow-control step id a MAP plan step is gated under:
// its index in the presented steps and its name. The confirm executor, plan
// resume and the next-step gate all name a step this way.
func mapStepGateID(index int, step WorkflowStep) string {
	return fmt.Sprintf("step_%d_%s", index, step.Name)
}

// planStepGateIDs is the set of gate step ids a plan's own steps are gated
// under, derived from the plan's presented steps (mapStepGateID) and never from
// a request field. A gate row under any other step id was written by another
// caller of the workflow's gate route, not by the plan's executor or resume
// (#4249 row 5713229791).
func planStepGateIDs(steps []WorkflowStep) map[string]bool {
	ids := make(map[string]bool, len(steps))
	for i := range steps {
		ids[mapStepGateID(i, steps[i])] = true
	}
	return ids
}

// foreignGateRowCount is how many of a workflow's gate rows are not the plan's
// own step gates, and so are not read by planResumeStepIndex's rule 2 or picked
// by the resume's approve and reject.
func foreignGateRowCount(steps []WorkflowStep, rows []workflow_control.WorkflowStep) int {
	own := planStepGateIDs(steps)
	n := 0
	for _, row := range rows {
		if !own[row.StepID] {
			n++
		}
	}
	return n
}

// planResumeRefusal is a plan resume, or a plan-level approve or reject, that
// must not act: Status is the HTTP status and Message names why (#4249).
// Ended marks the refusal "the plan's workflow has ended", which the resume's
// reject arm treats as the plan having been rejected already.
type planResumeRefusal struct {
	Status  int
	Message string
	Ended   bool
}

func (r *planResumeRefusal) Error() string { return r.Message }

// planWorkflowName is the name the confirm/step executor gives the workflow it
// creates for a plan in that mode. Both executors build the name here, so the
// name fallback (selectPlanWorkflow) selects by the same bytes they wrote.
func planWorkflowName(mode, planID string) string {
	return "map-" + mode + "-" + planID
}

// resolvePlanWorkflow finds the workflow-control workflow a plan resume, or a
// plan-level approve or reject, acts on (#4249, rows 5699811399, 5699811991 and
// 5700138487). The caller has already loaded the plan org-scoped.
//
//   - The plan must be in confirm or step mode (409). No other mode has a
//     workflow-control workflow, and a mode read from a workflow's name is a
//     mode a caller chose.
//   - A plan whose executor workflow was bound when it entered its mode
//     (planning.Plan.BoundWorkflowID) acts on that workflow and no other, read
//     under the CALLER's tenant: the executor created it under the tenant of
//     whoever executed the plan, which is not always the plan's own. A caller
//     that cannot see it is refused, 403 when the caller is not of the plan's
//     tenant, else 404. It must still be running (409, Ended).
//   - A plan marked executing on this release whose binding is still empty
//     (its executor has not returned) is refused (409): it has no workflow of
//     its own yet, and none is selected by name for it.
//   - A plan with no binding at all began executing before the binding
//     existed. It falls back to the executor's name for the plan's mode, under
//     the plan's tenant, refusing a caller of another tenant (403) and what a
//     name cannot establish (selectPlanWorkflow).
func resolvePlanWorkflow(ctx context.Context, svc *workflow_control.Service, plan *planning.Plan, callerTenantID, orgID string) (*workflow_control.WorkflowStatusResponse, *planResumeRefusal, error) {
	if plan.ExecutionMode != "confirm" && plan.ExecutionMode != "step" {
		return nil, &planResumeRefusal{Status: 409, Message: fmt.Sprintf(
			"plan is in %q execution mode; only a confirm or step plan is resumed or decided through its workflow", plan.ExecutionMode)}, nil
	}
	bound, marked := plan.ExecutionBinding()
	if marked && bound == "" {
		// Marked executing on this release, its executor not yet returned (or
		// the process stopped before the bind). No workflow of its own exists to
		// act on, and selecting one by name here is the lookalike window (#4249,
		// row 5701284556). An executor that fails fails the plan; a plan left in
		// this state is ended with POST /api/v1/plan/{id}/cancel.
		return nil, &planResumeRefusal{Status: 409, Message: "the plan's workflow is still being set up; it cannot be resumed or decided yet (a plan that stays in this state is ended with POST /api/v1/plan/{id}/cancel)"}, nil
	}
	if bound != "" {
		wf, err := svc.GetWorkflow(ctx, bound, callerTenantID, orgID)
		if err != nil {
			if errors.Is(err, workflow_control.ErrWorkflowNotFound) {
				if callerTenantID != plan.TenantID {
					return nil, &planResumeRefusal{Status: 403, Message: "this plan belongs to another tenant"}, nil
				}
				return nil, &planResumeRefusal{Status: 404, Message: "the plan's workflow was not found for this tenant"}, nil
			}
			return nil, nil, err
		}
		if wf.IsTerminal() {
			return nil, &planResumeRefusal{Status: 409, Ended: true, Message: fmt.Sprintf(
				"workflow %s of this plan is %s; the plan does not proceed past it", wf.WorkflowID, wf.Status)}, nil
		}
		resp := wf.ToStatusResponse()
		return &resp, nil, nil
	}
	if callerTenantID != plan.TenantID {
		return nil, &planResumeRefusal{Status: 403, Message: "this plan belongs to another tenant"}, nil
	}
	return selectPlanWorkflow(ctx, svc, planWorkflowName(plan.ExecutionMode, plan.PlanID), plan.TenantID, orgID)
}

// selectPlanWorkflow is resolvePlanWorkflow's fallback for a plan with no bound
// workflow (#4249, row 5699811399). The executor's name
// is chosen by whoever creates a workflow, so a name alone does not identify
// the executor's workflow. Every workflow of the tenant with that name is read,
// across all pages, and:
//   - any that has ended (aborted, failed, completed) refuses (409, Ended): a
//     rejection or an expiry aborts the executor's workflow and leaves the plan
//     executing, and a lookalike created afterwards must not resume it;
//   - more than one still running refuses (409): the selection is ambiguous;
//   - none refuses (404), as before.
//
// Its only cost is fail-closed: a tenant member who creates a lookalike of a
// pre-release plan makes that plan unresumable. A plan marked executing on this
// release never reaches it: its binding exists from the executing mark on.
func selectPlanWorkflow(ctx context.Context, svc *workflow_control.Service, name, tenantID, orgID string) (*workflow_control.WorkflowStatusResponse, *planResumeRefusal, error) {
	const pageSize = 100
	mapSource := workflow_control.WorkflowSource("map")
	var live []workflow_control.WorkflowStatusResponse
	for offset := 0; ; offset += pageSize {
		page, err := svc.ListWorkflows(ctx, workflow_control.ListWorkflowsOptions{
			Source: &mapSource, TenantID: tenantID, OrgID: orgID, WorkflowName: name, Limit: pageSize, Offset: offset,
		})
		if err != nil {
			return nil, nil, err
		}
		for _, wf := range page.Workflows {
			if wf.WorkflowName != name {
				continue
			}
			switch wf.Status {
			case workflow_control.WorkflowStatusCompleted, workflow_control.WorkflowStatusAborted, workflow_control.WorkflowStatusFailed:
				return nil, &planResumeRefusal{Status: 409, Ended: true, Message: fmt.Sprintf(
					"workflow %s of this plan is %s; the plan does not proceed past it", wf.WorkflowID, wf.Status)}, nil
			}
			live = append(live, wf)
		}
		if len(page.Workflows) < pageSize || offset+len(page.Workflows) >= page.Total {
			break
		}
	}
	switch len(live) {
	case 0:
		return nil, &planResumeRefusal{Status: 404, Message: "No active WCP workflow found for this plan"}, nil
	case 1:
		return &live[0], nil, nil
	}
	return nil, &planResumeRefusal{Status: 409, Message: fmt.Sprintf(
		"%d running workflows carry this plan's name; the plan does not choose between them", len(live))}, nil
}

// planNextStep is the plan's NEXT step: the lowest-index presented step that
// has not run, with its own gate row when it has one (row nil when it has
// none). ok is false when every step of the plan has run. Only the plan's own
// step gates are read (planStepGateIDs, #4249 row 5713229791); a row under any
// other step id is not the plan's.
func planNextStep(steps []WorkflowStep, rows []workflow_control.WorkflowStep) (index int, row *workflow_control.WorkflowStep, ok bool) {
	byID := make(map[string]workflow_control.WorkflowStep, len(rows))
	for _, r := range rows {
		byID[r.StepID] = r
	}
	for i := range steps {
		r, has := byID[mapStepGateID(i, steps[i])]
		if has && r.CompletionCount > 0 {
			continue
		}
		if !has {
			return i, nil, true
		}
		return i, &r, true
	}
	return len(steps), nil, false
}

// isStepRunRecord reports whether row is a step-run record
// (workflow_control.RecordStepRun): an allow with no approval status, stating
// one of the record's two reasons.
func isStepRunRecord(row *workflow_control.WorkflowStep) bool {
	return row != nil && row.ApprovalStatus == nil && row.Decision == workflow_control.GateDecisionAllow &&
		(row.DecisionReason == workflow_control.StepRunReasonStepModeFirstStep ||
			row.DecisionReason == workflow_control.StepRunReasonBackfilledAtUpgrade)
}

// planResumeStepIndex decides which presented step a plan resume runs, from the
// workflow as read AFTER the resume's own approve (#4249, rows 5698298886,
// 5699398978, 5699811652 and 5701284807).
//
// The step is keyed on the gate row's step_id, never on the workflow's
// current_step_index: StepGate stamps a row's step_index one past the
// workflow's current index (1-based, as every WCP client reads it), so the
// confirm executor's first row, step_0_<name>, carries index 1, and a resume
// that ran Steps[current_step_index] ran step 1 on step 0's approval.
//
// THE PLAN'S STEPS RUN IN ORDER (#4249 row 5701284807). The resume runs the
// plan's NEXT step (planNextStep), the lowest one that has not run, and reads a
// later step's gate only at that step's turn. Another caller of the workflow's
// gate route can write a later step's gate first; it used to become the
// "current" step, so the resume ran it and the approved earlier step never ran.
// The rules, in order:
//  1. The workflow has not ended. A rejection or an expiry aborts it; an approve
//     racing that rejection must not leave a step runnable.
//  2. Some step has not run; when every step has, nothing runs.
//  3. The next step's row is its own step-run record, not completed: it runs
//     (the run never finished, or its completion was lost). Otherwise the
//     next step's gate row is approved: it runs. A pending row refuses,
//     naming the step to approve; a row with no approval status, or one that is
//     rejected or expired, refuses (409): every MAP gate is an override-created
//     hold, so an unapproved row is a hold that was cleared or never granted.
//     When the resume approved a row itself, it is this step's.
//  4. The next step has no gate row: in STEP mode the plan's first step runs
//     ungated by design (ExecuteWithStep), and nothing else does. A confirm-mode
//     workflow writes every step's gate before the step runs.
func planResumeStepIndex(steps []WorkflowStep, gated *workflow_control.Workflow, approvedStepID string, stepMode bool) (int, *planResumeRefusal) {
	if gated.IsTerminal() {
		return 0, &planResumeRefusal{Status: 409, Message: fmt.Sprintf(
			"workflow %s is %s; the plan resume does not run a step", gated.WorkflowID, gated.Status)}
	}
	next, row, ok := planNextStep(steps, gated.Steps)
	if !ok {
		return 0, &planResumeRefusal{Status: 409, Message: "every step of the plan has already run; the plan resume does not run a step"}
	}
	if row == nil {
		if stepMode && next == 0 {
			return 0, nil
		}
		if len(gated.Steps) == 0 {
			return 0, &planResumeRefusal{Status: 409, Message: "a confirm-mode workflow with no gate row has nothing approved to run"}
		}
		return 0, &planResumeRefusal{Status: 409, Message: fmt.Sprintf(
			"no gate row names a step of this plan at its next step %s; the plan resume does not run a step", mapStepGateID(next, steps[next]))}
	}
	// A STEP-RUN RECORD THAT IS NOT COMPLETED RUNS (R3 round 2 MEDIUM-1): the
	// record is written before its step runs, so completion 0 means the run
	// never finished or its completion was lost. Refusing it as an unapproved
	// gate made every later resume refuse; running it is at-least-once on a
	// crash, the ordinary semantics.
	if isStepRunRecord(row) {
		return next, nil
	}
	if row.ApprovalStatus == nil {
		return 0, &planResumeRefusal{Status: 409, Message: fmt.Sprintf(
			"step %s carries no approval and is not the plan's own step-run record; the plan resume runs a step only on its approval or its record", row.StepID)}
	}
	status := string(*row.ApprovalStatus)
	switch status {
	case string(workflow_control.ApprovalStatusApproved):
	case string(workflow_control.ApprovalStatusPending):
		return 0, &planResumeRefusal{Status: 409, Message: fmt.Sprintf(
			"step %s holds approval pending; it is the plan's next step, and the plan resume runs it once it is approved", row.StepID)}
	default:
		return 0, &planResumeRefusal{Status: 409, Message: fmt.Sprintf(
			"step %s holds approval %s; the plan resume does not run a step past an unapproved gate", row.StepID, status)}
	}
	if approvedStepID != "" && row.StepID != approvedStepID {
		return 0, &planResumeRefusal{Status: 409, Message: fmt.Sprintf(
			"the approved step %s is not the plan's next step %s; the plan resume does not run it", approvedStepID, row.StepID)}
	}
	return next, nil
}
