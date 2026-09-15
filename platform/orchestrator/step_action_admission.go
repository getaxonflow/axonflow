// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// HOW A STEP IS PRESENTED TO THE ANCHORED ENGINE (#4254, PRD v11 §1.13).
//
// The engine decides an ACTION from the deployment vocabulary, so each plane
// presents its step as the shipped action the step's type maps to. The two
// planes spell their types differently and always have - the workflow control
// plane underscores them (workflow_control.StepType) and the multi-agent plane
// hyphenates them (the workflow engine's step processors) - so there are two
// tables, each over that plane's own tokens.
//
// THE TOKENS ARE EXACT. Neither table aliases an underscore to a hyphen or
// folds case: every spelling a table accepts is one a plane actually produces,
// and widening the accepted set is how a step type nobody reviewed gets
// presented as an action nobody chose. A type outside its plane's table is
// REFUSED, naming the token, and the request fails closed as
// request_unbuildable (anchoredenforcer.CauseRequest) rather than being
// defaulted to tool.call - which is what the multi-agent plane did before
// (mapStepTypeToWCP's default arm), so a step type nobody had mapped was
// governed as though it were a tool call.
//
// THE CONDITIONAL STEP IS NOT PRESENTED, AND IS REFUSED WHEN IT HAS BRANCHES.
// A multi-agent conditional step performs no governed action itself: it
// evaluates a condition and runs the branch steps it carries
// (ConditionalProcessor.ExecuteStep). Those branch steps ARE governed actions -
// an llm-call or a connector-call - and nothing presents them: every policy
// check on this plane walks the top-level steps only. So a conditional
// carrying branch steps is refused where the plan is admitted, before any step
// executes, and a conditional carrying none invokes nothing and is simply not
// presented, on every mode: the HITL engine skips it, and the confirm, step and
// resume paths leave it out of the governed steps (presentedSteps), so no gate is
// taken and nothing runs for it (R3 B-H1). Presenting the branch steps by their
// own type is the v11.1.0 follow-up (#4249).

// wcpStepActions is the shipped action each workflow-control step type is
// presented as. The types are workflow_control's own constants, so a new one
// cannot be added without a row here (TestEveryWorkflowStepTypeConstantHasAnAction).
var wcpStepActions = map[workflow_control.StepType]string{
	workflow_control.StepTypeLLMCall:       authoringcatalog.ActionLLMCompletion,
	workflow_control.StepTypeToolCall:      authoringcatalog.ActionToolCall,
	workflow_control.StepTypeConnectorCall: authoringcatalog.ActionToolCall,
	workflow_control.StepTypeHumanTask:     authoringcatalog.ActionAgentInvoke,
}

// mapStepTypeConditional is the multi-agent step type that carries branch steps
// rather than performing an action of its own.
const mapStepTypeConditional = "conditional"

// mapStepActions is the shipped action each multi-agent step type is presented
// as. The keys are the workflow engine's registered step processors, minus the
// conditional (TestEveryMultiAgentStepProcessorHasAnActionOrIsTheConditional).
var mapStepActions = map[string]string{
	"llm-call":       authoringcatalog.ActionLLMCompletion,
	"connector-call": authoringcatalog.ActionToolCall,
	"function-call":  authoringcatalog.ActionToolCall,
	"api-call":       authoringcatalog.ActionToolCall,
}

// mapStepGateTypes is the workflow-control step type each multi-agent step type
// is GATED as, when a multi-agent plan runs through the workflow control plane
// (confirm and step mode). It names exactly the tokens mapStepActions names -
// the two are the same contract seen from two sides, and
// TestTheMultiAgentGateAndActionMapsNameTheSameTokens holds them equal - so a
// step type the plane will not present is not gated under a borrowed type
// either.
var mapStepGateTypes = map[string]workflow_control.StepType{
	"llm-call":       workflow_control.StepTypeLLMCall,
	"connector-call": workflow_control.StepTypeConnectorCall,
	"function-call":  workflow_control.StepTypeToolCall,
	"api-call":       workflow_control.StepTypeToolCall,
}

// actionForWCPStep is the shipped action a workflow step is presented as, or
// the refusal naming the type the plane's map does not name.
func actionForWCPStep(stepType workflow_control.StepType) (string, error) {
	action, named := wcpStepActions[stepType]
	if !named {
		return "", fmt.Errorf("the workflow control plane presents no shipped action for a step of type %q", string(stepType))
	}
	return action, nil
}

// actionForMAPStep is the shipped action a multi-agent step is presented as, or
// the refusal naming the type the plane's map does not name. The conditional is
// refused here too: a step that is not presented has no action, and a caller
// that reaches this with one is asking for a verdict on something the plane
// does not decide (refuseUnpresentableSteps admits it, or refuses the plan).
func actionForMAPStep(stepType string) (string, error) {
	action, named := mapStepActions[stepType]
	if !named {
		return "", fmt.Errorf("the multi-agent plane presents no shipped action for a step of type %q", stepType)
	}
	return action, nil
}

// refuseUnpresentableSteps refuses a multi-agent workflow whose steps cannot all
// be presented to the engine, BEFORE any of them executes. It is called where a
// plan or a workflow is admitted, so every path into the plane refuses the same
// definition the same way.
//
// Only the conditional is refused here, and only when it carries branch steps:
// its branches would execute with no decision. An unmapped step TYPE is not
// refused here - it is refused per step, at the seam, as request_unbuildable -
// because that is a verdict on one request, and refusing the whole definition
// for it would withhold steps the plane can decide.
func refuseUnpresentableSteps(steps []WorkflowStep) error {
	for i, step := range steps {
		if step.Type != mapStepTypeConditional {
			continue
		}
		if len(step.IfTrue) == 0 && len(step.IfFalse) == 0 {
			continue
		}
		return fmt.Errorf("step %d (%q) is a conditional carrying %d branch steps, and a branch step is not presented to the policy engine; refusing the whole workflow rather than executing them undecided",
			i, step.Name, len(step.IfTrue)+len(step.IfFalse))
	}
	return nil
}

// mapStepNotPresented reports a conditional that carries no branch steps. It
// invokes nothing, so it is not presented to the engine, not gated and not run,
// on any mode (R3 B-H1).
func mapStepNotPresented(step WorkflowStep) bool {
	// refuseUnpresentableSteps stays the one admission-side reader of a step's
	// branch fields (TestNothingElseReadsAStepsBranchFields): a conditional it
	// does not refuse carries no branch steps.
	return step.Type == mapStepTypeConditional && refuseUnpresentableSteps([]WorkflowStep{step}) == nil
}

// presentedSteps is steps without the ones no plane presents, in order. The
// confirm, step and resume paths number the governed steps over this list, so
// the three agree on which step an index names.
func presentedSteps(steps []WorkflowStep) []WorkflowStep {
	out := make([]WorkflowStep, 0, len(steps))
	for _, step := range steps {
		if !mapStepNotPresented(step) {
			out = append(out, step)
		}
	}
	return out
}

// ungovernableResumeRequest is the request a plan resume records an ungovernable
// plan's refusal under. Its principal is the authenticated hop's organization,
// tenant and client, never the resume body, which carries only the approval.
// Built here, the resume handler that decodes that body names no principal type
// (TestEveryBodyDecodedPrincipalIsBound).
func ungovernableResumeRequest(planID, orgID, tenantID, clientID string) OrchestratorRequest {
	return OrchestratorRequest{
		RequestID:   planID,
		RequestType: "plan_resume",
		User:        UserContext{OrgID: orgID, TenantID: tenantID},
		Client:      ClientContext{ID: clientID, OrgID: orgID, TenantID: tenantID},
	}
}

// recordUngovernablePlan records the refusal of a workflow or plan whose steps
// cannot all be presented, as the multi-agent plane records every other refusal
// (R3 B-M5): the decision counter, under the label the enforcer's own
// request_unbuildable carries, and a blocked audit row stamped with plane map and
// the anchored engine (PRD v11 §5.7).
func recordUngovernablePlan(ctx context.Context, req OrchestratorRequest, err error) {
	anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "unavailable", anchoredenforcer.CauseRequest)
	if auditLogger == nil {
		return
	}
	auditLogger.LogBlockedRequest(ctx, req, &PolicyEvaluationResult{
		Allowed:         false,
		AppliedPolicies: []string{anchoredenforcer.CauseRequest},
		RequiredActions: []string{"blocked: " + anchoredenforcer.CauseRequest + ": " + err.Error()},
	}, anchoredDecisionFor(mapSeamScope, nil))
}
