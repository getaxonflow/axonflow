// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/anchoredenforcer"
)

// THE MULTI-AGENT PLANE DECIDES ON THE ANCHORED ENGINE (#4254).
//
// Every multi-agent step is presented to the engine before it runs (#4382),
// through mapStepGate.decide (map_step_gate.go), on the declarative
// WorkflowEngine, which runs every step of POST /api/v1/workflows/execute and
// of POST /api/v1/plan/execute outside confirm and step mode on every
// deployment (the in-memory HITL engine that also called it is retired, #4249
// row 5774060413). Confirm and step mode reach this plane in
// ExecuteSingleStep (map_wcp_execution.go). A step is presented as the shipped
// action its step type maps to (actionForMAPStep), for the client credential
// the agent authenticated, with the dynamic matcher's facts, and with THE
// STEP'S CONTENT (#4249 row 5666236540): mapStepContent's unescaped projection
// (step_content_projection.go) of the step's prompt, statement and parameters
// as written, then what its processor will send - rendered by the same function
// the processor sends it with - or, for a processor that renders nothing, the
// input it is passed (stepContentFor builds it for both executors). The written
// parts and the rendering are both presented, so a pattern that exists only once
// a template and a value are joined is decided, and so is one a rendering
// drops. Only a step with none of them presents EmptyContent.
//
// THE CHECKER NEVER RETURNS AN ERROR. mapStepGate.decide proceeds when a
// checker errors (the #2698 fail-open arm, which records the error), so every
// cause this plane cannot decide through is a block that names the cause, and
// the step never runs: no enforcer, an unavailable verdict, a subject the
// identity plane refuses, and a step type the map does not name. The fail-open
// arm stays, and no production checker reaches it.
//
// A CHALLENGE IS WITHHELD, never held. This seam answers it as a
// require_approval result carrying the typed approval requirement, and
// mapStepGate.decide withholds it as approval_requires_durable_record: no
// multi-agent executor keeps a durable approval record. ExecuteSingleStep
// withholds it the same way in confirm and step mode, whose durable holds are
// the workflow control plane's, decided under the wcp scope through StepGate.
// An approval that timed out before it was asked for is approval_expired.

// mapSeamScope is the enforcement scope this seam decides.
var mapSeamScope = legacycompile.MustScopeFor(legacycompile.PlaneMAP, "")

// This seam registers its own scope, so it adds a disjoint entry beside every
// other seam and edits none of their files.
func init() {
	orchestratorEnforcingScopes = append(orchestratorEnforcingScopes, mapSeamScope)
}

// The fact producer this plane decides from, built once per process from the
// dynamic engine the process wired. Replaceable so a test can install its own
// rows without a database.
var (
	// THE CHECKER PRESENTS CONTENT (see the file comment): asStepPlane
	// states the step's own context and sets no presentsNoContent, so every
	// content row is evaluated over it.
	newMAPFactProducer = func() (*dynamicFactProducer, error) { return wiredDynamicFactProducer(true) }

	mapFactSource = lazyFactSource[*dynamicFactProducer]{build: func() (*dynamicFactProducer, error) { return newMAPFactProducer() }}
)

func mapFactProducer() (*dynamicFactProducer, error) { return mapFactSource.get() }

// mapPlaneSubjectKey carries the subject a multi-agent execution's steps are
// decided for. The checker's interface is shared with the tests' checkers and
// receives no request, so the HTTP handler that starts the execution installs
// the subject on the context, as the response plane's seam does.
type mapPlaneSubjectKey struct{}

// withMAPPlaneSubject installs the subject every step of an execution started
// with ctx is decided for.
func withMAPPlaneSubject(ctx context.Context, subject func(now time.Time) (anchoredenforcer.Subject, bool)) context.Context {
	return context.WithValue(ctx, mapPlaneSubjectKey{}, subject)
}

func mapPlaneSubjectFrom(ctx context.Context) func(now time.Time) (anchoredenforcer.Subject, bool) {
	if ctx == nil {
		return nil
	}
	subject, _ := ctx.Value(mapPlaneSubjectKey{}).(func(now time.Time) (anchoredenforcer.Subject, bool))
	return subject
}

// mapStepPolicyCheck decides one multi-agent step: an allow lets the step run,
// and every other answer is a block or a hold. Every result carries the anchored
// decision its audit row records (PRD v11 §5.7).
func mapStepPolicyCheck(ctx context.Context, step WorkflowStep, content StepContent, execution *WorkflowExecution) *PolicyCheckResult {
	result, verdict := mapStepDecide(ctx, step, content, execution)
	if result != nil {
		result.decided = anchoredDecisionFor(mapSeamScope, verdict)
	}
	return result
}

// mapStepCostInputs is what the platform prices a multi-agent step by
// (step_cost_estimate.go): the step's own provider, model, output ceiling and
// output schema, read from the plan this deployment stored and is executing, so
// they are the plan author's and not the caller's of the request that runs it,
// plus the query the plane is deciding.
//
// THE TEXT PRICED IS THE PRESENTED CONTENT, WHICH CONTAINS THE RENDERED QUERY,
// not the step's template alone (R3 round 1, MEDIUM-3; the wording corrected in
// round 2, LOW-C). mapStepContent projects the step's prompt, statement and
// parameters AND what its processor will send - `{{input.*}}` rendered from the
// execute request's context, with the prior steps' outputs appended for a
// synthesis step - so the priced text is the template PLUS the rendering, and
// over-states by the template's own length. That is the conservative direction
// twice over: pricing the template ALONE would understate every step whose
// prompt interpolates anything, and a constraint reading `cost_estimate <= N`
// would admit a step whose real prompt is far larger. The caller's input can
// RAISE the number, never lower it below the plan author's own text, so a
// constraint here is still not the caller's to choose.
//
// ONLY A STEP THE PLANE PRESENTS AS AN LLM COMPLETION IS PRICED, derived from
// mapStepActions rather than named here (R3 round 1, LOW-10), so a later step
// type that spends LLM tokens is priced by adding it to that one table. A
// connector, function or api call presents tool.call and spends no LLM tokens.
func mapStepCostInputs(step WorkflowStep, query string) *stepCostInputs {
	if mapStepActions[step.Type] != authoringcatalog.ActionLLMCompletion {
		return nil
	}
	return &stepCostInputs{
		provider:  step.Provider,
		model:     step.Model,
		prompt:    query,
		maxTokens: step.MaxTokens,
		output:    step.Output,
	}
}

// mapStepDecide is mapStepPolicyCheck's decision, with the verdict the engine
// gave: nil when the plane failed closed before the engine answered.
func mapStepDecide(ctx context.Context, step WorkflowStep, content StepContent, execution *WorkflowExecution) (*PolicyCheckResult, *anchoredenforcer.Verdict) {
	enforcer := orchestratorEnforcer()
	if enforcer == nil {
		return mapStepUnavailable(anchoredenforcer.CauseNotWired), nil
	}
	subject := mapPlaneSubjectFrom(ctx)
	if subject == nil {
		// No handler installed a subject for this execution, so there is no one
		// to decide it for. Refused as the identity plane refuses an unverifiable
		// subject, and never decided for anyone.
		// Counted as the enforcer counts the same cause, "unavailable" (R3 B-L1).
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictUnavailable, anchoredenforcer.CauseSubjectUnverifiable)
		return mapStepBlocked(anchoredenforcer.CauseSubjectUnverifiable,
			anchoredenforcer.CauseSubjectUnverifiable+": no credential subject was installed for this execution"), nil
	}
	var user UserContext
	executionID := ""
	if execution != nil {
		user, executionID = execution.UserContext, execution.ID
	}
	query, err := mapStepContent(step, content, execution)
	if err != nil {
		anchoredenforcer.FailClosed(mapSeamScope, user.OrgID, anchoredenforcer.CauseRequest, err)
		return mapStepUnavailable(anchoredenforcer.CauseRequest), nil
	}
	req := OrchestratorRequest{
		RequestID:   executionID,
		Query:       query,
		RequestType: "map_step",
		User:        user,
		Context: map[string]interface{}{
			"step_name":     step.Name,
			"step_type":     step.Type,
			"step_provider": step.Provider,
			"step_model":    step.Model,
		},
		stepCost: mapStepCostInputs(step, query),
	}
	producer, err := mapFactProducer()
	var facts contract.AttributeSet
	if err == nil {
		facts, _, err = producer.Produce(ctx, req)
	}
	if err != nil {
		anchoredenforcer.FailClosed(mapSeamScope, user.OrgID, anchoredenforcer.CauseEvaluation, err)
		if errors.Is(err, errDynamicFactsUnavailable) {
			anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictUnavailable, anchoredenforcer.CauseEvaluation)
			return mapStepBlocked("segment_resolution_failed", "segment resolution unavailable - request denied (fail-closed, ADR-060 #2989 P3b)"), nil
		}
		return mapStepUnavailable(anchoredenforcer.CauseEvaluation), nil
	}
	action, actionErr := actionForMAPStep(step.Type)

	v := enforcer.Evaluate(ctx, anchoredenforcer.Call{
		Scope:        mapSeamScope,
		OrgID:        user.OrgID,
		RequestID:    executionID,
		Action:       action,
		ActionErr:    actionErr,
		Subject:      subject,
		Query:        query,
		EmptyContent: query == "",
		Facts:        facts,
	})

	switch anchoredenforcer.Classify(v) {
	case anchoredenforcer.ClassUnavailable:
		return mapStepUnavailable(v.Unavailable), &v
	case anchoredenforcer.ClassRefusal:
		reason := strings.ToLower(string(v.Refusal.Reason))
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictDeny, reason)
		return mapStepBlocked(reason, reason+": "+v.Refusal.Detail), &v
	}
	return mapStepFromDecision(v, dbRiskCalculator.CalculateRiskScore(req), time.Now(), atBranchPosition(ctx)), &v
}

// StepContent is what a multi-agent step presents beside its definition: the
// input the engine passes it, and the processor that will run it.
type StepContent struct {
	Input     map[string]interface{}
	Processor StepProcessor
}

// mapStepContent is the content a multi-agent step presents, as the unescaped
// projection of its parts (step_content_projection.go): its prompt, statement
// and parameters as written, then
//
//   - for a processor that renders what it sends (stepContentRenderer: llm-call,
//     connector-call), that rendering - the query, or the statement and the
//     built parameters - which is where the input it uses appears;
//   - for any other processor (api-call, function-call), the input the engine
//     passes it, which such a processor receives untemplated.
//
// An input key beginning "_" is the engine's own bookkeeping (the plan route's
// _policy_result), and it is left out of a non-rendering step's presented input.
// THAT IS SOUND ONLY WHILE NO SUCH PROCESSOR FORWARDS ITS WHOLE INPUT: api-call
// reads named keys (extractFlightSearchParams reads execution.Input by name) and
// function-call sends nothing. A processor that forwarded its input whole would
// send the "_" keys, and this filter would then drop content it sends. A connector-call step's
// buildParameters DOES copy the whole input, "_" keys included, into the
// parameters it sends, so there they are presented, as sent. A step with none
// of these presents "". Content that cannot be presented - a string that is not
// valid UTF-8, or a NaN or infinite number - is returned as an error, never
// presented empty; because an earlier step's output is part of a later step's
// input, one such output refuses every later step that presents its input or
// its built parameters (request_unbuildable), which fails closed.
func mapStepContent(step WorkflowStep, content StepContent, execution *WorkflowExecution) (string, error) {
	parts := []any{step.Prompt, step.Statement, step.Parameters}
	if renderer, ok := content.Processor.(stepContentRenderer); ok {
		if execution == nil {
			execution = &WorkflowExecution{}
		}
		parts = append(parts, renderer.RenderStepContent(step, content.Input, execution)...)
	} else {
		parts = append(parts, presentedStepInput(content.Input))
	}
	query, err := contentProjection(parts...)
	if err != nil {
		return "", fmt.Errorf("the step's content cannot be presented: %w", err)
	}
	return query, nil
}

// presentedStepInput is input without the engine's "_"-prefixed bookkeeping.
func presentedStepInput(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		if strings.HasPrefix(k, "_") {
			continue
		}
		out[k] = v
	}
	return out
}

// mapStepFromDecision answers the engine's decision in the checker's terms.
// atBranch is true when the step is a conditional's branch step
// (map_conditional_gate.go): it changes only how a challenge is answered and
// counted, never the verdict.
func mapStepFromDecision(v anchoredenforcer.Verdict, riskScore float64, now time.Time, atBranch bool) *PolicyCheckResult {
	// The decision half: the caller has answered a cause and a refusal, so only
	// the decision is classed here.
	dec := v.Decision
	class := anchoredenforcer.ClassifyDecision(dec)
	if class == anchoredenforcer.ClassNoDecision {
		return mapStepUnavailable(anchoredenforcer.CauseEvaluation)
	}
	deciding := anchoredenforcer.DecidingPolicies(dec)
	reason := string(dec.Reason)

	switch class {
	case anchoredenforcer.ClassAllow:
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictAllow, reason)
		// An allow is a result, not nil: its decision is recorded on the step's
		// audit row like every other one (PRD v11 §5.7), and the step runs.
		name := ""
		if len(deciding) > 0 {
			name = deciding[0]
		}
		return &PolicyCheckResult{Allowed: true, Action: "allow", PolicyID: name, PolicyName: name, Reason: reason}

	case anchoredenforcer.ClassChallenge:
		// A challenge carries its approval requirement. One that carries none is a
		// decision the contract rejects, so it is withheld as an evaluation failure
		// rather than held with no terms and the queue's default expiry (R3 B-L2).
		if dec.Approval == nil {
			return mapStepUnavailable(anchoredenforcer.CauseEvaluation)
		}
		// TIMEOUT IS DENY, as on the workflow step gate: an approval whose
		// expiry has already passed has timed out before anyone could grant it.
		if dec.Approval != nil && !dec.Approval.ExpiresAt.IsZero() && !dec.Approval.ExpiresAt.After(now) {
			expired := string(contract.ReasonApprovalExpired)
			anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictDeny, expired)
			return mapStepBlocked(expired, approvalExpiredReason(dec.DecisionID, dec.Approval.ExpiresAt))
		}
		name := anchoredenforcer.BlockingConstraint(dec.Determining, anchoredenforcer.UnknownConstraints(dec))
		if name == "" && len(deciding) > 0 {
			name = deciding[0]
		}
		// A BRANCH STEP CANNOT BE HELD (#4249 row 5665091860): nothing resumes an
		// execution paused inside a conditional, so the challenge is withheld
		// here, counted as the planes with no hold count it, and never queued.
		if atBranch {
			withheld := string(contract.ReasonApprovalRequired)
			anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictDeny, withheld)
			if name == "" {
				name = withheld
			}
			return mapStepBlocked(name, branchApprovalRequiredReason())
		}
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictNeedsApproval, reason)
		return &PolicyCheckResult{
			Allowed:    false,
			Action:     "require_approval",
			PolicyID:   name,
			PolicyName: name,
			Reason:     "Policy requires human approval",
			Severity:   deriveSeverityFromResult(&PolicyEvaluationResult{RiskScore: riskScore}),
			hold:       &stepGateHold{decisionID: dec.DecisionID, approval: dec.Approval},
		}

	default:
		// DENY and ERROR both withhold the step: unknown input is never an
		// admission (ADR-065 invariant 4).
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictDeny, reason)
		unknown := anchoredenforcer.UnknownConstraints(dec)
		detail := "Blocked by policy"
		if len(unknown) > 0 && v.Act != nil {
			if reasons := anchoredenforcer.UnknownConstraintReasons(v.Act, unknown, v.IdentityDetail); len(reasons) > 0 {
				detail = strings.Join(reasons, "; ")
			}
		}
		name := anchoredenforcer.BlockingConstraint(dec.Determining, unknown)
		if name == "" && len(deciding) > 0 {
			name = deciding[0]
		}
		return mapStepBlocked(name, detail)
	}
}

// mapStepUnavailable is the fail-closed answer: the step is withheld and the
// cause is named, never run because the plane could not decide.
func mapStepUnavailable(cause string) *PolicyCheckResult {
	anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictUnavailable, cause)
	message := anchoredenforcer.CauseMessages[cause]
	if message == "" {
		message = cause
	}
	return mapStepBlocked("decision_enforcement_unavailable", fmt.Sprintf("%s (%s)", message, cause))
}

// mapStepBlocked is one withheld step, named by the policy or the cause.
func mapStepBlocked(name, reason string) *PolicyCheckResult {
	return &PolicyCheckResult{
		Allowed:    false,
		Action:     "block",
		PolicyID:   name,
		PolicyName: name,
		Reason:     reason,
	}
}
