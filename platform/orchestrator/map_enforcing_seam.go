// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/anchoredenforcer"
)

// THE MULTI-AGENT PLANE DECIDES ON THE ANCHORED ENGINE (#4254).
//
// Each step the in-memory HITL workflow engine is about to run is presented to
// the engine as the shipped action its step type maps to (actionForMAPStep),
// for the client credential the agent authenticated, with the dynamic matcher's
// facts, and with NO CONTENT. The checker's query used to be a label it built
// from the step's name and type, never content a caller presented, so it is not
// scanned: the plane presents no content, stated like the workflow step gate.
//
// THE CHECKER NEVER RETURNS AN ERROR. The engine that calls it proceeds when a
// checker errors (HITLWorkflowEngine.ExecuteWithHITL documents that fail-open),
// so every cause this plane cannot decide through is a block that names the
// cause, and the step never runs: no enforcer, an unavailable verdict, a subject
// the identity plane refuses, and a step type the map does not name. The
// engine's fail-open arm stays, and no production checker reaches it.
//
// A CHALLENGE HOLDS, in memory: the step pauses for approval carrying the typed
// approval requirement exactly as the workflow step gate's queue row carries it,
// with plane "map". An approval that timed out before the pause withholds the
// step as approval_expired instead.

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
	mapFactsOnce sync.Once
	mapFacts     *dynamicFactProducer
	mapFactsErr  error

	newMAPFactProducer = func() (*dynamicFactProducer, error) {
		if dynamicPolicyEngine == nil {
			return nil, errors.New("the dynamic policy engine is not wired, so this plane's facts cannot be produced")
		}
		p, err := newDynamicFactProducer(dynamicPolicyEngine.ListActivePoliciesForTenant)
		if err != nil {
			return nil, err
		}
		// THE CHECKER PRESENTS NO CONTENT (see the file comment).
		p.presentsNoContent = true
		return p, nil
	}
)

func mapFactProducer() (*dynamicFactProducer, error) {
	mapFactsOnce.Do(func() { mapFacts, mapFactsErr = newMAPFactProducer() })
	return mapFacts, mapFactsErr
}

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
func mapStepPolicyCheck(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) *PolicyCheckResult {
	result, verdict := mapStepDecide(ctx, step, execution)
	if result != nil {
		result.decided = anchoredDecisionFor(mapSeamScope, verdict)
	}
	return result
}

// mapStepDecide is mapStepPolicyCheck's decision, with the verdict the engine
// gave: nil when the plane failed closed before the engine answered.
func mapStepDecide(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) (*PolicyCheckResult, *anchoredenforcer.Verdict) {
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
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "unavailable", anchoredenforcer.CauseSubjectUnverifiable)
		return mapStepBlocked(anchoredenforcer.CauseSubjectUnverifiable,
			anchoredenforcer.CauseSubjectUnverifiable+": no credential subject was installed for this execution"), nil
	}
	var user UserContext
	executionID := ""
	if execution != nil {
		user, executionID = execution.UserContext, execution.ID
	}
	req := OrchestratorRequest{
		RequestID:   executionID,
		RequestType: "map_step",
		User:        user,
		Context: map[string]interface{}{
			"step_name":     step.Name,
			"step_type":     step.Type,
			"step_provider": step.Provider,
			"step_model":    step.Model,
		},
	}
	producer, err := mapFactProducer()
	var facts contract.AttributeSet
	if err == nil {
		facts, _, err = producer.Produce(ctx, req)
	}
	if err != nil {
		anchoredenforcer.FailClosed(mapSeamScope, user.OrgID, anchoredenforcer.CauseEvaluation, err)
		if errors.Is(err, errDynamicFactsUnavailable) {
			anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "unavailable", anchoredenforcer.CauseEvaluation)
			return mapStepBlocked("segment_resolution_failed", "segment resolution unavailable - request denied (fail-closed, ADR-060 #2989 P3b)"), nil
		}
		return mapStepUnavailable(anchoredenforcer.CauseEvaluation), nil
	}
	action, actionErr := actionForMAPStep(step.Type)

	v := enforcer.Evaluate(ctx, anchoredenforcer.Call{
		Scope:     mapSeamScope,
		OrgID:     user.OrgID,
		RequestID: executionID,
		Action:    action,
		ActionErr: actionErr,
		Subject:   subject,
		// No content, stated as the plane's contract rather than computed.
		Query:        "",
		EmptyContent: true,
		Facts:        facts,
	})

	switch {
	case v.Unavailable != "":
		return mapStepUnavailable(v.Unavailable), &v
	case v.Refusal != nil:
		reason := strings.ToLower(string(v.Refusal.Reason))
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "deny", reason)
		return mapStepBlocked(reason, reason+": "+v.Refusal.Detail), &v
	}
	return mapStepFromDecision(v, dbRiskCalculator.CalculateRiskScore(req), time.Now()), &v
}

// mapStepFromDecision answers the engine's decision in the checker's terms.
func mapStepFromDecision(v anchoredenforcer.Verdict, riskScore float64, now time.Time) *PolicyCheckResult {
	dec := v.Decision
	if dec == nil {
		return mapStepUnavailable(anchoredenforcer.CauseEvaluation)
	}
	deciding := anchoredenforcer.DecidingPolicies(dec)
	reason := string(dec.Reason)

	switch dec.State {
	case contract.StateAllow:
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "allow", reason)
		// An allow is a result, not nil: its decision is recorded on the step's
		// audit row like every other one (PRD v11 §5.7), and the step runs.
		name := ""
		if len(deciding) > 0 {
			name = deciding[0]
		}
		return &PolicyCheckResult{Allowed: true, Action: "allow", PolicyID: name, PolicyName: name, Reason: reason}

	case contract.StateChallenge:
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
			anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "deny", expired)
			return mapStepBlocked(expired, approvalExpiredReason(dec.DecisionID, dec.Approval.ExpiresAt))
		}
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "needs_approval", reason)
		name := anchoredenforcer.BlockingConstraint(dec.Determining, anchoredenforcer.UnknownConstraints(dec))
		if name == "" && len(deciding) > 0 {
			name = deciding[0]
		}
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
		anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "deny", reason)
		unknown := anchoredenforcer.UnknownConstraints(dec)
		detail := "Blocked by policy"
		if len(unknown) > 0 && v.Act != nil {
			if reasons := anchoredenforcer.UnknownConstraintReasons(v.Act, unknown); len(reasons) > 0 {
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
	anchoredenforcer.RecordEnforcement(mapSeamScope, anchoredenforcer.EngineAnchored, "unavailable", cause)
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
