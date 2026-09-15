// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/anchoredenforcer"
	sharedaudit "axonflow/platform/shared/audit"
)

// THE TWO WORKFLOW CONTROL REQUEST ROUTES DECIDE ON THE ANCHORED ENGINE (#4254).
//
// /api/v1/process and /api/v1/plan/execute are call sites of the workflow
// control plane (legacy_call_sites.tsv), so they decide under the workflow step
// gate's scope. Unlike the step gate they PRESENT CONTENT - the request's query,
// or the stored plan's - so their facts come from a producer that runs every
// dynamic row's content detector over it, never from the step gate's no-content
// producer.
//
// NEITHER ROUTE CAN HOLD. A request answered in one round trip has no pending
// state to return to, so a challenge withholds it with the contract's own reason,
// approval_required, and nothing is queued (PRD v11 §1 item 13). It is recorded
// as a deny, as the agent records a challenge on a plane that cannot hold.
//
// A ROUTE EFFECT STAYS FACT-LAYER OUTPUT (PRD v11 §1.2 ruling R2). The routing
// hints of the rows that apply ride on an admitted request's result, where
// /api/v1/process has always read them for the LLM router; the engine never
// reads them.

// The actions the two routes present.
const (
	processRouteAction     = authoringcatalog.ActionLLMCompletion
	planExecuteRouteAction = authoringcatalog.ActionAgentInvoke
)

// The engine and verdict a withheld route request's envelope names, in the
// vocabulary the response plane's envelope already uses.
const (
	routeRequestEngine         = anchoredenforcer.EngineAnchored
	routeRequestVerdictBlocked = string(sharedaudit.DecisionBlocked)
)

// routeFactSource produces a route request's facts, and the route effects of
// the rows that apply to it. The production source is the dynamic fact
// producer; a test installs one that records the request the facts were
// produced for, which is the request the plane decided.
type routeFactSource interface {
	Produce(ctx context.Context, req OrchestratorRequest) (contract.AttributeSet, routeEffects, error)
}

// The fact source the two routes decide from, built once per process from the
// dynamic engine the process wired. Replaceable so a test can install its own.
var (
	routeRequestFactsOnce sync.Once
	routeRequestFacts     routeFactSource
	routeRequestFactsErr  error

	newRouteRequestFactProducer = func() (routeFactSource, error) {
		if dynamicPolicyEngine == nil {
			return nil, errors.New("the dynamic policy engine is not wired, so this plane's facts cannot be produced")
		}
		// THESE ROUTES PRESENT CONTENT: no presentsNoContent here.
		p, err := newDynamicFactProducer(dynamicPolicyEngine.ListActivePoliciesForTenant)
		if err != nil {
			return nil, err
		}
		return p, nil
	}
)

func routeRequestFactProducer() (routeFactSource, error) {
	routeRequestFactsOnce.Do(func() { routeRequestFacts, routeRequestFactsErr = newRouteRequestFactProducer() })
	return routeRequestFacts, routeRequestFactsErr
}

// routeRequestDecision is one route request's answer.
type routeRequestDecision struct {
	// result is what the response's policy_info and the audit row carry.
	// Allowed is false exactly when the request is withheld, and a withheld
	// result names why in required_actions, as "blocked: <reason>".
	result       *PolicyEvaluationResult
	subjectType  string
	policyBundle string
	// decisionID is the engine's decision id, empty when the engine reached no
	// decision; the refused route's audit row records it (PRD v11 §5.7).
	decisionID string
}

// decideRouteRequest decides req on the workflow control plane as action, for
// the client credential the agent authenticated (h).
//
// It FAILS CLOSED: a route that cannot reach a verdict withholds the request and
// names the dependency that was unavailable.
func decideRouteRequest(ctx context.Context, h http.Header, req OrchestratorRequest, action string) routeRequestDecision {
	d := decideRouteRequestOnce(ctx, h, req, action)
	// The platform's risk floor for the request, which the audit row records.
	d.result.RiskScore = dbRiskCalculator.CalculateRiskScore(req)
	return d
}

func decideRouteRequestOnce(ctx context.Context, h http.Header, req OrchestratorRequest, action string) routeRequestDecision {
	enforcer := orchestratorEnforcer()
	if enforcer == nil {
		return routeRequestUnavailable(anchoredenforcer.CauseNotWired)
	}
	orgID := req.Client.OrgID
	if orgID == "" {
		orgID = req.User.OrgID
	}
	producer, err := routeRequestFactProducer()
	var facts contract.AttributeSet
	var routes routeEffects
	if err == nil {
		facts, routes, err = producer.Produce(ctx, req)
	}
	if err != nil {
		anchoredenforcer.FailClosed(wcpSeamScope, orgID, anchoredenforcer.CauseEvaluation, err)
		if errors.Is(err, errDynamicFactsUnavailable) {
			// The id every route answers a segment-resolution outage by.
			anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "unavailable", anchoredenforcer.CauseEvaluation)
			d := routeRequestWithheld([]string{"segment_resolution_failed"}, "segment_resolution_failed")
			d.result.EvaluationError = true
			return d
		}
		return routeRequestUnavailable(anchoredenforcer.CauseEvaluation)
	}

	v := enforcer.Evaluate(ctx, anchoredenforcer.Call{
		Scope:     wcpSeamScope,
		OrgID:     orgID,
		RequestID: req.RequestID,
		Action:    action,
		Subject:   headerCredentialSubject(h),
		Query:     req.Query,
		Facts:     facts,
	})
	d := routeRequestFromVerdict(v, routes)
	d.subjectType = v.SubjectType
	if v.Act != nil {
		d.policyBundle = v.Act.PolicyBundle
	}
	if v.Decision != nil {
		d.decisionID = v.Decision.DecisionID
	}
	return d
}

// routeRequestFromVerdict answers the engine's verdict in the routes' terms.
func routeRequestFromVerdict(v anchoredenforcer.Verdict, routes routeEffects) routeRequestDecision {
	switch {
	case v.Unavailable != "":
		return routeRequestUnavailable(v.Unavailable)
	case v.Refusal != nil:
		reason := strings.ToLower(string(v.Refusal.Reason))
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "deny", reason)
		return routeRequestWithheld([]string{reason}, reason)
	case v.Decision == nil:
		return routeRequestUnavailable(anchoredenforcer.CauseEvaluation)
	}
	dec := v.Decision
	deciding := anchoredenforcer.DecidingPolicies(dec)
	unknown := anchoredenforcer.UnknownConstraints(dec)
	named := deciding
	if blocking := anchoredenforcer.BlockingConstraint(dec.Determining, unknown); blocking != "" {
		named = append([]string{blocking}, deciding...)
	}
	named = dedupeStepGateIDs(named)

	switch dec.State {
	case contract.StateAllow:
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "allow", string(dec.Reason))
		return routeRequestDecision{result: &PolicyEvaluationResult{
			Allowed:           true,
			AppliedPolicies:   deciding,
			RequiredActions:   []string{},
			PreferredProvider: routes.PreferredProvider,
			AllowedProviders:  routes.AllowedProviders,
			RoutingReason:     routes.RoutingReason,
		}}

	case contract.StateChallenge:
		// A challenge carries its approval requirement. One that carries none is a
		// decision the contract rejects, so it is withheld as an evaluation failure
		// rather than held with no terms and the queue's default expiry (R3 B-L2).
		if dec.Approval == nil {
			return routeRequestUnavailable(anchoredenforcer.CauseEvaluation)
		}
		// NEITHER ROUTE CAN HOLD (see the file comment): the challenge withholds
		// the request by the contract's reason, and nothing is queued.
		reason := string(contract.ReasonApprovalRequired)
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "deny", reason)
		if len(named) == 0 {
			named = []string{reason}
		}
		// The one sentence every plane with no hold answers a challenge with: the
		// reason code first, then the plane (PRD v11 §1 item 13).
		return routeRequestWithheld(named, anchoredenforcer.ApprovalRequiredReason(wcpSeamScope))

	default:
		// DENY and ERROR both withhold the request: unknown input is never an
		// admission (ADR-065 invariant 4).
		anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "deny", string(dec.Reason))
		reasons := []string{string(dec.Reason)}
		if len(unknown) > 0 && v.Act != nil {
			reasons = append(reasons, anchoredenforcer.UnknownConstraintReasons(v.Act, unknown)...)
		}
		return routeRequestWithheld(named, reasons...)
	}
}

// routeRequestUnavailable is the fail-closed answer, naming the cause.
func routeRequestUnavailable(cause string) routeRequestDecision {
	anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "unavailable", cause)
	d := routeRequestWithheld([]string{"decision_enforcement_unavailable"}, cause)
	d.result.EvaluationError = true
	return d
}

// routeRequestWithheld is one withheld request, naming the policies or the
// cause, and each reason as "blocked: <reason>".
func routeRequestWithheld(ids []string, reasons ...string) routeRequestDecision {
	actions := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		actions = append(actions, "blocked: "+reason)
	}
	return routeRequestDecision{result: &PolicyEvaluationResult{
		Allowed:         false,
		AppliedPolicies: ids,
		RequiredActions: actions,
	}}
}
