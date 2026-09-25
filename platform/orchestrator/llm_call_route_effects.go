// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// THE ORGANIZATION'S ROUTE ROWS BIND EVERY LLM CALL THE ORCHESTRATOR MAKES FOR
// IT, not only /api/v1/process (#4249 rows 5701303521 and 5774077156).
//
// /api/v1/process decides its route (decideRouteRequest) and hands the router
// the applying rows' allowed and preferred providers through the request
// context (run.go, policy_allowed_providers). A multi-agent plan's llm-call
// step and plan generation's two calls built their own requests without them,
// so a plan's prompts reached whatever provider the router picked, whatever
// the organization's rows allowed.
//
// applyLLMCallRoutes is the one place those calls take the route effects. It
// runs at the call, over the prompt the call sends, and not in a step's
// dispatch:
//   - every path that runs a step reaches the step's processor, whatever
//     decided the step before it ran;
//   - a resumed plan never re-runs the plan-level decision;
//   - the plan-level decision is made over the plan's query, not over what a
//     step sends.
//
// The effects come from the producer /api/v1/process decides from
// (routeRequestFactProducer), which presents content, so a route row
// conditioned on content applies to a step's prompt exactly as to a query.
// They are the producer's second output and never an attribute: taking them
// here changes no verdict.
//
// A REFUSAL IS AUDITED, on every path (recordLLMCallRouteRefusal): one row,
// policy_decision blocked with blocked_by route_layer and the reason, as
// /api/v1/process records the same refusal.
//
// Not covered, stated: POST /api/v1/llm-providers/{name}/test
// (llm_provider_api_handlers.go, handleTestProvider) calls a provider directly
// with the caller's prompt through a tenant-registered key. It is a
// bring-your-own-key smoke test of that provider, not a call on the
// organization's route, so the route rows do not apply to it.

import (
	"context"
	"errors"
	"fmt"
)

// llmCallRouteRefusal is an LLM call the organization's route rows refuse, or
// whose route could not be established. Reason is the code /api/v1/process
// names the same refusal with: no_compliant_provider, segment_not_established,
// segment_resolution_failed, or decision_enforcement_unavailable.
type llmCallRouteRefusal struct {
	Reason string
	detail string
}

func (r *llmCallRouteRefusal) Error() string {
	return r.Reason + ": " + r.detail
}

// applyLLMCallRoutes decides the route effects for presented, the request whose
// organization, user and prompt the call is made for, and sets them on target,
// the request the router is handed. They are one request for a step's call;
// plan generation presents its caller's identity while its LLM request keeps
// its own.
//
// An effect set that permits no provider REFUSES, never falling back to the
// default provider: every reader downstream takes an empty allow-list for
// "unrestricted" (routeEffects.NothingPermitted, #4348's rule). A route that
// cannot be established refuses too (fail-closed). With no applying route row,
// target is unchanged.
func applyLLMCallRoutes(ctx context.Context, presented OrchestratorRequest, target *OrchestratorRequest) error {
	producer, err := routeRequestFactProducer()
	var routes routeEffects
	if err == nil {
		_, routes, err = producer.Produce(ctx, presented)
	}
	if err != nil {
		if errors.Is(err, errDynamicFactsUnavailable) {
			return recordLLMCallRouteRefusal(ctx, presented, &llmCallRouteRefusal{Reason: "segment_resolution_failed",
				detail: "the organization's route rows could not be resolved, so no provider is called (fail-closed)"})
		}
		return recordLLMCallRouteRefusal(ctx, presented, &llmCallRouteRefusal{Reason: "decision_enforcement_unavailable",
			detail: fmt.Sprintf("the organization's route rows could not be read, so no provider is called (fail-closed): %v", err)})
	}
	if routes.NothingPermitted() {
		reason := reasonNoCompliantProvider
		if routes.SegmentNotEstablished {
			reason = reasonSegmentNotEstablished
		}
		return recordLLMCallRouteRefusal(ctx, presented, &llmCallRouteRefusal{Reason: reason,
			detail: "the organization's route rows permit no provider for this call"})
	}
	// The condition /api/v1/process injects its hints under (run.go).
	if routes.PreferredProvider == "" && len(routes.AllowedProviders) == 0 {
		return nil
	}
	if target.Context == nil {
		target.Context = map[string]interface{}{}
	}
	// The keys and types /api/v1/process sets and llm_request_adapter.go reads.
	if routes.PreferredProvider != "" {
		target.Context["policy_preferred_provider"] = routes.PreferredProvider
	}
	if len(routes.AllowedProviders) > 0 {
		target.Context["policy_allowed_providers"] = append([]string(nil), routes.AllowedProviders...)
	}
	if routes.RoutingReason != "" {
		target.Context["policy_routing_reason"] = routes.RoutingReason
	}
	return nil
}

// recordLLMCallRouteRefusal writes the refusal's audit row and returns it. The
// row is /api/v1/process's for the same refusal (routeRequestWithheld):
// policy_decision blocked, blocked_by route_layer, the reason as the applied
// policy and as "blocked: <reason>". It carries no anchored decision stamp: the
// route layer refuses after, and apart from, any engine decision. A call made
// for a plan carries its organization on the user only, so the row takes it
// from there.
func recordLLMCallRouteRefusal(ctx context.Context, presented OrchestratorRequest, refusal *llmCallRouteRefusal) error {
	if auditLogger != nil {
		row := presented
		if row.Client.OrgID == "" {
			row.Client.OrgID = row.User.OrgID
		}
		auditLogger.LogBlockedRequest(ctx, row, &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{refusal.Reason},
			RequiredActions: []string{"blocked: " + refusal.Reason},
			BlockedBy:       blockedByRouteLayer,
		}, nil)
	}
	return refusal
}
