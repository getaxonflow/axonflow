// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "sort"

// routeEffects are the LLM routing hints (#883) the dynamic rows that apply to a
// request carry in their route actions: a preferred provider, the reason, and
// the providers every applying row allows.
//
// A ROUTE EFFECT IS FACT-LAYER OUTPUT (#4254, PRD v11 §1.2 ruling R2). It steers
// which provider serves a request the engine has already admitted; it never
// admits or holds one, and it is never stated to the engine as an attribute. The
// one refusal it carries is NothingPermitted: a restriction every applying row
// agreed on that permits no provider at all. The seam and the preview refuse
// that request themselves, before any LLM call, because every reader downstream
// reads an empty allowed list as "no restriction" (llm/router.go, the injection
// in run.go) (#4249 row 5698088094).
type routeEffects struct {
	PreferredProvider string
	RoutingReason     string
	// AllowedProviders is the sorted set every applying row allows. It is
	// meaningful only when Restricted is true.
	AllowedProviders []string
	// Restricted is true once any applying row declared a non-empty
	// allowed_providers list. It is what tells "no row restricts" apart from "the
	// rows' restrictions permit nothing", which an empty AllowedProviders alone
	// cannot say.
	Restricted bool
	// SegmentNotEstablished names WHY nothing is permitted: the caller's segment
	// membership is not established, the organization's unsegmented rows alone
	// would still permit a provider, and it is the segment-scoped rows applied to
	// such a caller that took the last one away (ADR-067 Decision 4 step 1b). A
	// validated user token could then change the answer. When the unsegmented
	// rows alone already permit nothing, no identity changes it, and the refusal
	// is no_compliant_provider.
	SegmentNotEstablished bool
}

// reasonNoCompliantProvider is the reason a request is refused for when the
// applying rows' allowed_providers intersect to nothing. Named after the
// router's own "no compliant providers available", which is what the caller
// would otherwise have got had the list reached it non-empty; the contract's
// obligation_conflict is not reused, because no engine obligation decided this.
const reasonNoCompliantProvider = "no_compliant_provider"

// reasonSegmentNotEstablished is the same refusal for a caller whose segment
// membership is not established, so every segment's route restrictions applied
// (ADR-067 Decision 4 step 1b names it).
const reasonSegmentNotEstablished = "segment_not_established"

// blockedByRouteLayer is PolicyEvaluationResult.BlockedBy for a refusal the
// route layer made after the engine allowed: the audit row keeps the engine's
// decision_id and engine as provenance, and states this beside
// policy_decision=blocked so the row never reads as an engine deny.
const blockedByRouteLayer = "route_layer"

// NothingPermitted reports that at least one applying row restricts the
// providers and the restrictions together permit none. Such a request is
// refused: an empty allow-list never reaches a reader, which would take it for
// "unrestricted".
func (r routeEffects) NothingPermitted() bool {
	return r.Restricted && len(r.AllowedProviders) == 0
}

// apply merges one applying row's route action config into the effects. It is
// the ONE merge: the dynamic engine's evaluation and the fact producer both call
// it, so the two cannot drift while both exist.
//
// THE SHIPPED WINNER RULE IS PRESERVED ON PURPOSE. Rows are merged in the order
// evaluation walks them (sortedDynamicPolicyEntries: priority descending, then
// newest first, then cache key), and each applying row OVERWRITES the preferred
// provider and the reason, so the LAST applying row wins them: the lowest
// priority. Whether the highest-priority row should win instead is decided in
// v11.1.0, not here:
// https://github.com/getaxonflow/axonflow-enterprise/issues/4249#issuecomment-5668036520
//
// allowed_providers intersect across applying rows, and the result is a SET: the
// same rows give the same sorted list in any order, and once the intersection is
// empty it stays empty (NothingPermitted). This retires the rule this comment
// used to state, "An intersection that comes out empty is replaced by the next
// applying row's list, exactly as the engine has always merged it." That rule
// was a widening: two rows allowing disjoint providers left NO restriction at
// all, a third row made its own list the whole restriction, and so what a
// compliance list permitted depended on how many rows applied and in what order
// (#4249 row 5698088094).
//
// A row that declares allowed_providers as an empty list, or as no list, declares
// no restriction, the reading legacycompile gives the same row ("a route action
// naming no allowed_providers restricts nothing",
// platform/decision/legacycompile/dynamic.go). An operator restricts to nothing
// by writing rows whose lists share no provider, not by writing [].
func (r *routeEffects) apply(config map[string]interface{}) {
	if preferred, ok := config["preferred_provider"].(string); ok && preferred != "" {
		r.PreferredProvider = preferred
	}
	if reason, ok := config["reason"].(string); ok {
		r.RoutingReason = reason
	}
	allowedRaw, ok := config["allowed_providers"]
	if !ok {
		return
	}
	var policyAllowed []string
	switch v := allowedRaw.(type) {
	case []interface{}:
		for _, p := range v {
			if ps, ok := p.(string); ok {
				policyAllowed = append(policyAllowed, ps)
			}
		}
	case []string:
		policyAllowed = v
	}
	if len(policyAllowed) == 0 {
		return
	}
	declared := make(map[string]struct{}, len(policyAllowed))
	for _, p := range policyAllowed {
		declared[p] = struct{}{}
	}
	if r.Restricted {
		kept := make(map[string]struct{}, len(r.AllowedProviders))
		for _, p := range r.AllowedProviders {
			if _, ok := declared[p]; ok {
				kept[p] = struct{}{}
			}
		}
		declared = kept
	}
	intersection := make([]string, 0, len(declared))
	for p := range declared {
		intersection = append(intersection, p)
	}
	sort.Strings(intersection)
	r.AllowedProviders = intersection
	r.Restricted = true
}

// rowCarriesRouteAction reports whether row has a route action, the only rows
// whose applicability the fact producer evaluates as a whole.
func rowCarriesRouteAction(row DynamicPolicy) bool {
	for _, a := range row.Actions {
		if a.Type == "route" {
			return true
		}
	}
	return false
}
