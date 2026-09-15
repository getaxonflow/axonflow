// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// routeEffects are the LLM routing hints (#883) the dynamic rows that apply to a
// request carry in their route actions: a preferred provider, the reason, and
// the providers every applying row allows.
//
// A ROUTE EFFECT IS FACT-LAYER OUTPUT (#4254, PRD v11 §1.2 ruling R2). It steers
// which provider serves a request the engine has already admitted; it never
// admits, refuses or holds one, and it is never stated to the engine as an
// attribute.
type routeEffects struct {
	PreferredProvider string
	RoutingReason     string
	AllowedProviders  []string
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
// allowed_providers intersect across applying rows, so the most restrictive set
// wins. An intersection that comes out empty is replaced by the next applying
// row's list, exactly as the engine has always merged it.
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
	if len(r.AllowedProviders) == 0 {
		r.AllowedProviders = policyAllowed
		return
	}
	intersection := make([]string, 0)
	for _, p := range r.AllowedProviders {
		for _, ap := range policyAllowed {
			if p == ap {
				intersection = append(intersection, p)
				break
			}
		}
	}
	r.AllowedProviders = intersection
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
