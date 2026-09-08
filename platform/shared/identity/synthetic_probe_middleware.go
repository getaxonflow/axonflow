// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import "net/http"

// SyntheticProbeMiddleware stamps the request context with the synthetic-probe
// fact, ONCE, at the outermost edge of a binary's handler chain.
//
// # WHY THIS EXISTS AND WHY IT IS ONE MIDDLEWARE RATHER THAN N CALL SITES
//
// The identity axis already carries this fact on two channels that between
// them cover the identity adapter: LegacyAuth.Synthetic, set from
// SyntheticProbeHeader on the one function every client-credential path
// traverses, and the context value below, stamped by every ResolveToken caller
// (TestEveryResolveTokenCallerStampsTheSyntheticProbe pins that). Both are
// scoped to AUTHENTICATION. Neither reaches the policy engines.
//
// The DECISION axis needs the same fact several layers further in.
// planeshadow.Observe is called from inside UnifiedPolicyEngine.EvaluateRequest,
// the orchestrator's dynamic engine and the agent's proxy-tier evaluation. Those
// receive a context and no request, they are reached from nineteen call sites
// across two binaries, and the contexts the auth layer derives for ResolveToken
// are LOCAL to that call - r.Context() downstream is unstamped. So without this,
// every canary comparison on every plane would be filed under synthetic="false",
// into the ORGANIC volume the ADR-065 coverage gate reads. A wrong number, not a
// crash (#3817).
//
// Stamping per handler is the shape a census exists to police, and this axis
// would need a bigger census than the last one: eleven Authenticate callers,
// twelve planes, two binaries. Stamping ONCE at the root needs no census at all,
// because there is no second site to forget - which is the same argument
// shadowobserve.go makes for emitting one observation from inside the shared
// engine rather than from each of its callers. TestTheRootHandlerStampsTheSynthetic
// Probe (agent) and its orchestrator twin pin the wrap itself, which is the one
// thing that CAN be forgotten.
//
// # IT IS UNCONDITIONAL, AND THAT IS DELIBERATE
//
// The stamp is applied to every request, including unauthenticated ones and
// including requests on a deployment with every shadow mode off. It costs one
// header lookup and one context.WithValue per request. Gating it on the shadow
// mode would put a mode read on the request path outside effectiveMode, which is
// the single-reader invariant planeshadow's AST census enforces - and the same
// trade authenticator.go already refused for LegacyAuth.Synthetic, in the same
// words.
//
// # ITS FORGERY DIRECTION IS SAFE
//
// The header is caller-assertable. A tenant that tagged its own traffic
// synthetic would EXCLUDE that traffic from the volume floors, making the
// coverage gate harder to satisfy, never easier; it cannot manufacture coverage,
// because a synthetic comparison is still a comparison in the same divergence
// class. See LegacyAuth.Synthetic for the full argument. Nothing downstream of
// this reads the value for any purpose but a metric label - planeshadow.Observe
// returns void, and the value is never consulted by any admission or policy
// decision.
//
// A nil `next` is returned as nil rather than wrapped, so a caller that has not
// built its router yet fails at the mux rather than inside a middleware.
func SyntheticProbeMiddleware(next http.Handler) http.Handler {
	if next == nil {
		return nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(ContextWithSyntheticProbe(
			r.Context(), IsSyntheticProbeHeader(r.Header.Get(SyntheticProbeHeader)))))
	})
}
