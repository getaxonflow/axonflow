// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ADR-060 (#2989 P3, issue #3051) — segment resolution promoted from
// observability-only (P2, mcp_identity.go's resolveUserSegments) to
// POLICY-AFFECTING on the agent static plane (clientRequestHandler's
// tier-aware policy evaluation, run.go). This file owns exactly that
// promotion; it does not touch the orchestrator dynamic-policy plane (P3b,
// #3052 — out of scope here) nor mcp_identity.go's existing observe-only
// wiring, which keeps its P2 contract unchanged for the fleet/MCP-server
// plane.

// segmentPolicyFailClosedTotal counts requests DENIED specifically because
// segment resolution failed on the policy-affecting path (ADR-060
// §Fail-closed, locked): a genuine resolver error must never be silently
// treated as "caller has zero segments" (that would be an org-only
// fallback — the exact failure mode this counter exists to make
// observable). Distinct from segmentResolutionTotal{result="error"}
// (segment_resolution_metrics.go, P2), which counts the underlying
// resolution failure itself regardless of which plane observed it; this
// counter tracks the DOWNSTREAM consequence — a request actually denied —
// on the policy-affecting path specifically.
var segmentPolicyFailClosedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "axonflow_segment_policy_fail_closed_total",
	Help: "ADR-060 (#2989 P3) requests denied because governance-segment resolution failed on the policy-affecting path (fail-closed, never org-only fallback).",
})

// resolveSegmentsForPolicy resolves the caller's governance-segment set
// (ADR-060, #2989) for POLICY-AFFECTING consumption on the agent static
// plane — the P3 promotion of P2's observability-only resolution.
//
// Contract (deliberately the OPPOSITE of mcp_identity.go's
// resolveUserSegments, which must never reject a request over a segment
// lookup failure — see that function's doc):
//   - resolver unavailable (nil — community build, or Enterprise without
//     SCIM/segment resolution configured): returns (nil, true). This is
//     NOT a failure; it is "the capability does not apply here," and the
//     caller proceeds org-only, identical to every pre-P3 request. A
//     community deployment must never be denied over a capability it
//     never had.
//   - resolution SUCCEEDS with zero group memberships: returns (nil, true).
//     Zero segments is a legitimate outcome (ADR-060) — the caller proceeds
//     org-only, same as today.
//   - resolution SUCCEEDS with N>0 segments: returns (ids, true).
//   - resolution ERRORS (a genuine storage/query failure — segment_cache.go
//     never caches an error, so this is always a fresh failure, not a
//     stale cached one): returns (nil, false). The caller MUST deny the
//     whole request — ADR-060 §Fail-closed is explicit that a segment
//     resolution failure must never be papered over as "proceed org-only,"
//     because that IS the exact fail-open bypass ADR-060 exists to close
//     (a caller cannot escape a stricter segment's policy by however this
//     failure occurred).
//
// failClosed tells resolveSegmentsForPolicy which contract the caller is
// operating under, purely so the error-path log line reflects what actually
// happens next: clientRequestHandler passes true (a resolver error DENIES
// the request per ADR-060 §Fail-closed); policyTestHandler passes false (a
// resolver error there is NOT fail-closed — it falls back to an org-only
// simulation and still returns 200, so logging "DENYING" would mislead
// on-call). This does not change the resolver's return contract (ok=false
// on error regardless of failClosed) — it only changes log wording.
func resolveSegmentsForPolicy(ctx context.Context, orgID, email string, failClosed bool) (segmentIDs []string, ok bool) {
	resolver := getFleetSegmentResolver()
	if resolver == nil {
		return nil, true // capability unavailable — not a failure, proceed org-only
	}

	// No per-user identity on this request. On the agent static plane
	// (clientRequestHandler) `email` comes from the request's user_token, and a
	// legitimate TENANT-kind token (the whole self-hosted client-application
	// pattern — see scripts/generate-jwt.sh's default kind — plus every
	// community/community-SaaS synthetic identity) carries NO email claim. An
	// absent email is therefore "there is no user to resolve segments FOR," not
	// a storage failure: it is capability-not-applicable, identical to a nil
	// resolver, and must proceed org-only.
	//
	// This is NOT a fail-open hole in ADR-060 §Fail-closed. That contract exists
	// so a user who BELONGS to a stricter segment cannot ESCAPE it by inducing a
	// resolution failure. Segment membership is keyed on the user's SCIM email
	// (scim_users.email -> scim_group_members); with no email there is no
	// membership to escape, and this is exactly the org-only outcome every such
	// request had before ADR-060 P3 promoted resolution to policy-affecting.
	// Feeding an empty email into the resolver instead makes ResolveRole return
	// its "requires an email" error, which failClosed then converts into a hard
	// DENY of every tenant-token request — the #travel-us production outage this
	// guard closes. A genuine resolver failure (a NON-empty email whose lookup
	// errors) still fails closed below, unchanged.
	if email == "" {
		return nil, true
	}

	start := time.Now()
	resolved, err := resolver.Resolve(ctx, orgID, email)
	latency := time.Since(start)
	if err != nil {
		segmentResolutionTotal.WithLabelValues("error").Inc()
		if failClosed {
			segmentPolicyFailClosedTotal.Inc()
			log.Printf("[Policy] DENYING (fail-closed, ADR-060 #3051): segment resolution failed org=%q latency=%s: %v",
				orgID, latency, err)
		} else {
			log.Printf("[Policy] falling back to org-only (fail-open, simulator): segment resolution failed org=%q latency=%s: %v",
				orgID, latency, err)
		}
		return nil, false
	}
	segmentResolutionDurationSeconds.Observe(latency.Seconds())

	if len(resolved.Segments) == 0 {
		segmentResolutionTotal.WithLabelValues("empty").Inc()
		return nil, true
	}

	segmentResolutionTotal.WithLabelValues("resolved").Inc()
	ids := make([]string, len(resolved.Segments))
	for i, s := range resolved.Segments {
		ids[i] = string(s.ID)
	}
	return ids, true
}
