// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	sharedidentity "axonflow/platform/shared/identity"
)

// ADR-060 (#2989 P3, issue #3051) — segment resolution promoted from
// observability-only (P2, mcp_identity.go's resolveUserSegments) to
// POLICY-AFFECTING on the agent static plane (clientRequestHandler's
// tier-aware policy evaluation, run.go). This file owns exactly that
// promotion; it does not touch the orchestrator dynamic-policy plane (P3b,
// #3052 — out of scope here) nor mcp_identity.go's existing observe-only
// wiring, which keeps its P2 contract unchanged for the fleet/MCP-server
// plane.
//
// #3239 round 2 (fail-closed convergence): resolveSegmentsForPolicy used to
// take a failClosed bool so policyTestHandler (the read-only preview) could
// opt into a fail-OPEN fallback on a resolver error while
// clientRequestHandler (enforcement) fail-closed. That carve-out is gone —
// BOTH callers now fail closed, identically: a preview whose verdict can
// diverge from what enforcement would actually do is more dangerous than a
// preview that occasionally denies loudly. The resolution CONTRACT is now
// the byte-identical twin of platform/orchestrator/segment_policy_gate.go's
// function of the same name, so both packages call the single shared
// implementation in platform/shared/identity — this file is a thin adapter
// supplying the agent's own resolver singleton (getFleetSegmentResolver,
// mcp_identity.go) and its own Prometheus metric names (axonflow_agent_…),
// so the exported series are unchanged by the extraction.

// segmentPolicyFailClosedTotal counts requests DENIED specifically because
// segment resolution failed on the policy-affecting path (ADR-060
// §Fail-closed, locked): a genuine resolver error must never be silently
// treated as "caller has zero segments" (that would be an org-only
// fallback — the exact failure mode this counter exists to make
// observable). Distinct from segmentResolutionTotal{result="error"}
// (segment_resolution_metrics.go, P2), which counts the underlying
// resolution failure itself regardless of which plane observed it; this
// counter tracks the DOWNSTREAM consequence — a request actually denied —
// on the policy-affecting path specifically. After #3239 round 2 this fires
// for BOTH clientRequestHandler (enforcement) and policyTestHandler
// (preview) — there is no longer a fail-open preview path that avoids it.
var segmentPolicyFailClosedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "axonflow_segment_policy_fail_closed_total",
	Help: "ADR-060 (#2989 P3) requests denied because governance-segment resolution failed on the policy-affecting path (fail-closed, never org-only fallback).",
})

// agentSegmentPolicyMetrics adapts this package's existing Prometheus series
// (segmentResolutionTotal / segmentResolutionDurationSeconds, both defined in
// segment_resolution_metrics.go; segmentPolicyFailClosedTotal above) to the
// shared implementation's SegmentPolicyMetrics interface.
type agentSegmentPolicyMetrics struct{}

func (agentSegmentPolicyMetrics) ObserveResolutionResult(result string) {
	segmentResolutionTotal.WithLabelValues(result).Inc()
}

func (agentSegmentPolicyMetrics) ObserveResolutionDuration(seconds float64) {
	segmentResolutionDurationSeconds.Observe(seconds)
}

func (agentSegmentPolicyMetrics) IncFailClosed() {
	segmentPolicyFailClosedTotal.Inc()
}

// resolveSegmentsForPolicy resolves the caller's governance-segment set
// (ADR-060, #2989) for POLICY-AFFECTING consumption on the agent static
// plane — the P3 promotion of P2's observability-only resolution. Thin
// adapter over platform/shared/identity.ResolveSegmentsForPolicy: see that
// function's doc for the full resolver/empty-identity/error contract
// (unconditionally fail-closed on a resolver error; org-only — never a
// failure — on a nil resolver or an empty orgID/email). Both callers
// (clientRequestHandler and policyTestHandler) now share this exact
// contract; see the file doc above for why the preview no longer diverges.
func resolveSegmentsForPolicy(ctx context.Context, orgID, email string) (segmentIDs []string, ok bool) {
	return sharedidentity.ResolveSegmentsForPolicy(ctx, orgID, email, getFleetSegmentResolver(), agentSegmentPolicyMetrics{})
}
