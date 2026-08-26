// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ADR-060 (#2989) segment-resolution observability, on the fleet/MCP-server
// plane. One lookup (resolveUserSegments, segment_policy_gate.go) serves two
// call populations with different jobs:
//   - "session_auth": the resolution at handleMCPInitialize / resolveMCPSession
//     that runs once per resolved AUTH (authenticateMCPSession succeeding),
//     observability-only — its result is not read for any decision (#3473).
//     This is NOT reliably "once per MCP session": resolveMCPSession only
//     amortizes it across a session's calls when the caller reuses the
//     Mcp-Session-Id header and hits the cache. The stateless/hook-path
//     callers (the Claude Code/Desktop plugin fleet, #2753) send no such
//     header — every one of their requests is a cache miss, so for THAT
//     traffic this phase runs once per request, same as enforcement.
//   - "enforcement": the fresh-per-tools/call resolution
//     (resolveMCPServerSegmentsForPolicy, mcp_identity.go) and every other
//     policy-affecting call site (run.go, gateway_handlers.go), which IS
//     consumed for a verdict and fails closed on error.
//
// Both populations increment the SAME segmentResolutionTotal counter, so the
// "phase" label (#3473) is what keeps them separable — the two have opposite
// error contracts, and for check_policy/check_output traffic from a
// stateless caller the volumes run close to 1:1 (see above), which is
// exactly why "phase" carries a real distinction result alone does not:
// collapsing them into one unlabeled series would make it impossible to
// tell an observability-only failure from an enforcement-phase denial.
type segmentResolutionPhase string

const (
	segmentResolutionPhaseSessionAuth segmentResolutionPhase = "session_auth"
	segmentResolutionPhaseEnforcement segmentResolutionPhase = "enforcement"
	// segmentResolutionPhasePreview labels a call site that SIMULATES a
	// verdict without denying anything — the portal's policy-test preview.
	// It shares the enforcement phase's shape (the caller reads `ok`) but not
	// its consequence: nothing is refused, the caller gets 200, and no
	// production request is affected. It therefore takes the session_auth
	// phase's metric behaviour — no segmentPolicyFailClosedTotal increment and
	// a WARNING rather than "DENYING" — because that counter's Help text says
	// it counts requests DENIED, and a preview denies none. Without this,
	// clicking Test N times during a segment-store outage adds N to a
	// denial counter and emits N "DENYING" lines against zero denials, so
	// anyone alerting on it pages on button clicks.
	segmentResolutionPhasePreview segmentResolutionPhase = "preview"
)

var (
	// segmentResolutionTotal counts per-user segment resolution outcomes on
	// the fleet/MCP-server plane, labeled by:
	//   - result: "resolved" (non-empty applicable set), "empty" (resolution
	//     succeeded with zero group memberships), "error" (the resolver
	//     failed). resolveUserSegments itself always reports the error as
	//     ok=false; whether that DENIES anything depends on the caller — the
	//     enforcement phase acts on it, the session_auth phase discards it
	//     (see segmentResolutionPhase's doc above).
	//   - phase: "session_auth", "enforcement" or "preview"
	//     (segmentResolutionPhase).
	segmentResolutionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axonflow_segment_resolution_total",
		Help: "ADR-060 (#2989) per-user governance-segment resolution outcomes on the fleet/MCP-server plane, by result and by phase (session_auth vs enforcement).",
	}, []string{"result", "phase"})

	// segmentResolutionDurationSeconds observes resolution latency for
	// SUCCESSFUL resolutions (resolved or empty) across BOTH phases — a
	// failed lookup's latency is not comparable (it may fail fast on a
	// closed connection or slow on a timeout) and is tracked separately via
	// segmentResolutionTotal{result="error"}. Not phase-split: latency is a
	// property of the underlying resolver/cache, not of which call site
	// triggered it.
	segmentResolutionDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "axonflow_segment_resolution_duration_seconds",
		Help:    "Latency of successful ADR-060 (#2989) per-user governance-segment resolution.",
		Buckets: prometheus.DefBuckets,
	})
)
