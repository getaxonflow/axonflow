// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ADR-060 (#2989) segment-resolution observability, on the fleet/MCP-server
// plane. One lookup (resolveUserSegments, segment_policy_gate.go) serves one
// call population since #4253:
//   - "session_auth": the resolution at handleMCPInitialize / resolveMCPSession
//     that runs once per resolved AUTH (authenticateMCPSession succeeding),
//     observability-only — its result is not read for any decision (#3473).
//     This is NOT reliably "once per MCP session": resolveMCPSession only
//     amortizes it across a session's calls when the caller reuses the
//     Mcp-Session-Id header and hits the cache. The stateless/hook-path
//     callers (the Claude Code/Desktop plugin fleet, #2753) send no such
//     header — every one of their requests is a cache miss, so for THAT
//     traffic this phase runs once per request.
//
// The "enforcement" phase (/api/request's segment gate) and the "preview" phase
// (the policy-test preview) are gone with the pass they fed (#4253): the
// anchored engine reads no segments. The "phase" label stays, so an existing
// selector on phase="session_auth" keeps reading the same series.
type segmentResolutionPhase string

const (
	segmentResolutionPhaseSessionAuth segmentResolutionPhase = "session_auth"
)

var (
	// segmentResolutionTotal counts per-user segment resolution outcomes on
	// the fleet/MCP-server plane, labeled by:
	//   - result: "resolved" (non-empty applicable set), "empty" (resolution
	//     succeeded with zero group memberships), "error" (the resolver
	//     failed). resolveUserSegments itself always reports the error as
	//     ok=false; the one call site discards it, so it denies nothing.
	//   - phase: "session_auth" (segmentResolutionPhase).
	segmentResolutionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axonflow_segment_resolution_total",
		Help: "ADR-060 (#2989) per-user governance-segment resolution outcomes on the fleet/MCP-server plane, by result and by phase (session_auth).",
	}, []string{"result", "phase"})

	// segmentResolutionDurationSeconds observes resolution latency for
	// SUCCESSFUL resolutions (resolved or empty) — a failed lookup's latency is
	// not comparable (it may fail fast on a closed connection or slow on a
	// timeout) and is tracked separately via segmentResolutionTotal{result="error"}.
	segmentResolutionDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "axonflow_segment_resolution_duration_seconds",
		Help:    "Latency of successful ADR-060 (#2989) per-user governance-segment resolution.",
		Buckets: prometheus.DefBuckets,
	})
)
