// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ADR-060 (#2989 Phase 2) segment-resolution observability. Segments are NOT
// consumed for any policy decision in this phase — these metrics exist
// purely so the resolution itself (set / latency / error-vs-empty) is
// observable ahead of P3 wiring it into policy.

var (
	// segmentResolutionTotal counts per-user segment resolution outcomes on
	// the fleet/MCP-server plane, labeled by result:
	//   - "resolved": a non-empty applicable segment set.
	//   - "empty": resolution succeeded with zero group memberships.
	//   - "error": the resolver failed closed (query/storage error).
	segmentResolutionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axonflow_segment_resolution_total",
		Help: "ADR-060 (#2989) per-user governance-segment resolution outcomes on the fleet/MCP-server plane.",
	}, []string{"result"})

	// segmentResolutionDurationSeconds observes resolution latency for
	// SUCCESSFUL resolutions (resolved or empty) — a failed lookup's latency
	// is not comparable (it may fail fast on a closed connection or slow on
	// a timeout) and is tracked separately via segmentResolutionTotal{result="error"}.
	segmentResolutionDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "axonflow_segment_resolution_duration_seconds",
		Help:    "Latency of successful ADR-060 (#2989) per-user governance-segment resolution.",
		Buckets: prometheus.DefBuckets,
	})
)
