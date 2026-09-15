// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"log"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// ADR-060 (#2989) — the fleet/MCP-server plane's one user->segments lookup.
//
// Since #4253 its one caller is the MCP server's session authentication
// (mcp_server_handler.go), which resolves so the outcome stays observable and
// DISCARDS ok: nothing on the agent decides on a governance segment. The
// anchored engine reads none (PRD v11 §1.1, §1.2), and the last caller that
// denied on a resolution failure - /api/request's segment gate, which fed the
// segment set to that route's retired second pass - went with that pass (#4253,
// PRD v11 §1 item 1). Its denial counter, axonflow_segment_policy_fail_closed_total,
// went with it too: a counter no request can move reads as "no outage" through
// one.
//
// The lookup itself is the shared implementation in platform/shared/identity,
// whose contract is byte-identical to platform/orchestrator/segment_policy_gate.go's
// twin; this file supplies the agent's resolver singleton
// (getFleetSegmentResolver, mcp_identity.go) and its Prometheus series
// (segment_resolution_metrics.go).

// agentSegmentPolicyMetrics adapts this package's Prometheus series
// (segmentResolutionTotal / segmentResolutionDurationSeconds, both defined in
// segment_resolution_metrics.go) to the shared implementation's
// SegmentPolicyMetrics interface. phase is bound once per call by
// resolveUserSegments below and never mutated after construction.
type agentSegmentPolicyMetrics struct {
	phase segmentResolutionPhase
}

func (m agentSegmentPolicyMetrics) ObserveResolutionResult(result string) {
	segmentResolutionTotal.WithLabelValues(result, string(m.phase)).Inc()
}

func (m agentSegmentPolicyMetrics) ObserveResolutionDuration(seconds float64) {
	segmentResolutionDurationSeconds.Observe(seconds)
}

// IncFailClosed counts nothing: no call site on this plane denies a request on a
// resolution failure since #4253 (see the file doc), so there is no denial to
// count.
func (m agentSegmentPolicyMetrics) IncFailClosed() {}

// LogResolutionError logs a WARNING and never "DENYING": the one call site
// discards ok, so the failure denies nothing. The signal stays: an operator can
// still see the gap.
func (m agentSegmentPolicyMetrics) LogResolutionError(orgID string, latency time.Duration, err error) {
	log.Printf("[Identity] WARNING: #2989 segment resolution failed org=%q latency=%s: %v", orgID, latency, err)
}

// LogResolutionSuccess logs the org, the cardinality and the resolved segment
// ids for the session_auth phase: for stateless/hook-path callers (the Claude
// Code/Desktop plugin fleet, #2753) every request is a cache miss, and a
// specific caller resolving to a specific, nameable set is what this line exists
// to make visible (see segmentResolutionPhase's doc,
// segment_resolution_metrics.go).
func (m agentSegmentPolicyMetrics) LogResolutionSuccess(orgID string, latency time.Duration, segmentIDs []string) {
	if m.phase != segmentResolutionPhaseSessionAuth {
		return
	}
	if len(segmentIDs) == 0 {
		log.Printf("[Identity] #2989 segments resolved org=%q count=0 latency=%s", orgID, latency)
		return
	}
	log.Printf("[Identity] #2989 segments resolved org=%q count=%d segments=%v latency=%s", orgID, len(segmentIDs), segmentIDs, latency)
}

// resolveUserSegmentsForObservability labels a call site that resolves purely
// so the outcome is observable and DISCARDS ok — nothing downstream reads a
// session-scoped segment set. Its failures deny nothing.
//
// It is a named wrapper rather than a phase argument because the phase used to
// be positional and caller-supplied, and nothing pinned it; a wrapper cannot be
// mis-labelled by a call site.
func resolveUserSegmentsForObservability(ctx context.Context, orgID, email string) (segmentIDs []string, ok bool) {
	return resolveUserSegments(ctx, orgID, email, segmentResolutionPhaseSessionAuth)
}

// resolveUserSegments is the shared implementation. Thin adapter over
// platform/shared/identity.ResolveUserSegments: see that function's doc for the
// full resolver/empty-identity/error contract (ok==false on a resolver error;
// ok==true with nil ids on a nil resolver or an empty orgID/email). Prefer the
// wrapper above at call sites; this form exists for it and for tests.
func resolveUserSegments(ctx context.Context, orgID, email string, phase segmentResolutionPhase) (segmentIDs []string, ok bool) {
	return sharedidentity.ResolveUserSegments(ctx, orgID, email, getFleetSegmentResolver(), agentSegmentPolicyMetrics{phase: phase})
}
