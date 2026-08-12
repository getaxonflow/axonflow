// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"log"
	"sort"
	"time"
)

// ADR-060 (#2989) — this file is the single implementation shared by the
// agent static plane's segment gate (P3, #3051, platform/agent/
// segment_policy_gate.go) and the orchestrator dynamic-policy plane's gate
// (P3b, #3052, platform/orchestrator/segment_policy_gate.go). Round 1 of
// #3239 shipped these as two independently-maintained copies; round 2
// converged both planes on an unconditional fail-closed contract (dropping
// the agent's now-dead failClosed parameter and its fail-open branch), which
// made the two bodies byte-identical — the copy-drift that let the agent's
// copy diverge (missing the empty-identity early-return, and binding org
// from caller-chosen input rather than the authenticated context) in the
// first place. Extracting here removes that drift at the root instead of
// re-shipping it.
//
// Each service keeps its OWN Prometheus metric names
// (axonflow_agent_segment_… vs axonflow_orchestrator_segment_…) and its own
// resolver singleton/wiring — those stay thin per-package adapters
// (platform/agent/segment_policy_gate.go, platform/orchestrator/
// segment_policy_gate.go) that call the exported functions below.

// SegmentPolicyMetrics is the per-service Prometheus sink
// ResolveSegmentsForPolicy reports into. It carries the OUTCOME only; each
// service wires its own counter/histogram (with its own name/help text) via
// a small adapter, so this extraction changes no exported metric name.
type SegmentPolicyMetrics interface {
	// ObserveResolutionResult increments a per-result-label resolution
	// counter. result is one of "resolved", "empty", "error".
	ObserveResolutionResult(result string)
	// ObserveResolutionDuration records the latency (seconds) of a
	// SUCCESSFUL resolution (resolved or empty) — a failed lookup's latency
	// is not observed here, mirroring the pre-extraction behavior.
	ObserveResolutionDuration(seconds float64)
	// IncFailClosed increments the counter tracking requests DENIED because
	// segment resolution failed on the policy-affecting path.
	IncFailClosed()
}

// ResolveSegmentsForPolicy resolves the caller's governance-segment set
// (ADR-060, #2989) for POLICY-AFFECTING consumption. resolver is the
// caller's already-looked-up process-wide resolver (nil = capability
// unavailable — community build, or Enterprise without SCIM/segment
// resolution configured); metrics is the caller's per-service sink.
//
// Contract (fail-closed UNCONDITIONALLY — both the agent static plane and
// the orchestrator dynamic-policy plane converged on this after #3239 round
// 2: neither plane's preview/simulator surface (policyTestHandler /
// PolicySimulationHandler) gets a fail-open carve-out; a preview must be
// faithful to what enforcement actually does):
//
//   - resolver nil: returns (nil, true). Not a failure — the caller
//     proceeds org-only, identical to every pre-segment-targeting request.
//   - orgID or email empty (no verified per-user identity to resolve
//     against — a service-to-service caller with no per-user email, or an
//     omitted user_email on a preview): returns (nil, true). Org-only, not
//     a failure. This is the load-bearing early-return under fail-closed:
//     an absent identity must never be routed into the error branch below,
//     or a routine no-email preview would wrongly deny.
//   - resolution SUCCEEDS with zero group memberships: returns (nil, true).
//     Zero segments is a legitimate outcome — the caller proceeds org-only.
//   - resolution SUCCEEDS with N>0 segments: returns (ids, true).
//   - resolution ERRORS (a genuine storage/query failure): returns
//     (nil, false). The caller MUST deny the whole request — ADR-060
//     §Fail-closed is explicit that a segment resolution failure must never
//     be papered over as "proceed org-only", because that IS the exact
//     fail-open bypass ADR-060 exists to close.
func ResolveSegmentsForPolicy(ctx context.Context, orgID, email string, resolver IdentityAttributeResolver, metrics SegmentPolicyMetrics) (segmentIDs []string, ok bool) {
	if resolver == nil {
		return nil, true // capability unavailable — not a failure, proceed org-only
	}
	if orgID == "" || email == "" {
		return nil, true // no verified per-user identity to resolve against
	}

	start := time.Now()
	resolved, err := resolver.Resolve(ctx, orgID, email)
	latency := time.Since(start)
	if err != nil {
		metrics.ObserveResolutionResult("error")
		metrics.IncFailClosed()
		log.Printf("[Policy] DENYING (fail-closed, ADR-060 #2989): segment resolution failed org=%q latency=%s: %v",
			orgID, latency, err)
		return nil, false
	}
	metrics.ObserveResolutionDuration(latency.Seconds())

	if len(resolved.Segments) == 0 {
		metrics.ObserveResolutionResult("empty")
		return nil, true
	}

	metrics.ObserveResolutionResult("resolved")
	ids := make([]string, len(resolved.Segments))
	for i, s := range resolved.Segments {
		ids[i] = string(s.ID)
	}
	return ids, true
}

// NormalizeSegmentIDs dedupes, drops empty entries, and sorts a caller-
// supplied segment-ID set so a verdict cache key and a choke-point predicate
// both see one canonical form regardless of the order or duplication the
// resolver happened to return. Returns nil (never a non-nil empty slice) for
// an empty/all-empty input.
func NormalizeSegmentIDs(segmentIDs []string) []string {
	if len(segmentIDs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(segmentIDs))
	out := make([]string, 0, len(segmentIDs))
	for _, id := range segmentIDs {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// SegmentSetContains reports whether segmentIDs contains id. Shared by both
// planes' applicability choke points to test a policy's single segment_id
// against the caller's resolved set.
func SegmentSetContains(segmentIDs []string, id string) bool {
	for _, s := range segmentIDs {
		if s == id {
			return true
		}
	}
	return false
}
