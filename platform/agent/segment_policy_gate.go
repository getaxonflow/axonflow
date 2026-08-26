// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	sharedidentity "axonflow/platform/shared/identity"
)

// ADR-060 (#2989) — the fleet/MCP-server plane's one user->segments lookup.
//
// #3473 collapsed this file's two former occupants into the single function
// below:
//   - the P2 (#2989) session-auth resolution that used to live in
//     mcp_identity.go as resolveUserSegments: fail-open, observability-only,
//     called at handleMCPInitialize / resolveMCPSession on every resolved
//     auth (once per request for stateless/hook-path callers with no
//     Mcp-Session-Id to cache-hit against — see segmentResolutionPhase's
//     doc, segment_resolution_metrics.go).
//   - the P3 (#3051) policy-affecting resolution that used to live here as
//     resolveSegmentsForPolicy: fail-closed, called fresh at every
//     policy-affecting request (clientRequestHandler/run.go,
//     gateway_handlers.go's pre-check, and — via
//     resolveMCPServerSegmentsForPolicy, mcp_identity.go — every MCP-server
//     tools/call that reaches check_policy/check_output).
//
// They were never two different LOOKUPS — both take (ctx, orgID, email) and
// answer "which segments is this human in" against the same resolver and the
// same cache (dbSegmentReader -> segmentCache, identity_attribute_resolver.go
// / segment_cache.go). They differed only in what the CALLER did with the
// answer. That is a call-site concern, not a lookup-contract concern, so
// there is now exactly one function — fail-closed, `(segmentIDs, ok)` — and
// each caller decides for itself whether to act on `ok`:
//   - the session-create call site (mcp_server_handler.go) discards it
//     (`segIDs, _ := resolveUserSegments(...)`): nothing downstream reads a
//     session-scoped segment set anymore (mcpSession.userSegments and
//     AuthResult.Segments are gone — #3473), so there is nothing left to
//     fail open OR closed on at that call site. The resolution still runs
//     (so its outcome stays observable — see segment_resolution_metrics.go's
//     "session_auth" phase), it just decides nothing.
//   - every enforcement call site (this file's callers, plus
//     resolveMCPServerSegmentsForPolicy) DENIES on ok==false, per ADR-060
//     §Fail-closed.
//
// #3239 round 2 (fail-closed convergence, predates #3473): resolveSegmentsForPolicy
// used to take a failClosed bool so policyTestHandler (the read-only preview)
// could opt into a fail-OPEN fallback on a resolver error while
// clientRequestHandler (enforcement) fail-closed. That carve-out is gone —
// BOTH callers now fail closed, identically. The resolution CONTRACT is the
// byte-identical twin of platform/orchestrator/segment_policy_gate.go's
// function of the same name, so both packages call the single shared
// implementation in platform/shared/identity — this file is a thin adapter
// supplying the agent's own resolver singleton (getFleetSegmentResolver,
// mcp_identity.go) and its own Prometheus metric names (axonflow_...), so the
// exported series are unchanged in shape by the extraction (only the new
// "phase" label, #3473 item 5, is new).

// segmentPolicyFailClosedTotal counts requests DENIED specifically because
// segment resolution failed on the policy-affecting (enforcement-phase) path
// (ADR-060 §Fail-closed, locked): a genuine resolver error must never be
// silently treated as "caller has zero segments" (that would be an org-only
// fallback — the exact failure mode this counter exists to make observable).
// Distinct from segmentResolutionTotal{result="error"}
// (segment_resolution_metrics.go), which counts the underlying resolution
// failure itself regardless of which phase observed it; this counter tracks
// the DOWNSTREAM consequence — a request actually denied — on the
// policy-affecting path specifically.
//
// Deliberately NEVER incremented for the session-create phase (see
// agentSegmentPolicyMetrics.IncFailClosed below): a session-create resolution
// failure denies nothing (its return value is discarded), so counting it here
// would misreport a phase that never actually fails closed as if it does.
// segmentSubjectOrgMismatchTotal counts resolutions whose SUBJECT org (the
// validated token's org_id claim) disagreed with the AUTHENTICATED org of the
// credential the request arrived on.
//
// Segment ids are org-scoped group UUIDs, so a mismatch cannot escalate: the
// caller's groups in the asserted org can never match a policy targeting a
// group in the governing org. What it can do is UNDER-enforce silently — the
// lookup joins to zero rows, which ResolveUserSegments correctly reports as
// success with an empty set, and a verified member of a targeted segment is
// then evaluated org-only with no refusal, no audit row, and a
// result="empty" metric indistinguishable from a genuine non-member.
//
// Reached when a token is minted without an --org-id (scripts/generate-jwt.sh
// defaults it to the tenant id) or carries no org_id claim at all
// (validateUserToken falls back to tenantID), on a deployment where the org
// and tenant identifiers genuinely differ.
//
// Deliberately observable rather than a refusal: refusing would break exactly
// the deployments whose tokens default the claim, and the same subject key is
// used by the already-merged /api/v1/process and gateway pre-check planes, so
// a refusal on one plane would diverge the three. The cross-plane decision —
// refuse, or resolve against the authenticated org — is tracked separately.
var segmentSubjectOrgMismatchTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "axonflow_segment_subject_org_mismatch_total",
	Help: "Segment resolutions whose subject org (token org_id claim) disagreed with the authenticated credential org; the resolution proceeds and can only under-match, never over-match.",
})

var segmentPolicyFailClosedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "axonflow_segment_policy_fail_closed_total",
	Help: "ADR-060 (#2989 P3) requests denied because governance-segment resolution failed on the policy-affecting path (fail-closed, never org-only fallback).",
})

// agentSegmentPolicyMetrics adapts this package's existing Prometheus series
// (segmentResolutionTotal / segmentResolutionDurationSeconds, both defined in
// segment_resolution_metrics.go; segmentPolicyFailClosedTotal above) to the
// shared implementation's SegmentPolicyMetrics interface. phase carries which
// of the two call populations (#3473 item 5) this particular call belongs to
// — it is bound once per call by resolveUserSegments below, never mutated
// after construction, so a single shared metrics interface can serve both
// populations without either package-level counter losing which is which.
type agentSegmentPolicyMetrics struct {
	phase segmentResolutionPhase
}

func (m agentSegmentPolicyMetrics) ObserveResolutionResult(result string) {
	segmentResolutionTotal.WithLabelValues(result, string(m.phase)).Inc()
}

func (m agentSegmentPolicyMetrics) ObserveResolutionDuration(seconds float64) {
	segmentResolutionDurationSeconds.Observe(seconds)
}

// IncFailClosed is a no-op for the session_auth phase: that call site
// discards resolveUserSegments' `ok` return, so a resolver error there never
// actually denies a request — counting it into segmentPolicyFailClosedTotal
// (whose Help text is explicit that it counts requests DENIED) would be
// wrong. The preview phase is exempt for the same reason: policyTestHandler
// SIMULATES the deny a real request would produce and returns 200, so its
// failures are not denials either. Only the enforcement phase's failures are.
func (m agentSegmentPolicyMetrics) IncFailClosed() {
	if m.phase != segmentResolutionPhaseEnforcement {
		return
	}
	segmentPolicyFailClosedTotal.Inc()
}

// LogResolutionError is phase-gated the same way IncFailClosed is, and for
// the same reason: whether "DENYING" is a TRUE description of what happens
// next depends on which phase is calling.
//
//   - enforcement phase: the caller DOES deny on this failure (ADR-060
//     §Fail-closed) — reproduces the pre-#3473 wording byte-for-byte, since
//     nothing downstream parses this differently than it always has.
//   - session_auth and preview phases: these calls deny nothing — session_auth
//     discards `ok` (mcp_server_handler.go), and preview reports a simulated
//     verdict on a 200 (policyTestHandler). Logging "DENYING" for either would
//     be false; logging the same WARNING-level line the pre-#3473 P2-era
//     resolveUserSegments used keeps the signal (an operator can still see
//     the gap) without the false "this was a denial" claim a shared
//     "DENYING" line would carry into a request that got served 200.
func (m agentSegmentPolicyMetrics) LogResolutionError(orgID string, latency time.Duration, err error) {
	if m.phase == segmentResolutionPhaseEnforcement {
		log.Printf("[Policy] DENYING (fail-closed, ADR-060 #2989): segment resolution failed org=%q latency=%s: %v",
			orgID, latency, err)
		return
	}
	log.Printf("[Identity] WARNING: #2989 segment resolution failed org=%q latency=%s: %v", orgID, latency, err)
}

// LogResolutionSuccess restores the pre-#3473 P2-era resolveUserSegments'
// success log — org, cardinality, and the resolved segment ids — but ONLY
// for the session_auth phase. The enforcement phase deliberately logs
// nothing here: it runs on every policy-affecting request (including every
// check_policy/check_output tools/call, resolveMCPServerSegmentsForPolicy),
// so a log line per successful resolution would flood the log for no
// operational benefit the segmentResolutionTotal{phase="enforcement"}
// counter doesn't already provide; the session_auth phase's volume is NOT
// reliably lower than enforcement traffic — for stateless/hook-path callers
// (the Claude Code/Desktop plugin fleet, #2753) every request is a cache
// miss, so the two phases run close to 1:1 (see segmentResolutionPhase's
// doc, segment_resolution_metrics.go) — and it is exactly the population
// the original log line existed to make visible: a specific caller
// resolved to a specific, nameable set.
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

// resolveUserSegments resolves the caller's governance-segment set (ADR-060,
// #2989) for (orgID, email) against the fleet/MCP-server plane's resolver
// singleton (getFleetSegmentResolver). Thin adapter over
// platform/shared/identity.ResolveUserSegments: see that function's doc for
// the full resolver/empty-identity/error contract (unconditionally
// fail-closed — ok==false — on a resolver error; org-only — ok==true, nil
// ids, never a failure — on a nil resolver or an empty orgID/email).
//
// phase records which call population this invocation belongs to, purely for
// the segmentResolutionTotal{phase=...} / segmentPolicyFailClosedTotal split
// (#3473 item 5) — it changes NOTHING about the lookup itself, the cache it
// reads through, or the (segmentIDs, ok) contract callers get back. Pass
// segmentResolutionPhaseSessionAuth from the session-auth call site
// (mcp_server_handler.go — NOT reliably once per session, see
// segmentResolutionPhase's doc) and segmentResolutionPhaseEnforcement from
// every policy-affecting call site (this package's clientRequestHandler /
// policyTestHandler / handlePolicyPreCheck, and
// resolveMCPServerSegmentsForPolicy in mcp_identity.go).
// resolveUserSegmentsForEnforcement is the ONLY entry point whose failures are
// real fail-closed denials: the caller MUST deny on ok == false.
//
// The three named wrappers exist because the phase used to be a positional
// enum argument, which made it caller-supplied and unpinned — flipping every
// enforcement call site to the observability phase compiled and passed the
// entire suite, silently flatlining segmentPolicyFailClosedTotal through a
// live outage while requests were still being denied. A wrapper cannot be
// mis-labelled by a call site; picking the wrong one is picking a differently
// named function.
func resolveUserSegmentsForEnforcement(ctx context.Context, orgID, email string) (segmentIDs []string, ok bool) {
	return resolveUserSegments(ctx, orgID, email, segmentResolutionPhaseEnforcement)
}

// resolveUserSegmentsForObservability labels a call site that resolves purely
// so the outcome is observable and DISCARDS ok — nothing downstream reads a
// session-scoped segment set. Its failures deny nothing.
func resolveUserSegmentsForObservability(ctx context.Context, orgID, email string) (segmentIDs []string, ok bool) {
	return resolveUserSegments(ctx, orgID, email, segmentResolutionPhaseSessionAuth)
}

// resolveUserSegmentsForPreview labels a call site that SIMULATES a verdict
// and returns 200 — the portal policy-test preview. It reads ok, but denies
// nothing, so its failures must not reach the denial counter.
func resolveUserSegmentsForPreview(ctx context.Context, orgID, email string) (segmentIDs []string, ok bool) {
	return resolveUserSegments(ctx, orgID, email, segmentResolutionPhasePreview)
}

// resolveUserSegments is the shared implementation. Prefer the three phase
// wrappers above at call sites; this form exists for them and for tests that
// need to drive a specific phase directly.
func resolveUserSegments(ctx context.Context, orgID, email string, phase segmentResolutionPhase) (segmentIDs []string, ok bool) {
	return sharedidentity.ResolveUserSegments(ctx, orgID, email, getFleetSegmentResolver(), agentSegmentPolicyMetrics{phase: phase})
}
