// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	sharedidentity "axonflow/platform/shared/identity"
)

// ADR-060 (#2989 P3b, issue #3052) — segment-scoped policy targeting for the
// orchestrator's dynamic policy engine, DatabaseDynamicPolicyEngine
// (db_dynamic_policies.go) — the only dynamic policy engine since #3319
// deleted the in-memory DynamicPolicyEngine. This is the orchestrator-plane
// mirror of platform/agent/segment_policy_gate.go's promotion of segment resolution
// from observability-only to POLICY-AFFECTING, applied here to the
// orchestrator's dynamic (customer-CRUD-managed) policy plane rather than
// the agent's static plane (P3, PR #3057).
//
// Unlike the agent, the orchestrator has no session-create call site at all —
// every call here is policy-affecting — so, unlike the agent's
// resolveUserSegments (segment_policy_gate.go), this file's resolveUserSegments
// needs no phase parameter; every call implicitly is #3473's
// "enforcement" population. This file is both the resolver wiring
// (setOrchestratorSegmentResolver, mirroring mcp_identity.go's
// getFleetSegmentResolver/registerFleetValidators) AND the thin adapter over
// the resolution CONTRACT (platform/shared/identity.ResolveUserSegments),
// which after #3239 round 2's fail-closed convergence is the single shared
// implementation behind both this file's resolveUserSegments and
// platform/agent/segment_policy_gate.go's function of the same name.

// orchestratorSegmentResolver is the process-wide shared
// IdentityAttributeResolver used to resolve segments for the orchestrator's
// dynamic-policy enforcement path, wired once at startup (run.go, alongside
// dynamicPolicyEngine's own construction — see initSegmentPolicyGate). nil in
// community builds / when construction fails (ErrEnterpriseOnly or a DB
// problem) — resolveUserSegments treats nil as "capability
// unavailable", never an error.
var (
	orchestratorSegmentResolverMu sync.RWMutex
	orchestratorSegmentResolver   sharedidentity.IdentityAttributeResolver
)

func setOrchestratorSegmentResolver(r sharedidentity.IdentityAttributeResolver) {
	orchestratorSegmentResolverMu.Lock()
	orchestratorSegmentResolver = r
	orchestratorSegmentResolverMu.Unlock()
}

func getOrchestratorSegmentResolver() sharedidentity.IdentityAttributeResolver {
	orchestratorSegmentResolverMu.RLock()
	defer orchestratorSegmentResolverMu.RUnlock()
	return orchestratorSegmentResolver
}

// ResetOrchestratorSegmentResolverForTest clears the wired resolver.
// Test-only.
func ResetOrchestratorSegmentResolverForTest() {
	setOrchestratorSegmentResolver(nil)
}

// initSegmentPolicyGate constructs and wires the process-wide segment
// resolver from the platform database, mirroring registerFleetValidators'
// #2989 wiring (platform/agent/mcp_identity.go). Called once at orchestrator
// startup (run.go), right alongside the dynamic policy engine's own
// construction, so segment resolution is available for the very first
// request rather than depending on lazy first-use timing.
//
// A resolver-construction failure other than ErrEnterpriseOnly is logged;
// segment resolution then simply stays unavailable (resolveUserSegments
// returns ok=true with a nil set, i.e. org-only) rather than blocking boot —
// the dynamic policy engine itself is not gated on this. A nil db (usageDB
// unavailable at boot — H3, #3239) is likewise logged rather than silently
// skipped, so an operator can see segment enforcement stayed unwired instead
// of inferring it from an absence of the "wired" line.
func initSegmentPolicyGate(db *sql.DB) {
	if db == nil {
		log.Println("[Policy] ADR-060 (#2989 P3b) segment resolver NOT wired: usageDB unavailable — dynamic policies stay segment-unaware (org-only) until the database is available")
		return
	}
	resolver, err := sharedidentity.NewIdentityAttributeResolver(db)
	if err == nil {
		setOrchestratorSegmentResolver(resolver)
		// #3550: a SCIM-backed directory IS wired in this process, so the
		// built-in realms that can carry one declare DirectorySourceSCIM.
		noteOrchestratorDirectoryWired()
		log.Println("[Policy] ADR-060 (#2989 P3b) orchestrator segment resolver wired")
	} else if !errors.Is(err, sharedidentity.ErrEnterpriseOnly) {
		log.Printf("[Policy] ADR-060 (#2989 P3b) orchestrator segment resolver unavailable: %v", err)
	}
}

var (
	// orchestratorSegmentResolutionTotal counts per-request segment
	// resolution outcomes on the orchestrator's dynamic-policy plane,
	// labeled by result:
	//   - "resolved": a non-empty applicable segment set.
	//   - "empty": resolution succeeded with zero group memberships.
	//   - "error": the resolver failed closed (query/storage error).
	orchestratorSegmentResolutionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axonflow_orchestrator_segment_resolution_total",
		Help: "ADR-060 (#2989 P3b) per-request governance-segment resolution outcomes on the orchestrator dynamic-policy plane.",
	}, []string{"result"})

	// orchestratorSegmentResolutionDurationSeconds observes resolution
	// latency for SUCCESSFUL resolutions (resolved or empty) — a failed
	// lookup's latency is tracked separately via
	// orchestratorSegmentResolutionTotal{result="error"}.
	orchestratorSegmentResolutionDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "axonflow_orchestrator_segment_resolution_duration_seconds",
		Help:    "Latency of successful ADR-060 (#2989 P3b) governance-segment resolution on the orchestrator.",
		Buckets: prometheus.DefBuckets,
	})

	// orchestratorSegmentPolicyFailClosedTotal counts requests DENIED
	// specifically because segment resolution failed on the orchestrator's
	// policy-affecting path (ADR-060 §Fail-closed, locked): a genuine
	// resolver error must never be silently treated as "caller has zero
	// segments". After #3239 round 2 this fires uniformly for both
	// EvaluateDynamicPolicies (enforcement) and the simulate/test preview
	// path, which shares this exact same fail-closed contract — see the file
	// doc.
	orchestratorSegmentPolicyFailClosedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "axonflow_orchestrator_segment_policy_fail_closed_total",
		Help: "ADR-060 (#2989 P3b) requests denied because governance-segment resolution failed on the orchestrator's dynamic-policy enforcement path (fail-closed, never org-only fallback).",
	})
)

// orchestratorSegmentPolicyMetrics adapts this package's existing
// Prometheus series (above) to the shared implementation's
// SegmentPolicyMetrics interface.
type orchestratorSegmentPolicyMetrics struct{}

func (orchestratorSegmentPolicyMetrics) ObserveResolutionResult(result string) {
	orchestratorSegmentResolutionTotal.WithLabelValues(result).Inc()
}

func (orchestratorSegmentPolicyMetrics) ObserveResolutionDuration(seconds float64) {
	orchestratorSegmentResolutionDurationSeconds.Observe(seconds)
}

func (orchestratorSegmentPolicyMetrics) IncFailClosed() {
	orchestratorSegmentPolicyFailClosedTotal.Inc()
}

// LogResolutionError reproduces this package's pre-#3473 unconditional log
// line byte-for-byte: the orchestrator has no session-auth call site at all
// (every resolveUserSegments call here is policy-affecting — see this
// file's doc), so "DENYING" is always a true description of what happens
// next, unlike the agent's phase-gated twin (platform/agent/
// segment_policy_gate.go).
func (orchestratorSegmentPolicyMetrics) LogResolutionError(orgID string, latency time.Duration, err error) {
	log.Printf("[Policy] DENYING (fail-closed, ADR-060 #2989): segment resolution failed org=%q latency=%s: %v",
		orgID, latency, err)
}

// LogResolutionSuccess is a no-op: the orchestrator never had a success log
// line for segment resolution (that was always specific to the agent
// fleet/MCP-server plane's P2-era observability wiring), and every call here
// is the high-volume enforcement phase, where a per-resolution log line
// would flood the log for no benefit segmentResolutionTotal doesn't already
// provide.
func (orchestratorSegmentPolicyMetrics) LogResolutionSuccess(string, time.Duration, []string) {}

// resolveUserSegments resolves the caller's governance-segment set
// (ADR-060, #2989 P3b) for POLICY-AFFECTING consumption by the
// orchestrator's dynamic policy engine — DatabaseDynamicPolicyEngine's
// EvaluateDynamicPolicies calls this before consulting the applicable-policy set
// (getApplicablePolicies / dbCachedPolicyAppliesToTenant), so a
// segment-scoped dynamic policy is enforced the same way P3 enforces a
// segment-scoped static one. Also called by the simulate/test preview path,
// which shares this exact contract after #3239 round 2's fail-closed
// convergence — see below.
//
// orgID/email are composed ABOVE the already-resolved tenantscope scope
// (#3065): callers pass req.User.OrgID / req.User.Email exactly as already
// stamped upstream (resolveGovernedScope / tenantscope.Bind on the agent's
// governed forward, run.go:2209-2213). This function never reads a header
// or query param itself, so it cannot re-derive org/tenant the #3099/#3108
// fail-open way.
//
// Thin adapter over platform/shared/identity.ResolveUserSegments: see
// that function's doc for the full resolver/empty-identity/error contract.
// Both this plane and the agent static plane
// (platform/agent/segment_policy_gate.go's function of the same name) now
// fail closed UNCONDITIONALLY — neither has a read-only-simulator carve-out
// (removed in #3239 round 2; a preview must be faithful to what enforcement
// actually does, and the usability concern a fail-open carve-out used to
// address is covered instead by the segments_resolved signal on the preview
// response).
func resolveUserSegments(ctx context.Context, orgID, email string) (segmentIDs []string, ok bool) {
	return sharedidentity.ResolveUserSegments(ctx, orgID, email, getOrchestratorSegmentResolver(), orchestratorSegmentPolicyMetrics{})
}

// normalizeSegmentIDs dedupes, drops empty entries, and sorts a caller-
// supplied segment-ID set so the verdict cache key (verdictCacheKey /
// generateCacheKey) and the choke-point predicates both see one canonical
// form regardless of the order or duplication the resolver happened to
// return — mirrors platform/agent/tier_aware_policy_engine.go's function of
// the same name exactly (#2989 P3). Thin wrapper over
// platform/shared/identity.NormalizeSegmentIDs, the single implementation
// shared by both packages (#3239 round 2 extraction).
func normalizeSegmentIDs(segmentIDs []string) []string {
	return sharedidentity.NormalizeSegmentIDs(segmentIDs)
}

// segmentSetContains reports whether segmentIDs contains id. Shared by both
// choke points (memPolicyAppliesToTenant / dbCachedPolicyAppliesToTenant) to
// test a policy's single segment_id against the caller's resolved set. Thin
// wrapper over platform/shared/identity.SegmentSetContains (#3239 round 2
// extraction).
func segmentSetContains(segmentIDs []string, id string) bool {
	return sharedidentity.SegmentSetContains(segmentIDs, id)
}
