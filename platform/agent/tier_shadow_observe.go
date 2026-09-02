// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// The proxy tier engine's ADR-065 shadow observation site (#3564, session
// v10.3-A).
//
// # WHY THIS PLANE HAS ITS OWN SITE AT ALL
//
// proxy_tier is the ONLY plane that reads static_policies.action, through
// StaticPolicyRepository.GetEffective, and the only static plane that does not
// receive EvalOptions.ActionOverrides. It never touches the shared engine, so
// the observation the shared engine emits cannot cover it - and it is the plane
// an operator is least likely to check, which is exactly why leaving it
// unobserved would be the expensive omission.
//
// It is also the only plane that is FIRST-MATCH-WINS. evaluateFirstMatch
// returns inside its loop on the first pattern match, and evaluateStrictestMatch
// takes the single most restrictive of the segment rows; the two are then
// combined restriction-only. At most TWO rows determine a proxy-tier verdict,
// where every other plane accumulates all of them. That is modelled here by
// recording which rows the two walks actually LOOKED at, not by assuming the
// whole effective set participated.
package agent

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"slices"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/planeshadow"
)

// This file's own source, digested and stamped onto every comparison it emits
// (#3564 round 2). The proxy tier's copy of the per-site reset stamp; see
// platform/shared/policy/shadowobserve.go for the argument, which every site
// has to make for itself because go:embed cannot reach across a package
// directory.
//
// This site is the one the argument is strongest for. It is the only plane
// that reads static_policies.action, the only one that is first-match-wins,
// and therefore the one whose observation logic can change most independently
// of everything else in the shadow. A change to which rows the two walks
// report as looked-at moves what both sides see and moves no other digest.
//
//go:embed tier_shadow_observe.go
var tierShadowSiteSource []byte

var tierShadowSiteVersion = func() string {
	sum := sha256.Sum256(tierShadowSiteSource)
	return hex.EncodeToString(sum[:])
}()

// TierShadowContext is what the tier engine cannot derive from its own
// arguments: which plane the call is for, and who is making it.
//
// It is a REQUIRED parameter rather than a variadic option or a struct field
// with a usable zero value. Both of those are forgettable, and a call site that
// forgets produces an observation attributed to no plane - which is either
// dropped (a hole in a denominator that reads as complete) or attributed to
// some plane (a denominator an operator reads to decide a cutover, moved by a
// bug). A required parameter makes forgetting a compile error.
type TierShadowContext struct {
	// Plane is the enforcement plane. proxy_tier for the request path,
	// policy_test for the policy-test surface.
	Plane legacycompile.Plane
	// Principal is the caller the plane resolved, empty when it resolved none.
	Principal string
	// OrgID is the AUTHENTICATED organization, which is the key the
	// per-organization shadow mode is resolved for. It is distinct from the
	// orgID argument, which is the policy LOAD scope.
	OrgID string
}

// tierShadowTrace records which effective rows each walk looked at.
type tierShadowTrace struct {
	rows  []planeshadow.RowFact
	index map[string]int
}

// newTierShadowTrace returns a trace when the shadow could observe.
func newTierShadowTrace(policies []EffectiveStaticPolicy) *tierShadowTrace {
	if !planeshadow.Enabled() {
		return nil
	}
	t := &tierShadowTrace{
		rows:  make([]planeshadow.RowFact, 0, len(policies)),
		index: make(map[string]int, len(policies)),
	}
	for i := range policies {
		p := &policies[i]
		if _, dup := t.index[p.PolicyID]; dup {
			// GetEffective resolves at most one row per policy_id, so a
			// duplicate means the effective set is malformed. Skipped rather
			// than overwritten: overwriting would silently attribute the
			// second row's verdict to the first, and skipping leaves the
			// comparison not-comparable, which is the safe direction.
			continue
		}
		t.index[p.PolicyID] = len(t.rows)
		t.rows = append(t.rows, planeshadow.RowFact{
			Table:     "static_policies",
			PolicyID:  p.PolicyID,
			Category:  p.Category,
			UpdatedAt: planeshadow.StampKey(p.UpdatedAt),
		})
	}
	return t
}

// markRan records that a walk evaluated this row's pattern.
func (t *tierShadowTrace) markRan(policyID string) {
	if t == nil {
		return
	}
	if i, ok := t.index[policyID]; ok {
		t.rows[i].Ran = true
	}
}

// markMatched records that a row's pattern matched and names the action the
// walk resolved for it.
//
// It is called for EVERY matching row, including ones the combiner then
// discards - and then the emit step keeps only the rows the combined verdict
// actually determined. Recording the match here and filtering there keeps the
// two facts separate: "this pattern matched" is what the detector attribute on
// the ADR-065 side needs, and "this row determined the outcome" is what the
// legacy determining set needs. Conflating them would tell the PDP that a
// shadowed row's detector did not fire.
func (t *tierShadowTrace) markMatched(policyID, action string) {
	if t == nil {
		return
	}
	if i, ok := t.index[policyID]; ok {
		t.rows[i].Ran = true
		t.rows[i].Matched = true
		t.rows[i].Action = action
	}
}

// emit builds the observation and hands it to the shadow. It returns nothing.
//
// determining names the at-most-two rows the combined verdict actually rests
// on. Every OTHER matched row keeps its detector verdict - it did match - but
// contributes no legacy effect and no determining entry, which is what
// EC6_PROXY_TIER_FIRST_MATCH_SHADOWING exists to classify on the ADR-065 side.
func (t *tierShadowTrace) emit(
	ctx context.Context,
	sc TierShadowContext,
	loadScope string,
	segmentIDs []string,
	determining map[string]bool,
	executable bool,
) {
	if t == nil {
		return
	}
	rows := shadowedRowFacts(t.rows, determining)
	planeshadow.Observe(ctx, planeshadow.Observation{
		Plane: sc.Plane,
		// The tier engine evaluates the request phase only; its plane model
		// declares one phase, so the observation carries none.
		Phase:       "",
		OrgScope:    loadScope,
		OrgID:       sc.OrgID,
		Principal:   sc.Principal,
		SiteVersion: tierShadowSiteVersion,
		// CLONED, NOT ALIASED - the observation is read on a worker goroutine
		// and this slice belongs to the caller, who is free to reuse its
		// backing array the moment this returns.
		Groups: slices.Clone(segmentIDs),
		// GetEffectivePolicies filters segment rows in SQL against an already
		// resolved set; a resolution FAILURE denies before this engine is
		// reached, so an empty set here is a resolved empty set.
		SegmentsUnresolved: false,
		Legacy: planeshadow.LegacyOutcome{
			Executable: executable,
			// A load failure returns an error from EvaluatePolicy and never
			// reaches the emit, so an observation from here always describes a
			// completed evaluation.
			EvaluationError: false,
		},
		Rows: rows,
		// NO POSTURE. The proxy tier resolves through GetEffective and never
		// sees BuildActionOverrides' map - it is the one static plane whose
		// PlaneSpec.PostureLever is false. Passing the deployment posture here
		// would let a posture change appear to alter a plane it cannot reach,
		// which is the single most likely wrong answer on this plane.
		Posture: nil,
	})
}

// shadowedRowFacts applies the combiner's shadowing to the recorded facts.
//
// A NAMED FUNCTION RATHER THAN A LOOP INSIDE emit, so a test can exercise the
// REAL transformation instead of a copy of it. emit's only other work is
// assembling the Observation and handing it to a void function, so a test that
// re-derived these facts would be certifying its own reimplementation - which
// is how the defect below survived in the first place.
//
// A row the first-match/strictest reduction discarded keeps its detector
// verdict TRUE - the pattern really did match, and the ADR-065 side needs that
// or EC6_PROXY_TIER_FIRST_MATCH_SHADOWING can never fire. It is marked Shadowed
// so the LEGACY side leaves it out of the determining set, and its action is
// cleared so no legacy effect is attributed to a row the running system did not
// act on.
//
// Setting Matched back to false instead - which this did until R3 round 2
// measured it - makes the compiled detector attribute false, and EC6's evidence
// predicate requires it to be true. The one divergence this plane is known to
// have then records as a confident `match`.
func shadowedRowFacts(in []planeshadow.RowFact, determining map[string]bool) []planeshadow.RowFact {
	out := make([]planeshadow.RowFact, 0, len(in))
	for _, r := range in {
		if detectorMatchedButShadowed(r, determining) {
			r.Action = ""
			r.Shadowed = true
			r.Ran = true
		}
		out = append(out, r)
	}
	return out
}

// detectorMatchedButShadowed reports whether a matched row was discarded by the
// combiner.
//
// CALLED FROM emit, not merely declared beside it. It was a named helper that
// nothing called while emit restated the same predicate inline, which is one
// edit away from the two disagreeing - and the fix to the inline copy would
// have left this one describing the old behaviour.
func detectorMatchedButShadowed(r planeshadow.RowFact, determining map[string]bool) bool {
	return r.Matched && !determining[r.PolicyID]
}
