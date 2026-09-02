// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// The static substrate's ADR-065 shadow observation site (#3564, session
// v10.3-A).
//
// # ONE SITE, NOT EIGHT
//
// Eight of the twelve enforcement planes reach the legacy substrate through
// UnifiedPolicyEngine.EvaluateRequest and EvaluateResponse. The observation is
// emitted from INSIDE those two, which is the function all eight share: a call
// site that forgets to observe cannot exist, because there is nothing at the
// call site to forget. Bolting the observation onto each of the nineteen call
// sites is the shape [[feedback_a_guard_at_the_callers_is_not_a_guard]] names,
// and its failure mode - one plane observing and another not - is
// indistinguishable from a clean window on the plane that stopped.
//
// What a call site DOES supply is which plane it is, as EvalOptions.Plane.
// That is data rather than a decision, and its zero value is refused rather
// than defaulted (see planeshadow.Observation.Validate): an observation
// attributed to no plane cannot be counted, and attributing it to some plane
// would move a denominator an operator is reading.
//
// # THE COST WHEN THE SHADOW IS OFF
//
// One atomic load. planeshadow.Enabled() is a precomputed bool, and every
// allocation below - the row-fact slice, the ran set - happens only inside the
// guard. A deployment with the shadow off does not pay for a slice, a map or a
// string.
package policy

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
// (#3564 round 2).
//
// It is the ADR-065 gate-18 reset stamp for THIS observation site. The two
// stamps planeshadow computes cover the evaluator and the adapter; neither
// moves when this file changes which row facts it reports, how it attributes a
// phase, or whether a capped redaction is marked shadowed - all of which
// change what both sides of the diff see. A window that spanned such a change
// would be two windows read as one, and nothing in the records would say so.
//
// Self-referential on purpose: the digest covers the file that decides what is
// observed, which is this one.
//
//go:embed shadowobserve.go
var shadowSiteSource []byte

var shadowSiteVersion = func() string {
	sum := sha256.Sum256(shadowSiteSource)
	return hex.EncodeToString(sum[:])
}()

// shadowTrace accumulates what the shadow needs while an evaluation runs.
//
// A nil trace is the off state and every method on it is a no-op, so the
// evaluation loops carry no `if` of their own beyond the one that builds it.
type shadowTrace struct {
	// ran records, per policy_id, that the detector ACTUALLY RAN.
	//
	// It is populated as the loop advances rather than from the candidate
	// slice, because both evaluation loops stop early on a block: the policies
	// after the winning one were never evaluated, and reporting them as "ran
	// and did not match" would tell the PDP a detector positively did not fire
	// when nothing looked. ADR-065's tri-state exists for exactly this
	// distinction.
	ran map[string]bool
	// loaded is the phase-filtered set the loader returned, BEFORE the
	// category, capability and segment filters narrowed it. It is the set
	// whose (policy_id, updated_at) pairs identify the policy version this
	// evaluation ran against.
	loaded []CompiledPolicy
	// redactionsDropped names the policies whose redaction plan the
	// MaxRedactions cap discarded.
	//
	// # WHY THE MATCHED SET IS NOT THE APPLIED SET ON THE RESPONSE PHASE
	//
	// EvaluateResponse builds one redaction plan per matched PII policy and
	// then CAPS them (MaxRedactions, 100 at four production sites). The dropped
	// policies stay in result.MatchedPolicies - they did match - so deriving
	// the row facts from that set alone attributes a field_redact to a policy
	// the running system applied nothing for. Both sides then carry the same
	// phantom effect and the pair classifies `match`: recorded agreement about
	// an obligation that was dropped, in the numerator gate 18 is read from.
	//
	// Nil on the request phase, which builds no redaction plans.
	redactionsDropped map[string]bool
}

// noteRedactionDropped records that the cap discarded this policy's plan.
func (t *shadowTrace) noteRedactionDropped(policyID string) {
	if t == nil || policyID == "" {
		return
	}
	if t.redactionsDropped == nil {
		t.redactionsDropped = map[string]bool{}
	}
	t.redactionsDropped[policyID] = true
}

// newShadowTrace returns a trace when the shadow could observe, and nil
// otherwise.
//
// It is created BEFORE the policy load rather than after it, so that a load
// failure is observed too. An evaluation that could not load policies is not a
// policy verdict and is never compared, but it IS a hole in the denominator,
// and a hole nobody counts is indistinguishable from a plane nothing exercised.
func newShadowTrace() *shadowTrace {
	if !planeshadow.Enabled() {
		return nil
	}
	return &shadowTrace{ran: map[string]bool{}}
}

// setLoaded records the phase-filtered set the loader returned.
func (t *shadowTrace) setLoaded(loaded []CompiledPolicy) {
	if t == nil {
		return
	}
	t.loaded = loaded
}

// markRan records that a policy's detector was evaluated.
func (t *shadowTrace) markRan(policyID string) {
	if t == nil {
		return
	}
	t.ran[policyID] = true
}

// emit builds the observation and hands it to the shadow. It returns nothing,
// and neither does anything it calls.
func (t *shadowTrace) emit(
	ctx context.Context,
	phase Phase,
	opts EvalOptions,
	matched []PolicyMatch,
	executable bool,
	evaluationError bool,
) {
	if t == nil {
		return
	}
	matchedByID := make(map[string]PolicyMatch, len(matched))
	for _, m := range matched {
		// FIRST match wins, matching MatchedPolicies' own de-duplication: the
		// query-string scan records a policy once and the parameter scan does
		// not add a second entry for it. Taking the last would report the
		// parameter scan's FieldPath for a policy the query scan resolved.
		if _, seen := matchedByID[m.PolicyID]; !seen {
			matchedByID[m.PolicyID] = m
		}
	}

	rows := make([]planeshadow.RowFact, 0, len(t.loaded))
	for i := range t.loaded {
		p := &t.loaded[i]
		f := planeshadow.RowFact{
			Table:     "static_policies",
			PolicyID:  p.PolicyID,
			Category:  string(p.Category),
			UpdatedAt: p.UpdatedAt,
			Ran:       t.ran[p.PolicyID],
		}
		if m, ok := matchedByID[p.PolicyID]; ok {
			f.Matched = true
			f.Action = string(m.Action)
			if t.redactionsDropped[p.PolicyID] {
				// MATCHED, BUT THE CAP DISCARDED ITS PLAN, so the running
				// system applied nothing for it. Shadowed is exactly this
				// distinction: the detector fired (which the ADR-065 side
				// needs) and the row contributed no legacy effect and is not
				// determining (which the legacy side needs). Clearing the
				// action as well keeps legacyVerdictFor from inventing an
				// obligation for a redaction that never happened.
				f.Shadowed = true
				f.Action = ""
			}
			// A static redaction names no field path: static_policies stores
			// none, and the target was whatever span the detector matched. The
			// content root comes from the compilation options so BOTH sides
			// are given the same one; leaving it empty here is what lets the
			// translator supply it.
			f.Ran = true
		}
		rows = append(rows, f)
	}

	planeshadow.Observe(ctx, planeshadow.Observation{
		Plane:       opts.Plane,
		Phase:       observedPhase(opts.Plane, phase),
		OrgScope:    orgScopeOf(opts),
		OrgID:       opts.OrgID,
		Principal:   opts.UserID,
		SiteVersion: shadowSiteVersion,
		// CLONED, NOT ALIASED.
		//
		// The observation is queued and read on a worker goroutine. Handing it
		// the caller's own slice means the segment set the shadow compares
		// against is whatever the caller's slice holds WHEN THE WORKER GETS TO
		// IT, not what it held at the evaluation - and the caller is free to
		// reuse or re-sort that backing array the moment this returns. The
		// resulting divergence would be attributed to the migration, on a
		// random subset of requests, with nothing in the record to say the
		// input had moved. Cloning is O(len) on a set that is almost always
		// empty or tiny, and it is the difference between a race and a value.
		Groups: slices.Clone(opts.Segments),
		// SegmentsUnresolved is FALSE on this substrate, and that is a
		// statement about the callers rather than an omission: every static
		// plane that resolves segments denies the request on a resolver error
		// BEFORE reaching this engine (agent/human_actor_segment_gate.go,
		// mcp_identity.go), so an evaluation that gets here has either a
		// resolved set or a plane that resolves none at all. The dynamic
		// substrate is different - it carries the failure into the result as
		// EvaluationError - and its own observation site passes it through.
		SegmentsUnresolved: false,
		Action:             opts.ToolIdentity,
		Legacy: planeshadow.LegacyOutcome{
			Executable:      executable,
			EvaluationError: evaluationError,
		},
		Rows:    rows,
		Posture: postureOf(opts.ActionOverrides),
	})
}

// observedPhase returns the phase an observation should carry.
//
// A plane that evaluates ONE phase carries none: shadow.Case treats an empty
// phase as "this plane has one pass" and a phase-scoped world would then be
// built for a plane whose model declares no phases at all. A plane that
// evaluates TWO carries the one this pass ran, because production runs them
// separately and each resolves its own action column - conflating them into
// one comparison is the defect #3577's round 2 found in the offline corpus.
func observedPhase(plane legacycompile.Plane, phase Phase) legacycompile.Phase {
	spec, err := legacycompile.SpecFor(plane)
	if err != nil || len(spec.Phases) < 2 {
		return ""
	}
	switch phase {
	case PhaseRequest:
		return legacycompile.PhaseRequest
	case PhaseResponse:
		return legacycompile.PhaseResponse
	default:
		return ""
	}
}

// orgScopeOf renders the policy LOAD scope, which is what the shadow reads
// rows under. It is OrgScope when the caller supplied one and OrgID otherwise,
// mirroring loadFromDatabase's own scopeOrg resolution - a shadow that read a
// different scope than the plane loaded would compile a different policy set
// and report the difference as a migration finding.
func orgScopeOf(opts EvalOptions) string {
	// EXACTLY TWO RUNGS, BECAUSE THE WRITER HAS EXACTLY TWO.
	//
	// loadFromDatabase computes `scopeOrg := tenantID; if orgScope != nil &&
	// *orgScope != "" { scopeOrg = *orgScope }` and nothing else. This function
	// had a THIRD rung on opts.OrgID between them, which no writer has.
	//
	// It is unreachable today - every production call site that sets OrgID sets
	// OrgScope too - and that is not a reason to keep it. A future site setting
	// only OrgID would make the shadow compile its bundle from one scope while
	// the plane loaded its policies from another, and the resulting differences
	// would be attributed to the migration. A tenancy resolver must match the
	// WRITER of the structure it reads; a rung the writer does not have is a
	// divergence waiting for its first caller.
	if opts.OrgScope != nil && *opts.OrgScope != "" {
		return *opts.OrgScope
	}
	return opts.TenantID
}

// postureOf renders the action overrides as a plain map the shadow can carry
// without importing this package's Action type.
func postureOf(in map[PolicyCategory]Action) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[string(k)] = string(v)
	}
	return out
}
