// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

// THE DETECTOR FACTS EVERY ENFORCING SEAM DECIDES FROM (#3895, #3564; PRD v11
// §1.2).
//
// The shared engine's DETECTOR half is what the ADR-065 engine consumes: for
// each static policy an evaluation loaded, whether its detector ran on this
// content and whether it matched. An enforcing seam turns those facts into the
// anchored request's detector signals (observationOf), so a detector that ran
// is KNOWN at what it found and one that did not run is ABSENT - UNKNOWN to the
// engine, never a fabricated false.
//
// They are built on EVERY evaluation. Until v11 they were built only while the
// decision shadow could observe, because the shadow was their first consumer.
// The shadow is gone and every enforcing plane's verdict is the anchored
// engine's, so the facts are no longer optional: an evaluation without them
// would leave every detector-reading control UNKNOWN.
//
// They carry NO CONTENT: a policy identifier and two booleans per row, and the
// identity of a tool that scoped detectors out. The matched text, the request
// body and the caller's prompt are never here.

// Observation is one evaluation's detector facts, one row per policy the loader
// returned for the phase, before the category, capability and segment filters
// narrowed it. A policy the category or segment filter removed is present with
// Ran false: it did not look, which is not the same as looking and finding
// nothing. A policy capability scoping removed is present with Ran true and
// Matched false, and is named in CapabilityScoped.
type Observation struct {
	Rows []DetectorFact
	// CapabilityScoped names the detectors capability scoping (#2801) decided do
	// not apply to this request's tool, and that tool; nil when it scoped out
	// none. An execution-class match is not a finding for a tool positively
	// classified text-document, so each such detector's answer is a DETERMINED
	// false rather than unknown. This record is what lets an operator reading
	// that false on an audit row tell the reclassification from a miss.
	CapabilityScoped *CapabilityScoping
}

// CapabilityScoping is the tool that scoped detectors out and the policies
// whose detectors it scoped out, in load order.
type CapabilityScoping struct {
	Tool      string
	Detectors []string
}

// DetectorFact is what one loaded static policy's detector did.
type DetectorFact struct {
	PolicyID string
	// Ran reports that the detector was evaluated on this content (content with
	// no text in it to scan included: its answer is a determined no), or that
	// capability scoping decided it does not apply. Both evaluation passes run
	// every detector, past a block too, because a detector a pass skipped would
	// have to be reported as not run: saying "ran and did not match" would tell
	// the engine a detector positively did not fire when nothing looked, and
	// saying "not run" makes every control on it unknown to the anchored engine.
	Ran bool
	// Matched reports that the detector fired. A match whose redaction the
	// MaxRedactions cap discarded still matched: the detector found what it
	// found, and what the anchored decision does about it is the decision's.
	Matched bool
}

// detectorTrace accumulates the facts while an evaluation runs.
type detectorTrace struct {
	// loaded is the phase-filtered set the loader returned.
	loaded []CompiledPolicy
	// ran records, per policy_id, that the detector ACTUALLY RAN or was decided
	// not to apply. It is populated as the loop advances rather than from the
	// candidate slice, for DetectorFact.Ran's reason.
	ran map[string]bool
	// scoped is what capability scoping removed, nil when it removed nothing.
	scoped *CapabilityScoping
}

func newDetectorTrace() *detectorTrace { return &detectorTrace{ran: map[string]bool{}} }

// setLoaded records the phase-filtered set the loader returned.
func (t *detectorTrace) setLoaded(loaded []CompiledPolicy) { t.loaded = loaded }

// markRan records that a policy's detector was evaluated.
func (t *detectorTrace) markRan(policyID string) { t.ran[policyID] = true }

// scopeOut records the policies capability scoping removed from before for
// tool: each is DECIDED not to apply, so each reports as ran and unmatched, and
// the scoping itself is kept so the seam can say why.
func (t *detectorTrace) scopeOut(tool string, before, after []CompiledPolicy) {
	if len(after) == len(before) {
		return
	}
	kept := make(map[string]bool, len(after))
	for i := range after {
		kept[after[i].PolicyID] = true
	}
	for i := range before {
		id := before[i].PolicyID
		if kept[id] {
			continue
		}
		t.ran[id] = true
		if t.scoped == nil {
			t.scoped = &CapabilityScoping{Tool: tool}
		}
		t.scoped.Detectors = append(t.scoped.Detectors, id)
	}
}

// facts renders the evaluation's detector facts. matched is the evaluation's
// MatchedPolicies; a policy in it ran by definition.
func (t *detectorTrace) facts(matched []PolicyMatch) *Observation {
	fired := make(map[string]bool, len(matched))
	for _, m := range matched {
		fired[m.PolicyID] = true
	}
	rows := make([]DetectorFact, 0, len(t.loaded))
	for i := range t.loaded {
		id := t.loaded[i].PolicyID
		rows = append(rows, DetectorFact{PolicyID: id, Ran: t.ran[id] || fired[id], Matched: fired[id]})
	}
	return &Observation{Rows: rows, CapabilityScoped: t.scoped}
}
