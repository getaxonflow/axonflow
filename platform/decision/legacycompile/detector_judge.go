// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// DOES THIS SCOPE RUN THE DETECTORS A POLICY READS (#4249 row 5674230432).
//
// A policy that reads a registry detector (a static_policies row, through its
// signal.detector.* path) can only be decided on a scope whose call sites
// evaluate that row: anywhere else the detector is UNKNOWN, and the policy
// refuses every request it applies to as unknown_constraint. The shipped corpus
// has always been restricted per scope by this question (activation's
// restrictToScope). An organization's own document was not, so an organization
// control reading a registry detector withheld every request on the orchestrator
// planes, which run no registry detector.
//
// This is the ONE statement of the question, and it has TWO ENTRIES, named so
// the two callers cannot drift apart silently:
//
//   - Judge, all three arms, for the SHIPPED corpus (activation's
//     restrictToScope), exactly as that restriction always applied them.
//   - JudgeOrganization, for an organization's own document (activation's
//     organization arm and the publish validator, so publish's warning and
//     activation's omission are one answer). It applies the LOAD arm only, and
//     only on a scope that runs NO registry detector at all - the workflow step
//     gate, the multi-agent plane and the orchestrator request plane - where
//     such a control otherwise withheld every request. On a scope that runs
//     registry detectors it does not judge (DetectorArmNotApplied): a control
//     whose detector that scope drops on the category or phase arm stays as it
//     was, decided unknown and withheld, which is a separate ruling's (#4249
//     row on the agent planes), not a side effect of the plane split.
//
// THREE ARMS, in the order the restriction always applied them, each over the
// detector census (registry/detectors_census.tsv):
//
//   - LOAD: the census `planes` column lists the scope's plane.
//   - PHASE, on a scope that names one phase of a two-phase plane: the row
//     loads in that phase, which a WITNESS plane says - a single-phase plane on
//     the same read path whose only phase is it.
//   - CATEGORY: a call site on the scope passes the row's category to the
//     evaluator (AdmissionFor).
//
// ALL, NOT FIRST-MATCH. A policy reading two censused detectors is decided only
// where BOTH run: one unknown input makes the constraint Indeterminate, so a
// scope that runs one of them is exactly the scope where the policy would refuse
// every request. No shipped control reads two (activation's
// TestNoShippedControlReferencesTwoCensusedDetectors), so this is the explicit
// ALL that test's failure asks for, chosen before the first such control lands.

// DetectorArm is which arm a judgement came from.
type DetectorArm string

const (
	// DetectorArmUnjudged: the policy reads no censused detector, so the census
	// has no opinion and the policy is kept (a dynamic control's path is never
	// in it; the substrate places those).
	DetectorArmUnjudged DetectorArm = "unjudged"
	// DetectorArmKept: every censused detector it reads runs on the scope.
	DetectorArmKept DetectorArm = "kept"
	// DetectorArmLoad: a detector it reads does not load on the scope's plane.
	DetectorArmLoad DetectorArm = "load"
	// DetectorArmPhase: a detector it reads loads on the plane, not in the
	// scope's phase.
	DetectorArmPhase DetectorArm = "phase"
	// DetectorArmCategory: a detector it reads loads, and no call site on the
	// scope passes its category to the evaluator.
	DetectorArmCategory DetectorArm = "category"
	// DetectorArmNotApplied: JudgeOrganization on a scope that runs registry
	// detectors, which the organization pass does not judge.
	DetectorArmNotApplied DetectorArm = "not_applied"
)

// DetectorJudgement is one policy's answer on one scope.
type DetectorJudgement struct {
	Arm DetectorArm
	// Path is the signal path of the detector that decided a drop, empty when
	// kept or unjudged.
	Path string
	// Planes and Category are that detector's census planes and category.
	Planes   []string
	Category string
}

// Runs reports whether the scope decides the policy's detectors: kept, or no
// censused detector to judge.
func (j DetectorJudgement) Runs() bool {
	return j.Arm == DetectorArmKept || j.Arm == DetectorArmUnjudged || j.Arm == DetectorArmNotApplied
}

// censusEntry is what the judge reads about one censused detector.
type censusEntry struct {
	planes   []string
	category string
}

// ScopeDetectorJudge answers the three arms for one scope. Build it once per
// scope with NewScopeDetectorJudge.
type ScopeDetectorJudge struct {
	scope     EnforcementScope
	plane     string
	static    bool
	admission CategoryAdmission
	witnesses []string
	census    map[string]censusEntry
	// runsNone is true when no census row lists the scope's plane: the scope
	// runs no registry detector at all.
	runsNone bool
}

// NewScopeDetectorJudge builds the judge for scope. A static scope whose
// category admission cannot be derived, or a named phase with no witness, is
// REFUSED rather than judged: the zero admission admits nothing and would drop
// every control, a missing declaration dressed as a fact about the plane.
func NewScopeDetectorJudge(scope EnforcementScope) (*ScopeDetectorJudge, error) {
	scope, err := ScopeFor(scope.Plane, scope.Phase)
	if err != nil {
		return nil, fmt.Errorf("which detectors %s runs cannot be derived: %w", scope, err)
	}
	spec := MustSpecFor(scope.Plane)
	j := &ScopeDetectorJudge{scope: scope, plane: string(scope.Plane)}
	for _, s := range spec.Substrates {
		if s == SubstrateStatic {
			j.static = true
		}
	}
	if j.static {
		for _, ph := range scope.Phases() {
			a, err := AdmissionFor(scope.Plane, ph)
			if err != nil {
				return nil, fmt.Errorf("%s evaluates the static substrate and its category admission cannot be "+
					"derived, so which of its loaded controls its call sites actually evaluate is unknown: %w", scope, err)
			}
			j.admission = j.admission.Union(a)
		}
	}
	if scope.Phase != "" {
		j.witnesses = PhaseWitnesses(spec, scope.Phase)
		if len(j.witnesses) == 0 {
			return nil, fmt.Errorf("no single-phase plane on the %s read path evaluates the %s phase, so which "+
				"of %s's loaded controls load in that phase cannot be derived from the census", spec.StaticReadPath, scope.Phase, scope)
		}
	}
	rows, err := registry.ShippedCensus()
	if err != nil {
		return nil, fmt.Errorf("reading the shipped detector census: %w", err)
	}
	j.census = make(map[string]censusEntry, len(rows))
	j.runsNone = true
	for _, r := range rows {
		j.census[registry.DetectorID(r.PolicyID).SignalPath()] = censusEntry{planes: r.Planes, category: r.Category}
		if listsString(r.Planes, j.plane) {
			j.runsNone = false
		}
	}
	return j, nil
}

// Scope is the scope this judge answers for.
func (j *ScopeDetectorJudge) Scope() EnforcementScope { return j.scope }

// Admission is the scope's category admission, zero on a scope with no static
// substrate.
func (j *ScopeDetectorJudge) Admission() CategoryAdmission { return j.admission }

// RunsNoRegistryDetector reports whether no census row lists the scope's
// plane, so no registry detector is ever stated there.
func (j *ScopeDetectorJudge) RunsNoRegistryDetector() bool { return j.runsNone }

// JudgeOrganization answers an organization's own control on the judge's
// scope: the LOAD arm on a scope that runs no registry detector, and
// DetectorArmNotApplied on any other (see the file comment). A control that
// reads no censused detector is DetectorArmUnjudged on every scope.
func (j *ScopeDetectorJudge) JudgeOrganization(p pdp.Policy) DetectorJudgement {
	v := j.Judge(p)
	switch {
	case v.Arm == DetectorArmUnjudged:
		return v
	case !j.runsNone:
		return DetectorJudgement{Arm: DetectorArmNotApplied}
	}
	return v
}

// Judge answers p on the judge's scope, by all three arms (the shipped
// corpus's entry). Its censused detectors are judged in
// path order, and the first that fails an arm is the answer, so the reason
// names one detector deterministically; a policy is kept only when every one
// passes every arm.
func (j *ScopeDetectorJudge) Judge(p pdp.Policy) DetectorJudgement {
	var paths []string
	for _, path := range p.ReferencedPaths() {
		if contract.NamespaceOf(path) != contract.NsSignal {
			continue
		}
		if _, known := j.census[path]; known {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		return DetectorJudgement{Arm: DetectorArmUnjudged}
	}
	sort.Strings(paths)
	for _, path := range paths {
		fact := j.census[path]
		drop := DetectorJudgement{Path: path, Planes: append([]string(nil), fact.planes...), Category: fact.category}
		if !listsString(fact.planes, j.plane) {
			drop.Arm = DetectorArmLoad
			return drop
		}
		if j.scope.Phase != "" && !listsAnyString(fact.planes, j.witnesses) {
			drop.Arm = DetectorArmPhase
			return drop
		}
		if !j.admission.Admits(fact.category) {
			drop.Arm = DetectorArmCategory
			return drop
		}
	}
	return DetectorJudgement{Arm: DetectorArmKept}
}

// PhaseWitnesses are the planes whose listing of a row says it loads in one
// phase: single-phase planes on the same static read path whose only phase is
// that one. Derived from the plane model, so a plane added to it joins or
// leaves the witness set without an edit here.
func PhaseWitnesses(spec PlaneSpec, ph Phase) []string {
	var out []string
	for _, p := range AllPlanes() {
		w := MustSpecFor(p)
		if p == spec.Plane || w.StaticReadPath != spec.StaticReadPath || len(w.Phases) != 1 || w.Phases[0] != ph {
			continue
		}
		out = append(out, string(p))
	}
	return out
}

func listsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func listsAnyString(list, candidates []string) bool {
	for _, c := range candidates {
		if listsString(list, c) {
			return true
		}
	}
	return false
}
