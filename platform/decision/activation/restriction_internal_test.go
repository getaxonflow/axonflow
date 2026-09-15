// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/registry"
)

// phasePartitionViolations is the load arm's premise, stated over census rows:
// for a two-phase plane, a row lists the plane exactly when some phase witness
// lists it.
func phasePartitionViolations(rows []registry.CensusRow) []string {
	var out []string
	for _, p := range legacycompile.AllPlanes() {
		spec := legacycompile.MustSpecFor(p)
		if len(spec.Phases) < 2 {
			continue
		}
		for _, r := range rows {
			byWitness := false
			for _, ph := range spec.Phases {
				if listsAny(r.Planes, phaseWitnesses(spec, ph)) {
					byWitness = true
				}
			}
			if listsPlane(r.Planes, string(p)) != byWitness {
				out = append(out, r.PolicyID+" on "+string(p))
			}
		}
	}
	return out
}

// TestThePhaseWitnessesPartitionEveryTwoPhasePlanesLoad holds the witness
// derivation to the census in both directions: a row the plane loads that no
// witness lists would be dropped from BOTH phases, and a row a witness lists
// that the plane does not load would contradict the model's claim that planes
// on one read path agree about a phase.
func TestThePhaseWitnessesPartitionEveryTwoPhasePlanesLoad(t *testing.T) {
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	if v := phasePartitionViolations(rows); len(v) > 0 {
		t.Fatalf("the phase witnesses do not partition the census load of every two-phase plane: %v", v)
	}
	// PLANTED: a row listed on mcp and on no witness must be reported, or the
	// check above cannot fail.
	planted := []registry.CensusRow{{PolicyID: "planted_row", Planes: []string{string(legacycompile.PlaneMCP)}}}
	if v := phasePartitionViolations(planted); len(v) != 1 {
		t.Fatalf("a row listed on mcp and on no phase witness produced violations %v; want exactly one", v)
	}
	for _, ph := range legacycompile.MustSpecFor(legacycompile.PlaneMCP).Phases {
		if len(phaseWitnesses(legacycompile.MustSpecFor(legacycompile.PlaneMCP), ph)) == 0 {
			t.Fatalf("mcp's %s phase has no witness plane; the load arm would refuse it", ph)
		}
	}
}
