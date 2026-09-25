// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"slices"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// TestTheStepPlanesStateExactlyTheDeclaredStepContextArguments welds the step
// planes' producer map (stepContextFacts) to the arguments the system document
// declares for an organization's document to read
// (legacycompile.DeploymentDeclaredArguments), in both directions (#4249).
//
// A declared label the producer does not state is ABSENT on every plane, and a
// constraint over a caller-typed label treats absence as no_match, so an
// author's restriction on it would publish and then silently never apply. A
// producer entry that is not declared is dropped by the producer itself
// (dynamicFactProducer.fact states nothing for an undeclared path), so the map
// would claim a label no plane ever states. Both lists are hand-kept; this test
// is what keeps them one list.
func TestTheStepPlanesStateExactlyTheDeclaredStepContextArguments(t *testing.T) {
	declared := make([]string, 0, len(legacycompile.DeploymentDeclaredArguments))
	for _, a := range legacycompile.DeploymentDeclaredArguments {
		declared = append(declared, a.Path)
	}
	stated := make([]string, 0, len(stepContextFacts))
	for path := range stepContextFacts {
		stated = append(stated, path)
	}
	if len(declared) == 0 {
		t.Fatal("PREMISE: legacycompile.DeploymentDeclaredArguments declares nothing")
	}
	for _, path := range declared {
		if !slices.Contains(stated, path) {
			t.Errorf("%s is declared for an organization's document but no step plane states it (stepContextFacts), so a constraint over it would never apply", path)
		}
	}
	for _, path := range stated {
		if !slices.Contains(declared, path) {
			t.Errorf("%s is in the step planes' producer map (stepContextFacts) but not declared (legacycompile.DeploymentDeclaredArguments), so the producer drops it and no plane ever states it", path)
		}
	}
}
