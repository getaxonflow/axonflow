// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import "testing"

// TestTheDecisionWireVocabularyIsWellFormed holds the table to the contract it
// names: every entry is a declared obligation type at a valid schema version,
// no capability or wire name appears twice, and a lookup answers for exactly
// the declared capability - not for the same type at another version, which a
// PEP that claims v1 cannot be assumed to implement.
func TestTheDecisionWireVocabularyIsWellFormed(t *testing.T) {
	wire := DecisionWireObligations()
	if len(wire) == 0 {
		t.Fatal("the Decision API vocabulary is empty, so no decision-returning plane can hand any obligation to a caller")
	}
	capabilities, names := map[Capability]bool{}, map[string]bool{}
	for _, w := range wire {
		if _, err := FamilyOf(w.Capability.Type); err != nil {
			t.Errorf("%s is not a declared obligation type: %v", w.Capability, err)
		}
		if w.Capability.Version <= 0 {
			t.Errorf("%s carries no valid schema version", w.Capability)
		}
		if w.Name == "" {
			t.Errorf("%s has no wire name", w.Capability)
		}
		if capabilities[w.Capability] || names[w.Name] {
			t.Errorf("%s / %q appears twice; the wire must name one capability one way", w.Capability, w.Name)
		}
		capabilities[w.Capability], names[w.Name] = true, true

		name, ok := DecisionWireNameFor(Obligation{Type: w.Capability.Type, SchemaVersion: w.Capability.Version})
		if !ok || name != w.Name {
			t.Errorf("DecisionWireNameFor(%s) = (%q, %v); want (%q, true)", w.Capability, name, ok, w.Name)
		}
		if _, ok := DecisionWireNameFor(Obligation{Type: w.Capability.Type, SchemaVersion: w.Capability.Version + 1}); ok {
			t.Errorf("the wire claims to carry %s at version %d, which it does not declare", w.Capability.Type, w.Capability.Version+1)
		}
	}
	if got := DecisionWireCapabilities(); len(got) != len(wire) {
		t.Fatalf("DecisionWireCapabilities returned %d capabilities for a %d-entry vocabulary", len(got), len(wire))
	}

	// A copy, never the table: a caller appending to the result must not
	// change what the wire can say.
	mutated := DecisionWireObligations()
	mutated[0].Name = "mutated"
	if DecisionWireObligations()[0].Name == "mutated" {
		t.Fatal("DecisionWireObligations returned the table itself; a caller's edit changed the vocabulary")
	}
}
