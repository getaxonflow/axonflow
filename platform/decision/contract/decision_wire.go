// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import "sort"

// THE DECISION API'S OBLIGATION VOCABULARY (#4046).
//
// A plane that RETURNS its decision - POST /api/v1/decide, and the AuthZEN
// surface that delegates to it - does not discharge a disclosure obligation
// itself. It hands the obligation to the enforcement point that called it,
// under a wire name and a fulfillment route, and that enforcement point
// discharges it. Which obligations that wire can carry is ONE closed table, and
// it lives here because every reader of it is in a different module or package
// and none of them may keep a copy:
//
//   - platform/agent's renderer (wireObligationsFor) and its capability
//     projection (mapObligations) are driven by it;
//   - activation.Activate is told it (Inputs.Delivers) by every caller that
//     builds an engine for a scope answering on this wire - the agent's decide
//     seam and the orchestrator's and portal's publish-time dry run, neither of
//     which can import the agent - and reads it to decide whether a mandatory
//     obligation can be discharged by a caller that declares it.
//
// A second table beside the renderer would be a second answer to "what can
// this wire say", and the two would disagree without either noticing. The
// agent's TestTheDecisionWireRendersExactlyItsVocabulary drives the renderer
// over every declared obligation type and holds it to this table in both
// directions.

// DecisionWireObligation is one obligation the Decision API can hand an
// enforcement point.
type DecisionWireObligation struct {
	// Capability is the exact type and schema version the wire expresses. An
	// enforcement point must declare exactly this capability to be handed the
	// obligation; the wire name carries no version, so it names this one.
	Capability Capability
	// Name is the obligation's name on the wire.
	Name string
}

// decisionWireObligations is the closed vocabulary.
var decisionWireObligations = []DecisionWireObligation{
	{Capability: Capability{Type: ObFieldRedact, Version: 1}, Name: "redact_pii"},
}

// DecisionWireObligations returns a copy of the vocabulary, sorted by
// capability.
func DecisionWireObligations() []DecisionWireObligation {
	out := append([]DecisionWireObligation(nil), decisionWireObligations...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Capability.Type != out[j].Capability.Type {
			return out[i].Capability.Type < out[j].Capability.Type
		}
		return out[i].Capability.Version < out[j].Capability.Version
	})
	return out
}

// DecisionWireCapabilities returns the capabilities the Decision API can hand
// to an enforcement point that declares them, sorted.
func DecisionWireCapabilities() []Capability {
	wire := DecisionWireObligations()
	out := make([]Capability, 0, len(wire))
	for _, w := range wire {
		out = append(out, w.Capability)
	}
	return out
}

// DecisionWireNameFor returns the wire name the Decision API carries an
// obligation under, and false when the wire cannot express that exact type
// and schema version.
func DecisionWireNameFor(o Obligation) (string, bool) {
	for _, w := range decisionWireObligations {
		if w.Capability == o.CapabilityOf() {
			return w.Name, true
		}
	}
	return "", false
}
