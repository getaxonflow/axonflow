// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"testing"

	"axonflow/platform/decision/contract"
)

// TestAuditBothObligationAlgebrasAgreeOnMissingLeaf is the audit test from
// #3891, kept under its original name so the finding stays traceable.
//
// It was written against two algebras and it FAILED: with declared leaves
// [user.name] and a mandatory redact targeting user.ssn, the PDP's algebra
// answered Denied=false with one Unplaced obligation (absent target) while the
// requirements algebra answered a conflict (unknown target).
//
// IT NOW PASSES FOR ONE REASON, AND THE REASON IS STATED: there is one
// algebra. The planner does not compose, so the second value below is the
// first value read through the planner, and the two cannot disagree. That
// alone would make this test a tautology, so the expectation is PINNED AS A
// LITERAL rather than by comparing the two calls: the outcome is "not denied,
// one unplaced transform on user.ssn, nothing composed". A future planner that
// grew its own answer would fail the literal before it failed the comparison.
func TestAuditBothObligationAlgebrasAgreeOnMissingLeaf(t *testing.T) {
	reg := testRegistry(t)
	pep := &contract.PEPProfile{ID: "test", Capabilities: []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}}}
	wire := contract.Obligation{Type: contract.ObFieldRedact, SchemaVersion: 1, Mandatory: true, Target: "user.ssn", SourcePolicy: "redact-ssn"}

	pdp := contract.ComposeObligations(contract.ComposeInput{
		Payload:     contract.KnownPayloadLeaves("user.name"),
		Obligations: []contract.Obligation{wire},
		PEP:         pep,
	})
	planned := Plan(PlanInput{
		Registry: reg,
		Payload:  contract.KnownPayloadLeaves("user.name"),
		Obligations: []Obligation{{
			Obligation: wire, Phase: PhaseRequest, Applicability: Applicable,
		}},
		PEP:      pep,
		Evidence: map[contract.Capability]EvidenceState{},
	})

	// The literal: absent target, reported, permitted.
	if pdp.Denied || len(pdp.Unplaced) != 1 || pdp.Unplaced[0].Target != "user.ssn" || len(pdp.Obligations) != 0 {
		t.Fatalf("PDP: denied=%v unplaced=%+v composed=%+v; want not denied, one unplaced on user.ssn, nothing composed",
			pdp.Denied, pdp.Unplaced, pdp.Obligations)
	}
	if planned.Outcome != OutcomeAllow || len(planned.Plan.Unplaced) != 1 || planned.Plan.Unplaced[0].Target != "user.ssn" || len(planned.Plan.Obligations) != 0 {
		t.Fatalf("planner: outcome=%q unplaced=%+v composed=%+v reasons=%v; want ALLOW, one unplaced on user.ssn, nothing composed",
			planned.Outcome, planned.Plan.Unplaced, planned.Plan.Obligations, planned.Reasons)
	}
	if !hasReason(planned, ReasonTargetAbsentFromSchema) {
		t.Fatalf("the planner must REPORT the absent target under %q; reasons=%v", ReasonTargetAbsentFromSchema, planned.Reasons)
	}

	// And the contrast that the two algebras had collapsed: the SAME target
	// against an UNKNOWN schema denies on both sides, with the reason named.
	unknownPDP := contract.ComposeObligations(contract.ComposeInput{
		Payload: contract.UnknownPayloadLeaves(contract.ReasonNotSupplied), Obligations: []contract.Obligation{wire}, PEP: pep,
	})
	unknownPlanned := Plan(PlanInput{
		Registry: reg, Payload: contract.UnknownPayloadLeaves(contract.ReasonNotSupplied),
		Obligations: []Obligation{{Obligation: wire, Phase: PhaseRequest, Applicability: Applicable}},
		PEP:         pep, Evidence: map[contract.Capability]EvidenceState{},
	})
	if !unknownPDP.Denied || unknownPDP.Reason != contract.ReasonObligationConflict {
		t.Fatalf("PDP on an unknown schema: denied=%v reason=%q, want a conflict", unknownPDP.Denied, unknownPDP.Reason)
	}
	if unknownPlanned.Outcome != OutcomeDeny || !hasReason(unknownPlanned, ReasonConflict) {
		t.Fatalf("planner on an unknown schema: outcome=%q reasons=%v, want DENY with %q", unknownPlanned.Outcome, unknownPlanned.Reasons, ReasonConflict)
	}
}
