// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"strings"
	"testing"
)

// testRegistry is the initial registry with ordering, or a fatal test failure.
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := NewInitialRegistryWithOrdering()
	if err != nil {
		t.Fatalf("build initial registry: %v", err)
	}
	return r
}

// fullPEP advertises every capability the initial registry defines, so that a
// test which is not ABOUT capability negotiation never trips over it.
func fullPEP(t *testing.T, r *Registry) PEPCapabilities {
	t.Helper()
	return PEPCapabilities{
		PEPID:          "test_pep",
		ProfileVersion: "axonflow.v1",
		Supported:      r.Capabilities(),
	}.Normalize()
}

// allSatisfied marks every release-gating capability as discharged, so a test
// that is not about evidence gets ALLOW rather than CHALLENGE.
func allSatisfied(r *Registry) map[Capability]EvidenceState {
	m := map[Capability]EvidenceState{}
	for _, c := range r.Capabilities() {
		m[c] = EvidenceSatisfied
	}
	return m
}

func hasReason(res PlanResult, code string) bool {
	for _, r := range res.Reasons {
		if r == code {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// THE OBLIGATIONS-INDET SHAPE (ADR-065's sharpest correction; DoD item 1)
// ---------------------------------------------------------------------------

// TestUnknownApplicabilityOfMandatoryObligationDenies reproduces the exact
// shape the source spec fails open on:
//
//	a ceiling whose AUTHORIZATION contribution is null (it denies nothing),
//	whose condition is UNEVALUABLE,
//	and which carries a MANDATORY redaction obligation.
//
// In the source spec that ceiling "resolves cleanly" - there is no deny to
// contribute, so the whole thing is discarded and the mandatory redaction goes
// with it, and the request is permitted UNREDACTED. ADR-065 reverses it: the
// mandatory obligation's applicability is unknown, so the decision denies.
//
// The three properties this test pins, each of which the source spec gets
// wrong in a different way:
//
//  1. the outcome is DENY, not ALLOW and not CHALLENGE;
//  2. the reason names APPLICABILITY, not a missing schema or a failed
//     discharge - because nothing failed, the system simply does not know;
//  3. the unevaluable condition's REASON survives into the trace, so an
//     operator can see which attribute could not be resolved.
//
// A compiling mutant that flips the disposition of unknown applicability is
// run against this test by
// platform/shared/requirements/mutationgate; without that, "the test asserts
// DENY" and "the code can only produce DENY" would be indistinguishable.
func TestUnknownApplicabilityOfMandatoryObligationDenies(t *testing.T) {
	reg := testRegistry(t)

	// The cap-null ceiling: it contributes no authorization constraint. Its
	// ONLY contribution is a mandatory redaction whose applicability could not
	// be established.
	capNullCeiling := Obligation{
		Type:                TypeFieldRedaction,
		Version:             1,
		Enforcement:         Mandatory,
		Applicability:       Unknown,
		ApplicabilityReason: "resolution_failed: directory attribute user.department is outside its freshness bound",
		SourcePolicyID:      "ceiling-pii-redaction",
		// No params: there was nothing to parameterise, because the condition
		// that would have selected the fields could not be evaluated.
	}

	res := Plan(PlanInput{
		Registry:    reg,
		Leaves:      StaticLeafResolver{Universe: []string{"user.name", "user.ssn"}},
		Obligations: []Obligation{capNullCeiling},
		PEP:         fullPEP(t, reg),
		Evidence:    allSatisfied(reg),
	})

	if res.Outcome != OutcomeDeny {
		t.Fatalf("outcome = %q, want %q. This is the source-spec fail-open: an obligations-only ceiling with an unevaluable condition must not resolve cleanly and drop its mandatory redaction.\nreasons=%v\ndetails=%v",
			res.Outcome, OutcomeDeny, res.Reasons, res.Details)
	}
	if !hasReason(res, ReasonApplicabilityUnknown) {
		t.Errorf("reasons = %v, want to contain %q", res.Reasons, ReasonApplicabilityUnknown)
	}
	joined := strings.Join(res.Details, " | ")
	if !strings.Contains(joined, "freshness bound") {
		t.Errorf("the unevaluable condition's named reason did not survive into the trace; details = %v", res.Details)
	}
	if !strings.Contains(joined, "ceiling-pii-redaction") {
		t.Errorf("the deny is unattributable: the source policy id is absent from the trace; details = %v", res.Details)
	}
	// The plan must be empty on a deny: handing a caller a composed plan for a
	// decision that denied invites a PEP to act on it.
	if len(res.Plan.Disclosure) != 0 {
		t.Errorf("plan must be empty on DENY, got %v", res.Plan.Disclosure)
	}
}

// TestUnknownApplicabilityOfAdvisoryObligationDoesNotDeny is the other half of
// the asymmetry, and it is what stops the fix above from becoming a
// deny-everything. An ADVISORY obligation whose applicability is unknown is
// dropped and RECORDED; it cannot deny.
func TestUnknownApplicabilityOfAdvisoryObligationDoesNotDeny(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{
		Registry: reg,
		Obligations: []Obligation{{
			Type:                TypeImmutableAudit,
			Version:             1,
			Enforcement:         Advisory,
			Applicability:       Unknown,
			ApplicabilityReason: "resolution_failed: sink registry unavailable",
			SourcePolicyID:      "advisory-audit",
		}},
		PEP:      fullPEP(t, reg),
		Evidence: allSatisfied(reg),
	})
	if res.Outcome != OutcomeAllow {
		t.Fatalf("outcome = %q, want %q; an advisory obligation must never deny. reasons=%v", res.Outcome, OutcomeAllow, res.Reasons)
	}
	if len(res.Dropped) != 1 || res.Dropped[0].Reason != "advisory_applicability_unknown" {
		t.Fatalf("the drop must be recorded, not silent; dropped = %+v", res.Dropped)
	}
	if res.Dropped[0].Enforcement != Advisory {
		t.Errorf("dropped record must carry the enforcement level; got %q", res.Dropped[0].Enforcement)
	}
}

// TestNotApplicableIsNotUnknown pins the distinction the whole tri-state rests
// on. A requirement policy whose condition was successfully evaluated and did
// NOT match is not the same fact as one that could not be evaluated, and only
// the second denies.
func TestNotApplicableIsNotUnknown(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{
		Registry: reg,
		Obligations: []Obligation{{
			Type:           TypeFieldRedaction,
			Version:        1,
			Enforcement:    Mandatory,
			Applicability:  NotApplicable,
			SourcePolicyID: "ceiling-pii-redaction",
		}},
		PEP:      fullPEP(t, reg),
		Evidence: allSatisfied(reg),
	})
	if res.Outcome != OutcomeAllow {
		t.Fatalf("outcome = %q, want %q: a positively established non-match must not deny. reasons=%v", res.Outcome, OutcomeAllow, res.Reasons)
	}
	if len(res.Dropped) != 1 || res.Dropped[0].Reason != "not_applicable" {
		t.Fatalf("dropped = %+v, want one not_applicable record", res.Dropped)
	}
}

// ---------------------------------------------------------------------------
// Pre-permit proofs 2, 3, 6
// ---------------------------------------------------------------------------

func TestUnknownSchemaVersionDeniesForMandatoryAndDropsForAdvisory(t *testing.T) {
	reg := testRegistry(t)
	base := Obligation{
		Type:           TypeFieldRedaction,
		Version:        99, // no such schema
		Applicability:  Applicable,
		SourcePolicyID: "p1",
		Params:         DisclosureParams{Paths: []string{"user"}, Transform: Transform{Kind: TransformRemove}},
	}

	mandatory := base
	mandatory.Enforcement = Mandatory
	res := Plan(PlanInput{Registry: reg, Obligations: []Obligation{mandatory}, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg)})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonSchemaUnknown) {
		t.Fatalf("mandatory unknown schema: outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonSchemaUnknown)
	}

	advisory := base
	advisory.Enforcement = Advisory
	res = Plan(PlanInput{Registry: reg, Obligations: []Obligation{advisory}, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg)})
	if res.Outcome != OutcomeAllow {
		t.Fatalf("advisory unknown schema: outcome=%q reasons=%v, want ALLOW", res.Outcome, res.Reasons)
	}
	if len(res.Dropped) != 1 {
		t.Fatalf("advisory unknown schema must be recorded; dropped=%+v", res.Dropped)
	}
}

// TestPEPMustAdvertiseTheExactVersion is the negotiation contract: a PEP that
// supports v1 does not thereby support v2. "Close enough" is the failure this
// prevents - a v1 PEP handed a v2 obligation would discharge it under the old
// meaning and report success.
func TestPEPMustAdvertiseTheExactVersion(t *testing.T) {
	reg := testRegistry(t)
	// A registry with both v1 and v2 of field_redaction.
	b := NewRegistryBuilder("test.v1")
	for _, c := range reg.Capabilities() {
		s, _ := reg.Lookup(c.Type, c.Version)
		b.Add(s)
	}
	v2, _ := reg.Lookup(TypeFieldRedaction, 1)
	v2.Version = 2
	b.Add(v2)
	reg2, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	v1OnlyPEP := PEPCapabilities{
		PEPID:     "old_pep",
		Supported: []Capability{{Type: TypeFieldRedaction, Version: 1}},
	}.Normalize()

	res := Plan(PlanInput{
		Registry: reg2,
		Leaves:   StaticLeafResolver{Universe: []string{"user.ssn"}},
		Obligations: []Obligation{{
			Type: TypeFieldRedaction, Version: 2, Enforcement: Mandatory, Applicability: Applicable,
			SourcePolicyID: "p1",
			Params:         DisclosureParams{Paths: []string{"user.ssn"}, Transform: Transform{Kind: TransformRemove}},
		}},
		PEP:      v1OnlyPEP,
		Evidence: map[Capability]EvidenceState{{Type: TypeFieldRedaction, Version: 2}: EvidenceSatisfied},
	})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonCapabilityUnsupported) {
		t.Fatalf("outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonCapabilityUnsupported)
	}
	// The refusal must be actionable: it should say what the PEP DOES support.
	if !strings.Contains(strings.Join(res.Details, " "), "[1]") {
		t.Errorf("refusal does not name the versions the PEP supports; details=%v", res.Details)
	}
}

// TestMandatoryOutOfBandObligationNeedsDurableDelivery is pre-permit proof 6.
func TestMandatoryOutOfBandObligationNeedsDurableDelivery(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{
		Type: TypeNotification, Version: 1, Family: FamilyAuditNotification,
		Owner: "notification_service", Phases: []Phase{PhaseOutOfBand},
		Delivery: DeliveryNone, OnFailure: FailClosed,
	})
	reg, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	res := Plan(PlanInput{
		Registry: reg,
		Obligations: []Obligation{{
			Type: TypeNotification, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
			SourcePolicyID: "p1",
			Params:         AuditNotifyParams{Targets: []AuditNotifyTarget{{Channel: "siem", Address: "sink1", Delivery: DeliveryNone}}},
		}},
		PEP:      PEPCapabilities{PEPID: "p", Supported: []Capability{{Type: TypeNotification, Version: 1}}}.Normalize(),
		Evidence: map[Capability]EvidenceState{},
	})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonDeliveryNotDurable) {
		t.Fatalf("outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonDeliveryNotDurable)
	}
}

// ---------------------------------------------------------------------------
// Pre-permit proof 5: evidence
// ---------------------------------------------------------------------------

// TestMissingEvidenceChallengesAndFailedEvidenceDenies pins the three-state
// evidence contract. Missing and failed must NOT produce the same outcome: an
// undischarged obligation invites the caller back, a failed one does not.
func TestMissingEvidenceChallengesAndFailedEvidenceDenies(t *testing.T) {
	reg := testRegistry(t)
	ob := Obligation{
		Type: TypeFieldRedaction, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
		SourcePolicyID: "p1",
		Params:         DisclosureParams{Paths: []string{"user.ssn"}, Transform: Transform{Kind: TransformRemove}},
	}
	leaves := StaticLeafResolver{Universe: []string{"user.ssn"}}

	missing := Plan(PlanInput{Registry: reg, Leaves: leaves, Obligations: []Obligation{ob}, PEP: fullPEP(t, reg), Evidence: map[Capability]EvidenceState{}})
	if missing.Outcome != OutcomeChallenge || !hasReason(missing, ReasonEvidenceMissing) {
		t.Fatalf("missing evidence: outcome=%q reasons=%v, want CHALLENGE with %q", missing.Outcome, missing.Reasons, ReasonEvidenceMissing)
	}
	if len(missing.AwaitingEvidence) != 1 || missing.AwaitingEvidence[0] != ob.Capability() {
		t.Fatalf("a CHALLENGE must name what it waits for; awaiting=%v", missing.AwaitingEvidence)
	}
	// A CHALLENGE still carries the plan: the coordinator needs to know what
	// it is holding for.
	if len(missing.Plan.Disclosure) == 0 {
		t.Errorf("a CHALLENGE must carry the composed plan; got an empty one")
	}

	failed := Plan(PlanInput{Registry: reg, Leaves: leaves, Obligations: []Obligation{ob}, PEP: fullPEP(t, reg),
		Evidence: map[Capability]EvidenceState{ob.Capability(): EvidenceFailed}})
	if failed.Outcome != OutcomeDeny || !hasReason(failed, ReasonDischargeFailed) {
		t.Fatalf("failed evidence: outcome=%q reasons=%v, want DENY with %q", failed.Outcome, failed.Reasons, ReasonDischargeFailed)
	}
}

// TestAbsentEvidenceIsNeverReadAsSatisfied guards the direction that matters:
// a capability with no entry in the evidence map must be treated as MISSING,
// never as satisfied. A map lookup's zero value for EvidenceState is "", and
// an unhandled "" that fell through to the satisfied branch would permit every
// undischarged obligation.
func TestAbsentEvidenceIsNeverReadAsSatisfied(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{
		Registry: reg,
		Leaves:   StaticLeafResolver{Universe: []string{"user.ssn"}},
		Obligations: []Obligation{{
			Type: TypeFieldRedaction, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
			SourcePolicyID: "p1",
			Params:         DisclosureParams{Paths: []string{"user.ssn"}, Transform: Transform{Kind: TransformRemove}},
		}},
		PEP:      fullPEP(t, reg),
		Evidence: nil, // no map at all
	})
	if res.Outcome == OutcomeAllow {
		t.Fatalf("a nil evidence map produced ALLOW; an obligation nobody has discharged must never permit")
	}
}

// TestDenyBeatsChallenge: when one mandatory obligation has already
// established that the request cannot proceed, the caller must not be invited
// back for an approval that could never help.
func TestDenyBeatsChallenge(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{
		Registry: reg,
		Leaves:   StaticLeafResolver{Universe: []string{"user.ssn"}},
		Obligations: []Obligation{
			{ // will CHALLENGE (no evidence)
				Type: TypeFieldRedaction, Version: 1, Enforcement: Mandatory, Applicability: Applicable,
				SourcePolicyID: "p1",
				Params:         DisclosureParams{Paths: []string{"user.ssn"}, Transform: Transform{Kind: TransformRemove}},
			},
			{ // will DENY (unknown applicability)
				Type: TypeStepUpAuthentication, Version: 1, Enforcement: Mandatory, Applicability: Unknown,
				ApplicabilityReason: "resolution_failed: assurance claim absent",
				SourcePolicyID:      "p2",
			},
		},
		PEP:      fullPEP(t, reg),
		Evidence: map[Capability]EvidenceState{},
	})
	if res.Outcome != OutcomeDeny {
		t.Fatalf("outcome=%q, want DENY: a deny must not be downgraded to a challenge. reasons=%v", res.Outcome, res.Reasons)
	}
}

// ---------------------------------------------------------------------------
// Advisory cannot satisfy a mandatory requirement
// ---------------------------------------------------------------------------

func TestAdvisoryObligationCannotSatisfyAMandatoryRequirement(t *testing.T) {
	reg := testRegistry(t)
	advisoryRedaction := Obligation{
		Type: TypeFieldRedaction, Version: 1, Enforcement: Advisory, Applicability: Applicable,
		SourcePolicyID: "p1",
		Params:         DisclosureParams{Paths: []string{"user.ssn"}, Transform: Transform{Kind: TransformRemove}},
	}
	res := Plan(PlanInput{
		Registry:          reg,
		Leaves:            StaticLeafResolver{Universe: []string{"user.ssn"}},
		Obligations:       []Obligation{advisoryRedaction},
		PEP:               fullPEP(t, reg),
		Evidence:          allSatisfied(reg),
		RequiredMandatory: []Type{TypeFieldRedaction},
	})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonAdvisoryCannotSatisfy) {
		t.Fatalf("outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonAdvisoryCannotSatisfy)
	}

	// The distinct reason code matters: "only advisory present" and "nothing
	// present" are different operator problems.
	res = Plan(PlanInput{
		Registry: reg, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg),
		RequiredMandatory: []Type{TypeFieldRedaction},
	})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonRequirementMissing) {
		t.Fatalf("outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonRequirementMissing)
	}
	if hasReason(res, ReasonAdvisoryCannotSatisfy) {
		t.Errorf("an absent requirement must not be reported as an advisory-only one")
	}
}

// ---------------------------------------------------------------------------
// Unmapped legacy actions
// ---------------------------------------------------------------------------

// TestUnmappedLegacyActionDenies: an enforcement instruction that survived
// into the new plane as an unrecognised string must not be dropped. The legacy
// engine's switch had a default case that returned "no action", which is how a
// mis-typed action became a permit.
func TestUnmappedLegacyActionDenies(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{
		Registry:              reg,
		PEP:                   fullPEP(t, reg),
		Evidence:              allSatisfied(reg),
		UnmappedLegacyActions: []string{"pol-7:quarantine"},
	})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonLegacyActionUnmapped) {
		t.Fatalf("outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonLegacyActionUnmapped)
	}
	if !strings.Contains(strings.Join(res.Details, " "), "quarantine") {
		t.Errorf("the unmapped action must be named; details=%v", res.Details)
	}
}

// ---------------------------------------------------------------------------
// Malformed input is ERROR, not DENY
// ---------------------------------------------------------------------------

func TestMalformedObligationIsErrorNotDeny(t *testing.T) {
	reg := testRegistry(t)
	cases := []struct {
		name string
		ob   Obligation
	}{
		{"version zero is not latest", Obligation{Type: TypeFieldRedaction, Version: 0, Enforcement: Mandatory, Applicability: Applicable, Params: DisclosureParams{Paths: []string{"a"}, Transform: Transform{Kind: TransformRemove}}}},
		{"no enforcement default", Obligation{Type: TypeFieldRedaction, Version: 1, Applicability: Applicable, Params: DisclosureParams{Paths: []string{"a"}, Transform: Transform{Kind: TransformRemove}}}},
		{"unknown applicability enum", Obligation{Type: TypeFieldRedaction, Version: 1, Enforcement: Mandatory, Applicability: Applicability("maybe")}},
		{"unknown applicability without a reason", Obligation{Type: TypeFieldRedaction, Version: 1, Enforcement: Mandatory, Applicability: Unknown}},
		{"applicable with nil params", Obligation{Type: TypeFieldRedaction, Version: 1, Enforcement: Mandatory, Applicability: Applicable}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Plan(PlanInput{Registry: reg, Obligations: []Obligation{tc.ob}, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg)})
			if res.Outcome != OutcomeError {
				t.Fatalf("outcome=%q, want ERROR (a plumbing defect pages the owning service; a DENY does not). reasons=%v", res.Outcome, res.Reasons)
			}
		})
	}
}

func TestMissingRegistryIsError(t *testing.T) {
	res := Plan(PlanInput{PEP: PEPCapabilities{PEPID: "p"}})
	if res.Outcome != OutcomeError {
		t.Fatalf("outcome=%q, want ERROR", res.Outcome)
	}
}

func TestInvalidPEPAdvertisementIsError(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{Registry: reg, PEP: PEPCapabilities{ /* no PEPID */ }})
	if res.Outcome != OutcomeError {
		t.Fatalf("outcome=%q, want ERROR: an unidentified PEP cannot be bound into a decision proof", res.Outcome)
	}
	res = Plan(PlanInput{Registry: reg, PEP: PEPCapabilities{PEPID: "p", Supported: []Capability{{Type: TypeFieldRedaction, Version: 0}}}})
	if res.Outcome != OutcomeError {
		t.Fatalf("outcome=%q, want ERROR: version 0 must not be read as 'any version'", res.Outcome)
	}
}
