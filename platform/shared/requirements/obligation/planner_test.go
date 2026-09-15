// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

var testNow = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

// testRegistry is the initial registry with ordering, or a fatal test failure.
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := NewInitialRegistryWithOrdering()
	if err != nil {
		t.Fatalf("build initial registry: %v", err)
	}
	return r
}

// fullPEP advertises every capability the registry defines, so that a test
// which is not ABOUT capability negotiation never trips over it. It is the
// registry's own rendering, so the identity it advertises is the identity the
// registry keys on.
func fullPEP(t *testing.T, r *Registry) *contract.PEPProfile {
	t.Helper()
	return r.Profile("test_pep")
}

// allSatisfied marks every release-gating capability as discharged, so a test
// that is not about evidence gets ALLOW rather than CHALLENGE.
func allSatisfied(r *Registry) map[contract.Capability]EvidenceState {
	m := map[contract.Capability]EvidenceState{}
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

func joinedDetails(res PlanResult) string { return strings.Join(res.Details, " | ") }

// phaseFor picks the phase the initial registry declares first for a type, so
// a test that is not about phases never trips over the phase check.
func phaseFor(typ contract.ObligationType) Phase {
	switch typ {
	case contract.ObImmutableAudit, contract.ObNotification:
		return PhaseOutOfBand
	case contract.ObResponseFilter:
		return PhaseResponse
	}
	return PhaseRequest
}

// canon builds an APPLICABLE planner obligation around a canonical
// instruction. Every parameter is spelled in the canonical vocabulary; there
// is no other vocabulary to spell it in.
func canon(typ contract.ObligationType, target string, mandatory bool, src string, params map[string]string) Obligation {
	return Obligation{
		Obligation: contract.Obligation{
			Type: typ, Target: target, Params: params, Mandatory: mandatory, SourcePolicy: src, SchemaVersion: 1,
		},
		Phase:         phaseFor(typ),
		Applicability: Applicable,
	}
}

func redact(src, target string) Obligation {
	return canon(contract.ObFieldRedact, target, true, src, nil)
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
		Obligation: contract.Obligation{
			Type: contract.ObFieldRedact, Mandatory: true, SourcePolicy: "ceiling-pii-redaction", SchemaVersion: 1,
			// No target and no params: there was nothing to parameterise,
			// because the condition that would have selected the fields could
			// not be evaluated.
		},
		Phase:               PhaseRequest,
		Applicability:       Unknown,
		ApplicabilityReason: contract.ReasonStale,
		ApplicabilityDetail: "directory attribute user.department is outside its freshness bound",
	}

	res := Plan(PlanInput{
		Registry:    reg,
		Payload:     contract.KnownPayloadLeaves("user.name", "user.ssn"),
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
	joined := joinedDetails(res)
	if !strings.Contains(joined, "freshness bound") || !strings.Contains(joined, string(contract.ReasonStale)) {
		t.Errorf("the unevaluable condition's named reason did not survive into the trace; details = %v", res.Details)
	}
	if !strings.Contains(joined, "ceiling-pii-redaction") {
		t.Errorf("the deny is unattributable: the source policy id is absent from the trace; details = %v", res.Details)
	}
	// The plan must be empty on a deny: handing a caller a composed plan for a
	// decision that denied invites a PEP to act on it.
	if len(res.Plan.Obligations) != 0 || len(res.Plan.Order) != 0 {
		t.Errorf("plan must be empty on DENY, got %+v", res.Plan)
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
			Obligation:          contract.Obligation{Type: contract.ObImmutableAudit, SourcePolicy: "advisory-audit", SchemaVersion: 1},
			Phase:               PhaseOutOfBand,
			Applicability:       Unknown,
			ApplicabilityReason: contract.ReasonResolutionFailed,
			ApplicabilityDetail: "sink registry unavailable",
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
	if res.Dropped[0].Mandatory {
		t.Errorf("dropped record must carry the binding; got mandatory")
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
			Obligation:    contract.Obligation{Type: contract.ObFieldRedact, Mandatory: true, SourcePolicy: "ceiling-pii-redaction", SchemaVersion: 1},
			Phase:         PhaseRequest,
			Applicability: NotApplicable,
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
	base := redact("p1", "user")
	base.SchemaVersion = 99 // no such schema

	mandatory := base
	res := Plan(PlanInput{Registry: reg, Obligations: []Obligation{mandatory}, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg)})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonSchemaUnknown) {
		t.Fatalf("mandatory unknown schema: outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonSchemaUnknown)
	}

	advisory := base
	advisory.Mandatory = false
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
	// A registry with both v1 and v2 of field_redact.
	b := NewRegistryBuilder("test.v1")
	for _, c := range reg.Capabilities() {
		s, _ := reg.Lookup(c.Type, c.Version)
		b.Add(s)
	}
	v2, _ := reg.Lookup(contract.ObFieldRedact, 1)
	v2.Version = 2
	b.Add(v2)
	reg2, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	v1OnlyPEP := &contract.PEPProfile{ID: "old_pep", Capabilities: []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}}}

	ob := redact("p1", "user.ssn")
	ob.SchemaVersion = 2
	res := Plan(PlanInput{
		Registry:    reg2,
		Payload:     contract.KnownPayloadLeaves("user.ssn"),
		Obligations: []Obligation{ob},
		PEP:         v1OnlyPEP,
		Evidence:    map[contract.Capability]EvidenceState{{Type: contract.ObFieldRedact, Version: 2}: EvidenceSatisfied},
	})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonCapabilityUnsupported) {
		t.Fatalf("outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonCapabilityUnsupported)
	}
	// The refusal must be actionable: it should say what the PEP DOES support.
	if !strings.Contains(joinedDetails(res), "[1]") {
		t.Errorf("refusal does not name the versions the PEP supports; details=%v", res.Details)
	}
}

// TestMandatoryOutOfBandObligationNeedsDurableDelivery is pre-permit proof 6:
// the EXECUTOR registered for a mandatory out-of-band obligation must provide
// a durable delivery contract, whatever guarantee the obligation itself asked
// for.
func TestMandatoryOutOfBandObligationNeedsDurableDelivery(t *testing.T) {
	b := NewRegistryBuilder("test.v1")
	b.Add(Schema{
		Type: contract.ObNotification, Version: 1,
		Owner: "notification_service", Phases: []Phase{PhaseOutOfBand},
		Delivery: contract.DeliveryBestEffort, OnFailure: FailClosed,
	})
	reg, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	res := Plan(PlanInput{
		Registry:    reg,
		Obligations: []Obligation{canon(contract.ObNotification, "", true, "p1", map[string]string{"channel": "siem", "address": "sink1"})},
		PEP:         reg.Profile("p"),
		Evidence:    map[contract.Capability]EvidenceState{},
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
	ob := redact("p1", "user.ssn")
	payload := contract.KnownPayloadLeaves("user.ssn")

	missing := Plan(PlanInput{Registry: reg, Payload: payload, Obligations: []Obligation{ob}, PEP: fullPEP(t, reg), Evidence: map[contract.Capability]EvidenceState{}})
	if missing.Outcome != OutcomeChallenge || !hasReason(missing, ReasonEvidenceMissing) {
		t.Fatalf("missing evidence: outcome=%q reasons=%v, want CHALLENGE with %q", missing.Outcome, missing.Reasons, ReasonEvidenceMissing)
	}
	if len(missing.AwaitingEvidence) != 1 || missing.AwaitingEvidence[0] != ob.Capability() {
		t.Fatalf("a CHALLENGE must name what it waits for; awaiting=%v", missing.AwaitingEvidence)
	}
	// A CHALLENGE still carries the plan: the coordinator needs to know what
	// it is holding for.
	if len(missing.Plan.Obligations) == 0 {
		t.Errorf("a CHALLENGE must carry the composed plan; got an empty one")
	}

	failed := Plan(PlanInput{Registry: reg, Payload: payload, Obligations: []Obligation{ob}, PEP: fullPEP(t, reg),
		Evidence: map[contract.Capability]EvidenceState{ob.Capability(): EvidenceFailed}})
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
		Registry:    reg,
		Payload:     contract.KnownPayloadLeaves("user.ssn"),
		Obligations: []Obligation{redact("p1", "user.ssn")},
		PEP:         fullPEP(t, reg),
		Evidence:    nil, // no map at all
	})
	if res.Outcome == OutcomeAllow {
		t.Fatalf("a nil evidence map produced ALLOW; an obligation nobody has discharged must never permit")
	}
}

// TestAbsentTargetIsNotHeldForEvidence is the planner's half of the absent/
// unknown distinction: a mandatory transform whose target names no leaf of
// the KNOWN schema is vacuously satisfied, so it must neither CHALLENGE for a
// receipt nobody can produce nor deny. It is REPORTED under its own reason
// code, because the drift case (a schema that fell behind the real payload)
// is indistinguishable from the vacuous one and an operator must be able to
// find it.
func TestAbsentTargetIsNotHeldForEvidence(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{
		Registry:    reg,
		Payload:     contract.KnownPayloadLeaves("user.name"),
		Obligations: []Obligation{redact("p1", "user.ssn")},
		PEP:         fullPEP(t, reg),
		Evidence:    map[contract.Capability]EvidenceState{}, // nothing discharged
	})
	if res.Outcome != OutcomeAllow {
		t.Fatalf("outcome=%q reasons=%v details=%v, want ALLOW: an absent target cannot be waited on", res.Outcome, res.Reasons, res.Details)
	}
	if !hasReason(res, ReasonTargetAbsentFromSchema) {
		t.Errorf("reasons=%v, want %q so the drift case stays visible", res.Reasons, ReasonTargetAbsentFromSchema)
	}
	if len(res.Plan.Unplaced) != 1 || res.Plan.Unplaced[0].Target != "user.ssn" {
		t.Errorf("plan.Unplaced = %+v, want the absent transform", res.Plan.Unplaced)
	}
	if len(res.Plan.Obligations) != 0 {
		t.Errorf("plan carries %+v; nothing was placed", res.Plan.Obligations)
	}
	if len(res.AwaitingEvidence) != 0 {
		t.Errorf("awaiting %v; an absent target must not be held for evidence", res.AwaitingEvidence)
	}
}

// TestDenyBeatsChallenge: when one mandatory obligation has already
// established that the request cannot proceed, the caller must not be invited
// back for an approval that could never help.
func TestDenyBeatsChallenge(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{
		Registry: reg,
		Payload:  contract.KnownPayloadLeaves("user.ssn"),
		Obligations: []Obligation{
			redact("p1", "user.ssn"), // will CHALLENGE (no evidence)
			{ // will DENY (unknown applicability)
				Obligation:          contract.Obligation{Type: contract.ObStepUpAuth, Mandatory: true, SourcePolicy: "p2", SchemaVersion: 1},
				Phase:               PhaseRequest,
				Applicability:       Unknown,
				ApplicabilityReason: contract.ReasonResolutionFailed,
				ApplicabilityDetail: "assurance claim absent",
			},
		},
		PEP:      fullPEP(t, reg),
		Evidence: map[contract.Capability]EvidenceState{},
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
	advisoryRedaction := canon(contract.ObFieldRedact, "user.ssn", false, "p1", nil)
	res := Plan(PlanInput{
		Registry:          reg,
		Payload:           contract.KnownPayloadLeaves("user.ssn"),
		Obligations:       []Obligation{advisoryRedaction},
		PEP:               fullPEP(t, reg),
		Evidence:          allSatisfied(reg),
		RequiredMandatory: []contract.ObligationType{contract.ObFieldRedact},
	})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonAdvisoryCannotSatisfy) {
		t.Fatalf("outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonAdvisoryCannotSatisfy)
	}

	// The distinct reason code matters: "only advisory present" and "nothing
	// present" are different operator problems.
	res = Plan(PlanInput{
		Registry: reg, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg),
		RequiredMandatory: []contract.ObligationType{contract.ObFieldRedact},
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
	if !strings.Contains(joinedDetails(res), "quarantine") {
		t.Errorf("the unmapped action must be named; details=%v", res.Details)
	}
}

// ---------------------------------------------------------------------------
// Malformed input is ERROR, not DENY
// ---------------------------------------------------------------------------

func TestMalformedObligationIsErrorNotDeny(t *testing.T) {
	reg := testRegistry(t)
	mk := func(mutate func(*Obligation)) Obligation {
		o := redact("p1", "a")
		mutate(&o)
		return o
	}
	cases := []struct {
		name string
		ob   Obligation
	}{
		{"version zero is not latest", mk(func(o *Obligation) { o.SchemaVersion = 0 })},
		{"no phase default", mk(func(o *Obligation) { o.Phase = "" })},
		{"unknown applicability enum", mk(func(o *Obligation) { o.Applicability = Applicability("maybe") })},
		{"unknown applicability without a declared reason", mk(func(o *Obligation) { o.Applicability = Unknown })},
		{"unknown applicability with an undeclared reason", mk(func(o *Obligation) {
			o.Applicability = Unknown
			o.ApplicabilityReason = "because"
		})},
		{"a reason on an applicable obligation", mk(func(o *Obligation) { o.ApplicabilityReason = contract.ReasonStale })},
		{"a type the vocabulary does not declare", mk(func(o *Obligation) { o.Type = "field_redaction" })},
		{"applicable disclosure with no target", mk(func(o *Obligation) { o.Target = "" })},
		{"applicable with no source policy", mk(func(o *Obligation) { o.SourcePolicy = "" })},
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
	res := Plan(PlanInput{PEP: &contract.PEPProfile{ID: "p"}})
	if res.Outcome != OutcomeError {
		t.Fatalf("outcome=%q, want ERROR", res.Outcome)
	}
}

func TestInvalidPEPAdvertisementIsError(t *testing.T) {
	reg := testRegistry(t)
	res := Plan(PlanInput{Registry: reg, PEP: &contract.PEPProfile{ /* no ID */ }})
	if res.Outcome != OutcomeError {
		t.Fatalf("outcome=%q, want ERROR: an unidentified PEP cannot be bound into a decision proof", res.Outcome)
	}
	res = Plan(PlanInput{Registry: reg, PEP: nil})
	if res.Outcome != OutcomeError {
		t.Fatalf("outcome=%q, want ERROR: a plane that advertised nothing is not admitted", res.Outcome)
	}
	res = Plan(PlanInput{Registry: reg, PEP: &contract.PEPProfile{ID: "p", Capabilities: []contract.Capability{{Type: contract.ObFieldRedact, Version: 0}}}})
	if res.Outcome != OutcomeError {
		t.Fatalf("outcome=%q, want ERROR: version 0 must not be read as 'any version'", res.Outcome)
	}
}

// TestCompositionDenialsAreTranslatedNotReDecided pins the one-to-one table:
// every algebra reason code the planner can receive maps to exactly one
// planner code and outcome, and the algebra's own reason and detail survive
// verbatim in the trace.
func TestCompositionDenialsAreTranslatedNotReDecided(t *testing.T) {
	for _, code := range []contract.ReasonCode{
		contract.ReasonObligationConflict, contract.ReasonApprovalUnsatisfiable,
		contract.ReasonUnsupportedObligation, contract.ReasonSchemaViolation,
	} {
		if _, ok := compositionDenials[code]; !ok {
			t.Errorf("algebra reason %q has no planner translation; a composition denial with it would be an ERROR", code)
		}
	}
	reg := testRegistry(t)
	res := Plan(PlanInput{
		Registry: reg,
		Payload:  contract.KnownPayloadLeaves("user.ssn"),
		Obligations: []Obligation{
			canon(contract.ObFieldMask, "user.ssn", true, "p1", map[string]string{"keep": "last4"}),
			canon(contract.ObFieldMask, "user.ssn", true, "p2", map[string]string{"keep": "first6"}),
		},
		PEP: fullPEP(t, reg), Evidence: allSatisfied(reg),
	})
	if res.Outcome != OutcomeDeny || !hasReason(res, ReasonConflict) {
		t.Fatalf("outcome=%q reasons=%v, want DENY with %q", res.Outcome, res.Reasons, ReasonConflict)
	}
	if d := joinedDetails(res); !strings.Contains(d, string(contract.ReasonObligationConflict)) || !strings.Contains(d, "differing parameters") {
		t.Errorf("the algebra's reason and detail must survive verbatim; details=%v", res.Details)
	}
}

// TestNoOutcomeButAllowOrChallengeCarriesAPlan is the invariant the two ERROR
// paths after the plan is published would otherwise break. Handing a caller a
// composed plan for a decision that denied or errored invites an enforcement
// point to act on it, and an ERROR is exactly the case where the coordinator
// is least able to tell that it should not.
//
// The evidence-state case is reachable only through a malformed map, which is
// why it is driven directly rather than through a fixture.
func TestNoOutcomeButAllowOrChallengeCarriesAPlan(t *testing.T) {
	reg := testRegistry(t)
	ob := redact("p1", "user.ssn")
	payload := contract.KnownPayloadLeaves("user.ssn")

	res := Plan(PlanInput{
		Registry: reg, Payload: payload, Obligations: []Obligation{ob}, PEP: fullPEP(t, reg),
		Evidence: map[contract.Capability]EvidenceState{ob.Capability(): EvidenceState("who knows")},
	})
	if res.Outcome != OutcomeError {
		t.Fatalf("outcome=%q, want ERROR for an undeclared evidence state", res.Outcome)
	}
	if len(res.Plan.Obligations) != 0 || len(res.Plan.Order) != 0 || res.Plan.Approval != nil {
		t.Fatalf("an ERROR carried a composed plan: %+v", res.Plan)
	}

	// The positive control: the SAME input with a declared state does carry
	// one, so the assertion above is about the outcome and not about a plan
	// that was never built.
	ok := Plan(PlanInput{
		Registry: reg, Payload: payload, Obligations: []Obligation{ob}, PEP: fullPEP(t, reg),
		Evidence: map[contract.Capability]EvidenceState{ob.Capability(): EvidenceSatisfied},
	})
	if ok.Outcome != OutcomeAllow || len(ok.Plan.Obligations) != 1 {
		t.Fatalf("control: outcome=%q plan=%+v, want ALLOW carrying one obligation", ok.Outcome, ok.Plan)
	}
}
