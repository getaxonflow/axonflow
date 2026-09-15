// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

func strp(s string) *string { return &s }

func adaptedTypes(res AdaptResult) []string {
	out := make([]string, 0, len(res.Obligations))
	for _, o := range res.Obligations {
		out = append(out, string(o.Type)+"/"+string(o.Phase))
	}
	sort.Strings(out)
	return out
}

func mustGroup(t *testing.T, raw string) contract.ID {
	t.Helper()
	id, err := contract.ParseID(contract.KindGroup, raw)
	if err != nil {
		t.Fatalf("group id %q: %v", raw, err)
	}
	return id
}

var durableSink = []NotifyTarget{{Channel: "siem", Address: "s1", Delivery: contract.DeliveryDurable}}

// TestAdapterDistinguishesNullFromEmptyActionColumn is the core of the
// three-column mapping.
//
// action_request was added NULLABLE WITH NO DEFAULT, so most shipped rows
// carry NULL beside a set `action`. NULL means "this row says nothing about
// the request phase" and falls back to `action`. An EMPTY STRING is a
// different fact - a row written with a blank value - and the adapter refuses
// it rather than picking one of the two readings. A `string` field would have
// collapsed both at scan time and forced exactly that guess.
func TestAdapterDistinguishesNullFromEmptyActionColumn(t *testing.T) {
	base := LegacyPolicyRow{
		PolicyID: "p1", PolicyName: "PII", Action: "redact",
		Applicability: Applicable, RedactPaths: []string{"user.ssn"},
	}

	t.Run("NULL falls back to action", func(t *testing.T) {
		res, err := AdaptRow(base)
		if err != nil {
			t.Fatalf("adapt: %v", err)
		}
		if got := adaptedTypes(res); len(got) != 1 || got[0] != "field_redact/request" {
			t.Fatalf("types = %v, want one request-phase field_redact", got)
		}
	})

	t.Run("empty string is refused", func(t *testing.T) {
		row := base
		row.ActionRequest = strp("")
		_, err := AdaptRow(row)
		if err == nil || !strings.Contains(err.Error(), "NULL means") {
			t.Fatalf("err = %v, want a refusal that explains the NULL/empty distinction", err)
		}
	})

	t.Run("whitespace-only is refused too", func(t *testing.T) {
		row := base
		row.ActionResponse = strp("   ")
		if _, err := AdaptRow(row); err == nil {
			t.Fatal("a whitespace-only column must be refused, not trimmed into an empty action")
		}
	})
}

// TestRedactInTheResponsePhaseIsTheSameTypeInAnotherPhase: the legacy column
// says the same word in both phases and the canonical vocabulary has ONE type
// for it. The phase is the instance's, the target names which payload the
// field belongs to, and the executor registry declares field_redact in both
// phases - exactly as the PDP's legacy compiler emits it. Two instances, one
// per phase, not two types.
func TestRedactInTheResponsePhaseIsTheSameTypeInAnotherPhase(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{
		PolicyID: "p1", Action: "log", ActionResponse: strp("redact"),
		Applicability: Applicable, RedactPaths: []string{"user.ssn"},
		NotifyTargets: []NotifyTarget{{Channel: "audit", Address: "main", Delivery: contract.DeliveryDurable}},
	})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	got := adaptedTypes(res)
	want := []string{"field_redact/response", "immutable_audit/out_of_band"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("types = %v, want %v", got, want)
	}
	for _, o := range res.Obligations {
		if _, err := contract.FamilyOf(o.Type); err != nil {
			t.Errorf("%s is not in the canonical vocabulary: %v", o.Type, err)
		}
	}
}

// TestBothColumnsNullEmitsOneObligationNotTwo: the overwhelmingly common row.
// Emitting two would double every audit record and double-charge every
// reservation.
func TestBothColumnsNullEmitsOneObligationNotTwo(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "alert", Applicability: Applicable, NotifyTargets: durableSink})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Obligations) != 1 {
		t.Fatalf("got %d obligations, want 1: %+v", len(res.Obligations), res.Obligations)
	}
}

// TestBlockIsMappedToNothingOnPurpose. `block` is the authorization decision,
// not an obligation. The test exists so that "block produced no obligation"
// can never be read as "block was silently dropped": it must produce NO
// obligation AND NO unmapped entry.
func TestBlockIsMappedToNothingOnPurpose(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "block", Applicability: Applicable})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Obligations) != 0 {
		t.Errorf("block produced obligations %+v; the authorization decision carries it", res.Obligations)
	}
	if len(res.Unmapped) != 0 {
		t.Errorf("block was reported as unmapped %v; it is deliberately mapped to nothing", res.Unmapped)
	}
}

// TestModifyRiskIsReportedUnmappedNotSwallowed. Unlike `block`, modify_risk is
// an instruction that has to execute somewhere - on the inspection/risk plane.
// Swallowing it here would silently disable a risk adjustment.
func TestModifyRiskIsReportedUnmappedNotSwallowed(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "modify_risk", Applicability: Applicable})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Unmapped) != 1 || !strings.Contains(res.Unmapped[0], "inspection/risk plane") {
		t.Fatalf("unmapped = %v, want one entry naming the inspection/risk plane", res.Unmapped)
	}
}

// TestUnknownLegacyActionIsUnmappedNotDropped: the legacy engine's switch had
// a default case returning "no action", so a mis-typed action became a permit.
// Here it becomes a planner DENY with a reason code.
func TestUnknownLegacyActionIsUnmappedNotDropped(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "quarantine", Applicability: Applicable})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Unmapped) != 1 || !strings.Contains(res.Unmapped[0], "quarantine") {
		t.Fatalf("unmapped = %v, want the unrecognised action", res.Unmapped)
	}
	if len(res.Obligations) != 0 {
		t.Fatalf("an unrecognised action produced obligations: %+v", res.Obligations)
	}

	// And the planner denies on it, which is the point of returning it.
	reg := testRegistry(t)
	plan := Plan(PlanInput{Registry: reg, PEP: fullPEP(t, reg), Evidence: allSatisfied(reg), UnmappedLegacyActions: res.Unmapped})
	if plan.Outcome != OutcomeDeny {
		t.Fatalf("planner outcome = %q, want DENY", plan.Outcome)
	}
}

// TestAdapterCarriesTheApplicabilityTriStateThrough is the adapter's half of
// the INDET correction. An adapter that resolved Unknown into NotApplicable
// would reintroduce the fail-open one layer below the planner, where the
// planner could never see it.
func TestAdapterCarriesTheApplicabilityTriStateThrough(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{
		PolicyID: "p1", Action: "redact",
		Applicability: Unknown, ApplicabilityReason: contract.ReasonResolutionFailed,
		ApplicabilityDetail: "attribute user.clearance unresolved",
		RedactPaths:         []string{"user.ssn"},
	})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Obligations) != 1 {
		t.Fatalf("got %d obligations, want 1", len(res.Obligations))
	}
	o := res.Obligations[0]
	if o.Applicability != Unknown {
		t.Fatalf("applicability = %q, want %q; the adapter must not resolve the tri-state", o.Applicability, Unknown)
	}
	if o.ApplicabilityReason != contract.ReasonResolutionFailed || !strings.Contains(o.ApplicabilityDetail, "user.clearance") {
		t.Errorf("the named reason was lost: %q / %q", o.ApplicabilityReason, o.ApplicabilityDetail)
	}
	if o.Params != nil {
		t.Errorf("an unknown-applicability obligation must carry no params; got %v", o.Params)
	}
	if !o.Mandatory {
		t.Errorf("a legacy redact is mandatory")
	}
}

func TestAdapterRefusesARowWithNoApplicability(t *testing.T) {
	_, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "redact", RedactPaths: []string{"a"}})
	if err == nil || !strings.Contains(err.Error(), "will not default one") {
		t.Fatalf("err = %v, want a refusal to default the tri-state", err)
	}
	_, err = AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "redact", Applicability: Unknown, RedactPaths: []string{"a"}})
	if err == nil {
		t.Fatal("unknown applicability with no declared reason must be refused")
	}
	_, err = AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "redact", Applicability: Unknown, ApplicabilityReason: "because", RedactPaths: []string{"a"}})
	if err == nil {
		t.Fatal("unknown applicability with an UNDECLARED reason must be refused; the reason vocabulary is the attribute plane's")
	}
}

// TestAdapterRefusesToDefaultAnEligibleSet: `require_approval` with no clause
// configuration is the one place a permissive default would be catastrophic -
// "anyone may approve" is not an approval control.
func TestAdapterRefusesToDefaultAnEligibleSet(t *testing.T) {
	_, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "require_approval", Applicability: Applicable})
	if err == nil || !strings.Contains(err.Error(), "will not default an eligible set") {
		t.Fatalf("err = %v, want a refusal to default the eligible set", err)
	}
}

// TestAdapterRefusesARedactionWithNoTarget: a redaction with nothing to redact
// cannot be discharged, and admitting it would produce an obligation that
// always reports success having done nothing.
func TestAdapterRefusesARedactionWithNoTarget(t *testing.T) {
	if _, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "redact", Applicability: Applicable}); err == nil {
		t.Fatal("a redact row with no field paths must be refused")
	}
}

// TestLegacyRedactMapsToFieldRedactNotFieldRemove. The shipped redactor
// replaces with a marker; mapping to `field_remove` would claim a STRONGER
// guarantee than the engine provides, and the disclosure order would then let
// that false claim beat a real one. One obligation per path, each targeted.
func TestLegacyRedactMapsToFieldRedactNotFieldRemove(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: "redact", Applicability: Applicable, RedactPaths: []string{"user.ssn", "user.dob", "user.ssn"}})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Obligations) != 2 {
		t.Fatalf("got %d obligations, want one per DISTINCT path: %+v", len(res.Obligations), res.Obligations)
	}
	for _, o := range res.Obligations {
		if o.Type != contract.ObFieldRedact {
			t.Fatalf("type = %s, want %s: claiming remove would assert a stronger guarantee than the engine delivers", o.Type, contract.ObFieldRedact)
		}
		if o.Target != "user.dob" && o.Target != "user.ssn" {
			t.Fatalf("target = %q", o.Target)
		}
	}
}

// TestWarnIsAdvisoryAndAlertIsMandatory pins the distinction a numeric
// severity scale cannot make: the same type and the same family at different
// bindings.
func TestWarnIsAdvisoryAndAlertIsMandatory(t *testing.T) {
	for action, want := range map[string]bool{"warn": false, "alert": true, "log": false} {
		res, err := AdaptRow(LegacyPolicyRow{PolicyID: "p1", Action: action, Applicability: Applicable, NotifyTargets: durableSink})
		if err != nil {
			t.Fatalf("%s: adapt: %v", action, err)
		}
		if len(res.Obligations) != 1 {
			t.Fatalf("%s: got %d obligations", action, len(res.Obligations))
		}
		if got := res.Obligations[0].Mandatory; got != want {
			t.Errorf("%s: mandatory = %v, want %v", action, got, want)
		}
		if got := res.Obligations[0].Params["delivery"]; got != string(contract.DeliveryDurable) {
			t.Errorf("%s: delivery param = %q, want the canonical spelling %q", action, got, contract.DeliveryDurable)
		}
	}
}

// TestRouteIsNotLegalInTheResponsePhase: routing decides where a call goes,
// and there is nothing left to route once the response is in hand. It must be
// reported unmapped rather than silently accepted into a phase where no
// executor would run it.
func TestRouteIsNotLegalInTheResponsePhase(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{
		PolicyID: "p1", Action: "log", ActionResponse: strp("route"),
		Applicability: Applicable, RouteDestinations: []string{"eu"},
		NotifyTargets: []NotifyTarget{{Channel: "audit", Address: "m", Delivery: contract.DeliveryDurable}},
	})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Unmapped) != 1 || !strings.Contains(res.Unmapped[0], "not legal in the response phase") {
		t.Fatalf("unmapped = %v, want a phase-legality refusal", res.Unmapped)
	}
}

// TestAdapterAttributionSurvivesAMissingPolicyID. The WCP step gate can
// produce a row with a name and no id (its enqueue chokepoint deliberately
// does not require attribution), and losing it entirely would make the
// resulting deny unattributable.
func TestAdapterAttributionSurvivesAMissingPolicyID(t *testing.T) {
	res, err := AdaptRow(LegacyPolicyRow{PolicyName: "unknown", Action: "redact", Applicability: Applicable, RedactPaths: []string{"a"}})
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if res.Obligations[0].SourcePolicy != "unknown" {
		t.Fatalf("attribution = %q, want the policy name", res.Obligations[0].SourcePolicy)
	}
}

// TestAdaptRowsAccumulatesAcrossRows and deduplicates the unmapped list, so a
// deny reason does not repeat the same action a hundred times.
func TestAdaptRowsAccumulatesAcrossRows(t *testing.T) {
	rows := []LegacyPolicyRow{
		{PolicyID: "p1", Action: "quarantine", Applicability: Applicable},
		{PolicyID: "p1", Action: "quarantine", Applicability: Applicable},
		{PolicyID: "p2", Action: "redact", Applicability: Applicable, RedactPaths: []string{"a"}},
	}
	res, err := AdaptRows(rows)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Unmapped) != 1 {
		t.Fatalf("unmapped = %v, want one deduplicated entry", res.Unmapped)
	}
	if len(res.Obligations) != 1 {
		t.Fatalf("obligations = %+v, want one", res.Obligations)
	}
}

// TestAdaptedObligationsValidateAgainstTheInitialRegistry closes the loop: an
// adapter that produced something the registry rejects would turn every legacy
// row into a planner ERROR, and one that spelled a parameter in a vocabulary
// the algebra does not read would compose to nothing.
func TestAdaptedObligationsValidateAgainstTheInitialRegistry(t *testing.T) {
	reg := testRegistry(t)
	rows := []LegacyPolicyRow{
		{PolicyID: "p1", Action: "redact", Applicability: Applicable, RedactPaths: []string{"user.ssn"}},
		{PolicyID: "p2", Action: "require_approval", Applicability: Applicable,
			ApprovalClauses:    []contract.ApprovalClause{{Quorum: 1, Eligible: []contract.ID{mustGroup(t, "Group::realm_okta:security")}}},
			SeparationOfDuties: true},
		{PolicyID: "p3", Action: "route", Applicability: Applicable, RouteDestinations: []string{"eu"}},
		{PolicyID: "p4", Action: "alert", Applicability: Applicable, NotifyTargets: durableSink},
		{PolicyID: "p5", Action: "log", Applicability: Applicable,
			NotifyTargets: []NotifyTarget{{Channel: "audit", Address: "main", Delivery: contract.DeliveryDurable}}},
	}
	res, err := AdaptRows(rows)
	if err != nil {
		t.Fatalf("adapt: %v", err)
	}
	if len(res.Unmapped) != 0 {
		t.Fatalf("unmapped = %v, want none", res.Unmapped)
	}
	for _, o := range res.Obligations {
		if err := reg.ValidateObligation(o); err != nil {
			t.Errorf("adapted obligation %s does not validate: %v", o.Capability(), err)
		}
	}

	// And the whole set plans to a CHALLENGE (the approval has no evidence
	// yet), not to an ERROR or a DENY - through the one algebra, with the
	// approval's expiry and separation of duties reaching the composed
	// requirement.
	out := Plan(PlanInput{
		Registry:    reg,
		Payload:     contract.KnownPayloadLeaves("user.ssn", "user.name"),
		Obligations: res.Obligations,
		PEP:         fullPEP(t, reg),
		Evidence: map[contract.Capability]EvidenceState{
			{Type: contract.ObFieldRedact, Version: 1}:      EvidenceSatisfied,
			{Type: contract.ObRouteRestriction, Version: 1}: EvidenceSatisfied,
		},
		ApprovalExpiry: testNow.Add(48 * time.Hour), Now: testNow,
	})
	if out.Outcome != OutcomeChallenge {
		t.Fatalf("outcome = %q, want CHALLENGE. reasons=%v details=%v", out.Outcome, out.Reasons, out.Details)
	}
	if len(out.AwaitingEvidence) != 1 || out.AwaitingEvidence[0].Type != contract.ObApprovalChallenge {
		t.Fatalf("awaiting = %v, want the approval challenge", out.AwaitingEvidence)
	}
	if out.Plan.Approval == nil || !out.Plan.Approval.SeparationOfDuties || !out.Plan.Approval.ExpiresAt.Equal(testNow.Add(24*time.Hour)) {
		t.Fatalf("approval = %+v, want SoD on and the adapter's 24h default expiry (shorter than the evaluator's 48h)", out.Plan.Approval)
	}
}
