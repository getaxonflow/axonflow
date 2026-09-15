// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringedition

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/agent/license"
	"axonflow/platform/decision/authoring"
)

// TestTheRowsOfTheResolutionTable states, by name, what every combination of
// the three signals means.
//
// It is a hand-written expectation and deliberately NOT a loop that recomputes
// the answer from establishmentFor - that would be an assertion computed from
// the function it claims to verify, which passes for any table at all. Writing
// the rows out is what makes moving one a decision rather than something
// inherited by the next edit.
//
// THE TWO MIDDLE COLUMNS ARE THE WHOLE POINT and are asserted separately: the
// construct set and the duty rule are the two directions of one fallback, and
// a test that only checked "is it Community" would pass on a resolver that had
// dropped the duty half entirely - which is the state main shipped in.
func TestTheRowsOfTheResolutionTable(t *testing.T) {
	type want struct {
		establishment Establishment
		edition       authoring.Edition
		requiresSoD   bool
		// enforcesBoundary is EnforcesConstructBoundary: may a control refuse
		// an ALREADY ACTIVE document for spending a construct outside this
		// edition. It is a THIRD column rather than a restatement of
		// establishment, because the two differ on exactly one row and that
		// row is the reason the column exists.
		enforcesBoundary bool
	}
	cases := []struct {
		name                     string
		read                     license.TierRead
		modeIsEnterpriseEntitled bool
		inLicenceTransition      bool
		want                     want
	}{
		{
			name:                     "a verified Enterprise key on an entitled mode is the ordinary Enterprise deployment",
			read:                     license.TierRead{Tier: license.TierEnterprise, KeyPresent: true},
			modeIsEnterpriseEntitled: true,
			want:                     want{EstablishedByKey, authoring.EditionEnterprise, true, true},
		},
		{
			name:                     "a verified Evaluation key establishes Evaluation, which carries no duty rule",
			read:                     license.TierRead{Tier: license.TierEvaluation, KeyPresent: true},
			modeIsEnterpriseEntitled: false,
			want:                     want{EstablishedByKey, authoring.EditionEvaluation, false, true},
		},
		{
			// THE NEGATIVE TWIN. Without this row the fix could be "require a
			// second approver everywhere", which would put #3907 straight back
			// where it was: a single administrator unable to publish one
			// policy on the deployment the whole ladder exists for.
			name:                     "no key on a mode that is not entitled is a GENUINE Community deployment: sole author, as #3907 requires",
			read:                     license.TierRead{Tier: license.TierCommunity},
			modeIsEnterpriseEntitled: false,
			want:                     want{EstablishedByMode, authoring.EditionCommunity, false, true},
		},
		{
			// THE DEFECT. The portal's container, on an Enterprise stack.
			name:                     "no key on an ENTITLED mode cannot establish a tier: Community constructs, and the duty rule stays ON",
			read:                     license.TierRead{Tier: license.TierCommunity},
			modeIsEnterpriseEntitled: true,
			want:                     want{UnestablishedKeyAbsent, authoring.EditionCommunity, true, false},
		},
		{
			// An expired or forged key. The deployment believes it holds a
			// tier and this process cannot confirm which, on ANY mode.
			name:                     "a rejected key cannot establish a tier even on a mode that is not entitled",
			read:                     license.TierRead{Tier: license.TierCommunity, Rejected: true, Reason: "license expired on 2026-01-01"},
			modeIsEnterpriseEntitled: false,
			want:                     want{UnestablishedKeyRejected, authoring.EditionCommunity, true, false},
		},
		{
			name:                     "a rejected key on an entitled mode is reported as the rejection, not as the absence",
			read:                     license.TierRead{Tier: license.TierCommunity, Rejected: true, Reason: "signature"},
			modeIsEnterpriseEntitled: true,
			want:                     want{UnestablishedKeyRejected, authoring.EditionCommunity, true, false},
		},
		{
			// THE WIND-DOWN. No key, a mode that claims nothing, and an
			// operator who has DECLARED why (LicenceTransitionMode on the
			// marketplace template). The authoring boundary is exactly the
			// genuine-Community row above - same edition, same sole author -
			// and the ONE thing that differs is the last column: a control may
			// not refuse this deployment's already-active documents for
			// spending constructs it was entitled to last week.
			name:                     "a DECLARED licence transition is established, authors exactly as Community, and does NOT enforce the construct boundary",
			read:                     license.TierRead{Tier: license.TierCommunity},
			modeIsEnterpriseEntitled: false,
			inLicenceTransition:      true,
			want:                     want{EstablishedByTransition, authoring.EditionCommunity, false, false},
		},
		{
			// ORDER, ROW 1. A declaration is configuration; a key is a
			// signature. Without this row the transition arm could be moved
			// above the key rows and nothing would fail, which would let one
			// environment variable launder a verified Enterprise deployment
			// into the softer boundary.
			name:                     "a declared transition does NOT displace a verified key",
			read:                     license.TierRead{Tier: license.TierEnterprise, KeyPresent: true},
			modeIsEnterpriseEntitled: true,
			inLicenceTransition:      true,
			want:                     want{EstablishedByKey, authoring.EditionEnterprise, true, true},
		},
		{
			// ORDER, ROW 2. A forged or expired key stays a question for the
			// operator. A declaration must not answer it.
			name:                     "a declared transition does NOT convert a rejected key into a transition",
			read:                     license.TierRead{Tier: license.TierCommunity, Rejected: true, Reason: "signature"},
			modeIsEnterpriseEntitled: false,
			inLicenceTransition:      true,
			want:                     want{UnestablishedKeyRejected, authoring.EditionCommunity, true, false},
		},
		{
			// ORDER, ROW 3. The portal defect stays the portal defect: a mode
			// that says the deployment IS entitled to Enterprise has not ended
			// anything, so the remedy is still to plumb the licence key.
			name:                     "a declared transition on an ENTITLED mode is still the unplumbed-key defect",
			read:                     license.TierRead{Tier: license.TierCommunity},
			modeIsEnterpriseEntitled: true,
			inLicenceTransition:      true,
			want:                     want{UnestablishedKeyAbsent, authoring.EditionCommunity, true, false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolve(tc.read, tc.modeIsEnterpriseEntitled, tc.inLicenceTransition)
			if got.Establishment != tc.want.establishment {
				t.Errorf("establishment = %q, want %q", got.Establishment, tc.want.establishment)
			}
			if got.Profile.Edition() != tc.want.edition {
				t.Errorf("edition = %q, want %q", got.Profile.Edition(), tc.want.edition)
			}
			if got.Profile.RequiresSeparationOfDuties() != tc.want.requiresSoD {
				t.Errorf("RequiresSeparationOfDuties() = %t, want %t - this is the direction that decides whether "+
					"one person can publish and activate alone", got.Profile.RequiresSeparationOfDuties(), tc.want.requiresSoD)
			}
			if got.Profile.TierEstablished() != tc.want.establishment.Established() {
				t.Errorf("TierEstablished() = %t but the establishment is %q; the profile and the reason disagree",
					got.Profile.TierEstablished(), got.Establishment)
			}
			// THE COLUMN THAT IS NOT A RESTATEMENT. Established() and
			// EnforcesConstructBoundary() agree on every row but the
			// transition one, so asserting only the first would let the new
			// state be unreachable - or reachable and identical to
			// EstablishedByMode - and this table would still pass.
			if got.EnforcesConstructBoundary() != tc.want.enforcesBoundary {
				t.Errorf("EnforcesConstructBoundary() = %t, want %t - this is what decides whether an ALREADY "+
					"ACTIVE document is refused at the enforcement seam, where a refusal is a 503 rather than a "+
					"sentence an author reads", got.EnforcesConstructBoundary(), tc.want.enforcesBoundary)
			}
		})
	}
}

// TestTheAsymmetryHoldsInBothDirectionsAtOnce is the property the table above
// states row by row, asserted as one sentence about one value.
//
// A uniform fail-closed and a uniform fail-soft would each satisfy half of the
// table and neither satisfies this: the SAME profile must refuse an
// Enterprise-only construct and require an Enterprise-only second approver.
func TestTheAsymmetryHoldsInBothDirectionsAtOnce(t *testing.T) {
	p := resolve(license.TierRead{Tier: license.TierCommunity}, true, false).Profile
	if p.AllowsGroupScope() {
		t.Error("an unestablished tier was granted group scope; the CONSTRUCT half must fail soft to Community")
	}
	if !p.RequiresSeparationOfDuties() {
		t.Error("an unestablished tier was not required to name a second approver; the DUTY half must fail closed")
	}
	if got := p.Constructs(); got.SeparationOfDuties != true || got.Edition != authoring.EditionCommunity || got.TierEstablished {
		t.Errorf("the reported boundary does not say both halves: %+v", got)
	}
}

// TestAnUnestablishedTierIsCounted proves the operator-facing observable is
// WRITTEN, rather than proving that a log line was formatted.
//
// The counter is what makes a misconfigured deployment findable from a metrics
// scrape instead of from a customer noticing that one person can publish alone.
func TestAnUnestablishedTierIsCounted(t *testing.T) {
	before := counterValue(t, string(UnestablishedKeyAbsent))
	resolve(license.TierRead{Tier: license.TierCommunity}, true, false)
	after := counterValue(t, string(UnestablishedKeyAbsent))
	if after != before+1 {
		t.Fatalf("the unestablished resolution was not counted: %v -> %v", before, after)
	}

	// AND AN ESTABLISHED ONE IS NOT. Without this the counter could be
	// incremented unconditionally and the assertion above would still pass,
	// leaving a series that fires on every healthy deployment - an alert that
	// means nothing is worse than no alert.
	quiet := counterValue(t, string(UnestablishedKeyAbsent))
	resolve(license.TierRead{Tier: license.TierCommunity}, false, false)
	resolve(license.TierRead{Tier: license.TierEnterprise, KeyPresent: true}, true, false)
	if got := counterValue(t, string(UnestablishedKeyAbsent)); got != quiet {
		t.Fatalf("an ESTABLISHED resolution moved the unestablished counter: %v -> %v", quiet, got)
	}
}

// TestEveryEstablishmentValueIsRuled holds the two-member Established() set
// total over the declared constants.
//
// A fifth Establishment added without a ruling would otherwise be
// UNestablished by silence. That is the safe direction, and this test is what
// turns "safe by silence" into "decided": the new value has to be added here,
// which is the moment somebody chooses.
func TestEveryEstablishmentValueIsRuled(t *testing.T) {
	want := map[Establishment]bool{
		EstablishedByKey:  true,
		EstablishedByMode: true,
		// A declared transition IS established, and that is a ruling rather
		// than an omission: the unestablished profile requires a second
		// approver, so treating a wind-down as unestablished would turn the
		// two-person rule ON for an operator whose licence has just lapsed.
		// What a transition does not do is enforce the construct boundary -
		// asserted per row in the resolution table, not here.
		EstablishedByTransition:  true,
		UnestablishedKeyRejected: false,
		UnestablishedKeyAbsent:   false,
	}
	for e, established := range want {
		if e.Established() != established {
			t.Errorf("%q.Established() = %t, want %t", e, e.Established(), established)
		}
	}
	// The set is closed: anything outside it is unestablished, which is the
	// fail-closed direction for the duty rule.
	if Establishment("something_new").Established() {
		t.Error("an undeclared Establishment reported as established")
	}
}

func counterValue(t *testing.T, cause string) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 32)
	go func() { unresolvedTierObserved.Collect(ch); close(ch) }()
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("reading the counter: %v", err)
		}
		for _, l := range pb.GetLabel() {
			if l.GetName() == "cause" && l.GetValue() == cause {
				return pb.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// TestTheRefusalMessageNamesTheVariableAndNotJustTheProblem is a small test
// about a large failure mode.
//
// The whole cost of this defect was that nothing said which INPUT was missing.
// A message that says "the tier could not be established" and stops leaves an
// operator with the same problem one layer up, so the name of the variable is
// part of the fix rather than decoration on it.
func TestTheRefusalMessageNamesTheVariableAndNotJustTheProblem(t *testing.T) {
	if EnvLicenseKey != "AXONFLOW_LICENSE_KEY" {
		t.Fatalf("EnvLicenseKey = %q; it must name the variable license.ReadCurrentTier actually reads, "+
			"because the log line, the metric help text and the deployment guard all cite it", EnvLicenseKey)
	}
	if !strings.Contains(string(UnestablishedKeyAbsent), "absent") {
		t.Errorf("the cause label does not distinguish absence from rejection: %q", UnestablishedKeyAbsent)
	}
}
