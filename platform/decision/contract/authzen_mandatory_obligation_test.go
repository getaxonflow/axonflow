package contract

import (
	"testing"
	"time"
)

// permitWithObligations builds the smallest valid PERMIT carrying the given
// obligations, so a test can vary the one property it is about.
func permitWithObligations(t *testing.T, obs ...Obligation) *Decision {
	t.Helper()
	d := &Decision{
		DecisionID:    "d-1",
		RequestID:     "r-1",
		Authorization: AuthzPermit,
		State:         StateAllow,
		Reason:        ReasonPermitted,
		Obligations:   obs,
		Snapshot:      Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: "sha256:x"},
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("the fixture is not a valid decision, so nothing below is evidence: %v", err)
	}
	return d
}

// redactObligation is a mandatory disclosure transform on a leaf.
func redactObligation(mandatory bool) Obligation {
	return Obligation{
		Type:          ObFieldRedact,
		Target:        "response.ssn",
		Mandatory:     mandatory,
		SourcePolicy:  "test",
		SchemaVersion: 1,
	}
}

// TestToAuthZENDeniesAnAllowWhoseMandatoryObligationCannotBeDelivered pins the
// same rule the serving adapter enforces, at the OTHER site that renders a
// decision onto this wire.
//
// ToAuthZEN has no non-test caller today - the v10 route is served by
// platform/agent's adapter, and this is the function the v11 cutover switches
// to - but it carried the identical fail-open: a caller that did not negotiate
// the profile received the boolean, and the obligations that were preconditions
// of that boolean stayed behind in the response context it never got.
// "Unreachable today" is the state every fail-open starts in, and a v11 cutover
// is not the moment to discover this one.
func TestToAuthZENDeniesAnAllowWhoseMandatoryObligationCannotBeDelivered(t *testing.T) {
	mandatory := permitWithObligations(t, redactObligation(true))

	// The negotiated caller is untouched: it reads true AND receives the
	// obligation. Asserted first, because a `false` below proves nothing about
	// the withholding rule unless the same decision is genuinely an allow.
	got, err := mandatory.ToAuthZEN(AuthZENProfileV1)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !got.Decision {
		t.Fatal("the fixture is not an allow to a negotiated caller")
	}
	if got.Context == nil || len(got.Context.Obligations) != 1 || !got.Context.Obligations[0].Mandatory {
		t.Fatalf("the fixture does not carry a mandatory obligation: %+v", got.Context)
	}

	// An un-negotiated caller cannot receive the precondition, so it must not
	// be told the operation is permitted.
	for _, profile := range []AuthZENProfile{"", "axonflow-authzen-profile-2099-01-01", "garbage"} {
		bare, err := mandatory.ToAuthZEN(profile)
		if err != nil {
			t.Fatalf("rendering for %q: %v", profile, err)
		}
		if bare.Decision {
			t.Errorf("FAIL-OPEN: profile %q received decision:true with its mandatory obligation withheld", profile)
		}
		if bare.Context != nil {
			t.Errorf("profile %q received a profile context it did not negotiate", profile)
		}
	}
}

// TestToAuthZENStillAllowsWhatABarePEPMayPerform is the control.
//
// Without it, "deny whenever the profile was not negotiated" satisfies every
// assertion above while breaking every bare AuthZEN 1.0 caller. Both cases here
// are allows a PEP that receives nothing but the boolean is fully entitled to
// perform: one with no obligations at all, and one whose only obligation is
// ADVISORY - a suggestion, which is precisely what the profile gate was written
// for.
func TestToAuthZENStillAllowsWhatABarePEPMayPerform(t *testing.T) {
	for name, d := range map[string]*Decision{
		"an allow with no obligations":           permitWithObligations(t),
		"an allow whose obligation is advisory":  permitWithObligations(t, redactObligation(false)),
		"an allow with two advisory obligations": permitWithObligations(t, redactObligation(false), redactObligation(false)),
	} {
		bare, err := d.ToAuthZEN("")
		if err != nil {
			t.Fatalf("%s: rendering: %v", name, err)
		}
		if !bare.Decision {
			t.Errorf("%s: an unconditional allow was denied to a bare AuthZEN 1.0 caller; the rule is "+
				"keyed on negotiation rather than on the withheld obligation", name)
		}
		if bare.Context != nil {
			t.Errorf("%s: an un-negotiated caller received a profile context", name)
		}
	}
}

// TestToAuthZENLeavesAChallengeCarryingAMandatoryObligationAlone is the cell
// the deny control below cannot cover, and the only non-ALLOW state that can
// reach the rule.
//
// A CHALLENGE **is** a permit - StateFor maps AuthzPermit with an approval
// outstanding to StateChallenge - so Decision.Validate's "obligations are only
// carried on a permit" guard positively ALLOWS it to carry them, mandatory ones
// included. The DENY and ERROR states cannot construct the case at all, which
// makes this the one place where a rule that ignored the state would produce a
// visible difference: the decision must render false because it is a challenge,
// and it must NOT be reported as an obligation withheld from a caller that
// could not receive it. Nothing was withheld - execution was never on offer,
// and the caller's next move is to obtain the approval, not to send a header.
//
// The negotiated half is asserted first so the false below is evidence: it pins
// that this fixture really is a CHALLENGE really carrying a mandatory
// obligation, rather than something Validate quietly reshaped.
func TestToAuthZENLeavesAChallengeCarryingAMandatoryObligationAlone(t *testing.T) {
	challenged := &Decision{
		DecisionID:    "d-3",
		RequestID:     "r-3",
		Authorization: AuthzPermit,
		State:         StateChallenge,
		Reason:        ReasonApprovalRequired,
		Obligations:   []Obligation{redactObligation(true)},
		Approval: &ApprovalRequirement{
			AllOf:     []ApprovalClause{{Quorum: 2, Eligible: []ID{MustParseID(KindGroup, "Group::realm_ws:sec")}}},
			ExpiresAt: time.Now().Add(time.Hour),
		},
		Snapshot: Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: "sha256:x"},
	}
	if err := challenged.Validate(); err != nil {
		t.Fatalf("the fixture is not a valid decision, so nothing below is evidence: %v", err)
	}

	got, err := challenged.ToAuthZEN(AuthZENProfileV1)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if got.Decision {
		t.Fatal("a negotiated caller read a CHALLENGE as executable")
	}
	if got.Context == nil || got.Context.State != StateChallenge {
		t.Fatalf("the fixture is not a challenge to a negotiated caller: %+v", got.Context)
	}
	if len(got.Context.Obligations) != 1 || !got.Context.Obligations[0].Mandatory {
		t.Fatalf("the fixture carries no mandatory obligation, so the cell is vacuous: %+v", got.Context.Obligations)
	}
	if got.Context.Approval == nil {
		t.Error("a negotiated caller was told an approval is outstanding and not told what it is")
	}

	for _, profile := range []AuthZENProfile{"", "axonflow-authzen-profile-2099-01-01"} {
		bare, err := challenged.ToAuthZEN(profile)
		if err != nil {
			t.Fatalf("rendering for %q: %v", profile, err)
		}
		if bare.Decision {
			t.Errorf("profile %q read a CHALLENGE as executable", profile)
		}
		if bare.Context != nil {
			t.Errorf("profile %q received a profile context it did not negotiate", profile)
		}
		// The predicate must agree, because it is what decides the metric label
		// on the serving adapter: a challenge is not an integration that needs
		// to send a header.
		if MandatoryObligationWithheld(challenged.State, profile, challenged.Obligations) {
			t.Errorf("profile %q: a CHALLENGE carrying a mandatory obligation was classified as a "+
				"withheld-obligation deny; it is an approval that is outstanding, not a caller that "+
				"cannot receive an instruction", profile)
		}
	}
}

// TestToAuthZENLeavesTheNonPermitStatesAlone is the denied-path control.
//
// Validate forbids obligations on anything that is not an AuthzPermit, so DENY
// and ERROR cannot construct an obligation-carrying decision at all (CHALLENGE
// can, and has its own case above) - and the rendering must be exactly what it
// was before the rule existed.
func TestToAuthZENLeavesTheNonPermitStatesAlone(t *testing.T) {
	deny := &Decision{
		DecisionID: "d-2", RequestID: "r-2",
		Authorization: AuthzDeny, State: StateDeny, Reason: ReasonExplicitConstraint,
		Snapshot: Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: "sha256:x"},
	}
	for _, profile := range []AuthZENProfile{"", AuthZENProfileV1, "garbage"} {
		got, err := deny.ToAuthZEN(profile)
		if err != nil {
			t.Fatalf("rendering for %q: %v", profile, err)
		}
		if got.Decision {
			t.Errorf("profile %q read a denial as executable", profile)
		}
		if wantCtx := profile == AuthZENProfileV1; (got.Context != nil) != wantCtx {
			t.Errorf("profile %q: context present = %v, want %v", profile, got.Context != nil, wantCtx)
		}
	}
}
