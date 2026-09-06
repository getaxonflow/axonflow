package contract

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The guards that keep ONE producer of the AuthZEN profile payload.
//
// There used to be two hand-maintained renderings of this mapping - ToAuthZEN
// in this package, which only tests called, and a struct literal in
// platform/agent's route handler, which every served response came from - and
// they had already drifted on exactly one member: the handler never set
// Approval. A capability entry and an OpenAPI document both advertised the
// approval challenge, and no response the surface ever returned carried one.
//
// The drift was invisible because the two halves were checked by different
// things and nothing checked them against each other. Three guards now do,
// each catching what the others cannot:
//
//   - THIS FILE holds the producer's INPUT against the wire SHAPE, so a member
//     added to the response cannot be left unreachable from the only function
//     that produces one.
//   - platform/agent's TestServedAuthZENContextEqualsToAuthZEN compares the
//     BYTES a real HTTP response carried against ToAuthZEN's rendering of the
//     equivalent decision, member for member. That is the behavioural half: a
//     second producer written in any syntax at all is caught there the moment
//     it differs.
//   - platform/agent's TestNothingButTheContractProducesAnAuthZENContext is the
//     syntactic half, and it is only as wide as the syntax it matches - which
//     is why it is not the only guard.

// derivedContextMembers are the response members NewAuthZENResponseContext
// computes rather than accepts, with the reason recorded beside each. An
// exemption with no argument is how a member quietly stops being checked.
var derivedContextMembers = map[string]string{
	"Profile": "the profile is the one version this build emits; accepting it as an input would let a caller " +
		"emit a context labelled with a profile whose rendering it is not",
	"Category": "the category is a projection of the reason code (CategoryFor); accepting it separately would let " +
		"the two halves of one outcome disagree, which is the disclosure boundary between the operator and the requester audience",
}

// TestEveryAuthZENResponseContextMemberIsSuppliedByItsInput is the ratchet.
//
// Adding a member to AuthZENResponseContext without adding it to
// AuthZENContextInput leaves that member unreachable from the only function
// that produces a context - it would be emitted at its zero value on every
// response, forever, and no compiler error would say so. That is precisely how
// Approval came to be advertised and never sent.
func TestEveryAuthZENResponseContextMemberIsSuppliedByItsInput(t *testing.T) {
	ctxType := reflect.TypeOf(AuthZENResponseContext{})
	inType := reflect.TypeOf(AuthZENContextInput{})

	inputMembers := map[string]reflect.Type{}
	for i := 0; i < inType.NumField(); i++ {
		f := inType.Field(i)
		if f.PkgPath != "" {
			continue
		}
		inputMembers[f.Name] = f.Type
	}
	if len(inputMembers) == 0 {
		t.Fatal("AuthZENContextInput declares no exported members, so every comparison below is vacuous")
	}

	consumed := map[string]bool{}
	for i := 0; i < ctxType.NumField(); i++ {
		f := ctxType.Field(i)
		if f.PkgPath != "" {
			continue // unexported; never on the wire
		}
		if why, derived := derivedContextMembers[f.Name]; derived {
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s is exempted from the input with no recorded reason", f.Name)
			}
			continue
		}
		inField, present := inputMembers[f.Name]
		if !present {
			t.Errorf("AuthZENResponseContext.%s is on the wire but AuthZENContextInput cannot supply it, and "+
				"NewAuthZENResponseContext does not derive it. It would be emitted at its zero value on every "+
				"response and nothing would say so - which is exactly how `approval` came to be advertised in "+
				"capabilities.go and agent-api.yaml and never sent. Add it to the input, or record it in "+
				"derivedContextMembers with the reason it is computed.", f.Name)
			continue
		}
		// TYPES, not only names. A member supplied as a different type is a
		// member the producer converts or truncates at one call site.
		if inField != f.Type {
			t.Errorf("AuthZENResponseContext.%s is %s and AuthZENContextInput.%s is %s", f.Name, f.Type, f.Name, inField)
		}
		consumed[f.Name] = true
	}

	// ...and the reverse, so an input member cannot outlive the wire member it
	// fed. A dead input reads as a supported member at every call site.
	var dead []string
	for name := range inputMembers {
		if !consumed[name] {
			dead = append(dead, name)
		}
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Errorf("AuthZENContextInput declares %s, which the response context does not carry; "+
			"a call site supplying it would believe it was setting something", strings.Join(dead, ", "))
	}

	// The exemption list cannot name a member that is not there.
	for name := range derivedContextMembers {
		if _, ok := ctxType.FieldByName(name); !ok {
			t.Errorf("derivedContextMembers names %q, which AuthZENResponseContext does not declare", name)
		}
	}
}

// TestCarriesObligationsAgreesWithTheAuthorizationMapping holds the predicate
// to the function it is derived from, over the whole enumeration.
//
// The point of deriving it from StateFor rather than writing
// `s == StateAllow || s == StateChallenge` is that the two cannot come apart.
// This asserts that they have not, for every declared state, in both
// directions - so a state that becomes reachable from a permit is covered
// automatically, and one that stops being reachable stops carrying
// instructions.
func TestCarriesObligationsAgreesWithTheAuthorizationMapping(t *testing.T) {
	fromPermit := map[OperationalState]bool{}
	for _, outstanding := range []bool{false, true} {
		st, err := StateFor(AuthzPermit, outstanding)
		if err != nil {
			t.Fatalf("StateFor(permit, %t): %v", outstanding, err)
		}
		fromPermit[st] = true
	}
	if len(fromPermit) == 0 {
		t.Fatal("no state is reachable from a permit, so the comparison below is vacuous")
	}
	for _, s := range AllOperationalStates() {
		if got, want := s.CarriesObligations(), fromPermit[s]; got != want {
			t.Errorf("%s.CarriesObligations() = %t, but StateFor says reachable-from-permit = %t", s, got, want)
		}
	}
	// The two halves are both non-empty, so the agreement above is not the
	// agreement of two constant answers.
	if !StateAllow.CarriesObligations() {
		t.Error("ALLOW does not carry obligations, which would make every permit's instructions unreachable")
	}
	if StateDeny.CarriesObligations() {
		t.Error("DENY carries obligations; attaching instructions to a denial invites a PEP to perform them and proceed")
	}
}

// TestTheProducerDropsInstructionsOnADecisionThatPermitsNothing drives the gate
// over the whole state enumeration rather than the two states a caller happens
// to produce today.
func TestTheProducerDropsInstructionsOnADecisionThatPermitsNothing(t *testing.T) {
	obligation := Obligation{
		Type: ObFieldRedact, Target: "args.query", Mandatory: true,
		SourcePolicy: "p-1", SchemaVersion: 1,
	}
	approval := &ApprovalRequirement{
		AllOf:     []ApprovalClause{{Quorum: 1, Eligible: []ID{{Kind: KindGroup, Type: "Group", Qualifier: "realm", Local: "g"}}}},
		ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	for _, s := range AllOperationalStates() {
		out := NewAuthZENResponseContext(AuthZENContextInput{
			State:         s,
			Reason:        ReasonPermitted,
			Obligations:   []Obligation{obligation},
			Approval:      approval,
			DecisionID:    "d-1",
			SchemaVersion: SchemaVersion,
		})
		carried := len(out.Obligations) > 0
		if carried != s.CarriesObligations() {
			t.Errorf("state %s: obligations carried = %t, want %t", s, carried, s.CarriesObligations())
		}
		if (out.Approval != nil) != s.CarriesObligations() {
			t.Errorf("state %s: approval carried = %t, want %t", s, out.Approval != nil, s.CarriesObligations())
		}
		if out.Profile != AuthZENProfileV1 {
			t.Errorf("state %s: profile %q, want %q", s, out.Profile, AuthZENProfileV1)
		}
		if out.Category != CategoryFor(ReasonPermitted) {
			t.Errorf("state %s: category %q, want the projection of the reason", s, out.Category)
		}
	}
}

// TestToAuthZENRendersThroughTheSharedProducer is the direct check that this
// package's own renderer did not keep a literal of its own.
//
// Comparing the two renderings rather than reading the source: a literal that
// happened to agree today is not the defect; a literal that can DISAGREE
// tomorrow is, and equality on every member is what rules it out.
func TestToAuthZENRendersThroughTheSharedProducer(t *testing.T) {
	// A CHALLENGE carrying BOTH an obligation and an approval requirement. An
	// ALLOW fixture would leave Approval nil, and a ToAuthZEN literal that
	// dropped Approval - the exact historical defect - would pass against it.
	d := &Decision{
		DecisionID: "d-1", RequestID: "r-1",
		Authorization: AuthzPermit, State: StateChallenge, Reason: ReasonApprovalRequired,
		Approval: &ApprovalRequirement{
			AllOf:              []ApprovalClause{{Quorum: 2, Eligible: []ID{{Kind: KindGroup, Type: "Group", Qualifier: "realm", Local: "reviewers"}}}},
			SeparationOfDuties: true,
			ExpiresAt:          time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		Obligations: []Obligation{{
			Type: ObFieldRedact, Target: "args.query", Mandatory: true,
			SourcePolicy: "p-1", SchemaVersion: 1,
		}},
		Determining: Determining{MatchedPermissions: []string{"p-1"}},
		Snapshot: Snapshot{
			IdentityEpoch: 1, ResourceEpoch: 1, PolicyBundle: "sha256:abc",
			RegistryVersion: 1, SchemaVersion: SchemaVersion, PolicyEpoch: 1,
		},
	}
	resp, err := d.ToAuthZEN(AuthZENProfileV1)
	if err != nil {
		t.Fatalf("ToAuthZEN: %v", err)
	}
	want := NewAuthZENResponseContext(AuthZENContextInput{
		State:         d.State,
		Reason:        d.Reason,
		Obligations:   d.Obligations,
		Approval:      d.Approval,
		DecisionID:    d.DecisionID,
		SchemaVersion: d.Snapshot.SchemaVersion,
	})
	if !reflect.DeepEqual(resp.Context, want) {
		t.Errorf("ToAuthZEN's context is not what the shared producer renders:\n got %+v\nwant %+v", resp.Context, want)
	}
	// The fixture is the discriminating one, asserted rather than assumed: both
	// members a dropped literal would lose are actually present.
	if resp.Context.Approval == nil {
		t.Error("the fixture produced no approval requirement, so a rendering that dropped Approval would pass")
	}
	if len(resp.Context.Obligations) == 0 {
		t.Error("the fixture produced no obligations, so a rendering that dropped them would pass")
	}
}

// TestEveryInputMemberReachesTheProfilePayload is the VALUE-level half, and it
// exists because the shape-level ratchet above cannot see an omission.
//
// The ratchet compares struct shapes: it holds AuthZENResponseContext's members
// against AuthZENContextInput's. It says nothing about whether
// NewAuthZENResponseContext ASSIGNS them. Demonstrated rather than imagined:
// deleting `Reason: in.Reason` from the producer - leaving
// `Category: CategoryFor(in.Reason)` in place, so the reason is still READ -
// left every package in platform/decision green and the whole agent AuthZEN
// suite green. The safe reason code, which all three customer-facing
// advertisements promise, could vanish from every negotiated response in the
// product and nothing would say so.
//
// The byte-equality test in platform/agent cannot close it either, and that is
// worth stating: both sides of that comparison now go through this producer, so
// a producer-side omission is SYMMETRIC and invisible to it. Converging on one
// mapping removes the drift between two renderings and, in exchange, makes a
// fault in the single rendering harder to see. This is the guard that pays for
// that trade.
//
// Every member is given a distinguishable non-zero value, and every member of
// the output is checked against it. Reflection over the input drives the
// completeness, so a member added tomorrow is covered without anyone
// remembering to add it here - the failure a hand-written list would produce is
// the one the ratchet above already had.
func TestEveryInputMemberReachesTheProfilePayload(t *testing.T) {
	in := AuthZENContextInput{
		State:  StateChallenge,
		Reason: ReasonApprovalRequired,
		Obligations: []Obligation{{
			Type: ObFieldRedact, Target: "args.query", Mandatory: true,
			SourcePolicy: "p-roundtrip", SchemaVersion: 7,
		}},
		Approval: &ApprovalRequirement{
			AllOf:              []ApprovalClause{{Quorum: 2, Eligible: []ID{{Kind: KindGroup, Type: "Group", Qualifier: "realm", Local: "reviewers"}}}},
			SeparationOfDuties: true,
			ExpiresAt:          time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC),
		},
		DecisionID:    "d-roundtrip",
		SchemaVersion: "roundtrip-version",
	}
	// The fixture must have no zero-valued member, or a member the producer
	// drops would compare equal to the value it failed to set.
	inValue := reflect.ValueOf(in)
	for i := 0; i < inValue.NumField(); i++ {
		f := inValue.Type().Field(i)
		if f.PkgPath != "" {
			continue
		}
		if inValue.Field(i).IsZero() {
			t.Fatalf("the fixture leaves AuthZENContextInput.%s at its zero value; a producer that dropped it "+
				"would compare equal to the value it failed to set", f.Name)
		}
	}
	// ...and the state must be one that CARRIES obligations, or the gate drops
	// two members legitimately and the check below reads that as a defect.
	if !in.State.CarriesObligations() {
		t.Fatalf("the fixture's state %s carries no obligations, so two members would be dropped by design", in.State)
	}

	out := NewAuthZENResponseContext(in)
	outValue := reflect.ValueOf(*out)

	for i := 0; i < inValue.NumField(); i++ {
		f := inValue.Type().Field(i)
		if f.PkgPath != "" {
			continue
		}
		got := outValue.FieldByName(f.Name)
		if !got.IsValid() {
			// The shape ratchet reports this; saying it twice adds noise.
			continue
		}
		if !reflect.DeepEqual(got.Interface(), inValue.Field(i).Interface()) {
			t.Errorf("NewAuthZENResponseContext did not carry %s onto the payload: got %#v, gave it %#v. "+
				"A member the producer reads but never assigns disappears from every negotiated response in the "+
				"product, and the shape ratchet cannot see it.", f.Name, got.Interface(), inValue.Field(i).Interface())
		}
	}

	// The two DERIVED members, checked against what they are derived FROM
	// rather than against a literal, so the check moves with the derivation.
	if out.Profile != AuthZENProfileV1 {
		t.Errorf("the payload names profile %q, want %q", out.Profile, AuthZENProfileV1)
	}
	if out.Category != CategoryFor(in.Reason) {
		t.Errorf("the payload's category is %q, want the projection of the reason (%q)", out.Category, CategoryFor(in.Reason))
	}
	// ...and the derivation is not a constant: a different reason must give a
	// different category, or `Category: CategoryFor(in.Reason)` could be
	// replaced by any fixed value and pass.
	other := in
	other.Reason = ReasonExplicitConstraint
	if CategoryFor(other.Reason) == CategoryFor(in.Reason) {
		t.Fatal("the two reasons used here project onto the same category, so the derivation check below is vacuous")
	}
	if NewAuthZENResponseContext(other).Category == out.Category {
		t.Error("the payload's category did not change with the reason; it is not derived from it")
	}
}
