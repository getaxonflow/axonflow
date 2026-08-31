package contract

import (
	"strings"
	"testing"
	"time"
)

// TestExactEncodingDoesNotNormalizeAndCanonicalDoes pins the split between the
// two encoders.
//
// They exist for different jobs and must not be interchangeable. Cross-gateway
// agreement about a request wants two Unicode compositions of one string to be
// one string; artifact integrity wants them to be two artifacts, because the
// compiler that reads the artifact reads bytes.
func TestExactEncodingDoesNotNormalizeAndCanonicalDoes(t *testing.T) {
	// Built from explicit code points rather than written as two literals that
	// look alike: two source literals a reader cannot tell apart are two
	// literals a WRITER cannot tell apart either, and the test would then
	// compare a string with itself.
	precomposed := "policy caf" + string(rune(0x00E9))
	decomposed := "policy caf" + string(rune(0x0065)) + string(rune(0x0301))
	if precomposed == decomposed {
		t.Fatal("the two literals are byte-identical, so this test asserts nothing")
	}

	a, err := Digest(precomposed)
	if err != nil {
		t.Fatalf("digesting: %v", err)
	}
	b, err := Digest(decomposed)
	if err != nil {
		t.Fatalf("digesting: %v", err)
	}
	if a != b {
		t.Errorf("the cross-gateway digest distinguished two compositions of one string: %s vs %s", a, b)
	}

	ea, err := ExactDigest(precomposed)
	if err != nil {
		t.Fatalf("digesting exactly: %v", err)
	}
	eb, err := ExactDigest(decomposed)
	if err != nil {
		t.Fatalf("digesting exactly: %v", err)
	}
	if ea == eb {
		t.Error("the exact digest collapsed two byte sequences; a signature over it would be satisfied by either, " +
			"which is a signature bypass for any artifact that is read as bytes")
	}
}

// TestCanonicalEncodingRefusesInvalidUTF8 pins the refusal.
//
// Encoding an invalid byte as the replacement character maps every distinct
// invalid sequence of one length onto one output, so two different values would
// digest identically. A digest whose inputs collide is not a digest, and the
// right answer to an input that cannot be canonically represented is to say so
// rather than to represent it approximately.
func TestCanonicalEncodingRefusesInvalidUTF8(t *testing.T) {
	for _, encode := range []struct {
		name string
		fn   func(any) ([]byte, error)
	}{{"the cross-gateway encoder", CanonicalJSON}, {"the exact encoder", ExactJSON}} {
		for _, bad := range []string{"a\xffb", "a\xfeb", "\xff", "a\xff\xffb"} {
			if _, err := encode.fn(bad); err == nil {
				t.Errorf("%s accepted the invalid sequence %q", encode.name, bad)
			}
		}
		if _, err := encode.fn(map[string]any{"a\xffb": 1}); err == nil {
			t.Errorf("%s accepted an invalid sequence in an object KEY", encode.name)
		}
		if _, err := encode.fn("valid"); err != nil {
			t.Errorf("%s rejected a valid string: %v", encode.name, err)
		}
	}
}

// TestLargeIntegersDoNotCollide pins the number path.
//
// Two adjacent unsigned 64-bit integers round to the same float64, so routing an
// integer literal through a float collapses them. A quantity that collides with
// its neighbour is not safe to bind a decision to.
func TestLargeIntegersDoNotCollide(t *testing.T) {
	a, err := Digest(uint64(18446744073709551614))
	if err != nil {
		t.Fatalf("digesting: %v", err)
	}
	b, err := Digest(uint64(18446744073709551615))
	if err != nil {
		t.Fatalf("digesting: %v", err)
	}
	if a == b {
		t.Error("two adjacent unsigned 64-bit integers digested identically")
	}
	// And the documented equivalences still hold: how a caller spelled a number
	// must not change the digest.
	one, _ := CanonicalJSON(map[string]any{"n": 1})
	oneFloat, _ := CanonicalJSON(map[string]any{"n": 1.0})
	if string(one) != string(oneFloat) {
		t.Errorf("1 and 1.0 canonicalized differently: %s vs %s", one, oneFloat)
	}
}

// TestBindingDigestHasNoActorKeyCollision pins the structured attribute view.
//
// Joining an actor identifier and an attribute path with a separator both of
// them may contain lets two different actors own one map entry, so one
// attribute is overwritten before hashing and two requests that differ in a
// principal attribute bind identically. That is the exact failure the binding
// exists to prevent.
func TestBindingDigestHasNoActorKeyCollision(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	build := func(clearance string) *Request {
		principal := MustParseID(KindPrincipal, "Agent::realm_ws:bot")
		nested := MustParseID(KindPrincipal, "Agent::realm_ws:bot/principal.role")
		return &Request{
			RequestID:    "req_collide",
			Organization: MustParseID(KindOrganization, "Organization::org_acme"),
			Principal:    principal,
			Action:       MustParseID(KindAction, "Action::a.b"),
			Resource:     MustParseID(KindResource, "Ticket::conn:T-1"),
			Context: Context{ActorChain: []Actor{
				{ID: principal, Attributes: AttributeSet{
					"principal.role/principal.clearance": Known("UNCLASSIFIED", ProvDirectory, 1, now),
				}},
				{ID: nested, Attributes: AttributeSet{
					"principal.clearance": Known(clearance, ProvDirectory, 1, now),
				}},
			}},
			Snapshot:    Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: "sha256:aa"},
			Attributes:  AttributeSet{},
			EvaluatedAt: now,
		}
	}
	low, high := build("UNCLASSIFIED"), build("TOP-SECRET")
	if err := low.Validate(); err != nil {
		t.Fatalf("the low request does not validate, so the collision cannot be reached: %v", err)
	}
	if err := high.Validate(); err != nil {
		t.Fatalf("the high request does not validate: %v", err)
	}
	a, err := low.BindingDigest()
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	b, err := high.BindingDigest()
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	if a == b {
		t.Error("two requests differing in a principal attribute produced one binding digest; " +
			"an approval granted for one would be bindable to the other")
	}
}

// TestObligationIdentityKeepsMandatoryAndVersion pins the deduplication key.
//
// Two byte-identical obligations attached by two policies, one advisory and one
// mandatory, describe one instruction that IS mandatory. Collapsing them to
// whichever sorted first drops the mandatory twin, the enforcement point
// capability check never runs on it, and ADDING AN ADVISORY POLICY turns a deny
// into an allow.
func TestObligationIdentityKeepsMandatoryAndVersion(t *testing.T) {
	audit := func(mandatory bool, version int, source string) Obligation {
		return Obligation{
			Type: ObImmutableAudit, Mandatory: mandatory, SourcePolicy: source, SchemaVersion: version,
			Params: map[string]string{"channel": "audit", "level": "high", "delivery": string(DeliveryDurable)},
		}
	}
	noCapability := &PEPProfile{ID: "bare"}

	only := ComposeObligations(ComposeInput{
		Obligations: []Obligation{audit(true, 1, "R-mandatory")}, PEP: noCapability})
	if !only.Denied {
		t.Fatal("a mandatory obligation the enforcement point cannot discharge did not deny, " +
			"so the comparison below would prove nothing")
	}

	for _, order := range [][]Obligation{
		{audit(false, 1, "R-advisory"), audit(true, 1, "R-mandatory")},
		{audit(true, 1, "R-mandatory"), audit(false, 1, "R-advisory")},
	} {
		got := ComposeObligations(ComposeInput{Obligations: order, PEP: noCapability})
		if !got.Denied {
			t.Errorf("adding an advisory twin turned the denial into a permit (order starting with %q)",
				order[0].SourcePolicy)
		}
	}

	// The schema version half of the same defect. An enforcement point
	// advertising version 1 must not be assumed to implement version 2.
	v1Only := &PEPProfile{ID: "v1", Capabilities: []Capability{{Type: ObImmutableAudit, Version: 1}}}
	mixed := ComposeObligations(ComposeInput{
		Obligations: []Obligation{audit(true, 1, "R-v1"), audit(true, 2, "R-v2")}, PEP: v1Only})
	if !mixed.Denied {
		t.Error("an obligation required at schema version 2 was discharged by a profile advertising only version 1")
	}
}

// TestMergedFamiliesCarryTheStrictestFlags pins the routing and step-up merge.
//
// The merged obligation is a CONJUNCTION of its inputs, so it must be mandatory
// if any input was. Copying the first contributor's struct, which an unordered
// set makes arbitrary, hands the enforcement point a requirement marked
// advisory that a policy declared mandatory, and the capability check skips it.
func TestMergedFamiliesCarryTheStrictestFlags(t *testing.T) {
	stepUp := func(mandatory bool, source, methods string) Obligation {
		return Obligation{Type: ObStepUpAuth, Mandatory: mandatory, SourcePolicy: source, SchemaVersion: 1,
			Params: map[string]string{"assurance": "aal2", "methods": methods}}
	}
	route := func(mandatory bool, source, dests string) Obligation {
		return Obligation{Type: ObRouteRestriction, Mandatory: mandatory, SourcePolicy: source, SchemaVersion: 1,
			Params: map[string]string{"allowed_destinations": dests}}
	}
	noCapability := &PEPProfile{ID: "bare"}

	for name, set := range map[string][]Obligation{
		"a step-up requirement whose advisory contributor sorts first": {
			stepUp(false, "R-a-lax", "webauthn,sms"), stepUp(true, "R-b-strict", "webauthn"),
		},
		"a route restriction whose advisory contributor sorts first": {
			route(false, "R-a-lax", "eu,us"), route(true, "R-b-strict", "eu"),
		},
	} {
		got := ComposeObligations(ComposeInput{Obligations: set, PEP: noCapability})
		if !got.Denied {
			t.Errorf("%s composed to a permit against an enforcement point that advertises nothing: %+v", name, got.Obligations)
		}
	}

	// Mixed schema versions cannot be merged into one instruction, because the
	// merged one can only speak a single version and picking one would discard
	// a requirement rather than compose it.
	mixed := ComposeObligations(ComposeInput{Obligations: []Obligation{
		stepUp(true, "R-v1", "webauthn"),
		{Type: ObStepUpAuth, Mandatory: true, SourcePolicy: "R-v2", SchemaVersion: 2,
			Params: map[string]string{"assurance": "aal3", "methods": "webauthn"}},
	}, PEP: &PEPProfile{ID: "both", Capabilities: []Capability{
		{Type: ObStepUpAuth, Version: 1}, {Type: ObStepUpAuth, Version: 2},
	}}})
	if !mixed.Denied {
		t.Error("two step-up requirements at different schema versions merged into one instruction")
	}
}

// TestMeetRecomposesRatherThanConcatenating pins the cross-entry obligation
// algebra.
//
// Each entry's set was already resolved per leaf against its own policies.
// Concatenating two resolved sets puts two transforms back on one leaf, and the
// weaker of them then reaches the enforcement point alongside the stronger,
// which is strictly more permissive than the least permissive entry.
func TestMeetRecomposesRatherThanConcatenating(t *testing.T) {
	snap := Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: "sha256:aa"}
	entry := func(id string, o Obligation) *Decision {
		return &Decision{DecisionID: "dec", RequestID: "req", Authorization: AuthzPermit,
			State: StateAllow, Reason: ReasonPermitted, Snapshot: snap, Obligations: []Obligation{o}}
	}
	remove := Obligation{Type: ObFieldRemove, Target: "response.ssn", Mandatory: true, SourcePolicy: "A", SchemaVersion: 1}
	annotate := Obligation{Type: ObFieldAnnotate, Target: "response.ssn", Mandatory: true, SourcePolicy: "B", SchemaVersion: 1}

	pep := &PEPProfile{ID: "p", Capabilities: []Capability{
		{Type: ObFieldRemove, Version: 1}, {Type: ObFieldAnnotate, Version: 1},
	}}
	met, err := MeetDecisions([]*Decision{entry("a", remove), entry("b", annotate)},
		MeetOptions{PayloadLeaves: []string{"response.ssn"}, PEP: pep})
	if err != nil {
		t.Fatalf("meeting: %v", err)
	}
	if len(met.Obligations) != 1 {
		t.Fatalf("the meet emitted %d transforms for one leaf: %+v", len(met.Obligations), met.Obligations)
	}
	if met.Obligations[0].Type != ObFieldRemove {
		t.Errorf("the meet emitted %q for a leaf one entry required be removed", met.Obligations[0].Type)
	}
}

// TestMeetValidatesASingleEntryAndRefusesMixedSnapshots pins the two remaining
// holes in the meet's front door.
func TestMeetValidatesASingleEntryAndRefusesMixedSnapshots(t *testing.T) {
	snap := Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: "sha256:aa"}
	// Authorization deny carried with an ALLOW state: a decision that reports
	// itself executable while denying.
	broken := &Decision{DecisionID: "d", RequestID: "r", Authorization: AuthzDeny,
		State: StateAllow, Reason: ReasonExplicitConstraint, Snapshot: snap}
	if _, err := MeetDecisions([]*Decision{broken}, MeetOptions{}); err == nil {
		t.Error("a single malformed decision passed through the meet unvalidated")
	}

	ok := func(bundle string) *Decision {
		return &Decision{DecisionID: "d", RequestID: "r", Authorization: AuthzPermit,
			State: StateAllow, Reason: ReasonPermitted,
			Snapshot: Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: bundle}}
	}
	if _, err := MeetDecisions([]*Decision{ok("sha256:aa"), ok("sha256:bb")}, MeetOptions{}); err == nil {
		t.Error("two decisions evaluated against different bundles were combined into one that names only the first")
	}
	other := ok("sha256:aa")
	other.RequestID = "another"
	if _, err := MeetDecisions([]*Decision{ok("sha256:aa"), other}, MeetOptions{}); err == nil {
		t.Error("decisions belonging to two different requests were combined")
	}
}

// TestAuthZENDecoderRefusesDuplicateMembers pins the duplicate-key rule.
//
// Any layer that read the FIRST occurrence, a gateway, an audit log, a rate
// limiter, sees a different request than the decoder evaluates. It is the same
// class the unknown-key rule exists for, arriving through a member name the
// schema does declare.
func TestAuthZENDecoderRefusesDuplicateMembers(t *testing.T) {
	valid := `{"evaluation":{"subject":{"type":"identity","id":"alice"},` +
		`"action":{"name":"a.b"},"resource":{"type":"t","id":"1"}}}`
	if _, err := DecodeAuthZENEnvelope([]byte(valid)); err != nil {
		t.Fatalf("a valid envelope was refused, so the rejections below prove nothing: %v", err)
	}
	for name, raw := range map[string]string{
		"a repeated top-level member": `{"evaluation":{"subject":{"type":"identity","id":"attacker"},` +
			`"action":{"name":"delete"},"resource":{"type":"t","id":"1"}},` +
			`"evaluation":{"subject":{"type":"identity","id":"victim"},` +
			`"action":{"name":"read"},"resource":{"type":"t","id":"1"}}}`,
		"a repeated nested member": `{"evaluation":{"subject":{"type":"identity","id":"low","id":"root"},` +
			`"action":{"name":"a.b"},"resource":{"type":"t","id":"1"}}}`,
		"a declared member explicitly null beside another": `{"evaluation":{"subject":{"type":"identity","id":"a"},` +
			`"action":{"name":"x"},"resource":{"type":"t","id":"1"}},"evaluations":null}`,
		"the declared member null on its own": `{"evaluation":null}`,
	} {
		if _, err := DecodeAuthZENEnvelope([]byte(raw)); err == nil {
			t.Errorf("the decoder accepted %s", name)
		}
	}
}

// TestCallerPropertiesCannotSilentlyCollide pins the projection.
//
// Two caller inputs that land on one path are refused rather than resolved
// last-wins. Discarding one means the evaluated request is not the request that
// arrived, and the caller has no way to know which half was read.
func TestCallerPropertiesCannotSilentlyCollide(t *testing.T) {
	raw := `{"evaluation":{"subject":{"type":"identity","id":"a","properties":{"role":"user"}},` +
		`"action":{"name":"x"},"resource":{"type":"t","id":"1"},` +
		`"context":{"args":{"subject_properties.role":"admin"}}}}`
	env, err := DecodeAuthZENEnvelope([]byte(raw))
	if err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, err := env.Project(time.Now()); err == nil {
		t.Error("two caller-supplied properties projected onto one attribute path and one was silently discarded")
	} else if !strings.Contains(err.Error(), "project onto the attribute path") {
		t.Errorf("the projection failed for the wrong reason: %v", err)
	}
}

// TestDisclosureWinnerInheritsMandatoryAcrossRanks pins the second half of the
// mandatory-flag defect.
//
// Deduplication ORs the flag across obligations sharing one instruction. The
// RANK COMPARISON is a different step: a transform that discloses less wins the
// leaf outright, and carrying only the winner's own flag lets an advisory
// transform displace a mandatory requirement and skip the enforcement point
// capability check with it. A policy that required SOME transform on a leaf
// still requires one after a different transform outranked it.
func TestDisclosureWinnerInheritsMandatoryAcrossRanks(t *testing.T) {
	leaves := []string{"response.ssn"}
	// field_remove discloses less than field_annotate, so it wins the leaf.
	advisoryRemove := Obligation{Type: ObFieldRemove, Target: "response.ssn",
		Mandatory: false, SourcePolicy: "I-detector", SchemaVersion: 1}
	mandatoryAnnotate := Obligation{Type: ObFieldAnnotate, Target: "response.ssn",
		Mandatory: true, SourcePolicy: "R-requirement", SchemaVersion: 1}

	// A profile that can annotate but cannot remove. Without the requirement
	// alongside it, the advisory removal is dropped by the enforcement point
	// and the field goes out untransformed.
	annotateOnly := &PEPProfile{ID: "annotate-only",
		Capabilities: []Capability{{Type: ObFieldAnnotate, Version: 1}}}

	alone := ComposeObligations(ComposeInput{
		Obligations: []Obligation{mandatoryAnnotate}, Leaves: leaves, PEP: annotateOnly})
	if alone.Denied {
		t.Fatalf("the requirement alone did not compose, so the comparison proves nothing: %s", alone.Detail)
	}
	if len(alone.Obligations) != 1 || !alone.Obligations[0].Mandatory {
		t.Fatalf("the requirement alone produced %+v, expected one mandatory obligation", alone.Obligations)
	}

	// Adding an advisory transform must lose neither of two things: it must
	// not deny (an advisory control cannot), and it must not silently take the
	// leaf away from the requirement that demanded a transform there. Both are
	// asserted, because a fix for either one alone reintroduces the other.
	for name, order := range map[string][]Obligation{
		"the advisory transform listed first":  {advisoryRemove, mandatoryAnnotate},
		"the advisory transform listed second": {mandatoryAnnotate, advisoryRemove},
	} {
		got := ComposeObligations(ComposeInput{Obligations: order, Leaves: leaves, PEP: annotateOnly})
		if got.Denied {
			t.Errorf("%s: an advisory transform produced a denial: %s", name, got.Detail)
			continue
		}
		if len(got.Obligations) != 1 {
			t.Errorf("%s: composed to %+v, expected one transform on the leaf", name, got.Obligations)
			continue
		}
		if got.Obligations[0].Type != ObFieldAnnotate {
			t.Errorf("%s: the leaf took %q, which the enforcement point cannot discharge; "+
				"the mandatory requirement was displaced by an advisory transform",
				name, got.Obligations[0].Type)
		}
		if !got.Obligations[0].Mandatory {
			t.Errorf("%s: the surviving transform is advisory although a requirement demanded one on this leaf", name)
		}
		if len(got.DroppedAdvisory) != 1 {
			t.Errorf("%s: the dropped advisory contribution was not recorded: %+v", name, got.DroppedAdvisory)
		}
	}

	// And where the enforcement point CAN discharge the winner, the composed
	// obligation is still mandatory, so it is checked rather than dropped.
	both := &PEPProfile{ID: "both", Capabilities: []Capability{
		{Type: ObFieldAnnotate, Version: 1}, {Type: ObFieldRemove, Version: 1}}}
	ok := ComposeObligations(ComposeInput{
		Obligations: []Obligation{advisoryRemove, mandatoryAnnotate}, Leaves: leaves, PEP: both})
	if ok.Denied {
		t.Fatalf("composition denied against a capable profile: %s", ok.Detail)
	}
	if len(ok.DroppedAdvisory) != 0 {
		t.Errorf("an advisory contribution that composes was dropped anyway: %+v", ok.DroppedAdvisory)
	}
	if len(ok.Obligations) != 1 {
		t.Fatalf("expected one transform on the leaf, got %+v", ok.Obligations)
	}
	if ok.Obligations[0].Type != ObFieldRemove {
		t.Errorf("the leaf took %q, expected the least disclosing transform", ok.Obligations[0].Type)
	}
	if !ok.Obligations[0].Mandatory {
		t.Error("the winning transform is advisory although a requirement policy demanded a transform on this leaf")
	}
}

// TestAnUnplaceableMandatoryTransformIsReported pins the visibility of drift
// between a declared payload schema and the transforms scoped to it.
//
// It is reported rather than denied, and the reason is that the vacuous case
// and the drift case are indistinguishable here: an organization-wide rule to
// redact a date of birth is vacuously satisfied by an action whose response has
// no such field, and denying would make any cross-action data policy refuse
// every action missing one of its fields. What must not happen is the silence.
func TestAnUnplaceableMandatoryTransformIsReported(t *testing.T) {
	redactSSN := Obligation{Type: ObFieldRedact, Target: "response.ssn",
		Mandatory: true, SourcePolicy: "R-pii", SchemaVersion: 1}
	pep := &PEPProfile{ID: "p", Capabilities: []Capability{{Type: ObFieldRedact, Version: 1}}}

	placed := ComposeObligations(ComposeInput{
		Obligations: []Obligation{redactSSN}, Leaves: []string{"response.ssn", "response.name"}, PEP: pep})
	if placed.Denied || len(placed.Obligations) != 1 {
		t.Fatalf("the transform did not compose against a schema that carries its target: %+v", placed)
	}
	if placed.UnplacedDetail != "" {
		t.Errorf("a placed transform was reported as unplaceable: %s", placed.UnplacedDetail)
	}

	unplaced := ComposeObligations(ComposeInput{
		Obligations: []Obligation{redactSSN}, Leaves: []string{"response.name"}, PEP: pep})
	if unplaced.Denied {
		t.Errorf("a transform targeting a field this action does not return produced a denial: %s", unplaced.Detail)
	}
	if len(unplaced.Unplaced) != 1 {
		t.Fatalf("the unplaceable transform was not recorded: %+v", unplaced.Unplaced)
	}
	if !strings.Contains(unplaced.UnplacedDetail, "response.ssn") {
		t.Errorf("the report does not name the target: %s", unplaced.UnplacedDetail)
	}
	if !strings.Contains(unplaced.UnplacedDetail, "R-pii") {
		t.Errorf("the report does not name the policy that required it: %s", unplaced.UnplacedDetail)
	}
}

// TestStepUpAssuranceUsesADeclaredOrder pins the merge.
//
// Taking the maximum of two assurance labels with a string comparison is not
// taking the maximum of two assurance LEVELS. Lexicographically "high" sorts
// below "low", so composing a requirement for high assurance with one for low
// yields low, and the conjunction is weaker than one of its own inputs.
func TestStepUpAssuranceUsesADeclaredOrder(t *testing.T) {
	stepUp := func(source string, assurance Assurance) Obligation {
		return Obligation{Type: ObStepUpAuth, Mandatory: true, SourcePolicy: source, SchemaVersion: 1,
			Params: map[string]string{"assurance": string(assurance), "methods": "webauthn"}}
	}
	pep := &PEPProfile{ID: "p", Capabilities: []Capability{{Type: ObStepUpAuth, Version: 1}}}

	got := ComposeObligations(ComposeInput{
		Obligations: []Obligation{stepUp("R-strong", AssuranceLevel3), stepUp("R-weak", AssuranceLevel1)},
		PEP:         pep})
	if got.Denied {
		t.Fatalf("composition denied: %s", got.Detail)
	}
	if len(got.Obligations) != 1 {
		t.Fatalf("expected one merged step-up, got %+v", got.Obligations)
	}
	if a := got.Obligations[0].Params["assurance"]; a != string(AssuranceLevel3) {
		t.Errorf("the merged requirement asks for %q, which is weaker than the %q one of its inputs required",
			a, AssuranceLevel3)
	}

	// An undeclared label refuses rather than being ordered against the others
	// by whatever comparison happens to be available.
	undeclared := ComposeObligations(ComposeInput{
		Obligations: []Obligation{stepUp("R-a", AssuranceLevel2), stepUp("R-b", Assurance("very-high"))},
		PEP:         pep})
	if !undeclared.Denied {
		t.Error("an undeclared assurance label was merged into a requirement")
	}
}

// TestMeetRebuildsItsTrace pins the explain payload of a combined decision.
//
// Every audience reads the trace and nothing else. A combined decision that
// carries the first entry's trace explains itself with the first entry's state,
// reason and obligations while holding its own, so an operator is shown a permit
// for a challenge and one hop's obligations for the obligations of all of them.
func TestMeetRebuildsItsTrace(t *testing.T) {
	snap := Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: "sha256:aa"}
	plain := &Decision{DecisionID: "d", RequestID: "r", Authorization: AuthzPermit,
		State: StateAllow, Reason: ReasonPermitted, Snapshot: snap,
		Trace: &Trace{State: StateAllow, Category: CategoryAllowed, Reason: ReasonPermitted}}
	clause := Obligation{Type: ObApprovalChallenge, Mandatory: true, SourcePolicy: "C", SchemaVersion: 1,
		Params: map[string]string{"quorum": "2", "eligible": "Group::realm_ws:sec", "separation_of_duties": "true"}}
	challenged := &Decision{DecisionID: "d", RequestID: "r", Authorization: AuthzPermit,
		State: StateChallenge, Reason: ReasonApprovalRequired, Snapshot: snap,
		Obligations: []Obligation{clause},
		Approval: &ApprovalRequirement{
			AllOf:     []ApprovalClause{{Quorum: 2, Eligible: []ID{MustParseID(KindGroup, "Group::realm_ws:sec")}}},
			ExpiresAt: snapTime()},
		Trace: &Trace{State: StateChallenge, Category: CategoryApprovalPending, Reason: ReasonApprovalRequired}}

	pep := &PEPProfile{ID: "p", Capabilities: []Capability{{Type: ObApprovalChallenge, Version: 1}}}
	met, err := MeetDecisions([]*Decision{plain, challenged}, MeetOptions{PEP: pep})
	if err != nil {
		t.Fatalf("meeting: %v", err)
	}
	if met.State != StateChallenge {
		t.Fatalf("the meet produced state %q, expected CHALLENGE", met.State)
	}
	if met.Trace == plain.Trace {
		t.Error("the combined decision shares the first entry's trace pointer, so mutating one mutates the other")
	}
	if met.Trace.State != met.State {
		t.Errorf("the trace reports state %q while the decision is %q", met.Trace.State, met.State)
	}
	if met.Trace.Reason != met.Reason {
		t.Errorf("the trace reports reason %q while the decision is %q", met.Trace.Reason, met.Reason)
	}
	if len(met.Trace.Obligations) != len(met.Obligations) {
		t.Errorf("the trace carries %d obligations while the decision carries %d",
			len(met.Trace.Obligations), len(met.Obligations))
	}
	if met.Trace.ApprovalExpiresAt == nil {
		t.Error("the trace of a challenge carries no expiry")
	}
}

// snapTime is a fixed, non-zero expiry. An approval requirement with a zero
// expiry does not validate, and timeout is the only safe default, so a test
// fixture must supply one rather than leaving it unset.
func snapTime() time.Time { return time.Date(2026, 8, 29, 13, 0, 0, 0, time.UTC) }

// TestFutureObservationCannotBeFresh pins the freshness bound against a clock
// ahead of the evaluator.
//
// The subtraction is negative for a value observed after the evaluation
// instant, so it passes every comparison and the value is permanently fresh. It
// is the same un-establishable condition as a missing observation time, and it
// gets the same answer.
func TestFutureObservationCannotBeFresh(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	future := Known("v", ProvDirectory, 1, now.Add(72*time.Hour))
	future.MaxAgeSeconds = 30
	got := future.AtFreshness(now)
	if got.State != StateUnknown || got.Reason != ReasonStale {
		t.Errorf("a value observed 72 hours ahead of the evaluation instant is %s/%s, expected unknown/stale",
			got.State, got.Reason)
	}
	// The control: a value observed the same distance in the past.
	past := Known("v", ProvDirectory, 1, now.Add(-72*time.Hour))
	past.MaxAgeSeconds = 30
	if c := past.AtFreshness(now); c.State != StateUnknown {
		t.Errorf("the control did not go stale: %s", c.State)
	}
	// And a value inside its bound is untouched, so the rule above is not just
	// staleness applied to everything.
	fresh := Known("v", ProvDirectory, 1, now.Add(-10*time.Second))
	fresh.MaxAgeSeconds = 30
	if f := fresh.AtFreshness(now); f.State != StateKnown {
		t.Errorf("a value inside its bound was downgraded: %s", f.State)
	}
}

// TestEveryDeclaredUnknownReasonIsEmitted is the declared-but-never-emitted
// guard for this enumeration.
//
// A reason code nothing can produce is a value a caller may see in a schema and
// never in a decision, and it invites a handler for a case that cannot occur.
// Every code here is emitted either by the contract itself or by the
// platform-owned Rego helpers, and this test names where.
func TestEveryDeclaredUnknownReasonIsEmitted(t *testing.T) {
	emittedBy := map[UnknownReason]string{
		ReasonNotSupplied:        "AttributeSet.Lookup and the helper's attr rule, for an attribute nothing produced",
		ReasonResolutionFailed:   "the Policy Information Point, for a resolver or connector failure",
		ReasonStale:              "Attribute.AtFreshness, for a value outside its declared bound",
		ReasonSchemaMismatch:     "the helper's type guard, for a value of the wrong declared type",
		ReasonClosureUnavailable: "the directory resolver, for a closure it could not compute",
		ReasonClosureTruncated:   "the directory resolver, for a closure that hit a depth or size bound",
		ReasonMalformedValue:     "the helper's final fallback, for an attribute state this build does not recognise",
		ReasonRequiredAbsent:     "the helper, for the absence of an attribute the schema declares required",
	}
	for _, r := range AllUnknownReasons() {
		if _, ok := emittedBy[r]; !ok {
			t.Errorf("unknown reason %q is declared but this test names no producer for it; "+
				"a code nothing emits is a value a caller can only meet in a schema", r)
		}
	}
	for r := range emittedBy {
		found := false
		for _, declared := range AllUnknownReasons() {
			if declared == r {
				found = true
			}
		}
		if !found {
			t.Errorf("this test names a producer for %q, which is not a declared reason", r)
		}
	}
}
