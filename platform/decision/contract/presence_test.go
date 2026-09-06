package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The refusal tests for the presence boundary, and the schema-derived sweep of
// the class it belongs to.
//
// EVERY assertion below is driven from a hostile WIRE DOCUMENT rather than from
// a Go struct. That is the whole point: the defect is invisible to a Go
// constructor, because a Go constructor supplies every member by definition.
// A test asserting "absent decodes to false" would also pass on the tree before
// this change; the assertion has to be on the REFUSAL.

// decodeObligation is the wire path under test: bytes in, contract value out.
func decodeObligation(t *testing.T, raw string) Obligation {
	t.Helper()
	var o Obligation
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatalf("the document did not decode at all, so the refusal under test is not the one being measured: %v", err)
	}
	return o
}

// aValidObligationDocument is a complete, authored obligation. Members are
// removed from it per case, so every refusal is attributable to the removal
// rather than to a fixture that was never valid.
const aValidObligationDocument = `{
	"type": "field_redact",
	"target": "args.query",
	"mandatory": true,
	"source_policy": "p-1",
	"schema_version": 1
}`

// aValidApprovalDocument is the same for an approval requirement.
const aValidApprovalDocument = `{
	"all_of": [{"quorum": 2, "eligible": [{"kind":"group","type":"Group","qualifier":"realm","local":"reviewers"}]}],
	"separation_of_duties": true,
	"expires_at": "2030-01-01T00:00:00Z"
}`

// TestAnObligationOmittingMandatoryIsRefused is the item's own gate.
//
// Deleting the presence check in Obligation.Validate must turn this red; that
// is asserted mechanically by the entry in sourceMutations().
func TestAnObligationOmittingMandatoryIsRefused(t *testing.T) {
	// The fixture is valid first, so a refusal below cannot be the fixture's.
	if err := decodeObligation(t, aValidObligationDocument).Validate(); err != nil {
		t.Fatalf("the complete document was refused, so nothing below discriminates: %v", err)
	}

	omitted := `{"type":"field_redact","target":"args.query","source_policy":"p-1","schema_version":1}`
	o := decodeObligation(t, omitted)

	// The pre-change reading, stated so the regression is legible: absence
	// decoded to false, which the composition algebra reads as ADVISORY.
	if o.Mandatory {
		t.Fatalf("an absent mandatory member decoded as true, which is not the shape of this defect")
	}

	err := o.Validate()
	if err == nil {
		t.Fatalf("an obligation whose document omitted `mandatory` was accepted; it would compose as advisory, " +
			"and a control that stops being a precondition of the permit without saying so is a fail-open")
	}
	var missing *MissingMemberError
	if !errors.As(err, &missing) {
		t.Fatalf("the refusal is not typed: %T %v", err, err)
	}
	if missing.Pointer != "/mandatory" {
		t.Errorf("the refusal names %q, want %q", missing.Pointer, "/mandatory")
	}
	if missing.Shape != SchemaObligation {
		t.Errorf("the refusal names shape %q, want %q", missing.Shape, SchemaObligation)
	}

	// EXPLICIT false is still a legal advisory obligation. Without this the fix
	// could have been "refuse every non-mandatory obligation", which would pass
	// the assertion above while breaking the advisory half of the algebra.
	advisory := decodeObligation(t, `{"type":"field_redact","target":"args.query","mandatory":false,"source_policy":"p-1","schema_version":1}`)
	if err := advisory.Validate(); err != nil {
		t.Fatalf("an explicitly advisory obligation was refused: %v", err)
	}
	if advisory.Mandatory {
		t.Errorf("an explicit false decoded as mandatory")
	}

	// ...and explicit true is still mandatory.
	mandatory := decodeObligation(t, aValidObligationDocument)
	if !mandatory.Mandatory {
		t.Errorf("an explicit true did not decode as mandatory")
	}
}

// TestAnApprovalRequirementOmittingSeparationOfDutiesIsRefused is the same
// property one level up.
func TestAnApprovalRequirementOmittingSeparationOfDutiesIsRefused(t *testing.T) {
	decode := func(raw string) *ApprovalRequirement {
		t.Helper()
		var a ApprovalRequirement
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			t.Fatalf("the document did not decode: %v", err)
		}
		return &a
	}

	if err := decode(aValidApprovalDocument).Validate(); err != nil {
		t.Fatalf("the complete document was refused, so nothing below discriminates: %v", err)
	}

	a := decode(`{"all_of":[{"quorum":2,"eligible":[{"kind":"group","type":"Group","qualifier":"realm","local":"reviewers"}]}],"expires_at":"2030-01-01T00:00:00Z"}`)
	if a.SeparationOfDuties {
		t.Fatalf("an absent separation_of_duties decoded as true, which is not the shape of this defect")
	}
	err := a.Validate()
	if err == nil {
		t.Fatalf("an approval requirement whose document omitted `separation_of_duties` was accepted; " +
			"absence reads as `no separation required`, which is the permissive reading of a restrictive control")
	}
	var missing *MissingMemberError
	if !errors.As(err, &missing) {
		t.Fatalf("the refusal is not typed: %T %v", err, err)
	}
	if missing.Pointer != "/separation_of_duties" {
		t.Errorf("the refusal names %q, want %q", missing.Pointer, "/separation_of_duties")
	}
	if missing.Shape != SchemaApproval {
		t.Errorf("the refusal names shape %q, want %q", missing.Shape, SchemaApproval)
	}

	if err := decode(`{"all_of":[{"quorum":2,"eligible":[{"kind":"group","type":"Group","qualifier":"realm","local":"reviewers"}]}],"separation_of_duties":false,"expires_at":"2030-01-01T00:00:00Z"}`).Validate(); err != nil {
		t.Fatalf("an explicit false was refused: %v", err)
	}
}

// TestADecisionDocumentCarryingAnIncompleteMemberIsRefusedWithAnAbsolutePointer
// drives the refusal through the shape a caller actually sends.
//
// It is the difference between a rule that holds on a shape in isolation and
// one that holds on the document a plane decodes: Decision.Validate is what
// every serving path calls, and the pointer it reports has to name the member's
// real location rather than its offset within a shape the caller never
// addressed by itself.
func TestADecisionDocumentCarryingAnIncompleteMemberIsRefusedWithAnAbsolutePointer(t *testing.T) {
	decision := func(obligations, approval, authorization, state, reason string) string {
		return fmt.Sprintf(`{
			"decision_id": "d-1", "request_id": "r-1",
			"authorization": %q, "state": %q, "reason": %q,
			"obligations": %s, "approval": %s,
			"determining": {"matched_permissions":["p-1"],"matched_constraints":[],"matched_requirements":[],"matched_inspections":[]},
			"snapshot": {"identity_epoch":1,"resource_epoch":1,"policy_bundle":"sha256:abc","registry_version":1,"schema_version":%q,"policy_epoch":1}
		}`, authorization, state, reason, obligations, approval, SchemaVersion)
	}

	for _, tc := range []struct {
		name        string
		document    string
		wantPointer string
	}{
		{
			name: "an obligation at index 1 omits mandatory",
			document: decision(
				`[{"type":"field_redact","target":"args.a","mandatory":true,"source_policy":"p","schema_version":1},`+
					`{"type":"field_remove","target":"args.b","source_policy":"p","schema_version":1}]`,
				`null`, "permit", "ALLOW", "permitted"),
			wantPointer: "/obligations/1/mandatory",
		},
		{
			name: "the approval requirement omits separation_of_duties",
			document: decision(`[]`,
				`{"all_of":[{"quorum":1,"eligible":[{"kind":"group","type":"Group","qualifier":"realm","local":"g"}]}],"expires_at":"2030-01-01T00:00:00Z"}`,
				"permit", "CHALLENGE", "approval_required"),
			wantPointer: "/approval/separation_of_duties",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d Decision
			if err := json.Unmarshal([]byte(tc.document), &d); err != nil {
				t.Fatalf("the decision document did not decode: %v", err)
			}
			err := d.Validate()
			if err == nil {
				t.Fatalf("the decision was accepted with an incomplete member")
			}
			var missing *MissingMemberError
			if !errors.As(err, &missing) {
				t.Fatalf("the refusal is not typed: %T %v", err, err)
			}
			if missing.Pointer != tc.wantPointer {
				t.Errorf("the refusal names %q, want %q", missing.Pointer, tc.wantPointer)
			}
		})
	}

	// The control: the same decision with every member supplied is accepted, so
	// the two refusals above are attributable to the omission and not to a
	// fixture the validator was always going to reject.
	complete := decision(
		`[{"type":"field_redact","target":"args.a","mandatory":true,"source_policy":"p","schema_version":1}]`,
		`null`, "permit", "ALLOW", "permitted")
	var d Decision
	if err := json.Unmarshal([]byte(complete), &d); err != nil {
		t.Fatalf("the control document did not decode: %v", err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("the control decision was refused, so the cases above prove nothing: %v", err)
	}
}

// TestComposingAnObligationDecodedWithoutMandatoryDenies drives the refusal
// through the ALGEBRA rather than through a validator called directly.
//
// composeSet validates every obligation before it composes anything, so this is
// the path on which the fail-open would actually have been exploited: an
// obligation whose flag was dropped would have joined the advisory set, been
// recorded, and let the request proceed.
func TestComposingAnObligationDecodedWithoutMandatoryDenies(t *testing.T) {
	// The control first: the same obligation with the member supplied composes,
	// so every denial below is attributable to the omission.
	complete := decodeObligation(t, aValidObligationDocument)
	if out := ComposeObligations(ComposeInput{
		Obligations: []Obligation{complete},
		Leaves:      []string{"args.query"},
		PEP:         &PEPProfile{ID: "pep", Capabilities: []Capability{{Type: ObFieldRedact, Version: 1}}},
	}); out.Denied {
		t.Fatalf("composition denied a complete obligation: %s", out.Detail)
	}

	incomplete := decodeObligation(t, `{"type":"field_redact","target":"args.query","source_policy":"p-1","schema_version":1}`)
	out := ComposeObligations(ComposeInput{
		Obligations: []Obligation{incomplete},
		Leaves:      []string{"args.query"},
		PEP:         &PEPProfile{ID: "pep", Capabilities: []Capability{{Type: ObFieldRedact, Version: 1}}},
	})
	if !out.Denied {
		t.Fatalf("composition accepted an obligation whose document omitted `mandatory`; it was recorded as advisory "+
			"and the request proceeded: %+v", out)
	}
	if out.Reason != ReasonSchemaViolation {
		t.Errorf("the denial reports reason %q, want %q; a document that does not satisfy the declared shape is a "+
			"different fact from an instruction this build cannot carry out", out.Reason, ReasonSchemaViolation)
	}
	// The TYPED cause survives the composition path. Without it the JSON
	// Pointer is recoverable only by parsing Detail, which is what typing the
	// error was supposed to stop.
	var missing *MissingMemberError
	if !errors.As(out.Err, &missing) {
		t.Fatalf("the outcome carries no typed cause: %T %v", out.Err, out.Err)
	}
	if missing.Pointer != "/mandatory" {
		t.Errorf("the typed cause names %q, want %q", missing.Pointer, "/mandatory")
	}

	// THE NARROWNESS OF THE GUARD IS ITSELF ASSERTED. An advisory obligation
	// that is invalid for some OTHER reason must still be dropped and recorded,
	// not denied: the advisory-drop rule is a deliberate decision - a detector's
	// contribution must not be able to refuse a request - and widening this
	// guard to a full Validate() would have reversed it for every deployment
	// carrying a bundle compiled before the rule that refuses such an
	// obligation. Without this case, "refuse everything invalid" would satisfy
	// the assertions above completely.
	otherwiseInvalid := Obligation{
		Type: ObImmutableAudit, Mandatory: false, SourcePolicy: "p-advisory", SchemaVersion: 1,
		Params: map[string]string{"delivery": "eventual"}, // not a declared guarantee
	}
	dropped := ComposeObligations(ComposeInput{
		Obligations: []Obligation{complete, otherwiseInvalid},
		Leaves:      []string{"args.query"},
		PEP:         &PEPProfile{ID: "pep", Capabilities: []Capability{{Type: ObFieldRedact, Version: 1}}},
	})
	if dropped.Denied {
		t.Fatalf("an advisory obligation that is invalid for a reason OTHER than the unsplittable one denied the "+
			"decision; that is an allow-to-deny change for any bundle carrying one: %s", dropped.Detail)
	}
	if len(dropped.DroppedAdvisory) != 1 {
		t.Errorf("the invalid advisory obligation was not recorded as dropped: %+v", dropped.DroppedAdvisory)
	}

}

// TestTheCustomDecodersDidNotWidenTheBoundary is the regression the presence
// change could most easily have caused.
//
// encoding/json hands a custom UnmarshalJSON the raw bytes and applies NONE of
// the enclosing decoder's settings, so a method that called json.Unmarshal
// directly would have silently disarmed DisallowUnknownFields for every shape
// it was added to - tightening one axis while opening another, on the same
// commit. Both shapes must still refuse an undeclared member.
func TestTheCustomDecodersDidNotWidenTheBoundary(t *testing.T) {
	var o Obligation
	if err := json.Unmarshal([]byte(`{"type":"field_redact","target":"args.q","mandatory":true,"source_policy":"p","schema_version":1,"invented":"x"}`), &o); err == nil {
		t.Errorf("the obligation decoder accepted an undeclared member")
	}
	var a ApprovalRequirement
	if err := json.Unmarshal([]byte(`{"all_of":[],"separation_of_duties":false,"expires_at":"2030-01-01T00:00:00Z","invented":"x"}`), &a); err == nil {
		t.Errorf("the approval decoder accepted an undeclared member")
	}
	// Nested shapes decoded by the strict decoder inherit its strictness, which
	// is why ApprovalClause needs no decoder of its own.
	if err := json.Unmarshal([]byte(`{"all_of":[{"quorum":1,"eligible":[{"kind":"group","type":"Group","qualifier":"realm","local":"g"}],"invented":"x"}],"separation_of_duties":false,"expires_at":"2030-01-01T00:00:00Z"}`), &a); err == nil {
		t.Errorf("the approval decoder accepted an undeclared member on a nested clause")
	}
}

// TestAValueThisPackageProducesAlwaysCarriesTheTrackedMembers closes the
// round-trip.
//
// The refusal is only safe if nothing this package EMITS can trip it. Both
// members are declared without omitempty, so encoding/json writes them
// unconditionally - but that is a property of two struct tags, and a struct tag
// is one character away from omitempty. Asserted rather than assumed.
func TestAValueThisPackageProducesAlwaysCarriesTheTrackedMembers(t *testing.T) {
	raw, err := CanonicalJSON(Obligation{
		Type: ObFieldRedact, Target: "args.q", SourcePolicy: "p", SchemaVersion: 1,
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if !strings.Contains(string(raw), `"mandatory"`) {
		t.Errorf("an advisory obligation encoded without a mandatory member: %s", raw)
	}
	var back Obligation
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("the round trip did not decode: %v", err)
	}
	if err := back.Validate(); err != nil {
		t.Errorf("a value this package produced was refused on the way back in: %v", err)
	}

	raw, err = CanonicalJSON(&ApprovalRequirement{
		AllOf:     []ApprovalClause{{Quorum: 1, Eligible: []ID{{Kind: KindGroup, Type: "Group", Qualifier: "realm", Local: "g"}}}},
		ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if !strings.Contains(string(raw), `"separation_of_duties"`) {
		t.Errorf("an approval requirement encoded without a separation_of_duties member: %s", raw)
	}
	var backA ApprovalRequirement
	if err := json.Unmarshal(raw, &backA); err != nil {
		t.Fatalf("the round trip did not decode: %v", err)
	}
	if err := backA.Validate(); err != nil {
		t.Errorf("a value this package produced was refused on the way back in: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The class sweep.
// ---------------------------------------------------------------------------

// requiredScalarDisposition is what this package does about one REQUIRED
// boolean or integer member when the document omits it.
//
// The class is exactly that: a required member whose Go zero value is a legal
// value, so the validator that would otherwise catch absence has nothing to
// reject. Strings are not in it (an empty required string is refused by the
// value check that was going to run anyway), and neither are objects and arrays
// (the same, with one stated exception recorded below).
type requiredScalarDisposition string

const (
	// refusedByPresence means absence is TRACKED at the decode boundary and the
	// validator refuses it. This is what presence.go adds.
	refusedByPresence requiredScalarDisposition = "refused because absence is tracked"
	// refusedByZeroValue means the validator already refuses the value absence
	// decodes to, so absence needs no separate machinery.
	refusedByZeroValue requiredScalarDisposition = "refused because the zero value is itself invalid"
	// admittedWithReason means absence IS admitted, deliberately, and the reason
	// is recorded beside it.
	admittedWithReason requiredScalarDisposition = "admitted; see the recorded reason"
)

// requiredScalarRuling is the disposition of one member plus why.
type requiredScalarRuling struct {
	disposition requiredScalarDisposition
	// why is mandatory for admittedWithReason and is asserted non-empty. An
	// exemption with no argument is how a fail-open gets grandfathered.
	why string
}

// requiredScalarRulings is the sweep's answer sheet, keyed "<shape>/<member>".
//
// It is a RATCHET, not a list: the test below enumerates every required boolean
// and integer member the committed JSON Schema declares, and fails if any of
// them is missing from this map or present in it without being declared. So a
// new required scalar on any contract shape cannot land without someone writing
// down what happens when a document omits it.
func requiredScalarRulings() map[string]requiredScalarRuling {
	return map[string]requiredScalarRuling{
		// The two this change closes. Absence reads as the PERMISSIVE value on
		// both: advisory, and "no separation required".
		"obligation/mandatory":                      {refusedByPresence, ""},
		"approval_requirement/separation_of_duties": {refusedByPresence, ""},

		// Already safe: the value absence decodes to is itself refused, so the
		// existing check catches the omission on the way past.
		"obligation/schema_version":  {refusedByZeroValue, ""}, // schema_version <= 0
		"approval_clause/quorum":     {refusedByZeroValue, ""}, // quorum < 1
		"tool_call/registry_version": {refusedByZeroValue, ""}, // registry_version <= 0

		// Admitted, with the argument recorded here rather than in a commit
		// message. These are NOT the fail-open class: their absence cannot turn
		// a deny into a permit. They are a replay-metadata gap, filed as its own
		// issue rather than folded into this change, because closing them means
		// refusing documents the system legitimately produces today and that is
		// a compatibility decision, not a bug fix.
		"snapshot/identity_epoch": {admittedWithReason,
			"epoch 0 is a legal value for a fresh registry, so presence cannot be inferred from the value. " +
				"Absence mis-states what a decision was computed against - a replayability defect, not a permissiveness one. Routed to #3661."},
		"snapshot/resource_epoch":   {admittedWithReason, "as snapshot/identity_epoch. Routed to #3661."},
		"snapshot/registry_version": {admittedWithReason, "as snapshot/identity_epoch. Routed to #3661."},
		"snapshot/policy_epoch":     {admittedWithReason, "as snapshot/identity_epoch. Routed to #3661."},
		"attribute/source_version": {admittedWithReason,
			"0 is a legal authored value and is what the AuthZEN projection stamps on every caller-supplied " +
				"attribute (authzen.go, projectCallerProperties), so refusing absence would refuse the request path's own output. Routed to #3661."},
		"authzen_response/decision": {admittedWithReason,
			"this package PRODUCES the AuthZEN boolean and never decodes one; the shape carries no validator at all. " +
				"Absence reads as false, which is DENY - the fail-closed direction - and the response schema's own " +
				"conditional pins the boolean against the operational state in both directions " +
				"(TestAuthZENResponseCollapseIsTotalInBothDirections)."},
	}
}

// sweptShape binds one contract shape to a valid value and the validator this
// package runs on it.
type sweptShape struct {
	// valid is a value this package accepts. The sweep removes ONE member from
	// its encoding per case, so every refusal is attributable to the removal.
	valid any
	// validate decodes a document into a fresh value of the shape's type and
	// runs the package's validator on it. A nil validate means this package
	// declares none, which is itself a fact the sweep asserts.
	validate func(raw []byte) error
}

func sweptShapes(t *testing.T) map[Schema]sweptShape {
	t.Helper()
	observed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return map[Schema]sweptShape{
		SchemaObligation: {
			valid: Obligation{Type: ObFieldRedact, Target: "args.q", Mandatory: true, SourcePolicy: "p", SchemaVersion: 1},
			validate: func(raw []byte) error {
				var v Obligation
				if err := json.Unmarshal(raw, &v); err != nil {
					return err
				}
				return v.Validate()
			},
		},
		SchemaApproval: {
			valid: &ApprovalRequirement{
				AllOf:     []ApprovalClause{{Quorum: 1, Eligible: []ID{{Kind: KindGroup, Type: "Group", Qualifier: "realm", Local: "g"}}}},
				ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			validate: func(raw []byte) error {
				var v ApprovalRequirement
				if err := json.Unmarshal(raw, &v); err != nil {
					return err
				}
				return v.Validate()
			},
		},
		SchemaApprovalClause: {
			valid: ApprovalClause{Quorum: 1, Eligible: []ID{{Kind: KindGroup, Type: "Group", Qualifier: "realm", Local: "g"}}},
			validate: func(raw []byte) error {
				var v ApprovalClause
				if err := json.Unmarshal(raw, &v); err != nil {
					return err
				}
				return v.Validate()
			},
		},
		"tool_call": {
			valid: ToolCall{
				RegistryID:      ID{Kind: KindTool, Type: "Tool", Local: "t"},
				RegistryVersion: 1,
				ArgumentsDigest: "sha256:abc",
			},
			validate: func(raw []byte) error {
				var v ToolCall
				if err := json.Unmarshal(raw, &v); err != nil {
					return err
				}
				return v.Validate()
			},
		},
		"snapshot": {
			valid: Snapshot{
				IdentityEpoch: 1, ResourceEpoch: 1, PolicyBundle: "sha256:abc",
				RegistryVersion: 1, SchemaVersion: SchemaVersion, PolicyEpoch: 1,
			},
			validate: func(raw []byte) error {
				var v Snapshot
				if err := json.Unmarshal(raw, &v); err != nil {
					return err
				}
				return v.Validate()
			},
		},
		SchemaAttribute: {
			valid: Known("v", ProvPlatform, 7, observed),
			validate: func(raw []byte) error {
				var v Attribute
				if err := json.Unmarshal(raw, &v); err != nil {
					return err
				}
				return v.Validate("env.zone")
			},
		},
		SchemaAuthZENResponse: {
			valid:    AuthZENResponse{Decision: false},
			validate: nil, // this package produces it and decodes none; see the ruling.
		},
	}
}

// TestEveryRequiredScalarWireMemberHasARuling is the class sweep.
//
// It enumerates the class from the SCHEMA - the closed set the contract itself
// declares - rather than from a hand-written list, so it cannot be satisfied by
// a list that stopped being complete. For each required boolean or integer
// member it removes that member from a valid document and asserts the recorded
// ruling actually holds:
//
//   - refusedByPresence: the refusal is the typed MissingMemberError naming it
//   - refusedByZeroValue: refused, but NOT by the presence machinery, so the
//     ruling cannot silently become "we added a null check" without saying so
//   - admittedWithReason: accepted, and the reason is recorded
//
// Asserting the ADMITTED cases is the half that makes this a ratchet rather
// than a checklist: if a future change starts refusing one of them, the ruling
// stops being true and the reason beside it stops being the current argument.
func TestEveryRequiredScalarWireMemberHasARuling(t *testing.T) {
	raw, err := SchemaDocument()
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing the schema: %v", err)
	}

	rulings := requiredScalarRulings()
	shapes := sweptShapes(t)

	// The classification loop is a PURE function, and that is not tidiness. Its
	// behaviour on a member it cannot classify is the whole subject of the
	// hardening below it: an earlier revision `continue`d there, silently
	// narrowing the sweep, and a test that only drove the resolver would have
	// reported green with the call site reverted. Extracting it lets
	// TestTheClassSweepCallSiteRefusesRatherThanNarrowing drive THIS loop over
	// a schema that carries such a member, which the committed schema does not.
	problems, seen := sweepRequiredScalars(doc.Defs, rulings)
	for _, p := range problems {
		t.Error(p)
	}
	for key, ruling := range rulings {
		if !seen[key] {
			continue
		}
		defName, member, _ := strings.Cut(key, "/")
		t.Run(key, func(t *testing.T) {
			assertRuling(t, shapes, Schema(defName), member, ruling)
		})
	}

	if len(seen) == 0 {
		t.Fatal("the sweep found no required scalar members at all, so every ruling below is vacuous")
	}
	var stale []string
	for key := range rulings {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("these rulings name members the schema does not declare as required scalars: %s; "+
			"a ruling that outlives its member makes the sweep look wider than it is", strings.Join(stale, ", "))
	}
}

// assertRuling removes one member from a shape's valid document and checks the
// recorded disposition against what the validator actually does.
func assertRuling(t *testing.T, shapes map[Schema]sweptShape, shape Schema, member string, ruling requiredScalarRuling) {
	t.Helper()
	s, bound := shapes[shape]
	if !bound {
		t.Fatalf("shape %q carries a required scalar but is bound to no fixture; "+
			"the sweep cannot rule on a shape it cannot build a document for", shape)
	}
	if s.validate == nil {
		if ruling.disposition != admittedWithReason {
			t.Fatalf("shape %q has no validator, so it cannot be recorded as %q", shape, ruling.disposition)
		}
		return
	}

	encoded, err := json.Marshal(s.valid)
	if err != nil {
		t.Fatalf("encoding the %q fixture: %v", shape, err)
	}
	// The fixture must be valid FIRST. Without this the removal below could be
	// "proved" to be refused by a document that was never accepted.
	if err := s.validate(encoded); err != nil {
		t.Fatalf("the %q fixture is not valid, so removing a member from it proves nothing: %v", shape, err)
	}

	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &asMap); err != nil {
		t.Fatalf("re-reading the %q fixture: %v", shape, err)
	}
	if _, present := asMap[member]; !present {
		t.Fatalf("the %q fixture never carried %q, so removing it changes nothing", shape, member)
	}
	delete(asMap, member)
	reduced, err := json.Marshal(asMap)
	if err != nil {
		t.Fatalf("re-encoding the reduced %q document: %v", shape, err)
	}

	err = s.validate(reduced)
	var missing *MissingMemberError
	typed := errors.As(err, &missing)

	switch ruling.disposition {
	case refusedByPresence:
		if err == nil {
			t.Fatalf("a %q document omitting %q was accepted, but the ruling says the absence is tracked", shape, member)
		}
		if !typed {
			t.Fatalf("a %q document omitting %q was refused by something other than the presence check (%T: %v)", shape, member, err, err)
		}
		if missing.Pointer != "/"+member {
			t.Errorf("the refusal names %q, want %q", missing.Pointer, "/"+member)
		}
	case refusedByZeroValue:
		if err == nil {
			t.Fatalf("a %q document omitting %q was accepted, but the ruling says its zero value is refused", shape, member)
		}
		if typed {
			t.Fatalf("a %q document omitting %q is now refused by the PRESENCE check, not by the value check the ruling records; "+
				"update the ruling so the sweep keeps describing what the code does", shape, member)
		}
	case admittedWithReason:
		if err != nil {
			t.Fatalf("a %q document omitting %q was refused (%v), but the ruling records it as admitted: %s", shape, member, err, ruling.why)
		}
	default:
		t.Fatalf("%q carries an unrecognised disposition %q", shape+"/"+Schema(member), ruling.disposition)
	}
}

// ---------------------------------------------------------------------------
// The LIVE half of the class: separation_of_duties as a string PARAMETER.
// ---------------------------------------------------------------------------

// TestACarriedSeparationOfDutiesParameterMustBeADeclaredSpelling covers the one
// path in this product that actually reaches ApprovalRequirement.SeparationOfDuties.
//
// The wire boolean has a presence boundary now, but nothing in either shipped
// binary decodes that shape (see the file header on presence.go). The value a
// composed approval requirement really carries comes out of a
// map[string]string, and in a string-typed parameter every spelling that is not
// exactly "true" - "TRUE", "1", "yes", a trailing space - used to read as
// FALSE: "no separation required", the permissive answer for a control whose
// whole purpose is to be restrictive, arriving through the one path a policy
// author can reach.
//
// The assertion is on the REFUSAL, and the two controls on either side of it
// are what stop the fix being "refuse everything": absent is still legal and
// still means false, and both declared spellings still mean what they say.
func TestACarriedSeparationOfDutiesParameterMustBeADeclaredSpelling(t *testing.T) {
	approval := func(sod string) Obligation {
		o := Obligation{
			Type: ObApprovalChallenge, SourcePolicy: "p-1", SchemaVersion: 1,
			Params: map[string]string{"quorum": "1", "eligible": "Group::realm:reviewers"},
		}
		if sod != "" {
			o.Params["separation_of_duties"] = sod
		}
		return o
	}

	for _, spelling := range []string{"TRUE", "True", "1", "yes", "true ", ""} {
		if spelling == "" {
			continue // the absent case is the control below, not a carried value
		}
		o := approval(spelling)
		o.Params["separation_of_duties"] = spelling
		if err := o.Validate(); err == nil {
			t.Errorf("separation_of_duties=%q was accepted; it reads as false, and an author who wrote it "+
				"meant the opposite", spelling)
		}
	}

	// CONTROL 1: absent is legal and means false. Refusing it would refuse every
	// approval policy written to date.
	absent := approval("")
	if err := absent.Validate(); err != nil {
		t.Fatalf("an approval obligation carrying no separation_of_duties was refused: %v", err)
	}

	// CONTROL 2: both declared spellings validate AND mean what they say, read
	// through the real composition path rather than the parameter map.
	for _, tc := range []struct {
		spelling string
		want     bool
	}{{"true", true}, {"false", false}} {
		o := approval(tc.spelling)
		if err := o.Validate(); err != nil {
			t.Fatalf("separation_of_duties=%q was refused: %v", tc.spelling, err)
		}
		out := ComposeObligations(ComposeInput{
			Obligations:    []Obligation{o},
			PEP:            &PEPProfile{ID: "pep", Capabilities: []Capability{{Type: ObApprovalChallenge, Version: 1}}},
			ApprovalExpiry: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		})
		if out.Denied {
			t.Fatalf("composing separation_of_duties=%q denied: %s", tc.spelling, out.Detail)
		}
		if out.Approval == nil {
			t.Fatalf("composing separation_of_duties=%q produced no approval requirement", tc.spelling)
		}
		if out.Approval.SeparationOfDuties != tc.want {
			t.Errorf("separation_of_duties=%q composed to %t, want %t", tc.spelling, out.Approval.SeparationOfDuties, tc.want)
		}
	}
}

// TestTheApprovalDecoderRefusesAnUndeclaredSpellingOfItsOwn is the second
// guard, aimed at the READ rather than at the boundary.
//
// decodeApprovalParams is reached only after Obligation.Validate has run, so
// this can never fire in production - which is exactly why it is asserted
// directly. Depending on the order of two checks in different functions for a
// fail-closed property is how the property stops holding the next time one of
// them moves, and the delivery guarantee beside it is read with the same
// two-value idiom for the same reason.
func TestTheApprovalDecoderRefusesAnUndeclaredSpellingOfItsOwn(t *testing.T) {
	o := Obligation{
		Type: ObApprovalChallenge, SourcePolicy: "p-1", SchemaVersion: 1,
		Params: map[string]string{"quorum": "1", "eligible": "Group::realm:reviewers", "separation_of_duties": "TRUE"},
	}
	if _, _, err := decodeApprovalParams(o); err == nil {
		t.Error("the approval decoder read an undeclared spelling as the permissive answer instead of refusing it")
	}
	// Absent still decodes, and to false.
	delete(o.Params, "separation_of_duties")
	_, sod, err := decodeApprovalParams(o)
	if err != nil {
		t.Fatalf("an approval obligation carrying no separation_of_duties was refused by the decoder: %v", err)
	}
	if sod {
		t.Error("an absent separation_of_duties decoded as true")
	}
}

// requiredMemberIsScalar reports whether one required member of one definition
// is a boolean or an integer - the class of member whose Go zero value is a
// legal value, so the validator that would otherwise catch absence has nothing
// to reject.
//
// It resolves the three shapes a plain `{"type":"boolean"}` read cannot see:
// a UNION type (`["boolean","null"]`), a `$ref` to a definition that carries
// the type, and a name in `required` that the definition does not declare as a
// property at all. Each of those used to return "not a scalar" by failing to
// parse, which made the sweep quietly narrower than the class it names.
func requiredMemberIsScalar(defs map[string]json.RawMessage, defName, member string) (bool, error) {
	rawProp, declared := defs[defName]
	if !declared {
		return false, fmt.Errorf("the schema declares no definition %q", defName)
	}
	var def struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(rawProp, &def); err != nil {
		return false, fmt.Errorf("parsing the definition: %w", err)
	}
	raw, present := def.Properties[member]
	if !present {
		return false, fmt.Errorf("it is listed in `required` but the definition declares no such property")
	}
	return scalarKindOf(defs, raw, 0)
}

// scalarKindOf resolves one property node's JSON type, following one $ref at a
// time, and refuses anything it cannot resolve rather than answering "no".
func scalarKindOf(defs map[string]json.RawMessage, raw json.RawMessage, depth int) (bool, error) {
	if depth > 4 {
		return false, fmt.Errorf("the $ref chain is deeper than this resolver follows")
	}
	var node struct {
		Type  json.RawMessage   `json:"type"`
		Ref   string            `json:"$ref"`
		Enum  []any             `json:"enum"`
		OneOf []json.RawMessage `json:"oneOf"`
		AllOf []json.RawMessage `json:"allOf"`
		AnyOf []json.RawMessage `json:"anyOf"`
		Const json.RawMessage   `json:"const"`
	}
	if err := json.Unmarshal(raw, &node); err != nil {
		return false, fmt.Errorf("parsing the property: %w", err)
	}
	if node.Ref != "" {
		name := strings.TrimPrefix(node.Ref, "#/$defs/")
		if name == node.Ref {
			return false, fmt.Errorf("unsupported reference %q", node.Ref)
		}
		target, ok := defs[name]
		if !ok {
			return false, fmt.Errorf("the reference %q names no definition", node.Ref)
		}
		return scalarKindOf(defs, target, depth+1)
	}
	if len(node.Type) == 0 {
		// A const pins one literal, and its JSON type is the literal's. The
		// profile member is declared this way, so a resolver that refused it
		// would fail the sweep on the schema as committed.
		if len(node.Const) > 0 {
			var literal any
			if err := json.Unmarshal(node.Const, &literal); err != nil {
				return false, fmt.Errorf("parsing the const literal: %w", err)
			}
			switch literal.(type) {
			case bool, float64:
				return true, nil
			default:
				return false, nil
			}
		}
		// An enumeration constrains the value set rather than the JSON type,
		// and every enumeration in this contract is over strings; a oneOf is a
		// composition this resolver does not model.
		if len(node.Enum) > 0 {
			return false, nil
		}
		for what, parts := range map[string][]json.RawMessage{"oneOf": node.OneOf, "allOf": node.AllOf, "anyOf": node.AnyOf} {
			if len(parts) > 0 {
				return false, fmt.Errorf("the property is an %s composition, which this resolver does not model; "+
					"decide whether it is a required scalar and give it a ruling by hand", what)
			}
		}
		return false, fmt.Errorf("the property declares no type, no $ref, no enum and no const")
	}
	var single string
	if err := json.Unmarshal(node.Type, &single); err == nil {
		return single == "boolean" || single == "integer", nil
	}
	var union []string
	if err := json.Unmarshal(node.Type, &union); err != nil {
		return false, fmt.Errorf("`type` is neither a string nor an array of strings")
	}
	// A UNION including a scalar is in the class: the member is still one whose
	// absence a Go validator cannot see, and `["boolean","null"]` is the
	// shape that escaped the earlier read entirely.
	for _, t := range union {
		if t == "boolean" || t == "integer" {
			return true, nil
		}
	}
	return false, nil
}

// TestTheClassSweepRefusesAMemberItCannotClassify drives the resolver over the
// three shapes that used to be dropped in silence, plus the two it must still
// answer cleanly.
//
// Without it the hardening above is a claim: the sweep's own subject is the
// schema on disk, which carries none of these shapes today, so nothing else in
// this file would notice if the resolver went back to shrugging.
func TestTheClassSweepRefusesAMemberItCannotClassify(t *testing.T) {
	defs := map[string]json.RawMessage{
		"yesno":  json.RawMessage(`{"type":"boolean"}`),
		"target": json.RawMessage(`{"type":"object","properties":{"union":{"type":["boolean","null"]},"viaRef":{"$ref":"#/$defs/yesno"},"plain":{"type":"boolean"},"text":{"type":"string"}}}`),
	}
	for _, tc := range []struct {
		member     string
		wantScalar bool
		wantErr    bool
	}{
		{"union", true, false},  // was silently dropped: the class, missed
		{"viaRef", true, false}, // was silently dropped
		{"ghost", false, true},  // in `required`, declared nowhere
		{"plain", true, false},  // the control that must still resolve
		{"text", false, false},  // the control that must still be excluded
	} {
		t.Run(tc.member, func(t *testing.T) {
			got, err := requiredMemberIsScalar(defs, "target", tc.member)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("member %q was classified rather than refused", tc.member)
				}
				return
			}
			if err != nil {
				t.Fatalf("member %q could not be classified: %v", tc.member, err)
			}
			if got != tc.wantScalar {
				t.Errorf("member %q classified scalar=%t, want %t", tc.member, got, tc.wantScalar)
			}
		})
	}
	if _, err := requiredMemberIsScalar(defs, "absent_definition", "x"); err == nil {
		t.Error("a member of a definition that does not exist was classified rather than refused")
	}
}

// sweepRequiredScalars enumerates the class from the schema and reports every
// member whose ruling is missing, unclassifiable, or recorded without an
// argument. It returns the problems and the set of members it reached.
//
// PURE, so its behaviour on a member it cannot classify can be driven by a test
// rather than inferred. That is the property the round-1 hardening added and
// the property a resolver-only test cannot see: the resolver returning an error
// is worth nothing if the loop reading it goes back to `continue`.
func sweepRequiredScalars(defs map[string]json.RawMessage, rulings map[string]requiredScalarRuling) (problems []string, seen map[string]bool) {
	seen = map[string]bool{}
	names := make([]string, 0, len(defs))
	for name := range defs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, defName := range names {
		var def struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(defs[defName], &def); err != nil {
			problems = append(problems, fmt.Sprintf("parsing definition %q: %v", defName, err))
			continue
		}
		for _, member := range def.Required {
			isScalar, err := requiredMemberIsScalar(defs, defName, member)
			if err != nil {
				// NOT a skip. An earlier revision of this loop `continue`d here,
				// and that is a sweep that silently narrows itself: a required
				// `{"type": ["boolean","null"]}`, a `$ref` to a boolean
				// definition, and a name in `required` with no `properties`
				// entry were each dropped in silence, and the first of those is
				// a required boolean whose absence is invisible - the exact
				// class this sweep exists to enumerate.
				problems = append(problems, fmt.Sprintf(
					"%s/%s: %v. This sweep cannot decide whether the member is in the class, "+
						"so it reports rather than narrowing itself.", defName, member, err))
				continue
			}
			if !isScalar {
				continue
			}
			key := defName + "/" + member
			seen[key] = true
			ruling, declared := rulings[key]
			if !declared {
				problems = append(problems, fmt.Sprintf(
					"%s is a REQUIRED boolean or integer member with no recorded ruling. "+
						"A required scalar whose Go zero value is legal is invisible when absent; "+
						"decide what happens when a document omits it and record it in requiredScalarRulings.", key))
				continue
			}
			if ruling.disposition == admittedWithReason && strings.TrimSpace(ruling.why) == "" {
				problems = append(problems, fmt.Sprintf(
					"%s is admitted with no recorded reason; an exemption with no argument is how a fail-open gets grandfathered", key))
			}
		}
	}
	return problems, seen
}

// TestTheClassSweepCallSiteRefusesRatherThanNarrowing drives the LOOP, not the
// resolver, over the two inputs the committed schema cannot supply.
//
// Round 1 of the review on this change demonstrated the gap it closes: with the
// resolver correct and the loop reverted to `continue`, the sweep reported
// green over a schema carrying a required `["boolean","null"]` member with no
// ruling at all. Testing the predicate is not testing the call site.
func TestTheClassSweepCallSiteRefusesRatherThanNarrowing(t *testing.T) {
	defs := map[string]json.RawMessage{
		"widget": json.RawMessage(`{"type":"object","properties":{` +
			`"union":{"type":["boolean","null"]},` +
			`"ruled":{"type":"boolean"},` +
			`"text":{"type":"string"}},` +
			`"required":["union","ruled","text","ghost"]}`),
	}
	rulings := map[string]requiredScalarRuling{
		"widget/ruled": {refusedByPresence, ""},
	}
	problems, seen := sweepRequiredScalars(defs, rulings)

	// The union member is IN the class and has no ruling: the loop must say so.
	// This is the case a `continue` swallowed.
	if !containsSubstring(problems, "widget/union is a REQUIRED boolean or integer member with no recorded ruling") {
		t.Errorf("a required [\"boolean\",\"null\"] member with no ruling was not reported:\n  %s", strings.Join(problems, "\n  "))
	}
	// The ghost member cannot be classified at all: the loop must report rather
	// than drop it.
	if !containsSubstring(problems, "widget/ghost") {
		t.Errorf("a required member the definition does not declare was not reported:\n  %s", strings.Join(problems, "\n  "))
	}
	// The controls: a ruled scalar produces no problem and IS counted as
	// reached, and a string is out of the class entirely.
	if containsSubstring(problems, "widget/ruled") {
		t.Errorf("a member with a recorded ruling was reported as a problem:\n  %s", strings.Join(problems, "\n  "))
	}
	if !seen["widget/ruled"] {
		t.Error("a member with a recorded ruling was not counted as reached, so its disposition would never be asserted")
	}
	if containsSubstring(problems, "widget/text") || seen["widget/text"] {
		t.Error("a required STRING member was pulled into the class; its absence is caught by the value check that was going to run anyway")
	}

	// And an empty ruling reason is reported, so an exemption cannot be
	// grandfathered by leaving the argument blank.
	blank, _ := sweepRequiredScalars(defs, map[string]requiredScalarRuling{
		"widget/union": {admittedWithReason, "   "},
		"widget/ruled": {refusedByPresence, ""},
	})
	if !containsSubstring(blank, "widget/union is admitted with no recorded reason") {
		t.Errorf("an exemption with a blank reason was accepted:\n  %s", strings.Join(blank, "\n  "))
	}
}

func containsSubstring(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// TestTheWireStructsMirrorTheShapesTheyDecode closes the drift the presence
// boundary quietly opened.
//
// obligationWire and approvalRequirementWire are second declarations of two
// shapes, and strictDecode sets DisallowUnknownFields - so a member added to
// Obligation and forgotten in obligationWire does not decode as its zero value,
// it makes EVERY document carrying that member a decode failure. That is
// fail-closed, which is the right direction, and it is also a total outage of
// the shape on the first request that carries the new member.
//
// Comparing the json TAGS rather than the Go field names: the tag is what the
// wire agrees on, and a mirror struct is free to name its field anything.
func TestTheWireStructsMirrorTheShapesTheyDecode(t *testing.T) {
	tags := func(v any) map[string]bool {
		out := map[string]bool{}
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.PkgPath != "" {
				continue // unexported: never on the wire, and never mirrored
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			out[name] = true
		}
		return out
	}
	for _, tc := range []struct {
		name        string
		shape, wire any
	}{
		{"obligation", Obligation{}, obligationWire{}},
		{"approval_requirement", ApprovalRequirement{}, approvalRequirementWire{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shape, wire := tags(tc.shape), tags(tc.wire)
			if len(shape) == 0 || len(wire) == 0 {
				t.Fatalf("one side declares no wire members (%d vs %d), so the comparison is vacuous", len(shape), len(wire))
			}
			for name := range shape {
				if !wire[name] {
					t.Errorf("%T emits %q and its decode mirror does not declare it. strictDecode refuses unknown "+
						"members, so every document carrying %q would fail to decode entirely.", tc.shape, name, name)
				}
			}
			for name := range wire {
				if !shape[name] {
					t.Errorf("the decode mirror declares %q, which %T does not emit; it would be accepted on the way "+
						"in and dropped on the way out", name, tc.shape)
				}
			}
		})
	}
}

// TestAnExplicitNullIsRefusedAndSaysSo covers the branch that distinguishes a
// member present as `null` from one that was omitted.
//
// Both decode to a nil pointer and both are refused, so a test that only
// asserted "refused" would pass with the null branch deleted - and the refusal
// would then claim the document OMITTED a member it plainly carries, in the one
// error whose entire job is to tell presence from absence. Worse: without the
// branch, `null` is not distinguished at all, and an implementation that
// treated a nil raw message as "present and false" would read `null` as
// ADVISORY. The wording is asserted, not just the failure.
func TestAnExplicitNullIsRefusedAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name     string
		document string
		decode   func(string) error
		pointer  string
	}{
		{
			name:     "an obligation whose mandatory member is null",
			document: `{"type":"field_redact","target":"args.query","mandatory":null,"source_policy":"p-1","schema_version":1}`,
			pointer:  "/mandatory",
			decode: func(raw string) error {
				var o Obligation
				if err := json.Unmarshal([]byte(raw), &o); err != nil {
					return err
				}
				return o.Validate()
			},
		},
		{
			name:     "an approval requirement whose separation_of_duties is null",
			document: `{"all_of":[{"quorum":1,"eligible":[{"kind":"group","type":"Group","qualifier":"realm","local":"g"}]}],"separation_of_duties":null,"expires_at":"2030-01-01T00:00:00Z"}`,
			pointer:  "/separation_of_duties",
			decode: func(raw string) error {
				var a ApprovalRequirement
				if err := json.Unmarshal([]byte(raw), &a); err != nil {
					return err
				}
				return a.Validate()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.decode(tc.document)
			if err == nil {
				t.Fatalf("a member present as null was accepted; it carries no value, and the value it would " +
					"default to is the permissive one")
			}
			var missing *MissingMemberError
			if !errors.As(err, &missing) {
				t.Fatalf("the refusal is not typed: %T %v", err, err)
			}
			if missing.Pointer != tc.pointer {
				t.Errorf("the refusal names %q, want %q", missing.Pointer, tc.pointer)
			}
			if !missing.WasNull {
				t.Errorf("the refusal did not record that the member was present as null, so it reports an omission " +
					"the document did not make")
			}
			if !strings.Contains(err.Error(), "is present as null") {
				t.Errorf("the message does not say the member was null: %v", err)
			}
			if strings.Contains(err.Error(), "is absent from the document") {
				t.Errorf("the message claims the document omitted a member it carries: %v", err)
			}
		})
	}

	// A DECISION carrying a null member refuses with the absolute pointer, and
	// the null-ness survives being re-rooted.
	document := fmt.Sprintf(`{
		"decision_id":"d-1","request_id":"r-1","authorization":"permit","state":"ALLOW","reason":"permitted",
		"obligations":[{"type":"field_redact","target":"args.a","mandatory":null,"source_policy":"p","schema_version":1}],
		"determining":{"matched_permissions":["p-1"],"matched_constraints":[],"matched_requirements":[],"matched_inspections":[]},
		"snapshot":{"identity_epoch":1,"resource_epoch":1,"policy_bundle":"sha256:abc","registry_version":1,"schema_version":%q,"policy_epoch":1}
	}`, SchemaVersion)
	var d Decision
	if err := json.Unmarshal([]byte(document), &d); err != nil {
		t.Fatalf("the decision document did not decode: %v", err)
	}
	err := d.Validate()
	var missing *MissingMemberError
	if !errors.As(err, &missing) {
		t.Fatalf("a decision carrying a null mandatory member was not refused with a typed error: %T %v", err, err)
	}
	if missing.Pointer != "/obligations/0/mandatory" {
		t.Errorf("the refusal names %q, want %q", missing.Pointer, "/obligations/0/mandatory")
	}
	if !missing.WasNull {
		t.Error("re-rooting the pointer lost the fact that the member was null")
	}
}

// TestADuplicatedMemberIsRefusedRatherThanReadLastWins closes the other way a
// document can state one thing and be read as another.
//
// encoding/json silently keeps the LAST of a repeated member, so
// `{"mandatory":true,"mandatory":false}` decodes as advisory: a document that
// says the obligation is mandatory, read as the opposite. It is also the
// classic split-brain - a gateway, an audit log or a rate limiter that read the
// FIRST occurrence saw a different request than the evaluator did.
func TestADuplicatedMemberIsRefusedRatherThanReadLastWins(t *testing.T) {
	var o Obligation
	err := json.Unmarshal([]byte(
		`{"type":"field_redact","target":"args.q","mandatory":true,"mandatory":false,"source_policy":"p","schema_version":1}`), &o)
	if err == nil {
		t.Fatalf("a duplicated `mandatory` member was accepted and decoded as mandatory=%t; encoding/json keeps the "+
			"LAST occurrence, so a document stating the obligation is mandatory reads as advisory", o.Mandatory)
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("the refusal does not name the duplication: %v", err)
	}

	// The control: the same document with one occurrence decodes and validates.
	var clean Obligation
	if err := json.Unmarshal([]byte(
		`{"type":"field_redact","target":"args.q","mandatory":true,"source_policy":"p","schema_version":1}`), &clean); err != nil {
		t.Fatalf("the single-occurrence control did not decode: %v", err)
	}
	if err := clean.Validate(); err != nil {
		t.Fatalf("the single-occurrence control was refused: %v", err)
	}

	// ...and one level down, on a nested clause, since the walk is recursive.
	var a ApprovalRequirement
	if err := json.Unmarshal([]byte(
		`{"all_of":[{"quorum":1,"quorum":2,"eligible":[{"kind":"group","type":"Group","qualifier":"realm","local":"g"}]}],"separation_of_duties":true,"expires_at":"2030-01-01T00:00:00Z"}`), &a); err == nil {
		t.Error("a duplicated member on a nested clause was accepted")
	}
}
