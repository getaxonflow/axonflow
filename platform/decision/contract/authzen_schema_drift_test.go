package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The AuthZEN wire shapes exist as Go types first and as JSON Schema second.
// That ordering is a hazard: the schema is what every non-Go plane reads and
// what the SDK types are GENERATED from, so a schema that has drifted from the
// Go struct is a field one side emits and the other cannot see - and neither
// side can notice alone.
//
// These tests bind the two in BOTH directions. Every assertion below fails on a
// Go-side edit with no schema edit, AND on a schema-side edit with no Go edit.
// One direction alone is worth very little: a test that only checked that every
// schema property exists in Go would pass forever while Go grew a field nothing
// downstream could see, which is precisely the declared-but-never-emitted class
// the contract guards exist for, running in the other direction.

// wireBinding names one Go type and the schema definition that describes it.
//
// The zero value of the type is enough: reflection reads the field tags, never
// the values, so nothing here depends on a fixture staying representative.
type wireBinding struct {
	schema Schema
	goType any
}

func authzenWireBindings() []wireBinding {
	return []wireBinding{
		{SchemaAuthZENSubject, AuthZENSubject{}},
		{SchemaAuthZENAction, AuthZENAction{}},
		{SchemaAuthZENResource, AuthZENResource{}},
		{SchemaAuthZENRequest, AuthZENRequest{}},
		{SchemaAuthZENBulk, AuthZENBulk{}},
		{SchemaAuthZENEnvelope, AuthZENEnvelope{}},
		{SchemaAuthZENResponse, AuthZENResponse{}},
		{SchemaAuthZENResponseContext, AuthZENResponseContext{}},
		{SchemaAuthZENError, AuthZENError{}},
		// Reachable from the response context, therefore generated into every
		// SDK, therefore drift on them costs exactly what drift on an authzen_*
		// shape costs. Binding only the authzen_-prefixed shapes would have left
		// the obligation and approval types - the ones carrying the enforcement
		// instructions - unguarded.
		{SchemaObligation, Obligation{}},
		{SchemaApproval, ApprovalRequirement{}},
		{SchemaApprovalClause, ApprovalClause{}},
		{SchemaIdentifier, ID{}},
	}
}

// TestEveryAuthZENSchemaIsBoundToAGoType is the completeness ratchet.
//
// Without it, adding a ninth AuthZEN definition to AllSchemas and forgetting to
// bind it leaves that definition unchecked forever, and the drift suite below
// still reports green over the eight it does know about. A guard whose coverage
// can silently shrink is the failure mode the whole contract-guard family was
// built to answer, so coverage is asserted rather than assumed.
func TestEveryAuthZENSchemaIsBoundToAGoType(t *testing.T) {
	bound := map[Schema]bool{}
	for _, b := range authzenWireBindings() {
		if bound[b.schema] {
			t.Errorf("schema %q is bound twice", b.schema)
		}
		bound[b.schema] = true
	}
	for _, s := range AllSchemas() {
		if !strings.HasPrefix(string(s), "authzen") {
			continue
		}
		if !bound[s] {
			t.Errorf("schema %q is declared in AllSchemas but bound to no Go type; "+
				"add it to authzenWireBindings so the drift tests can see it", s)
		}
	}
	// ...and the reverse, so a binding cannot outlive the schema it names.
	declared := map[Schema]bool{}
	for _, s := range AllSchemas() {
		declared[s] = true
	}
	for _, b := range authzenWireBindings() {
		if !declared[b.schema] {
			t.Errorf("a binding names schema %q, which AllSchemas does not declare", b.schema)
		}
	}
}

// goWireFields returns the json field name -> required mapping a Go struct
// declares. Required means "carries no omitempty": encoding/json emits such a
// field unconditionally, so the schema must accept it as mandatory.
func goWireFields(t *testing.T, v any) map[string]bool {
	t.Helper()
	rt := reflect.TypeOf(v)
	if rt.Kind() != reflect.Struct {
		t.Fatalf("binding for %T is not a struct", v)
	}
	out := map[string]bool{}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" {
			continue // unexported; never on the wire
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			// No json tag: encoding/json emits the Go field name verbatim.
			// That is almost certainly a mistake on a wire type, and saying so
			// is better than silently comparing a CamelCase name against a
			// snake_case schema property.
			t.Errorf("%T field %q has no json tag; a wire type must name every field explicitly", v, f.Name)
			continue
		}
		omitempty := false
		for _, p := range parts[1:] {
			if p == "omitempty" {
				omitempty = true
			}
		}
		out[name] = !omitempty
	}
	return out
}

// schemaWireFields returns the property name -> required mapping one schema
// definition declares.
func schemaWireFields(t *testing.T, s Schema) map[string]bool {
	t.Helper()
	// Every level is read as a raw message and decoded only as far as needed.
	// A JSON Schema property value may legally be a boolean (`"value": true`
	// on the attribute definition is one), and additionalProperties may be a
	// schema object rather than a flag, so a struct that assumed either shape
	// would fail to parse the document over definitions this test never asked
	// about.
	rawDoc, err := SchemaDocument()
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(rawDoc, &doc); err != nil {
		t.Fatalf("parsing the schema: %v", err)
	}
	rawDef, ok := doc.Defs[string(s)]
	if !ok {
		t.Fatalf("the schema declares no definition %q", s)
	}
	var def struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties json.RawMessage            `json:"additionalProperties"`
	}
	if err := json.Unmarshal(rawDef, &def); err != nil {
		t.Fatalf("parsing definition %q: %v", s, err)
	}
	if len(def.Properties) == 0 {
		t.Fatalf("definition %q declares no properties; an unconstrained shape is not a contract", s)
	}
	// A wire shape that accepts undeclared members cannot be a drift guard: the
	// half of the comparison that catches a phantom field would be unenforceable
	// on the wire even when the test noticed it.
	if strings.TrimSpace(string(def.AdditionalProperties)) != "false" {
		t.Errorf("definition %q does not set additionalProperties:false (got %q); "+
			"strict decoding is the boundary, and a tolerant schema contradicts it",
			s, string(def.AdditionalProperties))
	}
	required := map[string]bool{}
	for _, r := range def.Required {
		required[r] = true
	}
	out := map[string]bool{}
	for name := range def.Properties {
		out[name] = required[name]
	}
	for r := range required {
		if _, ok := def.Properties[r]; !ok {
			t.Errorf("definition %q requires %q, which it does not declare as a property", s, r)
		}
	}
	return out
}

// TestAuthZENSchemaFieldsMatchTheGoStructs is the field-shape half of the drift
// guard: the same-name field-shape comparison, run in both directions.
func TestAuthZENSchemaFieldsMatchTheGoStructs(t *testing.T) {
	for _, b := range authzenWireBindings() {
		t.Run(string(b.schema), func(t *testing.T) {
			goFields := goWireFields(t, b.goType)
			schemaFields := schemaWireFields(t, b.schema)

			for name, goRequired := range goFields {
				schemaRequired, present := schemaFields[name]
				if !present {
					t.Errorf("%T emits %q, which the schema does not declare; "+
						"every plane that validates against this schema would refuse the field",
						b.goType, name)
					continue
				}
				if goRequired != schemaRequired {
					t.Errorf("%T field %q is %s in Go and %s in the schema",
						b.goType, name,
						requiredWord(goRequired), requiredWord(schemaRequired))
				}
			}
			for name := range schemaFields {
				if _, present := goFields[name]; !present {
					t.Errorf("the schema declares %q on %q, which %T never emits; "+
						"a generated SDK would carry a field the server cannot produce",
						name, b.schema, b.goType)
				}
			}
			for _, finding := range assertGoTypesMatchTheContract(t, b, goFields, shippedSurfaceDocument(t)) {
				t.Error(finding)
			}
		})
	}
}

func requiredWord(b bool) string {
	if b {
		return "required"
	}
	return "optional"
}

// TestAuthZENSchemaEnumerationsMatchTheGoDeclarations extends the existing
// enumeration guard onto the profile payload.
//
// state and category were previously unbound on BOTH sides: the decision and
// trace definitions restate them as literals and no test compared them to the
// Go constants, so either could have grown a value the other refused. The
// enumerators they read now exist for exactly this.
func TestAuthZENSchemaEnumerationsMatchTheGoDeclarations(t *testing.T) {
	raw, err := SchemaDocument()
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	// Decoded lazily, one property at a time: a property value may be a bare
	// boolean, which no fixed struct shape can hold.
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing the schema: %v", err)
	}
	propertyAt := func(def, prop string) struct {
		Enum  []string `json:"enum"`
		Const *string  `json:"const"`
	} {
		var out struct {
			Enum  []string `json:"enum"`
			Const *string  `json:"const"`
		}
		rawDef, ok := doc.Defs[def]
		if !ok {
			t.Fatalf("the schema declares no %q", def)
		}
		var d struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(rawDef, &d); err != nil {
			t.Fatalf("parsing definition %q: %v", def, err)
		}
		rawProp, ok := d.Properties[prop]
		if !ok {
			t.Fatalf("%q declares no property %q", def, prop)
		}
		if err := json.Unmarshal(rawProp, &out); err != nil {
			t.Fatalf("parsing %q/%q: %v", def, prop, err)
		}
		return out
	}

	compare := func(what string, schema, declared []string) {
		t.Helper()
		if len(schema) == 0 {
			t.Fatalf("%s: the schema declares no enumeration; there is nothing to compare", what)
		}
		if len(declared) == 0 {
			t.Fatalf("%s: the Go package declares nothing; the comparison would be vacuous", what)
		}
		s, d := map[string]bool{}, map[string]bool{}
		for _, v := range schema {
			s[v] = true
		}
		for _, v := range declared {
			d[v] = true
		}
		for v := range s {
			if !d[v] {
				t.Errorf("%s: the schema accepts %q, which the Go package does not declare", what, v)
			}
		}
		for v := range d {
			if !s[v] {
				t.Errorf("%s: the Go package declares %q, which the schema refuses", what, v)
			}
		}
	}

	enumAt := func(def, prop string) []string { return propertyAt(def, prop).Enum }

	var states []string
	for _, s := range AllOperationalStates() {
		states = append(states, string(s))
	}
	var categories []string
	for _, c := range AllCategories() {
		categories = append(categories, string(c))
	}
	var reasons []string
	for _, r := range AllReasonCodes() {
		reasons = append(reasons, string(r))
	}

	// The profile payload...
	compare("profile states", enumAt("authzen_response_context", "state"), states)
	compare("profile categories", enumAt("authzen_response_context", "category"), categories)
	compare("profile reason codes", enumAt("authzen_response_context", "reason"), reasons)

	// ...and the two internal definitions that restate the same enumerations and
	// were never compared to Go at all.
	compare("decision states", enumAt("decision", "state"), states)
	compare("trace states", enumAt("trace", "state"), states)
	compare("trace categories", enumAt("trace", "category"), categories)

	var errorCodes []string
	for _, c := range AllAuthZENErrorCodes() {
		errorCodes = append(errorCodes, string(c))
	}
	compare("refusal codes", enumAt("authzen_error", "code"), errorCodes)

	// The profile constant is the AuthZEN wire's version. A schema pinning a
	// different one would accept a payload no build emits, which is the same
	// defect class as a drifted enumeration and is invisible to the field
	// comparison because `profile` is present on both sides either way.
	prof := propertyAt("authzen_response_context", "profile")
	if prof.Const == nil {
		t.Fatal("the profile property declares no const; the wire version would be unpinned")
	}
	if *prof.Const != string(AuthZENProfileV1) {
		t.Errorf("the schema pins profile %q, the Go package emits %q", *prof.Const, AuthZENProfileV1)
	}
}

// TestAuthZENGoValuesValidateAgainstTheSchema closes the loop the two structural
// tests above leave open.
//
// Matching field names and required flags does not prove a value this package
// PRODUCES is one the schema ACCEPTS: types, formats and the conditional
// subschemas are all outside the field comparison. Encoding real values and
// validating them is what makes the schema a description of this package rather
// than a document that merely agrees with it about names.
func TestAuthZENGoValuesValidateAgainstTheSchema(t *testing.T) {
	subject := &AuthZENSubject{Type: "gateway", ID: "u-1", Properties: map[string]any{"dept": "legal"}}
	action := &AuthZENAction{Name: "read"}
	resource := &AuthZENResource{Type: "ticket", ID: "SUP-42"}

	for _, tc := range []struct {
		name   string
		schema Schema
		value  any
	}{
		{"singular envelope", SchemaAuthZENEnvelope, AuthZENEnvelope{
			Evaluation: &AuthZENRequest{Subject: subject, Action: action, Resource: resource},
		}},
		{"plural envelope", SchemaAuthZENEnvelope, AuthZENEnvelope{
			Evaluations: &AuthZENBulk{
				Subject: subject, Action: action,
				Evaluations: []AuthZENRequest{
					{Resource: resource},
					{Resource: &AuthZENResource{Type: "project", ID: "P-9"}},
				},
			},
		}},
		{"inheriting entry", SchemaAuthZENRequest, AuthZENRequest{}},
		{"un-negotiated response", SchemaAuthZENResponse, AuthZENResponse{Decision: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("encoding: %v", err)
			}
			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("decoding: %v", err)
			}
			if err := ValidateAgainstSchema(tc.schema, doc); err != nil {
				t.Errorf("the schema refused a value this package produces: %v\n%s", err, raw)
			}
		})
	}
}

// TestAuthZENResponseCollapseIsTotalInBothDirections pins the one conditional
// the response schema carries, using a decision this package actually produces.
//
// The boolean and the state are two encodings of one outcome. If they can
// disagree, a profile-aware enforcement point reading `decision` and a
// profile-aware auditor reading `state` describe the same request differently,
// and only one of them is right.
func TestAuthZENResponseCollapseIsTotalInBothDirections(t *testing.T) {
	for _, st := range AllOperationalStates() {
		resp := AuthZENResponse{
			Decision: st.Executable(),
			Context: &AuthZENResponseContext{
				Profile:       AuthZENProfileV1,
				State:         st,
				Category:      CategoryAllowed,
				DecisionID:    "d-1",
				SchemaVersion: SchemaVersion,
			},
		}
		raw, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("encoding: %v", err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		if err := ValidateAgainstSchema(SchemaAuthZENResponse, doc); err != nil {
			t.Errorf("the schema refused a consistent %s response: %v", st, err)
		}

		// Now flip ONLY the boolean. The schema must refuse every one of these,
		// including the ALLOW case: a false beside ALLOW is as wrong as a true
		// beside DENY, and a one-sided conditional would accept it.
		resp.Decision = !resp.Decision
		raw, err = json.Marshal(resp)
		if err != nil {
			t.Fatalf("encoding: %v", err)
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		if err := ValidateAgainstSchema(SchemaAuthZENResponse, doc); err == nil {
			t.Errorf("the schema accepted decision=%v beside state %s", resp.Decision, st)
		}
	}
}

// TestTheDecoderAndTheSchemaAgreeOnShape holds the schema to what THIS package
// actually runs on the request path.
//
// WHAT CHANGED AND WHY, because the correction is the point. This test used to
// measure `DecodeAuthZENEnvelope` + `AuthZENEnvelope.Project` behind a helper
// whose comment called that pair "the boundary in production". It was not.
// `grep -rn "\.Project("` outside this package returns only _test.go files: the
// AuthZEN route runs the decoder and then platform/agent's adapter, and Project
// runs nowhere on it. That mattered rather than being a documentation nit,
// because Project DOES enforce the schema's required set and the adapter did
// NOT - so this test reported the schema and the server as agreeing about
// `subject.type` while the route read an ABSENT type as the supported value and
// bound a caller-supplied end-user id to the gateway identity. A test measuring
// a function the request path does not call cannot see a defect on the request
// path.
//
// So the halves are split along the line the code actually draws:
//
//   - THIS test pins the DECODER against the schema. Those are the structural
//     rules - strict keys, no duplicate members, exactly one of the two
//     top-level members, a non-empty plural array - and the decoder is on every
//     request path, this package's and the route's alike.
//   - The COMPLETENESS half - required members, inheritance from the shared
//     base, and everything the adapter narrows - is pinned against the real
//     boundary by TestTheSchemaAgreesWithTheRouteBoundary in platform/agent,
//     which can call the adapter. This module may not import the rest of the
//     platform, so the test goes to the boundary rather than the boundary to
//     the test.
//
// Project keeps its own coverage as the PDP's future projection step
// (TestProjectRefusesAnIncompleteEvaluation below); what it must not do is
// stand in for a path that does not call it.
//
// One decoder rule is deliberately NOT in the table: a DUPLICATE member name.
// The decoder refuses it by walking the token stream, and a JSON Schema
// validator structurally cannot see it, because the document it validates has
// already been parsed and the duplicate collapsed to one member. Asserting
// agreement there would assert something no validator can deliver.
func TestTheDecoderAndTheSchemaAgreeOnShape(t *testing.T) {
	complete := `{"subject":{"type":"gateway","id":"u1"},"action":{"name":"read"},"resource":{"type":"ticket","id":"t1"}}`
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"neither member", `{}`},
		{"both members", `{"evaluation":` + complete + `,"evaluations":{"evaluations":[{}]}}`},
		{"an empty plural array", `{"evaluations":{"evaluations":[]}}`},
		{"an undeclared top-level member", `{"evaluation":` + complete + `,"profile":"x"}`},
		{"a null declared member", `{"evaluation":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, decodeErr := DecodeAuthZENEnvelope([]byte(tc.raw))
			var doc any
			if err := json.Unmarshal([]byte(tc.raw), &doc); err != nil {
				t.Fatalf("the fixture is not valid JSON: %v", err)
			}
			schemaErr := ValidateAgainstSchema(SchemaAuthZENEnvelope, doc)
			if decodeErr == nil {
				t.Errorf("the decoder accepted %s", tc.name)
			}
			if schemaErr == nil {
				t.Errorf("the schema accepted %s, which the decoder refuses; "+
					"a generated client would build a request the server rejects", tc.name)
			}
		})
	}

	// The agreement must also hold in the accepting direction, or the two
	// boundaries could agree only by both refusing everything.
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"a singular evaluation", `{"evaluation":` + complete + `}`},
		{"a plural envelope inheriting the base", `{"evaluations":{"subject":{"type":"gateway","id":"u1"},"action":{"name":"read"},"resource":{"type":"t","id":"1"},"evaluations":[{}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeAuthZENEnvelope([]byte(tc.raw)); err != nil {
				t.Errorf("the decoder refused %s: %v", tc.name, err)
			}
			var doc any
			if err := json.Unmarshal([]byte(tc.raw), &doc); err != nil {
				t.Fatalf("the fixture is not valid JSON: %v", err)
			}
			if err := ValidateAgainstSchema(SchemaAuthZENEnvelope, doc); err != nil {
				t.Errorf("the schema refused %s, which the decoder accepts: %v", tc.name, err)
			}
		})
	}
}

// TestProjectRefusesAnIncompleteEvaluation keeps Project's own rules covered,
// under a name that says whose rules they are.
//
// Project is this package's projection step for the ADR-065 PDP, not the
// AuthZEN route's boundary, so what it proves is that the PROJECTION refuses an
// incomplete evaluation - never that the request path does. The route's
// enforcement of the same rules is pinned in platform/agent, against the
// adapter the route actually calls.
func TestProjectRefusesAnIncompleteEvaluation(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"a singular member with no action", `{"evaluation":{"subject":{"type":"gateway","id":"u1"},"resource":{"type":"t","id":"1"}}}`},
		{"a subject with no type", `{"evaluation":{"subject":{"id":"u1"},"action":{"name":"read"},"resource":{"type":"t","id":"1"}}}`},
		{"a resource with no type", `{"evaluation":{"subject":{"type":"gateway","id":"u1"},"action":{"name":"read"},"resource":{"id":"1"}}}`},
		{"a plural entry inheriting an incomplete base", `{"evaluations":{"subject":{"type":"gateway","id":"u1"},"evaluations":[{"resource":{"type":"t","id":"1"}}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, err := DecodeAuthZENEnvelope([]byte(tc.raw))
			if err != nil {
				t.Fatalf("the decoder refused the fixture, so the projection is not what is under test: %v", err)
			}
			if _, err := env.Project(time.Unix(0, 0).UTC()); err == nil {
				t.Errorf("the projection accepted %s", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The TYPE axis (#3641).
// ---------------------------------------------------------------------------

// The comparison above pins field NAMES and REQUIRED-NESS. It did not pin
// TYPES, and the gap was demonstrated live rather than imagined: the R3 on
// #3632 changed `authzen_error.request_id` from string to integer in the schema
// and regenerated the artifact, and contract/authzen.go went on declaring
// `RequestID string` with all nine platform/decision packages green. The Go
// server and the artifact every SDK generates from described different wires.
//
// #3632 closed the half that protects the SDKs - the artifact's field types are
// pinned to the profile constant - but it is caught at the ARTIFACT, not at the
// Go struct. This closes the remaining hole:
//
//	schema <-> artifact                 pinned (byte identity, TestCommittedArtifactIsCurrent)
//	artifact <-> profile                pinned (#3632, all four axes)
//	schema <-> Go names + requiredness  pinned (above)
//	schema <-> Go TYPES                 this
//
// WHY IT READS THE ARTIFACT RATHER THAN THE SCHEMA. The artifact is the schema
// REDUCED - one flat document with every reference resolved and every type in
// the vocabulary the SDK generators consume - and it is byte-pinned to the
// schema by cmd/authzen-codegen's TestCommittedArtifactIsCurrent, in the same
// sweep. Re-deriving the type from raw JSON Schema here would put a SECOND
// implementation of that reducer in the test suite, free to disagree with the
// real one, and this file would then pin Go against its own opinion of the
// contract rather than against the contract. It is the same argument the
// response-surface ratchet already makes for reading required-ness and enum
// values off the artifact. The artifact's CURRENCY is asserted rather than
// assumed - see shippedSurfaceDocument.

// goWireType renders a Go struct field into the artifact's own TypeRef
// vocabulary, so the two can be compared as strings.
//
// The vocabulary is the reducer's, not one invented here: "string", "bool",
// "int", "object", "array<...>", "map<...>", "ref:<definition>". A third
// naming would certify the naming rather than the contract.
//
// ENUMS COLLAPSE TO THEIR UNDERLYING JSON TYPE, and the reason is stated rather
// than hidden. A Go named string type IS a string; nothing in the type system
// distinguishes OperationalState from string, so demanding
// "enum:operational_state" would assert a NAMING CONVENTION this test invented.
// The enum axis is covered by VALUE in
// TestAuthZENSchemaEnumerationsMatchTheGoDeclarations. What is asserted here is
// the one enum property the type system can carry: a member the contract
// declares as a closed set must not sit in a bare `string`.
func goWireType(t *testing.T, ft reflect.Type, bindings map[reflect.Type]Schema) string {
	t.Helper()
	for ft.Kind() == reflect.Pointer {
		ft = ft.Elem()
	}
	if schema, bound := bindings[ft]; bound {
		return "ref:" + string(schema)
	}
	// THE RENDERER READS THE DECLARATION; encoding/json reads the MARSHALLER.
	// Where the two disagree this function is guessing, and one of the guesses
	// is wrong-but-AGREEING: json.Number is declared as a string and goes on the
	// wire as a bare number, so a contract `string` and a Go json.Number would
	// compare equal while the wire carried something else. []byte (base64
	// string, declared as a slice) and json.RawMessage (any shape at all) are
	// the same class in the loud direction. So an unrecognised marshaller is
	// refused rather than rendered, which also makes the time.Time carve-out
	// below self-policing instead of a comment about today.
	switch {
	case ft == reflect.TypeOf(json.Number("")):
		t.Fatalf("json.Number is declared as a string and marshals as a bare NUMBER; this comparison reads the " +
			"declaration and would report agreement with a contract `string` while the wire carried a number")
	case ft == reflect.TypeOf(json.RawMessage(nil)):
		t.Fatalf("json.RawMessage marshals as whatever it holds; there is no single contract type to compare it to")
	case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Uint8:
		t.Fatalf("a []byte marshals as a base64 STRING, not as an array; rendering it from the declaration would " +
			"report a spurious mismatch against a correct contract `string`")
	case ft != reflect.TypeOf(time.Time{}) &&
		(ft.Implements(jsonMarshalerType) || reflect.PointerTo(ft).Implements(jsonMarshalerType)):
		t.Fatalf("%s carries a MarshalJSON of its own, so its wire form is not its declaration. Either add it here "+
			"with the type it actually emits, or give it a binding.", ft)
	}
	switch ft.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "int"
	case reflect.Slice, reflect.Array:
		return "array<" + goWireType(t, ft.Elem(), bindings) + ">"
	case reflect.Map:
		if ft.Key().Kind() != reflect.String {
			return "map<!non-string key>"
		}
		// map[string]any IS the contract's opaque `object`, not a typed map, and
		// the distinction is the reducer's own: it emits `object` for a JSON
		// Schema object with no additionalProperties schema, and `map<X>` only
		// when additionalProperties carries one. AuthZEN's `properties` and
		// `context` are declared the first way on purpose; obligation.params is
		// declared the second, as map<string>, which is why reducing both to
		// "some map" would let a generated SDK accept values the server refuses.
		// Collapsing here keeps the two DISTINCT while spelling each the way the
		// contract does.
		if ft.Elem().Kind() == reflect.Interface && ft.Elem().NumMethod() == 0 {
			return "object"
		}
		return "map<" + goWireType(t, ft.Elem(), bindings) + ">"
	case reflect.Interface:
		// `any` encodes as whatever it holds; the contract calls that an opaque
		// object, which is what AuthZEN's own `properties` and `context` are.
		return "object"
	case reflect.Struct:
		// time.Time is the one struct with a marshaller of its own this contract
		// uses, and it goes on the wire as an RFC 3339 string.
		if ft.PkgPath() == "time" && ft.Name() == "Time" {
			return "string"
		}
		return "object"
	default:
		return "!unsupported " + ft.Kind().String()
	}
}

// jsonMarshalerType is checked against, rather than a name, so a type that
// takes control of its own encoding cannot be rendered from its declaration.
var jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()

// artifactFieldTypesFor returns one artifact type's field name -> rendered type
// map, plus which of those members reach an enumeration.
func artifactFieldTypesFor(t *testing.T, doc map[string]any, typeName string) (rendered map[string]string, enumMembers map[string]bool) {
	t.Helper()
	rendered = map[string]string{}
	enumMembers = map[string]bool{}
	types, ok := doc["types"].([]any)
	if !ok {
		t.Fatalf("the surface artifact declares no types array")
	}
	for _, raw := range types {
		entry, ok := raw.(map[string]any)
		if !ok || entry["name"] != typeName {
			continue
		}
		fields, ok := entry["fields"].([]any)
		if !ok || len(fields) == 0 {
			t.Fatalf("artifact type %q declares no fields", typeName)
		}
		for _, rawField := range fields {
			field, ok := rawField.(map[string]any)
			if !ok {
				t.Fatalf("artifact type %q has a malformed field entry", typeName)
			}
			name, _ := field["name"].(string)
			encoded, err := json.Marshal(field["type"])
			if err != nil {
				t.Fatalf("re-encoding %s/%s's type: %v", typeName, name, err)
			}
			var ref artifactTypeRef
			if err := json.Unmarshal(encoded, &ref); err != nil {
				t.Fatalf("decoding %s/%s's type: %v", typeName, name, err)
			}
			enums := map[string]bool{}
			enumsReachedBy(&ref, enums)
			enumMembers[name] = len(enums) > 0
			rendered[name] = collapseEnums(renderArtifactType(&ref))
		}
		return rendered, enumMembers
	}
	t.Fatalf("the surface artifact declares no type %q", typeName)
	return nil, nil
}

// collapseEnums rewrites "enum:<name>" as "string" in a rendered TypeRef.
//
// Lossless with respect to the JSON type, which is the axis this comparison is
// about - and the premise is asserted rather than assumed by
// TestEveryArtifactEnumerationIsOverStrings.
func collapseEnums(rendered string) string {
	const token = "enum:"
	out := rendered
	from := 0
	for {
		i := strings.Index(out[from:], token)
		if i < 0 {
			return out
		}
		i += from
		// A TOKEN BOUNDARY, not a substring. "enum:" only opens a type when it
		// starts the rendering or follows a `<`; inside a definition name -
		// "ref:has_enum:inside" - it is part of the name, and collapsing there
		// would produce a WRONG answer rather than a loud one. Unreachable
		// today (the codegen's enum names carry no colon and no $defs key
		// does), which is exactly why it is worth pinning: nothing else would
		// notice if it became reachable.
		if i != 0 && out[i-1] != '<' {
			from = i + len(token)
			continue
		}
		j := i + len(token)
		for j < len(out) && out[j] != '>' {
			j++
		}
		out = out[:i] + "string" + out[j:]
		from = i + len("string")
	}
}

// assertGoTypesMatchTheContract compares one binding's Go field types against
// the contract's and reports every disagreement.
//
// It RETURNS the findings rather than calling t.Errorf, and that is not a
// style choice. A comparison that reports through t is one whose call site
// cannot be driven: with the comparison correct and the single call in
// TestAuthZENSchemaFieldsMatchTheGoStructs deleted - or its `if got != want`
// turned into `if false && got != want` - the entire package stayed green.
// Testing the predicate is not testing the call site, and the plant recorded in
// this change's own commit message was a one-off run rather than something the
// merged artifact keeps. Returning findings lets
// TestTheTypeComparisonReportsARealMismatch drive this function over a binding
// that genuinely disagrees.
func assertGoTypesMatchTheContract(t *testing.T, b wireBinding, goFields map[string]bool, doc map[string]any) []string {
	t.Helper()
	artifactTypes, enumMembers := artifactFieldTypesFor(t, doc, string(b.schema))

	bindings := map[reflect.Type]Schema{}
	for _, other := range authzenWireBindings() {
		bindings[reflect.TypeOf(other.goType)] = other.schema
	}

	var findings []string
	rt := reflect.TypeOf(b.goType)
	compared := 0
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		if _, declared := goFields[name]; !declared {
			continue
		}
		want, present := artifactTypes[name]
		if !present {
			// The name comparison already reports a member the contract does
			// not declare; saying it twice adds noise.
			continue
		}
		compared++
		got := goWireType(t, f.Type, bindings)
		if got != want {
			findings = append(findings, fmt.Sprintf(
				"%T field %q is %s in Go and %s in the contract. The server would serialise something other than "+
					"what the contract says, on the surface five SDKs and every third-party PEP decode strictly.",
				b.goType, name, got, want))
		}
		// The one enum property the Go type system can carry, and its reach is
		// stated rather than overclaimed: for a member that ALREADY has a
		// defined type, widening it to a bare `string` does not compile, because
		// existing call sites assign the constants. This guard is for the case
		// with no such call site - a NEW enumerated member declared as a plain
		// string - where nothing else would object, and where the value-level
		// enum comparison cannot help: that one compares the schema's list
		// against the package's declared constants, never against the field
		// holding them.
		if enumMembers[name] && f.Type.Kind() == reflect.String && f.Type.PkgPath() == "" {
			findings = append(findings, fmt.Sprintf(
				"%T field %q holds a contract ENUMERATION in a bare `string`; a defined type is what stops a value "+
					"outside the closed set being assigned without a conversion", b.goType, name))
		}
	}
	// Anti-vacuity, per binding. A binding whose fields all fell through the
	// filters above would report clean having compared nothing, which is the
	// same silent-narrowing shape this whole file exists to prevent.
	if compared == 0 {
		findings = append(findings, fmt.Sprintf(
			"no field of %T was type-compared against the contract; this binding is reporting clean without "+
				"asserting anything", b.goType))
	}
	return findings
}

// TestTheTypeComparisonReportsARealMismatch is the survivor test the axis
// needs, and it drives the COMPARISON rather than the renderer.
//
// TestTheTypeComparisonCanFail below pins goWireType's answers, which proves
// the renderer works and says nothing about whether anything reads it. This
// binds a Go shape that genuinely disagrees with the committed contract to the
// contract's own schema name and asserts the comparison says so - and asserts
// the matching shape does not, so it is not a function that complains about
// everything.
//
// The mismatch planted is the one that survived #3632's review: the contract
// declares authzen_error.request_id a string, and this Go type declares it an
// integer.
func TestTheTypeComparisonReportsARealMismatch(t *testing.T) {
	doc := shippedSurfaceDocument(t)

	type driftedError struct {
		Code      AuthZENErrorCode `json:"code"`
		Pointer   string           `json:"pointer,omitempty"`
		Message   string           `json:"message"`
		Supported []string         `json:"supported,omitempty"`
		RequestID int              `json:"request_id,omitempty"`
	}
	drifted := wireBinding{SchemaAuthZENError, driftedError{}}
	findings := assertGoTypesMatchTheContract(t, drifted, goWireFields(t, drifted.goType), doc)
	if len(findings) == 0 {
		t.Fatal("the comparison reported nothing for a Go type declaring request_id as an integer where the " +
			"contract declares a string. That is the exact drift that stayed green through all nine " +
			"platform/decision packages during the review of #3632, and it is the reason this axis exists.")
	}
	joined := strings.Join(findings, "\n")
	if !strings.Contains(joined, "request_id") || !strings.Contains(joined, "int in Go") {
		t.Errorf("the comparison reported something other than the planted drift:\n%s", joined)
	}

	// The control. The real type, against the same contract, must report
	// NOTHING - or the function above is one that complains about everything and
	// the assertion is meaningless.
	real := wireBinding{SchemaAuthZENError, AuthZENError{}}
	if clean := assertGoTypesMatchTheContract(t, real, goWireFields(t, real.goType), doc); len(clean) != 0 {
		t.Errorf("the comparison reported a disagreement for the committed type:\n%s", strings.Join(clean, "\n"))
	}
}

// shippedSurfaceDocument reads and parses the committed surface artifact, and
// asserts it is CURRENT with respect to the embedded schema.
//
// The currency check is what makes reading the artifact equivalent to reading
// the schema. Without it this file would pin Go against a document that may
// have stopped describing the contract, and would report green while doing it.
// cmd/authzen-codegen's TestCommittedArtifactIsCurrent asserts byte identity in
// its own package; this asserts the half reachable from here - the artifact
// records the digest of the schema it was reduced from, and that digest must be
// the digest of the schema THIS build embeds.
func shippedSurfaceDocument(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(authzenSurfaceArtifact)
	if err != nil {
		// Not a skip: a guard keyed on a file that may be absent, and that skips
		// when it is absent, is invisible exactly where it stopped running.
		t.Fatalf("reading %s: %v", authzenSurfaceArtifact, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", authzenSurfaceArtifact, err)
	}
	schemaDoc, err := SchemaDocument()
	if err != nil {
		t.Fatalf("reading the embedded schema: %v", err)
	}
	digest := sha256.Sum256(schemaDoc)
	recorded, _ := doc["source_schema_sha256"].(string)
	if recorded == "" {
		t.Fatal("the surface artifact records no source_schema_sha256, so nothing here can tell whether it still " +
			"describes the schema this build embeds")
	}
	// Compared against the FULL spelling the codegen writes, prefix included,
	// rather than by stripping the prefix first. Stripping accepts a bare hex
	// digest as well as a prefixed one - two different strings reading as
	// agreement - and it would also accept a "sha512:" prefix over a SHA-256
	// digest. Rebuilding the expected string rejects both.
	if recorded != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatalf("the surface artifact records source_schema_sha256=%q, and this build embeds a schema whose digest is "+
			"%q. Every type comparison would be against a document that has stopped describing the contract. "+
			"Regenerate: (cd platform/decision && go run ./cmd/authzen-codegen -out surface/authzen-surface.json)",
			recorded, "sha256:"+hex.EncodeToString(digest[:]))
	}
	return doc
}

// TestEveryArtifactEnumerationIsOverStrings is the premise collapseEnums rests
// on, asserted rather than assumed.
//
// If an enumeration were ever declared over integers, collapsing it to "string"
// would make the type comparison AGREE with a Go field of the wrong type - the
// exact failure this file exists to catch, introduced by its own normalisation.
func TestEveryArtifactEnumerationIsOverStrings(t *testing.T) {
	doc := shippedSurfaceDocument(t)
	enums, ok := doc["enums"].([]any)
	if !ok || len(enums) == 0 {
		t.Fatal("the surface artifact declares no enumerations, so the premise below is vacuous")
	}
	for _, raw := range enums {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatal("a malformed enumeration entry")
		}
		name, _ := entry["name"].(string)
		values, ok := entry["values"].([]any)
		if !ok || len(values) == 0 {
			t.Errorf("enumeration %q declares no values", name)
			continue
		}
		for _, v := range values {
			if _, isString := v.(string); !isString {
				t.Errorf("enumeration %q carries the non-string value %v; collapsing it to `string` in the type "+
					"comparison would make a Go field of the wrong type compare equal", name, v)
			}
		}
	}
}

// TestTheTypeComparisonCanFail is the anti-vacuity half.
//
// A comparison that renders both sides through the same code can agree because
// both are wrong, or because the rendering is degenerate. This drives goWireType
// over every shape the bindings contain and pins each answer.
func TestTheTypeComparisonCanFail(t *testing.T) {
	bindings := map[reflect.Type]Schema{}
	for _, b := range authzenWireBindings() {
		bindings[reflect.TypeOf(b.goType)] = b.schema
	}
	for _, tc := range []struct {
		name string
		in   any
		want string
	}{
		{"a plain string", struct{ F string }{}, "string"},
		{"a defined string type", struct{ F ReasonCode }{}, "string"},
		{"a bool", struct{ F bool }{}, "bool"},
		{"an int", struct{ F int }{}, "int"},
		{"an int64", struct{ F int64 }{}, "int"},
		{"a time", struct{ F time.Time }{}, "string"},
		{"an any", struct{ F any }{}, "object"},
		// The two map shapes the contract distinguishes, and they must not
		// collapse into each other: an opaque object accepts any value, a typed
		// map accepts one type, and reducing both to "some map" is how a
		// generated SDK comes to accept values the server refuses.
		{"a map of any is the contract's opaque object", struct{ F map[string]any }{}, "object"},
		{"a typed map stays a typed map", struct{ F map[string]string }{}, "map<string>"},
		{"a slice of a bound type", struct{ F []Obligation }{}, "array<ref:obligation>"},
		{"a pointer to a bound type", struct{ F *ApprovalRequirement }{}, "ref:approval_requirement"},
		{"a slice of a bound identifier", struct{ F []ID }{}, "array<ref:identifier>"},
		// AuthZENError.Supported. Present in the bindings and previously absent
		// from this table, which made the header's claim that the table covers
		// "every shape the bindings contain" wider than the table.
		{"a slice of plain strings", struct{ F []string }{}, "array<string>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := goWireType(t, reflect.TypeOf(tc.in).Field(0).Type, bindings)
			if got != tc.want {
				t.Errorf("goWireType rendered %s, want %s", got, tc.want)
			}
		})
	}

	// THE PLANTED DRIFT: the contract says integer, Go says string. This is the
	// literal mutation that stayed green through all nine packages during the
	// R3 on #3632, and it is the reason this axis exists.
	planted := struct {
		RequestID string `json:"request_id"`
	}{}
	if goWireType(t, reflect.TypeOf(planted).Field(0).Type, bindings) == "int" {
		t.Fatal("a Go string rendered as an int, so the comparison could never report the drift it was built for")
	}
	doc := shippedSurfaceDocument(t)
	types, _ := artifactFieldTypesFor(t, doc, string(SchemaAuthZENError))
	if types["request_id"] != "string" {
		t.Fatalf("the contract declares authzen_error.request_id as %q; if that is deliberate, the Go type must move with it", types["request_id"])
	}

	// ...and the collapse is not degenerate: it rewrites the enum and leaves
	// everything around it alone.
	for in, want := range map[string]string{
		"enum:reason_code":              "string",
		"array<enum:operational_state>": "array<string>",
		"map<enum:category>":            "map<string>",
		"ref:obligation":                "ref:obligation",
		"array<ref:obligation>":         "array<ref:obligation>",
		"string":                        "string",
	} {
		if got := collapseEnums(in); got != want {
			t.Errorf("collapseEnums(%q) = %q, want %q", in, got, want)
		}
	}
}
