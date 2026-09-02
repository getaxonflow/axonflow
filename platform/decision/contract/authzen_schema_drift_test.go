package contract

import (
	"encoding/json"
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
