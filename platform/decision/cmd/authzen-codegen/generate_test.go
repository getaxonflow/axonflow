// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"axonflow/platform/decision/contract"
)

// committedArtifact is the path this command's output is committed at. Every
// SDK vendors a copy of that file and generates its wire types from it.
const committedArtifact = "../../surface/authzen-surface.json"

func generate(t *testing.T) []byte {
	t.Helper()
	raw, err := contract.SchemaDocument()
	if err != nil {
		t.Fatalf("reading the canonical schema: %v", err)
	}
	s, err := reduce(raw)
	if err != nil {
		t.Fatalf("reducing: %v", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		t.Fatalf("encoding: %v", err)
	}
	return buf.Bytes()
}

// TestCommittedArtifactIsCurrent is the regeneration-is-clean gate.
//
// The artifact is committed rather than built on demand because four other
// repositories vendor it, and a vendored file has to exist to be vendored. A
// committed generated file is only trustworthy if something proves it is the
// output of the current input, which is what this asserts: edit the schema
// without regenerating and this fails in the same CI run.
func TestCommittedArtifactIsCurrent(t *testing.T) {
	want := generate(t)
	have, err := os.ReadFile(committedArtifact)
	if err != nil {
		t.Fatalf("reading the committed artifact: %v", err)
	}
	if !bytes.Equal(have, want) {
		t.Errorf("%s is not what the current schema generates.\n"+
			"Regenerate it in the same change:\n"+
			"  (cd platform/decision && go run ./cmd/authzen-codegen -out surface/authzen-surface.json)",
			filepath.Clean(committedArtifact))
	}
}

// TestGenerationIsDeterministic is the reason the committed-artifact check
// above is worth anything.
//
// Go randomises map iteration per run, and both the type set and each type's
// property set arrive as maps. A generator that leaked either order would
// produce a different byte sequence on most runs, and the check above would
// then fail on unrelated pull requests until somebody "fixed" it by deleting
// it. Sixteen reductions in one process is enough to make a leaked map order
// overwhelmingly likely to show up: the odds of twelve types landing in the
// same arbitrary order sixteen times running are negligible.
func TestGenerationIsDeterministic(t *testing.T) {
	first := generate(t)
	for i := 0; i < 16; i++ {
		if got := generate(t); !bytes.Equal(got, first) {
			t.Fatalf("reduction %d differs from the first; the generator is leaking a map order", i+1)
		}
	}
}

// TestArtifactCoversTheWholeSurface is the anti-vacuity guard.
//
// Every check in this file compares the artifact against itself or against a
// second run, so all of them stay green over an artifact that reduced to
// nothing at all. This one asserts the artifact actually describes the surface:
// every AuthZEN shape the contract declares is present, every type has fields,
// and every reference resolves to a type in the same document. Without it, a
// reducer that silently stopped following $refs would pass the other two.
func TestArtifactCoversTheWholeSurface(t *testing.T) {
	var s Surface
	raw, err := os.ReadFile(committedArtifact)
	if err != nil {
		t.Fatalf("reading the committed artifact: %v", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parsing the committed artifact: %v", err)
	}

	if s.Artifact != ArtifactName || s.ArtifactVersion != ArtifactVersion {
		t.Errorf("artifact identity is %q v%d, expected %q v%d",
			s.Artifact, s.ArtifactVersion, ArtifactName, ArtifactVersion)
	}
	if s.Profile != string(contract.AuthZENProfileV1) {
		t.Errorf("the artifact records profile %q, the package emits %q", s.Profile, contract.AuthZENProfileV1)
	}
	if s.ContractSchemaVersion != contract.SchemaVersion {
		t.Errorf("the artifact records contract version %q, the package declares %q",
			s.ContractSchemaVersion, contract.SchemaVersion)
	}

	byName := map[string]Type{}
	for _, tp := range s.Types {
		if len(tp.Fields) == 0 {
			t.Errorf("type %q has no fields", tp.Name)
		}
		byName[tp.Name] = tp
	}
	enums := map[string]bool{}
	for _, e := range s.Enums {
		if len(e.Values) == 0 {
			t.Errorf("enum %q has no values", e.Name)
		}
		enums[e.Name] = true
	}

	// Every AuthZEN shape the contract declares must have been reached. This is
	// the check that fails if a $ref stops being followed or a definition is
	// added to the contract and never reaches the SDKs.
	for _, sc := range contract.AllSchemas() {
		name := string(sc)
		if len(name) < 7 || name[:7] != "authzen" {
			continue
		}
		if _, ok := byName[name]; !ok {
			t.Errorf("the contract declares %q, which the artifact does not describe; "+
				"no SDK would generate it", name)
		}
	}

	// Every reference resolves inside this document. A dangling ref is a type an
	// emitter cannot generate, and it would surface as a compile error in four
	// SDKs rather than here.
	var checkRef func(where string, tr TypeRef)
	checkRef = func(where string, tr TypeRef) {
		switch tr.Kind {
		case "ref":
			if _, ok := byName[tr.Ref]; !ok {
				t.Errorf("%s references type %q, which the artifact does not define", where, tr.Ref)
			}
		case "enum":
			if !enums[tr.Enum] {
				t.Errorf("%s references enum %q, which the artifact does not define", where, tr.Enum)
			}
		case "array":
			if tr.Items == nil {
				t.Errorf("%s is an array with no item type", where)
				return
			}
			checkRef(where+"[]", *tr.Items)
		case "map":
			if tr.Value == nil {
				t.Errorf("%s is a map with no value type", where)
				return
			}
			checkRef(where+"{}", *tr.Value)
		case "string", "bool", "int", "object":
		default:
			t.Errorf("%s has unrecognised kind %q", where, tr.Kind)
		}
	}
	for _, tp := range s.Types {
		for _, f := range tp.Fields {
			checkRef(tp.Name+"."+f.Name, f.Type)
		}
	}

	// The two constructs no per-field flag can carry. If either is lost, an
	// emitter generates a type that accepts a malformed request: an envelope
	// with both members, or a singular evaluation with no action.
	env, ok := byName["authzen_envelope"]
	if !ok {
		t.Fatal("the artifact does not describe the envelope")
	}
	if len(env.ExactlyOneOf) != 1 || len(env.ExactlyOneOf[0]) != 2 {
		t.Errorf("the envelope's exactly-one-of rule did not survive the reduction: %v", env.ExactlyOneOf)
	}
	var singular *Field
	for i := range env.Fields {
		if env.Fields[i].Name == "evaluation" {
			singular = &env.Fields[i]
		}
	}
	if singular == nil {
		t.Fatal("the envelope has no evaluation member")
	}
	if len(singular.RequiresMembers) != 3 {
		t.Errorf("the singular member's own required set did not survive: %v", singular.RequiresMembers)
	}

	// obligation.params is the typed map. It is asserted by name because
	// widening it to an opaque object is a silent change that nothing else here
	// would notice, and it is exactly the shape a careless reducer flattens.
	ob, ok := byName["obligation"]
	if !ok {
		t.Fatal("the artifact does not describe an obligation")
	}
	for _, f := range ob.Fields {
		if f.Name != "params" {
			continue
		}
		if f.Type.Kind != "map" || f.Type.Value == nil || f.Type.Value.Kind != "string" {
			t.Errorf("obligation.params reduced to %+v, expected a map with string values", f.Type)
		}
	}
}

// TestFieldOrderFollowsTheSchema pins the property-order walk.
//
// Declaration order is not a correctness property of the wire format, but it is
// a correctness property of THIS generator: it is the difference between a
// stable artifact and one that reshuffles on every run. Asserting a known
// type's order is what catches the walk being replaced by a map range.
func TestFieldOrderFollowsTheSchema(t *testing.T) {
	var s Surface
	raw, err := os.ReadFile(committedArtifact)
	if err != nil {
		t.Fatalf("reading the committed artifact: %v", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	want := []string{"profile", "state", "category", "reason", "obligations", "approval", "decision_id", "schema_version"}
	for _, tp := range s.Types {
		if tp.Name != "authzen_response_context" {
			continue
		}
		if len(tp.Fields) != len(want) {
			t.Fatalf("expected %d fields, got %d", len(want), len(tp.Fields))
		}
		for i, f := range tp.Fields {
			if f.Name != want[i] {
				t.Errorf("field %d is %q, the schema declares %q", i, f.Name, want[i])
			}
		}
		return
	}
	t.Fatal("the artifact does not describe the response context")
}

// TestReducerRefusesWhatItCannotExpress pins the fail-loud rule.
//
// The whole value of this reducer is that an SDK generated from its output
// describes the same shapes the server does. A construct it silently skipped
// would become a field four SDKs never learn about - the declared-but-never-
// emitted class, arriving through the tool built to prevent it. So the
// unsupported cases must be errors, and that has to be asserted, because
// "returns an error" is exactly the branch nobody exercises.
func TestReducerRefusesWhatItCannotExpress(t *testing.T) {
	// Fixtures are built from surfaceRoots rather than listing the root names,
	// so adding a root cannot silently turn every case below into "the reducer
	// refused the scaffolding" - which is how a negative suite starts passing
	// for the wrong reason.
	fixture := func(subject string) string {
		defs := map[string]json.RawMessage{}
		for i, root := range surfaceRoots {
			if i == 0 {
				defs[root] = json.RawMessage(subject)
				continue
			}
			defs[root] = json.RawMessage(`{"type":"object","properties":{"filler":{"type":"string"}},"additionalProperties":false}`)
		}
		out, err := json.Marshal(map[string]any{"$defs": defs})
		if err != nil {
			t.Fatalf("building the fixture: %v", err)
		}
		return string(out)
	}

	for _, tc := range []struct {
		name    string
		subject string
	}{
		{"a union type", `{"type":"object","properties":{"x":{"type":["string","null"]}},"additionalProperties":false}`},
		{"an unsupported scalar", `{"type":"object","properties":{"x":{"type":"number"}},"additionalProperties":false}`},
		{"a construct with no type at all", `{"type":"object","properties":{"x":{"description":"nothing"}},"additionalProperties":false}`},
		{"an array with no items", `{"type":"object","properties":{"x":{"type":"array"}},"additionalProperties":false}`},
		{"a dangling reference", `{"type":"object","properties":{"x":{"$ref":"#/$defs/nope"}},"additionalProperties":false}`},
		{"a definition with no properties", `{"type":"object","additionalProperties":false}`},
		{"a oneOf it does not understand", `{"type":"object","properties":{"x":{"type":"string"}},"additionalProperties":false,"oneOf":[{"minProperties":1},{"maxProperties":2}]}`},
		{"an external reference", `{"type":"object","properties":{"x":{"$ref":"https://example.test/other.json"}},"additionalProperties":false}`},
		{"an object closed against everything", `{"type":"object","properties":{"x":{"type":"object","additionalProperties":false}},"additionalProperties":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := reduce([]byte(fixture(tc.subject))); err == nil {
				t.Errorf("the reducer accepted %s; it would have been dropped from every SDK", tc.name)
			}
		})
	}

	// The control: the same scaffolding with only supported constructs must
	// reduce cleanly. Without it every case above could be passing because
	// reduce refuses the fixture scaffolding rather than the construct named.
	ok := fixture(`{"type":"object","properties":{"x":{"type":"string"}},"additionalProperties":false}`)
	if _, err := reduce([]byte(ok)); err != nil {
		t.Errorf("the reducer refused a supported fixture: %v", err)
	}
}

// TestArtifactRequiredFlagsMatchTheSchema closes the one link in the chain that
// nothing checked.
//
// The chain is: Go structs <-> JSON Schema (bound in both directions by
// authzen_schema_drift_test.go) -> this artifact -> five SDKs' generated types
// (each repository regenerates and diffs). The middle arrow was unguarded: the
// artifact is a third copy of every field's optionality, and mutating
// `Required: required[prop]` to `false` in the reducer regenerates cleanly,
// propagates to the SDK, regenerates its types cleanly, and leaves every gate in
// both repositories green with 26 required fields silently turned optional.
//
// What that costs concretely: `authzen_response.decision` gains omitempty, so a
// Go enforcement point marshalling a DENIAL emits `{}` -- a denial that looks
// like an empty document. `authzen_error.code` does the same, which is the
// "client cannot branch on a code" failure that type's own doc argues against.
//
// The comparison is against the SCHEMA, read fresh, not against the reducer's
// own output, so it cannot agree with the bug by construction.
func TestArtifactRequiredFlagsMatchTheSchema(t *testing.T) {
	rawSchema, err := contract.SchemaDocument()
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(rawSchema, &doc); err != nil {
		t.Fatalf("parsing the schema: %v", err)
	}

	var s Surface
	raw, err := os.ReadFile(committedArtifact)
	if err != nil {
		t.Fatalf("reading the committed artifact: %v", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parsing the committed artifact: %v", err)
	}
	if len(s.Types) == 0 {
		t.Fatal("the artifact describes no types; the comparison would be vacuous")
	}

	compared := 0
	requiredSeen := 0
	for _, tp := range s.Types {
		rawDef, ok := doc.Defs[tp.Name]
		if !ok {
			t.Errorf("the artifact describes %q, which the schema does not define", tp.Name)
			continue
		}
		var def struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(rawDef, &def); err != nil {
			t.Fatalf("parsing definition %q: %v", tp.Name, err)
		}
		want := map[string]bool{}
		for _, r := range def.Required {
			want[r] = true
		}
		for _, f := range tp.Fields {
			compared++
			if f.Required {
				requiredSeen++
			}
			if f.Required != want[f.Name] {
				t.Errorf("%s.%s: artifact says required=%v, the schema says required=%v",
					tp.Name, f.Name, f.Required, want[f.Name])
			}
		}
	}

	// Anti-vacuity, in both directions: the comparison must have run over real
	// fields, and the surface must actually contain required ones -- otherwise
	// "all flags match" would be true of an artifact that marked nothing
	// required, which is exactly the mutation this test exists to catch.
	if compared == 0 {
		t.Fatal("no fields were compared")
	}
	if requiredSeen == 0 {
		t.Fatal("the artifact marks NO field required; the comparison cannot detect a required->optional flip")
	}
	t.Logf("compared %d fields, %d of them required", compared, requiredSeen)
}

// TestArtifactPublishesTheRouteAndHeader pins #3603's follow-up: the route and
// the profile header are in the artifact, equal to the contract constants the
// agent serves, so an SDK generates them instead of transcribing them.
func TestArtifactPublishesTheRouteAndHeader(t *testing.T) {
	var s Surface
	raw, err := os.ReadFile(committedArtifact)
	if err != nil {
		t.Fatalf("reading the committed artifact: %v", err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if s.Route.Method != contract.AuthZENRouteMethod || s.Route.Path != contract.AuthZENRoutePath {
		t.Errorf("artifact route = %s %s, want %s %s", s.Route.Method, s.Route.Path, contract.AuthZENRouteMethod, contract.AuthZENRoutePath)
	}
	if s.ProfileHeader != contract.AuthZENProfileHeader {
		t.Errorf("artifact profile_header = %q, want %q", s.ProfileHeader, contract.AuthZENProfileHeader)
	}
	if s.Route.Path == "" || s.ProfileHeader == "" {
		t.Fatal("an empty route or header would generate an SDK that calls nothing")
	}
}
