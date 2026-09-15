// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"sort"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

func TestSchemaCompiles(t *testing.T) {
	if _, err := documentSchema(); err != nil {
		t.Fatal(err)
	}
}

// TestEveryEnumMatchesTheGoDeclarations is what makes the schema a projection
// of the vocabulary instead of a second copy of it.
//
// A schema enum typed out by hand drifts the first time a value is added in Go,
// and it drifts in the permissive direction: the schema keeps accepting what it
// always accepted and quietly stops describing what the compiler understands,
// so a portal built against it refuses a policy the platform would compile.
// Each case below reads the enum out of the committed schema and compares it,
// as a set, against the declaration the compiler itself walks.
func TestEveryEnumMatchesTheGoDeclarations(t *testing.T) {
	cases := []struct {
		def  string
		want []string
	}{
		{"authority", stringsOf(contract.AllAuthorities())},
		{"assurance_class", stringsOf(pdp.AllAssuranceClasses())},
		{"root", stringsOf(pdp.AllRoots())},
		{"value_type", stringsOf(pdp.AllValueTypes())},
		{"condition_kind", stringsOf(pdp.AllCondKinds())},
		{"compare_op", stringsOf(pdp.AllCompareOps())},
		{"absence_handling", stringsOf(pdp.AllAbsenceHandlings())},
		{"obligation_type", stringsOf(contract.AllObligationTypes())},
		{"identifier_kind", stringsOf(contract.AllKinds())},
		// The principal vocabulary is closed (#3711) and the authoring schema
		// is enforced at the wire by NewDocument and by Parse for stored
		// artifacts, so the closure has to be here too or a policy scoped to a
		// seventh principal type is accepted by the surface that saves it.
		{"principal_type", stringsOf(contract.PrincipalTypes())},
		// The actions an organization may assign to a shipped control (PRD v11
		// §1.5): the one list the validator, the activation fold and this
		// schema all read.
		{"system_control_action", stringsOf(legacycompile.OverrideActions())},
	}
	if len(cases) == 0 {
		t.Fatal("no enums are checked, so this gate asserts nothing")
	}
	for _, tc := range cases {
		t.Run(tc.def, func(t *testing.T) {
			got, err := schemaEnum(tc.def)
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.want) == 0 {
				t.Fatalf("the Go declaration for %s is empty, so this comparison would pass against an empty schema enum", tc.def)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("$defs/%s declares %d values and Go declares %d\nschema: %v\ngo:     %v", tc.def, len(got), len(want), got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("$defs/%s differs from the Go declaration\nschema: %v\ngo:     %v", tc.def, got, want)
				}
			}
		})
	}
}

func stringsOf[T ~string](in []T) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, string(v))
	}
	return out
}

// TestGeneratedDocumentsSatisfyTheSchema runs the schema over the same corpus
// the round-trip property draws from, so the schema is exercised against the
// whole vocabulary rather than against one hand-written example.
func TestGeneratedDocumentsSatisfyTheSchema(t *testing.T) {
	cat := baseCatalog(t)
	g := &generator{rng: rand.New(rand.NewSource(20260830))}
	const draws = 400
	for i := 0; i < draws; i++ {
		d := g.document(t, cat, i)
		if err := ValidateAgainstSchema(d); err != nil {
			raw, _ := Render(d)
			t.Fatalf("draw %d does not satisfy the published schema: %v\n%s", i, err, raw)
		}
	}
	t.Logf("schema satisfied by %d generated documents, the same corpus the round-trip property draws", draws)
}

// TestTheSchemaRejectsWhatItShould is the falsification. A schema that accepts
// everything would pass the test above, and every case here is a shape the
// authoring API must refuse at the wire boundary rather than deeper in.
func TestTheSchemaRejectsWhatItShould(t *testing.T) {
	base := baseDocument(t)
	raw, err := Render(base)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		// system_controls (PRD v11 §1.5): each entry names a corpus control and
		// carries exactly one instruction.
		{"a system control entry that says enabled true", func(m map[string]any) {
			m["system_controls"] = []any{map[string]any{"control": sysStaticControl, "enabled": true}}
		}},
		{"a system control entry carrying both enabled and action", func(m map[string]any) {
			m["system_controls"] = []any{map[string]any{"control": sysStaticControl, "enabled": false, "action": "block"}}
		}},
		{"a system control entry carrying neither enabled nor action", func(m map[string]any) {
			m["system_controls"] = []any{map[string]any{"control": sysStaticControl}}
		}},
		{"a system control action nobody can assign", func(m map[string]any) {
			m["system_controls"] = []any{map[string]any{"control": sysStaticControl, "action": "allow"}}
		}},
		{"a system control entry with an undeclared member", func(m map[string]any) {
			m["system_controls"] = []any{map[string]any{"control": sysStaticControl, "enabled": false, "reason": "quiet"}}
		}},
		{"a system control named by something other than a corpus identifier", func(m map[string]any) {
			m["system_controls"] = []any{map[string]any{"control": "sys_admin_audit_log", "enabled": false}}
		}},
		{"a system_controls section that is not a list", func(m map[string]any) {
			m["system_controls"] = map[string]any{"control": sysStaticControl, "enabled": false}
		}},
		{"an undeclared authority", func(m map[string]any) {
			policies(m)[0].(map[string]any)["authority"] = "advisory"
		}},
		{"an undeclared authority root", func(m map[string]any) {
			m["policy"].(map[string]any)["root"] = "tenant"
		}},
		{"an undeclared condition kind", func(m map[string]any) {
			policies(m)[0].(map[string]any)["where"] = map[string]any{"kind": "sometimes"}
		}},
		{"an undeclared comparison operator", func(m map[string]any) {
			policies(m)[0].(map[string]any)["where"] = map[string]any{
				"kind": "compare", "path": "args.amount_cents", "op": "approximately", "literal": 1,
			}
		}},
		{"a compare with no operator", func(m map[string]any) {
			policies(m)[0].(map[string]any)["where"] = map[string]any{"kind": "compare", "path": "args.amount_cents"}
		}},
		{"a conjunction with one operand", func(m map[string]any) {
			policies(m)[0].(map[string]any)["where"] = map[string]any{
				"kind": "and", "operands": []any{map[string]any{"kind": "true"}},
			}
		}},
		{"a negation with two operands", func(m map[string]any) {
			policies(m)[0].(map[string]any)["where"] = map[string]any{
				"kind": "not", "operands": []any{map[string]any{"kind": "true"}, map[string]any{"kind": "true"}},
			}
		}},
		{"the unspecified absence handling offered as a value", func(m map[string]any) {
			policies(m)[0].(map[string]any)["where"] = map[string]any{
				"kind": "compare", "path": "args.note", "op": "eq", "literal": "x", "on_absent": "",
			}
		}},
		{"an undeclared obligation type", func(m map[string]any) {
			for _, p := range policies(m) {
				pm := p.(map[string]any)
				if _, ok := pm["obligations"]; !ok {
					continue
				}
				pm["obligations"].([]any)[0].(map[string]any)["type"] = "field_shred"
				return
			}
			t.Fatal("no policy in the baseline carries an obligation, so this case is vacuous")
		}},
		{"an obligation with no schema version", func(m map[string]any) {
			for _, p := range policies(m) {
				pm := p.(map[string]any)
				if _, ok := pm["obligations"]; !ok {
					continue
				}
				delete(pm["obligations"].([]any)[0].(map[string]any), "schema_version")
				return
			}
			t.Fatal("no policy in the baseline carries an obligation, so this case is vacuous")
		}},
		{"a document version of zero", func(m map[string]any) {
			m["policy"].(map[string]any)["version"] = 0
		}},
		{"a supersedes that is not a digest", func(m map[string]any) {
			m["metadata"].(map[string]any)["supersedes"] = "version-4"
		}},
		{"an author who is not a principal", func(m map[string]any) {
			m["metadata"].(map[string]any)["author"].(map[string]any)["kind"] = "group"
		}},
		{"an undeclared envelope version", func(m map[string]any) {
			m["api_version"] = "authoring.axonflow.com/v2"
		}},
		{"an undeclared top-level field", func(m map[string]any) {
			m["enforcement_mode"] = "report_only"
		}},
		{"an undeclared policy field", func(m map[string]any) {
			policies(m)[0].(map[string]any)["verdict"] = "permit"
		}},
		{"a document with no policies", func(m map[string]any) {
			m["policy"].(map[string]any)["policies"] = []any{}
		}},
	}

	sch, err := documentSchema()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tree map[string]any
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&tree); err != nil {
				t.Fatal(err)
			}
			// The unedited tree must pass, or the case below would "reject" a
			// document the schema was never going to accept.
			if err := sch.Validate(deepCopy(t, tree)); err != nil {
				t.Fatalf("the baseline does not satisfy the schema, so every rejection here is for the wrong reason: %v", err)
			}
			tc.edit(tree)
			if err := sch.Validate(tree); err == nil {
				t.Fatalf("the schema accepted %s", tc.name)
			}
		})
	}
}

func policies(m map[string]any) []any {
	return m["policy"].(map[string]any)["policies"].([]any)
}

func deepCopy(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTheCompiledSchemaRefusesAPrincipalTypeOutsideTheVocabulary exercises the
// COMPILED schema, not the enum's presence at a path (#3711).
//
// The enum-parity test above reads `$defs/principal_type/enum` and compares it
// to the Go declaration. That is necessary and not sufficient: the enum is
// applied through an `if`/`then` on `$defs/identifier`, and JSON Schema 2020-12
// IGNORES a `then` with no `if`. So deleting one line leaves the enum present,
// correct, and completely inert - the parity test still passes and every
// principal type is accepted again. R3 round 2 found exactly that, by deleting
// the `if` and watching the whole package stay green.
//
// This test asks the compiled schema to judge a real document instead, which is
// what NewDocument and Parse do, so an inert constraint fails here. The
// document comes from the same generator the corpus test uses, so it is valid
// for every reason other than the one under test - a hand-written probe that
// the schema refused for a MISSING FIELD would have "passed" this test while
// proving nothing.
func TestTheCompiledSchemaRefusesAPrincipalTypeOutsideTheVocabulary(t *testing.T) {
	cat := baseCatalog(t)
	g := &generator{rng: rand.New(rand.NewSource(20260908))}
	base := g.document(t, cat, 0)
	if err := ValidateAgainstSchema(base); err != nil {
		t.Fatalf("the generated document does not satisfy the schema before any edit: %v", err)
	}
	raw, err := Render(base)
	if err != nil {
		t.Fatal(err)
	}
	sch, err := documentSchema()
	if err != nil {
		t.Fatalf("compiling the authoring schema: %v", err)
	}

	// EVERY POSITION THE SCHEMA $refs THE IDENTIFIER FROM, probed by NAME.
	//
	// The first version of this test rewrote whatever principal identifiers the
	// generated document happened to contain, and at this seed that is exactly
	// one: /metadata/author. scope.principals is a one-in-three draw and came
	// up empty, so its n == 0 anti-vacuity guard could not fire and the doc
	// comment claiming "EVERY principal identifier" was not true of it. R3
	// round 3 moved the constraint from $defs/identifier onto metadata.author
	// alone and all eleven packages of platform/decision stayed green, with the
	// compiled schema still accepting Robot in scope.principals.
	//
	// So the positions are enumerated here rather than sampled. A position
	// added to the schema and not added here is not covered, and that is a
	// visible omission in a list rather than an invisible property of a seed.
	positions := []struct {
		name string
		// place installs one identifier at this position, replacing whatever
		// is there, and reports whether it could.
		place func(doc map[string]any, id map[string]any) bool
	}{
		{"/metadata/author", func(doc map[string]any, id map[string]any) bool {
			md, ok := doc["metadata"].(map[string]any)
			if !ok {
				return false
			}
			md["author"] = id
			return true
		}},
		{"/policy/policies/0/scope/principals", func(doc map[string]any, id map[string]any) bool {
			return placeInFirstPolicy(doc, id, "scope", "principals")
		}},
		{"/policy/policies/0/scope/groups", func(doc map[string]any, id map[string]any) bool {
			return placeInFirstPolicy(doc, id, "scope", "groups")
		}},
		{"/policy/policies/0/actions/actions", func(doc map[string]any, id map[string]any) bool {
			return placeInFirstPolicy(doc, id, "actions", "actions")
		}},
		{"/policy/policies/0/pierceable_by", func(doc map[string]any, id map[string]any) bool {
			pol, ok := firstPolicy(doc)
			if !ok {
				return false
			}
			pol["pierceable_by"] = []any{id}
			return true
		}},
	}

	principal := func(typ string) map[string]any {
		return map[string]any{"kind": "principal", "type": typ, "qualifier": "acme", "local": "probe"}
	}
	load := func() map[string]any {
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	for _, pos := range positions {
		t.Run(pos.name, func(t *testing.T) {
			// The position must ACCEPT a member of the vocabulary. Without
			// this every refusal below could be a refusal for some other
			// reason, and a position that rejected all principals outright
			// would look like perfect enforcement.
			for _, member := range contract.PrincipalTypes() {
				doc := load()
				if !pos.place(doc, principal(string(member))) {
					t.Fatalf("could not place an identifier at %s in the generated document; this position is not being probed at all", pos.name)
				}
				if err := sch.Validate(doc); err != nil {
					t.Fatalf("the compiled schema refuses %q at %s, so a refusal at this position says nothing about the type: %v", member, pos.name, err)
				}
			}
			for _, outside := range []string{"Robot", "Machine.v2", "user", "Users"} {
				doc := load()
				if !pos.place(doc, principal(outside)) {
					t.Fatalf("could not place an identifier at %s", pos.name)
				}
				if err := sch.Validate(doc); err == nil {
					t.Errorf("the compiled schema ACCEPTS %q at %s; the $defs/identifier if/then is missing or inert at this position, and an authoring document naming a seventh principal type would be saved", outside, pos.name)
				}
			}
		})
	}
}

func firstPolicy(doc map[string]any) (map[string]any, bool) {
	body, ok := doc["policy"].(map[string]any)
	if !ok {
		return nil, false
	}
	policies, ok := body["policies"].([]any)
	if !ok || len(policies) == 0 {
		return nil, false
	}
	pol, ok := policies[0].(map[string]any)
	return pol, ok
}

// placeInFirstPolicy installs id as the sole member of doc.policies[0][outer][inner].
func placeInFirstPolicy(doc map[string]any, id map[string]any, outer, inner string) bool {
	pol, ok := firstPolicy(doc)
	if !ok {
		return false
	}
	sub, ok := pol[outer].(map[string]any)
	if !ok {
		sub = map[string]any{}
		pol[outer] = sub
	}
	sub[inner] = []any{id}
	return true
}
