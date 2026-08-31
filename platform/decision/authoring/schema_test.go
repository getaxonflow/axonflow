package authoring

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"sort"
	"testing"

	"axonflow/platform/decision/contract"
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
		{"root", stringsOf(pdp.AllRoots())},
		{"value_type", stringsOf(pdp.AllValueTypes())},
		{"condition_kind", stringsOf(pdp.AllCondKinds())},
		{"compare_op", stringsOf(pdp.AllCompareOps())},
		{"absence_handling", stringsOf(pdp.AllAbsenceHandlings())},
		{"obligation_type", stringsOf(contract.AllObligationTypes())},
		{"identifier_kind", stringsOf(contract.AllKinds())},
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
