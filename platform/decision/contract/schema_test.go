package contract

import (
	"encoding/json"
	"testing"
)

// TestSchemaEnumerationsMatchTheGoDeclarations is the contract-guard for the
// declared-but-never-emitted class across the language boundary.
//
// The JSON Schema is what a non-Go plane reads. An enumeration that has drifted
// from the Go constants is a value one side accepts and the other refuses, and
// the drift is invisible from either side alone. Every closed enumeration in the
// schema is compared against the list the Go package declares.
func TestSchemaEnumerationsMatchTheGoDeclarations(t *testing.T) {
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

	enumAt := func(t *testing.T, def string, path ...string) []string {
		t.Helper()
		cur := doc.Defs[def]
		if len(cur) == 0 {
			t.Fatalf("the schema declares no %q", def)
		}
		for _, p := range path {
			var node map[string]json.RawMessage
			if err := json.Unmarshal(cur, &node); err != nil {
				t.Fatalf("walking %s to %q: %v", def, p, err)
			}
			cur = node[p]
			if len(cur) == 0 {
				t.Fatalf("the schema has no %q under %s", p, def)
			}
		}
		var node struct {
			Enum []string `json:"enum"`
		}
		if err := json.Unmarshal(cur, &node); err != nil {
			t.Fatalf("reading the enum at %s/%v: %v", def, path, err)
		}
		if len(node.Enum) == 0 {
			t.Fatalf("no enumeration at %s/%v", def, path)
		}
		return node.Enum
	}

	same := func(t *testing.T, what string, schema, declared []string) {
		t.Helper()
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

	var reasons []string
	for _, r := range AllUnknownReasons() {
		reasons = append(reasons, string(r))
	}
	same(t, "unknown reasons", enumAt(t, "attribute", "properties", "reason"), reasons)

	var provenances []string
	for _, p := range AllProvenances() {
		provenances = append(provenances, string(p))
	}
	same(t, "provenance classes", enumAt(t, "attribute", "properties", "source"), provenances)

	var states []string
	for _, s := range []AttrState{StateKnown, StateAbsent, StateUnknown} {
		states = append(states, string(s))
	}
	same(t, "attribute states", enumAt(t, "attribute", "properties", "state"), states)

	var authorizations []string
	for _, a := range AllAuthorizations() {
		authorizations = append(authorizations, string(a))
	}
	same(t, "authorization outcomes", enumAt(t, "decision", "properties", "authorization"), authorizations)

	var obligationTypes []string
	for _, o := range AllObligationTypes() {
		obligationTypes = append(obligationTypes, string(o))
	}
	same(t, "obligation types", enumAt(t, "obligation", "properties", "type"), obligationTypes)

	var authorities []string
	for _, a := range AllAuthorities() {
		authorities = append(authorities, string(a))
	}
	same(t, "policy authorities", enumAt(t, "unknown_policy", "properties", "authority"), authorities)

	var audiences []string
	for _, a := range AllAudiences() {
		audiences = append(audiences, string(a))
	}
	same(t, "trace audiences", enumAt(t, "trace", "properties", "audience"), audiences)

	var kinds []string
	for _, k := range AllKinds() {
		kinds = append(kinds, string(k))
	}
	same(t, "identifier kinds", enumAt(t, "identifier", "properties", "kind"), kinds)
}
