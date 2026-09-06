package authoring

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The authoring-plane form of the class #3630 closes in the decision contract.
//
// ValidateAgainstSchema validates a RE-RENDERED document: the bytes go through
// Parse into a Go value and back out, so a member the author OMITTED is
// re-materialised at its Go zero value and satisfies the schema's `required` on
// the way past. Every `required` declaration in the published schema was
// therefore unenforced at the wire for any member whose zero value serialises -
// which is every scalar declared without omitempty.
//
// Parse now validates the RAW bytes as well. The two answer different questions
// and both are wanted: the raw one says the author supplied what the schema
// requires, the rendered one says this build can round-trip it without loss.

// TestParseRefusesADocumentThatOmitsARequiredMember drives the top-level
// required set from the schema itself, so a member added to it is covered
// without anyone remembering to add it here.
func TestParseRefusesADocumentThatOmitsARequiredMember(t *testing.T) {
	base := baseDocument(t)
	complete, err := Render(base)
	if err != nil {
		t.Fatalf("rendering the fixture: %v", err)
	}
	if _, err := Parse(complete); err != nil {
		t.Fatalf("the complete fixture was refused, so nothing below discriminates: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(complete, &doc); err != nil {
		t.Fatalf("re-reading the fixture: %v", err)
	}

	required := topLevelRequiredMembers(t)
	if len(required) == 0 {
		t.Fatal("the schema declares no required top-level member, so every case below is vacuous")
	}

	checked := 0
	for _, member := range required {
		if _, present := doc[member]; !present {
			// The fixture does not carry it, so removing it changes nothing.
			// Reported rather than skipped: a fixture that stopped carrying a
			// required member would silently shrink this test.
			t.Errorf("the fixture does not carry the required member %q, so its omission cannot be tested", member)
			continue
		}
		reduced := map[string]json.RawMessage{}
		for k, v := range doc {
			if k != member {
				reduced[k] = v
			}
		}
		raw, err := json.Marshal(reduced)
		if err != nil {
			t.Fatalf("re-encoding without %q: %v", member, err)
		}
		checked++
		t.Run(member, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Errorf("a document omitting the required member %q was ACCEPTED. The schema declares it required, "+
					"and validating the re-rendered document cannot see the omission: the member comes back at its "+
					"Go zero value and satisfies `required`. An author's document would be stored carrying a value "+
					"they never wrote.", member)
			}
		})
	}
	if checked == 0 {
		t.Fatal("no required member was actually removed from the fixture; this test asserted nothing")
	}
}

// topLevelRequiredMembers reads the document schema's own required list.
func topLevelRequiredMembers(t *testing.T) []string {
	t.Helper()
	raw, err := SchemaDocument()
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	var doc struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing the schema: %v", err)
	}
	out := append([]string(nil), doc.Required...)
	sort.Strings(out)
	return out
}

// TestTheRawValidatorSeesWhatTheRenderedOneCannot is the direct comparison, and
// it is what makes the change more than a second call to the same check.
//
// THE CASE IT DRIVES IS A NESTED OBLIGATION'S `mandatory`, which is both the
// member #3630 is about and the only one that discriminates. The schema
// declares it required on `$defs/obligation`, its Go zero value is `false`
// which serialises - so the RE-RENDERED document carries `"mandatory": false`
// and satisfies `required`, while the author never wrote it. That is the
// authoring-plane form of the decision-contract defect, on the same member, one
// plane over.
//
// Both halves are asserted, and the first is the one that matters: the rendered
// validator must ACCEPT the document. If the two validators ever agree, the raw
// call added beside the rendered one has stopped being load-bearing and this
// test says so rather than passing quietly. That is also what kills the mutant
// that deletes the call from Parse.
//
// A CORRECTION WORTH RECORDING, because I got this wrong first and filed an
// issue on it. An earlier version removed "the first `mandatory` anywhere in
// the document", walking depth-first over sorted keys. The base fixture carries
// three: `/policy/policies/2/mandatory` - a POLICY-level member, optional in
// `$defs/policy` - comes first, so the removal hit a member nothing requires,
// both validators accepted, and I concluded the schema's `$defs/obligation`
// required set did not bind through its `$ref`. It binds. The census was
// bounded by the shape I searched for, not by the class I meant.
func TestTheRawValidatorSeesWhatTheRenderedOneCannot(t *testing.T) {
	base := baseDocument(t)
	complete, err := Render(base)
	if err != nil {
		t.Fatalf("rendering the fixture: %v", err)
	}

	var tree map[string]any
	dec := json.NewDecoder(strings.NewReader(string(complete)))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		t.Fatalf("re-reading the fixture: %v", err)
	}
	where, ok := dropAnObligationsMandatory(tree)
	if !ok {
		t.Fatal("the authoring fixture carries no policy with an obligation declaring `mandatory`, so the member " +
			"that discriminates between the two validators is not present. That is a fixture gap, not a passing " +
			"condition")
	}
	reduced, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("re-encoding the reduced document: %v", err)
	}

	// THE GAP, reproduced rather than described: the rendered path accepts it,
	// because the omitted member comes back at its Go zero value.
	var decoded Document
	dec2 := json.NewDecoder(strings.NewReader(string(reduced)))
	dec2.UseNumber()
	if err := dec2.Decode(&decoded); err != nil {
		t.Fatalf("decoding the reduced document: %v", err)
	}
	if err := ValidateAgainstSchema(&decoded); err != nil {
		t.Fatalf("the RENDERED validator refused a document omitting %s (%v). If that is now the behaviour, the raw "+
			"check beside it is redundant and this test should be rewritten rather than left passing for a reason it "+
			"does not state.", where, err)
	}

	// THE FIX: the raw path refuses it, and names where.
	rawErr := ValidateRawAgainstSchema(reduced)
	if rawErr == nil {
		t.Fatalf("the raw validator accepted a document omitting %s. The author did not write that obligation as "+
			"advisory; the re-render did.", where)
	}
	if !strings.Contains(rawErr.Error(), where) {
		t.Errorf("the refusal does not name the offending member (%s): %v", where, rawErr)
	}

	// ...and Parse, which is what every caller reaches, refuses it too. This is
	// the assertion the AUTHORING_RAW_SCHEMA mutant kills.
	if _, err := Parse(reduced); err == nil {
		t.Fatalf("Parse accepted a document omitting %s; the raw validation is not wired into the boundary every "+
			"caller goes through", where)
	}

	// The control: the untouched document still parses, so the refusals are
	// attributable to the removal rather than to the fixture.
	if _, err := Parse(complete); err != nil {
		t.Fatalf("the complete fixture was refused: %v", err)
	}
}

// dropAnObligationsMandatory removes the `mandatory` member of the first
// OBLIGATION that declares one, and returns the JSON Pointer it removed.
//
// It addresses the obligation explicitly rather than searching for a member
// name. `mandatory` is declared at TWO levels of this document - on a policy,
// where it is optional, and on an obligation, where it is required - so a
// name search finds the wrong one and proves the opposite of what it looks
// like it proves.
func dropAnObligationsMandatory(tree map[string]any) (string, bool) {
	policy, _ := tree["policy"].(map[string]any)
	policies, _ := policy["policies"].([]any)
	for i, rawPolicy := range policies {
		p, _ := rawPolicy.(map[string]any)
		obligations, _ := p["obligations"].([]any)
		for j, rawObligation := range obligations {
			o, _ := rawObligation.(map[string]any)
			if _, has := o["mandatory"]; !has {
				continue
			}
			delete(o, "mandatory")
			return fmt.Sprintf("/policy/policies/%d/obligations/%d", i, j), true
		}
	}
	return "", false
}
