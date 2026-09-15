// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"testing"

	"axonflow/platform/decision/pdp"
)

// TestTheSourceRefCarriesTheRowsName (#4127): a compiled record names the
// legacy row it came from, so the corpus can carry that name as each policy's
// operator-facing name. Both substrates, because they are compiled apart.
func TestTheSourceRefCarriesTheRowsName(t *testing.T) {
	rep, err := Compile([]RawRow{
		staticRow(t, "sys_named_static", map[string]any{"name": "Named static row"}),
		dynamicRow(t, "sys_named_dynamic", map[string]any{"name": "Named dynamic row"}),
	}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for id, want := range map[string]string{
		"sys_named_static":  "Named static row",
		"sys_named_dynamic": "Named dynamic row",
	} {
		if got := recordFor(t, rep, id).Source.Name; got != want {
			t.Errorf("%s: source name = %q, want the row's name %q", id, got, want)
		}
	}
}

// TestEveryShippedPolicyCarriesItsRowsName (#4127): every policy the platform
// ships, in the system document and the organization template, carries a name,
// and every policy compiled from one legacy row - its split and #n variants -
// carries that row's one name: an operator knows one control by one name.
func TestEveryShippedPolicyCarriesItsRowsName(t *testing.T) {
	system, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	byControl := map[string]string{}
	perControl := map[string]int{}
	for _, doc := range []*pdp.Document{system, template} {
		for _, p := range doc.Policies {
			if p.Name == "" {
				t.Errorf("shipped policy %s carries no name", p.ID)
				continue
			}
			control, _, ok := CorpusControlOf(p.ID)
			if !ok {
				t.Fatalf("shipped policy %s is not a corpus policy identifier", p.ID)
			}
			perControl[control]++
			if prev, seen := byControl[control]; seen && prev != p.Name {
				t.Errorf("row %s ships policies named %q and %q; its variants must share the row's name", control, prev, p.Name)
			}
			byControl[control] = p.Name
		}
	}
	// ANTI-VACUITY: the sharing rule is only tested where one row yields more
	// than one policy.
	multi := 0
	for _, n := range perControl {
		if n > 1 {
			multi++
		}
	}
	if multi == 0 {
		t.Fatal("no row ships more than one policy, so the sharing check above checks nothing")
	}
}
