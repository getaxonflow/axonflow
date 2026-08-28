package orchestrator

import "testing"

// TestDynamicCategoryForTemplate pins the catalog-to-dynamic category mapping
// ApplyTemplate stamps on the policies it creates.
//
// Before this mapping existed the field was never set at all: every applied
// template produced a dynamic policy with an EMPTY category - unfilterable in
// the portal, and a row the direct-create API would have refused with 400
// (isValidDynamicPolicyCategory requires a dynamic-/media- prefix). The rule
// is one line by design - "dynamic-" + the catalog category - because a lookup
// table drifts the moment a template family is added. Routed from epic #3528.
func TestDynamicCategoryForTemplate(t *testing.T) {
	cases := []struct{ catalog, want string }{
		// The real catalog vocabulary in the shipped seeds: core/024 uses
		// general and security; enterprise/109 uses hipaa/gdpr/pci-dss/soc2/
		// dora; enterprise/139 uses the canonical compliance-<x> family.
		{"general", "dynamic-general"},
		{"security", "dynamic-security"},
		{"hipaa", "dynamic-hipaa"},
		{"compliance-glba", "dynamic-compliance-glba"},
		// The empty catalog value maps to a real category, never to the empty
		// string this function exists to eliminate.
		{"", "dynamic-general"},
	}
	for _, c := range cases {
		got := dynamicCategoryForTemplate(c.catalog)
		if got != c.want {
			t.Errorf("dynamicCategoryForTemplate(%q) = %q, want %q", c.catalog, got, c.want)
		}
		// Every output must pass the direct-create path's own validator - the
		// invariant that makes the apply path stop writing rows the create
		// path forbids.
		if !isValidDynamicPolicyCategory(got) {
			t.Errorf("dynamicCategoryForTemplate(%q) = %q, which isValidDynamicPolicyCategory rejects", c.catalog, got)
		}
	}
}
