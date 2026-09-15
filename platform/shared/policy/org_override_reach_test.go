// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"slices"
	"testing"
)

// The reach is stated in literals, so a change that moved OrgOverrideCategoryFor
// and its inverse together, to the wrong answer, still fails here.
func TestOrgOverrideReachIsTheInverseOfOrgOverrideCategoryFor(t *testing.T) {
	for category, want := range map[string][]PolicyCategory{
		"pii":                 {CategoryPIIGlobal, CategoryPIIUS, CategoryPIIIndia, CategoryPIIEU, CategoryPIISingapore, CategoryPIIIndonesia},
		"sqli":                {CategorySecuritySQLi},
		"dangerous_command":   {CategorySecurityDangerous},
		"dangerous_query":     nil,
		"obligation_fallback": nil,
		"":                    nil,
		"exfiltration":        nil,
	} {
		if got := OrgOverrideReach(category); !slices.Equal(got, want) {
			t.Errorf("OrgOverrideReach(%q) = %v; want %v", category, got, want)
		}
	}
	for _, c := range AllPolicyCategories() {
		if name := OrgOverrideCategoryFor(c); name != "" && !slices.Contains(OrgOverrideReach(name), c) {
			t.Errorf("OrgOverrideCategoryFor(%s) = %q, and OrgOverrideReach(%q) does not reach it", c, name, name)
		}
	}
}
