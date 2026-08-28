// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3529 (epic #3528 Phase 1): guards for the compliance portion of the four
// agent plane category whitelists.
//
// THE DEFECT THESE EXIST TO PREVENT. A plane whitelist is applied BEFORE
// evaluation: sharedpolicy.EvalOptions.Categories filters the loaded policy set
// in memory, so a category missing from a whitelist means every policy in that
// category is dropped before it is ever evaluated. Nothing errors and nothing
// is logged - the request is simply allowed. That is the #2965 defect
// (pii-indonesia missing from three hand lists left Indonesian PII ungoverned)
// and the core/127 defect (a drifted category spelling excluded four seeded
// compliance families) in the same shape.
//
// Before #3529 all four planes hand-listed four of the six categories that
// sharedpolicy.AllComplianceCategories() returned, and that function had no
// non-test caller at all. compliance-gdpr and compliance-hipaa were therefore
// declared, advertised as authorable in the portal's category list, and
// filtered out before evaluation on every plane.
//
// TWO TESTS, DELIBERATELY. The first is SELF-REFERENTIAL and says so: the
// whitelists spread the same function it checks them against, so deleting a
// category from AllComplianceCategories would leave it green. The second is
// the independent one that actually bites - it asserts against literal
// strings, which is the only form that survives the function it is checking
// being wrong. The same pairing exists for PII in policy_result_convert_test.go
// and the reasoning is recorded there too.

import (
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// planeComplianceWhitelists is every category whitelist that gates evaluation
// on a request-carrying plane. All four are package vars; mcpInputPolicyCategories
// was hoisted from an inline literal in #3529 precisely so it could appear here
// - while it was a function-local, no test could see it.
func planeComplianceWhitelists() map[string][]sharedpolicy.PolicyCategory {
	return map[string][]sharedpolicy.PolicyCategory{
		"proxyPolicyCategories":           proxyPolicyCategories,
		"openaiCompatPolicyCategories":    openaiCompatPolicyCategories,
		"gatewayPreCheckPolicyCategories": gatewayPreCheckPolicyCategories,
		"mcpInputPolicyCategories":        mcpInputPolicyCategories,
	}
}

// TestPlaneWhitelistsCoverAllCompliance is the self-referential guard: every
// category AllComplianceCategories() returns must appear in every plane
// whitelist. It catches a plane that stops spreading the shared function (a
// revert to hand-listing), which is the regression that actually happens.
//
// It CANNOT catch a category deleted from AllComplianceCategories itself -
// see TestUSComplianceCategoriesReachEveryPlane below, which can.
func TestPlaneWhitelistsCoverAllCompliance(t *testing.T) {
	for name, list := range planeComplianceWhitelists() {
		present := make(map[sharedpolicy.PolicyCategory]bool, len(list))
		for _, c := range list {
			present[c] = true
		}
		for _, cat := range sharedpolicy.AllComplianceCategories() {
			if !present[cat] {
				t.Errorf("%s omits compliance category %q - every policy in that category would be filtered out before evaluation on this plane, allowing the request with no error and no log (#2965/#3529)", name, cat)
			}
		}
	}
}

// TestUSComplianceCategoriesReachEveryPlane is the INDEPENDENT cross-check.
//
// It hardcodes the four US category strings rather than reading them from
// sharedpolicy, so it fails if a category is dropped from
// AllComplianceCategories(), if a constant's VALUE is changed, or if a plane
// reverts to a hand list - none of which the self-referential test above can
// see. The strings below must equal the ones seeded by
// migrations/enterprise/139_us_compliance_templates.sql; that agreement is what
// migration 139's own real-Postgres test proves from the other direction.
func TestUSComplianceCategoriesReachEveryPlane(t *testing.T) {
	// The canonical spellings, written out. Do not replace these with the
	// constants: the whole value of this test is that it does not depend on
	// the thing it is checking.
	usCategories := []string{
		"compliance-glba",
		"compliance-fairlending",
		"compliance-bsa-aml",
		"compliance-nydfs",
	}

	for name, list := range planeComplianceWhitelists() {
		present := make(map[string]bool, len(list))
		for _, c := range list {
			present[string(c)] = true
		}
		for _, want := range usCategories {
			if !present[want] {
				t.Errorf("%s does not evaluate %q - the US template family seeded under that category would never fire on this plane (#3529)", name, want)
			}
		}
	}
}

// TestFinCrimeStaysOutOfTheComplianceVocabulary pins the one category that must
// NOT be swept into AllComplianceCategories().
//
// fincrime is deliberately its own category so the FinCrime pack is governed by
// neither the per-category action levers nor capability scoping (ADR-061 /
// #3329). If someone "tidied" it into the compliance list, the pack's rows
// would start being treated as compliance rows on every plane. The MCP plane
// appends it explicitly, which is why that plane must still carry it while the
// shared compliance list must not.
func TestFinCrimeStaysOutOfTheComplianceVocabulary(t *testing.T) {
	for _, cat := range sharedpolicy.AllComplianceCategories() {
		if cat == sharedpolicy.CategoryFinCrime {
			t.Fatalf("AllComplianceCategories() returns %q - fincrime is deliberately outside the compliance vocabulary (ADR-061/#3329); adding it changes how the pack is governed on all four planes", cat)
		}
	}
	if sharedpolicy.IsComplianceCategory(sharedpolicy.CategoryFinCrime) {
		t.Error("IsComplianceCategory(fincrime) = true, want false - fincrime is not a compliance category")
	}
	// ...and the MCP plane must still evaluate it, since that plane is where
	// the pack is enforced. Dropping it here would silently disable the pack
	// on the managed MCP planes.
	var found bool
	for _, c := range mcpInputPolicyCategories {
		if c == sharedpolicy.CategoryFinCrime {
			found = true
			break
		}
	}
	if !found {
		t.Error("mcpInputPolicyCategories no longer carries fincrime - the FinCrime Policy Pack would stop being evaluated on the managed MCP planes (ADR-061/#3329)")
	}
}

// TestEveryComplianceCategoryIsCanonicallySpelled is the core/127 guard applied
// to the vocabulary itself rather than to a seed file.
//
// core/127 exists because four seeds stored spellings like `rbi_compliance`
// while the exact-match filter wanted `compliance-rbi`. Every category in the
// shared list must therefore carry the canonical `compliance-` prefix and use
// hyphens rather than underscores, so a drifted constant cannot enter the
// vocabulary in the first place.
func TestEveryComplianceCategoryIsCanonicallySpelled(t *testing.T) {
	cats := sharedpolicy.AllComplianceCategories()
	if len(cats) == 0 {
		t.Fatal("AllComplianceCategories() is empty - this guard would be vacuous")
	}
	for _, cat := range cats {
		s := string(cat)
		if !strings.HasPrefix(s, "compliance-") {
			t.Errorf("compliance category %q does not use the canonical `compliance-` prefix - the exact-match category filter would exclude every row seeded under it (the core/127 class)", s)
		}
		if strings.Contains(s, "_") {
			t.Errorf("compliance category %q contains an underscore - the canonical spellings are hyphenated, and the drifted seeds core/127 had to repair were the underscored form", s)
		}
		if s != strings.ToLower(s) {
			t.Errorf("compliance category %q is not lowercase - category matching is exact, so a capital is a silent exclusion", s)
		}
	}
}
