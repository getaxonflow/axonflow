// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// TestPostureLeverMatchesBuildActionOverrides pins the ONE fact two packages
// have to agree on: which policy categories have their stored action replaced
// by the detection posture lever.
//
// BuildActionOverrides (detection_config.go) decides it at ENFORCEMENT time.
// sharedpolicy.PostureLeverForCategory answers the same question for every
// DISPLAY surface, including the customer portal's Policies page, which since
// #3441 discloses the lever's displacement for exactly this set.
// The portal lives in another module and cannot import this package, so nothing
// but a test can hold the two together, and a drift is silent in BOTH
// directions: a category that gains a lever keeps a page that states its row
// action with no disclosure of the lever displacing it, and a category that
// loses one gets a page naming a lever that does not govern it.
//
// This is a set-equality test on purpose. Asserting only "every lever category
// is in the map" would pass a map that grew, which is the more likely drift.
func TestPostureLeverMatchesBuildActionOverrides(t *testing.T) {
	cfg := &ModeDetectionConfig{}
	overrides := cfg.BuildActionOverrides()

	// Anti-vacuity: a build that returned an empty map would make every
	// assertion below trivially true, and the whole test would go green on the
	// exact regression it exists to catch.
	if len(overrides) == 0 {
		t.Fatal("BuildActionOverrides returned no categories; the parity assertions below would be vacuous")
	}

	for cat := range overrides {
		if lever := sharedpolicy.PostureLeverForCategory(cat); lever == "" {
			t.Errorf("category %q is lever-governed at enforcement time (present in BuildActionOverrides) "+
				"but PostureLeverForCategory reports no lever: a display surface will state the row's "+
				"action with no disclosure of the lever that displaces it", cat)
		}
	}

	// The reverse direction. Enumerated over every category constant the shared
	// package declares rather than over the map, so a category that gained a
	// lever name without gaining enforcement is caught too.
	for _, cat := range allDeclaredPolicyCategoriesForParity() {
		lever := sharedpolicy.PostureLeverForCategory(cat)
		_, enforced := overrides[cat]
		if lever != "" && !enforced {
			t.Errorf("PostureLeverForCategory(%q) = %q but BuildActionOverrides does not override that "+
				"category: a display surface will name a lever that displaces nothing", cat, lever)
		}
		if lever == "" && enforced {
			t.Errorf("category %q is overridden by BuildActionOverrides but has no lever name", cat)
		}
	}

	// Spot-check the two ends of the contract with literals, so a refactor that
	// made BOTH sides agree on the wrong answer still fails. security-sqli is
	// lever-governed; fincrime is explicitly NOT, which is what lets the
	// FinCrime pack's require_approval rows survive a warn/log posture. Note
	// the narrow meaning: "not lever-governed" is not "the base action column
	// is enforced" - the shared engine reads the phase columns and never
	// selects that column at all.
	if got := sharedpolicy.PostureLeverForCategory(sharedpolicy.CategorySecuritySQLi); got != "SQLI_ACTION" {
		t.Errorf("PostureLeverForCategory(security-sqli) = %q, want SQLI_ACTION", got)
	}
	if got := sharedpolicy.PostureLeverForCategory(sharedpolicy.CategoryFinCrime); got != "" {
		t.Errorf("PostureLeverForCategory(fincrime) = %q, want \"\" (no lever governs it)", got)
	}
	if got := sharedpolicy.PostureLeverForCategory(sharedpolicy.CategoryComplianceSEBI); got != "" {
		t.Errorf("PostureLeverForCategory(compliance-sebi) = %q, want \"\" (no lever governs it)", got)
	}
	// media-pii matches no "pii-" prefix and must not be swept in by
	// IsPIIPolicyCategory: it is the orchestrator's OCR subsystem, with no
	// agent text-engine match for a lever to displace.
	if got := sharedpolicy.PostureLeverForCategory(sharedpolicy.CategoryMediaPII); got != "" {
		t.Errorf("PostureLeverForCategory(media-pii) = %q, want \"\"", got)
	}
}

// allDeclaredPolicyCategoriesForParity lists every PolicyCategory constant
// declared in platform/shared/policy/types.go. Written out rather than derived
// so each entry is a compile-time reference: a renamed or deleted constant is a
// build failure here, which is the loudest possible signal that this list needs
// revisiting.
func allDeclaredPolicyCategoriesForParity() []sharedpolicy.PolicyCategory {
	return []sharedpolicy.PolicyCategory{
		sharedpolicy.CategorySecuritySQLi,
		sharedpolicy.CategorySecurityDangerous,
		sharedpolicy.CategoryAdminAccess,
		sharedpolicy.CategoryPIIGlobal,
		sharedpolicy.CategoryPIIUS,
		sharedpolicy.CategoryPIIIndia,
		sharedpolicy.CategoryPIIEU,
		sharedpolicy.CategoryPIISingapore,
		sharedpolicy.CategoryPIIIndonesia,
		sharedpolicy.CategoryDataExfiltration,
		sharedpolicy.CategorySensitiveData,
		sharedpolicy.CategoryDynamicRateLimit,
		sharedpolicy.CategoryDynamicBudget,
		sharedpolicy.CategoryDynamicTimeAccess,
		sharedpolicy.CategoryDynamicRoleAccess,
		sharedpolicy.CategoryComplianceGDPR,
		sharedpolicy.CategoryComplianceHIPAA,
		sharedpolicy.CategoryComplianceRBI,
		sharedpolicy.CategoryComplianceSEBI,
		sharedpolicy.CategoryComplianceEUAIAct,
		sharedpolicy.CategoryComplianceMASFEAT,
		sharedpolicy.CategoryFinCrime,
		sharedpolicy.CategoryMediaSafety,
		sharedpolicy.CategoryMediaBiometric,
		sharedpolicy.CategoryMediaDocument,
		sharedpolicy.CategoryMediaPII,
	}
}
