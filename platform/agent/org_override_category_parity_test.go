// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// TestOrgOverrideCategoryMatchesBuildActionOverrides pins the ONE fact two
// packages have to agree on: which policy categories an organization's recorded
// detection override can replace the stored action of (#3961).
//
// BuildActionOverrides (detection_config.go) decides it at ENFORCEMENT time.
// sharedpolicy.OrgOverrideCategoryFor answers the same question for every
// DISPLAY surface, including the customer portal's Policies page and the agent's
// audit advisory. The portal lives in another module and cannot import this
// package, so nothing but a test can hold the two together, and a drift is
// silent in BOTH directions: a category an override reaches whose page states
// the row action with no disclosure, or a page naming an override that replaces
// nothing.
//
// This is a set-equality test on purpose. Asserting only "every overridden
// category has a name" would pass a map that grew, which is the more likely
// drift.
func TestOrgOverrideCategoryMatchesBuildActionOverrides(t *testing.T) {
	// Every override category set, so the map holds every category any override
	// can reach. A config with no override builds an EMPTY map (the stored
	// actions decide), which is its own assertion below.
	cfg := &ModeDetectionConfig{
		PIIAction:              DetectionActionRedact,
		SQLIAction:             DetectionActionBlock,
		DangerousQueryAction:   DetectionActionBlock,
		DangerousCommandAction: DetectionActionBlock,
	}
	overrides := cfg.BuildActionOverrides()

	// Anti-vacuity: an empty map would make every assertion below trivially true.
	if len(overrides) == 0 {
		t.Fatal("BuildActionOverrides returned no categories with every override set; the parity assertions below would be vacuous")
	}

	for cat := range overrides {
		if name := sharedpolicy.OrgOverrideCategoryFor(cat); name == "" {
			t.Errorf("category %q is overridable at enforcement time (present in BuildActionOverrides) "+
				"but OrgOverrideCategoryFor names no override: a display surface will state the row's "+
				"action with no disclosure of the override that replaces it", cat)
		}
	}

	// The reverse direction, over every declared category rather than over the
	// map, so a category that gained a name without gaining enforcement is caught.
	for _, cat := range allDeclaredPolicyCategoriesForParity() {
		name := sharedpolicy.OrgOverrideCategoryFor(cat)
		_, enforced := overrides[cat]
		if name != "" && !enforced {
			t.Errorf("OrgOverrideCategoryFor(%q) = %q but BuildActionOverrides does not override that "+
				"category: a display surface will name an override that replaces nothing", cat, name)
		}
		if name == "" && enforced {
			t.Errorf("category %q is overridden by BuildActionOverrides but has no override category name", cat)
		}
	}

	// Literals, so a refactor that made BOTH sides agree on the wrong answer
	// still fails. sensitive-data has no override category (the table's CHECK
	// constraint lists none), so its stored action always decides; fincrime and
	// compliance-* are not overridable; media-pii is the orchestrator's OCR
	// subsystem and matches no "pii-" prefix.
	for cat, want := range map[sharedpolicy.PolicyCategory]string{
		sharedpolicy.CategorySecuritySQLi:      "sqli",
		sharedpolicy.CategorySecurityDangerous: "dangerous_command",
		sharedpolicy.CategoryPIIIndonesia:      "pii",
		sharedpolicy.CategorySensitiveData:     "",
		sharedpolicy.CategoryFinCrime:          "",
		sharedpolicy.CategoryComplianceSEBI:    "",
		sharedpolicy.CategoryMediaPII:          "",
	} {
		if got := sharedpolicy.OrgOverrideCategoryFor(cat); got != want {
			t.Errorf("OrgOverrideCategoryFor(%s) = %q, want %q", cat, got, want)
		}
	}

	// And the other half of #3961: with no override, nothing is displaced.
	if none := (&ModeDetectionConfig{Enabled: true}).BuildActionOverrides(); len(none) != 0 {
		t.Errorf("a config with no organization override built %d action overrides (%v); only a recorded override may replace a stored action", len(none), none)
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
