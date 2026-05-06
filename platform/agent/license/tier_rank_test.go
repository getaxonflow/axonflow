//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"testing"
)

// =============================================================================
// tierRank — full ladder coverage + unknown sentinel (GAP-3 + GAP-4)
//
// Pre-GAP-3, the default branch returned 0, silently treating any
// unrecognized tier as Community. These tests lock in the new behavior:
// known tiers map to their documented ranks; unknown tiers AND SaaS Plugin
// tiers map to -1 so rank-based comparisons fail closed.
// =============================================================================

func TestTierRank_KnownLadder(t *testing.T) {
	cases := map[Tier]int{
		TierCommunity:      0,
		TierEvaluation:     0,
		TierProfessional:   1,
		TierEnterprise:     2,
		TierEnterprisePlus: 3,
	}
	for tier, want := range cases {
		if got := tierRank(tier); got != want {
			t.Errorf("tierRank(%q) = %d, want %d", tier, got, want)
		}
	}
}

func TestTierRank_PluginTiers_ReturnSentinel(t *testing.T) {
	for _, tier := range []Tier{TierPro, TierPremium} {
		if got := tierRank(tier); got != -1 {
			t.Errorf("tierRank(%q) = %d, want -1 (plugin tiers are off-ladder)", tier, got)
		}
	}
}

func TestTierRank_UnknownTier_ReturnsSentinel(t *testing.T) {
	cases := []Tier{
		Tier("Unknown"),
		Tier(""),
		Tier("ProfessionalPlus"), // hypothetical future tier added without updating switch
		Tier("admin"),            // adversarial: lowercase tier, definitely not in switch
		Tier("Community "),       // trailing whitespace
	}
	for _, tier := range cases {
		if got := tierRank(tier); got != -1 {
			t.Errorf("tierRank(%q) = %d, want -1 (unknown tiers must fail closed)", tier, got)
		}
	}
}

// =============================================================================
// TierSatisfiesRequirement — full matrix on the self-hosted ladder
// =============================================================================

func TestTierSatisfiesRequirement_SelfHostedLadder(t *testing.T) {
	type row struct {
		current  Tier
		required Tier
		want     bool
	}

	cases := []row{
		// Community satisfies only Community/Evaluation (both rank 0)
		{TierCommunity, TierCommunity, true},
		{TierCommunity, TierEvaluation, true}, // both rank 0
		{TierCommunity, TierProfessional, false},
		{TierCommunity, TierEnterprise, false},
		{TierCommunity, TierEnterprisePlus, false},

		// Evaluation satisfies same level as Community
		{TierEvaluation, TierCommunity, true},
		{TierEvaluation, TierEvaluation, true},
		{TierEvaluation, TierProfessional, false},

		// Professional satisfies <= Professional
		{TierProfessional, TierCommunity, true},
		{TierProfessional, TierEvaluation, true},
		{TierProfessional, TierProfessional, true},
		{TierProfessional, TierEnterprise, false},
		{TierProfessional, TierEnterprisePlus, false},

		// Enterprise satisfies <= Enterprise
		{TierEnterprise, TierProfessional, true},
		{TierEnterprise, TierEnterprise, true},
		{TierEnterprise, TierEnterprisePlus, false},

		// EnterprisePlus satisfies everything on the ladder
		{TierEnterprisePlus, TierCommunity, true},
		{TierEnterprisePlus, TierEvaluation, true},
		{TierEnterprisePlus, TierProfessional, true},
		{TierEnterprisePlus, TierEnterprise, true},
		{TierEnterprisePlus, TierEnterprisePlus, true},
	}

	for _, c := range cases {
		got := TierSatisfiesRequirement(c.current, c.required)
		if got != c.want {
			t.Errorf("TierSatisfiesRequirement(current=%q, required=%q) = %v, want %v",
				c.current, c.required, got, c.want)
		}
	}
}

// TestTierSatisfiesRequirement_PluginTiersFailClosed asserts that SaaS Plugin
// tiers do NOT satisfy ANY self-hosted requirement, AND no self-hosted tier
// satisfies a SaaS Plugin requirement. They sit on different product lines.
func TestTierSatisfiesRequirement_PluginTiersFailClosed(t *testing.T) {
	pluginTiers := []Tier{TierPro, TierPremium}
	selfHosted := []Tier{TierCommunity, TierEvaluation, TierProfessional, TierEnterprise, TierEnterprisePlus}

	for _, pt := range pluginTiers {
		// SaaS Plugin CURRENT, self-hosted REQUIRED → false
		for _, sh := range selfHosted {
			if TierSatisfiesRequirement(pt, sh) {
				t.Errorf("TierSatisfiesRequirement(plugin=%q, self-hosted=%q) must be false (orthogonal product lines)",
					pt, sh)
			}
		}
		// self-hosted CURRENT, SaaS Plugin REQUIRED → false
		for _, sh := range selfHosted {
			if TierSatisfiesRequirement(sh, pt) {
				t.Errorf("TierSatisfiesRequirement(self-hosted=%q, plugin=%q) must be false (orthogonal product lines)",
					sh, pt)
			}
		}
		// SaaS Plugin CURRENT, SaaS Plugin REQUIRED → also false (not on the comparable ladder)
		for _, pt2 := range pluginTiers {
			if TierSatisfiesRequirement(pt, pt2) {
				t.Errorf("TierSatisfiesRequirement(%q, %q) must be false — SaaS Plugin tiers are not rank-comparable; gate them via IsSaasPluginTier",
					pt, pt2)
			}
		}
	}
}

// TestTierSatisfiesRequirement_UnknownTierFailsClosed locks in the GAP-3 fix:
// any unknown tier on either side of the comparison fails closed. Without
// this, the pre-GAP-3 default-zero behavior would have made:
//   - Unknown CURRENT vs known REQUIRED: false-positive whenever required is Community
//   - Known CURRENT vs Unknown REQUIRED: false-positive whenever current >= 0
//   - Unknown CURRENT vs Unknown REQUIRED: silent true (both 0 >= 0)
func TestTierSatisfiesRequirement_UnknownTierFailsClosed(t *testing.T) {
	unknown := Tier("Unknown_FutureTier")
	known := []Tier{TierCommunity, TierEvaluation, TierProfessional, TierEnterprise, TierEnterprisePlus}

	for _, k := range known {
		if TierSatisfiesRequirement(unknown, k) {
			t.Errorf("TierSatisfiesRequirement(unknown=%q, known=%q) must be false — unknown current must fail closed", unknown, k)
		}
		if TierSatisfiesRequirement(k, unknown) {
			t.Errorf("TierSatisfiesRequirement(known=%q, unknown=%q) must be false — unknown required must fail closed", k, unknown)
		}
	}
	// Unknown vs Unknown — must NOT trivially satisfy
	if TierSatisfiesRequirement(unknown, unknown) {
		t.Errorf("TierSatisfiesRequirement(unknown, unknown) must be false — pre-GAP-3 this incorrectly returned true (both rank 0)")
	}
}

// =============================================================================
// IsEvaluationOrHigher — known-tier classification
// =============================================================================

func TestIsEvaluationOrHigher(t *testing.T) {
	cases := map[Tier]bool{
		TierCommunity:      false,
		TierEvaluation:     true,
		TierProfessional:   true,
		TierEnterprise:     true,
		TierEnterprisePlus: true,

		// Plugin tiers are not "evaluation or higher" on the self-hosted
		// ladder — they're a separate product. Callers gating self-hosted
		// features (LLM matrix, MAP plans, EU AI Act templates) on this
		// helper must not see SaaS Plugin as eligible.
		TierPro:      false,
		TierPremium: false,

		// Unknown tier — fail closed
		Tier("Unknown"): false,
	}
	for tier, want := range cases {
		if got := IsEvaluationOrHigher(tier); got != want {
			t.Errorf("IsEvaluationOrHigher(%q) = %v, want %v", tier, got, want)
		}
	}
}
