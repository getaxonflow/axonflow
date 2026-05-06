//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"testing"
)

// =============================================================================
// tierRank — community build coverage (GAP-3 + GAP-4)
//
// Mirrors the enterprise-build tests in tier_rank_test.go but without the
// plugin-claim tier cases (those constants are only defined under the
// enterprise build tag). The community build still has the same fail-closed
// behavior for unknown tiers and the same self-hosted ladder semantics.
// =============================================================================

func TestTierRank_KnownLadder_Community(t *testing.T) {
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

func TestTierRank_UnknownTier_ReturnsSentinel_Community(t *testing.T) {
	cases := []Tier{
		Tier("Unknown"),
		Tier(""),
		Tier("ProfessionalPlus"),
		Tier("admin"),
	}
	for _, tier := range cases {
		if got := tierRank(tier); got != -1 {
			t.Errorf("tierRank(%q) = %d, want -1 (unknown tiers must fail closed)", tier, got)
		}
	}
}

func TestTierSatisfiesRequirement_SelfHostedLadder_Community(t *testing.T) {
	type row struct {
		current  Tier
		required Tier
		want     bool
	}
	cases := []row{
		{TierCommunity, TierCommunity, true},
		{TierCommunity, TierEvaluation, true},
		{TierCommunity, TierProfessional, false},
		{TierEvaluation, TierEnterprise, false},
		{TierProfessional, TierProfessional, true},
		{TierProfessional, TierEnterprise, false},
		{TierEnterprise, TierProfessional, true},
		{TierEnterprise, TierEnterprise, true},
		{TierEnterprise, TierEnterprisePlus, false},
		{TierEnterprisePlus, TierEnterprise, true},
		{TierEnterprisePlus, TierEnterprisePlus, true},
	}
	for _, c := range cases {
		got := TierSatisfiesRequirement(c.current, c.required)
		if got != c.want {
			t.Errorf("TierSatisfiesRequirement(%q, %q) = %v, want %v",
				c.current, c.required, got, c.want)
		}
	}
}

func TestTierSatisfiesRequirement_UnknownFailsClosed_Community(t *testing.T) {
	unknown := Tier("Unknown_FutureTier")
	for _, k := range []Tier{TierCommunity, TierEvaluation, TierProfessional, TierEnterprise, TierEnterprisePlus} {
		if TierSatisfiesRequirement(unknown, k) {
			t.Errorf("TierSatisfiesRequirement(unknown, %q) must be false", k)
		}
		if TierSatisfiesRequirement(k, unknown) {
			t.Errorf("TierSatisfiesRequirement(%q, unknown) must be false", k)
		}
	}
	if TierSatisfiesRequirement(unknown, unknown) {
		t.Errorf("TierSatisfiesRequirement(unknown, unknown) must be false")
	}
}

func TestIsEvaluationOrHigher_Community(t *testing.T) {
	cases := map[Tier]bool{
		TierCommunity:      false,
		TierEvaluation:     true,
		TierProfessional:   true,
		TierEnterprise:     true,
		TierEnterprisePlus: true,
		Tier("Unknown"):    false,
	}
	for tier, want := range cases {
		if got := IsEvaluationOrHigher(tier); got != want {
			t.Errorf("IsEvaluationOrHigher(%q) = %v, want %v", tier, got, want)
		}
	}
}
