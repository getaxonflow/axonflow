//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
)

// Community-build coverage for auth_daily_limit.go. The enterprise-only
// integration tests (TestRevokeAPIKey_DB et al.) exercise this code via
// the full SaaS auth path; community-build CI doesn't include those, so
// these direct unit tests close the coverage gap on the same functions
// without touching the enterprise binary path.
//
// Note: in the community build, license.GetTierLimits returns
// DailyEventQuota=-1 for every tier (the typed SaaS Plugin quotas are
// enterprise-only — see platform/agent/license/tier.go). Every code
// path therefore falls through to the COMMUNITY_SAAS_DAILY_LIMIT env-
// var lookup. We assert that fall-through behavior + bound it to known
// inputs.

func TestDailyLimitForTier_CommunityAlwaysFallsBackToEnv(t *testing.T) {
	t.Setenv("COMMUNITY_SAAS_DAILY_LIMIT", "1234")
	for _, tier := range []string{"", "Free", "Pro", "Premium", "Evaluation", "Professional", "unknown"} {
		got := dailyLimitForTier(tier)
		if got != 1234 {
			t.Errorf("dailyLimitForTier(%q) = %d, want 1234 "+
				"(community build always falls back to env)", tier, got)
		}
	}
}

func TestDailyLimitForTier_DefaultWithoutEnv(t *testing.T) {
	// Use t.Setenv("", "") with explicit empty value rather than raw
	// os.Unsetenv so the value is restored on test exit (auto-cleanup
	// via t.Cleanup). Empty string is treated by getEnvInt the same
	// as unset.
	t.Setenv("COMMUNITY_SAAS_DAILY_LIMIT", "")
	if got := dailyLimitForTier(""); got != 500 {
		t.Errorf("dailyLimitForTier(\"\") with env unset => %d, want 500 (envFallbackDefault)", got)
	}
	if got := dailyLimitForTier("Pro"); got != 500 {
		t.Errorf("dailyLimitForTier(\"Pro\") with env unset => %d, want 500", got)
	}
}

func TestDailyLimitForTenant_NilClient(t *testing.T) {
	t.Setenv("COMMUNITY_SAAS_DAILY_LIMIT", "777")
	if got := dailyLimitForTenant(nil); got != 777 {
		t.Errorf("nil client with env=777 => %d, want 777", got)
	}
}

func TestDailyLimitForTenant_EmptyEffectiveTier(t *testing.T) {
	t.Setenv("COMMUNITY_SAAS_DAILY_LIMIT", "777")
	c := &Client{EffectiveTier: ""}
	if got := dailyLimitForTenant(c); got != 777 {
		t.Errorf("client with empty EffectiveTier + env=777 => %d, want 777", got)
	}
}

func TestDailyLimitForTenant_NonEmptyTierStillEnvInCommunity(t *testing.T) {
	// Exercises the typed-tier branch of dailyLimitForTenant. In the
	// community build, the branch resolves to license.GetTierLimits
	// which returns DailyEventQuota=-1, so the function falls back to
	// the env-var path even when EffectiveTier is set. This pins the
	// community semantics + covers the typed-tier dispatch branch.
	t.Setenv("COMMUNITY_SAAS_DAILY_LIMIT", "777")
	c := &Client{EffectiveTier: "Pro"}
	if got := dailyLimitForTenant(c); got != 777 {
		t.Errorf("client with EffectiveTier=Pro + env=777 => %d, "+
			"want 777 (community build's GetTierLimits returns -1)", got)
	}
}
