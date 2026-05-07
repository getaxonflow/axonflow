// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "axonflow/platform/agent/license"

// dailyLimitForTenant resolves the per-tenant daily write-quota for the
// community-saas daily-cap check. The flow:
//
//  1. If the request resolved to a SaaS Plugin tier (EffectiveTier is one
//     of Free / Pro / Premium), use that tier's `DailyEventQuota` from
//     the typed `TierLimits` struct. The locked numbers per
//     PRD_TENANT_DURABILITY_AND_CLAIM (V1 Plugin Pro umbrella #1958) are
//     Free=200, Pro=2,000, Premium=5,000.
//
//  2. Otherwise (no tier resolution happened — e.g. self-hosted callers
//     hitting the same path, or a community build with the SaaS path
//     short-circuited), fall back to the legacy `COMMUNITY_SAAS_DAILY_LIMIT`
//     env var (default 500). This preserves backward compat for operators
//     running their own community-saas stacks (e.g. the perf-testing rig
//     that needs an explicit cap).
//
// `client == nil` is defensively handled — falls through to the env-var
// path. In practice the daily-cap call site only fires when auth has
// already produced a non-nil Client.
func dailyLimitForTenant(client *Client) int {
	if client != nil && client.EffectiveTier != "" {
		return dailyLimitForTier(client.EffectiveTier)
	}
	return dailyLimitForTier("")
}

// dailyLimitForTier resolves the daily quota by tier string alone.
// Used by the MCP server path (umbrella #1958 + #1976) where the
// session struct carries tier as a string but doesn't reconstruct a
// full *Client. Same semantics as dailyLimitForTenant otherwise: -1
// or 0 falls through to the env-var fallback.
func dailyLimitForTier(tier string) int {
	const envFallbackDefault = 500

	if tier != "" {
		limits := license.GetTierLimits(license.Tier(tier))
		if limits.DailyEventQuota > 0 {
			return limits.DailyEventQuota
		}
	}
	return getEnvInt("COMMUNITY_SAAS_DAILY_LIMIT", envFallbackDefault)
}
