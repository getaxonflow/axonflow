//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Per-tenant SaaS Plugin tier resolution (Free=200, Pro=2,000, Premium=5,000
// per V1 Plugin Pro umbrella #1958) is wired only in the enterprise build
// (platform/agent/license/tier_support.go, build-tagged enterprise). The
// community build's GetTierLimits falls through to CommunityLimits
// (DailyEventQuota=-1, n/a) and dailyLimitForTenant uses the
// COMMUNITY_SAAS_DAILY_LIMIT env-var fallback for everyone — there is no
// per-tenant differentiation to assert. Gate this test file accordingly so
// the assertions reflect a real product behavior on the build that ships
// to paying customers, instead of co-asserting on a fallback constant in
// the community CI.
package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEnforceCommunitySaasDailyCap_NonCommunitySaas asserts that the
// daily-cap helper short-circuits for any auth kind that isn't
// AuthKindCommunitySaaS. Without this short-circuit a self-hosted
// Enterprise tenant would be billed against the SaaS Plugin Pro
// 1000-events/day cap — completely wrong product. This guards the
// regression of accidentally extending the cap to all proxy callers.
func TestEnforceCommunitySaasDailyCap_NonCommunitySaas(t *testing.T) {
	cases := []struct {
		name string
		kind AuthKind
	}{
		{"community", AuthKindCommunity},
		{"enterprise", AuthKindEnterprise},
		{"internal_service", AuthKindInternalService},
	}

	// If the helper bypasses correctly, proxyDailyLimitChecker must NOT
	// be called for these kinds. Wire a stub that fails the test if it is.
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })
	proxyDailyLimitChecker = func(_ context.Context, _ string, _ int, _ *sql.DB) error {
		t.Fatalf("proxyDailyLimitChecker invoked for non-community-saas auth — should short-circuit")
		return nil
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			auth := &AuthResult{Kind: tc.kind, TenantID: "t1"}
			halted := enforceCommunitySaasDailyCap(rr, auth)
			if halted {
				t.Errorf("enforceCommunitySaasDailyCap halted on %s auth — expected false", tc.kind)
			}
			if rr.Code != http.StatusOK {
				t.Errorf("response code = %d (default OK), want 200", rr.Code)
			}
		})
	}
}

// TestEnforceCommunitySaasDailyCap_NilAuth asserts the helper safely
// handles a nil AuthResult (defense-in-depth — the caller always passes
// a non-nil result, but a future regression that drops the nil check
// before the call would panic without this guard).
func TestEnforceCommunitySaasDailyCap_NilAuth(t *testing.T) {
	rr := httptest.NewRecorder()
	if enforceCommunitySaasDailyCap(rr, nil) {
		t.Error("nil auth halted request — expected false")
	}
}

// TestEnforceCommunitySaasDailyCap_UnderCap asserts that a community-saas
// tenant under their daily quota is allowed through (helper returns
// false, no response written).
func TestEnforceCommunitySaasDailyCap_UnderCap(t *testing.T) {
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })

	var capturedTenant string
	var capturedLimit int
	proxyDailyLimitChecker = func(_ context.Context, tenantID string, dailyLimit int, _ *sql.DB) error {
		capturedTenant = tenantID
		capturedLimit = dailyLimit
		return nil // under cap
	}

	rr := httptest.NewRecorder()
	auth := &AuthResult{
		Kind:     AuthKindCommunitySaaS,
		TenantID: "cs_under_cap",
		Client:   &Client{EffectiveTier: "Free"}, // dailyLimitForTenant → Free=200
	}

	if enforceCommunitySaasDailyCap(rr, auth) {
		t.Fatal("under-cap request was halted — expected false")
	}
	if capturedTenant != "cs_under_cap" {
		t.Errorf("checker invoked with tenant=%q, want cs_under_cap", capturedTenant)
	}
	if capturedLimit != 200 {
		t.Errorf("checker invoked with dailyLimit=%d, want 200 (Free tier)", capturedLimit)
	}
	// No response should have been written.
	if rr.Code != http.StatusOK {
		t.Errorf("response code = %d, want default 200 (no write)", rr.Code)
	}
}

// TestEnforceCommunitySaasDailyCap_OverCap asserts that ErrDailyLimitExceeded
// from the checker produces an HTTP 429 with the V1 Plugin Pro structured
// upgrade envelope (locked per umbrella #1958) and halts the request. This
// is the core regression test for #1921 — without the proxy-side mirror,
// this 429 would never fire on /api/v1/process, /api/v1/audit/*,
// /api/v1/mcp/evaluate-policies, or /api/v1/connectors.
//
// Pre-#1958: response body was bare `{"error": "Daily request limit
// reached..."}`. Post-#1958: structured envelope with limit_type, tier,
// limit, remaining, window, resets_at, upgrade.{wording, compare_url,
// buy_url} + locked headers (X-Axonflow-Tier-Limit, X-Axonflow-Upgrade-URL,
// Retry-After). Detailed per-field assertions live in the helper's own
// test (community_saas_ratelimit_response_test.go); this test asserts the
// proxy path delivers the new envelope (i.e. wires writeRateLimitError
// in, not bare json.Marshal).
func TestEnforceCommunitySaasDailyCap_OverCap(t *testing.T) {
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })
	proxyDailyLimitChecker = func(_ context.Context, _ string, _ int, _ *sql.DB) error {
		return ErrDailyLimitExceeded
	}

	rr := httptest.NewRecorder()
	auth := &AuthResult{
		Kind:     AuthKindCommunitySaaS,
		TenantID: "cs_over_cap",
		Client:   &Client{EffectiveTier: "Free"}, // tier carried into envelope
	}

	if !enforceCommunitySaasDailyCap(rr, auth) {
		t.Fatal("over-cap request was NOT halted — expected true (regression of #1921)")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("response code = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	// V1 Plugin Pro envelope-shape assertions — proves the proxy path
	// is wired through writeRateLimitError (no longer bare json.Marshal).
	if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != LimitTypeDailyQuota {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, LimitTypeDailyQuota)
	}
	if got := rr.Header().Get("X-Axonflow-Upgrade-URL"); got != v1ProUpgradeCompareURL {
		t.Errorf("X-Axonflow-Upgrade-URL = %q, want %q", got, v1ProUpgradeCompareURL)
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header missing on 429")
	}

	var env rateLimitEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("response body is not the V1 envelope JSON: %v\n%s", err, rr.Body.String())
	}
	if env.LimitType != LimitTypeDailyQuota {
		t.Errorf("envelope.limit_type = %q, want %q", env.LimitType, LimitTypeDailyQuota)
	}
	if env.Tier != "Free" {
		t.Errorf("envelope.tier = %q, want Free (from auth.Client.EffectiveTier)", env.Tier)
	}
	if env.Upgrade.CompareURL != v1ProUpgradeCompareURL {
		t.Errorf("envelope.upgrade.compare_url = %q, want %q", env.Upgrade.CompareURL, v1ProUpgradeCompareURL)
	}
	if env.Upgrade.BuyURL != v1ProUpgradeBuyURL {
		t.Errorf("envelope.upgrade.buy_url = %q, want %q", env.Upgrade.BuyURL, v1ProUpgradeBuyURL)
	}
}

// TestEnforceCommunitySaasDailyCap_TierFallback asserts the proxy path
// gracefully defaults to "Free" when auth.Client is nil. The
// AuthKindCommunitySaaS guard normally produces a non-nil Client, but
// any future regression that bypasses that guard should not crash and
// must still emit a usable envelope.
func TestEnforceCommunitySaasDailyCap_TierFallback(t *testing.T) {
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })
	proxyDailyLimitChecker = func(_ context.Context, _ string, _ int, _ *sql.DB) error {
		return ErrDailyLimitExceeded
	}

	rr := httptest.NewRecorder()
	auth := &AuthResult{
		Kind:     AuthKindCommunitySaaS,
		TenantID: "cs_nil_client",
		Client:   nil, // defensive — falls back to "Free"
	}

	if !enforceCommunitySaasDailyCap(rr, auth) {
		t.Fatal("nil-client over-cap request was NOT halted — expected true")
	}

	var env rateLimitEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("response body is not the V1 envelope JSON: %v\n%s", err, rr.Body.String())
	}
	if env.Tier != "Free" {
		t.Errorf("envelope.tier = %q, want Free (defensive fallback)", env.Tier)
	}
}

// TestEnforceCommunitySaasDailyCap_TierResolution asserts the per-tier
// quota plumbing (Free=200, Pro=2000, Premium=5000 per V1 Plugin Pro
// umbrella #1958) is wired through to the checker. This is the
// post-#1882/#1903 contract — ensures we don't regress to a single
// hardcoded cap for every tenant.
func TestEnforceCommunitySaasDailyCap_TierResolution(t *testing.T) {
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })

	var capturedLimit int
	proxyDailyLimitChecker = func(_ context.Context, _ string, dailyLimit int, _ *sql.DB) error {
		capturedLimit = dailyLimit
		return nil
	}

	cases := []struct {
		tier      string
		wantLimit int
	}{
		{"Free", 200},
		{"Pro", 2000}, // V1 Plugin Pro umbrella #1958 bumped from 1,000
		{"Premium", 5000},
	}

	for _, tc := range cases {
		t.Run(tc.tier, func(t *testing.T) {
			capturedLimit = 0
			rr := httptest.NewRecorder()
			auth := &AuthResult{
				Kind:     AuthKindCommunitySaaS,
				TenantID: "cs_tier_test",
				Client:   &Client{EffectiveTier: tc.tier},
			}
			_ = enforceCommunitySaasDailyCap(rr, auth)
			if capturedLimit != tc.wantLimit {
				t.Errorf("tier=%s: dailyLimit=%d, want %d", tc.tier, capturedLimit, tc.wantLimit)
			}
		})
	}
}


// TestEnforceMCPSessionDailyCap_EmptyTierBypass asserts self-hosted /
// internal-service callers (empty tier) bypass the SaaS Plugin daily
// cap entirely. Mirrors enforceCommunitySaasDailyCap_NonCommunitySaas
// for the JSON-RPC variant.
func TestEnforceMCPSessionDailyCap_EmptyTierBypass(t *testing.T) {
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })
	proxyDailyLimitChecker = func(_ context.Context, _ string, _ int, _ *sql.DB) error {
		t.Fatal("proxyDailyLimitChecker invoked for empty-tier session — should short-circuit")
		return nil
	}

	rr := httptest.NewRecorder()
	req := &jsonRPCRequest{ID: "test-id"}
	session := &mcpSession{tenantID: "cs_t", tier: ""}

	if blocked := enforceMCPSessionDailyCap(rr, req, session); blocked {
		t.Error("empty-tier session was gate-blocked — expected bypass")
	}
}

// TestEnforceMCPSessionDailyCap_NilSession asserts nil session is
// safely handled (defensive — caller always passes non-nil session
// from requireMCPAuth, but a future regression that drops the nil
// check would panic without this guard).
func TestEnforceMCPSessionDailyCap_NilSession(t *testing.T) {
	rr := httptest.NewRecorder()
	req := &jsonRPCRequest{ID: 1}
	if enforceMCPSessionDailyCap(rr, req, nil) {
		t.Error("nil session blocked — expected false")
	}
}

// TestEnforceMCPSessionDailyCap_UnderCap asserts a SaaS Plugin tenant
// under their daily quota is allowed through (no JSON-RPC error
// written, helper returns false).
func TestEnforceMCPSessionDailyCap_UnderCap(t *testing.T) {
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })

	var capturedTenant string
	var capturedLimit int
	proxyDailyLimitChecker = func(_ context.Context, tenantID string, dailyLimit int, _ *sql.DB) error {
		capturedTenant = tenantID
		capturedLimit = dailyLimit
		return nil // under cap
	}

	rr := httptest.NewRecorder()
	req := &jsonRPCRequest{ID: "test-id"}
	session := &mcpSession{tenantID: "cs_under_cap", tier: "Free"}

	if enforceMCPSessionDailyCap(rr, req, session) {
		t.Fatal("under-cap session was halted — expected false")
	}
	if capturedTenant != "cs_under_cap" {
		t.Errorf("checker invoked with tenant=%q, want cs_under_cap", capturedTenant)
	}
	if capturedLimit != 200 {
		t.Errorf("checker invoked with dailyLimit=%d, want 200 (Free tier)", capturedLimit)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("response code = %d, want default 200", rr.Code)
	}
}

// TestEnforceMCPSessionDailyCap_OverCap asserts ErrDailyLimitExceeded
// produces a JSON-RPC error result with the V1 envelope as
// content[0].text. This is the core regression test for #1976.
func TestEnforceMCPSessionDailyCap_OverCap(t *testing.T) {
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })
	proxyDailyLimitChecker = func(_ context.Context, _ string, _ int, _ *sql.DB) error {
		return ErrDailyLimitExceeded
	}

	rr := httptest.NewRecorder()
	req := &jsonRPCRequest{ID: "over-cap-test"}
	session := &mcpSession{tenantID: "cs_over_cap", tier: "Free"}

	if !enforceMCPSessionDailyCap(rr, req, session) {
		t.Fatal("over-cap session was NOT halted — expected true (regression of #1976)")
	}

	// Wire shape: JSON-RPC result with isError=true + envelope as content[0].text
	var rpcResp struct {
		ID     interface{} `json:"id"`
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("response is not JSON-RPC: %v\n%s", err, rr.Body.String())
	}
	if rpcResp.ID != "over-cap-test" {
		t.Errorf("id = %v, want over-cap-test (request ID echo)", rpcResp.ID)
	}
	if !rpcResp.Result.IsError {
		t.Error("result.isError = false, want true")
	}
	if len(rpcResp.Result.Content) == 0 {
		t.Fatal("result.content empty")
	}

	var env rateLimitEnvelope
	if err := json.Unmarshal([]byte(rpcResp.Result.Content[0].Text), &env); err != nil {
		t.Fatalf("content[0].text not envelope JSON: %v\n%s", err, rpcResp.Result.Content[0].Text)
	}
	if env.LimitType != LimitTypeDailyQuota {
		t.Errorf("envelope.limit_type = %q, want %q", env.LimitType, LimitTypeDailyQuota)
	}
	if env.Tier != "Free" {
		t.Errorf("envelope.tier = %q, want Free", env.Tier)
	}
	if env.Limit != 200 {
		t.Errorf("envelope.limit = %d, want 200", env.Limit)
	}
	if env.Upgrade.CompareURL != v1ProUpgradeCompareURL {
		t.Errorf("envelope.upgrade.compare_url = %q, want %q", env.Upgrade.CompareURL, v1ProUpgradeCompareURL)
	}
}

// TestEnforceMCPSessionDailyCap_ProTier asserts a Pro tenant gets
// their tier-correct dailyLimit (2,000 not 1,000 — verifies the EE
// tier_support.go shadow sync from #1977).
func TestEnforceMCPSessionDailyCap_ProTier(t *testing.T) {
	original := proxyDailyLimitChecker
	t.Cleanup(func() { proxyDailyLimitChecker = original })

	var capturedLimit int
	proxyDailyLimitChecker = func(_ context.Context, _ string, dailyLimit int, _ *sql.DB) error {
		capturedLimit = dailyLimit
		return nil
	}

	rr := httptest.NewRecorder()
	req := &jsonRPCRequest{ID: 1}
	session := &mcpSession{tenantID: "cs_pro", tier: "Pro"}

	_ = enforceMCPSessionDailyCap(rr, req, session)
	if capturedLimit != 2000 {
		t.Errorf("Pro tier dailyLimit = %d, want 2000 (V1 Plugin Pro umbrella #1958)", capturedLimit)
	}
}
