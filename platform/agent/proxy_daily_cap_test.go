//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Per-tenant SaaS Plugin tier resolution (Free=200, Pro=1000, Premium=5000)
// is wired only in the enterprise build (platform/agent/license/tier_support.go,
// build-tagged enterprise). The community build's GetTierLimits falls through
// to CommunityLimits (DailyEventQuota=-1, n/a) and dailyLimitForTenant uses
// the COMMUNITY_SAAS_DAILY_LIMIT env-var fallback for everyone — there is
// no per-tenant differentiation to assert. Gate this test file accordingly
// so the assertions reflect a real product behavior on the build that ships
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
// from the checker produces an HTTP 429 with the expected JSON body and
// halts the request. This is the core regression test for #1921 — without
// the proxy-side mirror, this 429 would never fire on /api/v1/process,
// /api/v1/audit/*, /api/v1/mcp/evaluate-policies, or /api/v1/connectors.
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
		Client:   &Client{EffectiveTier: "Pro"}, // any tier — checker returns over-cap regardless
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

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v\n%s", err, rr.Body.String())
	}
	if got := body["error"]; got != "Daily request limit reached. Resets at midnight UTC." {
		t.Errorf("error message = %q, want exact 'Daily request limit reached. Resets at midnight UTC.'", got)
	}
}

// TestEnforceCommunitySaasDailyCap_TierResolution asserts the per-tier
// quota plumbing (Free=200, Pro=1000, Premium=5000) is wired through
// to the checker. This is the post-#1882/#1903 contract — ensures we
// don't regress to a single hardcoded cap for every tenant.
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
		{"Pro", 1000},
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

