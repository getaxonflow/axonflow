// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMinuteLimitForTier_Free(t *testing.T) {
	if got := minuteLimitForTier("Free"); got != 25 {
		t.Errorf("minuteLimitForTier(Free) = %d, want 25", got)
	}
}

func TestMinuteLimitForTier_Pro(t *testing.T) {
	if got := minuteLimitForTier("Pro"); got != 200 {
		t.Errorf("minuteLimitForTier(Pro) = %d, want 200", got)
	}
}

func TestMinuteLimitForTier_Premium(t *testing.T) {
	if got := minuteLimitForTier("Premium"); got != 200 {
		t.Errorf("minuteLimitForTier(Premium) = %d, want 200", got)
	}
}

func TestMinuteLimitForTier_Empty(t *testing.T) {
	if got := minuteLimitForTier(""); got != 25 {
		t.Errorf("minuteLimitForTier(\"\") = %d, want 25 (Free default)", got)
	}
}

func TestMinuteLimitForTier_Unknown(t *testing.T) {
	if got := minuteLimitForTier("Enterprise"); got != 25 {
		t.Errorf("minuteLimitForTier(Enterprise) = %d, want 25 (default)", got)
	}
}

func TestMinuteLimitForTenant_NilClient(t *testing.T) {
	if got := minuteLimitForTenant(nil); got != 25 {
		t.Errorf("minuteLimitForTenant(nil) = %d, want 25", got)
	}
}

func TestMinuteLimitForTenant_EmptyTier(t *testing.T) {
	c := &Client{EffectiveTier: ""}
	if got := minuteLimitForTenant(c); got != 25 {
		t.Errorf("minuteLimitForTenant(empty tier) = %d, want 25", got)
	}
}

func TestMinuteLimitForTenant_ProTier(t *testing.T) {
	c := &Client{EffectiveTier: "Pro"}
	if got := minuteLimitForTenant(c); got != 200 {
		t.Errorf("minuteLimitForTenant(Pro) = %d, want 200", got)
	}
}

func TestRateLimitCount_NoRedis_UnknownKey(t *testing.T) {
	if got := rateLimitCount("nonexistent-tenant-xyz"); got != 0 {
		t.Errorf("rateLimitCount(unknown) = %d, want 0", got)
	}
}

func TestRateLimitCount_NoRedis_PopulatedKey(t *testing.T) {
	key := "test-rl-count-populated"
	rateLimitMu.Lock()
	rateLimitMap[key] = &RateLimitEntry{
		Count:     15,
		ResetTime: time.Now().Add(30 * time.Second),
	}
	rateLimitMu.Unlock()
	defer func() {
		rateLimitMu.Lock()
		delete(rateLimitMap, key)
		rateLimitMu.Unlock()
	}()

	if got := rateLimitCount(key); got != 15 {
		t.Errorf("rateLimitCount(%s) = %d, want 15", key, got)
	}
}

func TestEnforceCommunitySaasDailyCap_PerMinuteBlock(t *testing.T) {
	key := "cs_per_minute_block_test"
	rateLimitMu.Lock()
	rateLimitMap[key] = &RateLimitEntry{
		Count:     100,
		ResetTime: time.Now().Add(30 * time.Second),
	}
	rateLimitMu.Unlock()
	defer func() {
		rateLimitMu.Lock()
		delete(rateLimitMap, key)
		rateLimitMu.Unlock()
	}()

	rr := httptest.NewRecorder()
	auth := &AuthResult{
		Kind:     AuthKindCommunitySaaS,
		TenantID: key,
		Client:   &Client{EffectiveTier: "Free"},
	}
	if !enforceCommunitySaasDailyCap(rr, auth) {
		t.Fatal("expected per-minute block for count=100 > Free limit=25")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rr.Code)
	}
}

func TestEnforceCommunitySaasDailyCap_PerMinutePass_Pro(t *testing.T) {
	key := "cs_per_minute_pass_pro_test"
	rateLimitMu.Lock()
	rateLimitMap[key] = &RateLimitEntry{
		Count:     50,
		ResetTime: time.Now().Add(30 * time.Second),
	}
	rateLimitMu.Unlock()
	defer func() {
		rateLimitMu.Lock()
		delete(rateLimitMap, key)
		rateLimitMu.Unlock()
	}()

	oldChecker := proxyDailyLimitChecker
	proxyDailyLimitChecker = func(ctx context.Context, tenantID string, dailyLimit int, db *sql.DB) error {
		return nil
	}
	defer func() { proxyDailyLimitChecker = oldChecker }()

	rr := httptest.NewRecorder()
	auth := &AuthResult{
		Kind:     AuthKindCommunitySaaS,
		TenantID: key,
		Client:   &Client{EffectiveTier: "Pro"},
	}
	if enforceCommunitySaasDailyCap(rr, auth) {
		t.Fatal("Pro user at count=50 should pass per-minute (limit=200)")
	}
}

func TestRateLimitCount_NoRedis_ExpiredKey(t *testing.T) {
	key := "test-rl-count-expired"
	rateLimitMu.Lock()
	rateLimitMap[key] = &RateLimitEntry{
		Count:     99,
		ResetTime: time.Now().Add(-10 * time.Second),
	}
	rateLimitMu.Unlock()
	defer func() {
		rateLimitMu.Lock()
		delete(rateLimitMap, key)
		rateLimitMu.Unlock()
	}()

	if got := rateLimitCount(key); got != 0 {
		t.Errorf("rateLimitCount(%s) = %d, want 0 (expired)", key, got)
	}
}
