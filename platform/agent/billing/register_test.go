//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStripeAllowlist_DefaultRejectsRandomIP(t *testing.T) {
	t.Setenv(stripeWebhookIPAllowlistEnv, "")
	a := loadStripeWebhookAllowlist()
	if a.allows("8.8.8.8") {
		t.Error("8.8.8.8 should be rejected by default Stripe allowlist")
	}
}

func TestStripeAllowlist_DefaultAllowsKnownStripeIP(t *testing.T) {
	t.Setenv(stripeWebhookIPAllowlistEnv, "")
	a := loadStripeWebhookAllowlist()
	if !a.allows("3.18.12.63") {
		t.Error("known Stripe IP 3.18.12.63 should be allowed by default")
	}
}

func TestStripeAllowlist_WildcardOverride_AllowsAll(t *testing.T) {
	t.Setenv(stripeWebhookIPAllowlistEnv, "*")
	a := loadStripeWebhookAllowlist()
	if !a.allows("8.8.8.8") {
		t.Error("wildcard should allow any IP")
	}
	if !a.disabled {
		t.Error("wildcard override should set disabled=true")
	}
}

func TestStripeAllowlist_CustomCIDR(t *testing.T) {
	t.Setenv(stripeWebhookIPAllowlistEnv, "10.0.0.0/8,192.168.1.5/32")
	a := loadStripeWebhookAllowlist()
	if !a.allows("10.0.0.7") {
		t.Error("10.0.0.7 should be in 10.0.0.0/8")
	}
	if !a.allows("192.168.1.5") {
		t.Error("192.168.1.5 should be in /32")
	}
	if a.allows("8.8.8.8") {
		t.Error("8.8.8.8 should be rejected against custom allowlist")
	}
}

func TestStripeAllowlist_MalformedCIDRSkipped(t *testing.T) {
	t.Setenv(stripeWebhookIPAllowlistEnv, "not-a-cidr,10.0.0.0/8")
	a := loadStripeWebhookAllowlist()
	if !a.allows("10.0.0.1") {
		t.Error("good CIDR should still allow despite malformed sibling")
	}
}

func TestStripeAllowlist_ZeroSlashZeroDisables(t *testing.T) {
	t.Setenv(stripeWebhookIPAllowlistEnv, "0.0.0.0/0")
	a := loadStripeWebhookAllowlist()
	if !a.disabled {
		t.Error("0.0.0.0/0 should set disabled=true (full open)")
	}
	if !a.allows("8.8.8.8") {
		t.Error("disabled allowlist should accept any IP")
	}
}

func TestStripeIPTracker_AllowsBelowLimit(t *testing.T) {
	tr := newStripeIPTracker(3)
	for i := 0; i < 3; i++ {
		if !tr.allow("1.2.3.4") {
			t.Errorf("attempt %d should be allowed under limit 3", i+1)
		}
	}
}

func TestStripeIPTracker_RejectsAboveLimit(t *testing.T) {
	tr := newStripeIPTracker(2)
	tr.allow("1.2.3.4")
	tr.allow("1.2.3.4")
	if tr.allow("1.2.3.4") {
		t.Error("3rd request from same IP at limit=2 should be rejected")
	}
}

func TestStripeIPTracker_DistinctIPsTrackedSeparately(t *testing.T) {
	tr := newStripeIPTracker(1)
	if !tr.allow("1.2.3.4") {
		t.Error("1.2.3.4 first call should pass")
	}
	if !tr.allow("5.6.7.8") {
		t.Error("5.6.7.8 first call should pass even though 1.2.3.4 is at limit")
	}
}

func TestStripeIPTracker_ZeroLimitDisablesTracking(t *testing.T) {
	tr := newStripeIPTracker(0)
	for i := 0; i < 1000; i++ {
		if !tr.allow("1.2.3.4") {
			t.Fatal("zero limit should always allow")
		}
	}
}

func TestExtractStripeWebhookIP_RemoteAddrFallback(t *testing.T) {
	t.Setenv("AXONFLOW_TRUST_PROXY", "")
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.RemoteAddr = "203.0.113.5:54321"
	if got := extractStripeWebhookIP(r); got != "203.0.113.5" {
		t.Errorf("got %q, want 203.0.113.5", got)
	}
}

func TestExtractStripeWebhookIP_TrustsXForwardedForOnlyWhenEnabled(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.99, 10.0.0.50")

	t.Setenv("AXONFLOW_TRUST_PROXY", "")
	if got := extractStripeWebhookIP(r); got != "10.0.0.1" {
		t.Errorf("trust=off: got %q, want 10.0.0.1 (RemoteAddr)", got)
	}

	t.Setenv("AXONFLOW_TRUST_PROXY", "1")
	if got := extractStripeWebhookIP(r); got != "203.0.113.99" {
		t.Errorf("trust=on: got %q, want 203.0.113.99 (XFF first hop)", got)
	}
}

// TestExtractStripeWebhookIP_XRealIPRequiresTrustProxy proves the security
// gate: X-Real-IP must NOT be honored without AXONFLOW_TRUST_PROXY=1. Without
// this, an attacker reaching the agent directly (bypassing ALB) could spoof
// any Stripe IP via "X-Real-IP: 3.18.12.63" and pass the allowlist.
func TestExtractStripeWebhookIP_XRealIPRequiresTrustProxy(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.RemoteAddr = "8.8.8.8:1234"           // attacker source IP
	r.Header.Set("X-Real-IP", "3.18.12.63") // spoofed Stripe IP

	t.Setenv("AXONFLOW_TRUST_PROXY", "")
	if got := extractStripeWebhookIP(r); got != "8.8.8.8" {
		t.Errorf("trust=off: X-Real-IP must NOT be honored — got %q, want RemoteAddr 8.8.8.8 (header injection bypass)", got)
	}

	t.Setenv("AXONFLOW_TRUST_PROXY", "1")
	if got := extractStripeWebhookIP(r); got != "3.18.12.63" {
		t.Errorf("trust=on: X-Real-IP should be honored — got %q, want 3.18.12.63", got)
	}
}

func TestStripeWebhookGuard_RejectsIPNotInAllowlist(t *testing.T) {
	allowlist := &stripeAllowlist{disabled: false}
	tracker := newStripeIPTracker(0)
	wrapped := stripeWebhookGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not be reached when IP rejected")
	}), allowlist, tracker)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/billing/stripe-webhook", nil)
	r.RemoteAddr = "8.8.8.8:1234"
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestStripeWebhookGuard_RejectsRateLimitExceeded(t *testing.T) {
	allowlist := &stripeAllowlist{disabled: true}
	tracker := newStripeIPTracker(1)
	tracker.allow("1.2.3.4")

	wrapped := stripeWebhookGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("inner handler should not be reached when rate-limited")
	}), allowlist, tracker)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/billing/stripe-webhook", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}
}

func TestStripeWebhookGuard_PassesThroughWhenChecksOK(t *testing.T) {
	allowlist := &stripeAllowlist{disabled: true}
	tracker := newStripeIPTracker(0)
	called := false
	wrapped := stripeWebhookGuard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), allowlist, tracker)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/billing/stripe-webhook", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, r)
	if !called {
		t.Error("inner handler should be reached when guard passes")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestLoadStripeWebhookRateLimit_DefaultWhenUnset(t *testing.T) {
	t.Setenv(stripeWebhookRateLimitEnv, "")
	if got := loadStripeWebhookRateLimit(); got != stripeWebhookDefaultRateLimit {
		t.Errorf("default: got %d, want %d", got, stripeWebhookDefaultRateLimit)
	}
}

func TestLoadStripeWebhookRateLimit_OverrideHonored(t *testing.T) {
	t.Setenv(stripeWebhookRateLimitEnv, "120")
	if got := loadStripeWebhookRateLimit(); got != 120 {
		t.Errorf("got %d, want 120", got)
	}
}

func TestLoadStripeWebhookRateLimit_InvalidFallsBackToDefault(t *testing.T) {
	t.Setenv(stripeWebhookRateLimitEnv, "abc")
	if got := loadStripeWebhookRateLimit(); got != stripeWebhookDefaultRateLimit {
		t.Errorf("invalid: got %d, want default %d", got, stripeWebhookDefaultRateLimit)
	}
}

func TestParseNonNegInt(t *testing.T) {
	good := map[string]int{"0": 0, "1": 1, "60": 60, "12345": 12345}
	for s, want := range good {
		got, err := parseNonNegInt(s)
		if err != nil || got != want {
			t.Errorf("parseNonNegInt(%q) = (%d, %v); want (%d, nil)", s, got, err, want)
		}
	}
	for _, s := range []string{"-1", "abc", "1.0", "", "12a"} {
		if _, err := parseNonNegInt(s); err == nil {
			t.Errorf("parseNonNegInt(%q) should error", s)
		}
	}
}
