// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestWriteRateLimitError_EnvelopeShape asserts the V1 Plugin Pro 429
// envelope contains every locked field per umbrella #1958. This is the
// single source-of-truth test — every plugin parser (S3 lane) must be
// able to consume this exact shape.
func TestWriteRateLimitError_EnvelopeShape(t *testing.T) {
	rr := httptest.NewRecorder()
	writeRateLimitError(rr, "cs_test_tenant", "Free", 200)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != LimitTypeDailyQuota {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, LimitTypeDailyQuota)
	}
	if got := rr.Header().Get("X-Axonflow-Upgrade-URL"); got != v1ProUpgradeCompareURL {
		t.Errorf("X-Axonflow-Upgrade-URL = %q, want %q", got, v1ProUpgradeCompareURL)
	}
	retryAfter := rr.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("Retry-After header missing")
	}
	if n, err := strconv.Atoi(retryAfter); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want positive integer seconds", retryAfter)
	}

	var env rateLimitEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not valid envelope JSON: %v\n%s", err, rr.Body.String())
	}
	if env.Error == "" {
		t.Error("envelope.error is empty")
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
	if env.Remaining != 0 {
		t.Errorf("envelope.remaining = %d, want 0", env.Remaining)
	}
	if env.Window != "daily_utc" {
		t.Errorf("envelope.window = %q, want daily_utc", env.Window)
	}
	if env.ResetsAt == nil {
		t.Fatal("envelope.resets_at is nil; want non-nil for daily_quota")
	}
	if !env.ResetsAt.After(time.Now()) {
		t.Errorf("envelope.resets_at = %v is not in the future", env.ResetsAt)
	}
	if env.Upgrade.Tier != "Pro" {
		t.Errorf("envelope.upgrade.tier = %q, want Pro", env.Upgrade.Tier)
	}
	if env.Upgrade.CompareURL != v1ProUpgradeCompareURL {
		t.Errorf("envelope.upgrade.compare_url = %q, want %q", env.Upgrade.CompareURL, v1ProUpgradeCompareURL)
	}
	if env.Upgrade.BuyURL != v1ProUpgradeBuyURL {
		t.Errorf("envelope.upgrade.buy_url = %q, want %q", env.Upgrade.BuyURL, v1ProUpgradeBuyURL)
	}
	if env.Upgrade.Wording == "" {
		t.Error("envelope.upgrade.wording is empty")
	}
	if !strings.Contains(env.Upgrade.Wording, "Pro raises this to 2,000/day") {
		t.Errorf("envelope.upgrade.wording missing locked phrase 'Pro raises this to 2,000/day'; got %q", env.Upgrade.Wording)
	}
}

// TestWriteRateLimitError_TierPassthrough asserts the tier label is carried
// verbatim through the envelope. Future analytics will join on this field;
// silently coercing "Free" → "free" or "Premium" → "premium" would break
// downstream consumers.
func TestWriteRateLimitError_TierPassthrough(t *testing.T) {
	for _, tier := range []string{"Free", "Pro", "Premium", "Enterprise", "custom-tier-name"} {
		t.Run(tier, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeRateLimitError(rr, "cs_t", tier, 200)
			var env rateLimitEnvelope
			if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if env.Tier != tier {
				t.Errorf("envelope.tier = %q, want %q", env.Tier, tier)
			}
		})
	}
}

// TestWriteRateLimitError_LimitPassthrough asserts the limit value is
// carried verbatim. Plugins display "X of Y" indicators and need the
// real cap, not a hardcoded 200.
func TestWriteRateLimitError_LimitPassthrough(t *testing.T) {
	for _, limit := range []int{200, 2000, 5000, 100000} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeRateLimitError(rr, "cs_t", "Free", limit)
			var env rateLimitEnvelope
			if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if env.Limit != limit {
				t.Errorf("envelope.limit = %d, want %d", env.Limit, limit)
			}
		})
	}
}

// TestWriteFreeLimitError_ActivePolicies asserts the 403 envelope shape
// for the object-count graduated limit. No window, no resets_at, no
// Retry-After header (delete-to-create-again has no clock).
func TestWriteFreeLimitError_ActivePolicies(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFreeLimitError(rr, LimitTypeActivePolicies, "Free", 2, 0, "", nil)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != LimitTypeActivePolicies {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, LimitTypeActivePolicies)
	}
	if got := rr.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q, want empty (no clock for object-count limits)", got)
	}

	var env rateLimitEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.LimitType != LimitTypeActivePolicies {
		t.Errorf("limit_type = %q, want %q", env.LimitType, LimitTypeActivePolicies)
	}
	if env.Limit != 2 {
		t.Errorf("limit = %d, want 2", env.Limit)
	}
	if env.Window != "" {
		t.Errorf("window = %q, want empty for active_policies", env.Window)
	}
	if env.ResetsAt != nil {
		t.Errorf("resets_at = %v, want nil for object-count limits", env.ResetsAt)
	}
	if !strings.Contains(env.Upgrade.Wording, "2 active custom policies") {
		t.Errorf("wording missing locked active_policies phrase; got %q", env.Upgrade.Wording)
	}
}

// TestWriteFreeLimitError_HITLWindow asserts the 403 envelope for the
// rolling-window graduated limit. Has window + resets_at + Retry-After
// (clients should back off until the window rolls).
func TestWriteFreeLimitError_HITLWindow(t *testing.T) {
	resetsAt := time.Now().Add(3*24*time.Hour + 12*time.Hour) // ~3.5 days out
	rr := httptest.NewRecorder()
	writeFreeLimitError(rr, LimitTypeHITLApprovalsWindow, "Free", 1, 0, "rolling_7d", &resetsAt)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != LimitTypeHITLApprovalsWindow {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, LimitTypeHITLApprovalsWindow)
	}
	retryAfter := rr.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("Retry-After header missing for hitl_approvals_window")
	}
	if n, err := strconv.Atoi(retryAfter); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want positive integer seconds", retryAfter)
	}

	var env rateLimitEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.LimitType != LimitTypeHITLApprovalsWindow {
		t.Errorf("limit_type = %q, want %q", env.LimitType, LimitTypeHITLApprovalsWindow)
	}
	if env.Window != "rolling_7d" {
		t.Errorf("window = %q, want rolling_7d", env.Window)
	}
	if env.ResetsAt == nil {
		t.Fatal("resets_at is nil; want non-nil for hitl_approvals_window")
	}
	if !strings.Contains(env.Upgrade.Wording, "1 of 1 HITL approvals used") {
		t.Errorf("wording missing locked HITL phrase; got %q", env.Upgrade.Wording)
	}
	// Wording should have the relative-time placeholder filled in (not literal "%s")
	if strings.Contains(env.Upgrade.Wording, "%s") {
		t.Errorf("wording still has unfilled placeholder: %q", env.Upgrade.Wording)
	}
}

// TestWriteFreeLimitError_FeatureProOnly asserts the 403 envelope for
// the binary Pro-only feature gate. No clock, no window, no Retry-After.
func TestWriteFreeLimitError_FeatureProOnly(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFreeLimitError(rr, LimitTypeFeatureProOnly, "Free", 0, 0, "", nil)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After = %q, want empty (no clock for feature_pro_only)", got)
	}

	var env rateLimitEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.LimitType != LimitTypeFeatureProOnly {
		t.Errorf("limit_type = %q, want %q", env.LimitType, LimitTypeFeatureProOnly)
	}
	if env.ResetsAt != nil {
		t.Errorf("resets_at = %v, want nil for feature_pro_only", env.ResetsAt)
	}
	if !strings.Contains(env.Upgrade.Wording, "Pro feature") {
		t.Errorf("wording missing locked feature_pro_only phrase; got %q", env.Upgrade.Wording)
	}
}

// TestRenderWording_AllLimitTypes asserts every locked limit_type renders
// a non-empty wording with the expected anchor phrase. Catches any
// future addition that forgets to thread through.
func TestRenderWording_AllLimitTypes(t *testing.T) {
	resetsAt := time.Now().Add(7 * 24 * time.Hour)
	cases := []struct {
		limitType string
		anchor    string
	}{
		{LimitTypeDailyQuota, "2,000/day"},
		{LimitTypeActivePolicies, "2 active custom policies"},
		{LimitTypeHITLApprovalsWindow, "HITL approvals"},
		{LimitTypeFeatureProOnly, "Pro feature"},
	}
	for _, tc := range cases {
		t.Run(tc.limitType, func(t *testing.T) {
			got := renderWording(tc.limitType, &resetsAt)
			if got == "" {
				t.Errorf("renderWording(%q) = empty", tc.limitType)
			}
			if !strings.Contains(got, tc.anchor) {
				t.Errorf("renderWording(%q) = %q, missing anchor %q", tc.limitType, got, tc.anchor)
			}
			if strings.Contains(got, "%s") {
				t.Errorf("renderWording(%q) = %q, unfilled placeholder", tc.limitType, got)
			}
		})
	}
}

// TestRenderWording_UnknownLimitType asserts unknown limit types fall
// through to a safe default rather than panicking.
func TestRenderWording_UnknownLimitType(t *testing.T) {
	got := renderWording("not_a_real_limit_type", nil)
	if got == "" {
		t.Error("renderWording(unknown) = empty; want safe fallback")
	}
}

// TestHumanizeRelativeTime covers the rendering matrix.
func TestHumanizeRelativeTime(t *testing.T) {
	cases := []struct {
		name string
		in   *time.Time
		want string
	}{
		{"nil", nil, "soon"},
		{"past", ptrTime(time.Now().Add(-1 * time.Hour)), "soon"},
		{"30min", ptrTime(time.Now().Add(30 * time.Minute)), "in less than 1 hour"},
		{"1h_exact", ptrTime(time.Now().Add(1*time.Hour + 30*time.Second)), "in 1 hour"},
		{"5h", ptrTime(time.Now().Add(5*time.Hour + 30*time.Second)), "in 5 hours"},
		{"1d_exact", ptrTime(time.Now().Add(24*time.Hour + 30*time.Second)), "in 1 day"},
		{"1d_3h", ptrTime(time.Now().Add(27*time.Hour + 30*time.Second)), "in 1 day 3 hours"},
		{"3d_exact", ptrTime(time.Now().Add(72*time.Hour + 30*time.Second)), "in 3 days"},
		{"6d_5h", ptrTime(time.Now().Add(149*time.Hour + 30*time.Second)), "in 6 days 5 hours"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := humanizeRelativeTime(tc.in)
			if got != tc.want {
				t.Errorf("humanizeRelativeTime(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNextUTCMidnightForRateLimit asserts the helper returns a time
// strictly in the future and falls on a UTC midnight boundary.
func TestNextUTCMidnightForRateLimit(t *testing.T) {
	got := nextUTCMidnightForRateLimit()
	if !got.After(time.Now()) {
		t.Errorf("nextUTCMidnightForRateLimit() = %v is not in the future", got)
	}
	if got.Hour() != 0 || got.Minute() != 0 || got.Second() != 0 || got.Nanosecond() != 0 {
		t.Errorf("nextUTCMidnightForRateLimit() = %v, not on a midnight boundary", got)
	}
	if got.Location() != time.UTC {
		t.Errorf("nextUTCMidnightForRateLimit() location = %v, want UTC", got.Location())
	}
}

// TestRetryAfterSeconds covers the boundary-flooring behavior.
func TestRetryAfterSeconds(t *testing.T) {
	cases := []struct {
		name     string
		offset   time.Duration
		wantMin  int
		wantMax  int
	}{
		{"past", -10 * time.Second, 1, 1},
		{"sub_second", 100 * time.Millisecond, 1, 1},
		{"5s", 5 * time.Second, 4, 5},
		{"1h", 1 * time.Hour, 3590, 3600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := retryAfterSeconds(time.Now().Add(tc.offset))
			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("retryAfterSeconds(now+%v) = %d, want [%d,%d]", tc.offset, got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

// TestEnvelopeJSONFieldOrder is a regression guard: the locked envelope
// shape per umbrella #1958 must serialize with these exact JSON keys.
// Spelling matters — every plugin parser keys by literal string.
func TestEnvelopeJSONFieldOrder(t *testing.T) {
	rr := httptest.NewRecorder()
	writeRateLimitError(rr, "cs_t", "Free", 200)

	body := rr.Body.String()
	wantKeys := []string{
		`"error":`,
		`"limit_type":"daily_quota"`,
		`"tier":"Free"`,
		`"limit":200`,
		`"remaining":0`,
		`"window":"daily_utc"`,
		`"resets_at":`,
		`"upgrade":`,
		`"compare_url":"https://getaxonflow.com/pricing/"`,
		`"buy_url":"https://buy.stripe.com/bJe28qbztcdVchjdkw8k800"`,
	}
	for _, k := range wantKeys {
		if !strings.Contains(body, k) {
			t.Errorf("envelope body missing locked key %q\nbody: %s", k, body)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// TestWriteRateLimitErrorJSONRPC_EnvelopeShape covers the JSON-RPC
// wrapper added in #1977 to fix the #1976 MCP gap. Asserts the
// envelope rides correctly inside `result.content[0].text` with
// `isError: true` so plugin parsers see the same shape as the HTTP
// 429 path. Headers locked verbatim against the HTTP variant.
func TestWriteRateLimitErrorJSONRPC_EnvelopeShape(t *testing.T) {
	rr := httptest.NewRecorder()
	writeRateLimitErrorJSONRPC(rr, "test-id", "cs_test_tenant", "Free", 200)

	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != LimitTypeDailyQuota {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, LimitTypeDailyQuota)
	}
	if got := rr.Header().Get("X-Axonflow-Upgrade-URL"); got != v1ProUpgradeCompareURL {
		t.Errorf("X-Axonflow-Upgrade-URL = %q, want %q", got, v1ProUpgradeCompareURL)
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header missing")
	}

	// Wire shape: {"jsonrpc":"2.0","id":"test-id","result":{"content":[{"type":"text","text":"<envelope>"}],"isError":true}}
	var rpcResp struct {
		JSONRPC string      `json:"jsonrpc"`
		ID      interface{} `json:"id"`
		Result  struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("body is not valid JSON-RPC: %v\n%s", err, rr.Body.String())
	}
	if rpcResp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", rpcResp.JSONRPC)
	}
	if rpcResp.ID != "test-id" {
		t.Errorf("id = %v, want test-id", rpcResp.ID)
	}
	if !rpcResp.Result.IsError {
		t.Error("result.isError = false, want true")
	}
	if len(rpcResp.Result.Content) != 1 {
		t.Fatalf("content len = %d, want 1", len(rpcResp.Result.Content))
	}
	if rpcResp.Result.Content[0].Type != "text" {
		t.Errorf("content[0].type = %q, want text", rpcResp.Result.Content[0].Type)
	}

	// content[0].text must parse as the V1 envelope
	var env rateLimitEnvelope
	if err := json.Unmarshal([]byte(rpcResp.Result.Content[0].Text), &env); err != nil {
		t.Fatalf("content[0].text is not valid envelope JSON: %v\n%s", err, rpcResp.Result.Content[0].Text)
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
	if env.Upgrade.BuyURL != v1ProUpgradeBuyURL {
		t.Errorf("envelope.upgrade.buy_url = %q, want %q", env.Upgrade.BuyURL, v1ProUpgradeBuyURL)
	}
}

// TestWriteRateLimitErrorJSONRPC_TierPassthrough asserts the tier
// label passes verbatim through the JSON-RPC envelope.
func TestWriteRateLimitErrorJSONRPC_TierPassthrough(t *testing.T) {
	for _, tier := range []string{"Free", "Pro", "Premium"} {
		t.Run(tier, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeRateLimitErrorJSONRPC(rr, 42, "cs_t", tier, 2000)
			var rpcResp struct {
				Result struct {
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"result"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &rpcResp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			var env rateLimitEnvelope
			if err := json.Unmarshal([]byte(rpcResp.Result.Content[0].Text), &env); err != nil {
				t.Fatalf("envelope decode: %v", err)
			}
			if env.Tier != tier {
				t.Errorf("envelope.tier = %q, want %q", env.Tier, tier)
			}
		})
	}
}

// TestWriteRateLimitErrorJSONRPC_LimitPassthrough asserts the limit
// value rides through verbatim. Pro buyers MUST see their actual cap
// (2,000), not a stale heuristic.
func TestWriteRateLimitErrorJSONRPC_LimitPassthrough(t *testing.T) {
	for _, limit := range []int{200, 2000, 5000} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeRateLimitErrorJSONRPC(rr, 1, "cs_t", "Pro", limit)
			var rpcResp struct {
				Result struct {
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"result"`
			}
			_ = json.Unmarshal(rr.Body.Bytes(), &rpcResp)
			var env rateLimitEnvelope
			_ = json.Unmarshal([]byte(rpcResp.Result.Content[0].Text), &env)
			if env.Limit != limit {
				t.Errorf("envelope.limit = %d, want %d", env.Limit, limit)
			}
		})
	}
}

// TestDailyLimitForTier_EmptyFallback asserts the by-tier-string daily-
// limit resolver falls through to the env-var fallback (default 500)
// when given an empty tier. This is the only assertion that runs in
// the community build — SaaS Plugin tier values (Free/Pro/Premium) are
// enterprise-build-only, asserted in the enterprise-tagged sibling
// file (community_saas_ratelimit_response_enterprise_test.go).
func TestDailyLimitForTier_EmptyFallback(t *testing.T) {
	if got := dailyLimitForTier(""); got <= 0 {
		t.Errorf("dailyLimitForTier(\"\") = %d, want positive fallback", got)
	}
}

// TestWriteRateLimitError_AuditLogEmit asserts the daily-quota 429 path
// logs a discriminating `[CSAAS-RL] daily_quota …` line on every
// throttle. Pre-fix this site emitted the 429 silently — only the
// encode-failure branch logged — and the daily-report's agent-log
// grep over the agent log group produced 0 hits while the ALB served
// thousands of 429s. Without this regression assertion, a future edit
// that drops or rewords the log line would re-open the same blind spot.
//
// `[CSAAS-RL]` is the common prefix all community-saas rate-limit
// emit sites (per_minute, daily_quota, hitl_pending_limit) share so
// daily-report tooling + CW alarms grep one pattern.
func TestWriteRateLimitError_AuditLogEmit(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	rr := httptest.NewRecorder()
	writeRateLimitError(rr, "cs_test_tenant_log_emit", "Free", 200)

	got := buf.String()
	if !strings.Contains(got, "[CSAAS-RL] daily_quota") {
		t.Errorf("expected `[CSAAS-RL] daily_quota` prefix in log; got:\n%s", got)
	}
	if !strings.Contains(got, "tenant=cs_test_tenant_log_emit") {
		t.Errorf("expected tenant=cs_test_tenant_log_emit in log; got:\n%s", got)
	}
	if !strings.Contains(got, "tier=Free") {
		t.Errorf("expected tier=Free in log; got:\n%s", got)
	}
	if !strings.Contains(got, "limit=200") {
		t.Errorf("expected limit=200 in log; got:\n%s", got)
	}
	if !strings.Contains(got, "retry_after=") {
		t.Errorf("expected retry_after= in log; got:\n%s", got)
	}
}
