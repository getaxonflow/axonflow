// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// V1 Plugin Pro structured upgrade-prompt envelope.
//
// Every customer-facing limit hit (429 daily-quota, 403 graduated/Pro-only)
// emits the same envelope shape so plugins can parse one response shape
// across all rejection paths and surface a consistent upgrade UX.
//
// Locked per umbrella getaxonflow/axonflow-enterprise#1958 + PRD_TENANT_DURABILITY_AND_CLAIM
// §"Customer-facing copy — locked wording (V1)". Tone: Pro removes the caps
// when AxonFlow becomes part of the user's real workflow. Never coercive,
// never "denied" / "forbidden" / "unauthorized".

package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// V1 Plugin Pro upgrade-prompt URLs (locked per umbrella #1958). These appear
// verbatim in:
//   - 429 / 403 response body upgrade.compare_url + upgrade.buy_url
//   - X-Axonflow-Upgrade-URL response header
//   - License-issuance email body (mirrored at platform/agent/billing/email.go)
//   - Stripe Live Plugin Pro product description (mirrored on Stripe Dashboard)
//   - Landing pricing.html Buy Plugin Pro button (mirrored at axonflow-landing)
//
// Changes here are part of the 6-surface drift checklist per
// `feedback_cross_surface_drift_check_categorized.md` — every edit needs a
// matching update on the other 5 surfaces in the same release train.
const (
	v1ProUpgradeCompareURL = "https://getaxonflow.com/pricing/"
	v1ProUpgradeBuyURL     = "https://buy.stripe.com/bJe28qbztcdVchjdkw8k800"
)

// Locked V1 limit-type identifiers per umbrella #1958. Used as both the
// envelope `limit_type` field and the X-Axonflow-Tier-Limit response header.
const (
	LimitTypeDailyQuota          = "daily_quota"
	LimitTypeActivePolicies      = "active_policies"
	LimitTypeHITLApprovalsWindow = "hitl_approvals_window"
	LimitTypeFeatureProOnly      = "feature_pro_only"
)

// Locked V1 wordings per umbrella #1958 + PRD §"Customer-facing copy —
// locked wording (V1)". Each wording fits under 200 chars so it works as
// both an inline plugin toast/CLI string AND the structured `error` field.
//
// hitl_approvals_window has a single %s placeholder filled at render time
// with a humanized "in X days" relative-time string derived from resets_at.
const (
	wordingDailyQuota          = "Daily limit reached on Free tier (200 events). Pro raises this to 2,000/day. Resets at midnight UTC."
	wordingActivePolicies      = "Free tier supports 2 active custom policies. Delete one to make room, or Pro removes the cap."
	wordingHITLApprovalsWindow = "1 of 1 HITL approvals used in the last 7 days. Next available %s. Pro removes this cap."
	wordingFeatureProOnly      = "LLM cost pre-flight is a Pro feature — see what a multi-step plan will cost before it runs."
)

// rateLimitEnvelope is the structured response body emitted on every
// V1 Plugin Pro Free-tier limit hit (429 daily-quota, 403 graduated /
// Pro-only). Locked shape per umbrella #1958 — DO NOT reshape without
// updating PRD_TENANT_DURABILITY_AND_CLAIM §"Customer-facing copy" and
// the four plugin-side parsers (S3 lane).
//
// Field semantics:
//   - error: short human-readable message (matches `upgrade.wording` for
//     graduated/Pro-only paths so simple parsers reading either field
//     get the same string)
//   - limit_type: one of LimitType* constants
//   - tier: caller's effective tier ("Free" expected; carried so future
//     metrics / analytics can join on tier without a separate lookup)
//   - limit: the cap value (200 for daily_quota Free, 2 for active_policies,
//     1 for hitl_approvals_window)
//   - remaining: typically 0 at the wall; surfaced so plugins can render
//     "X of Y used" indicators continuously, not just on the wall
//   - window: "daily_utc" for daily_quota, "rolling_7d" for hitl_approvals_window,
//     omitted for active_policies + feature_pro_only (object-count limits +
//     binary feature gates have no time window)
//   - resets_at: RFC3339 timestamp when the limit clears; nil/omitted for
//     object-count limits + feature_pro_only
//   - upgrade: the upgrade prompt block (see upgradeBlock)
type rateLimitEnvelope struct {
	Error     string       `json:"error"`
	LimitType string       `json:"limit_type"`
	Tier      string       `json:"tier"`
	Limit     int          `json:"limit"`
	Remaining int          `json:"remaining"`
	Window    string       `json:"window,omitempty"`
	ResetsAt  *time.Time   `json:"resets_at,omitempty"`
	Upgrade   upgradeBlock `json:"upgrade"`
}

// upgradeBlock carries the upgrade-prompt content. Same shape across every
// V1 envelope path so plugins implement one parser.
type upgradeBlock struct {
	Tier       string `json:"tier"`
	Wording    string `json:"wording"`
	CompareURL string `json:"compare_url"`
	BuyURL     string `json:"buy_url"`
}

// writeRateLimitError emits the V1 Plugin Pro 429 daily-quota envelope and
// sets the locked headers (X-Axonflow-Tier-Limit, X-Axonflow-Upgrade-URL,
// Retry-After).
//
// tier — caller's effective tier label ("Free" / "Pro" / "Premium" /
// "Enterprise"). For over-quota cases this is overwhelmingly "Free" since
// Pro raises the daily quota 10x and Premium 25x.
//
// limit — the daily quota that was breached (200 for Free, 2,000 for Pro,
// 5,000 for Premium per the locked tier table).
//
// tenantID is logged but not surfaced to the client.
func writeRateLimitError(w http.ResponseWriter, tenantID, tier string, limit int) {
	resetsAt := nextUTCMidnightForRateLimit()
	retrySecs := retryAfterSeconds(resetsAt)

	envelope := rateLimitEnvelope{
		Error:     "Daily request limit reached. Resets at midnight UTC.",
		LimitType: LimitTypeDailyQuota,
		Tier:      tier,
		Limit:     limit,
		Remaining: 0,
		Window:    "daily_utc",
		ResetsAt:  &resetsAt,
		Upgrade: upgradeBlock{
			Tier:       "Pro",
			Wording:    wordingDailyQuota,
			CompareURL: v1ProUpgradeCompareURL,
			BuyURL:     v1ProUpgradeBuyURL,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Axonflow-Tier-Limit", LimitTypeDailyQuota)
	w.Header().Set("X-Axonflow-Upgrade-URL", v1ProUpgradeCompareURL)
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySecs))
	w.WriteHeader(http.StatusTooManyRequests)
	if err := json.NewEncoder(w).Encode(envelope); err != nil {
		log.Printf("[V1 Pro envelope] tenant=%s daily_quota encode failed: %v", tenantID, err)
	}
}

// writeFreeLimitError emits the V1 Plugin Pro 403 graduated-limit /
// Pro-only envelope. Used by MCP tool dispatch (PR2 of umbrella #1958)
// when (a) a tool's RequiredTier blocks the caller, or (b) a tool's
// FreeUsageLimit is exhausted.
//
// limitType — one of the LimitType* constants (active_policies /
// hitl_approvals_window / feature_pro_only). daily_quota uses the 429
// helper above instead.
//
// tier — caller's effective tier label.
//
// limit — the cap value the caller tripped (e.g. 2 for active_policies,
// 1 for hitl_approvals_window). 0 for feature_pro_only since there is
// no quantitative cap, just a binary gate.
//
// remaining — typically 0 at the wall.
//
// window — "rolling_7d" for hitl_approvals_window, empty (omitted) for
// active_policies + feature_pro_only.
//
// resetsAt — non-nil when there's a clock (hitl_approvals_window),
// nil for object-count limits + feature_pro_only. When non-nil the
// Retry-After header is set to seconds-until-reset.
func writeFreeLimitError(w http.ResponseWriter, limitType, tier string, limit, remaining int, window string, resetsAt *time.Time) {
	wording := renderWording(limitType, resetsAt)

	envelope := rateLimitEnvelope{
		Error:     wording,
		LimitType: limitType,
		Tier:      tier,
		Limit:     limit,
		Remaining: remaining,
		Window:    window,
		ResetsAt:  resetsAt,
		Upgrade: upgradeBlock{
			Tier:       "Pro",
			Wording:    wording,
			CompareURL: v1ProUpgradeCompareURL,
			BuyURL:     v1ProUpgradeBuyURL,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Axonflow-Tier-Limit", limitType)
	w.Header().Set("X-Axonflow-Upgrade-URL", v1ProUpgradeCompareURL)
	if resetsAt != nil {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSeconds(*resetsAt)))
	}
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(envelope); err != nil {
		log.Printf("[V1 Pro envelope] limit_type=%s encode failed: %v", limitType, err)
	}
}

// renderWording fills in the relative-time placeholder for hitl_approvals_window;
// other limit_types use the wording as-is.
func renderWording(limitType string, resetsAt *time.Time) string {
	switch limitType {
	case LimitTypeDailyQuota:
		return wordingDailyQuota
	case LimitTypeActivePolicies:
		return wordingActivePolicies
	case LimitTypeHITLApprovalsWindow:
		return fmt.Sprintf(wordingHITLApprovalsWindow, humanizeRelativeTime(resetsAt))
	case LimitTypeFeatureProOnly:
		return wordingFeatureProOnly
	default:
		return "Free tier limit reached. Pro removes this cap."
	}
}

// humanizeRelativeTime renders a "in X days" / "in X hours" string for
// the user-facing wording. Returns "soon" when the input is nil or
// already in the past (defensive — the caller shouldn't pass a past
// resets_at, but the wording should never be wrong if they do).
func humanizeRelativeTime(t *time.Time) string {
	if t == nil {
		return "soon"
	}
	d := time.Until(*t)
	if d <= 0 {
		return "soon"
	}
	hours := int(d.Hours())
	days := hours / 24
	remHours := hours - days*24
	switch {
	case days == 0 && remHours == 0:
		return "in less than 1 hour"
	case days == 0 && remHours == 1:
		return "in 1 hour"
	case days == 0:
		return fmt.Sprintf("in %d hours", remHours)
	case days == 1 && remHours == 0:
		return "in 1 day"
	case days == 1:
		return fmt.Sprintf("in 1 day %d hours", remHours)
	case remHours == 0:
		return fmt.Sprintf("in %d days", days)
	default:
		return fmt.Sprintf("in %d days %d hours", days, remHours)
	}
}

// nextUTCMidnightForRateLimit returns the next UTC midnight after time.Now().
// Used by the daily_quota envelope's resets_at field. Named with the
// _ForRateLimit suffix to avoid collision with similar helpers in other
// packages (orchestrator/cost_estimation_handler.go has its own).
func nextUTCMidnightForRateLimit() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
}

// retryAfterSeconds computes the Retry-After header value as integer
// seconds until t. Floors at 1 to guarantee the header is always a
// positive integer; HTTP clients treat 0 as immediate retry which would
// hammer the agent on the boundary moment.
func retryAfterSeconds(t time.Time) int {
	d := time.Until(t)
	if d < time.Second {
		return 1
	}
	return int(d.Seconds())
}

// writeRateLimitErrorJSONRPC emits the V1 daily-quota envelope wrapped
// in a JSON-RPC result with isError=true. Used by the MCP server path
// (#1976 fix) — `/api/v1/mcp-server` is JSON-RPC, not bare HTTP, so the
// envelope rides inside `result.content[0].text` as JSON-encoded text.
//
// Plugins parse `content[0].text` as JSON to extract the envelope —
// same shape as the 429 HTTP path's body. Cross-surface drift is
// avoided by reusing rateLimitEnvelope + the same locked URLs/wording.
//
// reqID carries the JSON-RPC ID so the response correlates with the
// caller's request. tenantID is logged but not surfaced to the client.
func writeRateLimitErrorJSONRPC(w http.ResponseWriter, reqID interface{}, tenantID, tier string, limit int) {
	resetsAt := nextUTCMidnightForRateLimit()
	envelope := rateLimitEnvelope{
		Error:     "Daily request limit reached. Resets at midnight UTC.",
		LimitType: LimitTypeDailyQuota,
		Tier:      tier,
		Limit:     limit,
		Remaining: 0,
		Window:    "daily_utc",
		ResetsAt:  &resetsAt,
		Upgrade: upgradeBlock{
			Tier:       "Pro",
			Wording:    wordingDailyQuota,
			CompareURL: v1ProUpgradeCompareURL,
			BuyURL:     v1ProUpgradeBuyURL,
		},
	}
	envelopeJSON, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		log.Printf("[V1 Pro envelope JSON-RPC] tenant=%s marshal failed: %v", tenantID, err)
		envelopeJSON = []byte(`{"error":"daily quota exceeded"}`)
	}

	// Mirror the locked headers from the HTTP path. JSON-RPC clients
	// don't typically read these but they're useful for observability
	// (CloudWatch / ALB access logs surface them).
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Axonflow-Tier-Limit", LimitTypeDailyQuota)
	w.Header().Set("X-Axonflow-Upgrade-URL", v1ProUpgradeCompareURL)
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfterSeconds(resetsAt)))

	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      reqID,
		"result": map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": string(envelopeJSON)},
			},
			"isError": true,
		},
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[V1 Pro envelope JSON-RPC] tenant=%s encode failed: %v", tenantID, err)
	}
}
