// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// #4274: the MCP tools/call tier gates answer HTTP 403 with the V1 envelope in
// result.content[0].text, the X-Axonflow-Tier-Limit and X-Axonflow-Upgrade-URL
// headers, and Retry-After only where the limit has a reset time, as the REST
// twin writeFreeLimitError does. Before #4274 they answered 200 with no
// headers, so a client that reads the status passed the refusal by as an
// ordinary result, and the csaas telemetry row carried no limit_type.

// assertTierGateAnswer asserts the ruled tier-gate answer: 403, both tier-limit
// headers, the envelope in the JSON-RPC result with this limit type, and no
// Retry-After (the caller asserts Retry-After for a limit with a reset time).
func assertTierGateAnswer(t *testing.T, rr *httptest.ResponseRecorder, limitType string) rateLimitEnvelope {
	t.Helper()
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != limitType {
		t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, limitType)
	}
	if got := rr.Header().Get("X-Axonflow-Upgrade-URL"); got != v1ProUpgradeCompareURL {
		t.Errorf("X-Axonflow-Upgrade-URL = %q, want %q", got, v1ProUpgradeCompareURL)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	env := decodeMCPEnvelope(t, rr)
	if env.LimitType != limitType {
		t.Errorf("envelope.limit_type = %q, want %q", env.LimitType, limitType)
	}
	if env.Tier != "Free" {
		t.Errorf("envelope.tier = %q, want Free", env.Tier)
	}
	if env.Error == "" || env.Error != env.Upgrade.Wording {
		t.Errorf("envelope.error %q and upgrade.wording %q must be the same non-empty text", env.Error, env.Upgrade.Wording)
	}
	if env.Upgrade.CompareURL != v1ProUpgradeCompareURL || env.Upgrade.BuyURL != v1ProUpgradeBuyURL {
		t.Errorf("envelope.upgrade URLs = %q, %q", env.Upgrade.CompareURL, env.Upgrade.BuyURL)
	}
	// The shape every existing parser reads is unchanged.
	var viaExistingParser rateLimitEnvelope
	if err := extractEnvelopeFromMCPResult(rr.Body.Bytes(), &viaExistingParser); err != nil || viaExistingParser.LimitType != limitType {
		t.Errorf("extractEnvelopeFromMCPResult = (%q, %v), want %q", viaExistingParser.LimitType, err, limitType)
	}
	return env
}

func assertNoRetryAfter(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if got, ok := rr.Header()["Retry-After"]; ok {
		t.Errorf("Retry-After = %q on a limit with no reset time; want it absent", got)
	}
}

// Each limit type is answered with its own status: the rate limits 429, the
// tier gates 403. The mapping is the /health saas.upgrade_envelope text.
func TestWriteMCPGateError_AnswersTheStatusOfTheLimitType(t *testing.T) {
	cases := []struct {
		limitType string
		status    int
	}{
		// The two rate rows pin writeMCPGateError's mapping, not a wire shape a
		// client sees: no production caller hands this writer a rate type, and
		// the real 429 writers (writeRateLimitErrorJSONRPC,
		// writeMinuteRateLimitErrorJSONRPC) always send Retry-After.
		{LimitTypeDailyQuota, http.StatusTooManyRequests},
		{LimitTypePerMinute, http.StatusTooManyRequests},
		{LimitTypeFeatureProOnly, http.StatusForbidden},
		{LimitTypeHITLApprovalsWindow, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.limitType, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeMCPGateError(rr, &jsonRPCRequest{ID: "4274"}, tc.limitType, "Free", 1, 0, "", nil)
			if rr.Code != tc.status {
				t.Errorf("status = %d, want %d", rr.Code, tc.status)
			}
			if got := rr.Header().Get("X-Axonflow-Tier-Limit"); got != tc.limitType {
				t.Errorf("X-Axonflow-Tier-Limit = %q, want %q", got, tc.limitType)
			}
			assertNoRetryAfter(t, rr)
			if env := decodeMCPEnvelope(t, rr); env.LimitType != tc.limitType {
				t.Errorf("envelope.limit_type = %q, want %q", env.LimitType, tc.limitType)
			}
		})
	}
}

// Retry-After is set from the reset time when there is one, through the same
// retryAfterSeconds the REST twin uses.
func TestWriteMCPGateError_RetryAfterFollowsTheResetTime(t *testing.T) {
	resetsAt := time.Now().Add(90 * time.Minute)
	rr := httptest.NewRecorder()
	writeMCPGateError(rr, &jsonRPCRequest{ID: "4274"}, LimitTypeHITLApprovalsWindow, "Free", 2, 0, "rolling_7d", &resetsAt)
	env := assertTierGateAnswer(t, rr, LimitTypeHITLApprovalsWindow)
	if env.ResetsAt == nil || !env.ResetsAt.Equal(resetsAt) {
		t.Fatalf("envelope.resets_at = %v, want %v", env.ResetsAt, resetsAt)
	}
	got, err := strconv.Atoi(rr.Header().Get("Retry-After"))
	if err != nil {
		t.Fatalf("Retry-After = %q, want an integer: %v", rr.Header().Get("Retry-After"), err)
	}
	// The header was computed just before this expectation: it is the same
	// value or one second more.
	if want := retryAfterSeconds(resetsAt); got < want || got > want+1 {
		t.Errorf("Retry-After = %d, want %d (seconds until resets_at)", got, want)
	}
}

// feature_pro_only through the real gate: a Free caller on a Pro-only tool.
func TestEnforceMCPToolGate_FeatureProOnlyAnswers403WithoutRetryAfter(t *testing.T) {
	rr := httptest.NewRecorder()
	session := &mcpSession{tier: "Free", tenantID: "cs_4274_feature"}
	tool := mcpTool{Name: mcpToolNameGetCostEstimate, RequiredTier: "Pro"}
	if !enforceMCPToolGate(context.Background(), rr, &jsonRPCRequest{ID: 1}, session, tool, nil) {
		t.Fatal("a Free caller on a Pro-only tool was not refused")
	}
	assertTierGateAnswer(t, rr, LimitTypeFeatureProOnly)
	assertNoRetryAfter(t, rr)
}

// Through /api/v1/mcp-server: the 403 and the tier-limit header are on the
// response when the handler returns, which is where the csaas telemetry
// middleware reads them in production (this router does not mount it), and
// the refusal is still audited as the tier gate. No test before #4274
// asserted the status of a gated tools/call.
func TestHandleMCPToolsCall_ATierGateRefusalAnswers403OnTheWire(t *testing.T) {
	pinMinuteLimits(t)
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	key := "cs_4274_handler_gate"
	useRateLimitKey(t, key)
	stubDailyChecker(t, func(context.Context, string, int, *sql.DB) error { return nil })

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), key, key, key,
			"mcp_tools_call", "mcp tools/call: "+mcpToolNameGetCostEstimate, sqlmock.AnyArg(),
			mcpVerdictBlocked,
			detailsNaming{"tier_gate", "tier/usage gate denied tool access"},
			sqlmock.AnyArg(), PlaneMCP,
			nil, nil, nil,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	now := time.Now()
	sessionID := "sess-4274-gate"
	cacheMCPSession(t, &mcpSession{id: sessionID, createdAt: now, lastUsed: now,
		tenantID: key, orgID: key, clientID: key, userEmail: "u@e.com", userRole: "user", tier: "Free"})
	w := mcpServerPost(t, setupMCPServerRouter(), "tools/call", "gate-4274",
		map[string]interface{}{"name": mcpToolNameGetCostEstimate, "arguments": map[string]interface{}{"plan": "summarise the quarter"}},
		mcpSessionHeaderKey, sessionID)

	assertTierGateAnswer(t, w, LimitTypeFeatureProOnly)
	assertNoRetryAfter(t, w)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the refusal was not audited as the tier gate: %v", err)
	}
}
