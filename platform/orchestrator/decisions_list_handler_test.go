// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
)

// recentTimestamp is a sqlmock.Argument matcher that asserts the bound
// parameter is a time.Time within the last `maxAge` window. Used to
// verify the since-clamp behavior without freezing the wall clock.
type recentTimestamp struct {
	maxAge time.Duration
}

func (m recentTimestamp) Match(v driver.Value) bool {
	ts, ok := v.(time.Time)
	if !ok {
		return false
	}
	cutoff := time.Now().UTC().Add(-m.maxAge)
	return !ts.Before(cutoff)
}

// =============================================================================
// 401 path: missing X-Tenant-ID (mirrors explainDecisionHandler #1623 retro)
// =============================================================================

func TestListDecisions_RequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions", nil)
	// Deliberately no X-Tenant-ID
	w := httptest.NewRecorder()

	listDecisionsHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when X-Tenant-ID missing, got %d: %s", w.Code, w.Body.String())
	}
}

// =============================================================================
// Cross-tenant SQL contract test — the WHERE clause must filter by tenant_id
// (defense against the #1623 retro post-fetch-authorization shape).
// =============================================================================

func TestListDecisions_TenantFilterIsInWhereClause(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	// The contract: tenant_id MUST be the first positional arg of the
	// SELECT. If anybody refactors this to a post-fetch auth check, the
	// mock won't match the regex and the test will fail loudly.
	mock.ExpectQuery(`SELECT[\s\S]*?FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WithArgs(
			"tenant-a",
			sqlmock.AnyArg(), // since
			"",               // decision filter (empty = wildcard)
			"",               // policy_id filter (empty = wildcard)
			"",               // tool_signature filter (empty = wildcard)
			5,                // tier-default limit (Community)
		).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context"},
		))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()

	listDecisionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}

	// And that the response shape is the empty list.
	var resp DecisionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Decisions) != 0 {
		t.Errorf("expected empty list, got %d", len(resp.Decisions))
	}
}

// =============================================================================
// #2592 / ADR-058 Phase 1: decision_id is read from the first-class column via
// COALESCE(decision_id, policy_details->>'decision_id'), and the WHERE predicate
// admits a row whose decision_id is in the COLUMN even when the JSONB copy is
// absent. Red-on-revert: if the reader reverts to the JSONB-only projection +
// predicate, the regex (which requires the column arm) no longer matches and
// this test fails — guarding the no-flag-day contract from a silent regression.
// =============================================================================

func TestListDecisions_ReadsDecisionIdColumnWithJSONBFallback(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	// The projection MUST COALESCE the column first, and the predicate MUST
	// admit the column arm (decision_id IS NOT NULL) — both required so a
	// column-only row (no JSONB decision_id) still surfaces post-backfill.
	mock.ExpectQuery(`COALESCE\(decision_id, policy_details->>'decision_id'\)[\s\S]*?FROM audit_logs[\s\S]*?WHERE tenant_id = \$1[\s\S]*?\(decision_id IS NOT NULL OR policy_details->>'decision_id' IS NOT NULL\)`).
		WithArgs("tenant-a", sqlmock.AnyArg(), "", "", "", 5).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context"},
		).AddRow("dec-from-column", time.Now().UTC(), "deny", "pol-mcp", "", nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body DecisionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Decisions) != 1 || body.Decisions[0].DecisionID != "dec-from-column" {
		t.Fatalf("expected the column-sourced decision_id to surface, got %+v", body.Decisions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// =============================================================================
// Per-tier window+pagesize enforcement (5 cases)
// =============================================================================

// TestListDecisions_TierMatrix asserts the tier-matrix values for tiers
// that exist in BOTH community and enterprise builds. SaaS Plugin tiers
// (Free/Pro/Premium) live under //go:build enterprise — they are tested
// in decisions_list_handler_enterprise_test.go.
func TestListDecisions_TierMatrix(t *testing.T) {
	cases := []struct {
		name        string
		tier        license.Tier
		wantWindowH int
		wantMaxPage int
	}{
		{"Community 24h/5", license.TierCommunity, 24, 5},
		{"Evaluation 14d/100", license.TierEvaluation, 336, 100},
		{"Enterprise full/1000", license.TierEnterprise, -1, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limits := license.GetTierLimits(tc.tier)
			if limits.DecisionListWindowHours != tc.wantWindowH {
				t.Errorf("%s window: got %d, want %d",
					tc.tier, limits.DecisionListWindowHours, tc.wantWindowH)
			}
			if limits.DecisionListMaxPage != tc.wantMaxPage {
				t.Errorf("%s max page: got %d, want %d",
					tc.tier, limits.DecisionListMaxPage, tc.wantMaxPage)
			}
		})
	}
}

// =============================================================================
// 429 envelope shape on Community cap-hit (build-tag-agnostic). The
// SaaS-Free / Pro variants of this test live in
// decisions_list_handler_enterprise_test.go.
// =============================================================================

func TestListDecisions_CommunityCapHit429(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions?limit=10", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	// No X-Axonflow-Effective-Tier header → falls back to the deployment
	// tier (Community in this test binary, since tierChecker is nil).
	w := httptest.NewRecorder()

	listDecisionsHandler(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on over-cap request as Community, got %d: %s",
			w.Code, w.Body.String())
	}

	if got := w.Header().Get("X-Axonflow-Tier-Limit"); got != limitTypeDecisionListSize {
		t.Errorf("X-Axonflow-Tier-Limit header: got %q, want %q",
			got, limitTypeDecisionListSize)
	}
	if got := w.Header().Get("X-Axonflow-Upgrade-URL"); got != v11UpgradeCompareURL {
		t.Errorf("X-Axonflow-Upgrade-URL header: got %q, want %q",
			got, v11UpgradeCompareURL)
	}

	var env decisionListLimitEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.LimitType != limitTypeDecisionListSize {
		t.Errorf("envelope.limit_type: got %q, want %q",
			env.LimitType, limitTypeDecisionListSize)
	}
	if env.Limit != 5 {
		t.Errorf("envelope.limit: got %d, want 5 (Community max page)", env.Limit)
	}
	if env.Upgrade.Tier != "Pro" {
		t.Errorf("envelope.upgrade.tier: got %q, want Pro", env.Upgrade.Tier)
	}
	if env.Upgrade.CompareURL != v11UpgradeCompareURL {
		t.Errorf("envelope.upgrade.compare_url drift: got %q", env.Upgrade.CompareURL)
	}
	if env.Upgrade.BuyURL != v11UpgradeBuyURL {
		t.Errorf("envelope.upgrade.buy_url drift: got %q", env.Upgrade.BuyURL)
	}
	if env.Upgrade.Wording == "" {
		t.Error("envelope.upgrade.wording must be non-empty")
	}
}

// =============================================================================
// 400 path: bad query parameters
// =============================================================================

func TestListDecisions_BadLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions?limit=banana", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on non-integer limit, got %d", w.Code)
	}
}

func TestListDecisions_BadDecisionFilter(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions?decision=maybe", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown decision filter, got %d", w.Code)
	}
}

func TestListDecisions_BadSinceFormat(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions?since=yesterday", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on non-RFC3339 since, got %d", w.Code)
	}
}

// =============================================================================
// Happy path: integration via httptest.NewServer
// =============================================================================

func TestListDecisions_HappyPathIntegration(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context",
	}).
		AddRow("dec-3", now.Add(-1*time.Hour), "deny", "pol-sqli", "postgres.query",
			`{"x_ai_agent":"claude-code","x_session_id":"sess-abc123"}`).
		AddRow("dec-2", now.Add(-2*time.Hour), "require_approval", "pol-pii", "slack.send_message", nil).
		AddRow("dec-1", now.Add(-3*time.Hour), "allow", "pol-default", "", nil)

	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WithArgs(
			"tenant-a",
			sqlmock.AnyArg(),
			"",
			"",
			"",
			5, // Community max page
		).
		WillReturnRows(rows)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/decisions", listDecisionsHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	httpReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/decisions", nil)
	httpReq.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err := srv.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body DecisionListResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Decisions) != 3 {
		t.Fatalf("decisions len: got %d, want 3", len(body.Decisions))
	}
	// Order preserved (DESC by timestamp from SQL).
	if body.Decisions[0].DecisionID != "dec-3" {
		t.Errorf("decisions[0]: got %q, want dec-3", body.Decisions[0].DecisionID)
	}
	if body.Decisions[0].Decision != "deny" {
		t.Errorf("decisions[0].decision: got %q, want deny", body.Decisions[0].Decision)
	}
	if body.Decisions[0].PolicyID != "pol-sqli" {
		t.Errorf("decisions[0].policy_id: got %q", body.Decisions[0].PolicyID)
	}
	// Empty tool_signature deserialized via omitempty: third row has no tool.
	if body.Decisions[2].ToolSignature != "" {
		t.Errorf("decisions[2].tool_signature should be empty, got %q",
			body.Decisions[2].ToolSignature)
	}
	// Request context surfaces on the row that carried it (#2509).
	if got := body.Decisions[0].Context["x_ai_agent"]; got != "claude-code" {
		t.Errorf("decisions[0].context[x_ai_agent]: got %q, want claude-code", got)
	}
	if got := body.Decisions[0].Context["x_session_id"]; got != "sess-abc123" {
		t.Errorf("decisions[0].context[x_session_id]: got %q, want sess-abc123", got)
	}
	// Rows with a NULL context JSONB omit the field entirely.
	if body.Decisions[1].Context != nil {
		t.Errorf("decisions[1].context should be nil (NULL column), got %v", body.Decisions[1].Context)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// =============================================================================
// Filters are passed through to SQL (decision + policy_id + tool_signature).
// =============================================================================

func TestListDecisions_FiltersForwardedToSQL(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WithArgs(
			"tenant-a",
			sqlmock.AnyArg(),
			"deny",           // decision filter
			"pol-sqli",       // policy_id filter
			"postgres.query", // tool_signature filter
			3,
		).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context"},
		))

	url := "/api/v1/decisions?limit=3&decision=deny&policy_id=pol-sqli&tool_signature=postgres.query"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// =============================================================================
// Context surfacing + truncation-to-5 on the LIST endpoint (#2509).
// =============================================================================

func TestListDecisions_ContextTruncatedToFiveKeys(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	// 8 context keys persisted; the list summary must return exactly 5,
	// chosen deterministically (sorted): k0..k4 kept, k5..k7 dropped.
	ctxJSON := `{"k0":"v0","k1":"v1","k2":"v2","k3":"v3","k4":"v4","k5":"v5","k6":"v6","k7":"v7"}`
	rows := sqlmock.NewRows([]string{
		"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context",
	}).AddRow("dec-ctx", time.Now().UTC(), "allow", "pol-default", "", ctxJSON)

	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WithArgs("tenant-a", sqlmock.AnyArg(), "", "", "", 5).
		WillReturnRows(rows)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body DecisionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Decisions) != 1 {
		t.Fatalf("decisions len: got %d, want 1", len(body.Decisions))
	}
	ctx := body.Decisions[0].Context
	if len(ctx) != decisionListContextMaxKeys {
		t.Fatalf("list context keys: got %d, want %d (%v)", len(ctx), decisionListContextMaxKeys, ctx)
	}
	// Deterministic sorted subset: k0..k4 kept, k5+ dropped.
	for _, k := range []string{"k0", "k1", "k2", "k3", "k4"} {
		if _, ok := ctx[k]; !ok {
			t.Errorf("expected kept key %q in truncated list context", k)
		}
	}
	for _, k := range []string{"k5", "k6", "k7"} {
		if _, ok := ctx[k]; ok {
			t.Errorf("key %q should have been truncated from list context", k)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestTruncateContextMap(t *testing.T) {
	if got := truncateContextMap(nil, 5); got != nil {
		t.Errorf("nil map → nil, got %v", got)
	}
	if got := truncateContextMap(map[string]string{"a": "1"}, 0); got != nil {
		t.Errorf("n<=0 → nil, got %v", got)
	}
	full := map[string]string{"a": "1", "b": "2"}
	if got := truncateContextMap(full, 5); len(got) != 2 {
		t.Errorf("len(m)<=n returns all: got %d, want 2", len(got))
	}
}

// =============================================================================
// resolveDecisionListTier: header-precedence + closed-fail on unknown tier.
// SaaS Plugin tier-precedence cases live in
// decisions_list_handler_enterprise_test.go (Free / Pro / Premium tiers
// only exist under the enterprise build).
// =============================================================================

func TestResolveDecisionListTier_UnknownHeaderFallsBack(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/decisions", nil)
	// A self-hosted tier name in this header would be a bug — we ignore
	// it and fall back to the deployment-wide tier checker (Community
	// when tierChecker is unset in tests).
	r.Header.Set("X-Axonflow-Effective-Tier", "Bogus")

	tier, _ := resolveDecisionListTier(r)
	// The community-tier fallback applies when tierChecker is nil (the
	// default in this test binary).
	if tier != license.TierCommunity {
		t.Errorf("tier: got %q, want Community fallback", tier)
	}
}

// =============================================================================
// since-clamp behavior: caller asks for >tier window → clamped silently.
// =============================================================================

func TestListDecisions_SinceClampedToTierWindow(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	// Caller asks for since=30 days ago — Community/Free's tier window is
	// 24h. The SQL must receive a since within the last 25h (allowing
	// for the tiny clock drift between handler entry and expectation
	// match).
	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WithArgs(
			"tenant-a",
			recentTimestamp{maxAge: 25 * time.Hour},
			"", "", "",
			5,
		).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context"},
		))

	thirtyDaysAgo := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	url := "/api/v1/decisions?since=" + thirtyDaysAgo
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}
