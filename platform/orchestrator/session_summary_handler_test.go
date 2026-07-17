//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// usageEnrichmentColumns is the scan shape of the #2852 usage_events
// enrichment query (bucket key, email, metric name, type attr, decision
// attr, summed delta).
var usageEnrichmentColumns = []string{"bucket_key", "user_email", "metric_name", "attr_type", "attr_decision", "value"}

// expectUsageEnrichment queues the sqlmock expectations for one
// enrichSessionSummaryUsage pass: the WithOrgScope transaction (BEGIN +
// set_config bound to the tenant + COMMIT) around the usage_events query.
// Callers with ZERO buckets must NOT call this — enrichment short-circuits
// before touching the DB.
func expectUsageEnrichment(mock sqlmock.Sqlmock, tenant string, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec(`set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(tenant).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM usage_events`).WillReturnRows(rows)
	mock.ExpectCommit()
}

func emptyUsageRows() *sqlmock.Rows { return sqlmock.NewRows(usageEnrichmentColumns) }

// --- QuerySessionSummary -----------------------------------------------------

func TestQuerySessionSummary_NilDB_ReturnsEmpty(t *testing.T) {
	al := &AuditLogger{db: nil}
	buckets, truncated, err := al.QuerySessionSummary(context.Background(), "acme", "", "", time.Now().Add(-time.Hour), time.Now(), 200)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(buckets) != 0 || truncated {
		t.Fatalf("want empty untruncated buckets on nil db, got %+v truncated=%v", buckets, truncated)
	}
}

func TestQuerySessionSummary_SessionAndDayFallbackBuckets(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	t1 := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)

	totalsRows := sqlmock.NewRows([]string{
		"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency",
	}).
		AddRow("session:sess-1", "dev@acme.com", t1, t2, 5, 500, 0.05, 120.0).
		AddRow("day:2026-07-01", "other@acme.com", t1, t2, 3, 100, 0.01, 80.0)
	mock.ExpectQuery("ORDER BY MAX").WillReturnRows(totalsRows)

	outcomeRows := sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}).
		AddRow("session:sess-1", "dev@acme.com", "allowed", 4).
		AddRow("session:sess-1", "dev@acme.com", "denied", 1). // legacy spelling of blocked
		AddRow("day:2026-07-01", "other@acme.com", "allowed", 3)
	mock.ExpectQuery("user_email, policy_decision, COUNT").WillReturnRows(outcomeRows)

	toolRows := sqlmock.NewRows([]string{
		"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency",
	}).
		AddRow("session:sess-1", "dev@acme.com", "mcp_check_policy", 5, 500, 0.05, 120.0).
		AddRow("day:2026-07-01", "other@acme.com", "llm_call", 3, 100, 0.01, 80.0)
	mock.ExpectQuery("user_email, request_type, COUNT").WillReturnRows(toolRows)

	// No usage_events rows: the base view must be untouched and UsageMetrics
	// stay nil (unit-level graceful degradation).
	expectUsageEnrichment(mock, "acme", emptyUsageRows())

	buckets, truncated, err := al.QuerySessionSummary(context.Background(), "acme", "", "", t1.Add(-time.Hour), t2.Add(time.Hour), 200)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if truncated {
		t.Fatalf("2 buckets under a 200 limit must not truncate")
	}
	if len(buckets) != 2 {
		t.Fatalf("want 2 buckets, got %d: %+v", len(buckets), buckets)
	}

	sess := buckets[0]
	if sess.SessionID != "sess-1" || sess.Day != "" {
		t.Fatalf("want session bucket sess-1 with no day, got %+v", sess)
	}
	if sess.UserEmail != "dev@acme.com" || sess.TenantID != "acme" {
		t.Fatalf("wrong identity: %+v", sess)
	}
	if sess.Total != 5 || sess.TokensUsed != 500 || sess.Cost != 0.05 || sess.AvgLatencyMs != 120.0 {
		t.Fatalf("wrong totals: %+v", sess)
	}
	if sess.ByAction["allowed"] != 4 {
		t.Fatalf("wrong allowed count: %+v", sess.ByAction)
	}
	if sess.ByAction["blocked"] != 1 {
		t.Fatalf("legacy 'denied' did not fold into 'blocked': %+v", sess.ByAction)
	}
	for _, v := range []string{"allowed", "blocked", "redacted", "needs_approval", "error"} {
		if _, ok := sess.ByAction[v]; !ok {
			t.Fatalf("verdict %q missing from seeded ByAction", v)
		}
	}
	if len(sess.Tools) != 1 || sess.Tools[0].RequestType != "mcp_check_policy" || sess.Tools[0].Count != 5 {
		t.Fatalf("wrong tool usage: %+v", sess.Tools)
	}
	if sess.UsageMetrics != nil {
		t.Fatalf("no usage rows matched — UsageMetrics must stay nil, got %+v", sess.UsageMetrics)
	}

	day := buckets[1]
	if day.SessionID != "" || day.Day != "2026-07-01" {
		t.Fatalf("want day-fallback bucket with no session_id, got %+v", day)
	}
	if day.UserEmail != "other@acme.com" {
		t.Fatalf("wrong user for day bucket: %+v", day)
	}
	if day.ByAction["allowed"] != 3 {
		t.Fatalf("wrong day-bucket allowed count: %+v", day.ByAction)
	}
	if day.UsageMetrics != nil {
		t.Fatalf("no usage rows matched — day UsageMetrics must stay nil, got %+v", day.UsageMetrics)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestQuerySessionSummary_ExcludesOverrideLifecycle_AllThreeQueries pins the
// reconciliation contract at the SQL layer: every one of the three audit
// queries (totals, outcomes, tools) must carry the shared
// `policy_decision <> $4` predicate bound to the non-verdict marker, so an
// override_lifecycle row can never land in Total or surface as a pseudo-tool
// while foldDecisionCount skips it in ByAction. The totals query additionally
// carries the #2851 LIMIT sentinel as $5 (limit+1). (The behavioral proof
// against real SQL lives in session_summary_handler_integration_test.go.)
func TestQuerySessionSummary_ExcludesOverrideLifecycle_AllThreeQueries(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 1)
	exclusion := `policy_decision <> \$4`

	mock.ExpectQuery(exclusion+`[\s\S]*ORDER BY MAX[\s\S]*LIMIT \$5`).
		WithArgs("acme", start, end, "override_lifecycle", 201).
		WillReturnRows(sqlmock.NewRows(
			[]string{"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency"},
		))
	mock.ExpectQuery(`policy_decision, COUNT[\s\S]*`+exclusion).
		WithArgs("acme", start, end, "override_lifecycle").
		WillReturnRows(sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}))
	mock.ExpectQuery(`request_type, COUNT[\s\S]*`+exclusion).
		WithArgs("acme", start, end, "override_lifecycle").
		WillReturnRows(sqlmock.NewRows(
			[]string{"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency"},
		))
	// Zero buckets → the enrichment pass must not touch the DB at all, so no
	// further expectations are queued.

	if _, _, err := al.QuerySessionSummary(context.Background(), "acme", "", "", start, end, 200); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("a query is missing the override_lifecycle exclusion or its bound arg: %v", err)
	}
}

// With a user_email filter the exclusion keeps $4, the email moves to $5, and
// the totals LIMIT sentinel lands at $6 — a regression here would drop the
// exclusion, misnumber the ILIKE arg, or misplace the #2851 bound.
func TestQuerySessionSummary_ExclusionAndEmailFilter_ArgOrder(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 1)
	filterRe := `policy_decision <> \$4 AND user_email ILIKE '%' \|\| \$5 \|\| '%'`

	mock.ExpectQuery(filterRe+`[\s\S]*LIMIT \$6`).
		WithArgs("acme", start, end, "override_lifecycle", "dev@acme.com", 201).
		WillReturnRows(sqlmock.NewRows(
			[]string{"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency"},
		))
	mock.ExpectQuery(filterRe).
		WithArgs("acme", start, end, "override_lifecycle", "dev@acme.com").
		WillReturnRows(sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}))
	mock.ExpectQuery(filterRe).
		WithArgs("acme", start, end, "override_lifecycle", "dev@acme.com").
		WillReturnRows(sqlmock.NewRows(
			[]string{"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency"},
		))

	if _, _, err := al.QuerySessionSummary(context.Background(), "acme", "", "dev@acme.com", start, end, 200); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("exclusion + email filter arg order broken: %v", err)
	}
}

func TestQuerySessionSummary_OutcomeRowForUnknownBucket_SkippedSafely(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	mock.ExpectQuery("ORDER BY MAX").WillReturnRows(sqlmock.NewRows(
		[]string{"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency"},
	))
	// An outcome row referencing a bucket the totals query never produced —
	// exercises the defensive `ok` check rather than a nil-map write panic.
	mock.ExpectQuery("user_email, policy_decision, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}).
			AddRow("session:ghost", "nobody@acme.com", "allowed", 1),
	)
	mock.ExpectQuery("user_email, request_type, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency"}),
	)

	buckets, _, err := al.QuerySessionSummary(context.Background(), "acme", "", "", time.Now().Add(-time.Hour), time.Now(), 200)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(buckets) != 0 {
		t.Fatalf("want zero buckets (totals query is the source of truth), got %+v", buckets)
	}
}

// TestQuerySessionSummary_UsageEnrichment_FoldsMetrics pins the #2852 fold:
// every allowlisted metric lands on its field, token types split
// headline-vs-cache (cache NEVER in the headline), an unrecognized token type
// inflates neither, decisions split accept/reject, rows for a bucket the
// audit queries never built are ignored (enrichment invents no buckets), and
// the audit-sourced base tokens/cost are untouched (no double-count).
func TestQuerySessionSummary_UsageEnrichment_FoldsMetrics(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	t1 := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)

	mock.ExpectQuery("ORDER BY MAX").WillReturnRows(sqlmock.NewRows(
		[]string{"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency"},
	).
		AddRow("session:sess-1", "dev@acme.com", t1, t1, 2, 30, 0.03, 150.0).
		AddRow("day:2026-07-01", "other@acme.com", t1, t1, 1, 5, 0.005, 50.0))
	mock.ExpectQuery("user_email, policy_decision, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}).
			AddRow("session:sess-1", "dev@acme.com", "allowed", 2).
			AddRow("day:2026-07-01", "other@acme.com", "allowed", 1))
	mock.ExpectQuery("user_email, request_type, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency"}))

	usage := sqlmock.NewRows(usageEnrichmentColumns).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.token.usage", "input", "", 100.0).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.token.usage", "output", "", 50.0).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.token.usage", "cacheRead", "", 100000.0).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.token.usage", "cacheCreation", "", 5000.0).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.token.usage", "mystery", "", 7.0). // neither headline nor cache
		AddRow("session:sess-1", "dev@acme.com", "claude_code.cost.usage", "", "", 0.42).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.lines_of_code.count", "", "", 30.0).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.active_time.total", "", "", 300.5).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.commit.count", "", "", 2.0).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.pull_request.count", "", "", 1.0).
		// Different user.email spelling than the bucket's — the real CLI does
		// this (#2854); must fold via the unique-session fallback.
		AddRow("session:sess-1", "primary@acme.com", "claude_code.session.count", "", "", 1.0).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.code_edit_tool.decision", "", "accept", 3.0).
		AddRow("session:sess-1", "dev@acme.com", "claude_code.code_edit_tool.decision", "", "reject", 1.0).
		AddRow("session:ghost", "nobody@acme.com", "claude_code.token.usage", "input", "", 999.0) // no audit bucket → ignored
	expectUsageEnrichment(mock, "acme", usage)

	buckets, _, err := al.QuerySessionSummary(context.Background(), "acme", "", "", t1.Add(-time.Hour), t1.Add(time.Hour), 200)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(buckets) != 2 {
		t.Fatalf("enrichment must not add/remove buckets: want 2, got %d", len(buckets))
	}

	sess := buckets[0]
	m := sess.UsageMetrics
	if m == nil {
		t.Fatalf("session bucket should be enriched, got nil UsageMetrics")
	}
	if m.TokensUsed != 150 {
		t.Fatalf("headline tokens must be input+output only (150), got %d — cache or unknown type leaked in", m.TokensUsed)
	}
	if m.CacheTokens != 105000 {
		t.Fatalf("cache tokens want 105000, got %d", m.CacheTokens)
	}
	if m.CostUSD < 0.419 || m.CostUSD > 0.421 {
		t.Fatalf("cost_usd want ~0.42, got %v", m.CostUSD)
	}
	if m.LinesOfCode != 30 || m.Commits != 2 || m.PullRequests != 1 {
		t.Fatalf("counter folds wrong: %+v", m)
	}
	if m.SessionCount != 1 {
		t.Fatalf("session.count under a different user.email spelling must fold via the unique-session fallback (#2854): %+v", m)
	}
	if m.ActiveTimeSeconds < 300.4 || m.ActiveTimeSeconds > 300.6 {
		t.Fatalf("active_time_seconds want ~300.5, got %v", m.ActiveTimeSeconds)
	}
	if m.ToolPermissionDecisions.Accept != 3 || m.ToolPermissionDecisions.Reject != 1 {
		t.Fatalf("tool decisions want 3/1, got %+v", m.ToolPermissionDecisions)
	}
	// No double-count: the audit-sourced base fields are untouched by the
	// (much larger) metrics-export numbers.
	if sess.TokensUsed != 30 || sess.Cost != 0.03 {
		t.Fatalf("base tokens/cost must stay audit-sourced (30 / 0.03), got %d / %v", sess.TokensUsed, sess.Cost)
	}

	if buckets[1].UsageMetrics != nil {
		t.Fatalf("day bucket had no usage rows — UsageMetrics must stay nil, got %+v", buckets[1].UsageMetrics)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// Two audit buckets sharing one session_id under different emails make the
// #2854 session fallback AMBIGUOUS — a mismatched-email usage row must then
// be dropped (never guessed onto either bucket).
func TestQuerySessionSummary_UsageEnrichment_AmbiguousSessionFallback_Dropped(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	t1 := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	mock.ExpectQuery("ORDER BY MAX").WillReturnRows(sqlmock.NewRows(
		[]string{"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency"},
	).
		AddRow("session:sess-1", "a@acme.com", t1, t1, 1, 10, 0.01, 100.0).
		AddRow("session:sess-1", "b@acme.com", t1, t1, 1, 10, 0.01, 100.0))
	mock.ExpectQuery("user_email, policy_decision, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}).
			AddRow("session:sess-1", "a@acme.com", "allowed", 1).
			AddRow("session:sess-1", "b@acme.com", "allowed", 1))
	mock.ExpectQuery("user_email, request_type, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency"}))
	expectUsageEnrichment(mock, "acme", sqlmock.NewRows(usageEnrichmentColumns).
		AddRow("session:sess-1", "c@acme.com", "claude_code.session.count", "", "", 1.0))

	buckets, _, err := al.QuerySessionSummary(context.Background(), "acme", "", "", t1.Add(-time.Hour), t1.Add(time.Hour), 200)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(buckets) != 2 {
		t.Fatalf("want 2 buckets, got %d", len(buckets))
	}
	for _, b := range buckets {
		if b.UsageMetrics != nil {
			t.Fatalf("ambiguous session fallback must drop the row, but bucket %s/%s was enriched: %+v",
				b.SessionID, b.UserEmail, b.UsageMetrics)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// An enrichment failure (usage_events unreachable, RLS wrap error, …) must
// degrade to the un-enriched base view, never fail or empty it — the Part-1
// graceful-degradation invariant, now at the query layer.
func TestQuerySessionSummary_EnrichmentFailure_DegradesToBaseView(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	t1 := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	mock.ExpectQuery("ORDER BY MAX").WillReturnRows(sqlmock.NewRows(
		[]string{"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency"},
	).AddRow("session:sess-1", "dev@acme.com", t1, t1, 2, 30, 0.03, 150.0))
	mock.ExpectQuery("user_email, policy_decision, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}).
			AddRow("session:sess-1", "dev@acme.com", "allowed", 2))
	mock.ExpectQuery("user_email, request_type, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency"}))
	mock.ExpectBegin().WillReturnError(errors.New("usage_events plane down"))

	buckets, truncated, err := al.QuerySessionSummary(context.Background(), "acme", "", "", t1.Add(-time.Hour), t1.Add(time.Hour), 200)
	if err != nil {
		t.Fatalf("enrichment failure must not fail the base view: %v", err)
	}
	if truncated || len(buckets) != 1 {
		t.Fatalf("base view lost: buckets=%d truncated=%v", len(buckets), truncated)
	}
	if buckets[0].Total != 2 || buckets[0].UsageMetrics != nil {
		t.Fatalf("want intact un-enriched bucket, got %+v", buckets[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestQuerySessionSummary_BucketLimit_Truncates pins the #2851 cardinality
// bound: limit+1 is the sentinel, the sentinel bucket is dropped, truncated
// reports true, and later merges for the dropped bucket fold into nothing.
func TestQuerySessionSummary_BucketLimit_Truncates(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	t1 := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	// The regex pins the #2854 total ordering: MAX(timestamp) plus the
	// user_email + bucket-key tiebreakers that make the cap cut-off
	// deterministic (behavioral proof against real SQL lives in
	// TestQuerySessionSummary_BucketCap_DeterministicTiebreak_RealPostgres).
	mock.ExpectQuery(`ORDER BY MAX\(timestamp\) DESC, user_email DESC, CASE WHEN[\s\S]*LIMIT \$5`).
		WithArgs("acme", t1.Add(-time.Hour), t1.Add(time.Hour), "override_lifecycle", 2).
		WillReturnRows(sqlmock.NewRows(
			[]string{"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency"},
		).
			AddRow("session:sess-new", "dev@acme.com", t1, t1, 3, 30, 0.03, 100.0).
			AddRow("session:sess-old", "dev@acme.com", t1, t1, 9, 90, 0.09, 100.0))
	mock.ExpectQuery("user_email, policy_decision, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}).
			AddRow("session:sess-new", "dev@acme.com", "allowed", 3).
			AddRow("session:sess-old", "dev@acme.com", "allowed", 9)) // dropped bucket → folded nowhere
	mock.ExpectQuery("user_email, request_type, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency"}))
	expectUsageEnrichment(mock, "acme", emptyUsageRows())

	buckets, truncated, err := al.QuerySessionSummary(context.Background(), "acme", "", "", t1.Add(-time.Hour), t1.Add(time.Hour), 1)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !truncated {
		t.Fatalf("2 buckets under limit 1 must report truncated")
	}
	if len(buckets) != 1 || buckets[0].SessionID != "sess-new" {
		t.Fatalf("want only the most-recent bucket, got %+v", buckets)
	}
	if buckets[0].Total != 3 || buckets[0].ByAction["allowed"] != 3 {
		t.Fatalf("dropped bucket's rows leaked into the survivor: %+v", buckets[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// --- sessionSummaryHandler ---------------------------------------------------

func TestSessionSummaryHandler_MissingTenant_401(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/session-summary?start_date=2026-06-01&end_date=2026-07-01", nil)
		rr := httptest.NewRecorder()
		sessionSummaryHandler(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rr.Code)
		}
	})
}

func TestSessionSummaryHandler_MissingDates_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/session-summary", nil)
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		sessionSummaryHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestSessionSummaryHandler_InvalidDateFormat_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/session-summary?start_date=2026-06-01T00:00:00Z&end_date=2026-07-01", nil)
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		sessionSummaryHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestSessionSummaryHandler_EndBeforeStart_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/session-summary?start_date=2026-07-01&end_date=2026-06-01", nil)
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		sessionSummaryHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestSessionSummaryHandler_RangeExceedsYear_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/session-summary?start_date=2020-01-01&end_date=2026-01-01", nil)
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		sessionSummaryHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestSessionSummaryHandler_InvalidLimit_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		for _, bad := range []string{"abc", "0", "-5", "1.5"} {
			req := httptest.NewRequest(http.MethodGet,
				"/api/v1/audit/session-summary?start_date=2026-06-01&end_date=2026-07-01&limit="+bad, nil)
			req.Header.Set("X-Tenant-ID", "acme")
			rr := httptest.NewRecorder()
			sessionSummaryHandler(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("limit=%q: want 400, got %d", bad, rr.Code)
			}
		}
	})
}

func TestSessionSummaryHandler_NilLogger_503(t *testing.T) {
	withGlobalAuditLogger(nil, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/session-summary?start_date=2026-06-01&end_date=2026-07-01", nil)
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		sessionSummaryHandler(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", rr.Code)
		}
	})
}

func TestSessionSummaryHandler_Success_200(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	mock.ExpectQuery("ORDER BY MAX").WillReturnRows(sqlmock.NewRows(
		[]string{"bucket_key", "user_email", "min_ts", "max_ts", "count", "tokens", "cost", "avg_latency"},
	).AddRow("day:2026-06-15", "dev@acme.com", time.Now(), time.Now(), 2, 20, 0.002, 50.0))
	mock.ExpectQuery("user_email, policy_decision, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "policy_decision", "count"}).
			AddRow("day:2026-06-15", "dev@acme.com", "allowed", 2),
	)
	mock.ExpectQuery("user_email, request_type, COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"bucket_key", "user_email", "request_type", "count", "tokens", "cost", "avg_latency"}).
			AddRow("day:2026-06-15", "dev@acme.com", "mcp_check_policy", 2, 20, 0.002, 50.0),
	)
	expectUsageEnrichment(mock, "acme", emptyUsageRows())

	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/session-summary?user_email=dev@acme.com&start_date=2026-06-01&end_date=2026-07-01", nil)
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		sessionSummaryHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
		}
		var resp SessionSummaryResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("json: %v", err)
		}
		if resp.TenantID != "acme" || resp.StartDate != "2026-06-01" || resp.EndDate != "2026-07-01" {
			t.Fatalf("wrong response envelope: %+v", resp)
		}
		if len(resp.Buckets) != 1 || resp.Buckets[0].Day != "2026-06-15" {
			t.Fatalf("wrong buckets: %+v", resp.Buckets)
		}
		if resp.BucketLimit != sessionSummaryDefaultBucketLimit || resp.Truncated {
			t.Fatalf("want default bucket_limit + untruncated, got limit=%d truncated=%v", resp.BucketLimit, resp.Truncated)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
