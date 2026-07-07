//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Real-Postgres integration test for QuerySessionSummary (#2759, WS-7). Unlike
// the sqlmock unit tests in session_summary_handler_test.go, this executes the
// ACTUAL SQL against a real Postgres (testcontainers), which is the only way
// to catch bugs in the bucket-key CASE expression itself — e.g.
// date_trunc('day', timestamp)::text yields a zeroed timestamp string
// ("2026-07-01 00:00:00"), not the plain "2026-07-01" the Day field is
// documented to carry; sqlmock can't surface that because it never parses the
// SQL, only replays canned rows.
//
// Skips cleanly when Docker is unavailable (CI unit lane).

import (
	"context"
	"testing"
	"time"

	sharedaudit "axonflow/platform/shared/audit"
	"axonflow/platform/testutil"
)

// usageEventsTestDDL is the subset of the usage_events schema the #2852
// enrichment reads (migration 081 base columns + the 140 metric columns).
// The fk_usage_org FK to organizations is intentionally omitted — this test
// seeds metric rows directly and the enrichment never joins organizations.
const usageEventsTestDDL = `
CREATE TABLE usage_events (
    id BIGSERIAL PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    event_type VARCHAR(50) NOT NULL,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    estimated_cost_cents INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    session_id VARCHAR(255),
    user_email VARCHAR(320),
    metric_name VARCHAR(128),
    metric_value DOUBLE PRECISION,
    metric_attributes JSONB,
    metric_time TIMESTAMP WITH TIME ZONE
);
`

func TestQuerySessionSummary_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, auditLogsTestDDL)
	pg.RunMigration(t, usageEventsTestDDL)

	al := &AuditLogger{db: pg.DB}
	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)

	// Two rows sharing a real session_id — one bucket, folding "denied" (legacy
	// spelling) into "blocked".
	seedSessionRow(t, al, "s1", "acme", "sess-1", "dev@acme.com", "allowed", "mcp_check_policy", 100, 10, 0.01, base)
	seedSessionRow(t, al, "s2", "acme", "sess-1", "dev@acme.com", "denied", "mcp_check_policy", 200, 20, 0.02, base.Add(time.Minute))
	// A NULL-session row from a different developer on the same calendar day —
	// must land in its OWN day-fallback bucket, not collapse with dev@acme.com's.
	seedSessionRow(t, al, "s3", "acme", "", "other@acme.com", "allowed", "llm_call", 50, 5, 0.005, base.Add(2*time.Minute))
	// Cross-tenant row: must never surface for "acme".
	seedSessionRow(t, al, "o1", "other", "sess-x", "dev@other.com", "blocked", "mcp_check_policy", 999, 99, 0.99, base)

	// Override-lifecycle rows, exactly the shape LogOverrideEvent persists
	// (policy_decision = the non-verdict marker, request_type = a lifecycle
	// event type, session_id NULL — override_audit.go never sets one). Two
	// placements, both of which must be invisible to the summary:
	//   ov1 shares other@acme.com's day-fallback bucket — without the SQL
	//       exclusion it inflates Total to 2 (ByAction still sums to 1),
	//       surfaces "override_created" as a pseudo-tool, and halves
	//       AvgLatencyMs (0ms lifecycle row averaged against the 50ms call);
	//   ov2 is the ONLY activity for solo@acme.com — without the exclusion it
	//       materializes a phantom all-zero-verdict bucket.
	seedSessionRow(t, al, "ov1", "acme", "", "other@acme.com", sharedaudit.DecisionOverrideLifecycle, AuditEventOverrideCreated, 0, 0, 0, base.Add(3*time.Minute))
	seedSessionRow(t, al, "ov2", "acme", "", "solo@acme.com", sharedaudit.DecisionOverrideLifecycle, AuditEventOverrideRevoked, 0, 0, 0, base.Add(4*time.Minute))

	// usage_events metric rows (#2852 enrichment), the shape the OTLP ingest
	// persists (event_type='claude_code_metric', metric_value = normalized
	// delta, attrs allowlisted). sess-1 gets the full metric set including the
	// headline-vs-cache token split; other@acme.com's day bucket stays
	// metric-free (graceful degradation); a foreign-org row with acme's exact
	// session_id must never enrich acme's bucket (tenant scoping); a
	// metrics-only session with no governed audit rows must not invent a
	// bucket.
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.token.usage", `{"type":"input"}`, 100, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.token.usage", `{"type":"output"}`, 50, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.token.usage", `{"type":"cacheRead"}`, 100000, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.cost.usage", `{}`, 0.42, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.lines_of_code.count", `{}`, 30, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.active_time.total", `{}`, 300.5, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.commit.count", `{}`, 2, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.pull_request.count", `{}`, 1, base)
	// Deliberately a DIFFERENT user.email spelling than the bucket's — the
	// real Claude Code CLI attributes session.count to the account's primary
	// email while the rest of the run carries the workspace email (#2854,
	// observed live); the unique-session fallback must still fold it.
	seedUsageMetricRow(t, al, "acme", "sess-1", "primary@acme.com", "claude_code.session.count", `{}`, 1, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.code_edit_tool.decision", `{"decision":"accept"}`, 3, base)
	seedUsageMetricRow(t, al, "acme", "sess-1", "dev@acme.com", "claude_code.code_edit_tool.decision", `{"decision":"reject"}`, 1, base)
	seedUsageMetricRow(t, al, "other", "sess-1", "dev@acme.com", "claude_code.token.usage", `{"type":"input"}`, 99999, base)
	seedUsageMetricRow(t, al, "acme", "sess-metrics-only", "ghost@acme.com", "claude_code.token.usage", `{"type":"input"}`, 77, base)

	buckets, truncated, err := al.QuerySessionSummary(context.Background(), "acme", "", base.Add(-time.Hour), base.Add(time.Hour), 200)
	if err != nil {
		t.Fatalf("QuerySessionSummary err: %v", err)
	}
	if truncated {
		t.Fatalf("2 buckets under a 200 limit must not truncate")
	}
	// Still exactly 2: the ov2 lifecycle row must NOT materialize a phantom
	// bucket for solo@acme.com, and the sess-metrics-only usage rows must NOT
	// invent a bucket for ghost@acme.com (enrichment is additive-only).
	if len(buckets) != 2 {
		t.Fatalf("want 2 buckets (1 session + 1 day-fallback; no phantom override-only or metrics-only bucket), got %d: %+v", len(buckets), buckets)
	}
	for _, b := range buckets {
		if b.UserEmail == "ghost@acme.com" || b.SessionID == "sess-metrics-only" {
			t.Fatalf("metrics-only session invented a bucket: %+v", b)
		}
	}

	// The reconciliation invariant the fix exists for: in every bucket the
	// verdict cards sum exactly to Total — a lifecycle row that lands in one
	// but not the other breaks this.
	for _, b := range buckets {
		sum := 0
		for _, c := range b.ByAction {
			sum += c
		}
		if sum != b.Total {
			t.Fatalf("Total != sum(ByAction) for bucket %+v: total=%d sum=%d", b, b.Total, sum)
		}
	}

	var sessBucket, dayBucket *SessionSummaryBucket
	for _, b := range buckets {
		if b.SessionID == "sess-1" {
			sessBucket = b
		}
		if b.Day != "" {
			dayBucket = b
		}
	}
	if sessBucket == nil {
		t.Fatalf("session bucket sess-1 not found: %+v", buckets)
	}
	if sessBucket.UserEmail != "dev@acme.com" || sessBucket.TenantID != "acme" {
		t.Fatalf("wrong session bucket identity: %+v", sessBucket)
	}
	if sessBucket.Total != 2 {
		t.Fatalf("want total 2 for sess-1, got %d", sessBucket.Total)
	}
	if sessBucket.ByAction["allowed"] != 1 || sessBucket.ByAction["blocked"] != 1 {
		t.Fatalf("legacy 'denied' did not fold into 'blocked' against real SQL: %+v", sessBucket.ByAction)
	}
	if sessBucket.TokensUsed != 30 || sessBucket.Cost < 0.0299 || sessBucket.Cost > 0.0301 {
		t.Fatalf("wrong session totals: tokens=%d cost=%v", sessBucket.TokensUsed, sessBucket.Cost)
	}
	if len(sessBucket.Tools) != 1 || sessBucket.Tools[0].RequestType != "mcp_check_policy" || sessBucket.Tools[0].Count != 2 {
		t.Fatalf("wrong tool usage: %+v", sessBucket.Tools)
	}

	// #2852 enrichment against real SQL: the full metric set folds onto the
	// session bucket; cache tokens stay OUT of the headline; the foreign-org
	// row with the same session_id never leaks in (its 99999 would corrupt
	// the headline if tenant scoping regressed); the audit-sourced base
	// tokens/cost above are untouched (asserted already: 30 / 0.03).
	um := sessBucket.UsageMetrics
	if um == nil {
		t.Fatalf("session bucket should carry usage_metrics, got nil")
	}
	if um.TokensUsed != 150 {
		t.Fatalf("usage_metrics.tokens_used want 150 (input+output only, tenant-scoped), got %d", um.TokensUsed)
	}
	if um.CacheTokens != 100000 {
		t.Fatalf("usage_metrics.cache_tokens want 100000, got %d", um.CacheTokens)
	}
	if um.CostUSD < 0.419 || um.CostUSD > 0.421 {
		t.Fatalf("usage_metrics.cost_usd want ~0.42, got %v", um.CostUSD)
	}
	if um.LinesOfCode != 30 || um.Commits != 2 || um.PullRequests != 1 || um.SessionCount != 1 {
		t.Fatalf("usage_metrics counters wrong: %+v", um)
	}
	if um.ActiveTimeSeconds < 300.4 || um.ActiveTimeSeconds > 300.6 {
		t.Fatalf("usage_metrics.active_time_seconds want ~300.5, got %v", um.ActiveTimeSeconds)
	}
	if um.ToolPermissionDecisions.Accept != 3 || um.ToolPermissionDecisions.Reject != 1 {
		t.Fatalf("usage_metrics tool decisions want 3/1, got %+v", um.ToolPermissionDecisions)
	}

	if dayBucket == nil {
		t.Fatalf("day-fallback bucket not found: %+v", buckets)
	}
	// This is the exact assertion that catches the ::text-without-::date bug:
	// a bad cast would produce "2026-07-01 00:00:00" here instead of
	// "2026-07-01".
	if dayBucket.Day != "2026-07-01" {
		t.Fatalf("Day must be a plain YYYY-MM-DD, got %q (date_trunc cast regression?)", dayBucket.Day)
	}
	if dayBucket.UserEmail != "other@acme.com" || dayBucket.SessionID != "" {
		t.Fatalf("wrong day-fallback bucket identity: %+v", dayBucket)
	}
	// ov1 shares this bucket's key (same user, same day, NULL session): the
	// three assertions below are exactly what regresses if the lifecycle
	// exclusion is dropped from the totals (Total 1→2, AvgLatencyMs 50→25)
	// or tools (pseudo-tool appears) query.
	if dayBucket.Total != 1 {
		t.Fatalf("want total 1 for day-fallback bucket (lifecycle row must not count), got %d", dayBucket.Total)
	}
	if dayBucket.AvgLatencyMs < 49.9 || dayBucket.AvgLatencyMs > 50.1 {
		t.Fatalf("0ms lifecycle row dragged AvgLatencyMs: want ~50, got %v", dayBucket.AvgLatencyMs)
	}
	for _, b := range buckets {
		for _, tool := range b.Tools {
			if IsOverrideEventType(tool.RequestType) {
				t.Fatalf("override lifecycle event surfaced as a pseudo-tool in bucket %+v: %+v", b, tool)
			}
		}
	}
	if len(dayBucket.Tools) != 1 || dayBucket.Tools[0].RequestType != "llm_call" {
		t.Fatalf("day bucket must carry only the governed llm_call tool row: %+v", dayBucket.Tools)
	}
	// Graceful degradation against real SQL: no usage_events rows match this
	// bucket, so the base view is served with usage_metrics absent — never an
	// error, never an emptied bucket.
	if dayBucket.UsageMetrics != nil {
		t.Fatalf("day bucket has no metric rows — usage_metrics must be absent, got %+v", dayBucket.UsageMetrics)
	}

	// Cross-tenant isolation: "other" tenant's row never surfaces for "acme".
	for _, b := range buckets {
		if b.TenantID != "acme" {
			t.Fatalf("cross-tenant leak: bucket for tenant %q returned under acme query", b.TenantID)
		}
	}
}

// TestQuerySessionSummary_BucketCap_DeterministicTiebreak_RealPostgres pins
// the #2854 fix against real SQL: with several buckets sharing a
// microsecond-identical MAX(timestamp), which buckets survive the #2851 cap
// was previously Postgres scan-order luck. The tiebreakers (user_email DESC,
// then bucket key DESC — together exactly the GROUP BY, so the ordering is
// total) must make the cut-off identical on every run AND match the
// documented order.
func TestQuerySessionSummary_BucketCap_DeterministicTiebreak_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, auditLogsTestDDL)
	pg.RunMigration(t, usageEventsTestDDL)

	al := &AuditLogger{db: pg.DB}
	ts := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC) // ONE shared timestamp

	// Three buckets, all with MAX(timestamp) == ts:
	//   (zed@acme.com, sess-zb) — first  (email DESC, then key DESC)
	//   (zed@acme.com, sess-za) — second (same email, 'session:sess-zb' > 'session:sess-za')
	//   (amy@acme.com, sess-b)  — third
	seedSessionRow(t, al, "tb1", "acme", "sess-zb", "zed@acme.com", "allowed", "llm_call", 10, 1, 0.001, ts)
	seedSessionRow(t, al, "tb2", "acme", "sess-za", "zed@acme.com", "allowed", "llm_call", 10, 1, 0.001, ts)
	seedSessionRow(t, al, "tb3", "acme", "sess-b", "amy@acme.com", "allowed", "llm_call", 10, 1, 0.001, ts)

	for run := 0; run < 5; run++ {
		buckets, truncated, err := al.QuerySessionSummary(context.Background(), "acme", "", ts.Add(-time.Hour), ts.Add(time.Hour), 1)
		if err != nil {
			t.Fatalf("run %d: QuerySessionSummary err: %v", run, err)
		}
		if !truncated || len(buckets) != 1 {
			t.Fatalf("run %d: want 1 truncated bucket, got %d truncated=%v", run, len(buckets), truncated)
		}
		if buckets[0].SessionID != "sess-zb" || buckets[0].UserEmail != "zed@acme.com" {
			t.Fatalf("run %d: tiebreaker order broken: kept %s/%s, want sess-zb/zed@acme.com",
				run, buckets[0].SessionID, buckets[0].UserEmail)
		}

		two, truncated2, err := al.QuerySessionSummary(context.Background(), "acme", "", ts.Add(-time.Hour), ts.Add(time.Hour), 2)
		if err != nil {
			t.Fatalf("run %d: limit=2 err: %v", run, err)
		}
		if !truncated2 || len(two) != 2 {
			t.Fatalf("run %d: want 2 truncated buckets, got %d truncated=%v", run, len(two), truncated2)
		}
		if two[0].SessionID != "sess-zb" || two[1].SessionID != "sess-za" {
			t.Fatalf("run %d: limit=2 must keep zed's two buckets in tiebreak order, got %s then %s",
				run, two[0].SessionID, two[1].SessionID)
		}
	}
}

// seedUsageMetricRow inserts one usage_events metric row in the exact shape
// the OTLP ingest persists (insertOTELMetricRow): event_type =
// 'claude_code_metric', metric_value = normalized delta, allowlisted attrs.
func seedUsageMetricRow(t *testing.T, al *AuditLogger, orgID, sessionID, userEmail, metricName, attrsJSON string, value float64, ts time.Time) {
	t.Helper()
	_, err := al.db.Exec(`
		INSERT INTO usage_events (org_id, event_type, session_id, user_email,
			metric_name, metric_value, metric_attributes, metric_time)
		VALUES ($1, 'claude_code_metric', NULLIF($2, ''), $3, $4, $5, $6::jsonb, $7)`,
		orgID, sessionID, userEmail, metricName, value, attrsJSON, ts)
	if err != nil {
		t.Fatalf("seed usage metric %s: %v", metricName, err)
	}
}

func seedSessionRow(t *testing.T, al *AuditLogger, id, tenant, sessionID, userEmail, decision, requestType string, responseTimeMs, tokensUsed int64, cost float64, ts time.Time) {
	t.Helper()
	_, err := al.db.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision,
			response_time_ms, tokens_used, cost, session_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16, NULLIF($17, ''))`,
		id, "req-"+id, ts, 1, userEmail, "agent",
		tenant, tenant, "org-"+tenant, requestType, "q", "hash", decision,
		responseTimeMs, tokensUsed, cost, sessionID)
	if err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}
