//go:build enterprise

// Copyright 2026 AxonFlow
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License in the LICENSE file or at
// https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package orchestrator

// session_summary_handler.go — WS-7 (#2759), Enterprise-gated (HARD RULE 11).
//
//   GET /api/v1/audit/session-summary?[user_email=]&start_date=&end_date=[&limit=]
//
// Deterministic (no LLM), read-side session-activity reporting over the
// existing audit_logs table: "is a developer solving problems or
// token-maxing," built from what's already captured rather than a per-session
// LLM summarization pass (the cost/design constraint from #2759). A row is
// grouped into a bucket keyed on session_id when it carries one (core/129,
// #2753/#2754); rows without one (the majority until the plugin side of
// #2754 ships) fall back to one bucket per user per calendar day.
// user_email is always part of the bucket key so two developers' sessionless
// activity on the same day never collapses together.
//
// This endpoint returns aggregates only, never raw event content — a caller
// drills into a bucket's raw rows via the existing
// GET /api/v1/audit/search?session_id=<id> (real session) or
// ?user_email=<e>&start_time=&end_time= (day-fallback bucket), both already
// supported by SearchAuditLogs. tenant_id is always taken from the trusted
// X-Tenant-ID header, exactly like every other audit handler in this
// package — a query-string tenant_id would be a cross-tenant leak.
//
// New file only (WS-7 independence note): audit_read_handlers.go's
// /api/v1/audit/{search,export,report} handlers are untouched; this adds a
// single route-registration line to run.go. The community build mounts a 501
// stub at the same symbol name (session_summary_handler_community.go).

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"axonflow/platform/agent"
	sharedaudit "axonflow/platform/shared/audit"
	logutil "axonflow/platform/shared/logger"
)

// sessionSummaryMaxRangeDays bounds a single query, mirroring the 1-year cap
// already enforced on /api/v1/audit/report and /api/v1/audit/summary.
const sessionSummaryMaxRangeDays = 365

// Bucket-cardinality bound (#2851): a wide date range over a busy tenant can
// otherwise materialize one bucket per user per day with no ceiling. The
// totals query is LIMITed (most-recent-activity first, same ORDER BY the
// response is documented to carry) and the response reports bucket_limit +
// truncated so a caller knows to narrow the window. A caller-supplied ?limit=
// is clamped to [1, sessionSummaryMaxBucketLimit].
const (
	sessionSummaryDefaultBucketLimit = 200
	sessionSummaryMaxBucketLimit     = 1000
)

// sessionBucketKeySQL is the bucket-key expression shared by every query
// below: a row carrying a session_id groups by session; a NULL-session row
// falls back to one bucket per calendar day. Repeated verbatim in each GROUP
// BY (rather than relying on a SELECT-list alias) to keep the grouping
// unambiguous.
// The day half casts through ::date before ::text — date_trunc(...)::text
// alone would yield "2026-07-01 00:00:00" (a zeroed timestamp), not the plain
// "2026-07-01" the Day field on SessionSummaryBucket is documented to carry.
const sessionBucketKeySQL = `CASE WHEN session_id IS NOT NULL THEN 'session:' || session_id ELSE 'day:' || date_trunc('day', timestamp)::date::text END`

// SessionSummaryToolUsage is the per-request_type usage breakdown within a
// bucket.
//
// "Tool" in the #2759 design-partner ask maps to request_type here — the
// audit row's call-type discriminator (e.g. mcp_check_policy, mcp_check_output,
// tool_call_audit, llm_call). It's the one column populated identically by
// every write path today. A finer-grained tool identity (Bash vs Write vs a
// specific MCP server) currently lives in different places per writer (a
// prefix inside the `query` string for the agent's check_policy path,
// policy_details->>'tool_name' for the orchestrator's audit_tool_call path)
// and isn't unified across them — a v1.1 follow-up if per-tool-name rather
// than per-call-type granularity turns out to matter to the partner.
type SessionSummaryToolUsage struct {
	RequestType  string  `json:"request_type"`
	Count        int     `json:"count"`
	TokensUsed   int     `json:"tokens_used"`
	Cost         float64 `json:"cost"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

// SessionSummaryToolDecisions is the accept/reject split of Claude Code's
// tool-permission prompts (claude_code.code_edit_tool.decision, `decision`
// attribute) within a bucket.
type SessionSummaryToolDecisions struct {
	Accept int `json:"accept"`
	Reject int `json:"reject"`
}

// SessionSummaryUsageMetrics carries the Claude-export usage counters for a
// bucket, sourced from usage_events (event_type='claude_code_metric' — the
// v9.5.0 OTLP /v1/metrics ingest, #2832/#2835) and aggregated on the same
// bucket key (session_id, else user+day) + user_email. STRICTLY ADDITIVE +
// OPTIONAL (#2852): the pointer is nil — the JSON field absent — when no
// metric rows match the bucket (a deployment that never wired OTel, or a
// session whose CLI didn't export), and the audit_logs base view on the
// bucket is never altered by this enrichment.
//
// Token/cost reconciliation (the one place two sources could collide): the
// bucket-level TokensUsed/Cost fields REMAIN the per-request sums over
// governed audit_logs rows (the Part-1 #2759 contract — authoritative for
// what flowed through the gateway). The fields here are the CLI's own
// metrics-export aggregates, which count everything the tool did (governed
// or not), so they are deliberately nested + differently named rather than
// merged — a partner never sees two unlabeled token numbers for one session.
// TokensUsed here sums ONLY type=input/output datapoints; cache tokens
// (type=cacheRead/cacheCreation, ~1000x larger on a real session) are kept
// in CacheTokens and NEVER in the headline — same rule as the ingest's
// legacy-column mirror (platform/common/usage/recorder_enterprise.go) and
// the usage dashboard (#2848). An unrecognized type counts toward neither
// (fail-safe: never inflate a headline).
type SessionSummaryUsageMetrics struct {
	LinesOfCode             int                         `json:"lines_of_code"`
	ActiveTimeSeconds       float64                     `json:"active_time_seconds"`
	Commits                 int                         `json:"commits"`
	PullRequests            int                         `json:"pull_requests"`
	ToolPermissionDecisions SessionSummaryToolDecisions `json:"tool_permission_decisions"`
	SessionCount            int                         `json:"session_count"`
	TokensUsed              int                         `json:"tokens_used"`
	CacheTokens             int                         `json:"cache_tokens"`
	CostUSD                 float64                     `json:"cost_usd"`
}

// SessionSummaryBucket is one session (or day-fallback) bucket in the report.
type SessionSummaryBucket struct {
	// SessionID is set when the bucket is a real session (session_id IS NOT
	// NULL on every row in it).
	SessionID string `json:"session_id,omitempty"`
	// Day (YYYY-MM-DD) is set only for a fallback bucket — rows with no
	// session_id are grouped by calendar day instead.
	Day          string                    `json:"day,omitempty"`
	UserEmail    string                    `json:"user_email"`
	TenantID     string                    `json:"tenant_id"`
	StartTime    time.Time                 `json:"start_time"`
	EndTime      time.Time                 `json:"end_time"`
	Total        int                       `json:"total"`
	ByAction     map[string]int            `json:"by_action"`
	Tools        []SessionSummaryToolUsage `json:"tools"`
	TokensUsed   int                       `json:"tokens_used"`
	Cost         float64                   `json:"cost"`
	AvgLatencyMs float64                   `json:"avg_latency_ms"`
	// UsageMetrics is the optional Claude-export enrichment (#2852) — absent
	// (nil) when no usage_events metric rows match this bucket. See the type
	// doc for the token/cost reconciliation contract.
	UsageMetrics *SessionSummaryUsageMetrics `json:"usage_metrics,omitempty"`
}

// SessionSummaryResponse is the GET /api/v1/audit/session-summary payload.
type SessionSummaryResponse struct {
	TenantID  string                  `json:"tenant_id"`
	UserEmail string                  `json:"user_email,omitempty"`
	StartDate string                  `json:"start_date"`
	EndDate   string                  `json:"end_date"`
	Buckets   []*SessionSummaryBucket `json:"buckets"`
	// BucketLimit + Truncated report the #2851 cardinality bound: buckets is
	// capped at BucketLimit (most-recent activity first); Truncated is true
	// when the window held more buckets than the cap — narrow the window or
	// raise ?limit= (up to the server max).
	BucketLimit int  `json:"bucket_limit"`
	Truncated   bool `json:"truncated"`
}

// QuerySessionSummary buckets audit_logs into per-session (or per-user-day
// fallback) aggregates for [start, end), tenant-scoped and optionally
// filtered by user_email. Three GROUP BY queries share the same WHERE/bucket
// key: (1) bucket identity + time bounds + totals, (2) per-bucket outcome
// counts (folded onto the canonical verdict via foldDecisionCount, shared
// with ReportByAction, #2757), (3) per-bucket per-request_type usage. end
// MUST already be the exclusive upper bound (the caller's end_date + 1 day).
//
// limit caps the number of returned buckets (#2851); the returned bool is
// true when the window held more buckets than the cap. A fourth, separate
// query then enriches the surviving buckets with usage_events metrics
// (#2852) — see enrichSessionSummaryUsage for its isolation contract.
func (l *AuditLogger) QuerySessionSummary(ctx context.Context, tenantID, userEmail string, start, end time.Time, limit int) ([]*SessionSummaryBucket, bool, error) {
	if l.db == nil {
		return []*SessionSummaryBucket{}, false, nil
	}
	if limit < 1 {
		limit = sessionSummaryDefaultBucketLimit
	}

	// Non-verdict lifecycle rows (LogOverrideEvent's "override_lifecycle",
	// the one writer in the mig-123 CHECK set that isn't a PEP verdict) are
	// excluded in SQL, in the WHERE shared by all three queries, so the
	// exclusion cannot diverge between them. Without it, an override
	// grant/revoke lands in Total and in Tools (as a 0-token pseudo-tool)
	// but folds to nothing in ByAction (foldDecisionCount skips it), so the
	// allow/block/redact cards silently fail to sum to Total and
	// AvgLatencyMs/token aggregates are dragged by rows that never carried a
	// governed call — the same reconciliation rule ReportByAction applies in
	// its fold loop (audit_read_handlers.go). foldDecisionCount stays on the
	// outcome scan below as the belt-and-braces for any value that slips the
	// SQL filter. A plain <> on the exact constant is complete here:
	// migration 123 CHECK-constrains policy_decision (NOT NULL, mig 059) to
	// the five canonical verdicts + this one marker, all lowercase.
	where := " WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp < $3 AND policy_decision <> $4"
	args := []interface{}{tenantID, start, end, sharedaudit.DecisionOverrideLifecycle}
	if userEmail != "" {
		where += " AND user_email ILIKE '%' || $5 || '%'"
		args = append(args, userEmail)
	}

	buckets := map[string]*SessionSummaryBucket{}
	order := make([]string, 0)
	bucketFor := func(bucketKey, email string) *SessionSummaryBucket {
		key := bucketKey + "\x00" + email
		b, ok := buckets[key]
		if ok {
			return b
		}
		b = &SessionSummaryBucket{
			UserEmail: email,
			TenantID:  tenantID,
			ByAction:  map[string]int{},
		}
		for _, v := range sharedaudit.All() {
			b.ByAction[v] = 0
		}
		if strings.HasPrefix(bucketKey, "session:") {
			b.SessionID = strings.TrimPrefix(bucketKey, "session:")
		} else {
			b.Day = strings.TrimPrefix(bucketKey, "day:")
		}
		buckets[key] = b
		order = append(order, key)
		return b
	}

	// LIMIT limit+1 (#2851): the sentinel row only signals that more buckets
	// exist beyond the cap — it is dropped below, and the outcome/tool/usage
	// merges are lookup-guarded so its stray group rows fold into nothing.
	// Only the totals query is LIMITed: it alone defines which buckets exist.
	// The user_email + bucket-key tiebreakers (#2854) make the ordering
	// TOTAL: (bucket key, user_email) is exactly the GROUP BY, so no two
	// result rows compare equal, and which bucket falls past the cap at a
	// microsecond-identical MAX(timestamp) is deterministic across runs
	// instead of Postgres scan-order luck.
	totalsQuery := `
		SELECT ` + sessionBucketKeySQL + `, user_email,
		       MIN(timestamp), MAX(timestamp), COUNT(*),
		       COALESCE(SUM(tokens_used), 0), COALESCE(SUM(cost), 0),
		       COALESCE(AVG(response_time_ms), 0)
		FROM audit_logs` + where + `
		GROUP BY ` + sessionBucketKeySQL + `, user_email
		ORDER BY MAX(timestamp) DESC, user_email DESC, ` + sessionBucketKeySQL + ` DESC
		LIMIT $` + strconv.Itoa(len(args)+1) + `
	`
	totalsRows, err := l.db.Query(totalsQuery, append(append([]interface{}{}, args...), limit+1)...)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = totalsRows.Close() }()
	for totalsRows.Next() {
		var bucketKey, email string
		var bucketStart, bucketEnd time.Time
		var total, tokensUsed int
		var cost, avgLatency float64
		if err := totalsRows.Scan(&bucketKey, &email, &bucketStart, &bucketEnd, &total, &tokensUsed, &cost, &avgLatency); err != nil {
			log.Printf("[audit/session-summary] error scanning totals row: %v", err)
			continue
		}
		b := bucketFor(bucketKey, email)
		b.StartTime = bucketStart
		b.EndTime = bucketEnd
		b.Total = total
		b.TokensUsed = tokensUsed
		b.Cost = cost
		b.AvgLatencyMs = avgLatency
	}
	if err := totalsRows.Err(); err != nil {
		return nil, false, err
	}

	truncated := false
	if len(order) > limit {
		truncated = true
		for _, key := range order[limit:] {
			delete(buckets, key)
		}
		order = order[:limit]
	}

	outcomeQuery := `
		SELECT ` + sessionBucketKeySQL + `, user_email, policy_decision, COUNT(*)
		FROM audit_logs` + where + `
		GROUP BY ` + sessionBucketKeySQL + `, user_email, policy_decision
	`
	outcomeRows, err := l.db.Query(outcomeQuery, args...)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = outcomeRows.Close() }()
	for outcomeRows.Next() {
		var bucketKey, email, decision string
		var cnt int
		if err := outcomeRows.Scan(&bucketKey, &email, &decision, &cnt); err != nil {
			log.Printf("[audit/session-summary] error scanning outcome row: %v", err)
			continue
		}
		// Every (bucketKey, email) pair here was already produced by the totals
		// query above (same WHERE + same leading GROUP BY columns), so the
		// lookup always hits; the ok-check is defense in depth, not an expected
		// path.
		if b, ok := buckets[bucketKey+"\x00"+email]; ok {
			foldDecisionCount(b.ByAction, decision, cnt)
		}
	}
	if err := outcomeRows.Err(); err != nil {
		return nil, false, err
	}

	toolQuery := `
		SELECT ` + sessionBucketKeySQL + `, user_email, request_type, COUNT(*),
		       COALESCE(SUM(tokens_used), 0), COALESCE(SUM(cost), 0),
		       COALESCE(AVG(response_time_ms), 0)
		FROM audit_logs` + where + `
		GROUP BY ` + sessionBucketKeySQL + `, user_email, request_type
	`
	toolRows, err := l.db.Query(toolQuery, args...)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = toolRows.Close() }()
	for toolRows.Next() {
		var bucketKey, email, requestType string
		var cnt, tokensUsed int
		var cost, avgLatency float64
		if err := toolRows.Scan(&bucketKey, &email, &requestType, &cnt, &tokensUsed, &cost, &avgLatency); err != nil {
			log.Printf("[audit/session-summary] error scanning tool row: %v", err)
			continue
		}
		if b, ok := buckets[bucketKey+"\x00"+email]; ok {
			b.Tools = append(b.Tools, SessionSummaryToolUsage{
				RequestType:  requestType,
				Count:        cnt,
				TokensUsed:   tokensUsed,
				Cost:         cost,
				AvgLatencyMs: avgLatency,
			})
		}
	}
	if err := toolRows.Err(); err != nil {
		return nil, false, err
	}

	// Query 4 (#2852): usage_events enrichment. Deliberately OUTSIDE the
	// shared audit_logs WHERE — it must never touch the three queries above
	// (the lifecycle exclusion, arg order, and bucket identity are the Part-1
	// contract). Enrichment failure degrades to the un-enriched base view.
	if err := l.enrichSessionSummaryUsage(ctx, tenantID, userEmail, start, end, buckets); err != nil {
		log.Printf("[audit/session-summary] usage_events enrichment failed for tenant=%s (serving base view): %v",
			logutil.Sanitize(tenantID), err)
	}

	result := make([]*SessionSummaryBucket, 0, len(order))
	for _, key := range order {
		result = append(result, buckets[key])
	}
	return result, truncated, nil
}

// usageMetricBucketKeySQL mirrors sessionBucketKeySQL for usage_events metric
// rows so the enrichment lands on the same bucket identity the audit queries
// built: session-keyed when the datapoint carried session.id, else the
// user's calendar-day bucket. usage_events.session_id is nullable AND can be
// an ingest-truncated empty string, so both spellings fall back to day.
// Event time prefers metric_time (datapoint TimeUnixNano) and falls back to
// created_at (ingest time) — same precedence the usage dashboard uses.
const usageMetricBucketKeySQL = `CASE WHEN session_id IS NOT NULL AND session_id <> '' THEN 'session:' || session_id ELSE 'day:' || date_trunc('day', COALESCE(metric_time, created_at))::date::text END`

// enrichSessionSummaryUsage merges Claude-export usage counters
// (usage_events, event_type='claude_code_metric') onto already-built summary
// buckets. Isolation contract (#2852):
//
//   - ADDITIVE ONLY: it never creates buckets (a metrics-only session with no
//     governed audit rows stays invisible — buckets are defined by audit_logs,
//     the Part-1 base-view contract) and never mutates base-view fields; a
//     bucket with no matching metric rows keeps UsageMetrics nil.
//   - TENANT-SCOPED the same way the audit queries are: WHERE org_id = the
//     trusted X-Tenant-ID scope, AND the read runs under agent.WithOrgScope so
//     the usage_events RLS policy (org_id = app.current_org_id, migration 018)
//     enforces the same boundary under axonflow_app_role. This API is never a
//     cross-tenant/BYPASSRLS reader (that is the operator dashboard's job).
//   - metric_value is the ingest-normalized DELTA (migration 140), so SUM per
//     (bucket, metric, attr) is correct regardless of exporter temporality.
func (l *AuditLogger) enrichSessionSummaryUsage(ctx context.Context, tenantID, userEmail string, start, end time.Time, buckets map[string]*SessionSummaryBucket) error {
	if len(buckets) == 0 {
		return nil
	}

	usageWhere := ` WHERE org_id = $1 AND event_type = 'claude_code_metric'
		AND COALESCE(metric_time, created_at) >= $2 AND COALESCE(metric_time, created_at) < $3`
	usageArgs := []interface{}{tenantID, start, end}
	if userEmail != "" {
		usageWhere += " AND user_email ILIKE '%' || $4 || '%'"
		usageArgs = append(usageArgs, userEmail)
	}
	usageQuery := `
		SELECT ` + usageMetricBucketKeySQL + `, COALESCE(user_email, ''), metric_name,
		       COALESCE(metric_attributes->>'type', ''),
		       COALESCE(metric_attributes->>'decision', ''),
		       COALESCE(SUM(metric_value), 0)
		FROM usage_events` + usageWhere + `
		GROUP BY ` + usageMetricBucketKeySQL + `, user_email, metric_name,
		         metric_attributes->>'type', metric_attributes->>'decision'
	`

	// Session-key fallback index (#2854, found by the real-CLI runtime-e2e
	// leg): Claude Code can attribute datapoints of ONE session to different
	// user.email spellings within the same run (observed live: session.count
	// under the account's primary email, token/cost/active_time under the
	// active workspace email). A session bucket's identity is its session_id;
	// user_email in the bucket key exists to disambiguate DAY-fallback
	// buckets. So a session-keyed metric row whose exact (session, email)
	// bucket is absent folds onto the session's bucket IF exactly one exists
	// — unambiguous by construction; with two audit buckets on the same
	// session_id under different emails the row is dropped (never guessed).
	// Day-keyed rows stay strict: email is their only user identity.
	sessionKeyIndex := map[string][]string{}
	for key, b := range buckets {
		if b.SessionID != "" {
			bucketKey := "session:" + b.SessionID
			sessionKeyIndex[bucketKey] = append(sessionKeyIndex[bucketKey], key)
		}
	}

	return agent.WithOrgScope(ctx, l.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, usageQuery, usageArgs...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var bucketKey, email, metricName, tokenType, decision string
			var value float64
			if err := rows.Scan(&bucketKey, &email, &metricName, &tokenType, &decision, &value); err != nil {
				log.Printf("[audit/session-summary] error scanning usage row: %v", err)
				continue
			}
			b, ok := buckets[bucketKey+"\x00"+email]
			if !ok {
				if candidates := sessionKeyIndex[bucketKey]; len(candidates) == 1 {
					b, ok = buckets[candidates[0]]
				}
			}
			if !ok {
				// No governed audit bucket for this (session/day, user) —
				// enrichment never invents buckets.
				continue
			}
			if b.UsageMetrics == nil {
				b.UsageMetrics = &SessionSummaryUsageMetrics{}
			}
			m := b.UsageMetrics
			// Counters are integral deltas stored as DOUBLE PRECISION —
			// round, don't truncate (0.9999999 accumulation must not lose a
			// count).
			n := int(math.Round(value))
			switch metricName {
			case "claude_code.lines_of_code.count":
				m.LinesOfCode += n
			case "claude_code.active_time.total":
				m.ActiveTimeSeconds += value
			case "claude_code.commit.count":
				m.Commits += n
			case "claude_code.pull_request.count":
				m.PullRequests += n
			case "claude_code.session.count":
				m.SessionCount += n
			case "claude_code.cost.usage":
				m.CostUSD += value
			case "claude_code.token.usage":
				// Headline = input/output ONLY; cache tokens stay separate;
				// an unrecognized type inflates neither (see type doc).
				switch tokenType {
				case "input", "output":
					m.TokensUsed += n
				case "cacheRead", "cacheCreation":
					m.CacheTokens += n
				}
			case "claude_code.code_edit_tool.decision":
				switch decision {
				case "accept":
					m.ToolPermissionDecisions.Accept += n
				case "reject":
					m.ToolPermissionDecisions.Reject += n
				}
			}
		}
		return rows.Err()
	})
}

// sessionSummaryHandler serves GET /api/v1/audit/session-summary.
func sessionSummaryHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		log.Printf("[audit/session-summary] BLOCKED: missing X-Tenant-ID header from %s", r.RemoteAddr)
		sendErrorResponse(w, "tenant scoping required", http.StatusUnauthorized)
		return
	}

	q := r.URL.Query()
	userEmail := q.Get("user_email")
	startDateStr := q.Get("start_date")
	endDateStr := q.Get("end_date")
	if startDateStr == "" || endDateStr == "" {
		sendErrorResponse(w, "start_date and end_date are required (YYYY-MM-DD)", http.StatusBadRequest)
		return
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		sendErrorResponse(w, "invalid start_date: must be YYYY-MM-DD", http.StatusBadRequest)
		return
	}
	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		sendErrorResponse(w, "invalid end_date: must be YYYY-MM-DD", http.StatusBadRequest)
		return
	}
	// end_date is a calendar day, inclusive of the caller's intent — the query
	// window runs through the end of that day, so the upper bound passed to
	// QuerySessionSummary is the START of the following day (exclusive).
	endExclusive := endDate.AddDate(0, 0, 1)
	if !endExclusive.After(startDate) {
		sendErrorResponse(w, "end_date must be on or after start_date", http.StatusBadRequest)
		return
	}
	if endExclusive.Sub(startDate) > sessionSummaryMaxRangeDays*24*time.Hour {
		sendErrorResponse(w, "date range must not exceed 1 year", http.StatusBadRequest)
		return
	}

	// Same tier-based retention floor as /api/v1/audit/search and /export — a
	// caller can't reach further back than the tenant's retention window.
	if auditCleanupService != nil {
		cutoff := auditCleanupService.RetentionCutoff()
		if !cutoff.IsZero() && startDate.Before(cutoff) {
			startDate = cutoff
		}
	}

	// #2851: optional ?limit= caps returned buckets; invalid input is a 400
	// (silently ignoring it would surprise a caller paginating on it), while
	// an in-range-but-large value is clamped to the server max and the
	// effective bound echoed back as bucket_limit.
	limit := sessionSummaryDefaultBucketLimit
	if limitStr := q.Get("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil || parsed < 1 {
			sendErrorResponse(w, "invalid limit: must be a positive integer", http.StatusBadRequest)
			return
		}
		limit = parsed
		if limit > sessionSummaryMaxBucketLimit {
			limit = sessionSummaryMaxBucketLimit
		}
	}

	if auditLogger == nil {
		sendErrorResponse(w, "audit subsystem unavailable", http.StatusServiceUnavailable)
		return
	}

	buckets, truncated, err := auditLogger.QuerySessionSummary(r.Context(), tenantID, userEmail, startDate, endExclusive, limit)
	if err != nil {
		log.Printf("[audit/session-summary] query failed for tenant=%s: %v", logutil.Sanitize(tenantID), err)
		sendErrorResponse(w, "session summary query failed", http.StatusInternalServerError)
		return
	}

	resp := SessionSummaryResponse{
		TenantID:    tenantID,
		UserEmail:   userEmail,
		StartDate:   startDateStr,
		EndDate:     endDateStr,
		Buckets:     buckets,
		BucketLimit: limit,
		Truncated:   truncated,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[audit/session-summary] error encoding response: %v", err)
	}
}
