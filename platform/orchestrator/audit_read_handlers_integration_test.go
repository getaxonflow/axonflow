// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Real-Postgres integration test for the WS-2 audit read/report/export surface.
// Unlike the sqlmock unit tests, this executes the ACTUAL SQL against a real
// Postgres (testcontainers) so it catches what sqlmock cannot: $N placeholder
// numbering, COALESCE/JSONB handling, pq.Array expansion, window functions, and
// column/scan alignment. It also proves cross-tenant isolation end-to-end.
//
// Skips cleanly when Docker is unavailable (CI unit lane).

import (
	"testing"
	"time"

	"axonflow/platform/testutil"
)

// auditLogsTestDDL is the subset of the audit_logs schema the WS-2 read surface
// queries (migration 059 core columns + correlation_id (121) + decision_id/plane
// (119)). It intentionally mirrors the production column set + NOT NULL
// constraints so the seed + queries exercise the real shape.
const auditLogsTestDDL = `
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(255) PRIMARY KEY,
    request_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    user_id INTEGER NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    user_role VARCHAR(50) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    org_id VARCHAR(255),
    request_type VARCHAR(50) NOT NULL,
    query TEXT NOT NULL,
    query_hash VARCHAR(255) NOT NULL,
    policy_decision VARCHAR(50) NOT NULL,
    policy_details JSONB,
    provider VARCHAR(50),
    model VARCHAR(100),
    response_time_ms BIGINT,
    tokens_used INTEGER,
    cost DECIMAL(10, 6),
    redacted_fields JSONB,
    error_message TEXT,
    response_sample TEXT,
    compliance_flags JSONB,
    security_metrics JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    correlation_id VARCHAR(255),
    decision_id VARCHAR(255),
    plane VARCHAR(32),
    session_id VARCHAR(255)
);`

func seedAuditRow(t *testing.T, al *AuditLogger, id, tenant, decision, query, resp string, latency int64, ts time.Time) {
	t.Helper()
	_, err := al.db.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision,
			policy_details, response_time_ms, redacted_fields, response_sample, correlation_id,
			decision_id, plane, session_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		id, "req-"+id, ts, 1, "dev@acme.com", "agent",
		tenant, tenant, "org-"+tenant, "tool_call", query, "hash", decision,
		`{"policy_name":"sys_dangerous","tool_name":"bash","reasons":["x"],"latency_ms":3}`,
		latency, `["$.ssn"]`, resp, "corr-"+id, "dec-"+id, "mcp", "sess-"+id)
	if err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

func TestAuditReadSurface_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, auditLogsTestDDL)

	al := &AuditLogger{db: pg.DB}
	base := time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)

	// tenant "acme": one of each of three verdicts; redacted content stored.
	seedAuditRow(t, al, "a1", "acme", "blocked", "DROP TABLE users", "", 10, base)
	seedAuditRow(t, al, "a2", "acme", "redacted", "email [REDACTED:email]", "ssn [REDACTED:ssn]", 20, base.Add(time.Minute))
	seedAuditRow(t, al, "a3", "acme", "allowed", "hello", "hi there", 30, base.Add(2*time.Minute))
	// A non-verdict override_lifecycle row (as LogOverrideEvent writes): the
	// report must EXCLUDE it — Total stays 3 and AvgLatencyMs stays 20 (not 4 /
	// 15). This is the round-2 fix asserted against real SQL + real Normalize.
	seedAuditRow(t, al, "aL", "acme", "override_lifecycle", "override created", "", 0, base.Add(3*time.Minute))
	// tenant "other": must never surface for acme.
	seedAuditRow(t, al, "o1", "other", "blocked", "other tenant secret", "", 99, base)

	t.Run("detail returns full redacted record", func(t *testing.T) {
		e, err := al.GetAuditLogByID("a2", "acme")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if e.Query != "email [REDACTED:email]" || e.ResponseSample != "ssn [REDACTED:ssn]" {
			t.Fatalf("redacted content not returned verbatim: %q / %q", e.Query, e.ResponseSample)
		}
		if e.CorrelationID != "corr-a2" || e.DecisionID != "dec-a2" || e.Plane != "mcp" {
			t.Fatalf("canonical columns wrong: %+v", e)
		}
		if e.SessionID != "sess-a2" {
			t.Fatalf("session_id (WS-1 core/129) not returned in detail: %q", e.SessionID)
		}
		if e.PolicyDetails["tool_name"] != "bash" {
			t.Fatalf("policy_details JSONB not decoded: %+v", e.PolicyDetails)
		}
	})

	t.Run("cross-tenant isolation: acme id invisible to other tenant", func(t *testing.T) {
		if _, err := al.GetAuditLogByID("a1", "other"); err != ErrAuditLogNotFound {
			t.Fatalf("cross-tenant leak: acme row a1 readable as tenant 'other' (err=%v)", err)
		}
		if _, err := al.GetAuditLogByID("o1", "acme"); err != ErrAuditLogNotFound {
			t.Fatalf("cross-tenant leak: other row o1 readable as tenant 'acme' (err=%v)", err)
		}
	})

	t.Run("export tenant-scoped + redaction preserved + action filter", func(t *testing.T) {
		all, truncated, err := al.ExportAuditLogs(auditSearchCriteria{TenantID: "acme"})
		if err != nil || truncated {
			t.Fatalf("export err=%v truncated=%v", err, truncated)
		}
		// 4 acme rows: a1/a2/a3 + the override_lifecycle row. Export is a raw
		// audit_logs dump, so it legitimately includes lifecycle rows (only the
		// per-verdict *report* excludes them).
		if len(all) != 4 {
			t.Fatalf("expected 4 acme rows, got %d", len(all))
		}
		for _, e := range all {
			if e.TenantID != "acme" {
				t.Fatalf("export leaked tenant %q", e.TenantID)
			}
		}
		// redaction preserved
		var sawRedacted bool
		for _, e := range all {
			if e.ID == "a2" && e.ResponseSample == "ssn [REDACTED:ssn]" {
				sawRedacted = true
			}
		}
		if !sawRedacted {
			t.Fatalf("export did not preserve redacted response_sample")
		}
		// action filter: only blocked
		blocked, _, err := al.ExportAuditLogs(auditSearchCriteria{TenantID: "acme", Action: "blocked"})
		if err != nil {
			t.Fatalf("export blocked err: %v", err)
		}
		if len(blocked) != 1 || blocked[0].ID != "a1" {
			t.Fatalf("action filter wrong: %+v", blocked)
		}
	})

	t.Run("report counts reconcile + tenant-scoped + avg latency", func(t *testing.T) {
		rep, err := al.ReportByAction("acme", "", "", base.Add(-time.Hour), base.Add(time.Hour))
		if err != nil {
			t.Fatalf("report err: %v", err)
		}
		if rep.Total != 3 {
			t.Fatalf("expected total 3, got %d", rep.Total)
		}
		if rep.ByAction["blocked"] != 1 || rep.ByAction["redacted"] != 1 || rep.ByAction["allowed"] != 1 {
			t.Fatalf("by_action wrong: %+v", rep.ByAction)
		}
		// full canonical set present
		for _, v := range []string{"allowed", "blocked", "redacted", "needs_approval", "error"} {
			if _, ok := rep.ByAction[v]; !ok {
				t.Fatalf("verdict %q missing", v)
			}
		}
		if rep.AvgLatencyMs != 20.0 { // (10+20+30)/3
			t.Fatalf("avg latency wrong: %v", rep.AvgLatencyMs)
		}
		// tenant scoping: 'other' row (latency 99) excluded, else avg != 20
		if len(rep.TopPolicies) == 0 || rep.TopPolicies[0].PolicyName != "sys_dangerous" {
			t.Fatalf("top policies wrong: %+v", rep.TopPolicies)
		}
	})

	t.Run("report with user_email + action filter", func(t *testing.T) {
		rep, err := al.ReportByAction("acme", "dev@acme.com", "blocked", base.Add(-time.Hour), base.Add(time.Hour))
		if err != nil {
			t.Fatalf("report err: %v", err)
		}
		if rep.ByAction["blocked"] != 1 || rep.Total != 1 {
			t.Fatalf("filtered report wrong: %+v", rep.ByAction)
		}
	})
}
