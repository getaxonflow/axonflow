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
	"context"
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
    session_id VARCHAR(255),
    -- migration core/126. Added when the decisions feed own realpg proof
    -- (#3718) tried to run queryDecisionList against this fixture and got
    -- ERROR: column "transfer_basis" does not exist. The production SELECT has
    -- read these two since #2954, and a fixture missing a column the query
    -- names fails the query outright rather than returning a wrong answer -
    -- the loud direction, but it also meant no test in this package could
    -- exercise that query at all until now.
    transfer_basis VARCHAR(64),
    data_residency VARCHAR(64)
);`

func seedAuditRow(t *testing.T, al *AuditLogger, id, tenant, decision, query, resp string, latency int64, ts time.Time) {
	t.Helper()
	seedAuditRowDetails(t, al, id, tenant, decision, query, resp, latency, ts,
		`{"policy_name":"sys_dangerous","tool_name":"bash","reasons":["x"],"latency_ms":3}`)
}

// seedAuditRowDetails is seedAuditRow with an explicit policy_details payload,
// so a test can seed the shapes the OTHER writer planes produce (#3426). The
// default above is the SINGULAR HITL-style scalar, which is the only shape the
// pre-#3426 top-policies query could see: a fixture built entirely out of it
// passes while the defect is live.
func seedAuditRowDetails(t *testing.T, al *AuditLogger, id, tenant, decision, query, resp string, latency int64, ts time.Time, details string) {
	t.Helper()
	_, err := al.db.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision,
			policy_details, response_time_ms, redacted_fields, response_sample, correlation_id,
			decision_id, plane, session_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		id, "req-"+id, ts, 1, "dev@acme.com", "agent",
		tenant, tenant, "org-"+tenant, "tool_call", query, "hash", decision,
		details,
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
	// #3426: tenant "fincrime" carries the shapes the decide plane, the
	// FinCrime seam and the MCP check-input writer produce, alongside ONE
	// singular-scalar row like the HITL writer's. Its own tenant so the
	// verdict/latency expectations of the acme sub-tests above stay untouched.
	// Seeded here and not only in the runtime-e2e because this is where the
	// report's real SQL meets real JSONB.
	seedAuditRowDetails(t, al, "f1", "fincrime", "blocked", "wire 48500 to DE", "", 12, base,
		`{"policy_ids":["fincrime_structuring","fincrime_high_risk_geo"],"policy_names":["Structuring","High-Risk Jurisdiction"]}`)
	seedAuditRowDetails(t, al, "f2", "fincrime", "blocked", "wire 47900 to DE", "", 13, base.Add(time.Minute),
		`{"policy_ids":["fincrime_structuring"],"policy_names":["Structuring"]}`)
	seedAuditRowDetails(t, al, "f3", "fincrime", "redacted", "select * from users", "", 14, base.Add(2*time.Minute),
		`{"policy_matches":[{"policy_id":"sql-injection-block","policy_version":3}],"policy_names":["SQL Injection Block"]}`)
	seedAuditRowDetails(t, al, "f4", "fincrime", "needs_approval", "approve wire", "", 15, base.Add(3*time.Minute),
		`{"workflow_id":"w1","policy_id":"hv-wire-oversight","policy_name":"High-Value Wire Transfer Oversight"}`)

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
		rep, err := al.ReportByAction(context.Background(), "acme", "", "", "", base.Add(-time.Hour), base.Add(time.Hour))
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
		// (10+20+30)/3. #3424: the divisor is the number of MEASURED rows, so
		// this stays 20 -- but it now stays 20 for the right reason. The
		// override_lifecycle row seeded above carries latency 0 and is excluded
		// by BOTH the verdict fold and the measured-row filter; before the fix
		// the divisor was every folded verdict row, which happened to agree here
		// only because all three verdict rows were measured.
		if rep.AvgLatencyMs == nil {
			t.Fatalf("avg latency is null; want 20 over 3 measured rows")
		}
		if *rep.AvgLatencyMs != 20.0 {
			t.Fatalf("avg latency wrong: %v", *rep.AvgLatencyMs)
		}
		if rep.LatencySampleCount != 3 {
			t.Fatalf("latency_sample_count = %d, want 3", rep.LatencySampleCount)
		}
		// tenant scoping: 'other' row (latency 99) excluded, else avg != 20
		if len(rep.TopPolicies) == 0 || rep.TopPolicies[0].PolicyName != "sys_dangerous" {
			t.Fatalf("top policies wrong: %+v", rep.TopPolicies)
		}
	})

	// #3426. The Compliance Report's top_policies must count EVERY writer
	// plane, not only the singular-scalar HITL exception the pre-fix query
	// filtered on. Asserted against the real SQL over real JSONB, and against
	// the pre-fix predicate run side by side so the fixture is provably
	// discriminating rather than merely green.
	t.Run("report top_policies counts array-stamped planes and keeps the HITL row", func(t *testing.T) {
		rep, err := al.ReportByAction(context.Background(), "fincrime", "", "", "", base.Add(-time.Hour), base.Add(time.Hour))
		if err != nil {
			t.Fatalf("report err: %v", err)
		}
		got := map[string][2]int{}
		for _, p := range rep.TopPolicies {
			got[p.PolicyName] = [2]int{p.TriggerCount, p.BlockCount}
		}
		want := map[string][2]int{
			// Two rows carry it; both blocked.
			"fincrime_structuring": {2, 2},
			// The SECOND id on row f1: resolving policy_ids[0] alone would
			// under-report it by the same mechanism as excluding the row.
			"fincrime_high_risk_geo": {1, 1},
			// policy_matches, the pre-9.16.1 check-input shape.
			"sql-injection-block": {1, 0},
			// The HITL exception, still counted. The fix widens the reader; it
			// must not swap one exclusion for another.
			"hv-wire-oversight": {1, 0},
		}
		for name, w := range want {
			g, ok := got[name]
			if !ok {
				t.Fatalf("policy %q missing from top_policies: %+v", name, rep.TopPolicies)
			}
			if g != w {
				t.Fatalf("policy %q = (triggers %d, blocks %d), want (%d, %d)", name, g[0], g[1], w[0], w[1])
			}
		}
		if len(got) != len(want) {
			t.Fatalf("top_policies returned %d policies, want %d: %+v", len(got), len(want), rep.TopPolicies)
		}
		// Ordering is by trigger count, so the two-row policy leads.
		if rep.TopPolicies[0].PolicyName != "fincrime_structuring" {
			t.Fatalf("top_policies not ordered by trigger_count: %+v", rep.TopPolicies)
		}
		// A display name never appears beside the id it was stamped with: one
		// arm supplies the whole set.
		if _, leaked := got["Structuring"]; leaked {
			t.Fatalf("display name counted alongside its id: %+v", rep.TopPolicies)
		}
		// THE DISCRIMINATOR. The predicate both surfaces used before #3426,
		// executed against the same rows: it sees the HITL row and nothing
		// else. If this ever stops being 1, the fixture has stopped
		// reproducing the defect and the assertions above prove nothing.
		var preFix int
		if err := al.db.QueryRow(`SELECT count(DISTINCT policy_details->>'policy_name')
			FROM audit_logs WHERE tenant_id = 'fincrime'
			  AND policy_details IS NOT NULL AND policy_details->>'policy_name' IS NOT NULL`).Scan(&preFix); err != nil {
			t.Fatalf("pre-fix probe: %v", err)
		}
		if preFix != 1 {
			t.Fatalf("pre-fix predicate saw %d policies, want exactly 1 (the HITL row); the fixture no longer reproduces #3426", preFix)
		}
	})

	t.Run("report with user_email + action filter", func(t *testing.T) {
		rep, err := al.ReportByAction(context.Background(), "acme", "", "dev@acme.com", "blocked", base.Add(-time.Hour), base.Add(time.Hour))
		if err != nil {
			t.Fatalf("report err: %v", err)
		}
		if rep.ByAction["blocked"] != 1 || rep.Total != 1 {
			t.Fatalf("filtered report wrong: %+v", rep.ByAction)
		}
	})
}
