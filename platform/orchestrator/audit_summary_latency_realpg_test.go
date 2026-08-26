// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Real-Postgres proof for the Avg Latency tile's predicate (#3424 round 2).
//
// The runtime-e2e suite drives live traffic and can only produce the rows the
// live planes actually write, which after this change is "measured" almost
// everywhere. The three exclusions the tile depends on are therefore pinned
// HERE, where rows can be constructed deliberately:
//
//	plane='llm'                a PROVIDER round trip, not an enforcement
//	                           duration. Measured live, 3 such rows among 53
//	                           moved the tile from 5ms to 724ms.
//	override_lifecycle         not a verdict; total_requests excludes it, so
//	                           admitting it could make latency_sample_count
//	                           exceed the total the tile is shown against.
//	a NULL response_time_ms    the writer measured nothing.
//
// ...and so is the inclusion the same change turns on: a stored 0 IS a sample,
// because response_time_ms is whole milliseconds and a sub-millisecond decision
// has no other honest value. sqlmock cannot catch any of this: it would happily
// return whatever the test told it to.
//
// Skips cleanly when Docker is unavailable (CI unit lane).

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/testutil"
)

// plane is interface{} so a test can seed the two shapes an UNSTAMPED row
// really takes: a SQL NULL (rows older than migration core/119, which added
// the column and backfilled only decision_id) and the EMPTY STRING (the
// BatchWriter binds AuditEntry.Plane, a plain Go string, for any producer that
// never set it). A `string` parameter could only ever express the second.
func seedLatencyRow(t *testing.T, h *AuditSummaryHandler, id, decision string, plane interface{}, latency interface{}, ts time.Time, planeJSONBArg ...interface{}) {
	var planeJSONB interface{}
	if len(planeJSONBArg) > 0 {
		planeJSONB = planeJSONBArg[0]
	}
	t.Helper()
	// policy_details carries the DUAL-WRITTEN plane the LLM-forward writer has
	// recorded since #2597/#2611, which is what an exporter's
	// COALESCE(plane, policy_details->>'plane') recovers. Seeded so a reviewer
	// can see that this predicate deliberately does NOT consult it.
	details := `{}`
	if s, ok := planeJSONB.(string); ok && s != "" {
		details = `{"plane":"` + s + `"}`
	}
	_, err := h.db.Exec(`
		INSERT INTO audit_logs (id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash, policy_decision,
			policy_details, response_time_ms, plane)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		id, "req-"+id, ts, 1, "dev@acme.com", "agent",
		"client-acme", "acme", "org-acme", "tool_call", "q-"+id, "hash", decision,
		details, latency, plane)
	if err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

func TestAuditSummaryLatency_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, auditLogsTestDDL)

	h := &AuditSummaryHandler{db: pg.DB}
	base := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	from := base.Add(-time.Hour)
	to := base.Add(time.Hour)

	// Four enforcement-plane samples whose mean is exactly 4: 0, 2, 4, 10.
	// The 0 is the load-bearing one -- a decision that completed inside the
	// column's 1ms resolution. Under the pre-round-2 `> 0` predicate it was
	// discarded, which is how 19 of 20 live ALLOW decisions came to record
	// nothing and left the tile averaging only the slow tail.
	seedLatencyRow(t, h, "d0", "allowed", "decision", int64(0), base)
	seedLatencyRow(t, h, "d1", "allowed", "decision", int64(2), base.Add(time.Minute))
	seedLatencyRow(t, h, "d2", "blocked", "mcp", int64(4), base.Add(2*time.Minute))
	seedLatencyRow(t, h, "d3", "redacted", "gateway", int64(10), base.Add(3*time.Minute))

	// A provider round trip. If this counted, the mean would be (16+2000)/5 =
	// 403.2 rather than 4 -- the 140x swing the reviewer measured live.
	seedLatencyRow(t, h, "l1", "allowed", "llm", int64(2000), base.Add(4*time.Minute))
	// A non-verdict lifecycle marker carrying a measurement.
	seedLatencyRow(t, h, "x1", "override_lifecycle", "decision", int64(500), base.Add(5*time.Minute))
	// A genuinely unmeasured verdict row (HITL approvals and the connector-exec
	// MCP closure look like this).
	seedLatencyRow(t, h, "n1", "needs_approval", "decision", nil, base.Add(6*time.Minute))
	// A LEGACY provider round trip: written before migration core/119 added
	// audit_logs.plane, which backfilled only decision_id and never the plane
	// itself. It is the same quantity as l1 above and must be excluded for the
	// same reason -- but neither `plane <> 'llm'` nor `plane IS DISTINCT FROM
	// 'llm'` matches a NULL, so an exclusion written either of those ways lets
	// the whole historical population straight back in. On an install with
	// history that is the ENTIRE population the exclusion exists to remove.
	// Pre-119 SHAPED exactly: column NULL, plane only in policy_details, which
	// is the row an exporter's COALESCE would recover as 'llm'. It must be
	// excluded here by the stricter column rule, not by the JSONB read.
	seedLatencyRow(t, h, "g1", "allowed", nil, int64(3000), base.Add(7*time.Minute), "llm")
	// ...and the same quantity in its OTHER unstamped shape: the empty string
	// the BatchWriter binds for a producer that never set AuditEntry.Plane.
	// `plane IS NOT NULL` alone lets this one through.
	seedLatencyRow(t, h, "g2", "allowed", "", int64(4000), base.Add(8*time.Minute))

	summary, err := h.queryAuditSummary(context.Background(), "acme", "", from, to)
	if err != nil {
		t.Fatalf("queryAuditSummary: %v", err)
	}

	if summary.AvgLatencyMs == nil {
		t.Fatal("avg_latency_ms is null with four measured enforcement rows in range")
	}
	if got := *summary.AvgLatencyMs; got != 4.0 {
		t.Fatalf("avg_latency_ms = %v, want 4 (mean of 0,2,4,10).\n"+
			"  403.2 means the plane='llm' provider round trip was averaged in.\n"+
			"  603.2 means the legacy NULL-plane provider round trip was averaged in\n"+
			"        (a `plane <> 'llm'` or `IS DISTINCT FROM` exclusion never matches NULL).\n"+
			"  ~670   means the EMPTY-STRING-plane round trip was averaged in\n"+
			"        (`plane IS NOT NULL` alone does not exclude the BatchWriter's '').\n"+
			"  ~103   means the override_lifecycle row was averaged in.\n"+
			"  5.33   means the measured ZERO was discarded (the `> 0` predicate).", got)
	}
	if summary.LatencySampleCount != 4 {
		t.Fatalf("latency_sample_count = %d, want 4 (the measured enforcement rows only)", summary.LatencySampleCount)
	}

	// The invariant the tile's basis line renders as "N of M measured". The llm
	// row, the unmeasured row and the four samples are all verdicts; only the
	// lifecycle marker is not.
	if summary.TotalRequests != 8 {
		t.Fatalf("total_requests = %d, want 8 (every verdict row, lifecycle excluded)", summary.TotalRequests)
	}
	if summary.LatencySampleCount > summary.TotalRequests {
		t.Fatalf("latency_sample_count (%d) exceeds total_requests (%d): the tile would render "+
			"a basis like \"9 of 3 measured\"", summary.LatencySampleCount, summary.TotalRequests)
	}

	// And the empty case: a window with no rows at all reports absence, not 0.
	// This is the original #3424 defect, executed against real SQL rather than
	// against a mock that was told what to return.
	empty, err := h.queryAuditSummary(context.Background(), "acme", "", base.Add(240*time.Hour), base.Add(241*time.Hour))
	if err != nil {
		t.Fatalf("queryAuditSummary (empty window): %v", err)
	}
	if empty.AvgLatencyMs != nil {
		t.Fatalf("avg_latency_ms = %v for a window with no rows, want null (the portal renders N/A)",
			*empty.AvgLatencyMs)
	}
	if empty.LatencySampleCount != 0 {
		t.Fatalf("latency_sample_count = %d for an empty window, want 0", empty.LatencySampleCount)
	}
}
