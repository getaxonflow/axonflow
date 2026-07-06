//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres E2E for WS-A (#2832/#2835): two consecutive CUMULATIVE OTLP
// metric exports (the shape a real Claude Code session produces under the OTel
// SDK's default temporality) are POSTed through the REAL
// coworkOTELMetricsHandler over a LIVE Postgres with the FULL core migration
// chain (including 140). It asserts the datapoints land as canonical
// usage_events rows — org-tagged from auth (not the spoofable telemetry
// attrs), keyed on session_id + user_email — and that the second export is
// stored as the DELTA against the first (the over-count guard), with tokens
// mirrored into the legacy rollup columns.
//
// Gated on TEST_PG_INTEGRATION=1 + docker, same as the sibling logs test.

import (
	"database/sql"
	"net/http"
	"os"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

func TestCoworkOTELMetrics_RealPostgres_CumulativeDeltaBySession(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres integration test")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	dsn, cleanup := startCountTestPostgres(t)
	t.Cleanup(cleanup)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	for _, kv := range []struct{ key, val string }{
		{"app.db_password", "testpass"},
		{"app.deployment_org_id", "local-dev-org"},
		{"app.deployment_kind", "dev"},
		{"app.current_org_id", "otel-metrics-org"},
	} {
		if _, err := db.Exec("SELECT set_config($1, $2, false)", kv.key, kv.val); err != nil {
			t.Fatalf("set_config %s: %v", kv.key, err)
		}
	}

	applyAllCoreMigrations(t, db, "../../migrations/core")

	// usage_events.org_id has an FK to organizations.
	if _, err := db.Exec(`
		INSERT INTO organizations (org_id, name, license_key, tier)
		VALUES ('otel-metrics-org', 'otel-metrics', 'lic-otel-m', 'ENTERPRISE') ON CONFLICT (org_id) DO NOTHING
	`); err != nil {
		t.Fatalf("seed organizations row: %v", err)
	}

	origDB := usageDB
	usageDB = db
	t.Cleanup(func() { usageDB = origDB })

	const sessionID = "sess-metrics-e2e-1"
	const userEmail = "andi@design-partner.example"
	start := uint64(1700000000_000000000)

	post := func(tokens int64, costUSD float64, tsOffsetNs uint64) {
		t.Helper()
		req := coworkMetricsReq(
			[]*commonpb.KeyValue{
				strAttr("service.name", "claude-code"),
				strAttr("session.id", sessionID),
				strAttr("user.email", userEmail),
				strAttr("organization.id", "org-SPOOFED"),
			},
			sumMetric(metricFixture{
				name: "claude_code.token.usage", monotonic: true,
				temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				points: []*metricspb.NumberDataPoint{{
					Attributes:        []*commonpb.KeyValue{strAttr("type", "input"), strAttr("model", "claude-sonnet-5")},
					StartTimeUnixNano: start,
					TimeUnixNano:      start + tsOffsetNs,
					Value:             &metricspb.NumberDataPoint_AsInt{AsInt: tokens},
				}},
			}),
			sumMetric(metricFixture{
				name: "claude_code.cost.usage", monotonic: true,
				temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				points: []*metricspb.NumberDataPoint{{
					Attributes:        []*commonpb.KeyValue{strAttr("model", "claude-sonnet-5")},
					StartTimeUnixNano: start,
					TimeUnixNano:      start + tsOffsetNs,
					Value:             &metricspb.NumberDataPoint_AsDouble{AsDouble: costUSD},
				}},
			}),
		)
		rr := postCoworkMetrics(t, authCtx("otel-metrics-org", "tenant-dp", "client-1"), contentTypeProtobuf, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("ingest status %d body %s", rr.Code, rr.Body.String())
		}
	}

	// Export 1: cumulative totals to date (1000 input tokens, $0.05).
	post(1000, 0.05, 60_000000000)
	// Export 2: totals grew to 1500 tokens, $0.09 → deltas 500 / $0.04.
	post(1500, 0.09, 120_000000000)

	// A client RETRY of an already-committed export (identical series + times)
	// must land ZERO new rows: the advisory lock serializes it, the re-read
	// prior state yields delta 0, and the unique (series, time) index absorbs
	// any residual re-insert (R3 round-1/2 dedup stack, proven on real PG).
	post(1500, 0.09, 120_000000000)

	// Keyed by session + user, org from AUTH.
	var rows int
	if err := db.QueryRow(`
		SELECT count(*) FROM usage_events
		 WHERE session_id=$1 AND user_email=$2 AND org_id='otel-metrics-org' AND event_type='claude_code_metric'
	`, sessionID, userEmail).Scan(&rows); err != nil {
		t.Fatalf("count by session/user: %v", err)
	}
	if rows != 4 {
		t.Fatalf("usage rows keyed by session+user: got %d want 4 (a duplicate retry must not add rows)", rows)
	}

	// The over-count guard: SUM(metric_value) equals the true totals, and the
	// second export landed as a DELTA row.
	var tokenSum float64
	if err := db.QueryRow(`
		SELECT COALESCE(SUM(metric_value),0) FROM usage_events
		 WHERE session_id=$1 AND metric_name='claude_code.token.usage'
	`, sessionID).Scan(&tokenSum); err != nil {
		t.Fatalf("token sum: %v", err)
	}
	if tokenSum != 1500 {
		t.Errorf("SUM(token metric_value): got %v want 1500 (cumulative NOT normalized?)", tokenSum)
	}
	var delta2, raw2 float64
	var promptTokens2, totalTokens2 int
	if err := db.QueryRow(`
		SELECT metric_value, metric_raw_value, prompt_tokens, total_tokens FROM usage_events
		 WHERE session_id=$1 AND metric_name='claude_code.token.usage'
		 ORDER BY id DESC LIMIT 1
	`, sessionID).Scan(&delta2, &raw2, &promptTokens2, &totalTokens2); err != nil {
		t.Fatalf("read second token row: %v", err)
	}
	if delta2 != 500 || raw2 != 1500 {
		t.Errorf("second export row: delta=%v raw=%v want 500/1500", delta2, raw2)
	}
	if promptTokens2 != 500 || totalTokens2 != 500 {
		t.Errorf("legacy token mirror: prompt=%d total=%d want 500/500", promptTokens2, totalTokens2)
	}

	var costSum float64
	if err := db.QueryRow(`
		SELECT COALESCE(SUM(metric_value),0) FROM usage_events
		 WHERE session_id=$1 AND metric_name='claude_code.cost.usage'
	`, sessionID).Scan(&costSum); err != nil {
		t.Fatalf("cost sum: %v", err)
	}
	if costSum < 0.089 || costSum > 0.091 {
		t.Errorf("SUM(cost metric_value): got %v want ~0.09", costSum)
	}

	// Org came from AUTH, never the spoofed telemetry attribute.
	var spoof int
	if err := db.QueryRow(`SELECT count(*) FROM usage_events WHERE org_id='org-SPOOFED'`).Scan(&spoof); err != nil {
		t.Fatalf("scan spoof: %v", err)
	}
	if spoof != 0 {
		t.Errorf("telemetry-supplied org leaked into %d row(s); org must come from auth", spoof)
	}
}
