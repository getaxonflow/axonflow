//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres test for migration core/140 (#2832/#2835): the OTLP metric
// usage columns on usage_events. Applies the FULL core chain (so the migration
// runs in its real position, after 081 created usage_events on every topology
// — community runs core/ only, and 140 touches no enterprise-created table),
// then asserts:
//  1. Column shape — all ten metric columns exist, nullable, correct types.
//  2. Existing writers unaffected — the pre-140 api_call INSERT shape still works.
//  3. Idempotency — re-running the up migration is a no-op.
//  4. Down/up round-trip — down removes the columns + indexes, up restores them.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (same as the other realpg tests).

import (
	"database/sql"
	"os"
	"testing"
)

func TestMigration140_OTELUsageColumns_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration-140 test")
	}

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
		{"app.current_org_id", "local-dev-org"},
	} {
		if _, err := db.Exec("SELECT set_config($1, $2, false)", kv.key, kv.val); err != nil {
			t.Fatalf("set_config %s: %v", kv.key, err)
		}
	}

	applyAllCoreMigrations(t, db, "../../migrations/core")

	wantCols := map[string]string{
		"session_id":         "character varying",
		"user_email":         "character varying",
		"metric_name":        "character varying",
		"metric_value":       "double precision",
		"metric_raw_value":   "double precision",
		"metric_temporality": "character varying",
		"metric_series_key":  "character varying",
		"metric_attributes":  "jsonb",
		"metric_time":        "timestamp with time zone",
		"metric_start_time":  "timestamp with time zone",
	}

	assertCols := func(wantPresent bool) {
		t.Helper()
		for col, wantType := range wantCols {
			var dataType, nullable string
			err := db.QueryRow(`
				SELECT data_type, is_nullable FROM information_schema.columns
				 WHERE table_name = 'usage_events' AND column_name = $1
			`, col).Scan(&dataType, &nullable)
			if !wantPresent {
				if err != sql.ErrNoRows {
					t.Errorf("column %s should be absent after down, got err=%v type=%s", col, err, dataType)
				}
				continue
			}
			if err != nil {
				t.Fatalf("column %s missing: %v", col, err)
			}
			if dataType != wantType {
				t.Errorf("column %s: type %s want %s", col, dataType, wantType)
			}
			if nullable != "YES" {
				t.Errorf("column %s must be nullable (additive migration), got %s", col, nullable)
			}
		}
	}
	assertIndexes := func(wantPresent bool) {
		t.Helper()
		for _, idx := range []string{"idx_usage_events_metric_series", "idx_usage_events_session", "ux_usage_events_metric_point"} {
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM pg_indexes WHERE indexname = $1`, idx).Scan(&n); err != nil {
				t.Fatalf("index lookup %s: %v", idx, err)
			}
			if wantPresent && n != 1 {
				t.Errorf("index %s: got %d want 1", idx, n)
			}
			if !wantPresent && n != 0 {
				t.Errorf("index %s should be dropped, got %d", idx, n)
			}
		}
	}

	assertCols(true)
	assertIndexes(true)

	// Existing writers unaffected: the pre-140 api_call INSERT shape still works.
	if _, err := db.Exec(`
		INSERT INTO organizations (org_id, name, license_key, tier)
		VALUES ('mig140-org', 'mig140', 'lic-140', 'ENTERPRISE') ON CONFLICT (org_id) DO NOTHING
	`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO usage_events (org_id, event_type, instance_id, instance_type, http_method, http_path, http_status_code, latency_ms)
		VALUES ('mig140-org', 'api_call', 'i-1', 'agent', 'POST', '/api/request', 200, 5)
	`); err != nil {
		t.Fatalf("legacy api_call INSERT broken by 140: %v", err)
	}

	upSQL, err := os.ReadFile("../../migrations/core/140_usage_events_otel_metrics.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downSQL, err := os.ReadFile("../../migrations/core/140_usage_events_otel_metrics_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	// Idempotency: re-running up is a no-op.
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-running up migration must be idempotent: %v", err)
	}
	assertCols(true)

	// Down/up round-trip.
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("down migration: %v", err)
	}
	assertCols(false)
	assertIndexes(false)
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	assertCols(true)
	assertIndexes(true)
}
