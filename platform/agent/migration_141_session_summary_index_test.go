//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres test for migration core/141 (#2851/#2852): the
// (tenant_id, timestamp, session_id) composite index backing the
// session-summary bucket scans. Applies the FULL core chain (so the migration
// runs in its real position, after 059 created audit_logs and 129 added
// session_id), then asserts:
//  1. The index exists with the exact expected column order.
//  2. Idempotency — re-running the up migration is a no-op.
//  3. Down/up round-trip — down drops the index, up restores it.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (same as the other realpg tests).

import (
	"database/sql"
	"os"
	"strings"
	"testing"
)

func TestMigration141_SessionSummaryIndex_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration-141 test")
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

	assertIndex := func(wantPresent bool) {
		t.Helper()
		var indexdef string
		err := db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_audit_logs_tenant_ts_session'`).Scan(&indexdef)
		if !wantPresent {
			if err != sql.ErrNoRows {
				t.Errorf("index should be absent after down, got err=%v def=%s", err, indexdef)
			}
			return
		}
		if err != nil {
			t.Fatalf("index idx_audit_logs_tenant_ts_session missing: %v", err)
		}
		// Column ORDER is the point of a composite index — pin it exactly.
		want := `(tenant_id, "timestamp", session_id)`
		if !strings.Contains(indexdef, want) {
			t.Errorf("index columns/order wrong: %s (want %s)", indexdef, want)
		}
	}

	assertIndex(true)

	upSQL, err := os.ReadFile("../../migrations/core/141_audit_logs_session_summary_index.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downSQL, err := os.ReadFile("../../migrations/core/141_audit_logs_session_summary_index_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	// Idempotency: re-running up is a no-op.
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-running up migration must be idempotent: %v", err)
	}
	assertIndex(true)

	// Down/up round-trip.
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("down migration: %v", err)
	}
	assertIndex(false)
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	assertIndex(true)
}
