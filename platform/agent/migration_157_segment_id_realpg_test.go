//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres test for migration core/157 (#3051, ADR-060 #2989 P3): the
// nullable static_policies.segment_id column. Applies the FULL core chain
// (so the migration runs in its real position), then asserts:
//  1. The column exists, is nullable, and is NULL on every existing row
//     (backward compatibility — the DoD requirement that existing policies
//     are byte-identical after the migration).
//  2. Idempotency — re-running the up migration is a no-op.
//  3. Down/up round-trip — down drops the column + index, up restores it.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (same as the other realpg tests).

import (
	"database/sql"
	"os"
	"testing"
)

func TestMigration157_StaticPoliciesSegmentID_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration-157 test")
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

	assertColumn := func(wantPresent bool) {
		t.Helper()
		var isNullable string
		err := db.QueryRow(`SELECT is_nullable FROM information_schema.columns
			WHERE table_name = 'static_policies' AND column_name = 'segment_id'`).Scan(&isNullable)
		if !wantPresent {
			if err != sql.ErrNoRows {
				t.Errorf("segment_id column should be absent after down, got err=%v is_nullable=%s", err, isNullable)
			}
			return
		}
		if err != nil {
			t.Fatalf("static_policies.segment_id missing: %v", err)
		}
		if isNullable != "YES" {
			t.Errorf("static_policies.segment_id must be nullable, got is_nullable=%s", isNullable)
		}
	}

	assertColumn(true)

	// Backward compatibility: every pre-existing static_policies row (the
	// system policies seeded by earlier migrations) must have segment_id
	// NULL — the migration adds the column, it never writes to it.
	var nonNullCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM static_policies WHERE segment_id IS NOT NULL`).Scan(&nonNullCount); err != nil {
		t.Fatalf("count non-null segment_id: %v", err)
	}
	if nonNullCount != 0 {
		t.Errorf("expected zero pre-existing rows with segment_id set, got %d", nonNullCount)
	}

	var totalRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM static_policies`).Scan(&totalRows); err != nil {
		t.Fatalf("count static_policies rows: %v", err)
	}
	if totalRows == 0 {
		t.Fatal("expected the seeded system policies to exist post-migration (sanity check)")
	}

	// Index presence.
	var indexdef string
	if err := db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_static_policies_segment'`).Scan(&indexdef); err != nil {
		t.Fatalf("idx_static_policies_segment missing: %v", err)
	}

	upSQL, err := os.ReadFile("../../migrations/core/157_static_policies_segment_id.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downSQL, err := os.ReadFile("../../migrations/core/157_static_policies_segment_id_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	// Idempotency: re-running up is a no-op.
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-running up migration must be idempotent: %v", err)
	}
	assertColumn(true)

	// Down/up round-trip.
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("down migration: %v", err)
	}
	assertColumn(false)
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	assertColumn(true)
}
