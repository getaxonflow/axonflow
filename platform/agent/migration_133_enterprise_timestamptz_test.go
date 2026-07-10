//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres test for migration enterprise/133 (#2876): sibling of
// core/142 — retypes the 13 tz-naive TIMESTAMP columns (5 enterprise-only
// tables) found by a follow-up sweep of migrations/enterprise/ (the
// original #2876 audit only covered migrations/core/). Applies the FULL
// saas-mode chain (core + enterprise + industry/*, matching
// DEPLOYMENT_MODE=saas in migration_helpers.go), then asserts:
//  1. All 13 columns report data_type = 'timestamp with time zone'.
//  2. org_node_counts (view) and marketplace_usage_summary (view) /
//     marketplace_monthly_usage (materialized view, plus its index
//     idx_monthly_usage_month) — the three objects that block their source
//     columns' ALTER COLUMN TYPE — survive the round-trip.
//  3. Idempotency — re-running the up migration is a no-op.
//  4. Down/up round-trip — down reverts every column to 'timestamp without
//     time zone', up restores 'timestamp with time zone'.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (same as the other realpg tests).

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var enterpriseTimestamptzTargetColumns = []struct {
	table  string
	column string
}{
	{"agent_heartbeats", "last_heartbeat"},
	{"agent_heartbeats", "created_at"},
	{"customer_portal_api_keys", "last_used_at"},
	{"customer_portal_api_keys", "created_at"},
	{"customer_portal_api_keys", "expires_at"},
	{"customer_portal_api_keys", "revoked_at"},
	{"marketplace_usage_records", "timestamp"},
	{"marketplace_usage_records", "created_at"},
	{"marketplace_usage_records", "retried_at"},
	{"password_reset_tokens", "expires_at"},
	{"password_reset_tokens", "used_at"},
	{"password_reset_tokens", "created_at"},
	{"admin_audit_log", "created_at"},
}

// applyAllSaasMigrations applies core/ + enterprise/ + industry/{banking,
// travel} in the production composite (version, name) key order — mirrors
// applyAllCoreMigrations (system_policy_count_realpg_test.go) but widened to
// the additional categories DEPLOYMENT_MODE=saas pulls in (getMigrationPaths,
// migration_helpers.go). industry/healthcare is skipped: the directory
// doesn't exist yet (a future placeholder in getMigrationPaths), so this
// mirrors what the real runner does when it hits a missing category — skip,
// don't fail.
func applyAllSaasMigrations(t *testing.T, db *sql.DB, migrationsRoot string) {
	t.Helper()

	type mig struct {
		version int
		name    string
		path    string
	}
	var migs []mig

	for _, category := range []string{"core", "enterprise", "industry/banking", "industry/travel"} {
		dir := filepath.Join(migrationsRoot, category)
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read migration dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, "_down.sql") {
				continue
			}
			parts := strings.SplitN(name, "_", 2)
			if len(parts) < 2 || !hasThreeDigitPrefix(parts[0]) {
				continue
			}
			var v int
			if _, err := fmt.Sscanf(parts[0], "%d", &v); err != nil {
				continue
			}
			migs = append(migs, mig{version: v, name: name, path: filepath.Join(dir, name)})
		}
	}

	sort.Slice(migs, func(i, j int) bool {
		if migs[i].version != migs[j].version {
			return migs[i].version < migs[j].version
		}
		return migs[i].name < migs[j].name
	})

	for _, m := range migs {
		sqlBytes, err := os.ReadFile(m.path)
		if err != nil {
			t.Fatalf("read migration %s: %v", m.path, err)
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			t.Fatalf("apply migration %s: %v", m.name, err)
		}
	}
}

func TestMigration133_EnterpriseTimestamptz_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration-133 test")
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

	applyAllSaasMigrations(t, db, "../../migrations")

	assertColumnType := func(wantTZ bool) {
		t.Helper()
		for _, c := range enterpriseTimestamptzTargetColumns {
			var dataType string
			err := db.QueryRow(
				`SELECT data_type FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
				c.table, c.column,
			).Scan(&dataType)
			if err != nil {
				t.Fatalf("%s.%s: query data_type: %v", c.table, c.column, err)
			}
			want := "timestamp without time zone"
			if wantTZ {
				want = "timestamp with time zone"
			}
			if dataType != want {
				t.Errorf("%s.%s: data_type = %q, want %q", c.table, c.column, dataType, want)
			}
		}
	}

	assertDependents := func(wantPresent bool) {
		t.Helper()
		for _, q := range []string{
			`SELECT pg_get_viewdef('org_node_counts'::regclass)`,
			`SELECT pg_get_viewdef('marketplace_usage_summary'::regclass)`,
			`SELECT pg_get_viewdef('marketplace_monthly_usage'::regclass)`,
		} {
			var def string
			err := db.QueryRow(q).Scan(&def)
			if !wantPresent {
				if err == nil {
					t.Errorf("%s: expected absent, got def=%s", q, def)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
	}

	assertColumnType(true)
	assertDependents(true)

	upSQL, err := os.ReadFile("../../migrations/enterprise/133_timestamp_columns_to_timestamptz.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downSQL, err := os.ReadFile("../../migrations/enterprise/133_timestamp_columns_to_timestamptz_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	// Idempotency: re-running up is a no-op.
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-running up migration must be idempotent: %v", err)
	}
	assertColumnType(true)
	assertDependents(true)

	// Down/up round-trip.
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("down migration: %v", err)
	}
	assertColumnType(false)
	assertDependents(true) // views/matview survive the round-trip with their original definitions

	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	assertColumnType(true)
	assertDependents(true)
}
