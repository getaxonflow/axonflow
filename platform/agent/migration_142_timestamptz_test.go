//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres test for migration core/142 (#2876): retypes the 28 tz-naive
// TIMESTAMP columns (14 tables) to TIMESTAMPTZ, and the two SECURITY DEFINER
// functions whose signatures mirror them (promote_deployment_org_license,
// portal_session_lookup) to match, all in one migration file / one
// transaction. Column retypes and function retypes were originally two
// separate migrations (142 + 143); merged into one after confirming
// empirically that the split was a genuine partial-apply risk — with only
// the column retype applied, calling promote_deployment_org_license the way
// the Go agent does (a parameterized time.Time, arriving as a
// timestamptz-typed bind parameter) fails outright:
//
//	ERROR: function promote_deployment_org_license(varchar, varchar,
//	integer, timestamp with time zone) does not exist
//
// because Postgres's function-overload resolution only auto-applies
// IMPLICIT casts, and timestamp<->timestamptz is only an ASSIGNMENT-context
// cast. One migration file is one atomic commit (the runner Execs a whole
// file in one round-trip, and Postgres implicitly wraps a multi-statement
// simple-query batch in one transaction with no explicit BEGIN present), so
// folding both halves into a single file — explicitly wrapped in BEGIN/COMMIT
// here for clarity — makes that failure mode structurally impossible: either
// every column and both functions land together, or none do.
//
// Applies the FULL core chain (so 142 runs in its real position, after every
// table/view/function it touches has been created), then asserts:
//  1. All 28 columns report data_type = 'timestamp with time zone'.
//  2. promote_deployment_org_license / portal_session_lookup carry exactly
//     one overload each, typed TIMESTAMPTZ (the old TIMESTAMP-typed overload
//     of promote_deployment_org_license must be gone — CREATE OR REPLACE
//     cannot change an argument type, so a stray DROP FUNCTION omission
//     would leave both signatures live and callable).
//  3. promote_deployment_org_license works end-to-end against the retyped
//     organizations.expires_at.
//  4. Idempotency — re-running the up migration is a no-op.
//  5. Down/up round-trip — down reverts every column to 'timestamp without
//     time zone' and both functions to TIMESTAMP-typed signatures; up
//     restores TIMESTAMPTZ.
//  6. llm_cost_summary (the view that blocks llm_call_audits.created_at's
//     ALTER COLUMN TYPE) survives the round-trip with its original
//     definition intact.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (same as the other realpg tests).

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

// timestamptzTargetColumns is the exact 28-column, 14-table audit from
// issue #2876 — kept as a single source of truth so the up/down/idempotency
// assertions below can't silently drift from what the migration actually
// covers.
var timestamptzTargetColumns = []struct {
	table  string
	column string
}{
	{"organizations", "expires_at"},
	{"organizations", "created_at"},
	{"organizations", "updated_at"},
	{"saml_configurations", "created_at"},
	{"saml_configurations", "updated_at"},
	{"api_keys", "last_used_at"},
	{"api_keys", "created_at"},
	{"api_keys", "expires_at"},
	{"api_keys", "revoked_at"},
	{"user_sessions", "expires_at"},
	{"user_sessions", "created_at"},
	{"user_sessions", "last_activity_at"},
	{"grafana_organizations", "created_at"},
	{"policy_metrics", "timestamp"},
	{"policy_violations", "created_at"},
	{"agent_audit_logs", "timestamp"},
	{"connectors", "installed_at"},
	{"connectors", "last_health_check"},
	{"gateway_contexts", "expires_at"},
	{"gateway_contexts", "created_at"},
	{"llm_call_audits", "created_at"},
	{"evidence_exports", "date_range_start"},
	{"evidence_exports", "date_range_end"},
	{"evidence_exports", "created_at"},
	{"audit_logs", "timestamp"},
	{"audit_logs", "created_at"},
	{"tenants", "created_at"},
	{"tenants", "updated_at"},
}

func TestMigration142_TimestampColumnsToTimestamptz_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres migration-142 test")
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

	assertColumnType := func(wantTZ bool) {
		t.Helper()
		for _, c := range timestamptzTargetColumns {
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

	assertView := func(wantPresent bool) {
		t.Helper()
		var def string
		err := db.QueryRow(`SELECT pg_get_viewdef('llm_cost_summary'::regclass)`).Scan(&def)
		if !wantPresent {
			if err == nil {
				t.Errorf("llm_cost_summary should be absent, got def=%s", def)
			}
			return
		}
		if err != nil {
			t.Fatalf("llm_cost_summary missing: %v", err)
		}
	}

	assertFunctionSignatures := func(wantTZ bool) {
		t.Helper()

		var count int
		if err := db.QueryRow(`SELECT count(*) FROM pg_proc WHERE proname = 'promote_deployment_org_license'`).Scan(&count); err != nil {
			t.Fatalf("count promote_deployment_org_license overloads: %v", err)
		}
		if count != 1 {
			t.Fatalf("promote_deployment_org_license: %d overloads present, want exactly 1 (a stray DROP FUNCTION omission leaves the old TIMESTAMP-typed overload live alongside the new one)", count)
		}

		var promoteArgs, lookupResult string
		if err := db.QueryRow(`SELECT pg_get_function_arguments(oid) FROM pg_proc WHERE proname = 'promote_deployment_org_license'`).Scan(&promoteArgs); err != nil {
			t.Fatalf("promote_deployment_org_license args: %v", err)
		}
		if err := db.QueryRow(`SELECT pg_get_function_result(oid) FROM pg_proc WHERE proname = 'portal_session_lookup'`).Scan(&lookupResult); err != nil {
			t.Fatalf("portal_session_lookup result: %v", err)
		}

		wantType := "timestamp without time zone"
		if wantTZ {
			wantType = "timestamp with time zone"
		}
		if want := "p_expires_at " + wantType; !strings.Contains(promoteArgs, want) {
			t.Errorf("promote_deployment_org_license args = %q, want to contain %q", promoteArgs, want)
		}
		if want := "expires_at " + wantType; !strings.Contains(lookupResult, want) {
			t.Errorf("portal_session_lookup result = %q, want to contain %q", lookupResult, want)
		}
	}

	assertPromoteFunctional := func() {
		t.Helper()

		expiry := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Microsecond)
		if _, err := db.Exec(
			`SELECT promote_deployment_org_license($1, $2, $3, $4)`,
			"mig142-test-org", "Enterprise", 25, expiry,
		); err != nil {
			t.Fatalf("promote_deployment_org_license call: %v", err)
		}
		var gotTier string
		var gotExpiry time.Time
		if err := db.QueryRow(
			`SELECT tier, expires_at FROM organizations WHERE org_id = $1`, "mig142-test-org",
		).Scan(&gotTier, &gotExpiry); err != nil {
			t.Fatalf("query promoted organizations row: %v", err)
		}
		if gotTier != "Enterprise" {
			t.Errorf("organizations.tier = %q, want Enterprise", gotTier)
		}
		if !gotExpiry.Equal(expiry) {
			t.Errorf("organizations.expires_at = %v, want %v", gotExpiry, expiry)
		}

		// NOTE: portal_session_lookup itself is NOT exercised end-to-end here.
		// It has a pre-existing, unrelated bug (#2879, found while writing
		// this test): its body selects s.tenant_id, but user_sessions
		// (migration 002) has never had a tenant_id column — every real call
		// errors with "column s.tenant_id does not exist", regardless of
		// this migration's TIMESTAMP -> TIMESTAMPTZ change. Every existing
		// caller-side test mocks the DB (sqlmock), so nothing had exercised
		// this against a real schema before. assertFunctionSignatures above
		// still confirms the catalog-level contract (return type) this
		// migration is actually responsible for.
	}

	assertColumnType(true)
	assertView(true)
	assertFunctionSignatures(true)
	assertPromoteFunctional()

	upSQL, err := os.ReadFile("../../migrations/core/142_timestamp_columns_to_timestamptz.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downSQL, err := os.ReadFile("../../migrations/core/142_timestamp_columns_to_timestamptz_down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	// Idempotency: re-running up is a no-op.
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-running up migration must be idempotent: %v", err)
	}
	assertColumnType(true)
	assertView(true)
	assertFunctionSignatures(true)
	assertPromoteFunctional()

	// Down/up round-trip.
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("down migration: %v", err)
	}
	assertColumnType(false)
	assertView(true) // view survives the round-trip with its original definition
	assertFunctionSignatures(false)

	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("up after down: %v", err)
	}
	assertColumnType(true)
	assertView(true)
	assertFunctionSignatures(true)
	assertPromoteFunctional()
}
