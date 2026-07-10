//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres UPGRADE-PATH test for migrations core/142 + enterprise/133
// (#2876): the fresh-DB chain tests (migration_142_timestamptz_test.go,
// migration_133_enterprise_timestamptz_test.go) structurally CANNOT catch
// dependent objects created by higher-numbered migrations, because 142 sorts
// before industry/banking/300+401 — on a fresh deploy the banking views
// don't exist yet when 142 runs. Only an upgrade of an EXISTING banking/saas
// database reproduces the failure this test exists for: Postgres refuses
// ALTER COLUMN ... TYPE on policy_violations.created_at while
// sebi_audit_retention_status (banking/300) / mas_audit_retention_status
// (banking/401) depend on it.
//
// The test simulates a real release upgrade, per deployment mode:
//  1. Seed an "old release" database: apply the full migration chain for the
//     mode — selected by the PRODUCTION getMigrationPaths/collectMigrations
//     code via DEPLOYMENT_MODE, sorted by the production composite
//     (version, name) key — EXCLUDING the two migrations under test.
//  2. Seed data: a SEBI + a MAS static policy, and a policy_violations row
//     with a KNOWN naive timestamp, then snapshot pg_get_viewdef of both
//     banking views (where the mode creates them).
//  3. Apply the two new migrations in the runner's order (enterprise/133
//     sorts before core/142) — the upgrade.
//  4. Assert: every mode-applicable column is TIMESTAMPTZ; the banking views
//     survive with BYTE-IDENTICAL definitions (pg_get_viewdef equality — the
//     strongest verbatim-recreate check) and still return correct rows; the
//     known naive value converted as UTC (not the session zone — see below).
//  5. Idempotency, then down round-trip (142_down, 133_down), then re-up.
//
// The database is deliberately pinned to a NON-UTC timezone
// (Asia/Kolkata, +05:30) before any migration runs: the conversion must be
// pinned to UTC (USING ... AT TIME ZONE 'UTC' + SET LOCAL TIME ZONE 'UTC'),
// so a correct implementation produces the same absolute instants under any
// session zone, while a session-relative conversion (the earlier
// current_setting('TIMEZONE') formulation) would shift every value by
// +05:30 and fail the known-instant assertions.
//
// Gated on TEST_PG_INTEGRATION=1 + docker (same as the other realpg tests).

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	upgradeCoreMigFile       = "142_timestamp_columns_to_timestamptz.sql"
	upgradeEnterpriseMigFile = "133_timestamp_columns_to_timestamptz.sql"

	// A known instant, written as a naive timestamp pre-upgrade. The digits
	// are the UTC wall clock; a pinned-UTC conversion must yield exactly
	// 2026-01-02T03:04:05Z, while a session-zone (Asia/Kolkata) conversion
	// would yield 2026-01-01T21:34:05Z.
	seedNaiveTimestamp = "2026-01-02 03:04:05"
	seedUTCInstant     = "2026-01-02T03:04:05Z"
)

func TestMigration142_133_UpgradePath_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres upgrade-path test")
	}

	modes := []struct {
		mode string
		// hasEnterprise: chain includes migrations/enterprise (so 133 applies).
		hasEnterprise bool
		// hasBanking: chain includes industry/banking (so the sebi/mas
		// retention views exist and must survive 142's up AND down).
		hasBanking bool
	}{
		{mode: "in-vpc-banking", hasEnterprise: true, hasBanking: true},
		{mode: "saas", hasEnterprise: true, hasBanking: true}, // + industry/travel
		{mode: "community-saas", hasEnterprise: false, hasBanking: false},
	}

	for _, tc := range modes {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tc.mode)

			dsn, cleanup := startCountTestPostgres(t)
			t.Cleanup(cleanup)

			db, err := sql.Open("postgres", dsn)
			if err != nil {
				t.Fatalf("open db: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			db.SetMaxOpenConns(1)

			// Non-UTC zone at the DATABASE level so every (re)connection —
			// exactly like an RDS parameter-group timezone or a PGTZ-carrying
			// psql session — sees a non-UTC session TimeZone. The migrations
			// must be immune to it.
			if _, err := db.Exec(`ALTER DATABASE axonflow_test SET timezone TO 'Asia/Kolkata'`); err != nil {
				t.Fatalf("pin non-UTC database timezone: %v", err)
			}
			if _, err := db.Exec(`SET TIME ZONE 'Asia/Kolkata'`); err != nil {
				t.Fatalf("pin non-UTC session timezone: %v", err)
			}

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

			// Production selection + ordering: getMigrationPaths reads
			// DEPLOYMENT_MODE, collectMigrations sorts by the composite
			// (version, name) key — the exact order the boot-time runner uses.
			all, err := collectMigrations("../../migrations")
			if err != nil {
				t.Fatalf("collectMigrations: %v", err)
			}

			isUpgradeTarget := func(m MigrationFile) bool {
				base := filepath.Base(m.Path)
				return (m.Category == "core" && base == upgradeCoreMigFile) ||
					(m.Category == "enterprise" && base == upgradeEnterpriseMigFile)
			}

			apply := func(m MigrationFile) {
				t.Helper()
				sqlBytes, readErr := os.ReadFile(m.Path)
				if readErr != nil {
					t.Fatalf("read migration %s: %v", m.Path, readErr)
				}
				if _, execErr := db.Exec(string(sqlBytes)); execErr != nil {
					t.Fatalf("apply migration %s [%s]: %v", filepath.Base(m.Path), m.Category, execErr)
				}
			}

			// ---- Phase 1: seed the "old release" database ----
			var deferred []MigrationFile
			for _, m := range all {
				if isUpgradeTarget(m) {
					deferred = append(deferred, m)
					continue
				}
				apply(m)
			}
			wantDeferred := 1 // core/142 is in every mode's chain
			if tc.hasEnterprise {
				wantDeferred = 2
			}
			if len(deferred) != wantDeferred {
				t.Fatalf("expected %d deferred upgrade migrations for mode %s, got %d (%v)",
					wantDeferred, tc.mode, len(deferred), deferred)
			}

			// Covers plain views AND materialized views (information_schema
			// only lists the former).
			viewExists := func(name string) bool {
				t.Helper()
				var exists bool
				if err := db.QueryRow(
					`SELECT to_regclass('public.' || $1) IS NOT NULL`, name,
				).Scan(&exists); err != nil {
					t.Fatalf("view existence %s: %v", name, err)
				}
				return exists
			}
			viewDef := func(name string) string {
				t.Helper()
				var def string
				if err := db.QueryRow(`SELECT pg_get_viewdef(to_regclass('public.` + name + `'))`).Scan(&def); err != nil {
					t.Fatalf("pg_get_viewdef %s: %v", name, err)
				}
				return def
			}
			columnType := func(table, column string) string {
				t.Helper()
				var dataType string
				if err := db.QueryRow(
					`SELECT data_type FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`,
					table, column,
				).Scan(&dataType); err != nil {
					t.Fatalf("%s.%s: query data_type: %v", table, column, err)
				}
				return dataType
			}

			bankingViews := []string{"sebi_audit_retention_status", "mas_audit_retention_status"}
			for _, v := range bankingViews {
				if got := viewExists(v); got != tc.hasBanking {
					t.Fatalf("pre-upgrade: view %s exists=%v, want %v (mode %s)", v, got, tc.hasBanking, tc.mode)
				}
			}
			if got := columnType("policy_violations", "created_at"); got != "timestamp without time zone" {
				t.Fatalf("pre-upgrade: policy_violations.created_at = %q, want tz-naive", got)
			}

			// ---- Seed data + snapshot view definitions ----
			if _, err := db.Exec(`
				INSERT INTO static_policies (org_id, policy_id, name, category, pattern, severity, action, metadata)
				VALUES
				  ('local-dev-org', 'upg-sebi-policy', 'Upgrade Test SEBI', 'compliance-sebi', 'x', 'high', 'block',
				   '{"compliance_framework": "SEBI", "audit_retention_years": 5}'::jsonb),
				  ('local-dev-org', 'upg-mas-policy', 'Upgrade Test MAS', 'compliance-masfeat', 'x', 'high', 'block',
				   '{"compliance_framework": "MAS_FEAT", "audit_retention_years": 7}'::jsonb)
			`); err != nil {
				t.Fatalf("seed static_policies: %v", err)
			}
			if _, err := db.Exec(
				`INSERT INTO policy_violations (org_id, violation_type, severity, description, created_at)
				 VALUES ('local-dev-org', 'upg-sebi-policy', 'high', 'upgrade-path seed', $1::timestamp)`,
				seedNaiveTimestamp,
			); err != nil {
				t.Fatalf("seed policy_violations: %v", err)
			}

			// Snapshot the definition of EVERY view/matview the two migrations
			// drop and recreate (not just the banking pair): pg_get_viewdef
			// equality across the upgrade is the strongest verbatim-recreate
			// check and catches silent drift (a lost ORDER BY, a changed
			// filter) that presence checks cannot.
			recreatedViews := []string{
				"llm_cost_summary",
				"sebi_audit_retention_status",
				"mas_audit_retention_status",
				"org_node_counts",
				"marketplace_usage_summary",
				"marketplace_monthly_usage",
			}
			preDefs := map[string]string{}
			for _, v := range recreatedViews {
				if viewExists(v) {
					preDefs[v] = viewDef(v)
				}
			}
			assertRecreatedViews := func(stage string) {
				t.Helper()
				for _, v := range recreatedViews {
					_, existedBefore := preDefs[v]
					if got := viewExists(v); got != existedBefore {
						t.Fatalf("%s: view %s exists=%v, want %v (pre-upgrade state)", stage, v, got, existedBefore)
					}
					if existedBefore {
						if got := viewDef(v); got != preDefs[v] {
							t.Errorf("%s: %s definition drifted from pre-upgrade snapshot:\n--- pre ---\n%s\n--- post ---\n%s",
								stage, v, preDefs[v], got)
						}
					}
				}
			}
			if tc.hasBanking {
				var pre int
				if err := db.QueryRow(
					`SELECT total_violations FROM sebi_audit_retention_status WHERE policy_id = 'upg-sebi-policy'`,
				).Scan(&pre); err != nil {
					t.Fatalf("pre-upgrade sebi view query: %v", err)
				}
				if pre != 1 {
					t.Fatalf("pre-upgrade sebi view total_violations = %d, want 1", pre)
				}
			}

			// ---- Phase 2: the upgrade — apply 133 then 142 (runner order) ----
			for _, m := range deferred {
				apply(m)
			}

			assertUpgraded := func(stage string) {
				t.Helper()
				for _, c := range timestamptzTargetColumns {
					if got := columnType(c.table, c.column); got != "timestamp with time zone" {
						t.Errorf("%s: %s.%s = %q, want timestamptz", stage, c.table, c.column, got)
					}
				}
				if tc.hasEnterprise {
					for _, c := range enterpriseTimestamptzTargetColumns {
						if got := columnType(c.table, c.column); got != "timestamp with time zone" {
							t.Errorf("%s: %s.%s = %q, want timestamptz", stage, c.table, c.column, got)
						}
					}
				}
				for _, v := range bankingViews {
					if got := viewExists(v); got != tc.hasBanking {
						t.Fatalf("%s: view %s exists=%v, want %v", stage, v, got, tc.hasBanking)
					}
				}
				assertRecreatedViews(stage)
				if tc.hasBanking {
					var total int
					var instantOK bool
					if err := db.QueryRow(
						`SELECT total_violations, oldest_violation = $1::timestamptz
						 FROM sebi_audit_retention_status WHERE policy_id = 'upg-sebi-policy'`,
						seedUTCInstant,
					).Scan(&total, &instantOK); err != nil {
						t.Fatalf("%s: sebi view query: %v", stage, err)
					}
					if total != 1 {
						t.Errorf("%s: sebi view total_violations = %d, want 1", stage, total)
					}
					if !instantOK {
						t.Errorf("%s: sebi view oldest_violation != %s — conversion was not pinned to UTC (session zone leaked in)", stage, seedUTCInstant)
					}
				}
				// Direct table-level conversion check (every mode).
				var instantOK bool
				if err := db.QueryRow(
					`SELECT created_at = $1::timestamptz FROM policy_violations WHERE violation_type = 'upg-sebi-policy'`,
					seedUTCInstant,
				).Scan(&instantOK); err != nil {
					t.Fatalf("%s: policy_violations conversion query: %v", stage, err)
				}
				if !instantOK {
					t.Errorf("%s: policy_violations.created_at != %s — conversion was not pinned to UTC", stage, seedUTCInstant)
				}
			}
			assertUpgraded("post-upgrade")

			// ---- Idempotency: re-running the upgrade migrations is a no-op ----
			for _, m := range deferred {
				apply(m)
			}
			assertUpgraded("idempotent-rerun")

			// ---- Down round-trip: 142_down first, then 133_down (reverse) ----
			downFor := func(m MigrationFile) string {
				return strings.TrimSuffix(m.Path, ".sql") + "_down.sql"
			}
			for i := len(deferred) - 1; i >= 0; i-- {
				downPath := downFor(deferred[i])
				sqlBytes, readErr := os.ReadFile(downPath)
				if readErr != nil {
					t.Fatalf("read down migration %s: %v", downPath, readErr)
				}
				if _, execErr := db.Exec(string(sqlBytes)); execErr != nil {
					t.Fatalf("apply down migration %s: %v", filepath.Base(downPath), execErr)
				}
			}
			for _, c := range timestamptzTargetColumns {
				if got := columnType(c.table, c.column); got != "timestamp without time zone" {
					t.Errorf("post-down: %s.%s = %q, want tz-naive", c.table, c.column, got)
				}
			}
			if tc.hasEnterprise {
				for _, c := range enterpriseTimestamptzTargetColumns {
					if got := columnType(c.table, c.column); got != "timestamp without time zone" {
						t.Errorf("post-down: %s.%s = %q, want tz-naive", c.table, c.column, got)
					}
				}
			}
			for _, v := range bankingViews {
				if got := viewExists(v); got != tc.hasBanking {
					t.Fatalf("post-down: view %s exists=%v, want %v", v, got, tc.hasBanking)
				}
			}
			assertRecreatedViews("post-down")
			// The down conversion must restore the exact naive digits.
			var naiveOK bool
			if err := db.QueryRow(
				`SELECT created_at = $1::timestamp FROM policy_violations WHERE violation_type = 'upg-sebi-policy'`,
				seedNaiveTimestamp,
			).Scan(&naiveOK); err != nil {
				t.Fatalf("post-down: naive round-trip query: %v", err)
			}
			if !naiveOK {
				t.Errorf("post-down: policy_violations.created_at != %q — down conversion not pinned to UTC", seedNaiveTimestamp)
			}

			// ---- Re-up ----
			for _, m := range deferred {
				apply(m)
			}
			assertUpgraded("re-up")

			// ---- Option3 api_keys variant guard (142_down) ----
			// The in-VPC option3 auth schema
			// (platform/database/migrations/006_option3_auth_system.sql)
			// declares api_keys natively TIMESTAMPTZ; 142's up therefore never
			// converts it, and 142_down must NOT flip it to naive (that would
			// break auth_lookup_api_key's TIMESTAMPTZ RETURNS TABLE). The down
			// gates the api_keys revert on the option3 discriminator column,
			// license_key_hash — simulate that variant and prove the gate.
			if tc.mode == "in-vpc-banking" {
				if _, err := db.Exec(`ALTER TABLE api_keys ADD COLUMN license_key_hash VARCHAR(64)`); err != nil {
					t.Fatalf("add option3 discriminator column: %v", err)
				}
				downSQL, readErr := os.ReadFile("../../migrations/core/142_timestamp_columns_to_timestamptz_down.sql")
				if readErr != nil {
					t.Fatalf("read 142 down: %v", readErr)
				}
				if _, execErr := db.Exec(string(downSQL)); execErr != nil {
					t.Fatalf("142 down with option3 discriminator present: %v", execErr)
				}
				for _, col := range []string{"last_used_at", "created_at", "expires_at", "revoked_at"} {
					if got := columnType("api_keys", col); got != "timestamp with time zone" {
						t.Errorf("option3 guard: api_keys.%s = %q after down — the variant gate failed and a natively-TZ auth schema was flipped to naive", col, got)
					}
				}
				// A non-api_keys column must still have been reverted.
				if got := columnType("organizations", "expires_at"); got != "timestamp without time zone" {
					t.Errorf("option3 guard: organizations.expires_at = %q, want tz-naive (down should still revert non-api_keys columns)", got)
				}
				// Remove the discriminator: the gate opens and down reverts api_keys.
				if _, err := db.Exec(`ALTER TABLE api_keys DROP COLUMN license_key_hash`); err != nil {
					t.Fatalf("drop option3 discriminator column: %v", err)
				}
				if _, execErr := db.Exec(string(downSQL)); execErr != nil {
					t.Fatalf("142 down without option3 discriminator: %v", execErr)
				}
				for _, col := range []string{"last_used_at", "created_at", "expires_at", "revoked_at"} {
					if got := columnType("api_keys", col); got != "timestamp without time zone" {
						t.Errorf("option3 guard: api_keys.%s = %q, want tz-naive on the 002 schema", col, got)
					}
				}
				// Restore the fully-upgraded end state.
				for _, m := range deferred {
					apply(m)
				}
				assertUpgraded("post-option3-guard-re-up")
			}
		})
	}
}
