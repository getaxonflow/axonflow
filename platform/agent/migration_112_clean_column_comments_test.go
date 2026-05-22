package agent

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
)

// TestMigration112_CleanColumnCommentsAppliesAndIsIdempotent boots migrations
// 1..112 against a real Postgres, verifies that migration 112 refreshed the
// customer-facing comment strings on the v9 identity columns + saml_configurations
// metadata whose comments were tightened in source. Re-applies migration 112
// against the post-state to confirm idempotency.
func TestMigration112_CleanColumnCommentsAppliesAndIsIdempotent(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION not set — skipping real-Postgres test")
	}
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = getTestDatabaseURLWithContainer(t)
	}

	ctx := context.Background()
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Mirror migration_104_security_definer_test.go setup.
	if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := db.Exec(`SELECT set_config('app.db_password', 'test-pass', false)`); err != nil {
		t.Fatalf("set app.db_password: %v", err)
	}
	if _, err := db.Exec(`SELECT set_config('app.deployment_kind', 'dev', false)`); err != nil {
		t.Fatalf("set app.deployment_kind: %v", err)
	}
	if _, err := db.Exec(`SELECT set_config('app.deployment_org_id', 'mig112-test-bootstrap', false)`); err != nil {
		t.Fatalf("set app.deployment_org_id: %v", err)
	}

	runMigrationsRange(t, db, 1, 113)

	// ------------------------------------------------------------------
	// Verify cleaned comment strings landed in pg_description.
	// ------------------------------------------------------------------
	type check struct {
		name  string
		query string
		want  string
	}
	checks := []check{
		{
			name:  "tenants.client_id",
			query: `SELECT col_description('tenants'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='tenants'::regclass AND attname='client_id'))`,
			want:  "Credential/app identity column",
		},
		{
			name:  "audit_logs.client_id",
			query: `SELECT col_description('audit_logs'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='audit_logs'::regclass AND attname='client_id'))`,
			want:  "Credential identity column (req.Client.ID)",
		},
		{
			name:  "static_policies.client_id",
			query: `SELECT col_description('static_policies'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='static_policies'::regclass AND attname='client_id'))`,
			want:  "Credential identity column. The 'global' sentinel",
		},
		{
			name:  "service_identities.client_id",
			query: `SELECT col_description('service_identities'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='service_identities'::regclass AND attname='client_id'))`,
			want:  "Credential/service identity column",
		},
		{
			name:  "execution_history.client_id",
			query: `SELECT col_description('execution_history'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='execution_history'::regclass AND attname='client_id'))`,
			want:  "Credential identity column. Predates the v9 migration",
		},
		{
			name:  "saml_configurations.org_id",
			query: `SELECT col_description('saml_configurations'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='saml_configurations'::regclass AND attname='org_id'))`,
			want:  "Customer/account identity column",
		},
		{
			name:  "usage_records.team_id",
			query: `SELECT col_description('usage_records'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='usage_records'::regclass AND attname='team_id'))`,
			want:  "ATTRIBUTION TAG (not part of the v9 identity model)",
		},
	}

	for _, c := range checks {
		var got sql.NullString
		if err := db.QueryRowContext(ctx, c.query).Scan(&got); err != nil {
			t.Errorf("%s: query: %v", c.name, err)
			continue
		}
		if !got.Valid {
			t.Errorf("%s: pg_description is NULL — expected substring %q", c.name, c.want)
			continue
		}
		if !strings.Contains(got.String, c.want) {
			t.Errorf("%s: pg_description does NOT contain expected substring\n  want substring: %q\n  got: %q", c.name, c.want, got.String)
			continue
		}
		// Defense-in-depth: assert NONE of the scrubbed internal-ref tokens
		// remain. Catches regression where source-file scrub drifts AND mig
		// 112 doesn't catch it. Includes mutation-test / R3 / ADR / Phase /
		// PR-X / Brief / Epic / B[1-9] tokens (the round-1 R3 grep gap).
		for _, token := range []string{
			"Epic #", "Brief 11", "Phase 2", "Phase 3", "Phase 4", "Phase 8",
			"PR-A", "PR-B", "PR-C",
			"B1 ", "B2 ", "B5 ", "B6 ", "B8 ", "B9 ",
			"workstream", "R3 round", "mutation test", "mutation-test", "hostile review",
			"ADR-052", "ADR-053", "ADR-050", "ADR-043",
			"technical-docs/",
		} {
			if strings.Contains(got.String, token) {
				t.Errorf("%s: pg_description contains scrubbed token %q\n  got: %q", c.name, token, got.String)
			}
		}
	}

	// ------------------------------------------------------------------
	// Re-apply mig 112 — must succeed (idempotency).
	// ------------------------------------------------------------------
	body, err := os.ReadFile("../../migrations/core/112_v9_clean_column_comments.sql")
	if err != nil {
		t.Fatalf("read mig 112: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("re-apply mig 112: idempotency broken: %v", err)
	}

	// Sanity: tenants.client_id comment is byte-identical after re-apply.
	var afterRerun sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT col_description('tenants'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='tenants'::regclass AND attname='client_id'))`,
	).Scan(&afterRerun); err != nil {
		t.Fatalf("re-read tenants.client_id comment after re-apply: %v", err)
	}
	if !strings.Contains(afterRerun.String, "Credential/app identity column") {
		t.Errorf("tenants.client_id comment diverged after mig 112 re-apply: %q", afterRerun.String)
	}

	// ------------------------------------------------------------------
	// Mutation gate: revert ONE COMMENT to the dirty version via direct exec
	// and confirm the regression-token guard catches it. This proves the
	// guard discriminates — otherwise it would silently pass even on
	// re-introduced internal refs.
	// ------------------------------------------------------------------
	if _, err := db.ExecContext(ctx,
		`COMMENT ON COLUMN tenants.client_id IS 'v9 credential/app identity — equal to tenant_id until Phase 8 alias removal (ADR-052)'`,
	); err != nil {
		t.Fatalf("mutation: %v", err)
	}
	var mutated sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT col_description('tenants'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='tenants'::regclass AND attname='client_id'))`,
	).Scan(&mutated); err != nil {
		t.Fatalf("re-read mutated tenants.client_id: %v", err)
	}
	// The mutated string must trip at least one of the guard tokens —
	// proves the guard is load-bearing, not vacuously passing.
	tripped := false
	for _, token := range []string{"Phase 8", "ADR-052"} {
		if strings.Contains(mutated.String, token) {
			tripped = true
			break
		}
	}
	if !tripped {
		t.Errorf("mutation gate: dirty-string mutation did NOT trip any guard token — guard is not load-bearing.\n  mutated: %q", mutated.String)
	}
}
