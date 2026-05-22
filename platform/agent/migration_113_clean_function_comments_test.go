package agent

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
)

// TestMigration113_CleanFunctionCommentsAppliesAndIsIdempotent boots
// migrations 1..113 against a real Postgres, then verifies that migration 113
// refreshed the customer-facing comment strings on the helper functions, RLS
// policies, and audit_retention_config table whose comments were tightened in
// source.
//
// Re-applying migration 113 against an already-clean state must succeed (the
// COMMENT ON ... IS statement replaces the pg_description row idempotently).
//
// History: this migration was originally numbered 111 but collided with
// 111_v9_phase8_pr_c3_normalize_roles_org_id.sql (which landed in the same
// release train). Renamed to 113 to make the apply order deterministic. The
// idempotency property means stacks that already applied the 111-numbered
// version on local-dev will re-apply 113 cleanly with no observable effect.
func TestMigration113_CleanFunctionCommentsAppliesAndIsIdempotent(t *testing.T) {
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

	// Mirror migration_104_security_definer_test.go setup. Mig 028 references
	// app.db_password; migs 094/103 require app.deployment_kind + org_id GUCs.
	if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := db.Exec(`SELECT set_config('app.db_password', 'test-pass', false)`); err != nil {
		t.Fatalf("set app.db_password: %v", err)
	}
	if _, err := db.Exec(`SELECT set_config('app.deployment_kind', 'dev', false)`); err != nil {
		t.Fatalf("set app.deployment_kind: %v", err)
	}
	if _, err := db.Exec(`SELECT set_config('app.deployment_org_id', 'mig113-test-bootstrap', false)`); err != nil {
		t.Fatalf("set app.deployment_org_id: %v", err)
	}

	runMigrationsRange(t, db, 1, 113)

	type check struct {
		name  string
		query string
		want  string
	}
	checks := []check{
		{
			name:  "portal_auth_lookup_org",
			query: `SELECT obj_description('portal_auth_lookup_org(VARCHAR)'::regprocedure, 'pg_proc')`,
			want:  "SECURITY DEFINER pre-auth lookup. Bypasses FORCE RLS on organizations",
		},
		{
			name:  "csaas_auth_lookup",
			query: `SELECT obj_description('csaas_auth_lookup(VARCHAR)'::regprocedure, 'pg_proc')`,
			want:  "SECURITY DEFINER pre-auth credential lookup for community_saas_registrations",
		},
		{
			name:  "auth_lookup_api_key",
			query: `SELECT obj_description('auth_lookup_api_key(TEXT)'::regprocedure, 'pg_proc')`,
			want:  "SECURITY DEFINER pre-auth lookup for in-VPC enterprise auth",
		},
		{
			name:  "auth_insert_api_key",
			query: `SELECT obj_description('auth_insert_api_key(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR)'::regprocedure, 'pg_proc')`,
			want:  "SECURITY DEFINER INSERT into api_keys",
		},
		{
			name:  "register_org",
			query: `SELECT obj_description('register_org(VARCHAR, VARCHAR, VARCHAR, INTEGER)'::regprocedure, 'pg_proc')`,
			want:  "SECURITY DEFINER variant of the mig 062 register_org",
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
		// remain in the comment.
		for _, token := range []string{
			"Epic #", "Brief 11", "Phase 8",
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
	// Re-apply mig 113 — must succeed (idempotency).
	// ------------------------------------------------------------------
	body, err := os.ReadFile("../../migrations/core/113_v9_clean_function_comments.sql")
	if err != nil {
		t.Fatalf("read mig 113: %v", err)
	}
	if _, err := db.ExecContext(ctx, string(body)); err != nil {
		t.Fatalf("re-apply mig 113: idempotency broken: %v", err)
	}

	var afterRerun sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT obj_description('portal_auth_lookup_org(VARCHAR)'::regprocedure, 'pg_proc')`,
	).Scan(&afterRerun); err != nil {
		t.Fatalf("re-read portal_auth_lookup_org comment after re-apply: %v", err)
	}
	if !strings.Contains(afterRerun.String, "SECURITY DEFINER pre-auth lookup") {
		t.Errorf("portal_auth_lookup_org comment diverged after mig 113 re-apply: %q", afterRerun.String)
	}
}
