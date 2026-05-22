// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 B9 (Brief 11 PR B): real-Postgres contract tests for
// migrations 105 + 106 — B9 completion FORCE RLS on
// community_saas_registrations + sso_configurations + sister tables.
//
// What this pins:
//   - csaas_auth_lookup() works under FORCE RLS on community_saas_registrations
//     (the pre-auth credential bootstrap that issue #2337 closes).
//   - sso_configurations + sso_sessions + sso_login_attempts have org_id
//     column NOT NULL + canonical app.current_org_id policy + FORCE.
//   - The old app.tenant_id policy is removed.
//   - portal_check_sso_availability now queries by s.org_id.
//   - Mutation proof: ALTER FUNCTION csaas_auth_lookup SECURITY INVOKER →
//     the SAME caller (axonflow_app_role, no SET LOCAL) starts getting
//     empty rows. SECURITY DEFINER is load-bearing.
//
// Gated on TEST_PG_INTEGRATION=1 + TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
)

func TestMigrations105_106_B9CompletionUnderForceRLS(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION not set — skipping")
	}
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping")
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

	// Schema reset + GUCs (same setup as v9_followup_a_gaps_test.go).
	if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	for _, guc := range []struct{ k, v string }{
		{"app.db_password", "test-pass"},
		{"app.deployment_kind", "dev"},
		{"app.deployment_org_id", "mig105-test-bootstrap"},
	} {
		if _, err := db.Exec("SELECT set_config($1, $2, false)", guc.k, guc.v); err != nil {
			t.Fatalf("set %s: %v", guc.k, err)
		}
	}

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "RESET ROLE")
	})

	// Apply core migrations 1-106. Without mig 104 on disk (PR A unmerged
	// branch), the runner just skips it; my mig 105 + 106 are self-contained.
	runMigrationsRange(t, db, 1, 106)

	// Apply enterprise migrations: 065 (portal tenant identity) + 103
	// (organization passwords) + 108 (sso_configurations table + sister tables).
	// Then re-run 106 so its org_id column + FORCE step applies AFTER the
	// sso_configurations table exists (the migration's IF EXISTS guards
	// skip when run before the enterprise schema is in place).
	for _, mig := range []string{
		"../../migrations/enterprise/065_customer_portal_tenant_identity.sql",
		"../../migrations/enterprise/103_organization_passwords.sql",
		"../../migrations/enterprise/108_sso_configuration.sql",
	} {
		body, err := os.ReadFile(mig)
		if err != nil {
			t.Fatalf("read %s: %v", mig, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", mig, err)
		}
	}

	// Pre-install a minimal portal_check_sso_availability stub that mirrors
	// mig 104's body (PR A unmerged). This lets mig 106's R3-H3-gated Step 6
	// proceed — the gate verifies the function already exists before
	// applying the org_id-aware body update. In production, mig 104 + mig
	// 106 stack and Step 6's update lands automatically.
	mig104Stub := `
	CREATE OR REPLACE FUNCTION portal_check_sso_availability(p_org_id VARCHAR)
	    RETURNS TABLE(org_exists BOOLEAN, provider VARCHAR, enabled BOOLEAN, enforce_sso BOOLEAN)
	    LANGUAGE plpgsql
	    STABLE
	    SECURITY DEFINER
	AS $body$
	BEGIN
	    RETURN QUERY SELECT TRUE, NULL::VARCHAR, FALSE, FALSE;
	END;
	$body$;`
	if _, err := db.Exec(mig104Stub); err != nil {
		t.Fatalf("install mig104 stub: %v", err)
	}

	// Re-apply mig 106 so its sso_* schema work runs against the now-present
	// tables. mig 106 is fully idempotent.
	body, err := os.ReadFile("../../migrations/core/106_v9_b9_completion_sso_configurations.sql")
	if err != nil {
		t.Fatalf("read mig 106: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("re-apply mig 106: %v", err)
	}

	// ========================================================================
	// Pin 1: csaas_auth_lookup is SECURITY DEFINER (mig 105 verification)
	// ========================================================================
	var prosecdef bool
	if err := db.QueryRowContext(ctx,
		`SELECT prosecdef FROM pg_proc WHERE proname = 'csaas_auth_lookup'`,
	).Scan(&prosecdef); err != nil {
		t.Fatalf("query prosecdef for csaas_auth_lookup: %v", err)
	}
	if !prosecdef {
		t.Fatal("csaas_auth_lookup is NOT SECURITY DEFINER — mig 105 didn't apply correctly")
	}

	// ========================================================================
	// Pin 2: community_saas_registrations has FORCE RLS active
	// ========================================================================
	var forced bool
	if err := db.QueryRowContext(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname = 'community_saas_registrations'`,
	).Scan(&forced); err != nil {
		t.Fatalf("query FORCE on community_saas_registrations: %v", err)
	}
	if !forced {
		t.Fatal("FORCE RLS not active on community_saas_registrations")
	}

	// ========================================================================
	// Pin 3: sso_configurations + sister tables have org_id NOT NULL + FORCE +
	// canonical app.current_org_id policy
	// ========================================================================
	for _, tbl := range []string{"sso_configurations", "sso_sessions", "sso_login_attempts"} {
		var isNullable string
		if err := db.QueryRowContext(ctx,
			`SELECT is_nullable FROM information_schema.columns
			 WHERE table_name = $1 AND column_name = 'org_id'`,
			tbl,
		).Scan(&isNullable); err != nil {
			t.Fatalf("query org_id nullability on %s: %v", tbl, err)
		}
		if isNullable != "NO" {
			t.Errorf("%s.org_id is %s, want NOT NULL", tbl, isNullable)
		}

		var tblForced bool
		if err := db.QueryRowContext(ctx,
			`SELECT relforcerowsecurity FROM pg_class WHERE relname = $1`,
			tbl,
		).Scan(&tblForced); err != nil {
			t.Fatalf("query FORCE on %s: %v", tbl, err)
		}
		if !tblForced {
			t.Errorf("FORCE RLS not active on %s", tbl)
		}

		var policyCount int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pg_policies
			 WHERE tablename = $1 AND qual LIKE '%app.current_org_id%'`,
			tbl,
		).Scan(&policyCount); err != nil {
			t.Fatalf("query policy on %s: %v", tbl, err)
		}
		if policyCount == 0 {
			t.Errorf("%s has no app.current_org_id policy", tbl)
		}
	}

	// Assert NO remaining app.tenant_id policy on these tables.
	var tenantIDPolicyCount int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pg_policies
		 WHERE tablename IN ('sso_configurations','sso_sessions','sso_login_attempts')
		   AND qual LIKE '%app.tenant_id%'`,
	).Scan(&tenantIDPolicyCount); err != nil {
		t.Fatalf("query legacy tenant_id policy: %v", err)
	}
	if tenantIDPolicyCount > 0 {
		t.Errorf("legacy app.tenant_id policy still present on a sso_* table (%d remaining)", tenantIDPolicyCount)
	}

	// ========================================================================
	// Pin 4: portal_check_sso_availability queries by s.org_id (post-mig-106)
	// ========================================================================
	// Probe the function source to confirm the body references s.org_id.
	var fnSrc string
	if err := db.QueryRowContext(ctx,
		`SELECT prosrc FROM pg_proc WHERE proname = 'portal_check_sso_availability'`,
	).Scan(&fnSrc); err != nil {
		t.Fatalf("query portal_check_sso_availability source: %v", err)
	}
	if !strings.Contains(fnSrc, "s.org_id = p_org_id") {
		t.Errorf("portal_check_sso_availability not updated to query by s.org_id; body still uses old key")
	}

	// ========================================================================
	// Pin 5: csaas_auth_lookup works under FORCE RLS as axonflow_app_role
	// (no SET LOCAL needed because SECURITY DEFINER bypasses)
	// ========================================================================
	// Seed a csaas registration row.
	const testTenantID = "mig105-test-tenant-1"
	const testOrgID = "mig105-test-org-1"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO community_saas_registrations
		    (tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at)
		VALUES ($1, $1, 'placeholder-bcrypt', 'pfx', $2, 'test', NOW() + INTERVAL '7 days')
		ON CONFLICT (tenant_id) DO UPDATE SET
		    org_id = EXCLUDED.org_id,
		    secret_hash = EXCLUDED.secret_hash
	`, testTenantID, testOrgID); err != nil {
		t.Fatalf("seed csaas registration: %v", err)
	}

	// Switch to axonflow_app_role.
	if _, err := db.ExecContext(ctx, "GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		if !strings.Contains(err.Error(), "is a member of role") && !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("GRANT app_role: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
		t.Fatalf("SET ROLE: %v", err)
	}

	// Call csaas_auth_lookup as app_role with NO SET LOCAL — should return the row.
	t.Run("csaas_auth_lookup_under_force_rls", func(t *testing.T) {
		var secretHash string
		var expiresAt sql.NullTime
		var disabledAt sql.NullTime
		var terminatedAt sql.NullTime
		var orgID sql.NullString
		err := db.QueryRowContext(ctx,
			`SELECT secret_hash, expires_at, disabled_at, terminated_at, org_id
			 FROM csaas_auth_lookup($1)`,
			testTenantID,
		).Scan(&secretHash, &expiresAt, &disabledAt, &terminatedAt, &orgID)
		if err != nil {
			t.Fatalf("csaas_auth_lookup as app_role: %v (should bypass FORCE via SECURITY DEFINER)", err)
		}
		if secretHash != "placeholder-bcrypt" {
			t.Errorf("secret_hash mismatch: got %s, want placeholder-bcrypt", secretHash)
		}
		if !orgID.Valid || orgID.String != testOrgID {
			t.Errorf("org_id mismatch: got %v, want %s", orgID, testOrgID)
		}

		// Non-existent tenant_id → sql.ErrNoRows.
		err = db.QueryRowContext(ctx,
			`SELECT secret_hash, expires_at, disabled_at, terminated_at, org_id
			 FROM csaas_auth_lookup($1)`,
			"mig105-test-nonexistent",
		).Scan(&secretHash, &expiresAt, &disabledAt, &terminatedAt, &orgID)
		if err != sql.ErrNoRows {
			t.Errorf("expected ErrNoRows for non-existent tenant, got %v", err)
		}
	})

	// ========================================================================
	// Pin 6: Mutation proof — flip csaas_auth_lookup to SECURITY INVOKER.
	// Under FORCE RLS as axonflow_app_role with no SET LOCAL, the function's
	// internal SELECT returns 0 rows. The caller sees ErrNoRows.
	// ========================================================================
	t.Run("MutationProof_csaas_auth_lookup_security_invoker", func(t *testing.T) {
		_, _ = db.ExecContext(ctx, "RESET ROLE") // need superuser to ALTER FUNCTION

		if _, err := db.ExecContext(ctx,
			"ALTER FUNCTION csaas_auth_lookup(VARCHAR) SECURITY INVOKER",
		); err != nil {
			t.Fatalf("ALTER FUNCTION SECURITY INVOKER: %v", err)
		}
		// R3-LOW-1 pattern (from PR A) — RESET ROLE before deferred ALTER so
		// it runs as superuser, not app_role.
		defer func() {
			_, _ = db.ExecContext(ctx, "RESET ROLE")
			_, _ = db.ExecContext(ctx,
				"ALTER FUNCTION csaas_auth_lookup(VARCHAR) SECURITY DEFINER",
			)
		}()

		if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
			t.Fatalf("SET ROLE: %v", err)
		}

		var secretHash string
		var expiresAt sql.NullTime
		var disabledAt sql.NullTime
		var terminatedAt sql.NullTime
		var orgID sql.NullString
		err := db.QueryRowContext(ctx,
			`SELECT secret_hash, expires_at, disabled_at, terminated_at, org_id
			 FROM csaas_auth_lookup($1)`,
			testTenantID,
		).Scan(&secretHash, &expiresAt, &disabledAt, &terminatedAt, &orgID)
		if err != sql.ErrNoRows {
			t.Fatalf("expected ErrNoRows after SECURITY INVOKER flip (row hidden by FORCE), got err=%v secretHash=%s", err, secretHash)
		}
		t.Logf("mutation proof: SECURITY INVOKER on csaas_auth_lookup returned ErrNoRows under FORCE RLS — SECURITY DEFINER is load-bearing")
	})

	// ========================================================================
	// Pin 7: Cross-org isolation — seed two csaas rows in different orgs,
	// SET LOCAL app.current_org_id = orgA, verify only orgA's row is visible
	// even with NO function call (direct SELECT path).
	// ========================================================================
	t.Run("CrossOrgIsolation_DirectSelect", func(t *testing.T) {
		_, _ = db.ExecContext(ctx, "RESET ROLE") // as superuser, seed orgB

		const orgB = "mig105-test-org-B"
		const tenantB = "mig105-test-tenant-B"
		if _, err := db.ExecContext(ctx, `
			INSERT INTO community_saas_registrations
			    (tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at)
			VALUES ($1, $1, 'hashB', 'pfxB', $2, 'B', NOW() + INTERVAL '7 days')
			ON CONFLICT (tenant_id) DO UPDATE SET org_id = EXCLUDED.org_id
		`, tenantB, orgB); err != nil {
			t.Fatalf("seed orgB: %v", err)
		}

		// Switch back to app_role for the isolation test.
		if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
			t.Fatalf("SET ROLE: %v", err)
		}

		// Begin tx + set GUC to orgA only.
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx,
			"SELECT set_config('app.current_org_id', $1, true)", testOrgID,
		); err != nil {
			t.Fatalf("set_config orgA: %v", err)
		}

		// Direct SELECT as app_role under FORCE RLS — should see ONLY orgA's row.
		var count int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM community_saas_registrations`,
		).Scan(&count); err != nil {
			t.Fatalf("count under orgA scope: %v", err)
		}
		if count != 1 {
			t.Errorf("under app.current_org_id=orgA, expected to see 1 csaas row, saw %d", count)
		}
	})
}
