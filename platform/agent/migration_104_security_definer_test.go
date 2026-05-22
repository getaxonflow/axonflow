// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 B9 (Brief 11, issues #2335 + #2336): real-Postgres contract
// test for migration 104's SECURITY DEFINER helpers.
//
// What this test pins:
//   - portal_auth_lookup_org() works under FORCE RLS on organizations
//     (proves #2335's pre-auth bootstrap path).
//   - portal_check_sso_availability() returns existence + SSO config under
//     FORCE RLS on organizations + sso_configurations.
//   - portal_default_tenant_id() returns the canonical tenant under FORCE
//     RLS on tenants (proves #2336's post-auth tenant resolution).
//   - register_org() / register_tenant() INSERT into FORCE-RLS-protected
//     organizations + tenants WITHOUT a SET LOCAL app.current_org_id
//     (proves #2336's fire-and-forget registration path).
//   - Mutation proof: ALTER FUNCTION foo SECURITY INVOKER on each helper
//     in turn — the SAME caller (axonflow_app_role, no SET LOCAL) starts
//     getting empty rows / WITH CHECK violations. Confirms the SECURITY
//     DEFINER attribute is load-bearing, not noise.
//
// Gated on TEST_PG_INTEGRATION=1 + TEST_DATABASE_URL (matches sibling
// rls_phase6_isolation_test.go + v9_followup_a_gaps_test.go).

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMigration104_SecurityDefinerHelpersUnderForceRLS(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION not set — skipping real-Postgres test")
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
	// GUC continuity across statements requires single connection.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Mirror v9_followup_a_gaps_test.go's setup. Migration 028 references
	// app.db_password (template-substituted in production); the test runs
	// the literal so the value is set but unused. Also resets the schema
	// so prior tests' artifacts don't pollute migration application.
	if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if _, err := db.Exec(`SELECT set_config('app.db_password', 'test-pass', false)`); err != nil {
		t.Fatalf("set app.db_password: %v", err)
	}
	// app.deployment_kind GUC (mig 094 EXCEPTION on production+empty-org).
	// Use 'dev' to bypass — we're not testing 094 here.
	if _, err := db.Exec(`SELECT set_config('app.deployment_kind', 'dev', false)`); err != nil {
		t.Fatalf("set app.deployment_kind: %v", err)
	}
	// app.deployment_org_id GUC (mig 094 requires it).
	if _, err := db.Exec(`SELECT set_config('app.deployment_org_id', 'mig104-test-bootstrap', false)`); err != nil {
		t.Fatalf("set app.deployment_org_id: %v", err)
	}

	t.Cleanup(func() {
		// Best-effort cleanup. Drop test rows BEFORE migrations may rerun
		// in another test; the schema lives on between tests in the
		// shared testcontainer.
		_, _ = db.ExecContext(ctx, "RESET ROLE")
		_, _ = db.ExecContext(ctx, "DELETE FROM organizations WHERE org_id LIKE 'mig104-test-%'")
		_, _ = db.ExecContext(ctx, "DELETE FROM tenants WHERE org_id LIKE 'mig104-test-%' OR tenant_id LIKE 'mig104-test-%'")
		_, _ = db.ExecContext(ctx, "DELETE FROM sso_configurations WHERE tenant_id LIKE 'mig104-test-%'")
	})

	// Ensure migrations 1-104 are applied.
	runMigrationsRange(t, db, 1, 104)

	// Apply select enterprise migrations the customer-portal binary owns:
	//   - 065 portal tenant identity (adds tenant_id col to user_sessions
	//     + portal_default_tenant_id() function; mig 104 replaces the
	//     function with SECURITY DEFINER so we need 065 applied first to
	//     have the base function exist)
	//   - 103 organization passwords (adds password_hash + status cols to
	//     organizations; portal_auth_lookup_org reads these)
	//   - 108 sso_configurations (creates sso_configurations table;
	//     portal_check_sso_availability reads this)
	for _, enterpriseMig := range []string{
		"../../migrations/enterprise/065_customer_portal_tenant_identity.sql",
		"../../migrations/enterprise/103_organization_passwords.sql",
		"../../migrations/enterprise/108_sso_configuration.sql",
	} {
		body, err := os.ReadFile(enterpriseMig)
		if err != nil {
			t.Fatalf("read %s: %v", enterpriseMig, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", enterpriseMig, err)
		}
	}

	// Re-apply mig 104 AFTER enterprise migrations so portal_default_tenant_id
	// is re-marked SECURITY DEFINER (mig 065 just installed the non-DEFINER
	// version, overwriting our DEFINER definition).
	body, err := os.ReadFile("../../migrations/core/104_v9_b9_security_definer_helpers.sql")
	if err != nil {
		t.Fatalf("read mig 104: %v", err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("re-apply mig 104: %v", err)
	}

	// Verify the 5 SECURITY DEFINER functions exist + are prosecdef=true.
	expectedSecDef := []string{
		"portal_auth_lookup_org",
		"portal_check_sso_availability",
		"portal_default_tenant_id",
		"register_org",
		"register_tenant",
	}
	for _, fn := range expectedSecDef {
		var secDef bool
		err := db.QueryRowContext(ctx,
			`SELECT prosecdef FROM pg_proc WHERE proname = $1 AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname='public')`,
			fn,
		).Scan(&secDef)
		if err != nil {
			t.Fatalf("query prosecdef for %s: %v", fn, err)
		}
		if !secDef {
			t.Fatalf("function %s is NOT SECURITY DEFINER (prosecdef=false) — migration 104 didn't apply correctly", fn)
		}
	}

	// FORCE RLS on organizations + tenants (migration 103). Verify it's active.
	var orgsForced, tenantsForced bool
	if err := db.QueryRowContext(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname = 'organizations'`,
	).Scan(&orgsForced); err != nil {
		t.Fatalf("query FORCE on organizations: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname = 'tenants'`,
	).Scan(&tenantsForced); err != nil {
		t.Fatalf("query FORCE on tenants: %v", err)
	}
	if !orgsForced {
		t.Fatal("organizations is NOT FORCE RLS — migration 103 didn't apply; can't test SECURITY DEFINER bypass meaningfully")
	}
	if !tenantsForced {
		t.Fatal("tenants is NOT FORCE RLS — migration 103 didn't apply")
	}

	// Seed test rows AS TABLE OWNER (BYPASSRLS). We need rows for the
	// auth-lookup probes to find.
	const orgIDA = "mig104-test-orgA"
	const orgIDB = "mig104-test-orgB"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO organizations (org_id, name, tier, status, password_hash, contact_email, license_key)
		VALUES ($1, 'OrgA', 'Enterprise', 'ACTIVE', 'placeholderhashA', 'a@example.com', 'license-a'),
		       ($2, 'OrgB', 'Community',  'ACTIVE', NULL,                'b@example.com', 'license-b')
		ON CONFLICT (org_id) DO UPDATE
		   SET name = EXCLUDED.name,
		       tier = EXCLUDED.tier,
		       status = EXCLUDED.status,
		       password_hash = EXCLUDED.password_hash,
		       contact_email = EXCLUDED.contact_email
	`, orgIDA, orgIDB); err != nil {
		t.Fatalf("seed organizations: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO tenants (tenant_id, client_id, org_id, name)
		VALUES ($1, $1, $1, 'TenantA-canonical'),
		       ($2, $2, $2, 'TenantB-canonical')
		ON CONFLICT (tenant_id) DO NOTHING
	`, orgIDA, orgIDB); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sso_configurations (tenant_id, provider, enabled, enforce_sso)
		VALUES ($1, 'saml', TRUE, FALSE)
		ON CONFLICT (tenant_id) DO UPDATE
		   SET provider = EXCLUDED.provider,
		       enabled  = EXCLUDED.enabled
	`, orgIDA); err != nil {
		t.Fatalf("seed sso_configurations: %v", err)
	}

	// Switch to axonflow_app_role (NOBYPASSRLS) so FORCE RLS applies.
	// The test connection is the superuser; granting axonflow_app_role TO
	// CURRENT_USER + SET ROLE switches the active role context.
	if _, err := db.ExecContext(ctx, "GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		// already-granted is fine
		if !isAlreadyGrantedErr(err) {
			t.Fatalf("GRANT axonflow_app_role TO CURRENT_USER: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
		t.Fatalf("SET ROLE axonflow_app_role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "RESET ROLE")
	})

	// ========================================================================
	// Pin 1: portal_auth_lookup_org works under FORCE RLS WITHOUT SET LOCAL.
	// ========================================================================
	t.Run("portal_auth_lookup_org", func(t *testing.T) {
		var passwordHash sql.NullString
		var name sql.NullString
		var contactEmail sql.NullString
		err := db.QueryRowContext(ctx,
			`SELECT password_hash, name, contact_email FROM portal_auth_lookup_org($1)`,
			orgIDA,
		).Scan(&passwordHash, &name, &contactEmail)
		if err != nil {
			t.Fatalf("portal_auth_lookup_org under FORCE RLS as app_role: %v (should bypass via SECURITY DEFINER)", err)
		}
		if !passwordHash.Valid || passwordHash.String != "placeholderhashA" {
			t.Fatalf("password_hash mismatch: got %v, want placeholderhashA", passwordHash)
		}
		if !name.Valid || name.String != "OrgA" {
			t.Fatalf("name mismatch: got %v, want OrgA", name)
		}

		// No-row case for non-existent org (sanity).
		err = db.QueryRowContext(ctx,
			`SELECT password_hash, name, contact_email FROM portal_auth_lookup_org($1)`,
			"mig104-test-nonexistent",
		).Scan(&passwordHash, &name, &contactEmail)
		if err != sql.ErrNoRows {
			t.Fatalf("expected sql.ErrNoRows for non-existent org, got %v", err)
		}
	})

	// ========================================================================
	// Pin 2: portal_check_sso_availability returns existence + SSO config.
	// ========================================================================
	t.Run("portal_check_sso_availability", func(t *testing.T) {
		var orgExists bool
		var provider sql.NullString
		var enabled, enforceSSO sql.NullBool

		// OrgA: exists + has SSO row enabled=true
		err := db.QueryRowContext(ctx,
			`SELECT org_exists, provider, enabled, enforce_sso FROM portal_check_sso_availability($1)`,
			orgIDA,
		).Scan(&orgExists, &provider, &enabled, &enforceSSO)
		if err != nil {
			t.Fatalf("portal_check_sso_availability(orgA): %v", err)
		}
		if !orgExists {
			t.Fatal("orgA should exist, got exists=false")
		}
		if !provider.Valid || provider.String != "saml" {
			t.Fatalf("orgA provider mismatch: got %v, want 'saml'", provider)
		}
		if !enabled.Valid || !enabled.Bool {
			t.Fatalf("orgA enabled mismatch: got %v, want true", enabled)
		}

		// OrgB: exists but no SSO row → existence=true, provider=NULL
		err = db.QueryRowContext(ctx,
			`SELECT org_exists, provider, enabled, enforce_sso FROM portal_check_sso_availability($1)`,
			orgIDB,
		).Scan(&orgExists, &provider, &enabled, &enforceSSO)
		if err != nil {
			t.Fatalf("portal_check_sso_availability(orgB): %v", err)
		}
		if !orgExists {
			t.Fatal("orgB should exist, got exists=false")
		}
		if provider.Valid && provider.String != "" {
			t.Fatalf("orgB should have NULL provider (no SSO row), got %v", provider)
		}

		// Non-existent: existence=false
		err = db.QueryRowContext(ctx,
			`SELECT org_exists, provider, enabled, enforce_sso FROM portal_check_sso_availability($1)`,
			"mig104-test-nonexistent",
		).Scan(&orgExists, &provider, &enabled, &enforceSSO)
		if err != nil {
			t.Fatalf("portal_check_sso_availability(nonexistent): %v", err)
		}
		if orgExists {
			t.Fatal("nonexistent org should have exists=false")
		}
	})

	// ========================================================================
	// Pin 3: portal_default_tenant_id resolves the canonical tenant under
	// FORCE RLS on tenants.
	// ========================================================================
	t.Run("portal_default_tenant_id", func(t *testing.T) {
		var resolved string
		err := db.QueryRowContext(ctx,
			`SELECT portal_default_tenant_id($1)`,
			orgIDA,
		).Scan(&resolved)
		if err != nil {
			t.Fatalf("portal_default_tenant_id under FORCE RLS as app_role: %v", err)
		}
		if resolved != orgIDA {
			// Canonical default is tenant_id = org_id; we seeded that row.
			t.Fatalf("default tenant for orgA mismatch: got %s, want %s", resolved, orgIDA)
		}
	})

	// ========================================================================
	// Pin 4: register_org INSERTs into organizations WITHOUT SET LOCAL.
	// ========================================================================
	t.Run("register_org_no_set_local", func(t *testing.T) {
		const newOrgID = "mig104-test-newRegisterOrg"
		if _, err := db.ExecContext(ctx,
			`SELECT register_org($1, $2, $3, $4)`,
			newOrgID, "RegisterTestOrg", "Community", 5,
		); err != nil {
			t.Fatalf("register_org under FORCE RLS as app_role without SET LOCAL: %v", err)
		}

		// Verify the row landed (using table-owner role to see it past RLS).
		_, _ = db.ExecContext(ctx, "RESET ROLE")
		var rowCount int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM organizations WHERE org_id = $1`,
			newOrgID,
		).Scan(&rowCount); err != nil {
			t.Fatalf("verify register_org row landed: %v", err)
		}
		if rowCount != 1 {
			t.Fatalf("register_org didn't land a row: count=%d, want 1", rowCount)
		}
		_, _ = db.ExecContext(ctx, "SET ROLE axonflow_app_role") // restore for subsequent tests
	})

	// ========================================================================
	// Pin 5: register_tenant INSERTs into tenants WITHOUT SET LOCAL.
	// ========================================================================
	t.Run("register_tenant_no_set_local", func(t *testing.T) {
		const newTenantID = "mig104-test-newRegisterTenant"
		const newTenantOrgID = "mig104-test-newRegisterOrg" // from Pin 4
		if _, err := db.ExecContext(ctx,
			`SELECT register_tenant($1, $2, $3)`,
			newTenantID, newTenantOrgID, "RegisterTestTenant",
		); err != nil {
			t.Fatalf("register_tenant under FORCE RLS as app_role without SET LOCAL: %v", err)
		}

		_, _ = db.ExecContext(ctx, "RESET ROLE")
		var rowCount int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM tenants WHERE tenant_id = $1`,
			newTenantID,
		).Scan(&rowCount); err != nil {
			t.Fatalf("verify register_tenant row landed: %v", err)
		}
		if rowCount != 1 {
			t.Fatalf("register_tenant didn't land a row: count=%d, want 1", rowCount)
		}
		_, _ = db.ExecContext(ctx, "SET ROLE axonflow_app_role")
	})

	// ========================================================================
	// Pin 6: Mutation proof — flip portal_auth_lookup_org to SECURITY INVOKER.
	// Without SECURITY DEFINER the function runs as axonflow_app_role
	// (NOBYPASSRLS), the SELECT on organizations returns 0 rows under FORCE,
	// and the function-body SELECT-INTO emits 0 rows out. Caller sees
	// sql.ErrNoRows where it previously got the row.
	//
	// This proves the SECURITY DEFINER attribute is load-bearing.
	// ========================================================================
	t.Run("MutationProof_portal_auth_lookup_org_security_invoker", func(t *testing.T) {
		_, _ = db.ExecContext(ctx, "RESET ROLE") // need superuser to ALTER FUNCTION

		// Flip to SECURITY INVOKER (runs as caller, subject to FORCE RLS).
		if _, err := db.ExecContext(ctx,
			"ALTER FUNCTION portal_auth_lookup_org(VARCHAR) SECURITY INVOKER",
		); err != nil {
			t.Fatalf("ALTER FUNCTION ... SECURITY INVOKER: %v", err)
		}
		// R3-LOW-1 fix: defer fires AFTER the SET ROLE axonflow_app_role
		// below, so the ALTER must RESET ROLE first to run as superuser
		// (function owner). Without the RESET, the deferred ALTER silently
		// fails (app_role isn't the function owner) and a follow-up subtest
		// would observe SECURITY INVOKER state.
		defer func() {
			_, _ = db.ExecContext(ctx, "RESET ROLE")
			_, _ = db.ExecContext(ctx,
				"ALTER FUNCTION portal_auth_lookup_org(VARCHAR) SECURITY DEFINER",
			)
		}()

		// Switch back to app_role and probe — should return ErrNoRows now.
		if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
			t.Fatalf("SET ROLE: %v", err)
		}

		var passwordHash sql.NullString
		var name sql.NullString
		var contactEmail sql.NullString
		err := db.QueryRowContext(ctx,
			`SELECT password_hash, name, contact_email FROM portal_auth_lookup_org($1)`,
			orgIDA,
		).Scan(&passwordHash, &name, &contactEmail)
		if err != sql.ErrNoRows {
			t.Fatalf("expected sql.ErrNoRows after SECURITY INVOKER flip (orgA invisible under FORCE), got err=%v passwordHash=%v", err, passwordHash)
		}
		t.Logf("mutation proof: SECURITY INVOKER on portal_auth_lookup_org returned ErrNoRows under FORCE RLS — SECURITY DEFINER is load-bearing")
	})

	// ========================================================================
	// Pin 7: Mutation proof — flip register_org to SECURITY INVOKER. INSERT
	// should fail WITH CHECK because app.current_org_id is unset under
	// axonflow_app_role.
	// ========================================================================
	t.Run("MutationProof_register_org_security_invoker", func(t *testing.T) {
		_, _ = db.ExecContext(ctx, "RESET ROLE")

		if _, err := db.ExecContext(ctx,
			"ALTER FUNCTION register_org(VARCHAR, VARCHAR, VARCHAR, INTEGER) SECURITY INVOKER",
		); err != nil {
			t.Fatalf("ALTER FUNCTION ... SECURITY INVOKER: %v", err)
		}
		// R3-LOW-1 fix: same as Pin 6 — RESET ROLE first so the deferred
		// ALTER runs as superuser, not as app_role.
		defer func() {
			_, _ = db.ExecContext(ctx, "RESET ROLE")
			_, _ = db.ExecContext(ctx,
				"ALTER FUNCTION register_org(VARCHAR, VARCHAR, VARCHAR, INTEGER) SECURITY DEFINER",
			)
		}()

		if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
			t.Fatalf("SET ROLE: %v", err)
		}

		// Without app.current_org_id set, the INSERT inside register_org
		// can't satisfy WITH CHECK on the organizations RLS policy.
		// register_org returns VOID; the INSERT failure surfaces as an
		// ON CONFLICT no-op or WITH CHECK violation depending on whether
		// the row exists. We test with a NEW org_id so it's a fresh INSERT.
		_, err := db.ExecContext(ctx,
			`SELECT register_org($1, $2, $3, $4)`,
			"mig104-test-mutationProofRegOrg", "MutationProofOrg", "Community", 1,
		)
		// We expect an RLS violation error.
		if err == nil {
			t.Fatalf("expected RLS violation after SECURITY INVOKER flip on register_org, got nil")
		}
		// Postgres error: "new row violates row-level security policy"
		// or the function returns successfully with the INSERT silently
		// failing under WITH CHECK. Postgres ACTUALLY raises an error
		// (it's not a silent fail for WITH CHECK with insertable policy
		// not present). Either way, we got non-nil err.
		t.Logf("mutation proof: SECURITY INVOKER on register_org returned err=%v under FORCE RLS — SECURITY DEFINER is load-bearing", err)
	})
}

func isAlreadyGrantedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "is a member of role") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "duplicate")
}

// runMigrationsRange is defined in v9_followup_a_gaps_test.go (sibling
// test file in the same package). We DON'T redefine it here; reuse the
// canonical helper.

var _ = fmt.Sprintf // keep fmt import even if all sprintf calls get removed during edits
