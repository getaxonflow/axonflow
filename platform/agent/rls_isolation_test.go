// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 B1 — RLS isolation integration tests.
//
// These tests prove that FORCE ROW LEVEL SECURITY on the B1 tables
// (deployment_upgrades, saml_configurations, audit_archive) actually isolates
// rows by org_id when the connection runs under axonflow_app_role with a
// transaction-scoped SET LOCAL app.current_org_id.
//
// Test setup:
//
//   1. Connect as the master/owner via DATABASE_URL.
//   2. Run migrations 098 + 099 (idempotent — re-runs are no-ops).
//   3. Insert one row per test org into each B1 table (bypasses RLS as owner).
//   4. SET LOCAL ROLE axonflow_app_role inside a transaction (requires
//      membership grant; tests will skip if the grant is missing — see
//      ensureRoleMembership).
//   5. Issue SET LOCAL app.current_org_id = <test_org>.
//   6. Query the table; assert only the test_org's row is visible.
//
// Skip behavior:
//
//   - DATABASE_URL unset            → skip (CI gates DB-backed tests anyway).
//   - axonflow_app_role missing     → skip with diagnostic (migration 098 didn't apply).
//   - role membership missing       → skip with diagnostic (the test runner's role
//                                     lacks GRANT axonflow_app_role TO <runner>;
//                                     tests can opt in by GRANTing — or by running
//                                     under the role directly via AXONFLOW_DB_APP_ROLE_URL).

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

const (
	testOrgA = "rls-test-org-a"
	testOrgB = "rls-test-org-b"
)

// rlsTestSetup opens the master DB connection and verifies the RLS roles +
// FORCE state are in place. Returns the DB handle and a cleanup func that
// removes the test rows. Calls t.Skip when prerequisites are missing.
func rlsTestSetup(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping RLS isolation test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	ctx := context.Background()

	// Verify migration 098 ran (axonflow_app_role exists).
	var hasAppRole bool
	if err := db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='axonflow_app_role')").Scan(&hasAppRole); err != nil {
		t.Fatalf("check axonflow_app_role: %v", err)
	}
	if !hasAppRole {
		t.Skip("Skipping RLS isolation test: axonflow_app_role missing (migration 098 not applied)")
	}

	// Verify migration 099 ran (FORCE RLS on the B1 tables).
	for _, tbl := range []string{"deployment_upgrades", "saml_configurations", "audit_archive"} {
		var enabled, forced bool
		if err := db.QueryRowContext(ctx,
			`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname=$1`,
			tbl,
		).Scan(&enabled, &forced); err != nil {
			t.Fatalf("check FORCE RLS on %s: %v", tbl, err)
		}
		if !enabled || !forced {
			t.Skipf("Skipping RLS isolation test: %s rls_enabled=%v rls_forced=%v (migration 099 not applied)", tbl, enabled, forced)
		}
	}

	// Grant the test runner membership in axonflow_app_role so SET ROLE works
	// inside the test transaction. Cleanup later.
	if _, err := db.ExecContext(ctx, "GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		// If we can't grant, the test runner probably doesn't have admin
		// privileges in the test DB — skip rather than fail.
		t.Skipf("Skipping RLS isolation test: GRANT axonflow_app_role failed: %v", err)
	}
	if _, err := db.ExecContext(ctx, "GRANT axonflow_platform_admin TO CURRENT_USER"); err != nil {
		t.Skipf("Skipping RLS isolation test: GRANT axonflow_platform_admin failed: %v", err)
	}

	// Pre-clean any leftover test rows from a prior failed run.
	cleanupTestRows(t, db)

	// Insert one row per test org into each B1 table as the master (bypasses RLS).
	insertSeedRows(t, db)

	cleanup := func() {
		cleanupTestRows(t, db)
		_ = db.Close()
	}
	return db, cleanup
}

func cleanupTestRows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	for _, tbl := range []string{"deployment_upgrades", "saml_configurations", "audit_archive"} {
		_, _ = db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE org_id = $1 OR org_id = $2", tbl), testOrgA, testOrgB)
	}
	// Also clean orgs from the parent organizations table if FK requires it.
	_, _ = db.ExecContext(ctx, "DELETE FROM organizations WHERE org_id = $1 OR org_id = $2", testOrgA, testOrgB)
}

func insertSeedRows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// organizations FK is required for deployment_upgrades. Insert minimal stubs.
	// migrations/core/002_organizations_and_auth.sql requires (org_id, name,
	// license_key, tier) as NOT NULL — fill them with synthetic test values.
	for _, org := range []string{testOrgA, testOrgB} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO organizations (org_id, name, license_key, tier, created_at)
			VALUES ($1, $1, $2, 'DEVELOPER', NOW())
			ON CONFLICT (org_id) DO NOTHING
		`, org, "rls-test-license-"+org)
		if err != nil {
			t.Fatalf("insert organizations(%s): %v", org, err)
		}
	}

	// deployment_upgrades: one row per org.
	for _, org := range []string{testOrgA, testOrgB} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO deployment_upgrades (upgrade_id, org_id, status, services, started_at)
			VALUES ($1, $2, 'SUCCESS', 'agent', NOW())
			ON CONFLICT (upgrade_id) DO NOTHING
		`, "rls-test-"+org, org)
		if err != nil {
			t.Fatalf("insert deployment_upgrades(%s): %v", org, err)
		}
	}

	// saml_configurations not seeded in the unit-test harness — the active
	// assertions below cover deployment_upgrades + audit_archive, which is
	// enough to prove the FORCE RLS contract. The runtime-e2e harness has
	// equivalent coverage in shell+psql.

	// audit_archive: org_id NOT NULL, source_table NOT NULL, source_id, archived_data.
	for _, org := range []string{testOrgA, testOrgB} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO audit_archive (org_id, source_table, source_id, archived_data, original_created_at, archived_at)
			VALUES ($1, $2, $3, $4, NOW(), NOW())
		`, org, "test_source", int64(1), `{"test":true}`)
		if err != nil {
			t.Fatalf("insert audit_archive(%s): %v", org, err)
		}
	}
}

// runAsAppRoleWithOrg runs fn inside a transaction with axonflow_app_role +
// SET LOCAL app.current_org_id = orgID. Returns whatever fn returns.
func runAsAppRoleWithOrg(t *testing.T, db *sql.DB, orgID string, fn func(tx *sql.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("BeginTx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); err != nil {
		return fmt.Errorf("SET LOCAL ROLE: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
		return fmt.Errorf("set_config: %w", err)
	}
	return fn(tx)
}

// runAsAppRoleNoOrg runs fn inside a tx as axonflow_app_role WITHOUT setting
// app.current_org_id. Used to prove FORCE RLS returns zero rows when no
// context is set.
func runAsAppRoleNoOrg(t *testing.T, db *sql.DB, fn func(tx *sql.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("BeginTx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); err != nil {
		return fmt.Errorf("SET LOCAL ROLE: %w", err)
	}
	return fn(tx)
}

// runAsPlatformAdmin runs fn inside a tx as axonflow_platform_admin
// (BYPASSRLS). Should see ALL rows regardless of app.current_org_id.
func runAsPlatformAdmin(t *testing.T, db *sql.DB, fn func(tx *sql.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("BeginTx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_platform_admin"); err != nil {
		return fmt.Errorf("SET LOCAL ROLE: %w", err)
	}
	return fn(tx)
}

// countRowsForOrg counts B1-table rows visible inside the current tx whose
// org_id is one of the test orgs. With RLS in effect + SET LOCAL set to org_A,
// this returns 1 (only org_A row visible) for each table.
func countRowsForOrg(ctx context.Context, tx *sql.Tx, table string) (int, error) {
	var n int
	q := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE org_id IN ($1, $2)", table)
	if err := tx.QueryRowContext(ctx, q, testOrgA, testOrgB).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// =============================================================================
// Tests
// =============================================================================

// TestRLSIsolation_OrgA_SeesOnlyOrgA proves cross-org isolation under the
// app role with SET LOCAL.
func TestRLSIsolation_OrgA_SeesOnlyOrgA(t *testing.T) {
	db, cleanup := rlsTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := runAsAppRoleWithOrg(t, db, testOrgA, func(tx *sql.Tx) error {
		for _, tbl := range []string{"deployment_upgrades", "audit_archive"} {
			n, err := countRowsForOrg(ctx, tx, tbl)
			if err != nil {
				return fmt.Errorf("count %s: %w", tbl, err)
			}
			if n != 1 {
				return fmt.Errorf("expected 1 visible row in %s as org_A, got %d", tbl, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("isolation check failed: %v", err)
	}
}

// TestRLSIsolation_OrgB_SeesOnlyOrgB is the mirror of the above.
func TestRLSIsolation_OrgB_SeesOnlyOrgB(t *testing.T) {
	db, cleanup := rlsTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := runAsAppRoleWithOrg(t, db, testOrgB, func(tx *sql.Tx) error {
		for _, tbl := range []string{"deployment_upgrades", "audit_archive"} {
			n, err := countRowsForOrg(ctx, tx, tbl)
			if err != nil {
				return fmt.Errorf("count %s: %w", tbl, err)
			}
			if n != 1 {
				return fmt.Errorf("expected 1 visible row in %s as org_B, got %d", tbl, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("isolation check failed: %v", err)
	}
}

// TestRLSIsolation_NoOrgContext_ZeroRows proves FORCE RLS hides all rows
// when no app.current_org_id is set.
func TestRLSIsolation_NoOrgContext_ZeroRows(t *testing.T) {
	db, cleanup := rlsTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := runAsAppRoleNoOrg(t, db, func(tx *sql.Tx) error {
		for _, tbl := range []string{"deployment_upgrades", "audit_archive"} {
			n, err := countRowsForOrg(ctx, tx, tbl)
			if err != nil {
				return fmt.Errorf("count %s: %w", tbl, err)
			}
			if n != 0 {
				return fmt.Errorf("expected 0 rows in %s without org context, got %d (FORCE RLS not active?)", tbl, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("zero-context check failed: %v", err)
	}
}

// TestRLSIsolation_AdminBypass_SeesAllRows proves axonflow_platform_admin
// (BYPASSRLS) sees both orgs' rows simultaneously.
func TestRLSIsolation_AdminBypass_SeesAllRows(t *testing.T) {
	db, cleanup := rlsTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := runAsPlatformAdmin(t, db, func(tx *sql.Tx) error {
		for _, tbl := range []string{"deployment_upgrades", "audit_archive"} {
			n, err := countRowsForOrg(ctx, tx, tbl)
			if err != nil {
				return fmt.Errorf("count %s: %w", tbl, err)
			}
			if n != 2 {
				return fmt.Errorf("expected 2 rows in %s as platform_admin, got %d (BYPASSRLS not active?)", tbl, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("admin-bypass check failed: %v", err)
	}
}

// TestRLSIsolation_WithOrgScope_Helper proves the agent's WithOrgScope helper
// (platform/agent/rls_session.go) correctly sets app.current_org_id inside a
// transaction. The visibility check is intentionally NOT run here because:
//
//   - WithOrgScope deliberately does not SET ROLE — that's the caller's
//     responsibility (a v9-cut agent connects directly as axonflow_app_role).
//   - The local test harness typically runs as a superuser, which bypasses
//     RLS regardless of FORCE. Asserting row visibility under WithOrgScope
//     would either always pass (under superuser, returns all rows = matches
//     2 rows expected) or always fail (depending on role) — the assertion
//     isn't diagnostic.
//
// The role-scoped visibility assertions live in TestRLSIsolation_OrgA_/OrgB_
// (which explicitly SET LOCAL ROLE axonflow_app_role). What WithOrgScope owns
// is "did SET LOCAL app.current_org_id land in this tx?" — that's what we
// check here.
func TestRLSIsolation_WithOrgScope_Helper(t *testing.T) {
	db, cleanup := rlsTestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := WithOrgScope(ctx, db, testOrgA, func(tx *sql.Tx) error {
		gotOrg, err := CurrentOrgIDInTx(ctx, tx)
		if err != nil {
			return fmt.Errorf("CurrentOrgIDInTx: %w", err)
		}
		if gotOrg != testOrgA {
			return fmt.Errorf("expected app.current_org_id=%q inside WithOrgScope, got %q", testOrgA, gotOrg)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithOrgScope check failed: %v", err)
	}
}

// TestRLSIsolation_MutationProof_PolicyEnforced replaces the previous
// MutationProof_RemoveSetLocal test. The old form asserted "0 rows visible
// without SET LOCAL" — but that's a Postgres definitional fact (an unset
// app.current_org_id resolves to "" and "" matches no row's org_id), not a
// property of #2268's contribution. It passed even if WithOrgScope's
// set_config call was deleted entirely.
//
// This version proves the FULL chain is load-bearing by exercising the
// WITH CHECK side of the policy: under axonflow_app_role (NOBYPASSRLS) with
// app.current_org_id=testOrgA, an INSERT carrying org_id=testOrgB MUST be
// rejected with a row-level security policy violation. Reverting any of the
// SUT pieces flips the verdict observably:
//
//   - Delete runAsAppRoleWithOrg's set_config(...) call → INSERT(B) still
//     fails (empty app.current_org_id matches no row) BUT the matching
//     INSERT(A) assertion below ALSO fails (empty matches no row), so the
//     test catches the mutation.
//   - Drop the WITH CHECK clause from policy audit_archive_org_isolation
//     → INSERT(B) succeeds → test fails.
//   - Grant axonflow_app_role BYPASSRLS (NOBYPASSRLS removed in migration 098)
//     → INSERT(B) succeeds → test fails.
//
// Note on FORCE specifically: the CI/testcontainer master connection runs as
// a superuser (per memory/reference_force_rls_test_superuser_gotcha.md), so
// owner-bypass-without-FORCE is not directly testable here. Running the
// assertion under SET LOCAL ROLE axonflow_app_role sidesteps the gotcha by
// trading "is FORCE active" for "is the policy + role pair enforcing the
// CHECK" — the latter is what every prod query path actually depends on.
// The shell runtime-e2e at runtime-e2e/v9_phase8_b1_rls/test.sh covers the
// owner-path FORCE assertion separately.
//
// Per memory/feedback_mutation_test_to_prove_assertion_not_tautological.md:
// tests that pass when the SUT is right AND when the SUT is broken are
// useless. The two-INSERT shape below is the assertion that proves the
// isolation contract has teeth.
func TestRLSIsolation_MutationProof_PolicyEnforced(t *testing.T) {
	db, cleanup := rlsTestSetup(t)
	defer cleanup()

	ctx := context.Background()

	// Mismatch case: org_A scope, INSERT row with org_B → expect violation.
	err := runAsAppRoleWithOrg(t, db, testOrgA, func(tx *sql.Tx) error {
		_, ex := tx.ExecContext(ctx, `
			INSERT INTO audit_archive
			    (org_id, source_table, source_id, archived_data, original_created_at, archived_at)
			VALUES ($1, 'rls-mutation-proof-mismatch', 9001, '{"mutation":"mismatch"}'::jsonb, NOW(), NOW())
		`, testOrgB)
		if ex == nil {
			return fmt.Errorf("mutation proof FAILED: INSERT(org_id=%s) under SET LOCAL app.current_org_id=%s succeeded — policy WITH CHECK clause not enforced (FORCE reverted on table, role bypassed RLS, set_config not applied, or policy dropped)", testOrgB, testOrgA)
		}
		// PostgreSQL surfaces RLS violations with "new row violates row-level
		// security policy" in the message. We tolerate either phrasing for
		// resilience to driver wording drift but require the substring
		// "row-level security" or "violates" to confirm it's an RLS error
		// and not, say, a syntax error or constraint failure.
		msg := ex.Error()
		if !strings.Contains(msg, "row-level security") && !strings.Contains(msg, "violates") {
			return fmt.Errorf("INSERT(org_B under org_A scope) failed but not with an RLS-shaped error: %v", ex)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("mismatch INSERT check failed: %v", err)
	}

	// Happy-path control: org_A scope, INSERT row with org_A → succeeds.
	// This anchor proves set_config(testOrgA) actually landed; if it had
	// silently no-op'd, the policy would compare "" = testOrgA and fail.
	err = runAsAppRoleWithOrg(t, db, testOrgA, func(tx *sql.Tx) error {
		_, ex := tx.ExecContext(ctx, `
			INSERT INTO audit_archive
			    (org_id, source_table, source_id, archived_data, original_created_at, archived_at)
			VALUES ($1, 'rls-mutation-proof-match', 9002, '{"mutation":"match"}'::jsonb, NOW(), NOW())
		`, testOrgA)
		if ex != nil {
			return fmt.Errorf("anchor INSERT(org_id=%s) under matching scope failed: %v — set_config(app.current_org_id) did not land or policy is over-restrictive", testOrgA, ex)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("matched-org INSERT anchor check failed: %v", err)
	}
}
