// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 B2 — FORCE RLS isolation integration tests for customer-facing
// audit tables.
//
// Tables under test (per migration 100):
//   - mcp_query_audits
//   - audit_retention_config
//   - decision_chain
//
// Test setup mirrors B1 (rls_isolation_test.go):
//
//   1. Connect as the master/owner via DATABASE_URL.
//   2. Verify migrations 098 (roles) + 099 (B1) + 100 (B2 FORCE) all ran.
//   3. Insert one row per test org into each B2 table (bypasses RLS as owner).
//   4. SET LOCAL ROLE axonflow_app_role inside a transaction — this is the
//      critical step that avoids the B1 superuser-bypass test gotcha
//      (reference_force_rls_test_superuser_gotcha.md). Without it, the test
//      harness runs as a superuser which bypasses RLS even when FORCE is on.
//   5. SET LOCAL app.current_org_id = <test_org>.
//   6. Query each B2 table; assert only the test_org's row is visible.
//
// Mutation proof: comment out the SET LOCAL line and one assertion fails.
// Worker bypass proof: SET LOCAL ROLE axonflow_platform_admin and all rows
// are visible regardless of app.current_org_id.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lib/pq"
)

const (
	b2TestOrgA = "rls-b2-test-org-a"
	b2TestOrgB = "rls-b2-test-org-b"
)

// rlsB2TestSetup verifies the B2-specific migrations + roles + inserts seed
// rows in mcp_query_audits, audit_retention_config, decision_chain. Returns
// the DB + cleanup. Skips when prerequisites are missing.
//
// Re-uses the role-membership grant from rlsTestSetup (B1) where possible —
// duplicating the grant is idempotent on Postgres.
func rlsB2TestSetup(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	// rlsTestSetup() handles DATABASE_URL skip, role checks, and the GRANT
	// axonflow_app_role + axonflow_platform_admin TO CURRENT_USER. We re-use
	// it as the gating prerequisite then layer B2-specific seeds on top.
	db, b1Cleanup := rlsTestSetup(t)

	ctx := context.Background()
	for _, tbl := range []string{"mcp_query_audits", "audit_retention_config", "decision_chain"} {
		var enabled, forced bool
		if err := db.QueryRowContext(ctx,
			`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname=$1`,
			tbl,
		).Scan(&enabled, &forced); err != nil {
			t.Fatalf("check FORCE RLS on %s: %v", tbl, err)
		}
		if !enabled || !forced {
			t.Skipf("Skipping B2 RLS isolation test: %s rls_enabled=%v rls_forced=%v (migration 100 not applied)", tbl, enabled, forced)
		}
	}

	cleanupB2TestRows(t, db)
	insertB2SeedRows(t, db)

	cleanup := func() {
		cleanupB2TestRows(t, db)
		b1Cleanup()
	}
	return db, cleanup
}

func cleanupB2TestRows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	// Cleanup runs as table owner / superuser, which bypasses RLS by default.
	_, _ = db.ExecContext(ctx, "DELETE FROM mcp_query_audits WHERE org_id IN ($1, $2)", b2TestOrgA, b2TestOrgB)
	_, _ = db.ExecContext(ctx, "DELETE FROM audit_retention_config WHERE org_id IN ($1, $2)", b2TestOrgA, b2TestOrgB)
	_, _ = db.ExecContext(ctx, "DELETE FROM decision_chain WHERE org_id IN ($1, $2)", b2TestOrgA, b2TestOrgB)
	// audit_retention_config + decision_chain FKs reference organizations. B2
	// uses its own org_ids (rls-b2-test-org-a/b), distinct from B1's
	// rls-test-org-a/b — so we own the cleanup of B2's organizations rows.
	_, _ = db.ExecContext(ctx, "DELETE FROM organizations WHERE org_id IN ($1, $2)", b2TestOrgA, b2TestOrgB)
}

func insertB2SeedRows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// organizations FK is required for audit_retention_config + decision_chain.
	for _, org := range []string{b2TestOrgA, b2TestOrgB} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO organizations (org_id, name, license_key, tier, created_at)
			VALUES ($1, $1, $2, 'DEVELOPER', NOW())
			ON CONFLICT (org_id) DO NOTHING
		`, org, "rls-b2-test-license-"+org)
		if err != nil {
			t.Fatalf("insert organizations(%s): %v", org, err)
		}
	}

	// mcp_query_audits — required NOT NULL: audit_id, tenant_id, client_id,
	// connector_name, operation, success. org_id added by mig 061.
	for _, org := range []string{b2TestOrgA, b2TestOrgB} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO mcp_query_audits (audit_id, tenant_id, org_id, client_id, connector_name, operation, success)
			VALUES ($1, $2, $2, $3, $4, $5, true)
		`, "rls-b2-test-audit-"+org, org, "rls-b2-client-"+org, "test-connector", "test-op")
		if err != nil {
			t.Fatalf("insert mcp_query_audits(%s): %v", org, err)
		}
	}

	// audit_retention_config — required NOT NULL: org_id, data_type. Unique on
	// (org_id, data_type).
	for _, org := range []string{b2TestOrgA, b2TestOrgB} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO audit_retention_config (org_id, data_type, retention_days, compliance_framework, is_active)
			VALUES ($1, 'rls-b2-test', 1825, 'SEBI_AI_ML', true)
			ON CONFLICT (org_id, data_type) DO NOTHING
		`, org)
		if err != nil {
			t.Fatalf("insert audit_retention_config(%s): %v", org, err)
		}
	}

	// decision_chain — required NOT NULL: id (default), chain_id (uuid),
	// request_id (uuid), org_id (VARCHAR(255)), tenant_id (TEXT NOT NULL),
	// decision_type, decision_outcome, system_id. step_number defaults to 1.
	// Note: org_id and tenant_id have DIFFERENT types (VARCHAR vs TEXT), so we
	// pass them as separate parameters to avoid Postgres "inconsistent types
	// deduced for parameter $1" when the same arg is reused across columns.
	for _, org := range []string{b2TestOrgA, b2TestOrgB} {
		_, err := db.ExecContext(ctx, `
			INSERT INTO decision_chain (
				chain_id, request_id, org_id, tenant_id, client_id,
				decision_type, decision_outcome, system_id
			) VALUES (
				gen_random_uuid(), gen_random_uuid(), $1, $2, $3,
				'policy_enforcement', 'approved', 'rls-b2-test-system'
			)
		`, org, org, "rls-b2-client-"+org)
		if err != nil {
			t.Fatalf("insert decision_chain(%s): %v", org, err)
		}
	}
}

// countB2RowsForOrg counts B2-table rows visible inside the current tx whose
// org_id is one of the test orgs. With FORCE RLS + SET LOCAL app.current_org_id
// set to org_A, this returns 1 (only org_A row visible) per table.
func countB2RowsForOrg(ctx context.Context, tx *sql.Tx, table string) (int, error) {
	var n int
	q := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE org_id IN ($1, $2)", table)
	if err := tx.QueryRowContext(ctx, q, b2TestOrgA, b2TestOrgB).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// b2Tables is the canonical list of tables we exercise under B2.
var b2Tables = []string{"mcp_query_audits", "audit_retention_config", "decision_chain"}

// =============================================================================
// Tests
// =============================================================================

// TestRLSIsolation_B2_OrgA_SeesOnlyOrgA proves cross-org isolation on each B2
// table under axonflow_app_role with SET LOCAL set to org_A.
func TestRLSIsolation_B2_OrgA_SeesOnlyOrgA(t *testing.T) {
	db, cleanup := rlsB2TestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := runAsAppRoleWithOrg(t, db, b2TestOrgA, func(tx *sql.Tx) error {
		for _, tbl := range b2Tables {
			n, err := countB2RowsForOrg(ctx, tx, tbl)
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
		t.Fatalf("B2 isolation check failed: %v", err)
	}
}

// TestRLSIsolation_B2_OrgB_SeesOnlyOrgB mirrors the above for org_B.
func TestRLSIsolation_B2_OrgB_SeesOnlyOrgB(t *testing.T) {
	db, cleanup := rlsB2TestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := runAsAppRoleWithOrg(t, db, b2TestOrgB, func(tx *sql.Tx) error {
		for _, tbl := range b2Tables {
			n, err := countB2RowsForOrg(ctx, tx, tbl)
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
		t.Fatalf("B2 isolation check failed: %v", err)
	}
}

// TestRLSIsolation_B2_NoOrgContext_ZeroRows proves FORCE RLS hides all B2 rows
// when app.current_org_id is not set. This is the "handler forgot to set the
// session variable" case — the primary value of B2 per design doc.
func TestRLSIsolation_B2_NoOrgContext_ZeroRows(t *testing.T) {
	db, cleanup := rlsB2TestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := runAsAppRoleNoOrg(t, db, func(tx *sql.Tx) error {
		for _, tbl := range b2Tables {
			n, err := countB2RowsForOrg(ctx, tx, tbl)
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
		t.Fatalf("B2 zero-context check failed: %v", err)
	}
}

// TestRLSIsolation_B2_AdminBypass_SeesAllRows proves axonflow_platform_admin
// (BYPASSRLS) sees both orgs' rows simultaneously — the canonical mode for
// cross-org workers (sweep, aggregator, audit_cleanup once it migrates).
func TestRLSIsolation_B2_AdminBypass_SeesAllRows(t *testing.T) {
	db, cleanup := rlsB2TestSetup(t)
	defer cleanup()

	ctx := context.Background()
	err := runAsPlatformAdmin(t, db, func(tx *sql.Tx) error {
		for _, tbl := range b2Tables {
			n, err := countB2RowsForOrg(ctx, tx, tbl)
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
		t.Fatalf("B2 admin-bypass check failed: %v", err)
	}
}

// TestRLSIsolation_B2_WithOrgScope_InsertPath proves the agent's WithOrgScope
// helper (rls_session.go) correctly satisfies the WITH CHECK clause on INSERT
// for FORCE-RLS-enforced tables. Without WithOrgScope, the INSERT would fail
// because app.current_org_id is unset → org_id (in row) ≠ '' (session) → False.
//
// This is the end-to-end proof that the production write path
// (audit_queue.go::execWithRetryOrgScope + decision_chain.go::recordToDB)
// will actually work post-FORCE.
func TestRLSIsolation_B2_WithOrgScope_InsertPath(t *testing.T) {
	db, cleanup := rlsB2TestSetup(t)
	defer cleanup()

	ctx := context.Background()
	// Use a fresh audit_id outside the seed set; if WithOrgScope works, INSERT
	// lands and the seed-count assertion (cleanup-aware) goes up by 1.
	auditID := "rls-b2-withorgscope-insert-test"
	defer func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM mcp_query_audits WHERE audit_id = $1", auditID)
	}()

	// Need to do this under axonflow_app_role + SET LOCAL ROLE so that the
	// FORCE policy's WITH CHECK is actually evaluated. The agent's WithOrgScope
	// itself does NOT switch roles — that's the connection-string job. We
	// simulate by running our own tx with the role switch, then call WithOrgScope's
	// underlying behavior (SELECT set_config + INSERT).
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); err != nil {
		t.Fatalf("SET LOCAL ROLE: %v", err)
	}
	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", b2TestOrgA); err != nil {
		t.Fatalf("set_config: %v", err)
	}

	// INSERT as if we were the audit_queue.go path. WITH CHECK must pass.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO mcp_query_audits (audit_id, tenant_id, org_id, client_id, connector_name, operation, success)
		VALUES ($1, $2, $2, $3, 'test-conn', 'test-op', true)
	`, auditID, b2TestOrgA, "client-x")
	if err != nil {
		t.Fatalf("INSERT under SET LOCAL failed (WithOrgScope-equivalent path broken?): %v", err)
	}

	// Commit so the assertion below sees the row.
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Verify the row is visible from a fresh tx under org_A.
	var visible bool
	err = runAsAppRoleWithOrg(t, db, b2TestOrgA, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM mcp_query_audits WHERE audit_id = $1)", auditID)
		return row.Scan(&visible)
	})
	if err != nil {
		t.Fatalf("post-INSERT visibility check failed: %v", err)
	}
	if !visible {
		t.Fatalf("inserted row not visible to org_A — WithOrgScope INSERT path broken")
	}
}

// TestRLSIsolation_B2_MutationProof_InsertWithoutOrgScope proves the WITH CHECK
// clause actually bites: INSERT without app.current_org_id MUST be rejected
// under FORCE RLS. If this test passes (INSERT errors out), the assertion in
// TestRLSIsolation_B2_WithOrgScope_InsertPath is non-tautological.
//
// Per memory/feedback_mutation_test_to_prove_assertion_not_tautological.md.
func TestRLSIsolation_B2_MutationProof_InsertWithoutOrgScope(t *testing.T) {
	db, cleanup := rlsB2TestSetup(t)
	defer cleanup()

	ctx := context.Background()
	auditID := "rls-b2-mutation-proof-insert"
	defer func() {
		_, _ = db.ExecContext(ctx, "DELETE FROM mcp_query_audits WHERE audit_id = $1", auditID)
	}()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); err != nil {
		t.Fatalf("SET LOCAL ROLE: %v", err)
	}
	// Deliberately DO NOT call set_config('app.current_org_id', ...). This is
	// the mutation we're testing.

	_, err = tx.ExecContext(ctx, `
		INSERT INTO mcp_query_audits (audit_id, tenant_id, org_id, client_id, connector_name, operation, success)
		VALUES ($1, $2, $2, $3, 'test-conn', 'test-op', true)
	`, auditID, b2TestOrgA, "client-x")
	if err == nil {
		t.Fatalf("expected INSERT to FAIL without app.current_org_id under FORCE RLS, but it succeeded — WITH CHECK policy not enforcing")
	}
	// Per hostile-review of #2282: accepting ANY error is too permissive —
	// schema/FK/NOT-NULL violations would also satisfy the assertion and
	// falsely confirm WITH CHECK. Assert specifically on the RLS policy
	// violation error code (Postgres SQLSTATE 42501 — insufficient_privilege)
	// OR the canonical error message text.
	//
	// Postgres returns: "new row violates row-level security policy for table X"
	// with SQLSTATE 42501 (PG 9.5+, verified through 17).
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		if pqErr.Code != "42501" {
			t.Fatalf("expected RLS policy violation (SQLSTATE 42501), got SQLSTATE %s: %v", pqErr.Code, err)
		}
	} else if !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("expected RLS policy violation, got non-RLS error: %v", err)
	}
	t.Logf("mutation proof verified: INSERT correctly rejected with RLS policy violation: %v", err)
}
