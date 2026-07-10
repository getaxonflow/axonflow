// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 8 PR-A — SECURITY DEFINER helpers integration test.
//
// Mig 109 adds five helpers that close the auth-bootstrap chicken-egg pattern
// for write paths where org_id is being MINTED in the same request:
//
//   csaas_register_tenant   - INSERT into community_saas_registrations
//   csaas_register_touch    - UPDATE activity counter
//   csaas_recovery_insert   - INSERT recovered tenant row
//   auth_insert_api_key     - INSERT into in-VPC enterprise api_keys
//   portal_insert_api_key   - INSERT into customer_portal_api_keys
//
// Per #2384 Phase 1 DoD + brief: each helper must be exercised under
// axonflow_app_role (the role the binary will use post-app-role-flip) +
// have a mutation gate that proves SECURITY DEFINER is the load-bearing
// keyword (revert to SECURITY INVOKER -> call as app_role -> assert 42501).
//
// Gating: TEST_PG_INTEGRATION=1. Without it, the test skips.
//
// SET LOCAL ROLE gotcha (reference_force_rls_test_superuser_gotcha.md):
// the testcontainer's default postgres user is superuser, which bypasses
// RLS unconditionally. Every subtest below SETs LOCAL ROLE axonflow_app_role
// inside a transaction so RLS actually applies.
//
// Mutation-test pattern (reference_v9_phase8_b6_in_vpc_security_definer.md):
// recreate the function as SECURITY INVOKER, repeat the call, assert
// failure. Restore the SECURITY DEFINER version in a defer so subsequent
// subtests aren't affected.

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

// prATestSetup launches a throwaway postgres:15 container, runs core
// migrations 1-108, inline-applies the in-VPC enterprise + customer-portal
// schemas (so mig 109's helpers can resolve all 5 target tables at call
// time), then runs mig 109 to install the helpers.
//
// Returns the DB handle plus a cleanup func.
func prATestSetup(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("set TEST_PG_INTEGRATION=1 to run real-PG integration tests (requires docker)")
	}

	pgURL, containerCleanup := startPostgresContainer(t)

	db, err := sql.Open("postgres", pgURL)
	if err != nil {
		containerCleanup()
		t.Fatalf("sql.Open: %v", err)
	}
	// Pin pool to 1 so the GRANTs + SET LOCAL we issue land on the same backend.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`SELECT set_config('app.db_password', 'test-pass', false)`); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("set app.db_password: %v", err)
	}
	if _, err := db.Exec(`SELECT set_config('app.deployment_org_id', 'local-dev-org', false)`); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("set app.deployment_org_id: %v", err)
	}

	// Run mig 1-108. Includes mig 098 (axonflow_app_role role), mig 105
	// (community_saas_registrations FORCE RLS), mig 108 (api_keys + customers
	// FORCE RLS + auth_lookup/auth_touch helpers).
	runMigrationsRange(t, db, 1, 108)

	// Inline-apply the EE schemas that mig 109's auth_insert_api_key +
	// portal_insert_api_key bodies reference. In production these come from
	// migrations/enterprise/100 + 102 (which the core-only test runner
	// doesn't load) plus platform/database/migrations/006_option3_auth_system.sql
	// (operator-applied).
	applyPRAEnterpriseSchema(t, db)

	// Now run mig 109. Functions are created here; smoke verification at the
	// end of mig 109 asserts all 5 are prosecdef=true.
	runMigrationsRange(t, db, 109, 109)

	// Grant role memberships so SET LOCAL ROLE works inside test transactions.
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("GRANT axonflow_app_role: %v", err)
	}
	if _, err := db.ExecContext(ctx, "GRANT axonflow_platform_admin TO CURRENT_USER"); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("GRANT axonflow_platform_admin: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
		containerCleanup()
	}
	return db, cleanup
}

// applyPRAEnterpriseSchema applies the columns/tables PR-A's helpers
// reference: customer_portal_api_keys (enterprise/102) + in-VPC enterprise
// schema (enterprise/100 + 006_option3_auth_system).
func applyPRAEnterpriseSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		// pgcrypto for gen_random_uuid() — postgres:15 ships it built-in
		// but pinning makes the test robust against future testcontainer
		// image swaps (R3 round-2 LOW-1).
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		// customer_portal_api_keys (enterprise/102 minimal shape).
		`CREATE TABLE IF NOT EXISTS customer_portal_api_keys (
			id SERIAL PRIMARY KEY,
			org_id VARCHAR(255) NOT NULL,
			key_hash VARCHAR(512) NOT NULL,
			key_prefix VARCHAR(20) NOT NULL,
			name VARCHAR(255) NOT NULL,
			scopes JSONB DEFAULT '[]',
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		)`,
		// pricing_tiers (enterprise/100 minimal shape).
		`CREATE TABLE IF NOT EXISTS pricing_tiers (
			tier                VARCHAR(20)  NOT NULL,
			deployment_mode     VARCHAR(20)  NOT NULL,
			requests_per_minute INTEGER      NOT NULL,
			PRIMARY KEY (tier, deployment_mode)
		)`,
		// customers (enterprise/100 minimal shape — only columns mig 109's
		// auth_insert_api_key body touches via FK or returning chain).
		`CREATE TABLE IF NOT EXISTS customers (
			customer_id       VARCHAR(255) PRIMARY KEY,
			organization_id   VARCHAR(255),
			organization_name VARCHAR(255),
			tier              VARCHAR(20),
			deployment_mode   VARCHAR(20),
			tenant_id         VARCHAR(255),
			status            VARCHAR(20),
			enabled           BOOLEAN DEFAULT true,
			org_id            VARCHAR(255)
		)`,
		// api_keys 006_option3 extension columns. mig 002 already created the
		// base api_keys with (id, org_id, ...); we ADD the EE columns the
		// auth_insert_api_key body INSERTs into.
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS api_key_id UUID DEFAULT gen_random_uuid()`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS customer_id VARCHAR(255)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS license_key VARCHAR(512)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS license_key_hash VARCHAR(255)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_name VARCHAR(255)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_type VARCHAR(20)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS grace_period_days INTEGER DEFAULT 7`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '{}'::jsonb`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS custom_rate_limit INTEGER`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS total_requests BIGINT DEFAULT 0`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`,
		// 'enabled' lives in 006_option3 auth_system (operator-applied) — not
		// mig 002. ALTER add for the testcontainer so the helper's INSERT
		// resolves the column at CALL time.
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true`,
		// In production, 006_option3_auth_system runs BEFORE mig 002, so
		// mig 002's CREATE TABLE IF NOT EXISTS is a no-op and the 006_option3
		// schema (no key_hash NOT NULL constraint) is what's in effect. In
		// the testcontainer mig 002 fires unconditionally, leaving key_hash /
		// key_prefix / name as NOT NULL. The helper INSERT doesn't supply
		// them (those are mig-002-era OAuth-style fields the 006_option3
		// flow doesn't use). Drop the NOT NULL so the test mirrors the
		// production-effective schema.
		`ALTER TABLE api_keys ALTER COLUMN key_hash DROP NOT NULL`,
		`ALTER TABLE api_keys ALTER COLUMN key_prefix DROP NOT NULL`,
		`ALTER TABLE api_keys ALTER COLUMN name DROP NOT NULL`,
		// Seed a customer row so auth_insert_api_key has something to point at.
		// (mig 109's auth_insert_api_key body doesn't enforce FK; this seed
		// just keeps the schema realistic.)
		`INSERT INTO customers (customer_id, organization_id, organization_name, tier, deployment_mode, status, enabled, org_id)
		 VALUES ('cust-pra-test', 'org-pra-test', 'PR-A Test Customer', 'enterprise', 'in-vpc', 'active', true, 'org-pra-test')
		 ON CONFLICT DO NOTHING`,
		`INSERT INTO pricing_tiers (tier, deployment_mode, requests_per_minute)
		 VALUES ('enterprise', 'in-vpc', 1000)
		 ON CONFLICT DO NOTHING`,
		// Seed organizations rows for the api_keys.org_id FK. Subtest 06's
		// auth_insert_api_key call passes 'org-pra-test-06'; subtest 11
		// passes 'org-pra-mut'. Both must exist in organizations or the FK
		// fires before the SECURITY DEFINER body completes. Production
		// admins seed the org via the customer-portal before issuing keys.
		`INSERT INTO organizations (org_id, name, tier, max_nodes, license_key, status)
		 VALUES ('org-pra-test-06', 'PR-A subtest 06 org', 'enterprise', 1000, 'lk-test-pra-06', 'ACTIVE')
		 ON CONFLICT (org_id) DO NOTHING`,
		`INSERT INTO organizations (org_id, name, tier, max_nodes, license_key, status)
		 VALUES ('org-pra-mut', 'PR-A subtest 11 mutation org', 'enterprise', 1000, 'lk-mut', 'ACTIVE')
		 ON CONFLICT (org_id) DO NOTHING`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("applyPRAEnterpriseSchema %q: %v", truncForLog(s, 60), err)
		}
	}
}

func truncForLog(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// runAsAppRoleTx opens a transaction, SET LOCAL ROLEs to axonflow_app_role,
// runs fn, then either COMMITs (commit=true) or ROLLBACKs (commit=false) so
// concurrent subtests don't see each other's writes. Critically: if fn
// returns an error, the tx is ALWAYS rolled back — even when commit=true —
// so a pool pinned to MaxOpenConns=1 doesn't deadlock when a mutation
// subtest's fn returns the expected RLS-violation error.
func runAsAppRoleTx(t *testing.T, db *sql.DB, commit bool, fn func(tx *sql.Tx) error) (err error) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		// Always rollback when err != nil (caller saw an error from fn
		// or from the SET LOCAL ROLE). Belt-and-suspenders rollback when
		// caller asked for commit=false. tx.Rollback after a successful
		// Commit is a no-op.
		if err != nil || !commit {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	if commit {
		return tx.Commit()
	}
	return nil
}

// asserts pg_proc.prosecdef=true for the given function name. Caller
// supplies a slice of function names because we want a single assertion
// per subtest (avoids spamming the test output).
func assertProsecdefTrue(t *testing.T, db *sql.DB, fnNames []string) {
	t.Helper()
	for _, fn := range fnNames {
		var prosecdef bool
		err := db.QueryRow(
			`SELECT prosecdef FROM pg_proc
			 WHERE proname = $1
			   AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')`,
			fn,
		).Scan(&prosecdef)
		if err != nil {
			t.Fatalf("query prosecdef for %s: %v", fn, err)
		}
		if !prosecdef {
			t.Fatalf("function %s is NOT SECURITY DEFINER (prosecdef=false)", fn)
		}
	}
}

// pgErrCode extracts the SQLSTATE from a pq error, "" if not a pq error.
func pgErrCode(err error) string {
	if err == nil {
		return ""
	}
	if pe, ok := err.(*pq.Error); ok {
		return string(pe.Code)
	}
	return ""
}

// rlsViolationCode is the SQLSTATE for "new row violates row-level security
// policy" (and for the SECURITY DEFINER mutation flow when the caller role
// lacks BYPASSRLS + no GUC is set). 42501 = insufficient_privilege.
const rlsViolationCode = "42501"

// TestPRASecurityDefinerHelpers exercises all 5 helpers under app_role
// + verifies each carries a mutation-discriminating SECURITY DEFINER guard.
//
// Subtests:
//   01_prosecdef_smoke      — all 5 prosecdef=true (sanity)
//   02_csaas_register_tenant_with_email     — INSERT succeeds, row visible to admin
//   03_csaas_register_tenant_without_email  — INSERT succeeds (DEFAULT NULL branch)
//   04_csaas_register_touch                 — UPDATE returns rows_affected=1
//   05_csaas_recovery_insert                — INSERT succeeds
//   06_auth_insert_api_key                  — INSERT into in-VPC api_keys returns UUID
//   07_portal_insert_api_key                — INSERT into customer_portal_api_keys returns id
//   08_mutation_csaas_register_tenant       — SECURITY DEFINER -> INVOKER -> fails 42501
//   09_mutation_csaas_register_touch        — same shape
//   10_mutation_csaas_recovery_insert       — same shape
//   11_mutation_auth_insert_api_key         — same shape
//   12_mutation_portal_insert_api_key       — same shape
func TestPRASecurityDefinerHelpers(t *testing.T) {
	db, cleanup := prATestSetup(t)
	defer cleanup()

	t.Run("01_prosecdef_smoke", func(t *testing.T) {
		assertProsecdefTrue(t, db, []string{
			"csaas_register_tenant",
			"csaas_register_touch",
			"csaas_recovery_insert",
			"auth_insert_api_key",
			"portal_insert_api_key",
		})
	})

	t.Run("02_csaas_register_tenant_with_email", func(t *testing.T) {
		tenantID := "cs_pra_email_" + randomSuffix()
		expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
		err := runAsAppRoleTx(t, db, true, func(tx *sql.Tx) error {
			_, e := tx.Exec(
				`SELECT csaas_register_tenant($1, $2, $3, $4, $5, $6)`,
				tenantID, "hash-with-email", "prefix1", "label-with-email", expiresAt, "user@example.com",
			)
			return e
		})
		if err != nil {
			t.Fatalf("csaas_register_tenant (with email) failed: %v (sqlstate=%s)", err, pgErrCode(err))
		}
		// Verify via admin role (BYPASSRLS) to bypass the FORCE policy.
		var orgID, claimedBy string
		if err := db.QueryRow(
			`SELECT org_id, claimed_by_email FROM community_saas_registrations WHERE tenant_id = $1`,
			tenantID,
		).Scan(&orgID, &claimedBy); err != nil {
			t.Fatalf("post-insert SELECT: %v", err)
		}
		if orgID != tenantID {
			t.Fatalf("org_id mismatch: got %q, want %q (Phase 6 invariant)", orgID, tenantID)
		}
		if claimedBy != "user@example.com" {
			t.Fatalf("claimed_by_email mismatch: got %q, want %q", claimedBy, "user@example.com")
		}
	})

	t.Run("03_csaas_register_tenant_without_email", func(t *testing.T) {
		tenantID := "cs_pra_noemail_" + randomSuffix()
		expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
		err := runAsAppRoleTx(t, db, true, func(tx *sql.Tx) error {
			// Pass nil for the email param — exercises the DEFAULT NULL branch
			// of csaas_register_tenant which uses the 7-col INSERT shape.
			var nilEmail interface{}
			_, e := tx.Exec(
				`SELECT csaas_register_tenant($1, $2, $3, $4, $5, $6)`,
				tenantID, "hash-no-email", "prefix2", "label-no-email", expiresAt, nilEmail,
			)
			return e
		})
		if err != nil {
			t.Fatalf("csaas_register_tenant (without email) failed: %v (sqlstate=%s)", err, pgErrCode(err))
		}
		var orgID string
		var claimedBy sql.NullString
		if err := db.QueryRow(
			`SELECT org_id, claimed_by_email FROM community_saas_registrations WHERE tenant_id = $1`,
			tenantID,
		).Scan(&orgID, &claimedBy); err != nil {
			t.Fatalf("post-insert SELECT: %v", err)
		}
		if orgID != tenantID {
			t.Fatalf("org_id mismatch: got %q, want %q", orgID, tenantID)
		}
		if claimedBy.Valid {
			t.Fatalf("claimed_by_email should be NULL when email DEFAULT branch fires, got %q", claimedBy.String)
		}
	})

	t.Run("04_csaas_register_touch", func(t *testing.T) {
		// Seed a row to touch.
		tenantID := "cs_pra_touch_" + randomSuffix()
		expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
		err := runAsAppRoleTx(t, db, true, func(tx *sql.Tx) error {
			_, e := tx.Exec(
				`SELECT csaas_register_tenant($1, $2, $3, $4, $5, NULL)`,
				tenantID, "hash-touch", "prefixT", "label-touch", expiresAt,
			)
			return e
		})
		if err != nil {
			t.Fatalf("seed for touch: %v", err)
		}
		// Now exercise the touch helper.
		var rows int
		err = runAsAppRoleTx(t, db, true, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT csaas_register_touch($1)`, tenantID).Scan(&rows)
		})
		if err != nil {
			t.Fatalf("csaas_register_touch failed: %v (sqlstate=%s)", err, pgErrCode(err))
		}
		if rows != 1 {
			t.Fatalf("expected 1 row updated, got %d", rows)
		}
		// Verify request_count incremented + last_seen_at populated.
		var reqCount int
		var lastSeen sql.NullTime
		if err := db.QueryRow(
			`SELECT request_count, last_seen_at FROM community_saas_registrations WHERE tenant_id = $1`,
			tenantID,
		).Scan(&reqCount, &lastSeen); err != nil {
			t.Fatalf("post-touch SELECT: %v", err)
		}
		if reqCount != 1 {
			t.Fatalf("expected request_count=1, got %d", reqCount)
		}
		if !lastSeen.Valid {
			t.Fatal("last_seen_at not populated after touch")
		}
	})

	t.Run("05_csaas_recovery_insert", func(t *testing.T) {
		tenantID := "cs_pra_recovery_" + randomSuffix()
		expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
		err := runAsAppRoleTx(t, db, true, func(tx *sql.Tx) error {
			_, e := tx.Exec(
				`SELECT csaas_recovery_insert($1, $2, $3, $4, $5, $6)`,
				tenantID, "hash-recovery", "prefixR", "recovery for x@example.com", expiresAt, "x@example.com",
			)
			return e
		})
		if err != nil {
			t.Fatalf("csaas_recovery_insert failed: %v (sqlstate=%s)", err, pgErrCode(err))
		}
		var orgID, label, claimedBy string
		if err := db.QueryRow(
			`SELECT org_id, label, claimed_by_email FROM community_saas_registrations WHERE tenant_id = $1`,
			tenantID,
		).Scan(&orgID, &label, &claimedBy); err != nil {
			t.Fatalf("post-insert SELECT: %v", err)
		}
		if orgID != tenantID {
			t.Fatalf("org_id mismatch: got %q, want %q", orgID, tenantID)
		}
		if !strings.HasPrefix(label, "recovery for ") {
			t.Fatalf("label shape: got %q", label)
		}
		if claimedBy != "x@example.com" {
			t.Fatalf("claimed_by_email mismatch: got %q", claimedBy)
		}
	})

	t.Run("06_auth_insert_api_key", func(t *testing.T) {
		customerID := "cust-pra-test"
		expectedOrgID := "org-pra-test-06"
		var apiKeyID string
		err := runAsAppRoleTx(t, db, true, func(tx *sql.Tx) error {
			return tx.QueryRow(
				`SELECT auth_insert_api_key($1, $2, $3, $4, $5, $6)`,
				customerID, "lk-test-pra-06", "lkhash-pra-06", "test-key-pra-06", 30, expectedOrgID,
			).Scan(&apiKeyID)
		})
		if err != nil {
			t.Fatalf("auth_insert_api_key failed: %v (sqlstate=%s)", err, pgErrCode(err))
		}
		if apiKeyID == "" {
			t.Fatal("auth_insert_api_key returned empty api_key_id")
		}
		// Verify via admin that the row exists AND carries the expected org_id.
		// The org_id assertion is the load-bearing one: pre-PR-A raw INSERT
		// left org_id NULL, and the R3 round-1 HIGH finding was that the
		// helper perpetuated that gap. Asserting non-NULL + value matches
		// catches any regression that re-omits the column.
		var hash, orgID string
		if err := db.QueryRow(
			`SELECT license_key_hash, org_id FROM api_keys WHERE api_key_id::VARCHAR = $1`,
			apiKeyID,
		).Scan(&hash, &orgID); err != nil {
			t.Fatalf("post-insert SELECT: %v", err)
		}
		if hash != "lkhash-pra-06" {
			t.Fatalf("license_key_hash mismatch: got %q", hash)
		}
		if orgID != expectedOrgID {
			t.Fatalf("org_id mismatch: got %q, want %q — regression of R3 round-1 HIGH (raw INSERT pre-PR-A left org_id NULL, making rows invisible to direct app_role SELECTs under mig 108 FORCE RLS)", orgID, expectedOrgID)
		}
	})

	t.Run("07_portal_insert_api_key", func(t *testing.T) {
		orgID := "org-portal-pra-07"
		scopes, _ := json.Marshal([]string{"read:policies", "write:policies"})
		expires := time.Now().UTC().Add(90 * 24 * time.Hour)
		var keyID int
		err := runAsAppRoleTx(t, db, true, func(tx *sql.Tx) error {
			return tx.QueryRow(
				`SELECT portal_insert_api_key($1, $2, $3, $4, $5::jsonb, $6)`,
				orgID, "khash-pra-07", "kp_07", "test-portal-key-07", scopes, expires,
			).Scan(&keyID)
		})
		if err != nil {
			t.Fatalf("portal_insert_api_key failed: %v (sqlstate=%s)", err, pgErrCode(err))
		}
		if keyID <= 0 {
			t.Fatalf("portal_insert_api_key returned non-positive id: %d", keyID)
		}
		// Verify via admin.
		var dbOrgID, dbName string
		if err := db.QueryRow(
			`SELECT org_id, name FROM customer_portal_api_keys WHERE id = $1`,
			keyID,
		).Scan(&dbOrgID, &dbName); err != nil {
			t.Fatalf("post-insert SELECT: %v", err)
		}
		if dbOrgID != orgID {
			t.Fatalf("org_id mismatch: got %q, want %q", dbOrgID, orgID)
		}
		if dbName != "test-portal-key-07" {
			t.Fatalf("name mismatch: got %q", dbName)
		}
	})

	// ------------------------------------------------------------------
	// Mutation gates — flip SECURITY DEFINER → SECURITY INVOKER, repeat
	// the call as axonflow_app_role with no GUC, expect 42501. Then
	// restore the SECURITY DEFINER version in defer.
	// ------------------------------------------------------------------

	t.Run("08_mutation_csaas_register_tenant", func(t *testing.T) {
		runMutationSubtest(t, db,
			"csaas_register_tenant",
			"(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR)",
			func(tx *sql.Tx) error {
				tenantID := "cs_pra_mut_reg_" + randomSuffix()
				_, err := tx.Exec(
					`SELECT csaas_register_tenant($1, $2, $3, $4, $5, NULL)`,
					tenantID, "h", "p", "lbl", time.Now().UTC().Add(30*24*time.Hour),
				)
				return err
			},
		)
	})

	t.Run("09_mutation_csaas_register_touch", func(t *testing.T) {
		// Seed a row that exists in csaas_registrations so the touch UPDATE
		// has a target. Under SECURITY INVOKER + app_role + no GUC, the
		// UPDATE itself fails the policy (USING check excludes all rows
		// because get_current_org_id is NULL — but UPDATE on a 0-row match
		// is not a 42501. RLS-blocked UPDATE returns 0 rows affected, not
		// an error. To make the mutation discriminating, we instead test
		// that under SECURITY INVOKER + app_role the function returns 0
		// rows (vs 1 under SECURITY DEFINER) — that's the mutation signal
		// for this specific helper.
		tenantID := "cs_pra_mut_touch_" + randomSuffix()
		// seed via SECURITY DEFINER
		err := runAsAppRoleTx(t, db, true, func(tx *sql.Tx) error {
			_, e := tx.Exec(
				`SELECT csaas_register_tenant($1, $2, $3, $4, $5, NULL)`,
				tenantID, "h", "p", "lbl", time.Now().UTC().Add(30*24*time.Hour),
			)
			return e
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}

		// Snapshot the original definition (search by oid -> pg_get_functiondef).
		origDef := getFunctionDef(t, db, "csaas_register_touch")
		invokerDef := strings.Replace(origDef, "SECURITY DEFINER", "SECURITY INVOKER", 1)
		if invokerDef == origDef {
			t.Fatal("could not mutate csaas_register_touch: SECURITY DEFINER keyword not found in pg_get_functiondef output")
		}
		// Drop + recreate as INVOKER. Defer restoration.
		if _, err := db.Exec("DROP FUNCTION csaas_register_touch(VARCHAR)"); err != nil {
			t.Fatalf("drop fn: %v", err)
		}
		if _, err := db.Exec(invokerDef); err != nil {
			// Restore from origDef before failing.
			_, _ = db.Exec(origDef)
			t.Fatalf("create INVOKER fn: %v", err)
		}
		defer func() {
			if _, err := db.Exec("DROP FUNCTION csaas_register_touch(VARCHAR)"); err != nil {
				t.Errorf("defer drop INVOKER fn: %v", err)
			}
			if _, err := db.Exec(origDef); err != nil {
				t.Errorf("defer restore SECURITY DEFINER fn: %v", err)
			}
			// Restore GRANT on the SECURITY DEFINER variant so any subsequent
			// subtest that re-uses csaas_register_touch under app_role sees
			// the expected privilege state (R3 round-1 MEDIUM-2 fold).
			if _, err := db.Exec("GRANT EXECUTE ON FUNCTION csaas_register_touch(VARCHAR) TO axonflow_app_role"); err != nil {
				t.Errorf("defer restore GRANT: %v", err)
			}
		}()

		// Need to GRANT EXECUTE back to axonflow_app_role since DROP+CREATE
		// reset privileges.
		if _, err := db.Exec("GRANT EXECUTE ON FUNCTION csaas_register_touch(VARCHAR) TO axonflow_app_role"); err != nil {
			t.Fatalf("grant on invoker variant: %v", err)
		}

		// Call as app_role with no GUC. UPDATE matches 0 rows under app_role's
		// FORCE-RLS USING policy (org_id = NULL evaluates to NULL which is
		// not TRUE). Helper returns ROW_COUNT = 0. SECURITY DEFINER variant
		// returns 1 (asserted in subtest 04). Discriminator: 0 != 1.
		var rows int
		err = runAsAppRoleTx(t, db, false, func(tx *sql.Tx) error {
			return tx.QueryRow(`SELECT csaas_register_touch($1)`, tenantID).Scan(&rows)
		})
		if err != nil {
			t.Fatalf("INVOKER call (expected to succeed with rows=0, not error): %v", err)
		}
		if rows != 0 {
			t.Fatalf("SECURITY INVOKER mutation should return rows=0 (RLS hides target row from app_role with no GUC); got %d. Mutation gate FAILED — SECURITY DEFINER is not the load-bearing keyword for this helper.", rows)
		}
	})

	t.Run("10_mutation_csaas_recovery_insert", func(t *testing.T) {
		runMutationSubtest(t, db,
			"csaas_recovery_insert",
			"(VARCHAR, VARCHAR, VARCHAR, VARCHAR, TIMESTAMPTZ, VARCHAR)",
			func(tx *sql.Tx) error {
				tenantID := "cs_pra_mut_rec_" + randomSuffix()
				_, err := tx.Exec(
					`SELECT csaas_recovery_insert($1, $2, $3, $4, $5, $6)`,
					tenantID, "h", "p", "recovery for e", time.Now().UTC().Add(30*24*time.Hour), "e@example.com",
				)
				return err
			},
		)
	})

	t.Run("11_mutation_auth_insert_api_key", func(t *testing.T) {
		runMutationSubtest(t, db,
			"auth_insert_api_key",
			"(VARCHAR, VARCHAR, VARCHAR, VARCHAR, INTEGER, VARCHAR)",
			func(tx *sql.Tx) error {
				var apiKeyID string
				return tx.QueryRow(
					`SELECT auth_insert_api_key($1, $2, $3, $4, $5, $6)`,
					"cust-pra-test", "lk-mut", "lkhash-mut", "key-mut", 30, "org-pra-mut",
				).Scan(&apiKeyID)
			},
		)
	})

	t.Run("12_mutation_portal_insert_api_key", func(t *testing.T) {
		runMutationSubtest(t, db,
			"portal_insert_api_key",
			"(VARCHAR, VARCHAR, VARCHAR, VARCHAR, JSONB, TIMESTAMPTZ)",
			func(tx *sql.Tx) error {
				scopes, _ := json.Marshal([]string{"read"})
				var keyID int
				return tx.QueryRow(
					`SELECT portal_insert_api_key($1, $2, $3, $4, $5::jsonb, $6)`,
					"org-mut", "khash-mut", "kp_mut", "test-mut", scopes, time.Now().UTC().Add(90*24*time.Hour),
				).Scan(&keyID)
			},
		)
	})
}

// runMutationSubtest swaps the named function to SECURITY INVOKER, runs `op`
// (which is expected to fail with 42501 since the caller is axonflow_app_role
// with no GUC + the table is FORCE-RLS'd by mig 105/108), then restores the
// SECURITY DEFINER variant in defer. The mutation discriminates only when
// the table truly has FORCE RLS — for the 4 INSERT helpers in this PR
// (community_saas_registrations FORCEd by mig 105; api_keys FORCEd by mig
// 108; customer_portal_api_keys was deliberately not FORCEd by mig 099 due
// to chicken-and-egg) we still expect 42501 for the THREE that are FORCEd.
//
// For portal_insert_api_key: customer_portal_api_keys is NOT FORCEd in core/.
// Under SECURITY INVOKER + app_role + RLS not enabled on the table, the
// INSERT succeeds (RLS doesn't apply). To still produce a discriminating
// mutation gate for this helper, we ENABLE+FORCE customer_portal_api_keys
// inline for the duration of the mutation test (and defer-undo).
func runMutationSubtest(t *testing.T, db *sql.DB, fnName, fnSig string, op func(*sql.Tx) error) {
	t.Helper()

	// Detect whether the helper's target table needs inline RLS enablement
	// for the mutation to be discriminating.
	var inlineForceTable string
	if fnName == "portal_insert_api_key" {
		inlineForceTable = "customer_portal_api_keys"
	}

	if inlineForceTable != "" {
		// Add an org_id-isolation policy + ENABLE + FORCE for the duration of
		// the mutation test. This is local-only setup the integration test
		// does on the testcontainer; production deployments use the existing
		// rotation of FORCE migrations.
		setup := []string{
			"ALTER TABLE " + inlineForceTable + " ENABLE ROW LEVEL SECURITY",
			"DROP POLICY IF EXISTS pra_mutation_policy ON " + inlineForceTable,
			"CREATE POLICY pra_mutation_policy ON " + inlineForceTable +
				" FOR ALL USING (org_id = current_setting('app.current_org_id', true))" +
				" WITH CHECK (org_id = current_setting('app.current_org_id', true))",
			"ALTER TABLE " + inlineForceTable + " FORCE ROW LEVEL SECURITY",
		}
		for _, s := range setup {
			if _, err := db.Exec(s); err != nil {
				t.Fatalf("inline FORCE setup %q: %v", truncForLog(s, 60), err)
			}
		}
		defer func() {
			teardown := []string{
				"ALTER TABLE " + inlineForceTable + " NO FORCE ROW LEVEL SECURITY",
				"DROP POLICY IF EXISTS pra_mutation_policy ON " + inlineForceTable,
				"ALTER TABLE " + inlineForceTable + " DISABLE ROW LEVEL SECURITY",
			}
			for _, s := range teardown {
				if _, err := db.Exec(s); err != nil {
					t.Errorf("inline FORCE teardown %q: %v", truncForLog(s, 60), err)
				}
			}
		}()
	}

	// Snapshot the original SECURITY DEFINER definition.
	origDef := getFunctionDef(t, db, fnName)
	invokerDef := strings.Replace(origDef, "SECURITY DEFINER", "SECURITY INVOKER", 1)
	if invokerDef == origDef {
		t.Fatalf("could not mutate %s: SECURITY DEFINER keyword not found in pg_get_functiondef output", fnName)
	}

	// DROP + CREATE as INVOKER. Defer the restoration so subsequent subtests
	// still see SECURITY DEFINER.
	if _, err := db.Exec("DROP FUNCTION " + fnName + fnSig); err != nil {
		t.Fatalf("drop fn: %v", err)
	}
	if _, err := db.Exec(invokerDef); err != nil {
		_, _ = db.Exec(origDef) // best-effort restore on create-fail
		t.Fatalf("create INVOKER fn: %v", err)
	}
	defer func() {
		if _, err := db.Exec("DROP FUNCTION " + fnName + fnSig); err != nil {
			t.Errorf("defer drop INVOKER fn: %v", err)
		}
		if _, err := db.Exec(origDef); err != nil {
			t.Errorf("defer restore SECURITY DEFINER fn: %v", err)
		}
		// pg_get_functiondef does NOT carry GRANT/REVOKE state. DROP+CREATE
		// dropped the original axonflow_app_role EXECUTE grant. Re-apply on
		// the restored SECURITY DEFINER variant so any subsequent subtest
		// that re-uses this fn under axonflow_app_role sees the expected
		// privilege state (R3 round-1 MEDIUM-2 fold).
		if _, err := db.Exec("GRANT EXECUTE ON FUNCTION " + fnName + fnSig + " TO axonflow_app_role"); err != nil {
			t.Errorf("defer restore GRANT: %v", err)
		}
	}()

	// DROP+CREATE wipes privilege grants. Restore axonflow_app_role GRANT.
	if _, err := db.Exec("GRANT EXECUTE ON FUNCTION " + fnName + fnSig + " TO axonflow_app_role"); err != nil {
		t.Fatalf("grant on invoker variant: %v", err)
	}

	// Call as app_role with NO GUC. Expect SQLSTATE 42501 (RLS policy
	// violation OR insufficient_privilege depending on table state).
	err := runAsAppRoleTx(t, db, false, op)
	if err == nil {
		t.Fatalf("SECURITY INVOKER mutation of %s should have failed under axonflow_app_role + no GUC, but succeeded. Mutation gate FAILED — SECURITY DEFINER is not the load-bearing keyword for this helper.", fnName)
	}
	code := pgErrCode(err)
	if code != rlsViolationCode {
		t.Fatalf("SECURITY INVOKER mutation of %s failed with unexpected SQLSTATE %s (want %s): %v", fnName, code, rlsViolationCode, err)
	}
}

// getFunctionDef returns pg_get_functiondef(oid) for the named function.
// Used by mutation tests to round-trip the function through DROP + CREATE.
func getFunctionDef(t *testing.T, db *sql.DB, fnName string) string {
	t.Helper()
	var def string
	err := db.QueryRow(
		`SELECT pg_get_functiondef(p.oid)
		 FROM pg_proc p
		 JOIN pg_namespace n ON p.pronamespace = n.oid
		 WHERE n.nspname = 'public' AND p.proname = $1
		 LIMIT 1`,
		fnName,
	).Scan(&def)
	if err != nil {
		t.Fatalf("pg_get_functiondef(%s): %v", fnName, err)
	}
	return def
}

// randomSuffix returns a short timestamp-based suffix so subtest seed rows
// don't collide if the test reruns within the same container.
func randomSuffix() string {
	return strings.ReplaceAll(time.Now().UTC().Format("150405.000000"), ".", "")
}
