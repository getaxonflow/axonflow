// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Real-Postgres integration test for scripts/operators/provision-app-role.sh.
// Gated on TEST_PG_INTEGRATION=1 + docker available — same gate the
// sibling TestMigration094Precondition_RealPostgres uses
// (v9_followup_a_gaps_test.go:325).
//
// What this proves:
//
//   - SUT (scripts/operators/provision-app-role.sh) refuses to run with a
//     missing env var (exit 2).
//
//   - SUT refuses to ALTER when migration 098 has not run (exit 1, both
//     roles missing).
//
//   - SUT successfully ALTER ROLE … WITH PASSWORD on both roles after 098
//     has been applied, and the resulting role passwords actually
//     authenticate (test connects AS each role using the new password).
//
//   - Idempotency: a second invocation with the SAME passwords is a no-op
//     (the SUT detects rolpassword IS NOT NULL and skips ALTER), and a
//     subsequent FORCE_RESET=1 re-rotates.
//
//   - Mutation discrimination: temporarily DROP both roles between the
//     "success" run and the second run — the SUT detects role absence and
//     exits 1. Proves the migration-098 precondition check is load-bearing.
//
// The test exec's the SUT shell script rather than reimplementing the
// ALTER logic in Go. That way the test exercises the actual shell script
// operators will run — any divergence between the test and the operator
// experience surfaces immediately. The Go test wrapper exists only to
// borrow the existing startPostgresContainer + runMigrationsRange helpers
// (v9_followup_a_gaps_test.go:671+724).
func TestProvisionAppRoleScript_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("set TEST_PG_INTEGRATION=1 to run real-PG integration tests (requires docker)")
	}

	scriptPath, err := filepath.Abs("../../scripts/operators/provision-app-role.sh")
	if err != nil {
		t.Fatalf("resolve script path: %v", err)
	}
	if _, statErr := os.Stat(scriptPath); statErr != nil {
		t.Fatalf("script not present: %v", statErr)
	}

	pgURL, cleanup := startPostgresContainer(t)
	defer cleanup()

	// Helper: invoke the script with env vars, capture stdout+stderr and exit.
	runScript := func(t *testing.T, env map[string]string) (stdout, stderr string, exitCode int) {
		t.Helper()
		cmd := exec.Command("bash", scriptPath)
		// Inherit minimal env so docker/psql find their PATH; layer on caller env.
		cmd.Env = append(os.Environ(), "DATABASE_URL=") // clear inherited
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		var soBuf, seBuf strings.Builder
		cmd.Stdout = &soBuf
		cmd.Stderr = &seBuf
		runErr := cmd.Run()
		stdout = soBuf.String()
		stderr = seBuf.String()
		exitCode = 0
		if runErr != nil {
			if ee, ok := runErr.(*exec.ExitError); ok {
				exitCode = ee.ExitCode()
			} else {
				t.Fatalf("script exec failed (non-ExitError): %v\n%s\n%s", runErr, stdout, stderr)
			}
		}
		return
	}

	// Reset the schema before each subtest. Fresh-install state.
	resetSchema := func(t *testing.T) {
		t.Helper()
		db, err := sql.Open("postgres", pgURL)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
			t.Fatalf("reset schema: %v", err)
		}
		// Also drop the two roles if a prior subtest created them — they
		// live OUTSIDE the public schema and survive DROP SCHEMA.
		_, _ = db.Exec(`DROP ROLE IF EXISTS axonflow_app_role`)
		_, _ = db.Exec(`DROP ROLE IF EXISTS axonflow_platform_admin`)
	}

	t.Run("A_missing_env_var_exits_2", func(t *testing.T) {
		resetSchema(t)
		// No APP_ROLE_PASSWORD/PLATFORM_ADMIN_PASSWORD — should exit 2.
		stdout, stderr, code := runScript(t, map[string]string{
			"DATABASE_URL": pgURL,
		})
		if code != 2 {
			t.Errorf("missing-env exit: got %d, want 2\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		combined := stdout + stderr
		if !strings.Contains(combined, "APP_ROLE_PASSWORD") {
			t.Errorf("expected error mentioning APP_ROLE_PASSWORD; got: %s", combined)
		}
	})

	t.Run("B_pre_098_exits_1", func(t *testing.T) {
		resetSchema(t)
		// Roles do not exist — SUT should detect and exit 1.
		stdout, stderr, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       "test-app-password-A1B2C3",
			"PLATFORM_ADMIN_PASSWORD": "test-admin-password-D4E5F6",
		})
		if code != 1 {
			t.Errorf("pre-098 exit: got %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		if !strings.Contains(stdout, "axonflow_app_role does not exist") {
			t.Errorf("expected FAIL about axonflow_app_role missing; got:\n%s", stdout)
		}
	})

	t.Run("C_post_098_passwords_set_and_login_works", func(t *testing.T) {
		resetSchema(t)
		// Apply migration 098 only.
		db, err := sql.Open("postgres", pgURL)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		// Migration 098 grants on ALL TABLES IN SCHEMA public, which works on
		// an empty schema. We only need the role-create + attribute clauses.
		mig098, err := os.ReadFile("../../migrations/core/098_v9_rls_roles.sql")
		if err != nil {
			t.Fatalf("read mig 098: %v", err)
		}
		if _, err := db.Exec(string(mig098)); err != nil {
			t.Fatalf("apply mig 098: %v", err)
		}

		appPW := "appPW-uniqueA1-Yk7nQ"
		adminPW := "adminPW-uniqueB2-Wp9rL"

		stdout, stderr, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       appPW,
			"PLATFORM_ADMIN_PASSWORD": adminPW,
		})
		if code != 0 {
			t.Fatalf("post-098 first run: got exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}

		// Prove the password actually authenticates AS axonflow_app_role.
		// Build a per-role DSN from the master URL's host/port/dbname.
		dsn := strings.Replace(pgURL, "postgres://postgres:testpass@", "postgres://axonflow_app_role:"+appPW+"@", 1)
		appDB, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("sql.Open app_role: %v", err)
		}
		defer appDB.Close()
		var who string
		if err := appDB.QueryRow("SELECT current_user").Scan(&who); err != nil {
			t.Fatalf("app_role SELECT current_user: %v", err)
		}
		if who != "axonflow_app_role" {
			t.Errorf("app_role connection landed on user %q, want axonflow_app_role", who)
		}

		// Same for admin.
		dsnAdmin := strings.Replace(pgURL, "postgres://postgres:testpass@", "postgres://axonflow_platform_admin:"+adminPW+"@", 1)
		adminDB, err := sql.Open("postgres", dsnAdmin)
		if err != nil {
			t.Fatalf("sql.Open admin: %v", err)
		}
		defer adminDB.Close()
		if err := adminDB.QueryRow("SELECT current_user").Scan(&who); err != nil {
			t.Fatalf("admin SELECT current_user: %v", err)
		}
		if who != "axonflow_platform_admin" {
			t.Errorf("admin connection landed on user %q, want axonflow_platform_admin", who)
		}
	})

	t.Run("D_idempotent_re_run_same_password_skips_alter", func(t *testing.T) {
		// Operator scenario: run, then re-run with the SAME passwords (e.g.,
		// re-running the canonical provision workflow on the same env). Must
		// exit 0; ALTER is skipped (rolpassword IS NOT NULL); connectivity
		// probe succeeds because the supplied password matches.
		resetSchema(t)

		db, err := sql.Open("postgres", pgURL)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		mig098, _ := os.ReadFile("../../migrations/core/098_v9_rls_roles.sql")
		if _, err := db.Exec(string(mig098)); err != nil {
			t.Fatalf("apply mig 098: %v", err)
		}

		samePW := "same-pw-XYZ-aB1"
		sameAdminPW := "same-admin-XYZ-aB2"
		// First run sets passwords + verifies connectivity.
		if _, _, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       samePW,
			"PLATFORM_ADMIN_PASSWORD": sameAdminPW,
		}); code != 0 {
			t.Fatalf("first run exit: %d", code)
		}

		// Second run with the SAME passwords — ALTER must be skipped
		// (rolpassword already set), connectivity must still pass
		// (same password authenticates the role), exit 0.
		stdout, _, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       samePW,
			"PLATFORM_ADMIN_PASSWORD": sameAdminPW,
		})
		if code != 0 {
			t.Fatalf("idempotent re-run (same password): got exit %d, want 0\nstdout:\n%s", code, stdout)
		}
		if !strings.Contains(stdout, "already has a password") {
			t.Errorf("expected idempotent-skip notice; got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "ALTER ROLE skipped") {
			t.Errorf("expected 'ALTER ROLE skipped' confirmation; got:\n%s", stdout)
		}
	})

	t.Run("D2_mismatched_password_without_force_reset_exits_1", func(t *testing.T) {
		// Operator mistake: re-run with DIFFERENT passwords without setting
		// FORCE_RESET. Strict-mode contract: script must detect that
		// supplied password does not match stored password (via
		// connectivity probe), and exit 1 with a helpful message.
		// This is the audit gate that catches typo-mismatched env vars.
		resetSchema(t)

		db, err := sql.Open("postgres", pgURL)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		mig098, _ := os.ReadFile("../../migrations/core/098_v9_rls_roles.sql")
		if _, err := db.Exec(string(mig098)); err != nil {
			t.Fatalf("apply mig 098: %v", err)
		}

		// Seed initial passwords.
		firstPW := "first-pw-A1B2C3"
		firstAdminPW := "first-admin-D4E5F6"
		if _, _, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       firstPW,
			"PLATFORM_ADMIN_PASSWORD": firstAdminPW,
		}); code != 0 {
			t.Fatalf("first run: %d", code)
		}

		// Second run with DIFFERENT passwords + NO FORCE_RESET.
		decoyPW := "decoy-should-fail-Aa1"
		stdout, _, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       decoyPW,
			"PLATFORM_ADMIN_PASSWORD": decoyPW,
		})
		if code != 1 {
			t.Errorf("mismatched-password run: got exit %d, want 1 (strict-mode connectivity probe must fail)\nstdout:\n%s", code, stdout)
		}
		if !strings.Contains(stdout, "Could not connect") {
			t.Errorf("expected FAIL about connectivity; got:\n%s", stdout)
		}

		// Prove the FIRST password still works (no rotation happened).
		dsn := strings.Replace(pgURL, "postgres://postgres:testpass@", "postgres://axonflow_app_role:"+firstPW+"@", 1)
		appDB, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("sql.Open app_role: %v", err)
		}
		defer appDB.Close()
		if err := appDB.Ping(); err != nil {
			t.Errorf("first password rejected after mismatched re-run (idempotency leaked): %v", err)
		}

		// And prove the decoy password does NOT work.
		dsnDecoy := strings.Replace(pgURL, "postgres://postgres:testpass@", "postgres://axonflow_app_role:"+decoyPW+"@", 1)
		decoyDB, err := sql.Open("postgres", dsnDecoy)
		if err == nil {
			if pingErr := decoyDB.Ping(); pingErr == nil {
				t.Error("decoy password works post-mismatch — idempotency SKIP did not protect existing password")
			}
			_ = decoyDB.Close()
		}
	})

	t.Run("E_force_reset_overrides_idempotency", func(t *testing.T) {
		resetSchema(t)
		db, err := sql.Open("postgres", pgURL)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		mig098, _ := os.ReadFile("../../migrations/core/098_v9_rls_roles.sql")
		if _, err := db.Exec(string(mig098)); err != nil {
			t.Fatalf("apply mig 098: %v", err)
		}

		// First run sets initial passwords.
		oldPW := "oldPW-A-uniqueXYZ"
		oldAdminPW := "oldPW-B-uniqueXYZ"
		if _, _, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       oldPW,
			"PLATFORM_ADMIN_PASSWORD": oldAdminPW,
		}); code != 0 {
			t.Fatalf("first run: %d", code)
		}

		// Rotate via FORCE_RESET=1.
		newPW := "newPW-A-uniqueABC"
		newAdminPW := "newPW-B-uniqueABC"
		if _, _, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       newPW,
			"PLATFORM_ADMIN_PASSWORD": newAdminPW,
			"FORCE_RESET":             "1",
		}); code != 0 {
			t.Fatalf("rotation run: %d", code)
		}

		// NEW password works.
		dsnNew := strings.Replace(pgURL, "postgres://postgres:testpass@", "postgres://axonflow_app_role:"+newPW+"@", 1)
		newAppDB, _ := sql.Open("postgres", dsnNew)
		defer newAppDB.Close()
		if err := newAppDB.Ping(); err != nil {
			t.Errorf("FORCE_RESET new password failed: %v", err)
		}

		// OLD password rejected.
		dsnOld := strings.Replace(pgURL, "postgres://postgres:testpass@", "postgres://axonflow_app_role:"+oldPW+"@", 1)
		oldAppDB, _ := sql.Open("postgres", dsnOld)
		if err := oldAppDB.Ping(); err == nil {
			t.Error("OLD password still works after FORCE_RESET — rotation did not actually rotate")
		}
		_ = oldAppDB.Close()
	})

	t.Run("F_missing_role_after_drop_exits_1", func(t *testing.T) {
		// Mutation proof for the migration-098 check: even with passwords
		// passed correctly, if a role is DROPped (simulating a deployment
		// where migration 098 ran but then was rolled back), the SUT exits 1.
		resetSchema(t)
		db, err := sql.Open("postgres", pgURL)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		mig098, _ := os.ReadFile("../../migrations/core/098_v9_rls_roles.sql")
		if _, err := db.Exec(string(mig098)); err != nil {
			t.Fatalf("apply mig 098: %v", err)
		}
		// Drop one of the two roles to simulate rollback. Migration 098 has
		// granted CRUD on ALL TABLES + ALTER DEFAULT PRIVILEGES referencing
		// the role; both create dependencies that block DROP ROLE. REASSIGN +
		// DROP OWNED clear the catalog edges. (REVOKE is implicit in
		// DROP OWNED for the grantee.)
		for _, ddl := range []string{
			`REASSIGN OWNED BY axonflow_app_role TO postgres`,
			`DROP OWNED BY axonflow_app_role`,
			`DROP ROLE axonflow_app_role`,
		} {
			if _, err := db.Exec(ddl); err != nil {
				t.Fatalf("%s: %v", ddl, err)
			}
		}
		_, stderr, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       "any-pw-doesnt-matter-AaBbC1",
			"PLATFORM_ADMIN_PASSWORD": "any-other-pw-AaBbC2",
		})
		if code != 1 {
			t.Errorf("missing-role exit: got %d, want 1\nstderr: %s", code, stderr)
		}
	})

	t.Run("G_password_with_single_quote_rejected", func(t *testing.T) {
		resetSchema(t)
		// Single-quote in password breaks ALTER ROLE string literal. The
		// SUT must reject before issuing the ALTER. Migration 098 not
		// required — this validation lives in the early arg-check.
		_, stderr, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       "has-a-'-quote-A1",
			"PLATFORM_ADMIN_PASSWORD": "safe-pw-B2C3",
		})
		if code != 2 {
			t.Errorf("single-quote rejection: got %d, want 2\nstderr: %s", code, stderr)
		}
		if !strings.Contains(stderr, "single quote") && !strings.Contains(stderr, "not supported") {
			t.Errorf("expected message about single-quote; got: %s", stderr)
		}
	})

	t.Run("G2_admin_password_with_single_quote_rejected", func(t *testing.T) {
		// Symmetric coverage of the same guard in the script for
		// PLATFORM_ADMIN_PASSWORD. Closes the L1 coverage gap from R3.
		resetSchema(t)
		_, stderr, code := runScript(t, map[string]string{
			"DATABASE_URL":            pgURL,
			"APP_ROLE_PASSWORD":       "safe-pw-A1B2",
			"PLATFORM_ADMIN_PASSWORD": "admin-has-'-quote-C3",
		})
		if code != 2 {
			t.Errorf("admin single-quote rejection: got %d, want 2\nstderr: %s", code, stderr)
		}
		if !strings.Contains(stderr, "single quote") && !strings.Contains(stderr, "not supported") {
			t.Errorf("expected message about single-quote; got: %s", stderr)
		}
	})
}
