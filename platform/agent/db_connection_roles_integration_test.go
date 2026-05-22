// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Integration coverage for db_connection.go's role-asserting open helpers.
// The CSAAS-DELETE plumbing landed via #2402 (run.go::Run) routes through
// RequirePlatformAdminOrFatal + OpenPlatformAdminConnection but the
// surrounding Run() entrypoint is not unit-testable; these tests close
// the coverage gap on the open helpers themselves so a future refactor
// of the role-assertion path is exercised end-to-end against a real
// Postgres test instance.
//
// Real-PG via the same `DATABASE_URL` the CI Test Suite job sets. Skips
// cleanly when the env is unset (community-build local runs without a
// docker postgres). The CI job ALWAYS has DATABASE_URL set + has the
// `axonflow_app_role` + `axonflow_platform_admin` roles applied via
// migrations/core/098_v9_rls_roles.sql, so the test runs there.

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// dbCreds carries the bits we need to build per-role DSNs against the
// same test_db the CI job initialized.
type dbCreds struct {
	host, port, db string
}

// dbCredsFromEnv parses the CI DATABASE_URL into the components we
// need to build per-role DSNs. The original URL points at the test_user
// role; we rebuild it for axonflow_app_role + axonflow_platform_admin
// using their canonical passwords (set by migration 098 in CI).
func dbCredsFromEnv(t *testing.T) dbCreds {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping real-PG db_connection role tests")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse DATABASE_URL: %v", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	db := strings.TrimPrefix(u.Path, "/")
	return dbCreds{host: host, port: port, db: db}
}

// ensureRoleHasPassword grants a known password to the named role so
// per-role DSN open() succeeds. Migration 098 creates the roles WITHOUT
// passwords (they're meant to be granted by the operator via SETUP); in
// the test_db we attach a known password so the test can authenticate.
// Best-effort: a prior test may have set the same password — `ALTER
// ROLE ... PASSWORD` is idempotent.
func ensureRoleHasPassword(t *testing.T, master *sql.DB, role, password string) {
	t.Helper()
	// pq doesn't support placeholders in DDL; we sanitize the role name
	// against an allowlist before interpolation.
	if !roleAllowed(role) {
		t.Fatalf("disallowed role %q in test setup — guard against accidental SQL injection", role)
	}
	stmt := fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s LOGIN", role, pgEscapeStringLit(password))
	if _, err := master.ExecContext(context.Background(), stmt); err != nil {
		t.Fatalf("ALTER ROLE %s: %v", role, err)
	}
}

func roleAllowed(role string) bool {
	switch role {
	case "axonflow_app_role", "axonflow_platform_admin":
		return true
	}
	return false
}

func pgEscapeStringLit(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func dsnAs(c dbCreds, role, password string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		role, password, c.host, c.port, c.db)
}

// withMaster opens a connection as the test_user role (the DATABASE_URL
// owner) for setup work.
func withMaster(t *testing.T) (*sql.DB, dbCreds) {
	t.Helper()
	c := dbCredsFromEnv(t)
	master, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("open master: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := master.Ping(); err != nil {
		t.Skipf("master DB unreachable, skipping: %v", err)
	}
	return master, c
}

// =============================================================================
// OpenAppRoleConnection
// =============================================================================

func TestOpenAppRoleConnection_NoDSNReturnsError(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set — pure error-path test depends on env shape")
	}
	// Force both env knobs off so ResolveAppRoleDSN sees nothing.
	t.Setenv("AXONFLOW_DB_USE_APP_ROLE", "true")
	t.Setenv("AXONFLOW_DB_APP_ROLE_URL", "")
	_, err := OpenAppRoleConnection(context.Background(), "", 1)
	if err == nil {
		t.Fatal("OpenAppRoleConnection with no DSN must error")
	}
	if !strings.Contains(err.Error(), "no DSN available") {
		t.Errorf("expected 'no DSN available' in error, got: %v", err)
	}
}

func TestOpenAppRoleConnection_AppRoleSuccess(t *testing.T) {
	master, creds := withMaster(t)
	ensureRoleHasPassword(t, master, "axonflow_app_role", "testpass_app_role")
	dsn := dsnAs(creds, "axonflow_app_role", "testpass_app_role")

	t.Setenv("AXONFLOW_DB_USE_APP_ROLE", "true")
	t.Setenv("AXONFLOW_DB_APP_ROLE_URL", dsn)

	db, err := OpenAppRoleConnection(context.Background(), "", 1)
	if err != nil {
		t.Fatalf("OpenAppRoleConnection: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Verify the connection is actually on axonflow_app_role.
	var current string
	if err := db.QueryRow("SELECT current_user").Scan(&current); err != nil {
		t.Fatalf("current_user: %v", err)
	}
	if current != "axonflow_app_role" {
		t.Errorf("connected as %q, want axonflow_app_role", current)
	}
}

func TestOpenAppRoleConnection_RoleAssertionFailsWhenDSNPointsAtMaster(t *testing.T) {
	// Misconfigured DSN: app-role gate is ON but the DSN authenticates
	// as the master (test_user). The role assertion must catch this
	// and return an error rather than silently degrading.
	//
	// R3 HIGH-1 fold: gate via withMaster(t) so DATABASE_URL-set-but-
	// unreachable skips cleanly instead of failing this test on a
	// "connection refused" instead of the expected "role assertion
	// failed" error.
	_, _ = withMaster(t)
	t.Setenv("AXONFLOW_DB_USE_APP_ROLE", "true")
	t.Setenv("AXONFLOW_DB_APP_ROLE_URL", os.Getenv("DATABASE_URL"))

	_, err := OpenAppRoleConnection(context.Background(), "", 1)
	if err == nil {
		t.Fatal("OpenAppRoleConnection with misconfigured DSN (master role) must error")
	}
	if !strings.Contains(err.Error(), "role assertion failed") {
		t.Errorf("expected 'role assertion failed' in error, got: %v", err)
	}
}

func TestOpenAppRoleConnection_GateOffSkipsRoleAssertion(t *testing.T) {
	// When AXONFLOW_DB_USE_APP_ROLE=false, OpenAppRoleConnection opens
	// the DSN without enforcing the role identity (legacy v8.x posture).
	// Verify it succeeds even when the DSN points at the master.
	//
	// R3 HIGH-1 fold: gate via withMaster(t) so DATABASE_URL-set-but-
	// unreachable skips cleanly.
	_, _ = withMaster(t)
	t.Setenv("AXONFLOW_DB_USE_APP_ROLE", "false")
	t.Setenv("AXONFLOW_DB_APP_ROLE_URL", "")
	db, err := OpenAppRoleConnection(context.Background(), os.Getenv("DATABASE_URL"), 1)
	if err != nil {
		t.Fatalf("OpenAppRoleConnection with gate off: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var current string
	if err := db.QueryRow("SELECT current_user").Scan(&current); err != nil {
		t.Fatalf("current_user: %v", err)
	}
	// We're connected as the master (test_user) — role-assertion did NOT fire.
	if current == "axonflow_app_role" {
		t.Errorf("with gate off, expected master role, not app_role; got %q", current)
	}
}

// =============================================================================
// OpenPlatformAdminConnection
// =============================================================================

func TestOpenPlatformAdminConnection_UnsetReturnsNilNil(t *testing.T) {
	// Contract: returns nil + nil error when AXONFLOW_DB_PLATFORM_ADMIN_URL
	// is unset. Caller must treat the nil-with-nil-err as "fall back to
	// supplied db pool."
	t.Setenv("AXONFLOW_DB_PLATFORM_ADMIN_URL", "")
	db, err := OpenPlatformAdminConnection(context.Background(), 1)
	if err != nil {
		t.Errorf("unset AXONFLOW_DB_PLATFORM_ADMIN_URL: err = %v, want nil", err)
	}
	if db != nil {
		t.Errorf("unset AXONFLOW_DB_PLATFORM_ADMIN_URL: db != nil, want nil")
	}
}

func TestOpenPlatformAdminConnection_Success(t *testing.T) {
	master, creds := withMaster(t)
	ensureRoleHasPassword(t, master, "axonflow_platform_admin", "testpass_admin")
	dsn := dsnAs(creds, "axonflow_platform_admin", "testpass_admin")
	t.Setenv("AXONFLOW_DB_PLATFORM_ADMIN_URL", dsn)

	db, err := OpenPlatformAdminConnection(context.Background(), 1)
	if err != nil {
		t.Fatalf("OpenPlatformAdminConnection: %v", err)
	}
	if db == nil {
		t.Fatal("OpenPlatformAdminConnection returned nil db without error")
	}
	t.Cleanup(func() { _ = db.Close() })

	var current string
	if err := db.QueryRow("SELECT current_user").Scan(&current); err != nil {
		t.Fatalf("current_user: %v", err)
	}
	if current != "axonflow_platform_admin" {
		t.Errorf("connected as %q, want axonflow_platform_admin", current)
	}
}

func TestOpenPlatformAdminConnection_RoleAssertionFailsWhenDSNPointsAtMaster(t *testing.T) {
	// R3 HIGH-1 fold: gate via withMaster(t) so DATABASE_URL-set-but-
	// unreachable skips cleanly instead of failing on "connection
	// refused" instead of the expected "role assertion failed".
	_, _ = withMaster(t)
	t.Setenv("AXONFLOW_DB_PLATFORM_ADMIN_URL", os.Getenv("DATABASE_URL"))
	_, err := OpenPlatformAdminConnection(context.Background(), 1)
	if err == nil {
		t.Fatal("OpenPlatformAdminConnection with master DSN must error")
	}
	if !strings.Contains(err.Error(), "role assertion failed") {
		t.Errorf("expected 'role assertion failed', got: %v", err)
	}
}

// =============================================================================
// assertConnectedRole
// =============================================================================

func TestAssertConnectedRole_MatchSucceeds(t *testing.T) {
	master, _ := withMaster(t)
	// test_user is the master; current_user matches itself.
	if err := assertConnectedRole(context.Background(), master, "test_user"); err != nil {
		t.Errorf("assertConnectedRole(test_user): %v", err)
	}
}

func TestAssertConnectedRole_MismatchErrors(t *testing.T) {
	master, _ := withMaster(t)
	err := assertConnectedRole(context.Background(), master, "axonflow_app_role")
	if err == nil {
		t.Fatal("assertConnectedRole expected 'mismatch' error, got nil")
	}
	if !strings.Contains(err.Error(), "expected current_user") {
		t.Errorf("expected mismatch message, got: %v", err)
	}
}
