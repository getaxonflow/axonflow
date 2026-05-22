// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"axonflow/platform/agent/approletest"
)

// TestMainPoolConnectsAsAppRole_RealPostgres pins the agent's main authDB
// boot path to OpenAppRoleConnection. It exists because v9.0.0 shipped with
// AXONFLOW_DB_USE_APP_ROLE defaulting to true but the agent main pool was
// still on raw sql.Open — see Session 20 brief gap #1 (no boot-time
// current_user assertion).
//
// What the test proves:
//
//  1. Setup applies migrations 001..111 (which creates axonflow_app_role
//     via migration 098) and ALTER ROLE provisions login passwords for both
//     RLS roles, mirroring scripts/operators/provision-app-role.sh.
//  2. With AXONFLOW_DB_USE_APP_ROLE=true + AXONFLOW_DB_APP_ROLE_URL pointed
//     at the app-role DSN, OpenAppRoleConnection opens a pool that
//     authenticates as axonflow_app_role (verified via SELECT current_user
//     on the returned *sql.DB).
//  3. The internal role assertion runs: setting USE_APP_ROLE=true but
//     pointing APP_ROLE_URL at the master DSN (or unsetting it so the
//     fallback DSN is used) makes the helper reject the connection because
//     current_user != axonflow_app_role.
//  4. With AXONFLOW_DB_USE_APP_ROLE=false, the helper falls back to the
//     supplied DSN and skips the role check — boot under master role works
//     for local dev where the master IS the application role.
//
// Mutation-test discipline (per
// feedback_mutation_test_to_prove_assertion_not_tautological):
//
//   - Reverting platform/agent/run.go:891 to raw sql.Open MUST cause the
//     "WireSetsCurrentUserToAppRole" subtest to be misleading because the
//     production binary would silently connect as master while the test
//     here still talks to OpenAppRoleConnection directly. The companion
//     audit at TestAgentRunGoCallsOpenAppRoleConnection_NotRawSQLOpen
//     covers that regression at the source-level grep — see below.
//   - Removing the assertConnectedRole call in db_connection.go MUST make
//     the "WireRejectsMasterDSNUnderAppRoleGate" subtest hang or pass
//     wrongly. This is also exercised by the FailsWhenFallbackHitsMaster
//     subtest, which expects an error wrapping "expected current_user".
func TestMainPoolConnectsAsAppRole_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	t.Run("WireSetsCurrentUserToAppRole", func(t *testing.T) {
		t.Setenv(EnvUseAppRole, "true")
		t.Setenv(EnvAppRoleURL, env.AppRoleDSN)
		db, err := OpenAppRoleConnection(context.Background(), env.MasterDSN, 3)
		if err != nil {
			t.Fatalf("OpenAppRoleConnection: %v", err)
		}
		defer func() { _ = db.Close() }()
		approletest.AssertCurrentUser(t, db, "axonflow_app_role")
	})

	t.Run("WireRejectsMasterDSNUnderAppRoleGate", func(t *testing.T) {
		// USE_APP_ROLE=true + no APP_ROLE_URL → helper falls back to the
		// supplied dsnFallback (master DSN). The assertion catches this and
		// errors instead of silently bypassing RLS.
		t.Setenv(EnvUseAppRole, "true")
		_ = os.Unsetenv(EnvAppRoleURL)
		db, err := OpenAppRoleConnection(context.Background(), env.MasterDSN, 1)
		if err == nil {
			_ = db.Close()
			t.Fatalf("OpenAppRoleConnection unexpectedly succeeded — assertion bypass regression")
		}
		// Error wrapping check — keeps a future refactor from collapsing
		// the assertion into a silent fall-through.
		if errMsg := err.Error(); !containsSubstrS20(errMsg, "expected current_user") && !containsSubstrS20(errMsg, "role assertion failed") {
			t.Errorf("expected role-mismatch error, got: %v", err)
		}
	})

	t.Run("WireWithGateOffFallsBackToMaster", func(t *testing.T) {
		t.Setenv(EnvUseAppRole, "false")
		db, err := OpenAppRoleConnection(context.Background(), env.MasterDSN, 3)
		if err != nil {
			t.Fatalf("OpenAppRoleConnection with gate off: %v", err)
		}
		defer func() { _ = db.Close() }()
		approletest.AssertCurrentUser(t, db, "postgres")
	})

	t.Run("PlatformAdminConnectionAssertsBypassRole", func(t *testing.T) {
		// Smoke-test the platform-admin wire — same shape as the agent's
		// 4 worker call sites and customer-portal's adminDB.
		t.Setenv(EnvPlatformAdminURL, env.AdminDSN)
		db, err := OpenPlatformAdminConnection(context.Background(), 3)
		if err != nil {
			t.Fatalf("OpenPlatformAdminConnection: %v", err)
		}
		if db == nil {
			t.Fatalf("OpenPlatformAdminConnection returned nil with env set")
		}
		defer func() { _ = db.Close() }()
		approletest.AssertCurrentUser(t, db, "axonflow_platform_admin")
	})

	t.Run("PlatformAdminEnvUnsetReturnsNilNilNoError", func(t *testing.T) {
		_ = os.Unsetenv(EnvPlatformAdminURL)
		db, err := OpenPlatformAdminConnection(context.Background(), 3)
		if err != nil {
			t.Fatalf("expected nil err on unset env, got: %v", err)
		}
		if db != nil {
			_ = db.Close()
			t.Fatalf("expected nil db on unset env, got non-nil")
		}
	})
}

func containsSubstrS20(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestAgentRunGoCallsOpenAppRoleConnection_NotRawSQLOpen is a source-level
// regression guard. The integration test above exercises the helper, but a
// future refactor that re-introduces sql.Open at agent/run.go's authDB site
// (the Session 20 root-cause bug) would not be caught by that test alone.
// This audit reads run.go and asserts the call site uses
// OpenAppRoleConnection.
//
// Mutation-test: revert run.go:891 to `authDB, err = sql.Open("postgres",
// dbURL)` and this test fails with an actionable message naming the file.
func TestAgentRunGoCallsOpenAppRoleConnection_NotRawSQLOpen(t *testing.T) {
	source, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("read run.go: %v", err)
	}
	src := string(source)
	const (
		mustHave = `authDB, err = OpenAppRoleConnection(`
		mustNot1 = `authDB, err = sql.Open("postgres", dbURL)`
	)
	if !containsSubstrS20(src, mustHave) {
		t.Errorf("platform/agent/run.go: missing required call site `%s` — Session 20 regression", mustHave)
	}
	if containsSubstrS20(src, mustNot1) {
		t.Errorf("platform/agent/run.go: forbidden raw sql.Open call `%s` — Session 20 release-blocker regressed", mustNot1)
	}
}

// stubExpectSQLDB silences the unused-import warning when sql is referenced
// only inside an assertion macro.
var _ = sql.ErrNoRows
