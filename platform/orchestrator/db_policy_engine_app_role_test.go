// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"testing"

	"axonflow/platform/agent"
	"axonflow/platform/agent/approletest"
)

// TestDatabaseDynamicPolicyEngine_AppRoleGate_RealPostgres exercises the
// constructor's full path under AXONFLOW_DB_USE_APP_ROLE=true + a provisioned
// axonflow_app_role DSN. The Session 20 PR (#2381) wired the constructor's
// two pools through agent.OpenAppRoleConnection, but the existing integration
// tests in db_policy_engine_integration_test.go pin USE_APP_ROLE=false so the
// helper's assertion stays off and the testcontainer's master role can serve.
//
// Without an under-gate-on test, a future regression that reverts the wire to
// raw sql.Open would NOT surface in CI — it would only show up in production
// logs (a pool boot-log line saying current_user=master instead of
// axonflow_app_role).
//
// This test closes that gap by:
//
//   - Setting up a full postgres:15 testcontainer with every core migration
//     (which provisions axonflow_app_role + axonflow_platform_admin via mig
//     098 and the SECURITY DEFINER helpers via mig 104/108).
//   - Provisioning login passwords on both RLS roles, mirroring
//     scripts/operators/provision-app-role.sh.
//   - Setting AXONFLOW_DB_USE_APP_ROLE=true + AXONFLOW_DB_APP_ROLE_URL=<app-role DSN>.
//   - Invoking NewDatabaseDynamicPolicyEngine — the same constructor the
//     orchestrator calls at boot.
//   - Asserting both pools (db + metricsDB) have current_user=axonflow_app_role
//     via the test-only UnsafePoolsForTests accessor.
//
// Mutation-test discipline: reverting either pool's open to raw sql.Open in
// db_dynamic_policies.go fails this test with an actionable role-mismatch
// error. The companion AST audit at TestOrchestratorRunGoCallsOpenAppRoleConnection
// (in main_pool_app_role_test.go) catches the same regression at the source
// level — together they prevent the Session 20 root-cause shape from regressing
// silently to production.
func TestDatabaseDynamicPolicyEngine_AppRoleGate_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	// What this test verifies (and what it does NOT):
	//
	// `NewDatabaseDynamicPolicyEngine` invokes seedSystemMediaPolicies +
	// loadDefaultPolicies + refreshPolicies internally. Under
	// AXONFLOW_DB_USE_APP_ROLE=true + the testcontainer's full core migration
	// schema, the seed-path INSERTs against `dynamic_policies` fail because
	// the seed code doesn't `SET LOCAL app.current_org_id` before inserting
	// and the table's RLS WITH CHECK policy rejects the rows. (`dynamic_policies`
	// has ENABLE ROW LEVEL SECURITY per migration 018, not FORCE; that's
	// irrelevant here because axonflow_app_role is non-owner + NOBYPASSRLS,
	// so ENABLE is sufficient to gate it.) The engine logs "Warning: Failed
	// to seed ..." then falls back to in-memory defaults via
	// loadDefaultPolicies + returns a healthy engine handle. That fallback
	// IS the existing v9.0.0 contract for the seed path; it is not what
	// this test exercises.
	//
	// This test only asserts the constructor's boot-time pool-open wire:
	// both `db` and `metricsDB` MUST authenticate as `axonflow_app_role`
	// (verified via SELECT current_user through UnsafePoolsForTests).
	// Policy seeding + refresh correctness under FORCE RLS is out of scope
	// — that requires orchestrator-side handler GUC wrapping, tracked
	// separately (see v8.0.0 CHANGELOG entry for the Main connection pools
	// bullet's trailer).

	t.Run("BothPoolsConnectAsAxonflowAppRole", func(t *testing.T) {
		// t.Setenv handles cleanup automatically. Setting DATABASE_URL =
		// MasterDSN lets the engine's outer code (which calls os.Getenv
		// directly) get a valid DSN; AXONFLOW_DB_APP_ROLE_URL is what the
		// helper actually consumes under the gate.
		t.Setenv("DATABASE_URL", env.MasterDSN)
		t.Setenv(agent.EnvUseAppRole, "true")
		t.Setenv(agent.EnvAppRoleURL, env.AppRoleDSN)

		engine, err := NewDatabaseDynamicPolicyEngine()
		if err != nil {
			t.Fatalf("NewDatabaseDynamicPolicyEngine under USE_APP_ROLE=true: %v", err)
		}
		defer func() { _ = engine.Close() }()

		db, metricsDB := engine.UnsafePoolsForTests()
		if db == nil {
			t.Fatalf("engine.db is nil after successful constructor")
		}
		if metricsDB == nil {
			t.Fatalf("engine.metricsDB is nil after successful constructor")
		}
		approletest.AssertCurrentUser(t, db, "axonflow_app_role")
		approletest.AssertCurrentUser(t, metricsDB, "axonflow_app_role")
	})

	// Mutation guard: with the gate ON but no app-role DSN set, the helper
	// falls back to DATABASE_URL (master), then asserts current_user matches
	// axonflow_app_role — which FAILS for the master role. Under #3319,
	// NewDatabaseDynamicPolicyEngine never fails construction on a boot-time
	// database problem (see its doc comment) — it always returns a usable
	// engine serving the built-in default policy set. The safety property
	// this test guards therefore no longer surfaces as a constructor error;
	// it surfaces as connectDB returning before e.db/e.metricsDB are ever
	// assigned (db_dynamic_policies.go connectDB opens both role-asserted
	// pools before touching e.mu) and the engine staying on
	// policySetSourceDefaults. What MUST still be true: the engine must NOT
	// silently connect as master and serve database-loaded policies through
	// that connection.
	t.Run("RejectsMasterFallbackUnderGateOn", func(t *testing.T) {
		t.Setenv("DATABASE_URL", env.MasterDSN)
		t.Setenv(agent.EnvUseAppRole, "true")
		_ = os.Unsetenv(agent.EnvAppRoleURL)

		engine, err := NewDatabaseDynamicPolicyEngine()
		if err != nil {
			t.Fatalf("NewDatabaseDynamicPolicyEngine returned an unexpected error: %v", err)
		}
		defer func() { _ = engine.Close() }()

		db, metricsDB := engine.UnsafePoolsForTests()
		if db != nil || metricsDB != nil {
			t.Fatalf("engine connected its pools despite a role-assertion failure under gate=on — assertion bypass regression (db=%v, metricsDB=%v)", db, metricsDB)
		}
		if got := engine.PolicySetSource(); got != policySetSourceDefaults {
			t.Fatalf("engine promoted to policy-set source %q despite never completing a role-asserted connection — assertion bypass regression", got)
		}
	})

	// Verify the legacy gate-off path still works after the wire. Under
	// USE_APP_ROLE=false, the helper falls back to DATABASE_URL (master) and
	// skips the assertion. This is the path setupTestDBEnv in the sibling
	// file pins, and it MUST keep working for existing tests + dev compose.
	t.Run("GateOffConnectsAsMaster", func(t *testing.T) {
		t.Setenv("DATABASE_URL", env.MasterDSN)
		t.Setenv(agent.EnvUseAppRole, "false")

		engine, err := NewDatabaseDynamicPolicyEngine()
		if err != nil {
			t.Fatalf("NewDatabaseDynamicPolicyEngine under USE_APP_ROLE=false: %v", err)
		}
		defer func() { _ = engine.Close() }()

		db, metricsDB := engine.UnsafePoolsForTests()
		approletest.AssertCurrentUser(t, db, "postgres")
		approletest.AssertCurrentUser(t, metricsDB, "postgres")
	})
}
