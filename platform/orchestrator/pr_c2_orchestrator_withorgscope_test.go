// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// v9 Phase 8 PR-C2 (#2384) — real-Postgres integration test that proves
// every orchestrator-side write into an RLS-gated table now passes under
// axonflow_app_role (NOBYPASSRLS), and that reverting the wrap surfaces
// the canonical 42501 row_level_security failure mode.
//
// Coverage layering:
//
//  - This file's TestPRC2_Orchestrator_WithOrgScope_Sites pins the
//    SCHEMA + GUC + INSERT-col-list combo per table. Each subtest writes
//    raw SQL through a SET LOCAL ROLE axonflow_app_role transaction —
//    happy path with GUC set / mutation gate with GUC unset (or org_id
//    column omitted). If anyone changes the policy shape, schema column
//    list, or RLS gating, these tests catch it.
//
//  - The CALL BINDING (production function actually calls WithOrgScope
//    with the right orgID and the right INSERT col list) is pinned by:
//      * platform/orchestrator/llm/storage_integration_test.go
//        (SaveProvider/RecordUsage/DeleteProvider end-to-end)
//      * platform/connectors/registry/postgres_storage_integration_test.go
//        (SaveConnector/DeleteConnector/UpdateHealthStatus end-to-end)
//      * TestPRC2_PostgresStorage_SaveConnector_WithOrgScope below
//        (Storage methods through the production registry constructor
//         under an app_role runtime pool — proves the wrap is wired,
//         not just present).
//      * Mock tests in db_dynamic_policies_test.go, hitl_wcp_community_test.go,
//        plugin_batch1_coverage_test.go now expect the BEGIN/set_config/
//        EXEC/COMMIT envelope — a missed wrap fails sqlmock.
//      * PR-D AST audit walker (gated on C1+C2+C3 merge) is the final
//        regression guard against orphan unwrapped Exec calls into RLS
//        tables; ships separately after this PR.
//
// Mutation discipline (mirrors PR-A's pr_a_security_definer_test):
//
//  1. Happy-path subtest exercises the schema+wrap shape inside a tx with
//     SET LOCAL ROLE axonflow_app_role + a freshly-set app.current_org_id
//     GUC. INSERT/UPDATE/DELETE land — rowsAffected > 0 + no error.
//  2. Mutation gate: each happy-path subtest has a sibling that opens a
//     fresh tx, SET LOCAL ROLE axonflow_app_role, runs the SAME write
//     with NO app.current_org_id set, asserts pq.Error.Code == "42501"
//     (or rows-affected==0 for the silent-no-op DELETE/UPDATE class).
//
// Gating: TEST_PG_INTEGRATION=1. Without it, the test skips.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"axonflow/platform/agent"
	"axonflow/platform/agent/approletest"
	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
)

const prC2RLSViolationCode = "42501"

// prC2Setup spins a postgres:15 container, runs migs 1..111, provisions
// app-role + admin login passwords. mig 110 (which PR-C2 ships) is now
// inside approletest.Setup's range — the dedicated re-apply below is a
// no-op after the bump but kept for legacy compat. Returns an env handle
// whose DSN trio is ready to use.
func prC2Setup(t *testing.T) *approletest.Env {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	// Apply mig 109 (PR-A helpers — needed because mig 110's tests of
	// policy_overrides rely on the SECURITY DEFINER ecosystem already
	// being in place) + mig 110 (PR-C2's policy_overrides normalization).
	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open masterDSN: %v", err)
	}
	t.Cleanup(func() { _ = masterDB.Close() })
	for _, mig := range []string{
		"../../migrations/core/109_v9_phase8_pr_a_security_definer_helpers.sql",
		"../../migrations/core/110_v9_phase8_pr_c2_policy_overrides_org_id.sql",
	} {
		body, err := os.ReadFile(mig)
		if err != nil {
			t.Fatalf("read %s: %v", mig, err)
		}
		if _, err := masterDB.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", mig, err)
		}
	}

	// Schema fixups. connector_configs is enterprise-mode-only (created by
	// enterprise migrations, not core/) — mig 107 gates its FORCE step on
	// table presence. For PR-C2's wrap test we materialize a minimal shape
	// inline so the orchestrator INSERT can resolve at call time.
	// policy_overrides ToolSig/revoked_* columns are added by later core
	// migs (042, 044) that the test container's runner may or may not
	// have applied depending on its migration loader's path glob; ALTER
	// IF NOT EXISTS is harmless idempotency.
	for _, stmt := range []string{
		`ALTER TABLE policy_overrides ADD COLUMN IF NOT EXISTS tool_signature TEXT`,
		`ALTER TABLE policy_overrides ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`,
		`ALTER TABLE policy_overrides ADD COLUMN IF NOT EXISTS revoked_by VARCHAR(255)`,
		`CREATE TABLE IF NOT EXISTS organizations (
			id VARCHAR(255) PRIMARY KEY,
			org_id VARCHAR(255),
			name VARCHAR(255),
			tier VARCHAR(20),
			max_nodes INTEGER DEFAULT 1000,
			license_key VARCHAR(512),
			status VARCHAR(20)
		)`,
		`CREATE TABLE IF NOT EXISTS tenants (
			tenant_id VARCHAR(255) PRIMARY KEY,
			org_id VARCHAR(255)
		)`,
		// connector_configs (enterprise-only) — minimal shape matching the
		// orchestrator INSERT col list + mig 107 ENABLE+FORCE RLS gating.
		`CREATE TABLE IF NOT EXISTS connector_configs (
			id BIGSERIAL PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			org_id VARCHAR(255) NOT NULL,
			connector_name VARCHAR(255) NOT NULL,
			connector_type VARCHAR(50),
			display_name VARCHAR(255),
			description TEXT,
			connection_url TEXT,
			options JSONB DEFAULT '{}',
			credentials JSONB DEFAULT '{}',
			timeout_ms INTEGER DEFAULT 30000,
			max_retries INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT true,
			health_status VARCHAR(50) DEFAULT 'unknown',
			created_by VARCHAR(255),
			updated_by VARCHAR(255),
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE (tenant_id, connector_name)
		)`,
		`ALTER TABLE connector_configs ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE connector_configs FORCE ROW LEVEL SECURITY`,
		`DROP POLICY IF EXISTS connector_configs_org_id_isolation ON connector_configs`,
		`CREATE POLICY connector_configs_org_id_isolation ON connector_configs
			FOR ALL
			USING (org_id = current_setting('app.current_org_id', true))
			WITH CHECK (org_id = current_setting('app.current_org_id', true))`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON connector_configs TO axonflow_app_role`,
		`GRANT USAGE, SELECT ON SEQUENCE connector_configs_id_seq TO axonflow_app_role`,
	} {
		if _, err := masterDB.Exec(stmt); err != nil {
			t.Logf("PR-C2 schema fixup %q: %v (continuing — may already be applied)", truncForLogC2(stmt, 60), err)
		}
	}

	return env
}

// runAsAppRole opens a transaction on db, SET LOCAL ROLEs to
// axonflow_app_role, optionally SETs the app.current_org_id GUC, runs
// fn, then returns either the fn's error or the COMMIT error. Mirrors
// the pr_a runAsAppRoleTx helper but adds an optional GUC arg.
func prC2RunAsAppRole(t *testing.T, db *sql.DB, orgID string, fn func(tx *sql.Tx) error) (err error) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		// Always rollback on error so MaxOpenConns=1 pools don't deadlock.
		_ = tx.Rollback()
	}()
	if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); err != nil {
		return fmt.Errorf("SET LOCAL ROLE: %w", err)
	}
	if orgID != "" {
		if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
			return fmt.Errorf("set_config: %w", err)
		}
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func pgErrCodeC2(err error) string {
	if err == nil {
		return ""
	}
	if pe, ok := err.(*pq.Error); ok {
		return string(pe.Code)
	}
	return ""
}

// TestPRC2_Orchestrator_WithOrgScope_Sites exercises each wrap PR-C2 added.
// Each subtest pair = happy-path (GUC set) + mutation gate (GUC unset).
func TestPRC2_Orchestrator_WithOrgScope_Sites(t *testing.T) {
	env := prC2Setup(t)

	// ============================================================
	// Site #16: connector_configs UPSERT / DELETE
	// (the orchestrator's marketplace handlers go through Storage's
	// SaveConnector + DeleteConnector for the registry side — site
	// #15 — and call deleteConnectorConfig directly on connector_configs
	// for the orchestrator side — site #16. This test exercises the
	// connector_configs UPSERT path.)
	// ============================================================
	t.Run("connector_configs_insert_happy", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		orgID := "orgC2-cc-happy"
		seedOrg(t, env.MasterDSN, orgID)

		err = prC2RunAsAppRole(t, appRoleDB, orgID, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO connector_configs (
					tenant_id, org_id, connector_name, connector_type, display_name,
					description, connection_url, options, credentials, timeout_ms,
					max_retries, enabled, health_status, created_by, updated_by
				) VALUES ($1, $1, 'c-name', 'http', 'd', '', '', '{}'::jsonb, '{}'::jsonb, 30000, 0, true, 'unknown', 'test', 'test')
				ON CONFLICT (tenant_id, connector_name) DO NOTHING
			`, orgID)
			return execErr
		})
		if err != nil {
			t.Fatalf("happy-path insert (app_role + GUC set) failed: %v", err)
		}
	})

	t.Run("connector_configs_insert_mutation_no_guc", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		err = prC2RunAsAppRole(t, appRoleDB, "" /* mutation: GUC NOT set */, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO connector_configs (
					tenant_id, org_id, connector_name, connector_type, display_name,
					description, connection_url, options, credentials, timeout_ms,
					max_retries, enabled, health_status, created_by, updated_by
				) VALUES ('orgC2-cc-mut', 'orgC2-cc-mut', 'c-mut', 'http', 'd', '', '', '{}'::jsonb, '{}'::jsonb, 30000, 0, true, 'unknown', 'test', 'test')
			`)
			return execErr
		})
		if code := pgErrCodeC2(err); code != prC2RLSViolationCode {
			t.Fatalf("mutation: expected 42501 row_level_security failure, got err=%v (code=%q)", err, code)
		}
	})

	// ============================================================
	// Site #17 + #18: dynamic_policies INSERT (now includes org_id col)
	// ============================================================
	t.Run("dynamic_policies_insert_happy", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		orgID := "orgC2-dp-happy"
		err = prC2RunAsAppRole(t, appRoleDB, orgID, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO dynamic_policies (
					policy_id, name, policy_type, conditions, actions, tenant_id, org_id,
					priority, enabled
				) VALUES ($1, 'happy-test', 'security', '[]'::jsonb, '[]'::jsonb, $2, $2, 100, true)
			`, uuid.New().String(), orgID)
			return execErr
		})
		if err != nil {
			t.Fatalf("happy-path dynamic_policies insert failed: %v", err)
		}
	})

	t.Run("dynamic_policies_insert_mutation_omit_org_id_col", func(t *testing.T) {
		// Mutation: GUC IS set, but the INSERT col list OMITS org_id (the
		// pre-PR-C2 bug shape). The row lands with org_id=NULL → WITH CHECK
		// `org_id = get_current_org_id()` evaluates NULL=value → false → 42501.
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		err = prC2RunAsAppRole(t, appRoleDB, "orgC2-dp-mut", func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO dynamic_policies (
					policy_id, name, policy_type, conditions, actions, tenant_id,
					priority, enabled
				) VALUES ($1, 'mut-test', 'security', '[]'::jsonb, '[]'::jsonb, 'orgC2-dp-mut', 100, true)
			`, uuid.New().String())
			return execErr
		})
		if code := pgErrCodeC2(err); code != prC2RLSViolationCode {
			t.Fatalf("mutation (omit org_id col): expected 42501, got err=%v (code=%q)", err, code)
		}
	})

	// ============================================================
	// Site #19: policy_metrics INSERT (now includes org_id col)
	// ============================================================
	t.Run("policy_metrics_insert_happy", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		orgID := "orgC2-pm-happy"
		err = prC2RunAsAppRole(t, appRoleDB, orgID, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO policy_metrics (policy_id, policy_type, hit_count, block_count, date, org_id)
				VALUES ($1, 'dynamic', 1, 0, CURRENT_DATE, $2)
			`, "policy-pm-happy", orgID)
			return execErr
		})
		if err != nil {
			t.Fatalf("happy-path policy_metrics insert failed: %v", err)
		}
	})

	t.Run("policy_metrics_insert_mutation_no_guc", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		err = prC2RunAsAppRole(t, appRoleDB, "" /* GUC unset */, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO policy_metrics (policy_id, policy_type, hit_count, block_count, date, org_id)
				VALUES ('policy-pm-mut', 'dynamic', 1, 0, CURRENT_DATE, 'orgC2-pm-mut')
			`)
			return execErr
		})
		if code := pgErrCodeC2(err); code != prC2RLSViolationCode {
			t.Fatalf("mutation (no GUC): expected 42501, got err=%v (code=%q)", err, code)
		}
	})

	// ============================================================
	// Site #19: orchestrator_audit_logs INSERT (now includes org_id col)
	// ============================================================
	t.Run("orchestrator_audit_logs_insert_happy", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		err = prC2RunAsAppRole(t, appRoleDB, "system", func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO orchestrator_audit_logs (service_id, action, resource, timestamp, org_id)
				VALUES ('orchestrator', 'happy-test', 'details', NOW(), 'system')
			`)
			return execErr
		})
		if err != nil {
			t.Fatalf("happy-path orchestrator_audit_logs insert failed: %v", err)
		}
	})

	t.Run("orchestrator_audit_logs_insert_mutation_no_guc", func(t *testing.T) {
		// Sibling mutation gate per the file docstring's 1:1 pairing rule.
		// Without GUC + with FORCE not active on orchestrator_audit_logs
		// (mig 018 ENABLE-only), the bare-INSERT under app_role hits the
		// WITH CHECK with NULL=value → false → 42501.
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		err = prC2RunAsAppRole(t, appRoleDB, "" /* GUC unset */, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO orchestrator_audit_logs (service_id, action, resource, timestamp, org_id)
				VALUES ('orchestrator', 'mut-test', 'details', NOW(), 'system')
			`)
			return execErr
		})
		if code := pgErrCodeC2(err); code != prC2RLSViolationCode {
			t.Fatalf("mutation (no GUC): expected 42501, got err=%v (code=%q)", err, code)
		}
	})

	// ============================================================
	// Site #20: policy_overrides INSERT — exercises mig 110 normalization
	// (legacy app.tenant_id policy → canonical app.current_org_id)
	// ============================================================
	t.Run("policy_overrides_insert_happy_after_mig110", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		orgID := "orgC2-po-happy"
		err = prC2RunAsAppRole(t, appRoleDB, orgID, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO policy_overrides (
					id, policy_id, policy_type, tenant_id, org_id,
					action_override, override_reason, created_by, created_at, updated_at
				) VALUES ($1, $2, 'static', $3, $3, 'allow', 'mig110-test', 'tester', NOW(), NOW())
			`, uuid.New().String(), uuid.New().String(), orgID)
			return execErr
		})
		if err != nil {
			t.Fatalf("happy-path policy_overrides insert (mig 110 canonical policy): %v", err)
		}
	})

	t.Run("policy_overrides_insert_mutation_no_guc", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		err = prC2RunAsAppRole(t, appRoleDB, "" /* GUC unset */, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO policy_overrides (
					id, policy_id, policy_type, tenant_id, org_id,
					action_override, override_reason, created_by, created_at, updated_at
				) VALUES ($1, $2, 'static', 'orgC2-po-mut', 'orgC2-po-mut',
					'allow', 'mig110-mutation-test', 'tester', NOW(), NOW())
			`, uuid.New().String(), uuid.New().String())
			return execErr
		})
		if code := pgErrCodeC2(err); code != prC2RLSViolationCode {
			t.Fatalf("mutation (no GUC): expected 42501, got err=%v (code=%q)", err, code)
		}
	})

	// ============================================================
	// Site #21: llm_providers + llm_provider_usage (mig 027 ENABLE RLS)
	// ============================================================
	t.Run("llm_providers_insert_happy", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		orgID := "orgC2-llm-happy"
		err = prC2RunAsAppRole(t, appRoleDB, orgID, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO llm_providers (tenant_id, name, type, enabled)
				VALUES (current_setting('app.current_org_id', true), 'p-happy', 'openai', true)
			`)
			return execErr
		})
		if err != nil {
			t.Fatalf("happy-path llm_providers insert failed: %v", err)
		}
	})

	t.Run("llm_providers_insert_mutation_no_guc", func(t *testing.T) {
		// Without GUC, current_setting('app.current_org_id', true) returns
		// NULL (missing_ok=true). RLS policy `tenant_id = current_setting(...)`
		// evaluates NULL=value → NULL → false → 42501. This is good — the
		// wrap's protection is not just "fills in the right value" but also
		// "prevents the empty-tenant landing zone" that earlier Finding B
		// analysis assumed could happen. PostgreSQL rejects outright.
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		err = prC2RunAsAppRole(t, appRoleDB, "" /* GUC unset */, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO llm_providers (tenant_id, name, type, enabled)
				VALUES (current_setting('app.current_org_id', true), 'p-mut-no-guc', 'openai', true)
			`)
			return execErr
		})
		if code := pgErrCodeC2(err); code != prC2RLSViolationCode {
			t.Fatalf("mutation (no GUC): expected 42501 row_level_security failure, got err=%v (code=%q)", err, code)
		}
	})

	// ============================================================
	// Site #22: hitl_approval_queue (mig 025 ENABLE RLS)
	// ============================================================
	t.Run("hitl_approval_queue_insert_happy", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		orgID := "orgC2-hitl-happy"
		err = prC2RunAsAppRole(t, appRoleDB, orgID, func(tx *sql.Tx) error {
			ctx := json.RawMessage(`{}`)
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO hitl_approval_queue (
					request_id, org_id, tenant_id, client_id, user_id,
					original_query, request_type, request_context,
					triggered_policy_id, triggered_policy_name, trigger_reason,
					severity, status, created_at, expires_at
				) VALUES (
					$1, $2, $2, 'client-x', 'user-y',
					'step', 'wcp_step_gate', $3,
					'pol-z', 'pname', 'tr',
					'high', 'pending', NOW(), NOW() + INTERVAL '24 hours'
				)
			`, uuid.New(), orgID, []byte(ctx))
			return execErr
		})
		if err != nil {
			t.Fatalf("happy-path hitl_approval_queue insert failed: %v", err)
		}
	})

	t.Run("hitl_approval_queue_insert_mutation_no_guc", func(t *testing.T) {
		appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
		if err != nil {
			t.Fatalf("open app-role DSN: %v", err)
		}
		defer func() { _ = appRoleDB.Close() }()
		appRoleDB.SetMaxOpenConns(1)

		err = prC2RunAsAppRole(t, appRoleDB, "" /* GUC unset */, func(tx *sql.Tx) error {
			_, execErr := tx.ExecContext(context.Background(), `
				INSERT INTO hitl_approval_queue (
					request_id, org_id, tenant_id, client_id, user_id,
					original_query, request_type, request_context,
					triggered_policy_id, triggered_policy_name, trigger_reason,
					severity, status, created_at, expires_at
				) VALUES (
					$1, 'orgC2-hitl-mut', 'orgC2-hitl-mut', 'cx', 'uy',
					'step', 'wcp_step_gate', '{}'::jsonb,
					'pz', 'pname', 'tr', 'high', 'pending', NOW(), NOW() + INTERVAL '24 hours'
				)
			`, uuid.New())
			return execErr
		})
		if code := pgErrCodeC2(err); code != prC2RLSViolationCode {
			t.Fatalf("mutation (no GUC): expected 42501, got err=%v (code=%q)", err, code)
		}
	})
}

// TestPRC2_PostgresStorage_SaveConnector_WrapsInternally exercises site
// #15 — the registry storage layer wraps its SaveConnector + DeleteConnector
// internally now. Reverting the wrap (removing withOrgScopeTx) produces the
// same 42501 surface as the direct-INSERT mutation above; this test pins
// the integration of the wrap with the FORCE RLS policy on connectors
// (mig 107).
func TestPRC2_PostgresStorage_SaveConnector_WithOrgScope(t *testing.T) {
	env := prC2Setup(t)

	// FORCE RLS on connectors (mig 107). The storage runtime pool must
	// authenticate as axonflow_app_role for the wrap to be discriminating
	// — under master role, BYPASSRLS makes the wrap a no-op. Use the
	// Storage-with-opener constructor + agent.OpenAppRoleConnection +
	// env vars so the runtime pool is app_role while the master pool is
	// only used for schema init then closed (per the v9 design).
	t.Setenv(agent.EnvUseAppRole, "true")
	t.Setenv(agent.EnvAppRoleURL, env.AppRoleDSN)

	t.Run("SaveConnector_via_app_role_pool_happy_path", func(t *testing.T) {
		storage, err := registry.NewPostgreSQLStorageWithOpener(env.MasterDSN, agent.OpenAppRoleConnection)
		if err != nil {
			t.Fatalf("NewPostgreSQLStorageWithOpener: %v", err)
		}
		defer func() { _ = storage.Close() }()

		// Sanity-check the runtime pool authenticates as app_role —
		// otherwise the wrap is a no-op against master/BYPASSRLS.
		var role string
		if err := storage.UnsafeRuntimeDBForTests().QueryRowContext(context.Background(), "SELECT current_user").Scan(&role); err != nil {
			t.Fatalf("runtime pool current_user probe: %v", err)
		}
		if role != "axonflow_app_role" {
			t.Fatalf("runtime pool authenticated as %q, want axonflow_app_role", role)
		}

		ctx := context.Background()
		cfg := &base.ConnectorConfig{
			Name:        "pr-c2-conn-happy",
			Type:        "http",
			TenantID:    "orgC2-conn-happy",
			Options:     map[string]interface{}{},
			Credentials: map[string]string{},
			Timeout:     30 * time.Second,
		}
		if err := storage.SaveConnector(ctx, "pr-c2-conn-happy-id", cfg); err != nil {
			t.Fatalf("SaveConnector under app_role (wrap should set GUC, INSERT under FORCE RLS): %v", err)
		}
	})

	t.Run("DeleteConnector_requires_orgID_param", func(t *testing.T) {
		storage, err := registry.NewPostgreSQLStorageWithOpener(env.MasterDSN, agent.OpenAppRoleConnection)
		if err != nil {
			t.Fatalf("NewPostgreSQLStorageWithOpener: %v", err)
		}
		defer func() { _ = storage.Close() }()

		ctx := context.Background()
		cfg := &base.ConnectorConfig{
			Name:        "pr-c2-conn-del",
			Type:        "http",
			TenantID:    "orgC2-conn-del",
			Options:     map[string]interface{}{},
			Credentials: map[string]string{},
			Timeout:     30 * time.Second,
		}
		if err := storage.SaveConnector(ctx, "pr-c2-conn-del-id", cfg); err != nil {
			t.Fatalf("seed SaveConnector: %v", err)
		}
		if err := storage.DeleteConnector(ctx, "orgC2-conn-del", "pr-c2-conn-del-id"); err != nil {
			t.Fatalf("DeleteConnector with orgID: %v", err)
		}
	})

	t.Run("DeleteConnector_empty_orgID_rejected", func(t *testing.T) {
		storage, err := registry.NewPostgreSQLStorageWithOpener(env.MasterDSN, agent.OpenAppRoleConnection)
		if err != nil {
			t.Fatalf("NewPostgreSQLStorageWithOpener: %v", err)
		}
		defer func() { _ = storage.Close() }()

		// orgID="" must short-circuit before any SQL — the helper rejects.
		err = storage.DeleteConnector(context.Background(), "", "doesnt-matter")
		if err == nil {
			t.Fatal("DeleteConnector with empty orgID should error (cross-org work belongs on admin role)")
		}
	})
}

// seedOrg writes a minimal `organizations` row using the master DSN.
// connector_configs has no FK to organizations, but several test paths
// expect at least one row to exist (e.g. mig 110's policy_overrides
// backfill subquery joins organizations.id).
func seedOrg(t *testing.T, masterDSN, orgID string) {
	t.Helper()
	db, err := sql.Open("postgres", masterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`
		INSERT INTO organizations (id, org_id, name, tier, max_nodes, license_key, status)
		VALUES ($1, $1, $2, 'enterprise', 1000, 'lk-test', 'ACTIVE')
		ON CONFLICT (id) DO NOTHING
	`, orgID, "PR-C2 test org "+orgID); err != nil {
		t.Logf("seedOrg %q: %v (continuing — duplicate or schema variant)", orgID, err)
	}
}

func truncForLogC2(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
