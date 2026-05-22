// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package agent

// v9 Phase 8 #2384 PR-C1 DoD closure — real-PG integration coverage for the
// site clusters that PR-C1 wrapped but pr_c1_with_org_scope_integration_test.go
// did not cover. R3 round 1 MEDIUM-3 flagged this gap explicitly:
//
//   - static_policies (Create/Update/Delete/ToggleEnabled + recordVersion)
//   - policy_overrides (Create + duplicate-detection inside-the-wrap regression)
//   - execution_history (7 methods × WithOrgAndTenantScope dual-key wrap)
//   - hitl_approval_history (AddHistory)
//   - usage_events (RecordAPICall + RecordLLMRequest)
//   - billing webhook (agent_audit_logs INSERT via licenseeTenantID)
//
// Each cluster has:
//   (a) a "wrap-succeeds-under-SET-LOCAL-ROLE-axonflow_app_role" subtest
//       that proves the row lands.
//   (b) a "bare-INSERT-under-app_role-yields-sqlstate-42501" mutation gate
//       that proves the wrap is the load-bearing keyword (not some other
//       side-effect like the testcontainer's superuser BYPASSRLS).
//
// All tests are gated on TEST_PG_INTEGRATION=1 and skip silently otherwise.
// Reuses prc1TestSetup, asAppRole, pinAppRoleAndWrap, pinAppRoleAndDualWrap,
// isInsufficientPrivilege from pr_c1_with_org_scope_integration_test.go.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const prc1DodTestOrgID = "axonflow-test-c1-dod-org"
const prc1DodTestTenantID = "axonflow-test-c1-dod-tenant"

// pinAppRoleAndDualWrap composes the test-side SET LOCAL ROLE axonflow_app_role
// with the production WithOrgAndTenantScope wrap (sets app.current_org_id,
// app.current_tenant_id, app.tenant_id all in one BEGIN). Mirrors the
// shape of pinAppRoleAndWrap from the sibling _integration_test.go for
// the dual-key case (used by execution_history per mig 042).
func pinAppRoleAndDualWrap(ctx context.Context, db *sql.DB, orgID, tenantID string, fn func(*sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); err != nil {
		return fmt.Errorf("SET LOCAL ROLE: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
		return fmt.Errorf("set_config org: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set_config tenant: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set_config tenant_alias: %w", err)
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// asAppRoleDual mirrors asAppRole but for the dual-key surfaces — opens a
// txn, flips role to app_role, runs fn WITHOUT setting any GUC. Used by the
// mutation gates on execution_history to prove the GUC pins are the
// load-bearing keyword.
func asAppRoleDual(t *testing.T, db *sql.DB, fn func(*sql.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "SET LOCAL ROLE axonflow_app_role"); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("SET LOCAL ROLE: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// isInsufficientPrivilegeDod re-checks sqlstate 42501 without depending on
// the sibling file's isInsufficientPrivilege (helpers are package-scope so
// they'd collide).
func isInsufficientPrivilegeDod(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if pqErrAs(err, &pqErr) {
		return pqErr.Code == "42501"
	}
	return false
}

// pqErrAs is a local errors.As shim — keeps imports tight in this file.
func pqErrAs(err error, target **pq.Error) bool {
	for err != nil {
		if pe, ok := err.(*pq.Error); ok {
			*target = pe
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ---------------------------------------------------------------------------
// static_policies cluster (#25): Create/Update/Delete/ToggleEnabled + recordVersion
// ---------------------------------------------------------------------------

// TestPRC1Dod_WithOrgScope_StaticPolicies exercises the static_policies
// table wraps. recordVersion's INSERT into static_policy_versions runs in
// its own WithOrgScope (post mig 110 normalization to app.current_org_id),
// covered by the dedicated sub-test below.
func TestPRC1Dod_WithOrgScope_StaticPolicies(t *testing.T) {
	db, cleanup := prC1TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("INSERT wrap succeeds", func(t *testing.T) {
		policyID := uuid.New().String()
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO static_policies (
					id, policy_id, name, category, pattern, severity,
					description, action, tier, priority, enabled,
					organization_id, tenant_id, client_id, org_id,
					tags, metadata, version,
					phase, action_request, action_response,
					created_at, updated_at, created_by, updated_by
				) VALUES (
					$1, $2, $3, $4, $5, $6,
					$7, $8, $9, $10, $11,
					$12, $13, $13, $14,
					$15::jsonb, $16::jsonb, $17,
					$18, $19, $20,
					$21, $22, $23, $24
				)
			`,
				policyID, "test_policy_1", "Test Policy", "security-sqli", `\btest\b`, "high",
				"test", "block", "tenant", 50, true,
				nil, prc1DodTestTenantID, prc1DodTestOrgID,
				`[]`, `{}`, 1,
				"both", "block", "block",
				time.Now(), time.Now(), "test", "test")
			return exErr
		})
		if err != nil {
			t.Fatalf("wrapped INSERT failed: %v", err)
		}
	})

	t.Run("mutation gate: bare INSERT under app_role yields 42501", func(t *testing.T) {
		err := asAppRole(t, db, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO static_policies (
					id, policy_id, name, category, pattern, severity,
					description, action, tier, priority, enabled,
					organization_id, tenant_id, client_id, org_id,
					tags, metadata, version,
					phase, action_request, action_response,
					created_at, updated_at, created_by, updated_by
				) VALUES (
					$1, $2, $3, $4, $5, $6,
					$7, $8, $9, $10, $11,
					$12, $13, $13, $14,
					$15::jsonb, $16::jsonb, $17,
					$18, $19, $20,
					$21, $22, $23, $24
				)
			`,
				uuid.New().String(), "mut_policy_1", "Mut", "security-sqli", `\bmut\b`, "high",
				"mut", "block", "tenant", 50, true,
				nil, prc1DodTestTenantID, prc1DodTestOrgID,
				`[]`, `{}`, 1,
				"both", "block", "block",
				time.Now(), time.Now(), "test", "test")
			return exErr
		})
		if err == nil {
			t.Fatal("expected RLS denial under app_role, got nil")
		}
		if !isInsufficientPrivilegeDod(err) {
			t.Errorf("expected sqlstate 42501, got %v", err)
		}
	})

	t.Run("UPDATE wrap succeeds (proxy for Update/Delete/ToggleEnabled)", func(t *testing.T) {
		// Seed a row first (wrapped INSERT)
		policyID := uuid.New().String()
		if err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO static_policies (id, policy_id, name, category, pattern, severity, description, action, tier, priority, enabled, organization_id, tenant_id, client_id, org_id, tags, metadata, version, phase, action_request, action_response, created_at, updated_at, created_by, updated_by)
				VALUES ($1, $2, 'U', 'security-sqli', '\bu\b', 'high', 'u', 'block', 'tenant', 50, true, NULL, $3, $3, $4, '[]'::jsonb, '{}'::jsonb, 1, 'both', 'block', 'block', NOW(), NOW(), 't', 't')
			`, policyID, "upd_policy_"+policyID[:8], prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		}); err != nil {
			t.Fatalf("seed INSERT failed: %v", err)
		}

		// Now wrap an UPDATE — proves the Update/Delete/ToggleEnabled wrap shape works.
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `UPDATE static_policies SET enabled = false, version = version + 1, updated_at = NOW() WHERE id = $1`, policyID)
			return exErr
		})
		if err != nil {
			t.Fatalf("wrapped UPDATE failed: %v", err)
		}
	})

	t.Run("recordVersion wrap succeeds (static_policy_versions)", func(t *testing.T) {
		// Seed a parent static_policies row first
		policyID := uuid.New().String()
		if err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO static_policies (id, policy_id, name, category, pattern, severity, description, action, tier, priority, enabled, organization_id, tenant_id, client_id, org_id, tags, metadata, version, phase, action_request, action_response, created_at, updated_at, created_by, updated_by)
				VALUES ($1, 'ver_policy', 'V', 'security-sqli', '\bv\b', 'high', 'v', 'block', 'tenant', 50, true, NULL, $2, $2, $3, '[]'::jsonb, '{}'::jsonb, 1, 'both', 'block', 'block', NOW(), NOW(), 't', 't')
			`, policyID, prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		}); err != nil {
			t.Fatalf("seed INSERT (parent) failed: %v", err)
		}

		// Wrap the recordVersion INSERT — mig 110 made this surface key on app.current_org_id.
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO static_policy_versions (id, policy_id, version, snapshot, change_type, change_summary, changed_by, changed_at)
				VALUES ($1, $2, 1, '{}'::jsonb, 'create', 'first', 't', NOW())
			`, uuid.New().String(), policyID)
			return exErr
		})
		if err != nil {
			t.Fatalf("wrapped recordVersion INSERT failed: %v", err)
		}
	})

	t.Run("mutation gate: bare static_policy_versions INSERT yields 42501", func(t *testing.T) {
		err := asAppRole(t, db, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO static_policy_versions (id, policy_id, version, snapshot, change_type, change_summary, changed_by, changed_at)
				VALUES ($1, $2, 1, '{}'::jsonb, 'create', 'mutgate', 't', NOW())
			`, uuid.New().String(), uuid.New().String())
			return exErr
		})
		if err == nil {
			t.Fatal("expected RLS denial under app_role, got nil")
		}
		if !isInsufficientPrivilegeDod(err) {
			t.Errorf("expected sqlstate 42501, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// policy_overrides cluster (#26): Create / Delete / DeleteByPolicyID +
// R3 R2 HIGH-2 fold (overrideExistsTx inside the wrap)
// ---------------------------------------------------------------------------

func TestPRC1Dod_WithOrgScope_PolicyOverrides(t *testing.T) {
	db, cleanup := prC1TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("INSERT wrap succeeds", func(t *testing.T) {
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO policy_overrides (
					id, policy_id, policy_type,
					organization_id, tenant_id, org_id,
					action_override, enabled_override,
					override_reason, expires_at,
					created_by, created_at, updated_by, updated_at
				) VALUES (
					$1, $2, 'static',
					NULL, $3, $4,
					'warn', NULL,
					'test', NULL,
					'test', NOW(), 'test', NOW()
				)
			`, uuid.New().String(), uuid.New().String(), prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		})
		if err != nil {
			t.Fatalf("wrapped INSERT failed: %v", err)
		}
	})

	t.Run("mutation gate: bare INSERT under app_role yields 42501", func(t *testing.T) {
		err := asAppRole(t, db, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO policy_overrides (id, policy_id, policy_type, organization_id, tenant_id, org_id, action_override, enabled_override, override_reason, expires_at, created_by, created_at, updated_by, updated_at)
				VALUES ($1, $2, 'static', NULL, $3, $4, 'warn', NULL, 'mut', NULL, 'test', NOW(), 'test', NOW())
			`, uuid.New().String(), uuid.New().String(), prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		})
		if err == nil {
			t.Fatal("expected RLS denial, got nil")
		}
		if !isInsufficientPrivilegeDod(err) {
			t.Errorf("expected sqlstate 42501, got %v", err)
		}
	})

	t.Run("R3 R2 HIGH-2: existence-check inside wrap detects duplicates", func(t *testing.T) {
		// Insert a row first
		policyID := uuid.New().String()
		if err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO policy_overrides (id, policy_id, policy_type, organization_id, tenant_id, org_id, action_override, enabled_override, override_reason, expires_at, created_by, created_at, updated_by, updated_at)
				VALUES ($1, $2, 'static', NULL, $3, $4, 'warn', NULL, 'first', NULL, 'test', NOW(), 'test', NOW())
			`, uuid.New().String(), policyID, prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		}); err != nil {
			t.Fatalf("seed INSERT failed: %v", err)
		}

		// Now do a SELECT COUNT inside the same wrap — it MUST see the row.
		// This is the regression test for R3 round-2 HIGH-2: without the
		// wrap, USING masks the row from view and count returns 0.
		var count int
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_overrides WHERE policy_id = $1 AND tenant_id = $2`, policyID, prc1DodTestTenantID).Scan(&count)
		})
		if err != nil {
			t.Fatalf("wrapped COUNT query failed: %v", err)
		}
		if count != 1 {
			t.Errorf("existence-check-inside-wrap should see 1 row, got %d (HIGH-2 regression — USING is masking the row)", count)
		}
	})

	t.Run("R3 R2 HIGH-2 mutation gate: bare SELECT under app_role masks the row", func(t *testing.T) {
		// Confirm the inverse: a SELECT OUTSIDE the wrap (no SET LOCAL
		// org_id) returns count=0 even though the row exists — proving
		// the wrap is what makes the existence check work. This is the
		// failure mode that defeated duplicate-detection pre-fold.
		var count int
		err := asAppRole(t, db, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_overrides`).Scan(&count)
		})
		if err != nil {
			t.Fatalf("bare COUNT query failed: %v", err)
		}
		if count != 0 {
			t.Errorf("bare SELECT under app_role with no app.current_org_id set MUST mask all rows (USING returns NULL → predicate fails); got count=%d", count)
		}
	})
}

// ---------------------------------------------------------------------------
// execution_history cluster (#30): 7 methods × WithOrgAndTenantScope dual-key wrap
// ---------------------------------------------------------------------------

func TestPRC1Dod_WithOrgAndTenantScope_ExecutionHistory(t *testing.T) {
	db, cleanup := prC1TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("Create wrap succeeds (dual-key)", func(t *testing.T) {
		execID := uuid.New().String()
		err := pinAppRoleAndDualWrap(ctx, db, prc1DodTestOrgID, prc1DodTestTenantID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO execution_history (
					id, execution_type, external_id, name, source,
					tenant_id, org_id, user_id, client_id,
					status, current_step_index, total_steps,
					started_at, estimated_cost_usd, actual_cost_usd,
					steps, metadata, created_at, updated_at
				) VALUES (
					$1, $2, $1, 'test', '',
					$3, $4, NULL, NULL,
					'pending', 0, 1,
					NOW(), NULL, NULL,
					'[]'::jsonb, '{}'::jsonb, NOW(), NOW()
				)
			`, execID, "map_plan", prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		})
		if err != nil {
			t.Fatalf("Create wrap failed: %v", err)
		}
	})

	t.Run("UPDATE wrap succeeds (proxy for Update/UpdateStatus/UpdateSteps/UpdateCost/ExpireExecution)", func(t *testing.T) {
		// Seed first
		execID := uuid.New().String()
		if err := pinAppRoleAndDualWrap(ctx, db, prc1DodTestOrgID, prc1DodTestTenantID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO execution_history (id, execution_type, external_id, name, source, tenant_id, org_id, user_id, client_id, status, current_step_index, total_steps, started_at, estimated_cost_usd, actual_cost_usd, steps, metadata, created_at, updated_at)
				VALUES ($1, 'map_plan', $1, 't', '', $2, $3, NULL, NULL, 'running', 0, 1, NOW(), NULL, NULL, '[]'::jsonb, '{}'::jsonb, NOW(), NOW())
			`, execID, prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		}); err != nil {
			t.Fatalf("seed INSERT failed: %v", err)
		}

		err := pinAppRoleAndDualWrap(ctx, db, prc1DodTestOrgID, prc1DodTestTenantID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `UPDATE execution_history SET status = 'completed', updated_at = NOW() WHERE id = $1`, execID)
			return exErr
		})
		if err != nil {
			t.Fatalf("UPDATE wrap failed: %v", err)
		}
	})

	t.Run("DELETE wrap succeeds", func(t *testing.T) {
		execID := uuid.New().String()
		if err := pinAppRoleAndDualWrap(ctx, db, prc1DodTestOrgID, prc1DodTestTenantID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO execution_history (id, execution_type, external_id, name, source, tenant_id, org_id, user_id, client_id, status, current_step_index, total_steps, started_at, estimated_cost_usd, actual_cost_usd, steps, metadata, created_at, updated_at)
				VALUES ($1, 'map_plan', $1, 'd', '', $2, $3, NULL, NULL, 'completed', 1, 1, NOW(), NULL, NULL, '[]'::jsonb, '{}'::jsonb, NOW(), NOW())
			`, execID, prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		}); err != nil {
			t.Fatalf("seed INSERT failed: %v", err)
		}

		err := pinAppRoleAndDualWrap(ctx, db, prc1DodTestOrgID, prc1DodTestTenantID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `DELETE FROM execution_history WHERE id = $1`, execID)
			return exErr
		})
		if err != nil {
			t.Fatalf("DELETE wrap failed: %v", err)
		}
	})

	t.Run("mutation gate: bare INSERT under app_role with NO GUC set yields 42501", func(t *testing.T) {
		err := asAppRoleDual(t, db, func(tx *sql.Tx) error {
			mutID := uuid.New().String()
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO execution_history (id, execution_type, external_id, name, source, tenant_id, org_id, user_id, client_id, status, current_step_index, total_steps, started_at, estimated_cost_usd, actual_cost_usd, steps, metadata, created_at, updated_at)
				VALUES ($3, 'map_plan', $3, 'mut', '', $1, $2, NULL, NULL, 'pending', 0, 1, NOW(), NULL, NULL, '[]'::jsonb, '{}'::jsonb, NOW(), NOW())
			`, prc1DodTestTenantID, prc1DodTestOrgID, mutID)
			return exErr
		})
		if err == nil {
			t.Fatal("expected RLS denial, got nil")
		}
		if !isInsufficientPrivilegeDod(err) {
			t.Errorf("expected sqlstate 42501, got %v", err)
		}
	})

	t.Run("PurgeOldest (DoD D-4 fold) wrap succeeds", func(t *testing.T) {
		execID := "purge-" + uuid.New().String()
		if err := pinAppRoleAndDualWrap(ctx, db, prc1DodTestOrgID, prc1DodTestTenantID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO execution_history (id, execution_type, external_id, name, source, tenant_id, org_id, user_id, client_id, status, current_step_index, total_steps, started_at, estimated_cost_usd, actual_cost_usd, steps, metadata, created_at, updated_at)
				VALUES ($1, 'map_plan', $1, 'p', '', $2, $3, NULL, NULL, 'completed', 1, 1, NOW(), NULL, NULL, '[]'::jsonb, '{}'::jsonb, NOW(), NOW())
			`, execID, prc1DodTestTenantID, prc1DodTestOrgID)
			return exErr
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		// PurgeOldest's DELETE inside the wrap (mirrors the production wrap shape).
		err := pinAppRoleAndDualWrap(ctx, db, prc1DodTestOrgID, prc1DodTestTenantID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				DELETE FROM execution_history
				WHERE tenant_id = $1
				AND id NOT IN (SELECT id FROM execution_history WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2)
			`, prc1DodTestTenantID, 0)
			return exErr
		})
		if err != nil {
			t.Fatalf("PurgeOldest wrap failed: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// hitl_approval_history cluster (#23 AddHistory)
// ---------------------------------------------------------------------------

func TestPRC1Dod_WithOrgScope_HitlApprovalHistory(t *testing.T) {
	db, cleanup := prC1TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("AddHistory wrap succeeds", func(t *testing.T) {
		// Need a parent request_id in hitl_approval_queue (FK target)
		reqID := uuid.New()
		if err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO hitl_approval_queue (
					request_id, org_id, tenant_id, client_id, user_id,
					original_query, request_type, request_context,
					triggered_policy_id, triggered_policy_name, trigger_reason, severity,
					eu_ai_act_article, compliance_framework, risk_classification,
					status, expires_at
				) VALUES (
					$1, $2, $3, 'c', 'u', 'SELECT 1', 'sql', '{}'::jsonb,
					'p', 'pn', 'pr', 'high',
					NULL, NULL, NULL,
					'pending', NOW() + INTERVAL '1 day'
				) RETURNING id, created_at, updated_at
			`, reqID, prc1DodTestOrgID, prc1DodTestTenantID)
			return exErr
		}); err != nil {
			t.Fatalf("seed INSERT (parent) failed: %v", err)
		}

		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			var id int64
			var createdAt time.Time
			return tx.QueryRowContext(ctx, `
				INSERT INTO hitl_approval_history (
					request_id, org_id, tenant_id, action,
					actor_id, actor_email, actor_role, actor_ip,
					comment, justification,
					previous_status, new_status
				) VALUES (
					$1, $2, $3, 'approved',
					'r1', 'r@e.com', 'admin', '1.2.3.4',
					'ok', NULL,
					'pending', 'approved'
				) RETURNING id, created_at
			`, reqID, prc1DodTestOrgID, prc1DodTestTenantID).Scan(&id, &createdAt)
		})
		if err != nil {
			t.Fatalf("AddHistory wrap failed: %v", err)
		}
	})

	t.Run("mutation gate: bare AddHistory INSERT yields 42501", func(t *testing.T) {
		err := asAppRole(t, db, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO hitl_approval_history (request_id, org_id, tenant_id, action, actor_id, actor_email, actor_role, actor_ip, comment, justification, previous_status, new_status)
				VALUES ($1, $2, $3, 'a', 'r1', 'r@e.com', 'admin', '1.2.3.4', 'mut', NULL, 'pending', 'approved')
			`, uuid.New(), prc1DodTestOrgID, prc1DodTestTenantID)
			return exErr
		})
		if err == nil {
			t.Fatal("expected RLS denial, got nil")
		}
		if !isInsufficientPrivilegeDod(err) {
			t.Errorf("expected sqlstate 42501, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// usage_events cluster (#28): RecordAPICall + RecordLLMRequest
// ---------------------------------------------------------------------------

func TestPRC1Dod_WithOrgScope_UsageEvents(t *testing.T) {
	db, cleanup := prC1TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("RecordAPICall wrap succeeds", func(t *testing.T) {
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO usage_events (
					org_id, client_id, event_type, instance_id, instance_type,
					http_method, http_path, http_status_code, latency_ms
				) VALUES ($1, $2, 'api_call', $3, $4, $5, $6, $7, $8)
			`, prc1DodTestOrgID, "client-1", "instance-1", "agent", "POST", "/api/test", 200, 15)
			return exErr
		})
		if err != nil {
			t.Fatalf("RecordAPICall wrap failed: %v", err)
		}
	})

	t.Run("RecordLLMRequest wrap succeeds", func(t *testing.T) {
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO usage_events (
					org_id, client_id, event_type, instance_id, instance_type,
					llm_provider, llm_model, prompt_tokens, completion_tokens,
					total_tokens, estimated_cost_cents, latency_ms, http_status_code
				) VALUES ($1, $2, 'llm_request', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			`, prc1DodTestOrgID, "client-1", "instance-1", "orchestrator",
				"openai", "gpt-4", 100, 200, 300, 50, 1500, 200)
			return exErr
		})
		if err != nil {
			t.Fatalf("RecordLLMRequest wrap failed: %v", err)
		}
	})

	t.Run("mutation gate: bare usage_events INSERT yields 42501", func(t *testing.T) {
		err := asAppRole(t, db, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO usage_events (org_id, client_id, event_type, instance_id, instance_type, http_method, http_path, http_status_code, latency_ms)
				VALUES ($1, 'c', 'api_call', 'i', 'agent', 'GET', '/m', 200, 5)
			`, prc1DodTestOrgID)
			return exErr
		})
		if err == nil {
			t.Fatal("expected RLS denial, got nil")
		}
		if !isInsufficientPrivilegeDod(err) {
			t.Errorf("expected sqlstate 42501, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// billing webhook agent_audit_logs (#24 — both community + EE)
// ---------------------------------------------------------------------------

func TestPRC1Dod_WithOrgScope_BillingWebhookAgentAuditLogs(t *testing.T) {
	db, cleanup := prC1TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("billing audit INSERT wrap succeeds", func(t *testing.T) {
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO agent_audit_logs (client_id, action, resource, timestamp, org_id)
				VALUES ($1, $2, $3, NOW(), $4)
			`, "cs_session_1", "license_revoked_full_refund", "charge=ch_1 amount=999", prc1DodTestOrgID)
			return exErr
		})
		if err != nil {
			t.Fatalf("wrap failed: %v", err)
		}
	})

	t.Run("mutation gate: bare INSERT yields 42501", func(t *testing.T) {
		err := asAppRole(t, db, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `
				INSERT INTO agent_audit_logs (client_id, action, resource, timestamp, org_id)
				VALUES ($1, $2, $3, NOW(), $4)
			`, "cs_session_mut", "license_revoked_full_refund", "charge=ch_mut amount=1", prc1DodTestOrgID)
			return exErr
		})
		if err == nil {
			t.Fatal("expected RLS denial, got nil")
		}
		if !isInsufficientPrivilegeDod(err) {
			t.Errorf("expected sqlstate 42501, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// agent_heartbeats cluster (D-1: EE removeHeartbeat wrap fold)
// ---------------------------------------------------------------------------

// TestPRC1Dod_WithOrgScope_AgentHeartbeats_RemoveHeartbeat exercises the D-1
// fold: ee/platform/agent/node_enforcement/heartbeat.go::removeHeartbeat
// previously dropped the SET LOCAL wrap that the community variant has.
// Asserts the wrap is now load-bearing for the DELETE under app_role.
//
// NOTE on #2400 (heartbeat wrap structurally present but RLS still fires):
// the issue tracked there is on the INSERT/UPSERT path (sendHeartbeat),
// not the DELETE (removeHeartbeat). The DELETE works under the wrap
// because the USING predicate sees the row when app.current_org_id
// matches. sendHeartbeat integration coverage is deferred until #2400
// lands a fix — PR-C1 DoD ships removeHeartbeat coverage only.
func TestPRC1Dod_WithOrgScope_AgentHeartbeats_RemoveHeartbeat(t *testing.T) {
	db, cleanup := prC1TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("DELETE wrap succeeds (post-seed via master)", func(t *testing.T) {
		instanceID := "test-instance-" + uuid.New().String()
		// Seed a heartbeat row via the master-role connection (bypasses RLS).
		if _, err := db.ExecContext(ctx, `
			INSERT INTO agent_heartbeats (
				instance_id, instance_type, host_name, ip_address, port,
				version, license_key_hash, org_id, region, last_heartbeat,
				heartbeat_count, host_info
			) VALUES ($1, 'agent', 'h1', '127.0.0.1', 8080, '8.0.0', 'hash', $2, 'us-east-1', NOW(), 1, '{}'::jsonb)
		`, instanceID, prc1DodTestOrgID); err != nil {
			t.Fatalf("seed agent_heartbeats: %v", err)
		}

		// Wrapped DELETE under app_role must succeed.
		err := pinAppRoleAndWrap(ctx, db, prc1DodTestOrgID, func(tx *sql.Tx) error {
			_, exErr := tx.ExecContext(ctx, `DELETE FROM agent_heartbeats WHERE instance_id = $1`, instanceID)
			return exErr
		})
		if err != nil {
			t.Fatalf("wrapped DELETE failed: %v", err)
		}
	})

	t.Run("mutation gate: bare DELETE under app_role affects zero rows (USING masks)", func(t *testing.T) {
		// agent_heartbeats is FORCE-RLS (mig 107). Bare DELETE under
		// app_role with no app.current_org_id set hits a USING that
		// returns NULL → predicate fails → zero rows affected. We assert
		// the wrap is what makes the DELETE actually see and remove the
		// row (a sister failure mode to the 42501-on-INSERT pattern other
		// mutation gates assert; the DELETE path silently zero-rows
		// rather than erroring).
		instanceID := "mut-instance-" + uuid.New().String()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO agent_heartbeats (
				instance_id, instance_type, host_name, ip_address, port,
				version, license_key_hash, org_id, region, last_heartbeat,
				heartbeat_count, host_info
			) VALUES ($1, 'agent', 'h2', '127.0.0.1', 8080, '8.0.0', 'hash', $2, 'us-east-1', NOW(), 1, '{}'::jsonb)
		`, instanceID, prc1DodTestOrgID); err != nil {
			t.Fatalf("seed agent_heartbeats: %v", err)
		}

		var rowsAffected int64
		_ = asAppRole(t, db, func(tx *sql.Tx) error {
			result, exErr := tx.ExecContext(ctx, `DELETE FROM agent_heartbeats WHERE instance_id = $1`, instanceID)
			if exErr != nil {
				return exErr
			}
			rowsAffected, _ = result.RowsAffected()
			return nil
		})
		if rowsAffected != 0 {
			t.Errorf("bare DELETE under app_role with no app.current_org_id set MUST affect 0 rows (USING masks); got %d", rowsAffected)
		}
	})
}

// Defensive: a json.Marshal reference so the import survives even if I refactor.
var _ = json.Marshal
