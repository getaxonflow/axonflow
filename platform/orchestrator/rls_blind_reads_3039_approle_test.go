// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Regression tests for #3039 — RLS-blind reads on the app-role request path.
//
// dynamic_policies (mig 018) and execution_history (mig 042) are RLS-enabled;
// the writers were wrapped across v9 Phase 8 but a set of readers never were.
// Under axonflow_app_role (NOBYPASSRLS) those readers matched 0 rows:
//   - PolicyRepository.GetByID/List → create succeeded, read-back 404'd
//   - DatabaseDynamicPolicyEngine.refreshPolicies → the gate-eval cache
//     loaded EMPTY, so tenant dynamic policies were silently NOT ENFORCED
//     (observed on production: an over-threshold wire that must
//     require_approval sailed through as allow)
//   - execution.PostgresRepository.Get/List → executions API empty / 404
//
// Each test carries a vacuity control proving the fixture actually enforces
// RLS against the app-role connection (a superuser-shaped fixture passes
// even with the fix reverted — feedback_realpg_tests_as_superuser_hide_rls_defects).
//
// Gating: TEST_PG_INTEGRATION=1 + docker (see approletest.SkipUnlessEnabled).

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/shared/execution"
)

type approleFixture struct {
	masterDB  *sql.DB
	appRoleDB *sql.DB
	adminDB   *sql.DB
}

func setup3039Fixture(t *testing.T) *approleFixture {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	open := func(dsn, label string) *sql.DB {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open %s DSN: %v", label, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}

	f := &approleFixture{
		masterDB:  open(env.MasterDSN, "master"),
		appRoleDB: open(env.AppRoleDSN, "app_role"),
		adminDB:   open(env.AdminDSN, "platform_admin"),
	}
	// Single connection so bare (no-GUC) probes can't ride a leaked SET LOCAL.
	f.appRoleDB.SetMaxOpenConns(1)
	approletest.AssertCurrentUser(t, f.appRoleDB, "axonflow_app_role")

	// Mig 153 (org_id='global' backfill on the mig-031 system policy seeds)
	// is outside approletest's core 001..111 range — apply it here so the
	// 'global'-scope reads see the REAL production global rows, not a
	// synthetic probe. (Pre-153 those rows have org_id NULL and are
	// invisible to every scoped read — R3 finding on the first round.)
	migSQL, err := os.ReadFile("../../migrations/core/153_backfill_global_policy_org_id.sql")
	if err != nil {
		t.Fatalf("read migration 153: %v", err)
	}
	if _, err := f.masterDB.Exec(string(migSQL)); err != nil {
		t.Fatalf("apply migration 153: %v", err)
	}

	// Mig 159 (dynamic_policies.segment_id, ADR-060 #2989 P3b) is likewise
	// outside approletest's core 001..111 range — apply it here so
	// refreshPolicies' SELECT of segment_id resolves against the real column
	// rather than failing with "column \"segment_id\" does not exist". The
	// migration is table-guarded and self-contained, so it applies cleanly on
	// top of the 111+153 fixture schema.
	segMigSQL, err := os.ReadFile("../../migrations/core/159_dynamic_policies_segment_id.sql")
	if err != nil {
		t.Fatalf("read migration 159: %v", err)
	}
	if _, err := f.masterDB.Exec(string(segMigSQL)); err != nil {
		t.Fatalf("apply migration 159: %v", err)
	}
	return f
}

func (f *approleFixture) seedOrg(t *testing.T, org string) {
	t.Helper()
	if _, err := f.masterDB.Exec(`
		INSERT INTO organizations (org_id, name, license_key, tier)
		VALUES ($1, $2, $3, $4) ON CONFLICT (org_id) DO NOTHING
	`, org, org+"-name", "test-license-"+org, "ENTERPRISE"); err != nil {
		t.Fatalf("seed organizations row %s: %v", org, err)
	}
}

// bareCount proves the fixture enforces RLS: the count the OLD unwrapped
// reads performed must see 0 rows on the app-role connection.
func (f *approleFixture) bareCount(t *testing.T, table, where string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := f.appRoleDB.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+where, args...).Scan(&n); err != nil {
		t.Fatalf("bare app_role count on %s: %v", table, err)
	}
	return n
}

func TestPolicyRepositoryReadsUnderAppRole(t *testing.T) {
	f := setup3039Fixture(t)
	const org = "rls3039-policy-org"
	f.seedOrg(t, org)
	f.seedOrg(t, GlobalTenantSentinel)

	repo := NewPolicyRepository(f.appRoleDB)
	repo.SetCrossOrgDB(f.adminDB)
	ctx := context.Background()

	policy := &PolicyResource{
		Name:        "RLS Read-Back Probe",
		Description: "policy created and read back under app_role",
		Type:        "context_aware",
		Category:    "dynamic-compliance",
		Conditions:  []PolicyCondition{{Field: "step_input.amount_eur", Operator: "greater_than", Value: float64(5000)}},
		Actions:     []PolicyAction{{Type: "require_approval"}},
		Priority:    900,
		Enabled:     true,
		TenantID:    org,
	}
	if err := repo.Create(ctx, policy); err != nil {
		t.Fatalf("Create under app_role: %v", err)
	}

	// Vacuity control — the old bare read saw nothing.
	if n := f.bareCount(t, "dynamic_policies", "tenant_id = $1", org); n != 0 {
		t.Fatalf("fixture not faithful: bare app_role read sees %d dynamic_policies rows (RLS not enforced)", n)
	}

	t.Run("GetByID_reads_back_created_policy", func(t *testing.T) {
		got, err := repo.GetByID(ctx, org, policy.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got == nil {
			t.Fatalf("GetByID returned nil for a policy created moments ago — RLS-blind read regressed (#3039)")
		}
		if got.Name != policy.Name {
			t.Fatalf("GetByID name = %q, want %q", got.Name, policy.Name)
		}
	})

	t.Run("List_includes_tenant_and_global_rows", func(t *testing.T) {
		policies, total, err := repo.List(ctx, org, ListPoliciesParams{Page: 1, PageSize: 100})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var haveTenant, haveMig031Global bool
		for _, p := range policies {
			if p.ID == policy.ID {
				haveTenant = true
			}
			// sys_dyn_high_risk_block is a REAL mig-031 system seed
			// (tenant_id='global', org_id NULL until mig 153) — asserting
			// it, not a synthetic probe, proves the migration + the
			// global-scope pass together restore the production rows.
			if p.ID == "sys_dyn_high_risk_block" {
				haveMig031Global = true
			}
		}
		if !haveTenant {
			t.Fatalf("List missing the tenant policy (total=%d) — RLS-blind read regressed (#3039)", total)
		}
		if !haveMig031Global {
			t.Fatalf("List missing the mig-031 'global' system policy sys_dyn_high_risk_block (total=%d) — mig 153 backfill or global-scope merge regressed", total)
		}
		if total != len(policies) {
			t.Fatalf("List total=%d != len(policies)=%d for an unpaginated page", total, len(policies))
		}
	})

	t.Run("CountByTenant_counts_tenant_rows", func(t *testing.T) {
		n, err := repo.CountByTenant(ctx, org)
		if err != nil {
			t.Fatalf("CountByTenant: %v", err)
		}
		if n != 1 {
			t.Fatalf("CountByTenant = %d, want 1 — tier-limit undercount (#3039)", n)
		}
	})

	t.Run("CountOrgPolicies_uses_cross_org_pool", func(t *testing.T) {
		if _, err := f.masterDB.Exec(`
			INSERT INTO dynamic_policies (
				policy_id, name, description, policy_type, tier, conditions, actions,
				tenant_id, client_id, org_id, priority, enabled, version,
				created_by, updated_by, created_at, updated_at
			) VALUES ('rls3039_orgtier_probe', 'Org Tier Probe', 'org tier probe', 'content', 'organization',
				'[]'::jsonb, '[]'::jsonb, $1, $1, $1, 100, true, 1,
				'system', 'system', NOW(), NOW())
			ON CONFLICT (policy_id) DO NOTHING
		`, org); err != nil {
			t.Fatalf("seed org-tier policy: %v", err)
		}
		n, err := repo.CountOrgPolicies(ctx)
		if err != nil {
			t.Fatalf("CountOrgPolicies: %v", err)
		}
		if n < 1 {
			t.Fatalf("CountOrgPolicies = %d, want >= 1 — cross-org count reads 0 under RLS (#3039)", n)
		}
	})
}

func TestDynamicPolicyEngineGateCacheUnderAppRole(t *testing.T) {
	f := setup3039Fixture(t)
	const org = "rls3039-engine-org"
	f.seedOrg(t, org)

	repo := NewPolicyRepository(f.appRoleDB)
	ctx := context.Background()
	policy := &PolicyResource{
		Name:       "Gate Cache Probe",
		Type:       "context_aware",
		Category:   "dynamic-compliance",
		Conditions: []PolicyCondition{{Field: "step_input.amount_eur", Operator: "greater_than", Value: float64(5000)}},
		Actions:    []PolicyAction{{Type: "require_approval"}},
		Priority:   900,
		Enabled:    true,
		TenantID:   org,
	}
	if err := repo.Create(ctx, policy); err != nil {
		t.Fatalf("Create under app_role: %v", err)
	}

	// Vacuity control: an engine whose refresh pool is the app-role pool —
	// the pre-fix wiring — loads an EMPTY cache. This is the exact defect
	// that let an over-threshold wire bypass require_approval in production.
	broken := &DatabaseDynamicPolicyEngine{
		db:       f.appRoleDB,
		policies: make(map[string]interface{}),
	}
	if err := broken.refreshPolicies(); err != nil {
		t.Fatalf("refreshPolicies (app-role pool): %v", err)
	}
	broken.mu.RLock()
	brokenCount := len(broken.policies)
	broken.mu.RUnlock()
	if brokenCount != 0 {
		t.Fatalf("fixture not faithful: app-role-pool refresh loaded %d policies (RLS not enforced — the vacuity control proves nothing)", brokenCount)
	}

	// Fixed wiring: refresh through the BYPASSRLS admin pool.
	engine := &DatabaseDynamicPolicyEngine{
		db:        f.appRoleDB,
		refreshDB: f.adminDB,
		policies:  make(map[string]interface{}),
	}
	if err := engine.refreshPolicies(); err != nil {
		t.Fatalf("refreshPolicies (admin pool): %v", err)
	}
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	if _, ok := engine.policies[policy.ID]; !ok {
		t.Fatalf("gate cache missing the enabled tenant policy after refresh (loaded %d) — dynamic policies would not be enforced (#3039)", len(engine.policies))
	}
}

func TestExecutionRepositoryReadsUnderAppRole(t *testing.T) {
	f := setup3039Fixture(t)
	const org = "rls3039-exec-org"
	f.seedOrg(t, org)

	repo := execution.NewPostgresRepository(f.appRoleDB)
	repo.SetCrossOrgDB(f.adminDB)
	ctx := context.Background()
	now := time.Now().UTC()

	exec := &execution.ExecutionStatus{
		ExecutionID:   "wf_rls3039_probe",
		ExecutionType: execution.ExecutionTypeWCP,
		Name:          "rls probe workflow",
		Source:        "test",
		TenantID:      org,
		OrgID:         org,
		Status:        execution.StatusRunning,
		TotalSteps:    2,
		StartedAt:     now,
		Steps:         []execution.StepStatus{},
		Metadata:      map[string]interface{}{"plan_id": "plan_rls3039"},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := repo.Create(ctx, exec); err != nil {
		t.Fatalf("Create under app_role: %v", err)
	}

	// Vacuity control — the old bare reads saw nothing.
	if n := f.bareCount(t, "execution_history", "tenant_id = $1", org); n != 0 {
		t.Fatalf("fixture not faithful: bare app_role read sees %d execution_history rows (RLS not enforced)", n)
	}

	t.Run("Get_by_id_resolves", func(t *testing.T) {
		got, err := repo.Get(ctx, exec.ExecutionID)
		if err != nil {
			t.Fatalf("Get: %v — by-id discovery read regressed (#3039)", err)
		}
		if got.TenantID != org {
			t.Fatalf("Get tenant = %q, want %q", got.TenantID, org)
		}
	})

	t.Run("GetByPlanID_resolves", func(t *testing.T) {
		got, err := repo.GetByPlanID(ctx, "plan_rls3039")
		if err != nil {
			t.Fatalf("GetByPlanID: %v — metadata discovery read regressed (#3039)", err)
		}
		if got.ExecutionID != exec.ExecutionID {
			t.Fatalf("GetByPlanID id = %q, want %q", got.ExecutionID, exec.ExecutionID)
		}
	})

	t.Run("List_scoped_by_tenant_returns_rows", func(t *testing.T) {
		rowsOut, total, err := repo.List(ctx, execution.ListExecutionsRequest{TenantID: org, OrgID: org, Limit: 10})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 1 || len(rowsOut) != 1 {
			t.Fatalf("List = %d rows / total %d, want 1/1 — portal Executions page reads zero (#3039)", len(rowsOut), total)
		}
	})

	t.Run("CountActive_counts_running", func(t *testing.T) {
		n, err := repo.CountActive(ctx, org)
		if err != nil {
			t.Fatalf("CountActive: %v", err)
		}
		if n != 1 {
			t.Fatalf("CountActive = %d, want 1 — concurrency limits never engage (#3039)", n)
		}
	})
}
