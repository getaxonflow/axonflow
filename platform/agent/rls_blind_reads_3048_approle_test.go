// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Regression tests for #3048 — RLS-blind reads of static_policies on the
// agent's request path.
//
// static_policies is RLS-enabled (mig 018, org_id = get_current_org_id());
// under axonflow_app_role every bare reader matched ZERO rows silently, so
// the unified policy engine loaded nothing and BOTH content planes evaluated
// nothing (live prod: check-input with `DROP TABLE` + SSN returned
// {"allowed": true, "policies_evaluated": 0}; portal Static count 0).
//
// Each test carries a vacuity control proving the fixture actually enforces
// RLS against the app-role connection (a superuser-shaped fixture passes even
// with the fix reverted — feedback_realpg_tests_as_superuser_hide_rls_defects).
//
// Gating: TEST_PG_INTEGRATION=1 + docker (see approletest.SkipUnlessEnabled).

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"axonflow/platform/agent/approletest"
	sharedpolicy "axonflow/platform/shared/policy"
)

type approle3048Fixture struct {
	masterDB  *sql.DB
	appRoleDB *sql.DB
	adminDB   *sql.DB
}

// setup3048Fixture boots the app-role posture DB with core migrations
// 001..111 (approletest's stable range). Migrations 153/154 — the org_id
// backfill + choke-point default this fix depends on — are applied by the
// individual tests so the PRE-153 state can serve as the item-10 vacuity
// control.
func setup3048Fixture(t *testing.T) *approle3048Fixture {
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

	f := &approle3048Fixture{
		masterDB:  open(env.MasterDSN, "master"),
		appRoleDB: open(env.AppRoleDSN, "app_role"),
		adminDB:   open(env.AdminDSN, "platform_admin"),
	}
	// Single connection so bare (no-GUC) probes can't ride a leaked SET LOCAL.
	f.appRoleDB.SetMaxOpenConns(1)
	approletest.AssertCurrentUser(t, f.appRoleDB, "axonflow_app_role")
	return f
}

func (f *approle3048Fixture) applyMigration(t *testing.T, name string) {
	t.Helper()
	migSQL, err := os.ReadFile("../../migrations/core/" + name)
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	if _, err := f.masterDB.Exec(string(migSQL)); err != nil {
		t.Fatalf("apply migration %s: %v", name, err)
	}
}

func (f *approle3048Fixture) seedOrg(t *testing.T, org string) {
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
func (f *approle3048Fixture) bareCount(t *testing.T, table, where string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := f.appRoleDB.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE "+where, args...).Scan(&n); err != nil {
		t.Fatalf("bare app_role count on %s: %v", table, err)
	}
	return n
}

// TestUnifiedEngineEnforcementUnderAppRole is the #3048 headline regression:
// the shared engine over the APP-ROLE pool must load the REAL migration-seeded
// system policies through the two-scope read and BLOCK a `DROP TABLE`
// statement — the exact payload live prod allowed with policies_evaluated=0.
//
// It also proves the item-10 invariant guard against the REAL pre-fix data
// shape: BEFORE mig 153/154 the global rows carry NULL org_id and the scoped
// load "succeeds" with zero system rows — the engine must fail CLOSED with
// the empty-system-set signal, not allow (the unfixed bare-read shape and the
// pre-backfill data shape are the same failure and this doubles as the
// vacuity control for the enforcement assertion below).
func TestUnifiedEngineEnforcementUnderAppRole(t *testing.T) {
	f := setup3048Fixture(t)
	const org = "rls3048-engine-org"
	f.seedOrg(t, org)

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(f.appRoleDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	defer engine.Stop()
	ctx := context.Background()

	// Vacuity control 1 — the old bare read saw nothing under app_role.
	if n := f.bareCount(t, "static_policies", "tenant_id = 'global'"); n != 0 {
		t.Fatalf("fixture not faithful: bare app_role read sees %d global static_policies rows (RLS not enforced)", n)
	}
	// Control 2 — the rows exist for the owner (so a zero scoped read below
	// would be an enforcement bug, not missing seeds).
	var seeded int
	if err := f.masterDB.QueryRow(`SELECT COUNT(*) FROM static_policies WHERE tenant_id = 'global' AND enabled = true`).Scan(&seeded); err != nil {
		t.Fatalf("master seed count: %v", err)
	}
	if seeded == 0 {
		t.Fatal("fixture broken: no migration-seeded global static policies present")
	}

	// Item-10 guard against the PRE-153 data shape: org_id is NULL on the
	// seeded global rows, so the scoped load returns zero system rows —
	// the gate must fail CLOSED with the availability signal, never allow.
	pre := engine.EvaluateRequest(ctx, "DROP TABLE users; my SSN is 523-45-6789",
		sharedpolicy.EvalOptions{TenantID: org, OrgID: org})
	if !pre.Blocked || !pre.EvaluationError {
		t.Fatalf("pre-153 data shape must fail CLOSED with EvaluationError (empty system set); got blocked=%v evalErr=%v evaluated=%d",
			pre.Blocked, pre.EvaluationError, pre.PoliciesEvaluated)
	}

	// Apply the org_id backfill + choke-point default, then re-evaluate.
	f.applyMigration(t, "153_backfill_global_policy_org_id.sql")
	f.applyMigration(t, "154_global_policy_org_id_default.sql")
	engine.InvalidateCache(org, nil)

	result := engine.EvaluateRequest(ctx, "DROP TABLE users; my SSN is 523-45-6789",
		sharedpolicy.EvalOptions{TenantID: org, OrgID: org})
	if result.EvaluationError {
		t.Fatalf("post-153/154 load must succeed; got evaluation error (blocked=%v)", result.Blocked)
	}
	if result.PoliciesEvaluated == 0 {
		t.Fatal("policies_evaluated = 0 — the two-scope load regressed (#3048: content enforcement silently OFF)")
	}
	if !result.Blocked {
		t.Fatalf("DROP TABLE must be blocked by the migration-seeded policy; evaluated=%d", result.PoliciesEvaluated)
	}

	// Control: a clean statement still passes (the block above is the policy
	// firing, not a blanket failure).
	engine.InvalidateCache(org, nil)
	clean := engine.EvaluateRequest(ctx, "what is the current order status",
		sharedpolicy.EvalOptions{TenantID: org, OrgID: org})
	if clean.Blocked {
		t.Fatalf("clean statement must not be blocked (reason=%q, evalErr=%v)", clean.BlockReason, clean.EvaluationError)
	}
	if clean.PoliciesEvaluated == 0 {
		t.Fatal("clean statement evaluated 0 policies — load regressed")
	}
}

// TestStaticPolicyRepositoryReadsUnderAppRole covers the repository surface:
// create → by-id read-back, List (tenant + system merge), GetEffective
// (portal unified view source — live prod showed Static 0), and the
// tenant-policy count.
func TestStaticPolicyRepositoryReadsUnderAppRole(t *testing.T) {
	f := setup3048Fixture(t)
	const org = "rls3048-repo-org"
	f.seedOrg(t, org)
	f.applyMigration(t, "153_backfill_global_policy_org_id.sql")
	f.applyMigration(t, "154_global_policy_org_id_default.sql")

	repo := NewStaticPolicyRepository(f.appRoleDB)
	// The caller org travels via the auth context in production
	// (apiAuthMiddleware); mirror that.
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, org)
	ctx = context.WithValue(ctx, ContextKeyTenantID, org)

	policy := &StaticPolicy{
		Name:     "RLS 3048 Read-Back Probe",
		Category: "security-sqli",
		Tier:     TierTenant,
		Pattern:  `\bRLS3048_MARKER\b`,
		Severity: "high",
		Action:   "block",
		TenantID: org,
		OrgID:    org,
		Enabled:  true,
	}
	if err := repo.Create(ctx, policy, "test-user"); err != nil {
		t.Fatalf("Create under app_role: %v", err)
	}

	// Vacuity control — the old bare reads saw nothing.
	if n := f.bareCount(t, "static_policies", "tenant_id = $1", org); n != 0 {
		t.Fatalf("fixture not faithful: bare app_role read sees %d tenant rows (RLS not enforced)", n)
	}

	t.Run("GetByID_reads_back_created_policy", func(t *testing.T) {
		got, err := repo.GetByID(ctx, policy.PolicyID)
		if err != nil {
			t.Fatalf("GetByID: %v — by-id read-back regressed (#3048)", err)
		}
		if got.Name != policy.Name {
			t.Fatalf("GetByID name = %q, want %q", got.Name, policy.Name)
		}
	})

	t.Run("GetByID_resolves_system_policy_via_global_scope", func(t *testing.T) {
		got, err := repo.GetByID(ctx, "drop_table_prevention")
		if err != nil {
			t.Fatalf("GetByID(system): %v — the 'global'-scope fallback regressed (#3048)", err)
		}
		if got.TenantID != GlobalOrgSentinel {
			t.Fatalf("system policy tenant = %q, want global", got.TenantID)
		}
	})

	t.Run("List_merges_tenant_and_system_rows", func(t *testing.T) {
		resp, err := repo.List(ctx, org, &ListStaticPoliciesParams{Page: 1, PageSize: 100})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var haveTenant, haveSystem bool
		for _, p := range resp.Policies {
			if p.PolicyID == policy.PolicyID {
				haveTenant = true
			}
			// sys_sqli_union_select is a REAL mig-031 system seed — asserting
			// it (not a synthetic probe) proves mig 153 + the global-scope
			// pass together restore the production rows.
			if p.PolicyID == "sys_sqli_union_select" {
				haveSystem = true
			}
		}
		if !haveTenant {
			t.Fatalf("List missing the tenant policy (total=%d) — tenant-scope pass regressed (#3048)", resp.Pagination.TotalItems)
		}
		if !haveSystem {
			t.Fatalf("List missing the mig-031 system policy (total=%d) — global-scope pass regressed (#3048; portal showed Static 0)", resp.Pagination.TotalItems)
		}
	})

	t.Run("GetEffective_returns_system_baseline", func(t *testing.T) {
		orgID := org
		policies, err := repo.GetEffective(ctx, org, &orgID)
		if err != nil {
			t.Fatalf("GetEffective: %v", err)
		}
		var systemCount, tenantCount int
		for _, p := range policies {
			switch p.Tier {
			case TierSystem:
				systemCount++
			case TierTenant:
				tenantCount++
			}
		}
		if systemCount == 0 {
			t.Fatal("GetEffective returned 0 system policies — the portal 'Static (Read-only) 0' bug (#3048)")
		}
		if tenantCount == 0 {
			t.Fatal("GetEffective missing the tenant policy — tenant-scope pass regressed (#3048)")
		}
	})

	t.Run("countTenantPolicies_counts_scoped", func(t *testing.T) {
		n, err := repo.countTenantPolicies(ctx, org)
		if err != nil {
			t.Fatalf("countTenantPolicies: %v", err)
		}
		if n != 1 {
			t.Fatalf("countTenantPolicies = %d, want 1 — Community tier limit undercount (#3048)", n)
		}
	})
}

// TestMigration154TriggerDefaultsGlobalOrgID proves the choke-point default:
// an industry-template-shaped INSERT (tenant_id='global', NO org_id — the
// exact shape of migrations/industry/banking/302 etc., which apply AFTER
// core/153) acquires org_id='global' and becomes visible to the scoped reads.
func TestMigration154TriggerDefaultsGlobalOrgID(t *testing.T) {
	f := setup3048Fixture(t)
	f.applyMigration(t, "153_backfill_global_policy_org_id.sql")
	f.applyMigration(t, "154_global_policy_org_id_default.sql")

	if _, err := f.masterDB.Exec(`
		INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tier, tenant_id, enabled)
		VALUES ('rls3048_industry_probe', 'Industry Probe', 'security-sqli', 'INDUSTRY_PROBE_MARKER', 'high', 'probe', 'block', 'system', 'global', true)
	`); err != nil {
		t.Fatalf("industry-shaped seed insert: %v", err)
	}

	var orgID sql.NullString
	if err := f.masterDB.QueryRow(
		`SELECT org_id FROM static_policies WHERE policy_id = 'rls3048_industry_probe'`,
	).Scan(&orgID); err != nil {
		t.Fatalf("read probe row: %v", err)
	}
	if !orgID.Valid || orgID.String != "global" {
		t.Fatalf("mig 154 trigger did not default org_id='global' (got %v) — post-153 seeds stay invisible under app-role", orgID)
	}

	// And the scoped loader actually sees it on the app-role pool.
	loader := sharedpolicy.NewPolicyLoader(f.appRoleDB, sharedpolicy.NewPolicyCache(0, 10))
	policies, err := loader.LoadSystemPolicies(context.Background())
	if err != nil {
		t.Fatalf("LoadSystemPolicies: %v", err)
	}
	found := false
	for _, p := range policies {
		if p.PolicyID == "rls3048_industry_probe" {
			found = true
		}
	}
	if !found {
		t.Fatal("scoped LoadSystemPolicies does not see the trigger-defaulted row under app_role")
	}
}

// TestGlobalBaselineWritesRejectedUnderAppRole is the #3048 R3 BLOCKER-1
// real-PG regression: a tenant caller must NOT be able to delete / disable /
// rewrite the shared 'global'-wildcard baseline (drop_table_prevention is a
// REAL mig-010 seed, demoted to tier='tenant' by mig 031 and stamped
// org_id='global' by mig 153) — while the read exemption keeps the row
// visible. Asserts the row is INTACT after each attempt via the master pool.
func TestGlobalBaselineWritesRejectedUnderAppRole(t *testing.T) {
	f := setup3048Fixture(t)
	const org = "rls3048-attacker-org"
	f.seedOrg(t, org)
	f.applyMigration(t, "153_backfill_global_policy_org_id.sql")
	f.applyMigration(t, "154_global_policy_org_id_default.sql")

	repo := NewStaticPolicyRepository(f.appRoleDB)
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, org)
	ctx = context.WithValue(ctx, ContextKeyTenantID, org)

	assertIntact := func(t *testing.T, when string) {
		t.Helper()
		var enabled bool
		var deleted sql.NullTime
		var pattern string
		if err := f.masterDB.QueryRow(
			`SELECT enabled, deleted_at, pattern FROM static_policies WHERE policy_id = 'drop_table_prevention'`,
		).Scan(&enabled, &deleted, &pattern); err != nil {
			t.Fatalf("master read (%s): %v", when, err)
		}
		if !enabled || deleted.Valid || pattern != `drop\s+table` {
			t.Fatalf("SECURITY (%s): baseline row mutated — enabled=%v deleted=%v pattern=%q", when, enabled, deleted.Valid, pattern)
		}
	}

	t.Run("delete rejected and row intact", func(t *testing.T) {
		err := repo.Delete(ctx, "drop_table_prevention", "attacker@a.example")
		if !errors.Is(err, ErrSystemPolicyDeletion) {
			t.Fatalf("SECURITY: tenant caller soft-deleted the deployment-wide DROP TABLE guard (err=%v)", err)
		}
		assertIntact(t, "after delete attempt")
	})

	t.Run("disable rejected and row intact", func(t *testing.T) {
		err := repo.ToggleEnabled(ctx, "drop_table_prevention", false, "attacker@a.example")
		if !errors.Is(err, ErrSystemPolicyModification) {
			t.Fatalf("SECURITY: tenant caller disabled the deployment-wide DROP TABLE guard (err=%v)", err)
		}
		assertIntact(t, "after disable attempt")
	})

	t.Run("pattern rewrite rejected and row intact", func(t *testing.T) {
		p := "never_matches"
		_, err := repo.Update(ctx, "drop_table_prevention", &UpdateStaticPolicyRequest{Pattern: &p}, "attacker@a.example")
		if !errors.Is(err, ErrSystemPolicyModification) {
			t.Fatalf("SECURITY: tenant caller rewrote the DROP TABLE guard's pattern (err=%v)", err)
		}
		assertIntact(t, "after update attempt")
	})

	t.Run("read exemption still resolves the row", func(t *testing.T) {
		got, err := repo.GetByID(ctx, "drop_table_prevention")
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.PolicyID != "drop_table_prevention" {
			t.Fatalf("wrong row: %s", got.PolicyID)
		}
	})
}

// TestOrgTenantSplitEnforcementUnderAppRole is the #3048 R3 HIGH-3 real-PG
// regression: an org whose org_id differs from its tenant_id must still have
// its tenant-tier policies enforced. The gates now pass the validated caller
// org through EvalOptions.OrganizationID; without it the loader's tenant pass
// scoped the GUC to the TENANT id, hid the org-stamped rows under RLS, and —
// because the 'global' system set still loaded — the zero-system-set guard
// did NOT trip: the policy silently stopped enforcing.
func TestOrgTenantSplitEnforcementUnderAppRole(t *testing.T) {
	f := setup3048Fixture(t)
	const orgID = "rls3048-split-org"
	const tenantID = "rls3048-split-tenant"
	f.seedOrg(t, orgID)
	f.applyMigration(t, "153_backfill_global_policy_org_id.sql")
	f.applyMigration(t, "154_global_policy_org_id_default.sql")

	// Tenant-tier policy stamped with the ORG key (the shape Create writes
	// when X-Org-ID differs from the tenant).
	repo := NewStaticPolicyRepository(f.appRoleDB)
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, orgID)
	policy := &StaticPolicy{
		Name:     "Split Org Marker",
		Category: "security-sqli",
		Tier:     TierTenant,
		Pattern:  `\bSPLIT_ORG_MARKER\b`,
		Severity: "high",
		Action:   "block",
		TenantID: tenantID,
		OrgID:    orgID,
		Enabled:  true,
	}
	if err := repo.Create(ctx, policy, "admin@split.example"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(f.appRoleDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	defer engine.Stop()

	// Vacuity control — WITHOUT the org, the tenant pass scopes the GUC to
	// the tenant id, the org-stamped row is invisible, and the statement
	// sails through (system SQLi seeds don't match the marker). This is the
	// silent under-enforcement HIGH-3 names.
	without := engine.EvaluateRequest(context.Background(), "run SPLIT_ORG_MARKER now",
		sharedpolicy.EvalOptions{TenantID: tenantID})
	if without.Blocked {
		t.Fatalf("vacuity control broken: statement blocked without the org scope (reason=%q)", without.BlockReason)
	}

	// With the org plumbed (what the gates now do): the policy enforces.
	engine.InvalidateCache(tenantID, sharedpolicy.OrgScopePtr(orgID))
	with := engine.EvaluateRequest(context.Background(), "run SPLIT_ORG_MARKER now",
		sharedpolicy.EvalOptions{TenantID: tenantID, OrgID: orgID, OrganizationID: sharedpolicy.OrgScopePtr(orgID)})
	if with.EvaluationError {
		t.Fatalf("load failed with the org scope: blocked=%v", with.Blocked)
	}
	if !with.Blocked {
		t.Fatalf("org≠tenant policy NOT enforced with OrganizationID set (evaluated=%d) — R3 HIGH-3 regressed", with.PoliciesEvaluated)
	}
}
