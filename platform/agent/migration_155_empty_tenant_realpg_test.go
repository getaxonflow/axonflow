// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"path/filepath"
	"testing"

	"axonflow/platform/testutil"
)

// TestMigration155NormalizesEmptyTenantPolicies_RealPostgres covers migration
// core/155's REPAIR branch, which no other leg of the migrations gate reaches.
//
// 155 exists because `tenant_id = ”` is a fourth, accidental policy-row shape
// with no defined meaning: the orchestrator's evaluator gates such a row to
// NOBODY while the pre-#3059 list endpoint returned it to EVERYBODY. The
// migration normalizes it to NULL and then adds a CHECK forbidding the shape.
//
// On dynamic_policies the normalization ALSO disables the row, and that is the
// property most worth pinning here. NULL is loaded by refreshPolicies as the
// 'default' apply-to-all sentinel, so normalizing alone would flip a dormant
// row — possibly carrying a `block` action — into deployment-wide enforcement
// on upgrade. `enabled = false` prevents that: refreshPolicies selects
// `WHERE enabled = true`, so a disabled row never enters the gate cache and
// stays enforced for nobody, which is what
// tenant_id = ” already meant.
//
// That behavior-preservation claim is scoped to DatabaseDynamicPolicyEngine,
// which is what production runs. On the in-memory fallback DynamicPolicyEngine
// an empty tenant applies to EVERY caller (memPolicyAppliesToTenant), so the
// same repair is a de-enforcement there rather than a no-op. Compound
// reachability is negligible, but the asymmetry is real; the migration header
// carries the full trade-off.
//
// static_policies is deliberately NOT disabled: its loader predicate
// `(tenant_id = $1 OR tenant_id = 'global')` excludes ” and NULL alike, so
// there the normalization changes nothing. The test asserts that asymmetry in
// both directions, so neither half can be "tidied" into matching the other.
//
// The fresh-DB and seeded-legacy legs of the gate both start from data that
// has no empty-string tenant, so they only ever exercise the ADD CONSTRAINT
// half. If the UPDATE half were wrong or narrower than the constraint it
// precedes, those legs would stay green while a real upgrade carrying one such
// legacy row aborted the migration and crash-looped the agent — the
// repair-scope-narrower-than-verify-scope failure that migration 150 shipped.
//
// So: reconstruct the pre-155 world, plant the row the repair must fix, and
// let the REAL runner apply the rest of the chain on top.
func TestMigration155NormalizesEmptyTenantPolicies_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")

	// 1. The pre-155 world.
	ranBefore, _ := applyChainUpTo(t, pc.DB, migrationsPath, 155)
	if ranBefore == 0 {
		t.Fatal("applied 0 migrations before the cutoff — the seed would be meaningless")
	}

	// 2. Plant the legacy shape on both constrained tables. This must succeed:
	//    if it fails, 155 (or something before it) already forbids the shape
	//    and the repair assertions below would be vacuous.
	seedEmptyTenantPolicy(t, pc.DB, "dynamic_policies", `
		INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority, enabled)
		VALUES ('mig155-empty-dyn', 'legacy empty tenant', 'pre-155 shape', 'content', '[]'::jsonb, '[]'::jsonb, '', 100, true)
	`)
	seedEmptyTenantPolicy(t, pc.DB, "static_policies", `
		INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, tenant_id)
		VALUES ('mig155-empty-static', 'legacy empty tenant', 'test', 'x', 'low', 'pre-155 shape', 'warn', '')
	`)

	// 3. The rest of the chain, INCLUDING 155, must apply on top of that.
	//    155 self-tests internally and RAISEs on failure, so a repair narrower
	//    than its own constraint aborts here rather than passing silently.
	applyChain(t, pc.DB, migrationsPath)

	// 4. The repair actually ran: '' became NULL, the rows still exist (the
	//    migration must not have deleted policy data to satisfy its own
	//    constraint), and no empty-string tenant survives anywhere.
	for _, tc := range []struct {
		table, id   string
		wantEnabled bool
		enabledWhy  string
	}{
		{
			"dynamic_policies", "mig155-empty-dyn", false,
			"a NULL tenant loads as the apply-to-all 'default' sentinel, so leaving this row ENABLED promotes it from enforced-for-nobody to enforced-for-every-tenant on upgrade",
		},
		{
			"static_policies", "mig155-empty-static", true,
			"the static loader predicate (tenant_id = $1 OR tenant_id = 'global') excludes '' and NULL alike, so this normalization changes no enforcement and must not disable the row",
		},
	} {
		var isNull, enabled bool
		err := pc.DB.QueryRow(
			`SELECT tenant_id IS NULL, enabled FROM `+tc.table+` WHERE policy_id = $1`, tc.id,
		).Scan(&isNull, &enabled)
		if err == sql.ErrNoRows {
			t.Fatalf("%s: migration 155 DELETED the legacy row %s instead of normalizing it", tc.table, tc.id)
		}
		if err != nil {
			t.Fatalf("%s: read back %s: %v", tc.table, tc.id, err)
		}
		if !isNull {
			t.Errorf("%s: %s still has a non-NULL tenant_id after migration 155 — the ''→NULL repair did not cover it", tc.table, tc.id)
		}

		// The enforcement-inversion guard, asserted in BOTH directions so
		// neither table's treatment can be "tidied" into matching the other.
		if enabled != tc.wantEnabled {
			t.Errorf("%s: %s has enabled=%v after migration 155, want %v — %s",
				tc.table, tc.id, enabled, tc.wantEnabled, tc.enabledWhy)
		}

		var remaining int
		if err := pc.DB.QueryRow(`SELECT COUNT(*) FROM ` + tc.table + ` WHERE tenant_id = ''`).Scan(&remaining); err != nil {
			t.Fatalf("%s: count empty tenants: %v", tc.table, err)
		}
		if remaining != 0 {
			t.Errorf("%s: %d row(s) still carry tenant_id='' after migration 155", tc.table, remaining)
		}

		// 5. The constraint is live: the shape cannot come back.
		if _, err := pc.DB.Exec(
			`UPDATE ` + tc.table + ` SET tenant_id = '' WHERE policy_id = '` + tc.id + `'`,
		); err == nil {
			t.Errorf("%s: tenant_id='' was accepted after migration 155 — the CHECK constraint is missing", tc.table)
		}
	}
}

// seedEmptyTenantPolicy inserts a pre-155 empty-tenant row, failing the test if
// the insert is rejected — which would mean the fixture never reproduced the
// shape the repair is supposed to fix.
func seedEmptyTenantPolicy(t *testing.T, db *sql.DB, table, stmt string) {
	t.Helper()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("seed pre-155 empty tenant_id into %s failed (%v) — the repair assertions would be vacuous", table, err)
	}
}
