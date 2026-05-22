// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// v9 Phase 6 — cross-org RLS isolation contract test for the identity tables
// that Phase 8 B8/B9 (Epic #2230) will FORCE ROW LEVEL SECURITY on:
//
//   - community_saas_registrations
//   - tenants
//   - organizations
//
// Phase 6 (PR #2278, merged 2026-05-20) replaced the shared 'community-saas'
// org_id constant with per-customer cs_<uuid> values. B8/B9 will land FORCE
// RLS + an org_id isolation policy on these tables in a separate PR. This
// test pins the contract that B8/B9 must satisfy: with axonflow_app_role +
// SET LOCAL app.current_org_id, each customer sees ONLY their own rows.
//
// Out of scope (per Brief 5 / Issue #2292): this PR does NOT add a migration
// that FORCEs RLS on the Phase 6 tables. The test setup applies the FORCE +
// policy in-process so the contract is testable today; when B8/B9 ships a
// real migration, this setup can be replaced with a check that the migration
// ran (mirroring rlsB2TestSetup) without changing the assertions.
//
// Test scenarios (16 subtests under one top-level test):
//
//   Visibility (4 scenarios × 3 tables = 12 subtests):
//     A — axonflow_app_role + SET LOCAL app.current_org_id = orgA → sees A's row
//     B — axonflow_app_role + SET LOCAL app.current_org_id = orgB → sees B's row
//     C — axonflow_app_role with NO SET LOCAL → sees zero rows (RLS hides)
//     D — axonflow_platform_admin (BYPASSRLS)  → sees BOTH rows
//
//   WITH CHECK enforcement (3 subtests, one per table):
//     under orgA's context, INSERT a row with org_id=orgB → RLS violation
//
//   Mutation proof (1 subtest):
//     temporarily DISABLE RLS on community_saas_registrations, re-run the
//     orgA visibility query, assert the count flips from 1 to 2 (cross-org
//     leak observable). Restore ENABLE + FORCE in defer. This proves the
//     test is not tautological — without RLS the assertion in subtest A
//     would fail, so its passing today is load-bearing on the RLS package
//     (ENABLE + policy) being active. FORCE-for-owner is not exercisable
//     under app_role (Postgres only consults FORCE for owner roles) —
//     that side of the B8/B9 contract is covered separately by the
//     runtime-e2e shell harness.
//
// Gating: TEST_PG_INTEGRATION=1. Without it, the test skips so unit-test runs
// (which lack docker) stay green. Pattern follows TestMigration094Precondition_RealPostgres
// in v9_followup_a_gaps_test.go (same package; shares startPostgresContainer
// + runMigrationsRange helpers).
//
// SET LOCAL ROLE gotcha (reference_force_rls_test_superuser_gotcha.md):
// every read/write subtest below runs through runAsAppRoleWithOrg /
// runAsAppRoleNoOrg / runAsPlatformAdmin in rls_isolation_test.go which
// SET LOCAL ROLE inside the transaction. Without this, the docker postgres
// container's default `postgres` user is a superuser and bypasses RLS,
// making every assertion trivially pass.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/lib/pq"
)

const (
	phase6OrgA = "cs_aaa-test-org-A"
	phase6OrgB = "cs_bbb-test-org-B"

	// Distinct, unique content markers per org so the assertion can check
	// row CONTENT not just COUNT — defeats the "matched by accident" class
	// of tautology (per R3 check (a)).
	phase6LabelA = "phase6-seed-A-uniqmarker-9f3c1"
	phase6LabelB = "phase6-seed-B-uniqmarker-7a8e2"
)

// phase6TestTable describes one table under test with its content column.
// The content column carries the per-org unique label so assertions verify
// not just that a row is present but that it's the EXPECTED row.
type phase6TestTable struct {
	name       string // table name
	contentCol string // VARCHAR column carrying phase6Label{A,B}
}

var phase6Tables = []phase6TestTable{
	{name: "community_saas_registrations", contentCol: "label"},
	{name: "tenants", contentCol: "name"},
	{name: "organizations", contentCol: "name"},
}

// rlsPhase6TestSetup brings up an isolated postgres testcontainer, runs every
// migration the schema needs (1-102), applies FORCE RLS + an org_id isolation
// policy on the 3 Phase 6 tables (the work Phase 8 B8/B9 will eventually
// migrate), and seeds two distinct (orgA, orgB) cohorts in each table.
//
// Returns the DB handle and a cleanup func.
func rlsPhase6TestSetup(t *testing.T) (*sql.DB, func()) {
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

	// app.db_password is read by migration 028's dblink template path. Provide a
	// placeholder; we never connect as the grafana user in this test.
	if _, err := db.Exec(`SELECT set_config('app.db_password', 'test-pass', false)`); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("set app.db_password: %v", err)
	}

	// app.deployment_org_id satisfies migration 094's precondition (added in
	// PR #2309 — see v9_followup_a_gaps_test.go). 'local-dev-org' is the
	// recognized dev/CI placeholder that lets Pass-2 backfill no-op instead
	// of EXCEPTION'ing.
	if _, err := db.Exec(`SELECT set_config('app.deployment_org_id', 'local-dev-org', false)`); err != nil {
		_ = db.Close()
		containerCleanup()
		t.Fatalf("set app.deployment_org_id: %v", err)
	}

	// Run all migrations through 103. Migration 098 creates axonflow_app_role +
	// axonflow_platform_admin; 099/101/102 are B1 + B2 RLS (irrelevant to our
	// Phase 6 tables but safe). Migration 103 is B9: ENABLEs + FORCEs RLS on
	// organizations + tenants (NOT on community_saas_registrations — see B9
	// migration header for the auth-bootstrap deferral rationale).
	//
	// After this, organizations + tenants carry the production policy
	// (`organizations_org_id_isolation` / `tenants_org_id_isolation`) shipped
	// in migration 103. applyPhase6ForceRLSAndPolicy below ALSO stacks a
	// Phase 6 test-scoped policy alongside — Postgres ORs permissive
	// policies, so visibility is identical. The test-scoped policy on
	// community_saas_registrations is the ONLY isolation source for that
	// table (B9 deferred it; tracked at the follow-up issue cited in the
	// migration 103 header).
	runMigrationsRange(t, db, 1, 103)

	// GRANT both RLS roles TO CURRENT_USER so the tests can SET LOCAL ROLE
	// inside their transactions. Same trick as rls_isolation_test.go::rlsTestSetup.
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

	applyPhase6ForceRLSAndPolicy(t, db)
	seedPhase6Rows(t, db)

	cleanup := func() {
		_ = db.Close()
		containerCleanup()
	}
	return db, cleanup
}

// applyPhase6ForceRLSAndPolicy installs FORCE RLS + an org_id isolation policy
// on the three Phase 6 tables. This is what Phase 8 B8/B9 will eventually
// migrate; the test self-applies it so the contract is testable today.
//
// The policy USING + WITH CHECK clauses both compare row.org_id to the
// session GUC app.current_org_id (set to '' when unset).
//
// Pre-existing RLS overlap (migration 018):
//
//   organizations is already in migration 018's `tables_with_org_id` array
//   (018_row_level_security.sql:39). That migration ENABLEs RLS and creates
//   four `tenant_isolation_{select,insert,update,delete}` policies on
//   organizations whose USING/WITH CHECK expression (`org_id =
//   get_current_org_id()`) is functionally identical to the Phase 6 policy
//   we install below. Postgres ORs multiple permissive policies, so adding
//   the Phase 6 policy to organizations is parity — not net-new coverage.
//
//   We keep organizations in phase6Tables intentionally: B8/B9 may
//   consolidate/replace migration 018's policies; the Phase 6 test pin
//   guards against that drift by asserting the contract independently of
//   which migration ultimately owns the policy.
//
//   tenants + community_saas_registrations are NOT in migration 018's list
//   — for those two, the Phase 6 setup is the only RLS source, and the
//   test is the diagnostic contract pin.
//
// Why FORCE here even though our test runs under axonflow_app_role: per
// Postgres docs (ddl-rowsecurity), FORCE only affects whether the table
// OWNER is subject to RLS. axonflow_app_role is NOBYPASSRLS (migration 098)
// so it's already subject to RLS the moment ENABLE is on, FORCE or not.
// FORCE matters for production B8/B9 because that migration will land in
// deployments where the migration-runner role IS the table owner — without
// FORCE, that role bypasses RLS during runtime audits/sweeps. Our mutation
// proof below cannot exercise FORCE-for-owner specifically (the docker
// postgres user is a superuser and bypasses RLS unconditionally per
// Postgres semantics — superuser BYPASSRLS overrides FORCE). We pin the
// app_role-side contract here; the owner-side FORCE check happens in the
// runtime-e2e harness (runtime-e2e/v9_phase8_b1_rls/test.sh and the
// matching B8/B9 harness B8/B9 will land).
func applyPhase6ForceRLSAndPolicy(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	for _, tbl := range phase6Tables {
		// ENABLE + FORCE — required for the policy to apply to the table owner too.
		stmts := []string{
			fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tbl.name),
			fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tbl.name),
			fmt.Sprintf(`DROP POLICY IF EXISTS %s_phase6_org_isolation ON %s`, tbl.name, tbl.name),
			fmt.Sprintf(`CREATE POLICY %s_phase6_org_isolation ON %s
				USING (org_id = current_setting('app.current_org_id', true))
				WITH CHECK (org_id = current_setting('app.current_org_id', true))`,
				tbl.name, tbl.name),
		}
		for _, s := range stmts {
			if _, err := db.ExecContext(ctx, s); err != nil {
				t.Fatalf("apply Phase 6 FORCE/policy on %s: %v\n(stmt: %s)", tbl.name, err, s)
			}
		}
	}
}

// seedPhase6Rows inserts one row per orgA / orgB into each Phase 6 table.
// Inserts run as the table owner (superuser) which bypasses RLS — that's
// intentional, the seed needs to populate both org cohorts up front.
//
// FK ordering: organizations → tenants → community_saas_registrations.
// (organizations.org_id is the FK target for tenants.org_id.)
func seedPhase6Rows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// Cleanup any leftovers from a prior aborted run. Owner / superuser
	// bypasses RLS so the DELETE sees both rows.
	cleanupPhase6Rows(t, db)

	cohorts := []struct {
		orgID string
		label string
	}{
		{phase6OrgA, phase6LabelA},
		{phase6OrgB, phase6LabelB},
	}

	for _, c := range cohorts {
		// organizations — must come first because tenants.org_id FKs to it.
		if _, err := db.ExecContext(ctx, `
			INSERT INTO organizations (org_id, name, license_key, tier, created_at)
			VALUES ($1, $2, $3, 'Community', NOW())
		`, c.orgID, c.label, "phase6-rls-test-license-"+c.orgID); err != nil {
			t.Fatalf("seed organizations(%s): %v", c.orgID, err)
		}

		// tenants
		if _, err := db.ExecContext(ctx, `
			INSERT INTO tenants (tenant_id, org_id, name, environment)
			VALUES ($1, $1, $2, 'test')
		`, c.orgID, c.label); err != nil {
			t.Fatalf("seed tenants(%s): %v", c.orgID, err)
		}

		// community_saas_registrations — secret_hash + secret_prefix are
		// NOT NULL; we don't authenticate against this row so synthetic
		// values are fine. client_id was added by migration 088.
		if _, err := db.ExecContext(ctx, `
			INSERT INTO community_saas_registrations
			    (tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at)
			VALUES ($1, $1, $2, $3, $1, $4, NOW() + INTERVAL '30 days')
		`, c.orgID, "phase6-test-hash-"+c.orgID, "phase6", c.label); err != nil {
			t.Fatalf("seed community_saas_registrations(%s): %v", c.orgID, err)
		}
	}
}

// cleanupPhase6Rows removes the seed cohorts. Reverse FK order: registrations
// → tenants → organizations.
func cleanupPhase6Rows(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	_, _ = db.ExecContext(ctx, "DELETE FROM community_saas_registrations WHERE org_id IN ($1, $2)", phase6OrgA, phase6OrgB)
	_, _ = db.ExecContext(ctx, "DELETE FROM tenants WHERE org_id IN ($1, $2)", phase6OrgA, phase6OrgB)
	_, _ = db.ExecContext(ctx, "DELETE FROM organizations WHERE org_id IN ($1, $2)", phase6OrgA, phase6OrgB)
}

// phase6Row is a (org_id, contentMarker) pair returned by SELECTs against any
// Phase 6 table. Assertions check both the org_id and the content marker —
// per R3 (a), this defeats the "row leaked but happens to have the right
// org_id" tautology class.
type phase6Row struct {
	OrgID   string
	Content string
}

// selectVisiblePhase6Rows returns the (org_id, content) pairs visible from
// the given table inside the current tx, filtered to our two test orgs and
// sorted by org_id for stable assertion.
func selectVisiblePhase6Rows(ctx context.Context, tx *sql.Tx, tbl phase6TestTable) ([]phase6Row, error) {
	q := fmt.Sprintf(
		"SELECT org_id, %s FROM %s WHERE org_id IN ($1, $2) ORDER BY org_id",
		tbl.contentCol, tbl.name,
	)
	rows, err := tx.QueryContext(ctx, q, phase6OrgA, phase6OrgB)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []phase6Row
	for rows.Next() {
		var r phase6Row
		if err := rows.Scan(&r.OrgID, &r.Content); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Sort defensively even though SQL ORDER BY ran.
	sort.Slice(out, func(i, j int) bool { return out[i].OrgID < out[j].OrgID })
	return out, nil
}

// assertRowsEqual fails the test if got != want, including a clear diagnostic
// of which side carries which (org_id, content) pairs.
func assertRowsEqual(t *testing.T, table string, got, want []phase6Row) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s visibility mismatch: got %d rows %+v, want %d rows %+v", table, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s row[%d] mismatch: got %+v, want %+v (full got=%+v, want=%+v)", table, i, got[i], want[i], got, want)
		}
	}
}

// =============================================================================
// TestRLSIsolation_Phase6 — top-level entry; runs 16 subtests.
// =============================================================================

func TestRLSIsolation_Phase6(t *testing.T) {
	db, cleanup := rlsPhase6TestSetup(t)
	defer cleanup()

	ctx := context.Background()

	// -------------------------------------------------------------------------
	// Scenario A: app_role + SET LOCAL app.current_org_id = orgA → sees only A
	// -------------------------------------------------------------------------
	for _, tbl := range phase6Tables {
		tbl := tbl
		t.Run("A_OrgA_SeesOnlyOrgA/"+tbl.name, func(t *testing.T) {
			err := runAsAppRoleWithOrg(t, db, phase6OrgA, func(tx *sql.Tx) error {
				rows, err := selectVisiblePhase6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				assertRowsEqual(t, tbl.name, rows, []phase6Row{
					{OrgID: phase6OrgA, Content: phase6LabelA},
				})
				return nil
			})
			if err != nil {
				t.Fatalf("scenario A query: %v", err)
			}
		})
	}

	// -------------------------------------------------------------------------
	// Scenario B: app_role + SET LOCAL app.current_org_id = orgB → sees only B
	// -------------------------------------------------------------------------
	for _, tbl := range phase6Tables {
		tbl := tbl
		t.Run("B_OrgB_SeesOnlyOrgB/"+tbl.name, func(t *testing.T) {
			err := runAsAppRoleWithOrg(t, db, phase6OrgB, func(tx *sql.Tx) error {
				rows, err := selectVisiblePhase6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				assertRowsEqual(t, tbl.name, rows, []phase6Row{
					{OrgID: phase6OrgB, Content: phase6LabelB},
				})
				return nil
			})
			if err != nil {
				t.Fatalf("scenario B query: %v", err)
			}
		})
	}

	// -------------------------------------------------------------------------
	// Scenario C: app_role with NO SET LOCAL → sees zero rows
	//
	// Per R3 (c): the GUC app.current_org_id starts as the empty string (its
	// reset_val) at the top of every fresh transaction. set_config(.., is_local=true)
	// scopes any prior subtest's GUC to that subtest's tx, which Rolled back
	// on exit — so no leakage. Defensive check: re-confirm here that
	// current_setting returns '' before the visibility query.
	// -------------------------------------------------------------------------
	for _, tbl := range phase6Tables {
		tbl := tbl
		t.Run("C_NoOrgContext_ZeroRows/"+tbl.name, func(t *testing.T) {
			err := runAsAppRoleNoOrg(t, db, func(tx *sql.Tx) error {
				// Defensive entry check — proves no GUC leaked from a prior tx.
				var orgGUC string
				if err := tx.QueryRowContext(ctx, "SELECT current_setting('app.current_org_id', true)").Scan(&orgGUC); err != nil {
					return fmt.Errorf("check entry GUC: %w", err)
				}
				if orgGUC != "" {
					return fmt.Errorf("expected app.current_org_id='' at tx entry, got %q (GUC leaked from prior subtest)", orgGUC)
				}
				rows, err := selectVisiblePhase6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				assertRowsEqual(t, tbl.name, rows, nil)
				return nil
			})
			if err != nil {
				t.Fatalf("scenario C query: %v", err)
			}
		})
	}

	// -------------------------------------------------------------------------
	// Scenario D: axonflow_platform_admin (BYPASSRLS) → sees both rows
	// -------------------------------------------------------------------------
	for _, tbl := range phase6Tables {
		tbl := tbl
		t.Run("D_AdminBypass_SeesBothRows/"+tbl.name, func(t *testing.T) {
			err := runAsPlatformAdmin(t, db, func(tx *sql.Tx) error {
				rows, err := selectVisiblePhase6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				assertRowsEqual(t, tbl.name, rows, []phase6Row{
					{OrgID: phase6OrgA, Content: phase6LabelA},
					{OrgID: phase6OrgB, Content: phase6LabelB},
				})
				return nil
			})
			if err != nil {
				t.Fatalf("scenario D query: %v", err)
			}
		})
	}

	// -------------------------------------------------------------------------
	// WITH CHECK enforcement (per-table). Under orgA's context, INSERT a row
	// with org_id=orgB → expect a SQLSTATE 42501 RLS policy violation.
	//
	// All INSERTs run inside the tx returned by runAsAppRoleWithOrg, which
	// rolls back on exit — even if the INSERT had unexpectedly succeeded,
	// the row wouldn't survive.
	// -------------------------------------------------------------------------
	t.Run("WITH_CHECK_OrgA_RejectsOrgBInsert/community_saas_registrations", func(t *testing.T) {
		err := runAsAppRoleWithOrg(t, db, phase6OrgA, func(tx *sql.Tx) error {
			_, ex := tx.ExecContext(ctx, `
				INSERT INTO community_saas_registrations
				    (tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at)
				VALUES ($1, $1, $2, $3, $4, $5, NOW() + INTERVAL '30 days')
			`,
				"phase6-with-check-attack-A",
				"phase6-with-check-hash",
				"phase6",
				phase6OrgB, // <-- mismatched org_id
				"phase6-with-check-attack-label",
			)
			return mustBeRLSViolation(ex)
		})
		if err != nil {
			t.Fatalf("WITH CHECK community_saas_registrations: %v", err)
		}
	})

	t.Run("WITH_CHECK_OrgA_RejectsOrgBInsert/tenants", func(t *testing.T) {
		err := runAsAppRoleWithOrg(t, db, phase6OrgA, func(tx *sql.Tx) error {
			// tenants.org_id FKs to organizations(org_id). Pre-INSERT an
			// "attacker" organizations row OUT-OF-BAND (would need to bypass RLS
			// itself, which is the point) — instead we attack by using orgB
			// which already exists in organizations from the seed. The FK is
			// satisfied; only the RLS WITH CHECK on tenants should fire.
			_, ex := tx.ExecContext(ctx, `
				INSERT INTO tenants (tenant_id, org_id, name, environment)
				VALUES ($1, $2, $3, 'test')
			`,
				"phase6-with-check-attack-tenant-A",
				phase6OrgB, // <-- mismatched org_id (still satisfies FK)
				"phase6-with-check-attack-tenant-label",
			)
			return mustBeRLSViolation(ex)
		})
		if err != nil {
			t.Fatalf("WITH CHECK tenants: %v", err)
		}
	})

	t.Run("WITH_CHECK_OrgA_RejectsOrgBInsert/organizations", func(t *testing.T) {
		err := runAsAppRoleWithOrg(t, db, phase6OrgA, func(tx *sql.Tx) error {
			_, ex := tx.ExecContext(ctx, `
				INSERT INTO organizations (org_id, name, license_key, tier, created_at)
				VALUES ($1, $2, $3, 'Community', NOW())
			`,
				phase6OrgB+"-attacker-clone", // unique PK so we don't conflict with seed
				"phase6-with-check-attack-org-label",
				"phase6-with-check-license",
			)
			// First attempt with a fresh org_id under orgA context: WITH CHECK
			// compares row.org_id (the fresh value) to session GUC (phase6OrgA).
			// They differ → violation. (Anchor check below confirms this is
			// the WITH CHECK firing, not some other constraint.)
			return mustBeRLSViolation(ex)
		})
		if err != nil {
			t.Fatalf("WITH CHECK organizations: %v", err)
		}
	})

	// -------------------------------------------------------------------------
	// Mutation proof: temporarily DISABLE RLS on community_saas_registrations,
	// re-run the scenario A visibility query, assert it now sees BOTH rows
	// (count flips 1 → 2). Restore ENABLE + FORCE in defer.
	//
	// Per Brief DoD #4: "if reverting doesn't change visibility, the test is
	// tautological — fix the test, not the assertion."
	//
	// Why DISABLE (not NO FORCE): under axonflow_app_role (NOBYPASSRLS per
	// migration 098 line 44), FORCE is irrelevant — Postgres only consults
	// FORCE for table-owner roles. ENABLE + policy together gate app_role's
	// visibility. The mutation that observably changes scenario A's count
	// is therefore DISABLE (which clears ENABLE) or DROP POLICY (which
	// leaves ENABLE on but default-denies to 0 rows — flip in the opposite
	// direction). We pick DISABLE because the 1 → 2 flip pattern is the
	// brief's specified shape.
	//
	// What this mutation proves: the RLS-PACKAGE (ENABLE + policy) is
	// load-bearing for scenario A's assertion under app_role. If B8/B9's
	// migration omits ENABLE or drops the policy, this test fails. The
	// FORCE-for-owner side of the contract (B8/B9 also adds FORCE so that
	// the migration-runner role can't accidentally read cross-org rows
	// during audits/sweeps) is NOT exercised here — the docker postgres
	// user is a superuser and bypasses RLS unconditionally per Postgres
	// semantics, so FORCE-vs-no-FORCE has no observable difference at this
	// level. That side is covered by the runtime-e2e shell harness.
	// -------------------------------------------------------------------------
	// Run the DISABLE-RLS mutation proof against EVERY Phase 6 table so the
	// contract holds independently per table. Without this per-table sweep,
	// a future regression that drops the policy on one of the three tables
	// (without also dropping the others) would slip past the prior single-
	// table mutation proof.
	//
	// Subtest order: community_saas_registrations FIRST so the in-process
	// Phase 6 setup remains the load-bearing protection on that table (B9
	// migration 103 deferred it). organizations + tenants prove that
	// migration 103's policy (`organizations_org_id_isolation` /
	// `tenants_org_id_isolation`) is also load-bearing.
	for _, tbl := range phase6Tables {
		tbl := tbl
		t.Run("MutationProof_DisableRLS_LeaksCrossOrg/"+tbl.name, func(t *testing.T) {
			tblName := tbl.name
			if _, err := db.ExecContext(ctx,
				fmt.Sprintf("ALTER TABLE %s DISABLE ROW LEVEL SECURITY", tblName)); err != nil {
				t.Fatalf("disable RLS on %s: %v", tblName, err)
			}

			// Restore on defer regardless of subtest outcome — leaves the
			// table in the same state subsequent runs / subtests expect.
			defer func() {
				if _, err := db.ExecContext(ctx,
					fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", tblName)); err != nil {
					t.Errorf("restore ENABLE on %s: %v", tblName, err)
				}
				if _, err := db.ExecContext(ctx,
					fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", tblName)); err != nil {
					t.Errorf("restore FORCE on %s: %v", tblName, err)
				}
			}()

			// Re-run scenario A. Expect both rows now visible — the leak
			// the mutation proves observable.
			err := runAsAppRoleWithOrg(t, db, phase6OrgA, func(tx *sql.Tx) error {
				rows, err := selectVisiblePhase6Rows(ctx, tx, tbl)
				if err != nil {
					return err
				}
				if len(rows) != 2 {
					return fmt.Errorf("mutation proof FAILED: with RLS DISABLED on %s, scenario A still sees %d rows %+v; expected 2 (cross-org leak should be observable). Assertion in scenario A is tautological — the test does not actually depend on RLS being active.",
						tblName, len(rows), rows)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("mutation proof query: %v", err)
			}
			t.Logf("mutation proof verified: disabling RLS on %s flipped scenario A from 1 visible row to 2 (cross-org leak observable, RLS package is load-bearing)", tblName)
		})
	}
}

// mustBeRLSViolation returns nil if err is an RLS policy violation (SQLSTATE
// 42501 or a postgres error message containing "row-level security"), or a
// failure if err is nil or any other class of error.
//
// Per rls_b2_isolation_test.go's precedent: accepting ANY error is too
// permissive — schema/FK/NOT NULL constraint violations would falsely
// confirm WITH CHECK. We pin to SQLSTATE 42501 (insufficient_privilege),
// which Postgres emits for any RLS policy violation (USING or WITH CHECK).
func mustBeRLSViolation(err error) error {
	if err == nil {
		return fmt.Errorf("expected RLS policy violation, got nil error — WITH CHECK clause not enforced (FORCE reverted, role bypassed RLS, set_config not applied, or policy missing)")
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		if pqErr.Code != "42501" {
			return fmt.Errorf("expected RLS policy violation (SQLSTATE 42501), got SQLSTATE %s: %v", pqErr.Code, err)
		}
		return nil
	}
	if strings.Contains(err.Error(), "row-level security") {
		return nil
	}
	return fmt.Errorf("expected RLS policy violation, got non-RLS error: %v", err)
}
