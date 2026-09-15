// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres contract test for migration 117's promote_deployment_org_license
// SECURITY DEFINER helper (#2535). Mirrors migration_104_security_definer_test.go.
//
// Pins, under FORCE RLS on organizations (mig 103), called as axonflow_app_role
// (NOBYPASSRLS) WITHOUT any SET LOCAL app.current_org_id — the exact role posture
// the agent boot path uses:
//   - Pin 1: promote INSERTS a fresh deployment-org row at the licensed tier.
//   - Pin 2: promote PROMOTES an existing migration-094 'Community' placeholder
//            row in place (UPDATE), not just inserts.
//   - Pin 3: idempotent — a second promote with the same license is a no-op
//            (updated_at unchanged, no error, no flapping).
//   - Pin 5: perpetual / no-expiry license — the real run.go helper's
//            zero-ExpiresAt → SQL NULL branch persists expires_at NULL and
//            re-promote no-ops (NULL IS DISTINCT FROM NULL is false).
//   - Pin 4: mutation proof — ALTER FUNCTION ... SECURITY INVOKER makes the same
//            app_role caller FAIL under FORCE RLS, confirming SECURITY DEFINER is
//            load-bearing, not noise. (Runs last; it mutates the function.)
//
// Gated on TEST_PG_INTEGRATION=1 + TEST_DATABASE_URL (matches the mig-104 test).

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

// alteredHelperSignatures names both halves of the promotion helper as core/175
// leaves them: the VOID forwarder under the original name, and the body under
// _returning. Both carry the TIMESTAMPTZ fourth parameter core/142 retyped.
var alteredHelperSignatures = []string{
	"promote_deployment_org_license(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ)",
	"promote_deployment_org_license_returning(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ)",
}

func TestMigration117_PromoteDeploymentOrgLicenseUnderForceRLS(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION not set — skipping real-Postgres test")
	}
	ctx := context.Background()
	db := migrationSchemaDB(t)
	defer db.Close()

	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "RESET ROLE")
		_, _ = db.ExecContext(ctx, "DELETE FROM organizations WHERE org_id LIKE 'mig117-test-%'")
	})

	// THE CHAIN IS migrationSchemaDB'S, AND IT IS UNBOUNDED (#4034).
	//
	// This test applied 1..104 and then migration 117 on its own, to avoid
	// pulling 105..116. That fixture stopped describing the product when
	// core/175 landed: the perpetual-licence pin drives the REAL agent helper
	// promoteDeploymentOrgTier, and since 175 that helper calls
	// promote_deployment_org_license_returning, which a 104+117 schema does not
	// have. Its first execution anywhere -- gate run 34559845210 -- said so in
	// the product's own words:
	//
	//	pq: function promote_deployment_org_license_returning(unknown, unknown,
	//	unknown, unknown) does not exist
	//
	// The first repair was `runMigrationsRange(t, db, 1, 175)`, which fixed the
	// instance and KEPT the defect: a hand-maintained upper bound is a fixture
	// somebody has to bump for every migration touching its subject, and
	// core/176 already existed when it was written. approletest deleted exactly
	// such a literal in #3490 after 55 migrations of drift, one of which changed
	// a column TYPE.
	//
	// So the bound is gone rather than raised. migrationSchemaDB applies every
	// core migration present and provisions both login roles, and it is also
	// where the session GUCs are set -- core/028 reads app.db_password with
	// current_setting(..., false), so a missing value is an error rather than an
	// empty string.
	//
	// Two consequences the assertions below depend on, both from migrations now
	// in range: core/142 retyped the helper's fourth parameter to TIMESTAMPTZ,
	// and core/175 made the old name a VOID forwarder whose body lives in
	// _returning.

	// Helper is installed + SECURITY DEFINER.
	var secDef bool
	if err := db.QueryRowContext(ctx,
		`SELECT prosecdef FROM pg_proc WHERE proname='promote_deployment_org_license' AND pronamespace=(SELECT oid FROM pg_namespace WHERE nspname='public')`,
	).Scan(&secDef); err != nil {
		t.Fatalf("query prosecdef: %v", err)
	}
	if !secDef {
		t.Fatal("promote_deployment_org_license is NOT SECURITY DEFINER")
	}

	// FORCE RLS on organizations must be active or the bypass proof is hollow.
	var orgsForced bool
	if err := db.QueryRowContext(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname='organizations'`,
	).Scan(&orgsForced); err != nil {
		t.Fatalf("query FORCE on organizations: %v", err)
	}
	if !orgsForced {
		t.Fatal("organizations is NOT FORCE RLS — mig 103 didn't apply; SECURITY DEFINER bypass not meaningful")
	}

	// Switch to axonflow_app_role (NOBYPASSRLS) so FORCE RLS applies — the same
	// posture as the agent's app-role boot connection under
	// AXONFLOW_DB_USE_APP_ROLE=true.
	if _, err := db.ExecContext(ctx, "GRANT axonflow_app_role TO CURRENT_USER"); err != nil {
		if !isAlreadyGrantedErr(err) {
			t.Fatalf("GRANT axonflow_app_role TO CURRENT_USER: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
		t.Fatalf("SET ROLE axonflow_app_role: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, "RESET ROLE") })

	expiry := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	const expiryWant = "2027-06-01 00:00:00"

	// ========================================================================
	// Pin 1: fresh INSERT under FORCE RLS as app_role, no SET LOCAL.
	// ========================================================================
	t.Run("inserts fresh deployment-org row at licensed tier", func(t *testing.T) {
		const org = "mig117-test-fresh"
		if _, err := db.ExecContext(ctx,
			`SELECT promote_deployment_org_license($1,$2,$3,$4)`,
			org, "Enterprise", 999999, expiry,
		); err != nil {
			t.Fatalf("promote (insert) under FORCE RLS as app_role: %v (SECURITY DEFINER should bypass)", err)
		}
		tier, maxNodes, exp := readOrg117(t, ctx, db, org)
		if tier != "Enterprise" || maxNodes != 999999 || !exp.Valid || exp.Time.UTC().Format("2006-01-02 15:04:05") != expiryWant {
			t.Fatalf("fresh row mismatch: tier=%q max_nodes=%d expires=%v (want Enterprise/999999/%s)", tier, maxNodes, exp, expiryWant)
		}
	})

	// ========================================================================
	// Pin 2: promote an EXISTING migration-094 'Community' placeholder in place.
	// ========================================================================
	t.Run("promotes existing Community placeholder in place", func(t *testing.T) {
		const org = "mig117-test-placeholder"
		// Seed the placeholder exactly the way mig 094 does. Insert as table
		// owner (RESET ROLE) so the seed itself isn't gated by RLS.
		if _, err := db.ExecContext(ctx, "RESET ROLE"); err != nil {
			t.Fatalf("reset role for seed: %v", err)
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO organizations (org_id, name, tier, max_nodes, license_key) VALUES ($1,$1,'Community',2,'') ON CONFLICT (org_id) DO NOTHING`,
			org,
		); err != nil {
			t.Fatalf("seed Community placeholder: %v", err)
		}
		if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
			t.Fatalf("re-set app_role: %v", err)
		}
		// Pre-state is the 094 placeholder: Community / 2 / NULL.
		if tier, mn, exp := readOrg117(t, ctx, db, org); tier != "Community" || mn != 2 || exp.Valid {
			t.Fatalf("pre-state not the 094 placeholder: tier=%q max_nodes=%d expires=%v", tier, mn, exp)
		}
		// Promote.
		if _, err := db.ExecContext(ctx,
			`SELECT promote_deployment_org_license($1,$2,$3,$4)`,
			org, "Enterprise", 999999, expiry,
		); err != nil {
			t.Fatalf("promote (update) of placeholder: %v", err)
		}
		tier, mn, exp := readOrg117(t, ctx, db, org)
		if tier != "Enterprise" || mn != 999999 || !exp.Valid || exp.Time.UTC().Format("2006-01-02 15:04:05") != expiryWant {
			t.Fatalf("placeholder NOT promoted: tier=%q max_nodes=%d expires=%v", tier, mn, exp)
		}
	})

	// ========================================================================
	// Pin 3: idempotent — a second promote with the same license is a no-op.
	// ========================================================================
	t.Run("idempotent: re-promote is a no-op", func(t *testing.T) {
		const org = "mig117-test-idem"
		if _, err := db.ExecContext(ctx,
			`SELECT promote_deployment_org_license($1,$2,$3,$4)`,
			org, "Enterprise", 999999, expiry,
		); err != nil {
			t.Fatalf("first promote: %v", err)
		}
		firstUpdated := readOrgUpdatedAt117(t, ctx, db, org)
		// Second promote, identical license. The DO UPDATE ... WHERE distinct
		// guard matches no rows → no write → updated_at unchanged, no error.
		if _, err := db.ExecContext(ctx,
			`SELECT promote_deployment_org_license($1,$2,$3,$4)`,
			org, "Enterprise", 999999, expiry,
		); err != nil {
			t.Fatalf("second promote errored — not idempotent: %v", err)
		}
		secondUpdated := readOrgUpdatedAt117(t, ctx, db, org)
		if !firstUpdated.Equal(secondUpdated) {
			t.Fatalf("updated_at changed on no-op re-promote (flapping): %v -> %v", firstUpdated, secondUpdated)
		}
	})

	// ========================================================================
	// Pin 5: perpetual / no-expiry license — exercises the REAL run.go helper's
	// zero-ExpiresAt → SQL NULL branch (promoteDeploymentOrgTier, run.go), which
	// the other pins never hit. expires_at must persist as NULL, and a
	// re-promote must be a no-op (NULL IS DISTINCT FROM NULL is false).
	// ========================================================================
	t.Run("perpetual license: zero ExpiresAt persists NULL expires_at, idempotent", func(t *testing.T) {
		const org = "mig117-test-perpetual"
		// Call the production helper directly (same package) with a zero
		// time.Time so the nil-argument path is what actually runs.
		promoteDeploymentOrgTier(db, org, "Enterprise", 999999, time.Time{})
		tier, mn, exp := readOrg117(t, ctx, db, org)
		if tier != "Enterprise" || mn != 999999 || exp.Valid {
			t.Fatalf("perpetual promote: tier=%q max_nodes=%d expires=%v (want %s/999999/NULL)", tier, mn, exp, "Enterprise")
		}
		upd1 := readOrgUpdatedAt117(t, ctx, db, org)
		// Re-promote the same perpetual license → WHERE-distinct no-op.
		promoteDeploymentOrgTier(db, org, "Enterprise", 999999, time.Time{})
		upd2 := readOrgUpdatedAt117(t, ctx, db, org)
		if !upd1.Equal(upd2) {
			t.Fatalf("perpetual re-promote flapped updated_at (NULL distinctness bug): %v -> %v", upd1, upd2)
		}
	})

	// ========================================================================
	// Pin 4: mutation proof — SECURITY INVOKER breaks the path under FORCE RLS.
	// (Last, because it ALTERs the function; its cleanup restores SECURITY
	// DEFINER but later pins must not depend on ordering.)
	// ========================================================================
	t.Run("mutation proof: SECURITY INVOKER fails under FORCE RLS", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, "RESET ROLE"); err != nil {
			t.Fatalf("reset role: %v", err)
		}
		// BOTH FUNCTIONS, AND THE POST-142 SIGNATURE.
		//
		// core/175 split this helper: the old name is a VOID forwarder and the
		// body moved to promote_deployment_org_license_returning. Altering the
		// forwarder alone proves nothing -- it delegates to a body that is
		// still SECURITY DEFINER, so the write would succeed and this pin would
		// report "SECURITY DEFINER is not load-bearing" about a mutation that
		// never reached the privileged code. core/142 retyped the fourth
		// parameter to TIMESTAMPTZ, so the TIMESTAMP signature this used to
		// name no longer exists at all.
		for _, sig := range alteredHelperSignatures {
			if _, err := db.ExecContext(ctx, `ALTER FUNCTION `+sig+` SECURITY INVOKER`); err != nil {
				t.Fatalf("ALTER %s SECURITY INVOKER: %v", sig, err)
			}
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(ctx, "RESET ROLE")
			for _, sig := range alteredHelperSignatures {
				_, _ = db.ExecContext(ctx, `ALTER FUNCTION `+sig+` SECURITY DEFINER`)
			}
		})
		if _, err := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); err != nil {
			t.Fatalf("set app_role: %v", err)
		}
		_, err := db.ExecContext(ctx,
			`SELECT promote_deployment_org_license($1,$2,$3,$4)`,
			"mig117-test-invoker", "Enterprise", 999999, expiry,
		)
		if err == nil {
			t.Fatal("promote SUCCEEDED as SECURITY INVOKER under FORCE RLS with no app.current_org_id — SECURITY DEFINER is NOT load-bearing (the fix would be RLS-unsafe)")
		}
	})
}

// readOrg117 reads tier/max_nodes/expires_at for an org. It reads as the table
// OWNER (RESET ROLE) so the SELECT itself isn't gated by FORCE RLS — under
// app_role with no app.current_org_id the org_id=get_current_org_id() USING
// clause would return zero rows even though the row exists. It restores
// axonflow_app_role afterward so subsequent promote calls keep the app-role
// posture the pins assert against.
func readOrg117(t *testing.T, ctx context.Context, db *sql.DB, org string) (string, int, sql.NullTime) {
	t.Helper()
	if _, err := db.ExecContext(ctx, "RESET ROLE"); err != nil {
		t.Fatalf("reset role for read: %v", err)
	}
	var tier string
	var maxNodes int
	var exp sql.NullTime
	err := db.QueryRowContext(ctx,
		`SELECT tier, max_nodes, expires_at FROM organizations WHERE org_id=$1`, org,
	).Scan(&tier, &maxNodes, &exp)
	if _, e := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); e != nil {
		t.Fatalf("restore app_role after read: %v", e)
	}
	if err == sql.ErrNoRows {
		t.Fatalf("org %q not found", org)
	}
	if err != nil {
		t.Fatalf("read org %q: %v", org, err)
	}
	return tier, maxNodes, exp
}

// readOrgUpdatedAt117 reads organizations.updated_at as the table owner (same
// RLS rationale as readOrg117).
func readOrgUpdatedAt117(t *testing.T, ctx context.Context, db *sql.DB, org string) time.Time {
	t.Helper()
	if _, err := db.ExecContext(ctx, "RESET ROLE"); err != nil {
		t.Fatalf("reset role for read: %v", err)
	}
	var updated time.Time
	err := db.QueryRowContext(ctx, `SELECT updated_at FROM organizations WHERE org_id=$1`, org).Scan(&updated)
	if _, e := db.ExecContext(ctx, "SET ROLE axonflow_app_role"); e != nil {
		t.Fatalf("restore app_role after read: %v", e)
	}
	if err != nil {
		t.Fatalf("read updated_at for %q: %v", org, err)
	}
	return updated
}
