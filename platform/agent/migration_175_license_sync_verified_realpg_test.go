// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres test for migration 175 (#3957 item 1).
//
// WHAT IT SETTLES, AND WHY IT HAD TO BE A REAL DATABASE.
//
// The fix could have been a SELECT in the agent after the promotion call. That
// rests on a precondition nobody had established: `organizations` carries FORCE
// ROW LEVEL SECURITY (mig 103) - which binds the table OWNER too - under a
// policy keyed on `current_setting('app.current_org_id', true)`, and the agent's
// migration connection never sets that GUC. If the precondition is false, a
// caller-side read-back returns zero rows on a HEALTHY deployment and the agent
// reports "the licensed tier reached nothing" every boot.
//
// It could not be settled by reading the tree. Migrations 146, 148, 149, 151 and
// 165 all read `organizations` unfiltered after 103 applied FORCE RLS, and every
// one of them is silently satisfied by seeing nothing - 146 loops over zero
// organizations, 149 counts zero orphans, 145 only RAISEs a WARNING. Those are
// vacuous negatives.
//
// So this test MEASURES both reads side by side under the real posture:
//
//	Pin 1 - the in-function read (core/175) returns the promoted row.
//	Pin 2 - a CALLER-SIDE read of the same row, on the same connection, in the
//	        same transaction-less session, is compared against it. Whatever it
//	        returns is recorded rather than asserted, because either answer is
//	        informative: zero rows proves the read-back design would have
//	        false-alarmed, and a row proves the concern was unfounded. What the
//	        test ASSERTS is that Pin 1 works regardless - which is the property
//	        the design was chosen for.
//	Pin 3 - the silent-no-op shape: with public.organizations absent the helper
//	        returns ZERO ROWS rather than succeeding silently, which is what the
//	        pre-175 VOID signature did and what the agent logged a tick for.
//	Pin 4 - idempotency: a second promotion with the same licence still reports
//	        the row (the ON CONFLICT ... WHERE distinct guard writes nothing, and
//	        "wrote nothing" must not read as "reached nothing").
//	Pin 5 - mutation proof: SECURITY INVOKER makes Pin 1 stop working, so
//	        SECURITY DEFINER is load-bearing rather than decoration.
//	Pin 6 - the PLANTED POSITIVE for the headline claim (#3957 F5): a BEFORE
//	        trigger forces the stored row to Community while the call asks for
//	        Enterprise, so a helper that READS reports Community and one that
//	        ECHOES ITS ARGUMENTS reports Enterprise. Without it, replacing the
//	        RETURN QUERY with `SELECT p_tier, p_max_nodes, p_expires_at` passed
//	        every other pin here, all the sqlmock tests and the live e2e.
//
// Gated on TEST_PG_INTEGRATION=1, and starts a container when TEST_DATABASE_URL
// is unset - the same shape as the other realpg tests in this package.

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/testutil"
)

// mig175Schema is the minimum of the real migration chain this test needs: the
// organizations table (002), its RLS posture (103) and the roles (098).
//
// It is a SUBSET and says so. Applying all of migrations/core here would make
// the test a migration-runner test rather than a test of this function, and the
// full chain is already covered by the migration runner's own suites. What
// matters is that the three properties the function depends on - the table
// shape, ENABLE + FORCE ROW LEVEL SECURITY, and the org_id policy keyed on a
// GUC nobody sets - are reproduced verbatim from those migrations.
const mig175Schema = `
CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    org_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    license_key VARCHAR(512) NOT NULL,
    tier VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'ACTIVE',
    max_nodes INTEGER NOT NULL DEFAULT 10,
    expires_at TIMESTAMPTZ,
    contact_email VARCHAR(255),
    contact_phone VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- migration 103, verbatim in effect
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organizations_org_id_isolation ON organizations;
CREATE POLICY organizations_org_id_isolation ON organizations
    FOR ALL
    USING (org_id = current_setting('app.current_org_id', true))
    WITH CHECK (org_id = current_setting('app.current_org_id', true));
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

-- migration 094's placeholder seed, which is the value a failed promotion
-- leaves behind and the one this whole issue is about.
INSERT INTO organizations (org_id, name, license_key, tier, max_nodes)
VALUES ('org-3957-realpg', 'org-3957-realpg', '', 'Community', 2)
ON CONFLICT (org_id) DO NOTHING;
`

func mig175OpenDB(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres test")
	}
	// SetMaxOpenConns(1) ON EVERY PATH. `set_config(..., false)` and `SET ROLE`
	// are SESSION state, and database/sql hands out an arbitrary pooled
	// connection per call - so on a pool of two, the SET ROLE and the statement
	// it was meant to constrain can land on different sessions and the test
	// silently measures the wrong role. The 117 sibling pins this
	// (migration_117_promote_org_license_test.go:50); this test did not, which
	// is a real deviation even though it happened to fail RED rather than
	// vacuous.
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		db, err := sql.Open("postgres", url)
		if err != nil {
			t.Fatalf("open TEST_DATABASE_URL: %v", err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.DB.SetMaxOpenConns(1)
	return pg.DB
}

// applyMig175 installs the schema subset and the real 175 function body, read
// FROM THE MIGRATION FILE rather than restated here.
//
// Reading the file is the point: a copy of the function in this test would
// certify a body that no deployment applies, which is the "fixture that encodes
// a shape the writer never emits" failure. If the migration is edited and this
// test still passes, it passed against the edit.
func applyMig175(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(mig175Schema); err != nil {
		t.Fatalf("apply schema subset: %v", err)
	}
	sqlBytes, err := os.ReadFile("../../migrations/core/175_promote_deployment_org_license_reports_the_row.sql")
	if err != nil {
		t.Fatalf("read migration 175: %v", err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("apply migration 175: %v", err)
	}
}

func TestMigration175_PromotionReportsTheRowUnderForceRLS(t *testing.T) {
	db := mig175OpenDB(t)
	applyMig175(t, db)

	const orgID = "org-3957-realpg"
	expiry := time.Date(2028, 4, 5, 6, 7, 8, 0, time.UTC)

	// PRECONDITION, asserted rather than assumed: the row starts at migration
	// 094's Community placeholder. Read as the owner with the GUC set, so this
	// preflight cannot itself be defeated by RLS - a preflight that returned
	// nothing would make every assertion below vacuous.
	if _, err := db.Exec("SELECT set_config('app.current_org_id', $1, false)", orgID); err != nil {
		t.Fatalf("set the org GUC for the preflight: %v", err)
	}
	var preTier string
	var preNodes int
	if err := db.QueryRow("SELECT tier, max_nodes FROM organizations WHERE org_id = $1", orgID).
		Scan(&preTier, &preNodes); err != nil {
		t.Fatalf("preflight read of the placeholder row: %v", err)
	}
	if preTier != "Community" || preNodes != 2 {
		t.Fatalf("the fixture row is %s/%d, expected the migration-094 placeholder Community/2", preTier, preNodes)
	}

	// Now CLEAR the GUC. This is the agent's real posture: setMigrationSessionVars
	// sets app.db_password, app.deployment_org_id and app.deployment_kind, and
	// never app.current_org_id, so the policy's USING clause evaluates against
	// NULL for the whole boot.
	if _, err := db.Exec("SELECT set_config('app.current_org_id', '', false)"); err != nil {
		t.Fatalf("clear the org GUC: %v", err)
	}

	// ---- Pin 1: the in-function read returns the promoted row ----
	got, gotRow, err := promoteAndReadDeploymentOrgLicense(db, orgID,
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50, ExpiresAt: expiry})
	if err != nil {
		t.Fatalf("Pin 1: the promotion call failed: %v", err)
	}
	if !gotRow {
		t.Fatal("Pin 1: core/175 returned NO ROWS with public.organizations present and the row " +
			"promoted. The in-function read does not have the write's visibility, which is the one " +
			"property this migration exists to provide.")
	}
	if got.Tier != "Enterprise" || got.MaxNodes != 50 {
		t.Errorf("Pin 1: the helper reported %s/%d, expected Enterprise/50", got.Tier, got.MaxNodes)
	}
	if !sameExpiry(got.ExpiresAt, expiry) {
		t.Errorf("Pin 1: the helper reported expiry %s, expected %s", got.ExpiresAt, expiry)
	}

	// ---- Pin 2: what a CALLER-SIDE read would have returned ----
	//
	// RECORDED, NOT ASSERTED, and deliberately so. This is the measurement the
	// design decision rested on and could not get from source. Either answer is
	// informative and neither changes whether Pin 1 is correct, so asserting
	// one would be asserting a fact about this container's role setup rather
	// than about the platform.
	var callerTier string
	callerErr := db.QueryRow("SELECT tier FROM organizations WHERE org_id = $1", orgID).Scan(&callerTier)
	switch {
	case callerErr == sql.ErrNoRows:
		t.Logf("Pin 2 [MEASURED]: a caller-side SELECT with no app.current_org_id returns ZERO ROWS "+
			"under FORCE RLS. A read-back in the agent would have reported %q as unpromoted on every "+
			"healthy boot; moving the read inside the SECURITY DEFINER function is what avoids that.",
			orgID)
	case callerErr != nil:
		t.Logf("Pin 2 [MEASURED]: a caller-side SELECT errored: %v", callerErr)
	default:
		t.Logf("Pin 2 [MEASURED]: a caller-side SELECT DOES see the row (tier=%q) — this role bypasses "+
			"FORCE RLS, so on a deployment with this posture a caller-side read-back would also have "+
			"worked. The in-function read is still the safe choice: it does not depend on which role "+
			"the deployment's DATABASE_URL authenticates as.", callerTier)
	}

	// ---- Pin 4: idempotency. "wrote nothing" must not read as "reached nothing" ----
	got2, gotRow2, err := promoteAndReadDeploymentOrgLicense(db, orgID,
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50, ExpiresAt: expiry})
	if err != nil {
		t.Fatalf("Pin 4: the second promotion failed: %v", err)
	}
	if !gotRow2 || got2.Tier != "Enterprise" || got2.MaxNodes != 50 {
		t.Errorf("Pin 4: a re-promotion with the same licence reported row=%v %s/%d. The ON CONFLICT "+
			"... WHERE distinct guard correctly writes nothing here, and the RETURN QUERY must still "+
			"report the row - otherwise every steady-state boot would look like a failure.",
			gotRow2, got2.Tier, got2.MaxNodes)
	}
	if s := verifyLicenseSync(licenseSyncValues{Tier: "Enterprise", MaxNodes: 50, ExpiresAt: expiry},
		got2, gotRow2, nil); !s.Verified {
		t.Errorf("Pin 4: a steady-state re-boot reported unverified: %s", s.Reason)
	}
}

// TestMigration175_SecurityDefinerIsLoadBearing is the mutation proof (Pin 5).
//
// It runs in its own container because it mutates the function. Without it,
// Pin 1 above could pass on a role that bypasses RLS anyway, and SECURITY
// DEFINER would be decoration nobody had tested.
func TestMigration175_SecurityDefinerIsLoadBearing(t *testing.T) {
	db := mig175OpenDB(t)
	applyMig175(t, db)

	const orgID = "org-3957-realpg"
	want := licenseSyncValues{Tier: "Enterprise", MaxNodes: 50}

	// A non-owner role, which is the posture the GRANT in 117/142/175 exists for
	// and the one the 117 test uses.
	for _, stmt := range []string{
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'axonflow_app_role')
		   THEN CREATE ROLE axonflow_app_role NOLOGIN NOBYPASSRLS; END IF; END $$;`,
		`GRANT USAGE ON SCHEMA public TO axonflow_app_role`,
		`GRANT SELECT, INSERT, UPDATE ON organizations TO axonflow_app_role`,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO axonflow_app_role`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("prepare app_role: %v (%s)", err, stmt)
		}
	}
	if _, err := db.Exec("SELECT set_config('app.current_org_id', '', false)"); err != nil {
		t.Fatalf("clear the org GUC: %v", err)
	}

	// THE CONTROL FIRST: as app_role, with SECURITY DEFINER intact, the promotion
	// works. Asserted before the mutation, because a mutation whose "after" fails
	// for an unrelated reason proves nothing.
	if _, err := db.Exec("SET ROLE axonflow_app_role"); err != nil {
		t.Fatalf("SET ROLE: %v", err)
	}
	// The control below is only about app_role if we are actually app_role.
	approletest.AssertCurrentUser(t, db, "axonflow_app_role")
	got, gotRow, err := promoteAndReadDeploymentOrgLicense(db, orgID, want)
	if err != nil || !gotRow || got.Tier != "Enterprise" {
		t.Fatalf("control: as axonflow_app_role with SECURITY DEFINER intact the promotion did not "+
			"land (err=%v row=%v tier=%q). The mutation below would then prove nothing.",
			err, gotRow, got.Tier)
	}
	if _, err := db.Exec("RESET ROLE"); err != nil {
		t.Fatalf("RESET ROLE: %v", err)
	}

	// THE MUTATION, verified applied before its effect is believed.
	if _, err := db.Exec(
		`ALTER FUNCTION promote_deployment_org_license_returning(VARCHAR, VARCHAR, INTEGER, TIMESTAMPTZ) SECURITY INVOKER`,
	); err != nil {
		t.Fatalf("apply the SECURITY INVOKER mutation: %v", err)
	}
	var secdef bool
	if err := db.QueryRow(
		`SELECT prosecdef FROM pg_proc WHERE proname = 'promote_deployment_org_license_returning'
		   AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname='public')`,
	).Scan(&secdef); err != nil {
		t.Fatalf("read prosecdef back: %v", err)
	}
	if secdef {
		t.Fatal("the SECURITY INVOKER mutation did not apply (prosecdef is still true); a red below " +
			"would be unattributable and a green would be meaningless")
	}

	if _, err := db.Exec("SET ROLE axonflow_app_role"); err != nil {
		t.Fatalf("SET ROLE after mutation: %v", err)
	}
	approletest.AssertCurrentUser(t, db, "axonflow_app_role")
	defer func() { _, _ = db.Exec("RESET ROLE") }()

	mutGot, mutRow, mutErr := promoteAndReadDeploymentOrgLicense(db, orgID,
		licenseSyncValues{Tier: "Professional", MaxNodes: 9})
	if mutErr == nil && mutRow && mutGot.Tier == "Professional" {
		t.Error("with SECURITY INVOKER the promotion STILL landed and reported as axonflow_app_role. " +
			"FORCE RLS on organizations is then not actually constraining this role, so SECURITY " +
			"DEFINER is not load-bearing here and the whole privilege argument in mig 117/142/175 " +
			"needs rewriting rather than repeating.")
	} else {
		t.Logf("Pin 5 confirmed: with SECURITY INVOKER the same call as axonflow_app_role fails or "+
			"reports nothing (err=%v row=%v tier=%q), so SECURITY DEFINER is load-bearing.",
			mutErr, mutRow, mutGot.Tier)
	}
}

// TestMigration175_NoOrganizationsTableReturnsZeroRows is Pin 3: the shape the
// pre-175 VOID signature reported as success.
func TestMigration175_NoOrganizationsTableReturnsZeroRows(t *testing.T) {
	db := mig175OpenDB(t)
	applyMig175(t, db)

	// Drop the table the function writes. The helper's guard must then report
	// zero rows rather than returning successfully having written nothing -
	// which is exactly what the old signature did, and what the agent logged a
	// tick for.
	if _, err := db.Exec("DROP TABLE organizations CASCADE"); err != nil {
		t.Fatalf("drop organizations: %v", err)
	}

	got, gotRow, err := promoteAndReadDeploymentOrgLicense(db, "org-3957-realpg",
		licenseSyncValues{Tier: "Enterprise", MaxNodes: 50})
	if err != nil {
		// An error is an acceptable answer too - it is reported as a failed
		// promotion either way. What must NOT happen is a silent success.
		t.Logf("Pin 3: with no organizations table the call errored (%v), which the agent reports as "+
			"a failed promotion", err)
		return
	}
	if gotRow {
		t.Fatalf("Pin 3: with no organizations table the helper reported a row (%s/%d). The "+
			"table-exists guard is meant to make this state observable as zero rows; a row here "+
			"means it is fabricating one.", got.Tier, got.MaxNodes)
	}
	s := verifyLicenseSync(licenseSyncValues{Tier: "Enterprise", MaxNodes: 50}, got, gotRow, nil)
	if s.Verified {
		t.Fatal("Pin 3: a schema with no organizations table reported a VERIFIED licence sync. This " +
			"is the pre-175 behaviour: the VOID helper returned success, db.Exec saw no error, and " +
			"the agent logged a tick for a write that never happened.")
	}
}

// TestMigration175_ReportsTheRowNotItsArguments is the planted positive for this
// PR's headline claim, and it did not exist.
//
// "The helper reports the row it wrote" was unfalsified by the entire suite:
// mutating the migration's RETURN QUERY to
//
//	RETURN QUERY SELECT p_tier, p_max_nodes, p_expires_at;
//
// passes every other pin here, all eight sqlmock tests, and the live e2e -
// because in all of them the argument and the stored row are the same values,
// so echoing the input is indistinguishable from reading the row. Found by R3.
//
// The discriminator is a row that DIFFERS from what was passed. A BEFORE
// trigger rewrites the write, so the stored tier is Community while the call
// asked for Enterprise: a helper that reads reports Community, a helper that
// echoes reports Enterprise. Nothing else in the suite can tell those apart.
func TestMigration175_ReportsTheRowNotItsArguments(t *testing.T) {
	db := mig175OpenDB(t)
	applyMig175(t, db)

	const orgID = "org-3957-realpg"

	// Rewrite every write to organizations. Deliberately NOT a RULE or a
	// permission trick: a BEFORE trigger leaves the INSERT/UPDATE succeeding, so
	// the helper's own control flow is untouched and only the STORED value
	// diverges from the argument.
	if _, err := db.Exec(`
CREATE OR REPLACE FUNCTION mig175_force_community() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    NEW.tier := 'Community';
    NEW.max_nodes := 2;
    RETURN NEW;
END
$fn$;
DROP TRIGGER IF EXISTS mig175_force_community ON organizations;
CREATE TRIGGER mig175_force_community
    BEFORE INSERT OR UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION mig175_force_community();`); err != nil {
		t.Fatalf("install the rewriting trigger: %v", err)
	}

	// VERIFY THE PLANT IS ACTUALLY IN PLACE before believing anything it implies
	// - a trigger that failed to attach would make this test pass vacuously.
	var trigCount int
	if err := db.QueryRow(`SELECT count(*) FROM pg_trigger
		WHERE tgname = 'mig175_force_community' AND NOT tgisinternal`).Scan(&trigCount); err != nil {
		t.Fatalf("read the trigger back: %v", err)
	}
	if trigCount != 1 {
		t.Fatalf("the rewriting trigger is not installed (count=%d); this test would pass without discriminating anything", trigCount)
	}

	want := licenseSyncValues{Tier: "Enterprise", MaxNodes: 50}
	got, gotRow, err := promoteAndReadDeploymentOrgLicense(db, orgID, want)
	if err != nil {
		t.Fatalf("the promotion call failed: %v", err)
	}
	if !gotRow {
		t.Fatal("no row reported with organizations present and writable")
	}

	// THE ASSERTION. Enterprise here means the helper echoed its arguments.
	if got.Tier == want.Tier || got.MaxNodes == want.MaxNodes {
		t.Errorf("the helper reported tier=%q max_nodes=%d, which is exactly what was PASSED IN, "+
			"while a trigger forced the stored row to Community/2. The function is echoing its "+
			"arguments rather than reporting the row it wrote - which is this migration's entire "+
			"claim and its title.", got.Tier, got.MaxNodes)
	}
	if got.Tier != "Community" || got.MaxNodes != 2 {
		t.Errorf("the helper reported %s/%d; the stored row is Community/2 and that is what reading it returns",
			got.Tier, got.MaxNodes)
	}

	// And the consequence the agent draws from it must be "not verified".
	if s := verifyLicenseSync(want, got, gotRow, nil); s.Verified {
		t.Error("a row holding Community/2 against an Enterprise/50 licence was reported VERIFIED")
	}
}

// TestMigration175_TheOldNameStaysVoidAndForwards is #4007's shape guard.
//
// 175 originally redefined 142's OWN signature with a new RETURN TYPE. That
// made migration 142 un-re-runnable at the fully-migrated state -- `CREATE OR
// REPLACE ... RETURNS VOID` over a set-returning function raises "cannot change
// return type of existing function" -- and seven migration tests in this
// package re-run their migration's up and down at exactly that state, because
// that is what this repository means by idempotent and what makes a `_down`
// usable for incident rollback at the CURRENT schema.
//
// THE TWO SHAPE ASSERTIONS BELOW ARE OPPOSITES ON PURPOSE, AND THAT PAIR IS THE
// GUARD AGAINST A FUTURE TIDY-UP. `_returning` must return a set; the old name
// must NOT. They look like an inconsistency and they are the contract: an edit
// that makes the two functions the same shape breaks one of them, and this pair
// is what says so rather than leaving it to be rediscovered by a red migration
// on an upgrade path nobody runs.
//
// SCOPE, STATED SO THIS IS NOT MISTAKEN FOR THE WHOLE PROOF. This test runs
// against applyMig175's schema SUBSET, not a fully-migrated database, so it
// cannot re-run 142 -- 142's up touches tables the subset does not have. The
// re-run property is owned by
// TestMigration142_TimestampColumnsToTimestamptz_RealPostgres, which applies
// every core migration and then re-runs 142; that
// test is what #4007 broke and what proves it fixed. What THIS test pins is the
// shape that makes the re-run possible, at the point 175 itself establishes it.
func TestMigration175_TheOldNameStaysVoidAndForwards(t *testing.T) {
	db := mig175OpenDB(t)
	applyMig175(t, db)

	var forwarderRetType string
	var forwarderRetSet bool
	if err := db.QueryRow(
		`SELECT pg_catalog.format_type(prorettype, NULL), proretset FROM pg_proc
		   WHERE proname = 'promote_deployment_org_license'
		     AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname='public')`,
	).Scan(&forwarderRetType, &forwarderRetSet); err != nil {
		t.Fatalf("read the forwarder's return type: %v", err)
	}
	if forwarderRetSet || forwarderRetType != "void" {
		t.Errorf("promote_deployment_org_license must stay RETURNS VOID at 142's signature, got rettype=%q retset=%v.\n"+
			"Re-running migration 142 then raises \"cannot change return type of existing function\" (#4007).",
			forwarderRetType, forwarderRetSet)
	}

	var returningRetSet bool
	if err := db.QueryRow(
		`SELECT proretset FROM pg_proc
		   WHERE proname = 'promote_deployment_org_license_returning'
		     AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname='public')`,
	).Scan(&returningRetSet); err != nil {
		t.Fatalf("promote_deployment_org_license_returning must exist - it carries the body: %v", err)
	}
	if !returningRetSet {
		t.Error("promote_deployment_org_license_returning must return a set; it is the one the agent reads the row from")
	}

	// THE FORWARDER MUST STILL PROMOTE. Two names with the right shapes and a
	// forwarder that writes nothing would satisfy every assertion above while
	// silently breaking every caller of the old name.
	const orgID = "org-4007-forwarder"
	if _, err := db.Exec("SELECT set_config('app.current_org_id', $1, false)", orgID); err != nil {
		t.Fatalf("set the org GUC: %v", err)
	}
	if _, err := db.Exec(
		`SELECT promote_deployment_org_license($1, $2, $3, $4)`,
		orgID, "enterprise", 42, nil,
	); err != nil {
		t.Fatalf("the old name must still promote through the forwarder: %v", err)
	}
	var tier string
	var maxNodes int
	if err := db.QueryRow(
		`SELECT tier, max_nodes FROM organizations WHERE org_id = $1`, orgID,
	).Scan(&tier, &maxNodes); err != nil {
		t.Fatalf("read back the row the forwarder promoted: %v", err)
	}
	if tier != "enterprise" || maxNodes != 42 {
		t.Errorf("the forwarder wrote tier=%q max_nodes=%d, want enterprise/42 - it is not reaching the body", tier, maxNodes)
	}

	// THE DOWN MIGRATION, EXECUTED (#4007 review). Nothing else in this
	// repository runs 175_down: this test applied only the up, and the
	// migration-chain helpers skip `_down.sql` by design. That gap is not
	// theoretical - the down carried the SAME unqualified COMMENT ON FUNCTION
	// that made the up fail on the upgrade path, and it was found by reading
	// rather than by any test failing.
	//
	// Rollback must leave the schema as 142 left it: the _returning function
	// gone, the old name present and VOID, and EXACTLY ONE function of that
	// name - a down that dropped one overload and left another would satisfy
	// the first two checks and still be the ambiguity this issue is about.
	downSQL, err := os.ReadFile("../../migrations/core/175_promote_deployment_org_license_reports_the_row_down.sql")
	if err != nil {
		t.Fatalf("read 175 down: %v", err)
	}
	if _, err := db.Exec(string(downSQL)); err != nil {
		t.Fatalf("applying 175's down migration must succeed: %v", err)
	}

	var returningCount int
	if err := db.QueryRow(
		`SELECT count(*) FROM pg_proc
		   WHERE proname = 'promote_deployment_org_license_returning'
		     AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname='public')`,
	).Scan(&returningCount); err != nil {
		t.Fatalf("count _returning after down: %v", err)
	}
	if returningCount != 0 {
		t.Errorf("175's down left %d promote_deployment_org_license_returning function(s); it is 175's own creation and rollback must remove it", returningCount)
	}

	var oldCount int
	var oldRetType string
	if err := db.QueryRow(
		`SELECT count(*), coalesce(max(pg_catalog.format_type(prorettype, NULL)), '') FROM pg_proc
		   WHERE proname = 'promote_deployment_org_license'
		     AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname='public')`,
	).Scan(&oldCount, &oldRetType); err != nil {
		t.Fatalf("count the old name after down: %v", err)
	}
	if oldCount != 1 {
		t.Errorf("after 175's down there must be EXACTLY ONE promote_deployment_org_license, found %d - two overloads is the state that makes an unqualified reference ambiguous, which is mechanism 1 of #4007", oldCount)
	}
	if oldRetType != "void" {
		t.Errorf("after 175's down the old name must be RETURNS VOID as 142 leaves it, got %q", oldRetType)
	}

	// AND UP AGAIN, so the pair is proven re-applicable rather than one-way.
	upSQL, err := os.ReadFile("../../migrations/core/175_promote_deployment_org_license_reports_the_row.sql")
	if err != nil {
		t.Fatalf("read 175 up: %v", err)
	}
	if _, err := db.Exec(string(upSQL)); err != nil {
		t.Fatalf("re-applying 175's up after its own down must succeed: %v", err)
	}
}
