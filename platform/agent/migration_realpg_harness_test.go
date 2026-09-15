// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Self-provisioning harnesses for the real-Postgres migration proofs that used
// to take their DSN from the environment (#4034, follow-up to #4021).
//
// # WHY THESE EXIST
//
// Seven migration proofs read `TEST_DATABASE_URL` or `DATABASE_URL` and
// `t.Skip`ped when it was unset. `.github/workflows/migrations-gate.yml` sets
// `TEST_PG_INTEGRATION=1` and deliberately sets NO DSN -- its real-Postgres
// tests are hermetic and start their own container -- so naming these seven in
// the gate would have added seven names that SKIP on every run, and the paired
// `Assert ... actually ran` step would red on a `^--- PASS:` that can never
// appear. They were therefore EXEMPTED from the wiring census with the reason
// "needs a self-provisioning harness before it can be wired".
//
// This file is that harness. Exemptions that name a remedy and are never
// revisited are how a stated gap becomes a permanent one, and a gap that is
// merely DOCUMENTED still runs nowhere on the pull_request tier: the only lane
// that executed these, `Unit Tests: Enterprise-Tagged + Real-PG`, is post-merge.
//
// # THE TWO HARNESSES ARE DIFFERENT BECAUSE THE TWO CLASSES ARE
//
// migrationTestDB serves the four proofs that RESET the schema and apply their
// own range (104, 105/106, 107, 117). They were already hermetic GIVEN a
// superuser database of their own; the database was the only thing missing.
//
// migrationSchemaDB serves the three schema-sanity proofs (076 x2, 082), which
// want the opposite: a database with the chain ALREADY applied, so the
// assertion is about what the migration created. They asserted a table's
// columns and indexes against whatever database the environment pointed at, and
// SKIPPED when the table was absent -- so even handed a live DSN they could
// report a pass-shaped non-result. Against a database the harness itself
// migrated, an absent table is a DEFECT IN THE MIGRATION, which is the only
// thing those tests exist to detect, so the skip is gone and the caller asserts
// presence as a failure.
//
// NEITHER READS A DSN FROM THE ENVIRONMENT. Both own their database outright,
// which is not a preference: see migrationTestDB for the shared-schema
// destruction the first version of this file caused by reusing a helper that
// falls back to DATABASE_URL.

import (
	"database/sql"
	"testing"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/testutil"
)

// migrationTestDB returns a superuser handle on a THROWAWAY database the caller
// may reset.
//
// It resets `public` before returning, which the four callers all did for
// themselves and for the same reason: a previous test's artifacts otherwise
// pollute migration application, and these proofs assert on what a migration
// creates.
//
// `SetMaxOpenConns(1)` is LOAD-BEARING and not tuning. These tests set session
// GUCs (`app.db_password`, `app.deployment_kind`, `app.deployment_org_id`) and
// then apply migrations that read them; with a pool, the apply can land on a
// different connection than the `set_config` did and the migration sees an
// unset value. All four callers set it, one line apart, which is exactly the
// kind of detail that survives four copies until it does not.
func migrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	approletest.SkipUnlessEnabled(t)

	// NO SkipIfNoDocker, DELIBERATELY, AND BOTH HELPERS AGREE ON THAT.
	//
	// This one carried it and migrationSchemaDB did not, because
	// approletest.startPostgresContainer FATALS on a docker failure. An
	// asymmetry inside one file is a decision nobody made, and it was the wrong
	// one on this PR's own terms: the gate already says which behaviour it
	// wants. Its "Verify Docker is available" step exists to `fail LOUDLY
	// rather than let testutil.SkipIfNoDocker silently skip and turn this
	// required check green without having run anything`. Propagating the skip
	// here would push that hazard back down into the tests the job compensates
	// for.
	//
	// SkipUnlessEnabled above is the opt-in and stays: a caller who has not set
	// TEST_PG_INTEGRATION has not asked for a container. A caller who HAS set it
	// and cannot get one has an environment error, not a reason to report a
	// pass-shaped non-result -- which is the same sentence as requireTables
	// below, one level out.
	//
	// A THROWAWAY CONTAINER, NEVER THE ENVIRONMENT'S DSN, and the first
	// version of this file got that wrong in the destructive direction.
	//
	// It called getTestDatabaseURLWithContainer, which returns TEST_DATABASE_URL
	// or DATABASE_URL when either is set and only starts a container otherwise
	// (migration_helpers_test.go:247). Every caller of this helper then runs
	// `DROP SCHEMA public CASCADE` -- correct against a database of its own,
	// catastrophic against a shared one. `Unit Tests: Agent` (test.yml) sets
	// DATABASE_URL to a migrated service Postgres and runs the WHOLE package
	// with no -run, so the three schema-sanity callers, which carry no
	// TEST_PG_INTEGRATION guard of their own, dropped that shared schema
	// mid-run and re-applied a truncated chain over it. Measured on the first
	// head that shipped it: `Unit Tests: Agent` went from success on five
	// consecutive main runs to failure, with 20 "migration 082 not applied"
	// skips and a core/109 function missing from the re-applied prefix.
	//
	// A helper that resets a schema must OWN the database. The guards above
	// are here rather than in the callers for the same reason: safety that
	// depends on every caller remembering is not safety.
	db, err := sql.Open("postgres", testutil.StartPostgres(t, testutil.DefaultPostgresConfig()).URL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("ping test database: %v", err)
	}
	if _, err := db.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		db.Close()
		t.Fatalf("reset public schema: %v", err)
	}
	return db
}

// migrationSchemaDB returns a handle on a database with EVERY CORE migration
// applied, so a schema assertion is a statement about the migration chain
// rather than about whoever last pointed DATABASE_URL somewhere.
//
// CORE ONLY, AND UNFILTERED. approletest.Setup is handed
// `../../migrations/core` and applies every `NNN_*.sql` in it that is not a
// `_down.sql`, in version order, with no DEPLOYMENT_MODE filter and no
// dependency validation. That is the same scope migration 117's fixture had
// before -- core-only -- so moving it here changed the BOUND and not the set of
// directories. It is NOT what TestMigrationChainAppliesCleanly_RealPostgres
// does, which goes through collectMigrations over core plus enterprise,
// mode-filtered, recording schema_migrations; do not borrow that test's
// authority for this helper's coverage.
//
// IT USES approletest.Setup RATHER THAN A BOUND, AND #4034 IS ITS OWN ARGUMENT
// FOR THAT. The first version applied 1..76 and 1..82 -- exactly the shape that
// broke migration 117's fixture, which applied 1..104 and stopped describing
// the product the moment core/175 moved the function it drives. A bounded
// fixture is one somebody has to keep in step with every migration touching its
// subject, and the only thing that would notice the drift is the test.
// approletest's own doc comment says the same thing about its bounded variant,
// having reached 55 migrations of drift once.
//
// Nothing in these assertions wants a historical schema: they ask what
// migration 076 and 082 CREATED, and the answer has to still be true at HEAD or
// it is not a property of the product. Setup also provisions the two login
// roles and sets the same three session GUCs this helper used to set by hand --
// one of which, app.db_password, core/028 reads with
// current_setting(..., false), so a missing value is an error rather than a
// silent empty string.
func migrationSchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	approletest.SkipUnlessEnabled(t)

	env := approletest.Setup(t, "../../migrations/core")
	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("ping master DSN: %v", err)
	}
	return db
}

// requireTables fails -- it does NOT skip -- when a table the migrations should
// have created is absent.
//
// THE SKIP IT REPLACES WAS THE DEFECT, not a safety net. `t.Skipf("... table
// not present (migration 076 not applied?)")` is the correct answer against an
// arbitrary environment DSN and the WRONG one against a database the harness
// just migrated: there, "the table is not there" is the finding. A skip also
// reads as a pass to every counter that matters -- `go test` exits 0, the gate
// sees `ok`, and the paired `--- PASS` assertion is the only thing that would
// have caught it.
func requireTables(t *testing.T, db *sql.DB, tables ...string) {
	t.Helper()
	for _, table := range tables {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT FROM information_schema.tables WHERE table_name = $1
		)`, table).Scan(&exists); err != nil {
			t.Fatalf("look up table %s: %v", table, err)
		} else if !exists {
			t.Fatalf("table %s is absent after the migrations that create it were applied; "+
				"this is a migration defect, which is the only thing this test exists to detect", table)
		}
	}
}
