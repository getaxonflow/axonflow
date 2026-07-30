// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// "Migrations apply cleanly" — the gate #3002 asks for.
//
// # WHY THIS EXISTS
//
// Migration core/148 merged in a state that ABORTS on apply
// ("Migration 148 failed: N system role(s) not reconciled"), crash-looping the
// agent on any stack that runs the chain. main was broken until #2999.
//
// CI did catch it — the `E2E Production-Posture (axonflow_app_role)` job failed
// on that exact error — but that job is not in the required check set, so the
// merge queue merged the PR while it was red. Nothing in the REQUIRED set runs
// the migration chain: unit, lint and build jobs never touch a database, and
// the realpg tests that do skip without Docker.
//
// This test closes that gap. It is deliberately cheap — a Postgres container
// and the SQL chain, no compose stack, no image build, no application boot — so
// it can be promoted into the required set without the ~9-minute cost of the
// full E2E job.
//
// # FAITHFULNESS
//
// It drives the REAL runner sequence from run.go, reusing the same
// package-level functions in the same order — collectMigrations (ordering +
// the same-version Name tiebreak), validateMigrationDependencies,
// ensureSchemaMigrationsTable, setMigrationSessionVars (the app.db_password /
// app.deployment_org_id / app.deployment_kind GUCs that several migrations read
// via current_setting), substituteGrafanaPassword and the per-file Exec. A
// hand-rolled `psql -f` loop would not: it would miss the ordering rules and
// the session variables, and three migrations abort without them.
//
// It runs every DEPLOYMENT_MODE, because getMigrationPaths selects a DIFFERENT
// migration set per mode — a migration that aborts only in in-vpc-banking is
// exactly as catastrophic and exactly as invisible.
package agent

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// Every RECOGNISED DEPLOYMENT_MODE spelling — canonical names plus the
// `enterprise` / `invpc` aliases — with "" for unset (which still resolves to
// community here; see #3128 and getMigrationPaths).
//
// Derived from recognisedDeploymentModes() rather than hand-listed. The literal
// this replaced predated #3167 and therefore omitted `enterprise`, which is the
// value our own docker-compose.enterprise.yml has always defaulted to: the one
// mode string most likely to reach a customer's database was the one this
// chain never applied. Since an unrecognised value is now refused outright,
// there is no longer an "unknown mode" set to cover separately.
func migrationChainModes() []string {
	return append([]string{""}, recognisedDeploymentModes()...)
}

func TestMigrationChainAppliesCleanly_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	if _, err := os.Stat(migrationsPath); err != nil {
		t.Fatalf("migrations directory not found at %s: %v", migrationsPath, err)
	}

	for _, mode := range migrationChainModes() {
		label := mode
		if label == "" {
			label = "unset(resolves-to-community — see #3128)"
		}
		t.Run(label, func(t *testing.T) {
			// A FRESH database per mode. The bug class this guards is
			// "aborts when the chain runs", which only reproduces from a
			// clean slate — against an already-migrated DB every file is
			// skipped as applied and the abort never fires.
			pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
			t.Setenv("DEPLOYMENT_MODE", mode)

			applyChain(t, pc.DB, migrationsPath)
		})
	}
}

// TestMigrationChainAppliesOnSeededLegacyData_RealPostgres is the SEEDED-DATA
// leg (#3002).
//
// The fresh-database leg above cannot catch a migration that aborts on a data
// shape a PREVIOUS release created — and that is not hypothetical: migration
// 150 shipped in this very PR with a repair predicate narrower than its own
// verification predicate, so a row migration 149's drift trigger creates was
// invisible to the repair and fatal to the verification. The chain rolled back,
// was never recorded, and re-ran on the next boot; run.go log.Fatalf's on a
// failed migration, so that is a permanent agent crash-loop.
//
// The fresh-DB leg was green throughout, because on a clean slate the shape
// never exists. "Migrations apply cleanly" is only a real gate if it also
// applies them to data that is already there.
//
// So: run the chain up to (but excluding) 150, seed the 149-era shapes a real
// deployment would be carrying, then let the rest of the chain run.
func TestMigrationChainAppliesOnSeededLegacyData_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	// core-only: 148/149/150 all live in core, and this keeps the version
	// cutoff below from also truncating the independently-numbered
	// enterprise/ and industry/ categories.
	t.Setenv("DEPLOYMENT_MODE", "community")

	// 1. The pre-150 world.
	ranBefore, _ := applyChainUpTo(t, pc.DB, migrationsPath, 150)
	if ranBefore == 0 {
		t.Fatal("applied 0 migrations before the cutoff — the seed would be meaningless")
	}

	// 2. Seed the shapes a 149-era deployment actually carries. Each is built
	//    through the REAL 149 triggers/choke point, never by hand-writing rows
	//    — a hand-written row is a guess about what 149 did; this is what it
	//    does.
	seedLegacyOwnerShapes(t, pc.DB, true)

	// 3. The rest of the chain, including 150, must apply on top of that.
	applyChain(t, pc.DB, migrationsPath)
}

// seedLegacyOwnerShapes creates the pre-150 owner-grant shapes.
//
// Used on a database that has run 149 but not 150 (the seeded leg), and on one
// that has run the WHOLE chain (the replay leg) — hence the ON CONFLICT DO
// NOTHING on the explicit assignment inserts: on an already-migrated database
// migration 150 has already canonicalized the row this seeds, and the shape
// under test is "such a row exists", not "this statement created it".
func seedLegacyOwnerShapes(t *testing.T, db *sql.DB, requireDivergent bool) {
	t.Helper()

	mustExecChain := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}

	// (a) MIXED-CASE contact_email. The 149 org-creation trigger keys the
	//     owner grant on the RAW column value, so the stored key is
	//     'Ops@Example.com' while the post-#3000 login presents
	//     'ops@example.com'.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-mixedcase', 'Seed MixedCase', 'Ops@Example.com', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)

	// (b) DRIFT: the operator later normalizes the column. 149's
	//     reseed_org_owner_on_contact_change trigger ADDS a grant on the new
	//     identity and never deletes the old one, leaving a stale row whose
	//     canonical form equals the login identity but which is NOT byte-equal
	//     to the current raw column. This is the shape that boot-looped 150.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-drift', 'Seed Drift', 'Ops@Example.com', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`UPDATE organizations SET contact_email = 'ops@example.com'
	                WHERE org_id = 'seed-drift'`)

	// (b2) DRIFT BETWEEN TWO *NON*-CANONICAL SPELLINGS. The killer shape, and
	//      the one case (b) cannot produce: drifting 'Ops@Example.com' ->
	//      'ops@Example.com' leaves TWO raw rows that canonicalize identically
	//      and NEITHER is canonical. A "does a canonical twin already exist"
	//      test sees nothing to do, and the re-key UPDATE then rewrites both
	//      onto the same (org_id, user_email, role_id) — duplicate key
	//      violation, migration rolls back, agent boot-loops.
	//
	//      One case-only edit by an operator is enough to create it.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-drift2', 'Seed Drift2', 'Ops@Example.com', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`UPDATE organizations SET contact_email = 'ops@Example.com'
	                WHERE org_id = 'seed-drift2'`)

	// (b3) Three-deep, with whitespace in the mix, to prove the collapse is
	//      general rather than tuned to pairs.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-drift3', 'Seed Drift3', 'Ops@Three.example', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`UPDATE organizations SET contact_email = '  OPS@Three.example  ' WHERE org_id = 'seed-drift3'`)
	mustExecChain(`UPDATE organizations SET contact_email = 'OPS@three.EXAMPLE' WHERE org_id = 'seed-drift3'`)

	// (b4) A NON-SYSTEM row already holding the canonical key (R3 pass 2, F1).
	//      The unique constraint (org_id, user_email, role_id) has no `source`
	//      column, so a collapse that ranks only source='system' rows leaves an
	//      ordinary portal grant ('manual', the column DEFAULT) as a live
	//      collision target for the re-key UPDATE. Two steps, both ordinary:
	//      149's trigger writes the system row on a mixed-case contact_email,
	//      then the operator grants owner to the lowercase address via the
	//      portal RBAC API.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-manual', 'Seed Manual', 'Ops@Example.com', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, source)
	               SELECT 'seed-manual', 'ops@example.com', id, 'portal', 'manual'
	                 FROM custom_roles
	                WHERE org_id = 'seed-manual' AND name = 'owner' AND is_system
	               ON CONFLICT (org_id, user_email, role_id) DO NOTHING`)

	// (b5) An EXPIRED duplicate holding the canonical key while the live grant
	//      is the raw one. The collapse must keep the LIVE row (an expired row
	//      confers nothing — every permission read filters expires_at) and must
	//      still free the canonical key for the re-key.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-expired', 'Seed Expired', 'Ops@Exp.example', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, source, expires_at)
	               SELECT 'seed-expired', 'ops@exp.example', id, 'system', 'system', NOW() - INTERVAL '1 day'
	                 FROM custom_roles
	                WHERE org_id = 'seed-expired' AND name = 'owner' AND is_system
	               ON CONFLICT (org_id, user_email, role_id) DO NOTHING`)

	// (b6) UNICODE WHITESPACE in contact_email (R3 pass 2, F2). Go's
	//      strings.TrimSpace strips NBSP and tab; SQL btrim() with no second
	//      argument strips ASCII space only. If the two disagree the migration
	//      "repairs" the row into a form the login can never present — a silent
	//      lockout that its own verification accepts.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-nbsp', 'Seed NBSP', E'\u00A0Ops@Example.com', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-tab', 'Seed Tab', E'\tOps@Example.com', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)

	// (b7) A QUALIFIER (admin) keyed on a UNICODE-WHITESPACE address, and NOT
	//      itself an owner row. This is the shape that separates
	//      lower(btrim(...)) from axonflow_canonical_email(...) in migration
	//      149's completeness check:
	//
	//        backfill stores  axonflow_canonical_email(x)  -> NBSP stripped
	//        check compares   lower(btrim(x))              -> NBSP kept
	//
	//      so the check cannot see the owner row it just created and raises
	//      "N principal(s) held sso:configure pre-upgrade but hold no owner
	//      role" — a hand re-run of 149 aborts, and run.go turns that into a
	//      boot loop. A qualifier that is ALSO an owner row self-satisfies the
	//      check and hides the defect, which is why this row must carry a
	//      NON-owner role.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-nbsp-admin', 'Seed NBSP Admin', 'org@nbspadmin.example', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, source)
	               SELECT 'seed-nbsp-admin', E'\u00A0Admin.Person@Corp.example', id, 'portal', 'manual'
	                 FROM custom_roles
	                WHERE org_id = 'seed-nbsp-admin' AND name = 'admin' AND is_system
	               ON CONFLICT (org_id, user_email, role_id) DO NOTHING`)

	// (c) Surrounding WHITESPACE — the other way a raw key diverges from its
	//     canonical form without any case difference.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-space', 'Seed Space', '  ops@space.example  ', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)

	// (d) A pre-150 BREAK-GLASS / portal-bootstrap grant keyed on the EMPTY
	//     identity — legal before 150, and exactly what 150 must clean up
	//     rather than trip over. Written through the 149 choke point, which
	//     still accepts '' at this point in the chain.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-blank', 'Seed Blank', NULL, 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`SELECT ensure_org_owner_assignment('seed-blank', '', 'system:portal-bootstrap')`)

	// (e) A pre-150 break-glass grant on a mixed-case named identity that is
	//     NOT the org's login identity. 150 must leave it alone: it is an
	//     operator's deliberate act, and re-keying it would silently change
	//     who holds owner.
	mustExecChain(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	               VALUES ('seed-bg', 'Seed BreakGlass', 'org@bg.example', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChain(`SELECT ensure_org_owner_assignment('seed-bg', 'Named.Person@Corp.example', 'break-glass:admin')`)

	// Sanity: the seed produced the divergent shape the gate exists to cover.
	var divergent int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM role_assignments ra
		JOIN organizations o ON o.org_id = ra.org_id
		WHERE ra.source = 'system'
		  AND ra.user_email <> lower(btrim(ra.user_email))`).Scan(&divergent); err != nil {
		t.Fatalf("seed sanity check: %v", err)
	}
	// Only meaningful BEFORE migration 150 has run. On the replay leg the whole
	// chain is already applied, so 150 has canonicalized these rows and zero
	// divergent rows is the correct, expected state.
	if requireDivergent && divergent == 0 {
		t.Fatal("seed produced no non-canonically-keyed system grant — the seeded leg would be vacuous")
	}
	t.Logf("seeded %d non-canonically-keyed system owner grant(s) plus a blank-keyed grant", divergent)
}

// applyChain mirrors the migration block of run.go against db, failing the test
// on the first migration that aborts. Returns (ran, skipped).
//
// It records success in schema_migrations exactly as the runner does. That
// matters: without the record, a second pass would re-execute every file
// against an already-populated database, which is NOT what a real boot does
// (the runner skips applied files) and would fail on migrations that were never
// written to be re-runnable — a harness artifact, not a production defect.
func applyChain(t *testing.T, db *sql.DB, migrationsPath string) (int, int) {
	t.Helper()
	return applyChainUpTo(t, db, migrationsPath, 0)
}

// applyChainUpTo is applyChain restricted to migrations whose numeric version
// is BELOW stopBefore (0 = no limit), so a test can reconstruct the state a
// previous release left behind and then let the remaining migrations run on
// top of it.
func applyChainUpTo(t *testing.T, db *sql.DB, migrationsPath string, stopBefore int) (int, int) {
	t.Helper()

	migrations, err := collectMigrations(migrationsPath)
	if err != nil {
		t.Fatalf("collectMigrations: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatal("collectMigrations returned 0 migrations — the chain would silently no-op")
	}

	// The runner FATALs on this, so a dependency declared against a file the
	// mode does not include is a boot failure, not a warning.
	if err := validateMigrationDependencies(migrations); err != nil {
		t.Fatalf("validateMigrationDependencies: %v", err)
	}

	ensureSchemaMigrationsTable(db)

	// The GUCs several migrations read via current_setting(). Without these,
	// 028 (app.db_password) and 094 (app.deployment_org_id) abort — proof that
	// a naive psql loop would not be a faithful gate.
	setMigrationSessionVars(db, "test-db-password", getDeploymentOrgID(), getDeploymentKind())

	applied := getAppliedMigrations(db)

	var ran, skipped int
	for _, m := range migrations {
		filename := filepath.Base(m.Path)

		if stopBefore > 0 && migrationVersionNumber(t, filename, m.Version) >= stopBefore {
			continue
		}

		if applied[migrationKey(m.Version, m.Name)] {
			skipped++
			continue
		}

		sqlBytes, err := os.ReadFile(m.Path)
		if err != nil {
			t.Fatalf("read migration %s: %v", filename, err)
		}

		sqlContent, err := substituteGrafanaPassword(string(sqlBytes))
		if err != nil {
			t.Fatalf("substituteGrafanaPassword(%s): %v", filename, err)
		}
		if sqlContent == "" {
			// Grafana not deployed — the runner skips this file too.
			skipped++
			continue
		}

		if _, err := db.Exec(sqlContent); err != nil {
			t.Fatalf("MIGRATION ABORTED: %s [%s] failed to apply.\n"+
				"On a real deployment this crash-loops the agent at boot.\n"+
				"error: %v", filename, m.Category, err)
		}
		recordMigrationSuccess(db, m.Version, filename, 0)
		ran++
	}

	t.Logf("applied %d migration(s), skipped %d", ran, skipped)
	return ran, skipped
}

// The chain must also be RE-runnable: the agent re-runs migrations on every
// boot, and a migration that is not idempotent breaks the second start even
// though the first succeeded. Applying the same chain twice against one
// database catches that.
//
// Uses in-vpc-enterprise (core + enterprise) — the self-hosted shape the
// #2997/#3000 owner migrations actually target.
func TestMigrationChainIsIdempotent_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")

	firstRan, firstSkipped := applyChain(t, pc.DB, migrationsPath)
	if firstRan == 0 {
		t.Fatal("first pass applied 0 migrations — the chain did not actually run")
	}

	// Second pass = the agent's next boot. Every file is recorded, so the
	// runner must skip all of them and apply nothing. A non-zero count here
	// means schema_migrations bookkeeping is broken and the chain would
	// re-execute on every restart.
	secondRan, secondSkipped := applyChain(t, pc.DB, migrationsPath)
	if secondRan != 0 {
		t.Errorf("second pass re-applied %d migration(s); a re-boot must skip every recorded file", secondRan)
	}
	// Everything the first pass applied, PLUS whatever it already skipped
	// (files the runner declines for other reasons, e.g. Grafana not deployed).
	if want := firstRan + firstSkipped; secondSkipped != want {
		t.Errorf("second pass skipped %d, want %d (everything the first pass applied or skipped)", secondSkipped, want)
	}
}

// The migrations THIS bundle adds each declare themselves idempotent and safe
// to re-run (they are re-executed by hand during upgrades and incident
// recovery, and 149's own header promises it). Unlike the chain as a whole —
// where the runner's schema_migrations bookkeeping means a file is never
// re-executed — that promise is only worth anything if it holds, so re-apply
// them directly against an already-migrated database.
func TestOwnerMigrationsAreReRunnable_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	applyChain(t, pc.DB, migrationsPath)

	for _, name := range []string{
		"148_reconcile_system_roles_to_5tier.sql",
		"149_owner_assignment_backfill_and_bootstrap.sql",
		"150_owner_assignment_requires_real_identity.sql",
	} {
		sqlBytes, err := os.ReadFile(filepath.Join(migrationsPath, "core", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// Twice more, on top of the chain's application: an idempotent
		// migration converges, it does not merely survive one repeat.
		for pass := 1; pass <= 2; pass++ {
			if _, err := pc.DB.Exec(string(sqlBytes)); err != nil {
				t.Fatalf("%s is NOT idempotent — re-apply pass %d failed: %v", name, pass, err)
			}
		}
	}
}

// migrationVersionNumber returns the leading numeric part of a migration
// version. Versions are not always plain integers — `030a_fix_action_override_
// constraint.sql` carries the version "030a", a same-number follow-up to 030 —
// so a strict Atoi rejects a real file. The leading digits are what orders the
// chain, and a suffixed variant sorts with its base number, which is exactly
// the grouping a "stop before version N" cutoff wants.
func migrationVersionNumber(t *testing.T, filename, version string) int {
	t.Helper()
	digits := version
	for i, r := range version {
		if r < '0' || r > '9' {
			digits = version[:i]
			break
		}
	}
	if digits == "" {
		t.Fatalf("migration %s has version %q with no leading digits", filename, version)
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		t.Fatalf("migration %s: parse version %q: %v", filename, version, err)
	}
	return n
}

// #3000 R3 F-149rerun: re-running migration 149 by hand on a database that has
// already applied 150 must NOT strip 150's identity guard.
//
// Re-running a migration is a documented recovery action, and 149 defines
// ensure_org_owner_assignment with CREATE OR REPLACE. Unguarded, a re-run would
// silently roll the choke point back to the pre-#3000 definition that accepts a
// blank user_email — re-opening the privilege hole with no error and no trace.
//
// TestOwnerMigrationsAreReRunnable does NOT catch this: it re-applies the files
// in ascending order, so 150 always lands last and repairs whatever 149 undid.
// This asserts the reverse order, which is what an operator actually does.
func TestMigration149RerunDoesNotStripGuard_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")
	applyChain(t, pc.DB, migrationsPath)

	// Guard is installed by 150.
	assertBlankRefused := func(stage string) {
		t.Helper()
		var rc int
		if err := pc.DB.QueryRow(
			`SELECT ensure_org_owner_assignment('__guard_probe_org__', '', 'test')`).Scan(&rc); err != nil {
			t.Fatalf("%s: probe: %v", stage, err)
		}
		if rc != -2 {
			t.Fatalf("%s: ensure_org_owner_assignment('', ...) = %d, want -2 — migration 150's identity guard is GONE, so a blank user_email can hold owner again (#3000)", stage, rc)
		}
	}
	assertBlankRefused("after the full chain")

	// Seed a MIXED-CASE privileged assignment before the re-run (#3000 R3 F3).
	// The portal AssignRole API and SCIM both store user_email raw, so this is
	// an ordinary row — but mig 150's choke point stores the grant it creates
	// CANONICALLY. If 149's completeness check compares raw, it cannot see the
	// owner row the backfill just created for this principal and the re-run
	// aborts with "N principal(s) held sso:configure pre-upgrade but hold no
	// owner role". Without this seed the test passes vacuously.
	mustExecChainQ := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := pc.DB.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	mustExecChainQ(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	                VALUES ('rerun-mixed', 'Rerun Mixed', 'org@rerun.example', 'lic-' || md5(random()::text), 'Enterprise', 'ACTIVE')`)
	mustExecChainQ(`INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, source)
	                SELECT 'rerun-mixed', 'Admin.Person@Corp.example', id, 'portal', 'manual'
	                  FROM custom_roles
	                 WHERE org_id = 'rerun-mixed' AND name = 'admin' AND is_system`)

	// Now re-run 149 ALONE, exactly as an operator recovering by hand would.
	sqlBytes, err := os.ReadFile(filepath.Join(migrationsPath, "core", "149_owner_assignment_backfill_and_bootstrap.sql"))
	if err != nil {
		t.Fatalf("read 149: %v", err)
	}
	if _, err := pc.DB.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("re-run 149: %v", err)
	}

	assertBlankRefused("after re-running migration 149 by hand")
}

// TestMigrationChainReplaysWithFunctionsPresent_RealPostgres is the SEEDED-REPLAY
// leg (#3015).
//
// The other legs apply each migration at most once per database, always in
// ascending order. That misses an entire class: what a migration does when the
// LATER migrations' objects are ALREADY INSTALLED — which is exactly the state
// an operator re-running a migration by hand is in, and exactly the state a
// fix-forward migration lands in.
//
// Three shipped BLOCKERs lived in that gap:
//   - 149 SKIPPED redefining ensure_org_owner_assignment when 150's guard was
//     present, so any later change to the choke point silently did not install;
//   - 149's verification compared lower(btrim(...)) while 150's choke point
//     stored axonflow_canonical_email(...) — different functions, so a re-run
//     aborted on any address carrying a tab or NBSP;
//   - a trigger created by one migration and dropped by a later one was
//     re-created by a replay, resurrecting the behavior the drop removed.
//
// Every one is invisible to a fresh-DB run and to a single ascending pass.
// run.go log.Fatalf's on a failed migration, so each is a permanent boot loop.
func TestMigrationChainReplaysWithFunctionsPresent_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")

	// Full chain first, so EVERY later object exists during the replay.
	applyChain(t, pc.DB, migrationsPath)
	// Then the legacy shapes. On THIS leg the chain has already run, so the
	// org-creation trigger writes through 150's canonical-storing choke point
	// and every seeded grant lands already-canonical — i.e. the seed alone
	// gives the replay nothing to repair. De-canonicalize the owner rows
	// afterwards so 150's collapse/re-key is genuinely exercised on the replay.
	seedLegacyOwnerShapes(t, pc.DB, false)

	// De-canonicalize, or this leg is VACUOUS (#3002 follow-up).
	deCanonicalized := deCanonicalizeOwnerGrants(t, pc.DB)
	if deCanonicalized == 0 {
		t.Fatal("replay leg de-canonicalized 0 owner grant(s) — 150's collapse/re-key has nothing to repair and this leg is vacuous")
	}
	t.Logf("replay leg de-canonicalized %d owner grant(s)", deCanonicalized)

	replay := ownerChainMigrationFiles(t, migrationsPath, 148)
	if len(replay) == 0 {
		t.Fatal("no migrations >= 148 found to replay — the leg would be vacuous")
	}
	t.Logf("replaying %d migration(s) with all later functions present", len(replay))

	// Twice: an idempotent migration must CONVERGE, not merely survive one repeat.
	for pass := 1; pass <= 2; pass++ {
		for _, name := range replay {
			sqlBytes, readErr := os.ReadFile(filepath.Join(migrationsPath, "core", name))
			if readErr != nil {
				t.Fatalf("read %s: %v", name, readErr)
			}
			if _, execErr := pc.DB.Exec(string(sqlBytes)); execErr != nil {
				t.Fatalf("REPLAY ABORTED on pass %d: %s failed with the rest of the chain already present.\n"+
					"On a real deployment that is a hand re-run — a documented recovery action — and run.go turns the failure into a boot loop.\n"+
					"error: %v", pass, name, execErr)
			}
		}
	}

	// A hand re-run of 149 ALONE — the documented recovery action — must
	// actually INSTALL 149's definition, not silently skip it.
	//
	// This is the assertion BLOCKER 1 needed and behavior alone cannot give:
	// an earlier revision guarded the whole CREATE OR REPLACE behind
	// "is 150's guard already present?", so on any 150-applied stack 149's body
	// was never installed. Every later change to the choke point — a
	// fix-forward extending it, for instance — then appeared to apply and
	// simply did not exist. The guard still worked, so no behavioral probe
	// could see it; only the function's own source can.
	sql149, err := os.ReadFile(filepath.Join(migrationsPath, "core", "149_owner_assignment_backfill_and_bootstrap.sql"))
	if err != nil {
		t.Fatalf("read 149: %v", err)
	}
	if _, err := pc.DB.Exec(string(sql149)); err != nil {
		t.Fatalf("hand re-run of 149 alone (all later objects present) ABORTED: %v", err)
	}
	var def string
	if err := pc.DB.QueryRow(
		`SELECT pg_get_functiondef('ensure_org_owner_assignment(varchar,varchar,varchar,timestamptz)'::regprocedure)`).Scan(&def); err != nil {
		t.Fatalf("read function definition: %v", err)
	}
	if !strings.Contains(def, "to_regprocedure") {
		t.Fatalf("after re-running migration 149 alone, ensure_org_owner_assignment is NOT 149's definition — 149 skipped its own CREATE OR REPLACE, so any later change to this function silently does not install (#3015 BLOCKER 1).\ndefinition was:\n%s", def)
	}

	// ...and the re-run must not have reverted the STORAGE FORM either.
	//
	// A definition-string check cannot see this: 149's body is installed either
	// way, and the guard still returns -2 either way. Only an actual write
	// shows whether the choke point still canonicalizes. Conditionalizing the
	// guard but not the storage silently rolled an upgraded stack back to raw
	// keys while HandleLogin presents the canonical one — zero resolved
	// assignments, i.e. the #2997 lockout re-created by the recovery action.
	if _, err := pc.DB.Exec(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
		VALUES ('rekey-probe','Rekey Probe','probe@rekey.example','lic-rekey','Enterprise','ACTIVE')`); err != nil {
		t.Fatalf("seed rekey probe org: %v", err)
	}
	var grantRC int
	if err := pc.DB.QueryRow(
		`SELECT ensure_org_owner_assignment('rekey-probe', '  Mixed.Case@Rekey.Example  ', 'test')`).Scan(&grantRC); err != nil {
		t.Fatalf("post-rerun grant probe: %v", err)
	}
	var storedKey string
	if err := pc.DB.QueryRow(`
		SELECT ra.user_email FROM role_assignments ra
		JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
		WHERE ra.org_id='rekey-probe' AND cr.name='owner'
		  AND lower(btrim(ra.user_email)) = 'mixed.case@rekey.example'`).Scan(&storedKey); err != nil {
		t.Fatalf("read back the probe grant (rc=%d): %v", grantRC, err)
	}
	if storedKey != "mixed.case@rekey.example" {
		t.Fatalf("after re-running migration 149, the choke point stored %q instead of the canonical form — a hand re-run reverted the storage form, so every later first-owner write is keyed differently from what the login presents (#2997 lockout)", storedKey)
	}

	// ...and re-running 149 must not have stripped 150's guard.
	var rc int
	if err := pc.DB.QueryRow(
		`SELECT ensure_org_owner_assignment('__replay_probe_org__', '', 'test')`).Scan(&rc); err != nil {
		t.Fatalf("post-replay guard probe: %v", err)
	}
	if rc != -2 {
		t.Fatalf("after replaying the chain, ensure_org_owner_assignment('', ...) = %d, want -2 — a replay STRIPPED migration 150's identity guard, so a blank user_email can hold owner again (#3000)", rc)
	}
}

// deCanonicalizeOwnerGrants rewrites the seeded org-login owner grants back into
// the RAW (pre-150) spelling and adds a second raw-spelled duplicate, then
// returns how many rows now diverge from their canonical form.
//
// WHY THE REPLAY LEG NEEDS THIS. On this leg the whole chain has already run, so
// every row seedLegacyOwnerShapes creates goes through migration 150's
// canonical-storing choke point and lands already-canonical. 150's collapse and
// re-key therefore have NOTHING to repair, and the replay exercises none of the
// logic the leg exists to cover — it passed while doing nothing, which is the
// same false assurance #3002 was filed about.
//
// The two shapes restored here are the two a 149-era stack actually carries:
//
//	(1) a single system owner row keyed on the RAW contact_email, and
//	(2) TWO rows that canonicalize identically and of which NEITHER is
//	    canonical — produced on a real stack by 149's org-creation trigger plus
//	    its (since-dropped) contact-change re-seed trigger, and the shape that
//	    makes 150's re-key UPDATE collide on uq_role_assignments_user_role.
func deCanonicalizeOwnerGrants(t *testing.T, db *sql.DB) int {
	t.Helper()

	if _, err := db.Exec(`
		UPDATE role_assignments ra
		   SET user_email = o.contact_email
		  FROM organizations o, custom_roles cr
		 WHERE cr.org_id = o.org_id AND cr.name = 'owner' AND cr.is_system
		   AND ra.org_id = o.org_id
		   AND ra.role_id = cr.id
		   AND ra.source = 'system'
		   AND o.contact_email IS NOT NULL
		   AND ra.user_email = axonflow_canonical_email(o.contact_email)
		   AND o.contact_email <> axonflow_canonical_email(o.contact_email)`); err != nil {
		t.Fatalf("de-canonicalize owner grants: %v", err)
	}

	// Shape (2): a SECOND raw spelling in the same class. Distinct from the row
	// above ('ops@Example.com' for seed-drift2) and equally non-canonical, so
	// neither can be found by a "does a canonical twin exist" test.
	if _, err := db.Exec(`
		INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, source)
		SELECT 'seed-drift2', 'OPS@Example.COM', id, 'system:org-contact-change', 'system'
		  FROM custom_roles
		 WHERE org_id = 'seed-drift2' AND name = 'owner' AND is_system
		ON CONFLICT (org_id, user_email, role_id) DO NOTHING`); err != nil {
		t.Fatalf("seed second raw spelling: %v", err)
	}

	var divergent int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM role_assignments ra
		JOIN organizations o ON o.org_id = ra.org_id
		WHERE ra.source = 'system'
		  AND ra.user_email <> axonflow_canonical_email(ra.user_email)`).Scan(&divergent); err != nil {
		t.Fatalf("de-canonicalize sanity check: %v", err)
	}
	return divergent
}

// ownerChainMigrationFiles returns the core UP migrations with version >= from,
// in the order the runner would apply them.
func ownerChainMigrationFiles(t *testing.T, migrationsPath string, from int) []string {
	t.Helper()
	migs, err := collectMigrations(migrationsPath)
	if err != nil {
		t.Fatalf("collectMigrations: %v", err)
	}
	var out []string
	for _, m := range migs {
		if m.Category != "core" {
			continue
		}
		name := filepath.Base(m.Path)
		if migrationVersionNumber(t, name, m.Version) >= from {
			out = append(out, name)
		}
	}
	return out
}

// #3003/#3015 BLOCKER 3: the contact_email owner-drift trigger must not exist
// after the chain, and a REPLAY must not resurrect it.
//
// That trigger re-seeded the owner grant onto whatever address contact_email
// was changed to, conferring the top role ANONYMOUSLY to anyone able to write
// the column. Migration 152 drops it. Leaving the CREATE in 149 would undo that
// on any replay where 149 runs after 152 — a create-then-drop pair across two
// migrations is resurrected every time the earlier one is re-applied, which is
// exactly what a hand recovery does.
func TestContactEmailDriftTriggerStaysDropped_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)

	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")
	applyChain(t, pc.DB, migrationsPath)

	assertAbsent := func(stage string) {
		t.Helper()
		var n int
		if err := pc.DB.QueryRow(
			`SELECT COUNT(*) FROM pg_trigger WHERE tgname = 'reseed_org_owner_on_contact_change' AND NOT tgisinternal`).Scan(&n); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		if n != 0 {
			t.Fatalf("%s: the contact_email owner-drift trigger is PRESENT — a bare UPDATE of organizations.contact_email mints owner for any address (#3003)", stage)
		}
	}
	assertAbsent("after the full chain")

	// Replay 148+ twice, as a hand recovery would.
	for pass := 1; pass <= 2; pass++ {
		for _, name := range ownerChainMigrationFiles(t, migrationsPath, 148) {
			sqlBytes, readErr := os.ReadFile(filepath.Join(migrationsPath, "core", name))
			if readErr != nil {
				t.Fatalf("read %s: %v", name, readErr)
			}
			if _, execErr := pc.DB.Exec(string(sqlBytes)); execErr != nil {
				t.Fatalf("replay pass %d: %s: %v", pass, name, execErr)
			}
		}
		assertAbsent(fmt.Sprintf("after replay pass %d", pass))
	}

	// THE decisive case: re-run 149 ALONE, as a hand recovery does.
	//
	// An ascending replay always ends with 152, which drops the trigger again —
	// so it masks this entirely. Only running the EARLIER migration by itself
	// exposes a create-then-drop pair split across two files, and that is
	// precisely the documented recovery action.
	sql149, err := os.ReadFile(filepath.Join(migrationsPath, "core", "149_owner_assignment_backfill_and_bootstrap.sql"))
	if err != nil {
		t.Fatalf("read 149: %v", err)
	}
	if _, err := pc.DB.Exec(string(sql149)); err != nil {
		t.Fatalf("hand re-run of 149 alone ABORTED: %v", err)
	}
	assertAbsent("after re-running migration 149 ALONE")

	// And the behavior itself: changing contact_email must mint nothing.
	mustExecChainQ := func(q string) {
		t.Helper()
		if _, err := pc.DB.Exec(q); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	mustExecChainQ(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
	                VALUES ('drift-probe','Drift Probe','founder@probe.example','lic-probe','Enterprise','ACTIVE')`)
	mustExecChainQ(`UPDATE organizations SET contact_email='attacker@evil.example' WHERE org_id='drift-probe'`)

	var minted int
	if err := pc.DB.QueryRow(`
		SELECT COUNT(*) FROM role_assignments ra
		JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
		WHERE ra.org_id='drift-probe' AND cr.name='owner' AND ra.user_email='attacker@evil.example'`).Scan(&minted); err != nil {
		t.Fatalf("count minted: %v", err)
	}
	if minted != 0 {
		t.Fatal("a bare contact_email UPDATE minted owner for the new address — the #3003 anonymous-conferral vector is OPEN")
	}
}

// =============================================================================
// #3005 follow-up: the expired-owner revive, and the escalation check's
// tolerance for a qualifier migration 150 legitimately collapsed.
// =============================================================================

// chainedPostgres applies the whole core chain to a fresh container and returns
// it, so the tests below all start from the state a real upgraded stack is in.
func chainedPostgres(t *testing.T) *sql.DB {
	t.Helper()
	testutil.SkipIfNoDocker(t)
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")
	applyChain(t, pc.DB, migrationsPath)
	return pc.DB
}

// rerun149 applies migration 149 by hand — the documented recovery action —
// and returns the error rather than failing, so a test can assert either way.
func rerun149(t *testing.T, db *sql.DB) error {
	t.Helper()
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	sqlBytes, err := os.ReadFile(filepath.Join(migrationsPath, "core", "149_owner_assignment_backfill_and_bootstrap.sql"))
	if err != nil {
		t.Fatalf("read 149: %v", err)
	}
	_, execErr := db.Exec(string(sqlBytes))
	return execErr
}

func liveOwnerRows(t *testing.T, db *sql.DB, orgID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM role_assignments ra
		JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
		WHERE ra.org_id = $1 AND cr.name = 'owner'
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())`, orgID).Scan(&n); err != nil {
		t.Fatalf("count live owners for %s: %v", orgID, err)
	}
	return n
}

// TestExpiredOwnerRowIsRevivedOnlyByIntentionalCallers_RealPostgres pins the
// #3005-B revive on the FINAL choke-point definition, and pins that it stays
// scoped.
//
// Migration 149 carried the revive and migration 150 redefined the same function
// with a bare DO NOTHING. 150 runs second, so on every complete chain the revive
// did not exist — and nothing said so: the insert conflicted with the expired
// row, ROW_COUNT was 0, and the caller was told "already held" while the org had
// ZERO live owners. Break-glass, the documented way OUT of an owner lockout,
// answered success and granted nothing.
//
// The scoping half matters just as much: an unconditional revive would make
// EVERY portal restart silently convert a deliberately time-boxed owner grant
// into a permanent one.
func TestExpiredOwnerRowIsRevivedOnlyByIntentionalCallers_RealPostgres(t *testing.T) {
	db := chainedPostgres(t)

	if _, err := db.Exec(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
		VALUES ('revive-org','Revive Org','Boss@Revive.Example','lic-revive','Enterprise','ACTIVE')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	// The org-creation trigger granted owner to the canonical login identity.
	// Age it out: this is an org whose only owner grant has LAPSED.
	if _, err := db.Exec(`
		UPDATE role_assignments ra SET expires_at = NOW() - INTERVAL '1 day'
		  FROM custom_roles cr
		 WHERE cr.id = ra.role_id AND cr.org_id = ra.org_id
		   AND ra.org_id = 'revive-org' AND cr.name = 'owner'`); err != nil {
		t.Fatalf("expire the owner row: %v", err)
	}
	if n := liveOwnerRows(t, db, "revive-org"); n != 0 {
		t.Fatalf("setup: org has %d live owner(s), want 0 — the test would not exercise the revive", n)
	}

	// --- AMBIENT caller (the portal's every-boot grant): must NOT revive.
	var rc int
	if err := db.QueryRow(
		`SELECT ensure_org_owner_assignment('revive-org','boss@revive.example','system:portal-bootstrap')`).Scan(&rc); err != nil {
		t.Fatalf("ambient grant: %v", err)
	}
	if rc != 0 {
		t.Errorf("ambient caller rc = %d, want 0 (no-op)", rc)
	}
	if n := liveOwnerRows(t, db, "revive-org"); n != 0 {
		t.Fatalf("a portal-bootstrap grant REVIVED a lapsed owner row (%d live) — every restart would silently make a time-boxed owner grant permanent", n)
	}

	// --- BREAK-GLASS: must revive, because that is the entire point of the
	//     endpoint an already-locked-out operator reaches for.
	if err := db.QueryRow(
		`SELECT ensure_org_owner_assignment('revive-org','boss@revive.example','break-glass:adm_abc')`).Scan(&rc); err != nil {
		t.Fatalf("break-glass grant: %v", err)
	}
	if rc != 1 {
		t.Errorf("break-glass rc = %d, want 1 (revived)", rc)
	}
	if n := liveOwnerRows(t, db, "revive-org"); n != 1 {
		t.Fatalf("break-glass on an org whose only owner row had EXPIRED left %d live owner(s), want 1 — the endpoint reports success and grants nothing (#3005)", n)
	}

	// The revive must not rewrite assigned_by: migration 149's DOWN deletes on
	// the backfill marker, and stamping a marker onto a row a human or SCIM
	// created would let the rollback delete their grant.
	var assignedBy, source string
	if err := db.QueryRow(`
		SELECT ra.assigned_by, ra.source FROM role_assignments ra
		JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
		WHERE ra.org_id='revive-org' AND cr.name='owner'`).Scan(&assignedBy, &source); err != nil {
		t.Fatalf("read revived row: %v", err)
	}
	if assignedBy != "system:org-bootstrap" {
		t.Errorf("revived row assigned_by = %q, want the ORIGINAL grant's attribution (system:org-bootstrap) — a revive must not claim a row it did not create", assignedBy)
	}
	if source != "system" {
		t.Errorf("revived row source = %q, want system (149's SCIM-safety invariant)", source)
	}

	// --- The migration backfill's own marker also revives (that is the
	//     #3005-B upgrade-repair path).
	if _, err := db.Exec(`
		UPDATE role_assignments ra SET expires_at = NOW() - INTERVAL '1 day'
		  FROM custom_roles cr
		 WHERE cr.id = ra.role_id AND cr.org_id = ra.org_id
		   AND ra.org_id = 'revive-org' AND cr.name = 'owner'`); err != nil {
		t.Fatalf("re-expire: %v", err)
	}
	if err := db.QueryRow(
		`SELECT ensure_org_owner_assignment('revive-org','boss@revive.example','migration:149_owner_backfill')`).Scan(&rc); err != nil {
		t.Fatalf("backfill-marker grant: %v", err)
	}
	if n := liveOwnerRows(t, db, "revive-org"); n != 1 {
		t.Fatalf("the migration backfill marker did not revive the expired row (%d live) — the #3005-B upgrade repair is inert", n)
	}
}

// TestMigration149ToleratesCollapsedOrgLoginQualifier_RealPostgres pins the
// no-escalation check's tolerance for a qualifier migration 150 legitimately
// collapsed.
//
// The state constructed here is what an earlier revision of 150 actually left
// behind: the org-login identity's canonical owner row survives the collapse
// carrying 'migration:149_owner_backfill', and the raw-keyed row that justified
// it — the SAME principal's original grant — is gone. A hand re-run of 149 then
// aborted with "N backfilled owner assignment(s) went to principals that did not
// hold sso:configure pre-upgrade (escalation)", and run.go log.Fatalf's on a
// failed migration, so that is a permanent agent boot loop.
//
// 150's collapse now transfers the deleted row's attribution onto the survivor,
// so a current stack does not reach this state. This is the repair for the ones
// that already did, and for an operator who hand-deletes a duplicate owner row.
func TestMigration149ToleratesCollapsedOrgLoginQualifier_RealPostgres(t *testing.T) {
	db := chainedPostgres(t)

	if _, err := db.Exec(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
		VALUES ('collapsed-qual','Collapsed Qualifier','ops@collapsed.example','lic-cq','Enterprise','ACTIVE')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	// Re-mark the surviving row exactly as the collapse left it.
	if _, err := db.Exec(`
		UPDATE role_assignments ra SET assigned_by = 'migration:149_owner_backfill'
		  FROM custom_roles cr
		 WHERE cr.id = ra.role_id AND cr.org_id = ra.org_id
		   AND ra.org_id = 'collapsed-qual' AND cr.name = 'owner'`); err != nil {
		t.Fatalf("mark survivor: %v", err)
	}

	// The shape is only the shape if there is genuinely NO surviving qualifier.
	var qualifiers int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM role_assignments ra
		JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
		WHERE ra.org_id = 'collapsed-qual'
		  AND COALESCE(ra.assigned_by,'') <> 'migration:149_owner_backfill'
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		  AND (cr.permissions @> '["*"]'::jsonb OR cr.permissions @> '["sso:configure"]'::jsonb)`).Scan(&qualifiers); err != nil {
		t.Fatalf("count qualifiers: %v", err)
	}
	if qualifiers != 0 {
		t.Fatalf("setup: org still has %d non-backfill qualifier(s) — the escalation check would pass regardless and this test would be vacuous", qualifiers)
	}
	if n := liveOwnerRows(t, db, "collapsed-qual"); n != 1 {
		t.Fatalf("setup: org has %d live owner(s), want exactly the collapsed survivor", n)
	}

	if err := rerun149(t, db); err != nil {
		t.Fatalf("re-running migration 149 on a database where 150 collapsed the org-login qualifier ABORTED — a hand recovery is a documented action and run.go turns this into a boot loop.\nerror: %v", err)
	}
	if n := liveOwnerRows(t, db, "collapsed-qual"); n != 1 {
		t.Errorf("after the re-run the org has %d live owner(s), want 1", n)
	}
}

// TestMigration149StillCatchesGenuineEscalation_RealPostgres is the other half
// of the tolerance above, and the reason it is a tolerance rather than a hole.
//
// The relaxation is scoped to the org-LOGIN identity, because 150's collapse
// operates on exactly that identity and can remove no other principal's
// qualifier. A backfilled owner grant for anyone else with no qualifying role is
// still a widening, and must still abort the migration.
func TestMigration149StillCatchesGenuineEscalation_RealPostgres(t *testing.T) {
	db := chainedPostgres(t)

	if _, err := db.Exec(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
		VALUES ('genuine-esc','Genuine Escalation','real@esc.example','lic-esc','Enterprise','ACTIVE')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	// A backfilled owner grant for a principal that is NOT the org-login
	// identity and holds no qualifying role: a real widening.
	if _, err := db.Exec(`
		INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, source)
		SELECT 'genuine-esc', 'stranger@evil.example', id, 'migration:149_owner_backfill', 'system'
		  FROM custom_roles WHERE org_id='genuine-esc' AND name='owner' AND is_system`); err != nil {
		t.Fatalf("seed the escalated row: %v", err)
	}

	err := rerun149(t, db)
	if err == nil {
		t.Fatal("migration 149 ACCEPTED a backfilled owner grant for a principal that held no qualifying role — the collapsed-qualifier tolerance is a hole, not a tolerance")
	}
	if !strings.Contains(err.Error(), "escalation") {
		t.Fatalf("migration 149 failed for the wrong reason; want the escalation check.\nerror: %v", err)
	}
}

// TestMigration150CollapseTransfersProvenance_RealPostgres pins the other half
// of the collapsed-qualifier fix: the collapse must not leave the migration's
// own marker on a grant that PREDATES it.
//
// The class 150 collapses on a replay holds two rows for ONE principal — the
// org-login identity's original owner grant (keyed on the RAW contact_email) and
// the CANONICAL row 149's backfill created for the same identity. Rule 5 keeps
// the canonical one, so absent a transfer the survivor carries
// 'migration:149_owner_backfill' while the row that actually established
// ownership is deleted. Two consequences, both real:
//
//   - 149's no-escalation check finds a backfilled row with no qualifier and
//     aborts, which run.go turns into a boot loop, and
//   - 149's DOWN deletes on that marker, so a rollback removes the org's only
//     owner.
func TestMigration150CollapseTransfersProvenance_RealPostgres(t *testing.T) {
	db := chainedPostgres(t)
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
		VALUES ('prov-org','Provenance Org','Ops@Prov.Example','lic-prov','Enterprise','ACTIVE')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	// Put the trigger's grant back into the RAW 149-era spelling...
	if _, err := db.Exec(`
		UPDATE role_assignments ra SET user_email = 'Ops@Prov.Example'
		  FROM custom_roles cr
		 WHERE cr.id = ra.role_id AND cr.org_id = ra.org_id
		   AND ra.org_id = 'prov-org' AND cr.name = 'owner'`); err != nil {
		t.Fatalf("de-canonicalize the original grant: %v", err)
	}
	// ...and add the canonical row 149's backfill creates for the same principal.
	if _, err := db.Exec(`
		INSERT INTO role_assignments (org_id, user_email, role_id, assigned_by, source)
		SELECT 'prov-org', 'ops@prov.example', id, 'migration:149_owner_backfill', 'system'
		  FROM custom_roles WHERE org_id='prov-org' AND name='owner' AND is_system`); err != nil {
		t.Fatalf("seed the backfilled row: %v", err)
	}

	sql150, err := os.ReadFile(filepath.Join(migrationsPath, "core", "150_owner_assignment_requires_real_identity.sql"))
	if err != nil {
		t.Fatalf("read 150: %v", err)
	}
	if _, err := db.Exec(string(sql150)); err != nil {
		t.Fatalf("re-run 150 on the two-row class: %v", err)
	}

	var key, assignedBy string
	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM role_assignments ra
		JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
		WHERE ra.org_id='prov-org' AND cr.name='owner'`).Scan(&n); err != nil {
		t.Fatalf("count owner rows: %v", err)
	}
	if n != 1 {
		t.Fatalf("after the collapse the org has %d owner row(s), want exactly 1 survivor", n)
	}
	if err := db.QueryRow(`
		SELECT ra.user_email, ra.assigned_by FROM role_assignments ra
		JOIN custom_roles cr ON cr.id = ra.role_id AND cr.org_id = ra.org_id
		WHERE ra.org_id='prov-org' AND cr.name='owner'`).Scan(&key, &assignedBy); err != nil {
		t.Fatalf("read survivor: %v", err)
	}
	if key != "ops@prov.example" {
		t.Errorf("survivor key = %q, want the canonical form the login presents", key)
	}
	if assignedBy == "migration:149_owner_backfill" {
		t.Fatal("the collapse survivor still carries the migration-149 backfill marker: 149's no-escalation check now has no qualifier for it (boot loop on a hand re-run), and 149's DOWN would delete the org's only owner (#3005)")
	}
	if assignedBy != "system:org-bootstrap" {
		t.Errorf("survivor assigned_by = %q, want the collapsed row's original attribution (system:org-bootstrap)", assignedBy)
	}

	// ...and 149 must now re-run clean without needing the tolerance clause.
	if err := rerun149(t, db); err != nil {
		t.Fatalf("after the provenance transfer, re-running 149 still ABORTED: %v", err)
	}
}

// migration149BlindPredicate EXTRACTS migration 149's RLS canary from the file
// instead of restating it.
//
// A hand-copied predicate is worse than no predicate: it is byte-identical on
// the day it is written and drifts silently forever after, so the test goes on
// passing while the shipped canary is disabled. Verified: with a copy,
// `IF v_blind THEN` -> `IF FALSE THEN` in the migration left this test green.
// Reading the source makes an edit to the migration an edit to the test.
func migration149BlindPredicate(t *testing.T, migrationsPath string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(migrationsPath, "core", "149_owner_assignment_backfill_and_bootstrap.sql"))
	if err != nil {
		t.Fatalf("read 149: %v", err)
	}
	const startMark = "SELECT NOT EXISTS ("
	const endMark = "INTO v_blind;"
	body := string(raw)
	// Ambiguity is the silent failure mode: a second occurrence of startMark
	// earlier in the file would make this extract a DIFFERENT predicate, and the
	// test would go on passing while pinning something else. Today a mutation
	// that adds one happens to produce a SQL syntax error, but that diagnostic
	// names the wrong cause. Say the real one.
	if n := strings.Count(body, startMark); n != 1 {
		t.Fatalf("migration 149 contains %d occurrences of %q, want exactly 1 — this guard extracts the RLS canary by that marker, so more than one means it may be pinning a different predicate entirely", n, startMark)
	}
	if n := strings.Count(body, endMark); n != 1 {
		t.Fatalf("migration 149 contains %d occurrences of %q, want exactly 1", n, endMark)
	}
	i := strings.Index(body, startMark)
	j := strings.Index(body, endMark)
	if i < 0 || j < 0 || j <= i {
		t.Fatalf("could not locate migration 149's RLS canary predicate between %q and %q — the migration was restructured and this guard no longer reads the shipped predicate", startMark, endMark)
	}
	return body[i:j]
}

// TestMigration149RLSCanaryDiscriminates_RealPostgres pins the canary migration
// 149 gained for the silent-no-op upgrade (#3005 R3 pass 4).
//
// THE DEFECT IT REPORTS. Migrations run on the raw DATABASE_URL and never bind
// app.current_org_id, and `organizations` is ENABLE + FORCE RLS (mig 103) —
// FORCE being what makes RLS apply to the TABLE OWNER too. A deployment whose
// migration role owns the tables but is neither a Postgres superuser nor
// BYPASSRLS (an RDS master is exactly that: rds_superuser is NOT superuser) sees
// ZERO rows in `organizations`. 149's backfill then enumerates nothing from that
// leg and its orphan report counts nothing, so the upgrade announces success
// having repaired nothing. Self-hosted docker never shows it, because
// POSTGRES_USER is a container superuser and superusers bypass RLS even under
// FORCE.
//
// WHAT THIS ASSERTS is the DISCRIMINATOR, which is the part that can be wrong in
// a way that matters: it must fire for a blind role and must NOT fire for a
// role that can see the table. A canary that cries wolf on every fresh install
// would be turned off, and one that never fires is decoration. It deliberately
// does not assert on row COUNTS — a fresh install legitimately has zero orgs,
// which is precisely why the count-shaped canary in migration 151 is ambiguous
// exactly when it fires.
func TestMigration149RLSCanaryDiscriminates_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	predicate := migration149BlindPredicate(t, migrationsPath)

	blind := func(db *sql.DB, label string) bool {
		t.Helper()
		var b bool
		if err := db.QueryRow(predicate).Scan(&b); err != nil {
			t.Fatalf("evaluate the canary as %s: %v", label, err)
		}
		return b
	}

	// A faithful RDS-style migration role: OWNS the schema, is neither
	// superuser nor BYPASSRLS.
	for _, stmt := range []string{
		`CREATE ROLE rdsmaster LOGIN PASSWORD 'rdspw' CREATEDB CREATEROLE`,
		`GRANT ALL ON SCHEMA public TO rdsmaster`,
		`ALTER SCHEMA public OWNER TO rdsmaster`,
	} {
		if _, err := pc.DB.Exec(stmt); err != nil {
			t.Fatalf("seed the rds-style role (%s): %v", stmt, err)
		}
	}
	u, err := url.Parse(pc.URL)
	if err != nil {
		t.Fatalf("parse container URL: %v", err)
	}
	u.User = url.UserPassword("rdsmaster", "rdspw")
	ownerDB, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("open the rds-style pool: %v", err)
	}
	defer func() { _ = ownerDB.Close() }()

	var super, bypass bool
	if err := ownerDB.QueryRow(
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass); err != nil {
		t.Fatalf("read role attrs: %v", err)
	}
	if super || bypass {
		t.Fatalf("the stand-in migration role is superuser=%v bypassrls=%v — it must be NEITHER or this test proves nothing", super, bypass)
	}

	// The table as migration 103 leaves it, created BY that role so it is the
	// owner and FORCE therefore binds it.
	for _, stmt := range []string{
		`CREATE TABLE organizations (org_id varchar PRIMARY KEY, contact_email varchar)`,
		`ALTER TABLE organizations ENABLE ROW LEVEL SECURITY`,
		`CREATE POLICY organizations_org_id_isolation ON organizations FOR ALL
			USING (org_id = current_setting('app.current_org_id', true))
			WITH CHECK (org_id = current_setting('app.current_org_id', true))`,
	} {
		if _, err := ownerDB.Exec(stmt); err != nil {
			t.Fatalf("build the organizations table (%s): %v", stmt, err)
		}
	}

	// --- ENABLE only: the OWNER is still exempt, so the migration is not blind.
	if blind(ownerDB, "owner, ENABLE-only") {
		t.Error("the canary fires with ENABLE-only RLS, where the table owner is exempt — it would cry wolf on every deployment that has not run mig 103")
	}

	if _, err := ownerDB.Exec(`ALTER TABLE organizations FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatalf("force RLS: %v", err)
	}

	// --- FORCE: the owner IS subject. The canary must fire, and the blindness
	//     must be real — rows present, zero visible.
	if _, err := pc.DB.Exec(`INSERT INTO organizations VALUES ('acme','a@x.example'),('bare','b@x.example')`); err != nil {
		t.Fatalf("seed orgs as the superuser: %v", err)
	}
	var seenByOwner, seenBySuper int
	if err := ownerDB.QueryRow(`SELECT COUNT(*) FROM organizations`).Scan(&seenByOwner); err != nil {
		t.Fatalf("count as the migration role: %v", err)
	}
	if err := pc.DB.QueryRow(`SELECT COUNT(*) FROM organizations`).Scan(&seenBySuper); err != nil {
		t.Fatalf("count as the superuser: %v", err)
	}
	if seenBySuper == 0 {
		t.Fatal("the superuser sees no orgs either — the fixture is broken and every assertion here is vacuous")
	}
	if seenByOwner != 0 {
		t.Fatalf("the migration role sees %d/%d orgs under FORCE RLS; the blindness this canary reports does not reproduce, so the canary is describing nothing", seenByOwner, seenBySuper)
	}
	if !blind(ownerDB, "owner, FORCE") {
		t.Fatalf("the canary does NOT fire for a role that genuinely sees 0 of %d orgs — migration 149 would report a successful backfill having done nothing (#3005)", seenBySuper)
	}

	// --- A bound org scope makes the read work, so the canary must go quiet:
	//     it reports "no scope AND no privilege", not "RLS exists".
	tx, err := ownerDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_org_id', 'acme', true)`); err != nil {
		t.Fatalf("bind org scope: %v", err)
	}
	var b bool
	if err := tx.QueryRow(predicate).Scan(&b); err != nil {
		t.Fatalf("evaluate the canary with a bound scope: %v", err)
	}
	if b {
		t.Error("the canary fires even with app.current_org_id bound — it would fire on paths that can see their rows")
	}

	// --- And the ordinary self-hosted path (container superuser): never fires.
	if blind(pc.DB, "superuser") {
		t.Error("the canary fires for a SUPERUSER migration role — every docker deployment would emit a false alarm and the signal would be ignored")
	}

	// --- BYPASSRLS (axonflow_platform_admin's attribute): never fires either.
	if _, err := pc.DB.Exec(`ALTER ROLE rdsmaster BYPASSRLS`); err != nil {
		t.Fatalf("grant bypassrls: %v", err)
	}
	if blind(ownerDB, "owner, BYPASSRLS") {
		t.Error("the canary fires for a BYPASSRLS role, which can see every row")
	}
}

// TestMigrationNoticesReachTheLog_RealPostgres pins the thing that made every
// migration diagnostic in this repo inaudible (#3005 R3 pass 5).
//
// database/sql's plain Open DISCARDS every server NOTICE and WARNING — lib/pq
// only delivers them through pq.ConnectorWithNoticeHandler, and the migration
// runner did not install one. So `RAISE NOTICE 'Migration 149: granted N owner
// assignment(s)'`, the orphan-org report that tells an operator which orgs need
// the break-glass endpoint, and the RLS canaries in core/149 and core/151 have
// never appeared in an agent log. A migration that "warns" into a connection
// that throws warnings away is not a signal — it is the silent failure it was
// written to prevent, one layer down.
//
// This asserts the RUNNER's own opener, not a hand-built connection, and it
// asserts a WARNING specifically: that is the severity the canaries use, and it
// is the one an operator must not scroll past.
func TestMigrationNoticesReachTheLog_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())

	db, err := openMigrationDB(pc.URL)
	if err != nil {
		t.Fatalf("openMigrationDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	if _, err := db.Exec(`DO $$ BEGIN
		RAISE NOTICE 'probe-notice-visible';
		RAISE WARNING 'probe-warning-visible';
	END $$;`); err != nil {
		log.SetOutput(prev)
		t.Fatalf("probe: %v", err)
	}
	log.SetOutput(prev)

	got := buf.String()
	if !strings.Contains(got, "probe-notice-visible") {
		t.Errorf("a migration RAISE NOTICE never reached the log; the runner's diagnostics are invisible.\ncaptured:\n%s", got)
	}
	if !strings.Contains(got, "probe-warning-visible") {
		t.Fatalf("a migration RAISE WARNING never reached the log — the RLS canaries in core/149 and core/151 are decoration and an under-repaired upgrade reports success silently.\ncaptured:\n%s", got)
	}
	// The DISTINCT marking, not merely the word "WARNING" — that substring is
	// satisfied by any format interpolating n.Severity, so collapsing the
	// handler to one un-prefixed log.Printf left the old assertion green while
	// removing the very behavior run.go argues hardest for.
	if !strings.Contains(got, "⚠️") {
		t.Errorf("a migration WARNING was not marked distinctly from an ordinary NOTICE, so it reads like routine chatter and gets scrolled past — which is what the RLS canaries must not be.\ncaptured:\n%s", got)
	}
}

// TestMigration149EmitsItsRLSCanary_RealPostgres proves the canary fires FROM
// THE REAL MIGRATION, through the REAL runner connection, when the migration
// role genuinely cannot see `organizations`.
//
// The discriminator test above checks the predicate's semantics; this one is the
// end-to-end claim, and it is the one that cannot be satisfied by a predicate
// that has drifted, an `IF FALSE THEN`, or a warning that lib/pq swallows.
//
// The reachable shape is an UPGRADE whose DATABASE_URL points at a role that is
// neither superuser nor BYPASSRLS but owns the tables — `organizations` is
// FORCE RLS (mig 103), and FORCE is what makes RLS bind the owner. A fresh
// chain cannot be applied by such a role at all (mig 098 needs superuser to set
// BYPASSRLS), so the chain is applied privileged first and ownership handed
// over, which is exactly the state an operator lands in.
func TestMigration149EmitsItsRLSCanary_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")
	applyChain(t, pc.DB, migrationsPath)

	if _, err := pc.DB.Exec(`INSERT INTO organizations (org_id, name, contact_email, license_key, tier, status)
		VALUES ('canary-org','Canary','ops@canary.example','lic-canary','Enterprise','ACTIVE')`); err != nil {
		t.Fatalf("seed an org: %v", err)
	}

	// Membership in the schema owner lets the blind role CREATE OR REPLACE the
	// functions migration 149 redefines. Role ATTRIBUTES (SUPERUSER, BYPASSRLS)
	// are NOT inherited through membership, so the role stays subject to RLS —
	// which the blindness assertion below re-proves rather than assumes.
	var schemaOwner string
	if err := pc.DB.QueryRow(`SELECT current_user`).Scan(&schemaOwner); err != nil {
		t.Fatalf("read the schema owner: %v", err)
	}
	for _, stmt := range []string{
		`CREATE ROLE blindmigrator LOGIN PASSWORD 'blindpw'`,
		`GRANT ` + schemaOwner + ` TO blindmigrator`,
		// The owner-choke-point functions belong to axonflow_platform_admin
		// (mig 149/150 hand them over when that role exists), and migration 149
		// CREATE OR REPLACEs them. Membership is what a migration role that can
		// apply 149 must have; BYPASSRLS is an ATTRIBUTE and is not inherited
		// with it, so the role stays blind — asserted below.
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='axonflow_platform_admin') THEN GRANT axonflow_platform_admin TO blindmigrator; END IF; END $$`,
		`GRANT USAGE, CREATE ON SCHEMA public TO blindmigrator`,
		`DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='axonflow_platform_admin') THEN GRANT USAGE, CREATE ON SCHEMA public TO axonflow_platform_admin; END IF; END $$`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO blindmigrator`,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO blindmigrator`,
		`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO blindmigrator`,
	} {
		if _, err := pc.DB.Exec(stmt); err != nil {
			t.Fatalf("seed the blind migration role (%s): %v", stmt, err)
		}
	}

	u, err := url.Parse(pc.URL)
	if err != nil {
		t.Fatalf("parse container URL: %v", err)
	}
	u.User = url.UserPassword("blindmigrator", "blindpw")
	blindDB, err := openMigrationDB(u.String())
	if err != nil {
		t.Fatalf("openMigrationDB as the blind role: %v", err)
	}
	defer func() { _ = blindDB.Close() }()

	// The blindness must be real, or the assertion below is about nothing.
	var seenByBlind, seenBySuper int
	if err := blindDB.QueryRow(`SELECT COUNT(*) FROM organizations`).Scan(&seenByBlind); err != nil {
		t.Fatalf("count as the blind role: %v", err)
	}
	if err := pc.DB.QueryRow(`SELECT COUNT(*) FROM organizations`).Scan(&seenBySuper); err != nil {
		t.Fatalf("count as the superuser: %v", err)
	}
	if seenBySuper == 0 || seenByBlind != 0 {
		t.Fatalf("the fixture did not produce the blind shape (blind sees %d, superuser sees %d) — every assertion here would be vacuous", seenByBlind, seenBySuper)
	}
	var super, bypass bool
	if err := blindDB.QueryRow(`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypass); err != nil {
		t.Fatalf("read role attrs: %v", err)
	}
	if super || bypass {
		t.Fatalf("the stand-in migration role is superuser=%v bypassrls=%v — it must be NEITHER", super, bypass)
	}

	sql149, err := os.ReadFile(filepath.Join(migrationsPath, "core", "149_owner_assignment_backfill_and_bootstrap.sql"))
	if err != nil {
		t.Fatalf("read 149: %v", err)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	_, execErr := blindDB.Exec(string(sql149))
	log.SetOutput(prev)

	if execErr != nil {
		t.Fatalf("migration 149 ABORTED for the blind role: %v\nAn abort here is a permanent agent boot loop (run.go log.Fatalf's), which is why the canary WARNS rather than raising.\ncaptured:\n%s", execErr, buf.String())
	}
	got := buf.String()
	if !strings.Contains(got, "subject to row-level security") {
		t.Fatalf("migration 149 did NOT emit its RLS canary while the migration role saw 0 of %d orgs — the upgrade reports success having backfilled nothing, silently (#3005).\ncaptured:\n%s", seenBySuper, got)
	}
	if !strings.Contains(got, "WARNING") {
		t.Errorf("the canary was emitted but not at WARNING severity.\ncaptured:\n%s", got)
	}
}

// TestMigrationRunnerUsesTheNoticeHandlingOpener closes a vacuity in the two
// tests above: both call openMigrationDB directly, so reverting run.go's CALL
// SITE back to `sql.Open("postgres", dbURL)` left them green while every
// migration diagnostic went silent again. Verified — that exact one-line revert
// produced 0 failures.
//
// A behavioural test cannot see this: run.go's migration block is inline in a
// 200-line boot function with no seam to drive. So assert the source, which is
// the only thing that distinguishes "the opener exists" from "the runner uses
// it". Scoped to the migration connection's own region so an unrelated
// sql.Open elsewhere in the file cannot satisfy or break it.
func TestMigrationRunnerUsesTheNoticeHandlingOpener(t *testing.T) {
	src, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatalf("read run.go: %v", err)
	}
	body := string(src)

	const startMark = "var migrationDB *sql.DB"
	const endMark = "setMigrationSessionVars(migrationDB"
	i := strings.Index(body, startMark)
	j := strings.Index(body, endMark)
	if i < 0 || j < 0 || j <= i {
		t.Fatalf("could not locate the migration-connection block in run.go between %q and %q — it was restructured and this guard no longer reads the real call site", startMark, endMark)
	}
	region := body[i:j]

	if !strings.Contains(region, "openMigrationDB(dbURL)") {
		t.Errorf("the migration connection is not opened through openMigrationDB. lib/pq DISCARDS every server NOTICE and WARNING unless the connection carries a notice handler, so the migrations' entire diagnostic story — the backfill counts, the orphan-org report that names the orgs needing break-glass, and the RLS canaries in core/149 and core/151 — vanishes and an under-repaired upgrade reports success in silence.\nregion was:\n%s", region)
	}
	if strings.Contains(region, `sql.Open("postgres"`) {
		t.Errorf("the migration connection still uses a plain sql.Open, which throws away NOTICE/WARNING.\nregion was:\n%s", region)
	}
}
