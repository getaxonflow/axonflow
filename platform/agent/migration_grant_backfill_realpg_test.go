package agent

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/testutil"
)

// The runtime half of #3636, and the one thing the static census cannot say.
//
// The census asserts that every FORCE-RLS table is granted somewhere. It cannot
// assert that the grant MATTERS, because in every other fixture in this tree
// the same role applies core/098 and every migration after it - so core/098's
// `ALTER DEFAULT PRIVILEGES ... TO axonflow_app_role`, which binds to the role
// that executed it, covers everything and the explicit grant is redundant.
// enterprise/148 says exactly that about itself: "it is invisible to the test
// suites, which provision both roles under one owner."
//
// This builds the shape that is NOT invisible: a second migration role that is
// not the owner core/098 granted for. Under it the tables core/169 creates are
// unreachable to axonflow_app_role, and core/170 is what restores them. Both
// halves are asserted, because "the app can read the table" proves nothing
// unless it could not read it a moment earlier.

// TestMigration170GrantsAreLoadBearing_RealPostgres proves the backfill closes
// a real permission gap rather than restating one core/098 already covered.
func TestMigration170GrantsAreLoadBearing_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")
	applyChain(t, pc.DB, migrationsPath)

	// A SECOND migration role. It owns nothing yet and is not the role that
	// executed core/098, so core/098's default privileges do not follow it -
	// which is the whole point. It is neither superuser nor BYPASSRLS, asserted
	// below rather than assumed.
	for _, stmt := range []string{
		`CREATE ROLE latemigrator LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'latepw'`,
		`GRANT USAGE, CREATE ON SCHEMA public TO latemigrator`,
	} {
		if _, err := pc.DB.Exec(stmt); err != nil {
			t.Fatalf("seed the second migration role (%s): %v", stmt, err)
		}
	}
	lateURL, err := url.Parse(pc.URL)
	if err != nil {
		t.Fatalf("parse container URL: %v", err)
	}
	lateURL.User = url.UserPassword("latemigrator", "latepw")
	// openMigrationDB, not sql.Open: it is the runner's own opener and installs
	// the notice handler, so a migration's diagnostics are visible here exactly
	// as they are in production.
	lateDB, err := openMigrationDB(lateURL.String())
	if err != nil {
		t.Fatalf("open as latemigrator: %v", err)
	}
	defer func() { _ = lateDB.Close() }()

	var isSuper, bypass bool
	if err := lateDB.QueryRow(`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper, &bypass); err != nil {
		t.Fatalf("read the second role's attributes: %v", err)
	}
	if isSuper || bypass {
		t.Fatalf("the second migration role is superuser=%v bypassrls=%v; it must be NEITHER, or the gap this test "+
			"measures cannot exist", isSuper, bypass)
	}

	// Re-create core/169's tables UNDER THE SECOND ROLE. Dropping first is what
	// makes the ownership change real: the chain already created them owned by
	// the first role, where core/098's defaults do cover them.
	for _, tbl := range []string{"identity_realm_epochs", "identity_trust_realms"} {
		if _, err := pc.DB.Exec(`DROP TABLE IF EXISTS ` + tbl + ` CASCADE`); err != nil {
			t.Fatalf("drop %s: %v", tbl, err)
		}
	}
	applyMigrationAs(t, lateDB, migrationsPath, "core", "169_identity_trust_realms.sql")

	// THE GAP. Read as the application role: the tables exist, it cannot touch
	// them, and the failure is a permission error rather than an empty result -
	// which is the "fails closed, but loudly and in the wrong place" that
	// enterprise/149's comment describes.
	appDB := connectAs(t, pc.URL, "axonflow_app_role")
	defer func() { _ = appDB.Close() }()

	for _, tbl := range []string{"identity_trust_realms", "identity_realm_epochs"} {
		_, err := appDB.Exec(`SELECT 1 FROM ` + tbl + ` LIMIT 1`)
		if err == nil {
			t.Fatalf("axonflow_app_role could already read %s under a second migration role, so core/170 has nothing "+
				"to restore and every assertion below would hold vacuously. Either core/098's default privileges "+
				"follow a role change after all, or this fixture did not produce the split it intends.", tbl)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Fatalf("reading %s failed for a reason other than privilege (%v); the gap under test is a permission "+
				"gap and this is measuring something else", tbl, err)
		}
	}

	// THE FIX. core/170 applied by the SAME second role - a corrective migration
	// runs in whatever run discovers it, not in the run that created the table.
	applyMigrationAs(t, lateDB, migrationsPath, "core", "170_forcerls_grant_backfill.sql")

	for _, tbl := range []string{"identity_trust_realms", "identity_realm_epochs"} {
		if _, err := appDB.Exec(`SELECT 1 FROM ` + tbl + ` LIMIT 1`); err != nil {
			t.Errorf("after core/170, axonflow_app_role still cannot read %s: %v", tbl, err)
		}
	}
	// The write half too. SELECT alone would pass on a migration that granted
	// only SELECT, which is not the baseline core/098 declares.
	//
	// In a TRANSACTION, because the org scope is a `SET LOCAL` and *sql.DB is a
	// pool: setting it on one pooled connection and inserting on another leaves
	// the RLS policy's `current_setting('app.current_org_id', true)` NULL, the
	// WITH CHECK false, and the INSERT refused for a reason that has nothing to
	// do with the privilege under test. Measured - the first version of this
	// probe failed with "new row violates row-level security policy" while the
	// grant had landed perfectly.
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin as the application role: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_org_id = 'grant-probe'`); err != nil {
		t.Fatalf("set the org scope: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO identity_realm_epochs (org_id, epoch) VALUES ('grant-probe', 1)`); err != nil {
		t.Errorf("after core/170, axonflow_app_role cannot INSERT into identity_realm_epochs: %v. core/098 declares "+
			"SELECT, INSERT, UPDATE, DELETE as the baseline for every table; a backfill that restores only SELECT "+
			"restores the wrong thing.", err)
	}
	if err := tx.Commit(); err != nil {
		t.Errorf("committing the write probe: %v", err)
	}

	// IDEMPOTENT: a second apply changes nothing and raises nothing. The runner
	// will not re-run it, but an operator repairing a database by hand will.
	applyMigrationAs(t, lateDB, migrationsPath, "core", "170_forcerls_grant_backfill.sql")
	if _, err := appDB.Exec(`SELECT 1 FROM identity_trust_realms LIMIT 1`); err != nil {
		t.Errorf("a second apply of core/170 broke the access the first one restored: %v", err)
	}
}

// applyMigrationAs executes one migration file over the given connection.
func applyMigrationAs(t *testing.T, db *sql.DB, migrationsPath, category, name string) {
	t.Helper()
	path := filepath.Join(migrationsPath, category, name)
	body, err := os.ReadFile(path) //nolint:gosec // a path built from the repo's own migrations directory
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatalf("apply %s/%s: %v", category, name, err)
	}
}

// connectAs opens a connection as one of the RLS roles seeded by core/098.
//
// The password is set here rather than assumed: core/098 creates the roles with
// LOGIN but the container fixture does not give them passwords, and a
// connection that silently fell back to the superuser would make every
// assertion in this file vacuous.
func connectAs(t *testing.T, containerURL, role string) *sql.DB {
	t.Helper()
	u, err := url.Parse(containerURL)
	if err != nil {
		t.Fatalf("parse container URL: %v", err)
	}
	admin, err := openMigrationDB(containerURL)
	if err != nil {
		t.Fatalf("open as the container owner: %v", err)
	}
	defer func() { _ = admin.Close() }()
	pw := role + "_probe_pw"
	if _, err := admin.Exec(fmt.Sprintf(`ALTER ROLE %s WITH LOGIN PASSWORD '%s'`, role, pw)); err != nil {
		t.Fatalf("set a password on %s: %v", role, err)
	}
	u.User = url.UserPassword(role, pw)
	db, err := openMigrationDB(u.String())
	if err != nil {
		t.Fatalf("open as %s: %v", role, err)
	}
	var current string
	if err := db.QueryRow(`SELECT current_user`).Scan(&current); err != nil {
		t.Fatalf("read current_user as %s: %v", role, err)
	}
	if current != role {
		t.Fatalf("connected as %q, wanted %q; every assertion made through this connection would be about the "+
			"wrong role", current, role)
	}
	return db
}

// applyMigrationCapturingNotices runs one migration and returns the PostgreSQL
// NOTICEs it raised.
//
// database/sql's plain Open DISCARDS every server NOTICE - lib/pq delivers them
// only through a notice handler, which openMigrationDB installs and which the
// runner logs. The NOTICE is the entire subject of #3635, so a test that ran
// the migration and asserted only on its error would be asserting the one thing
// that never changed.
func applyMigrationCapturingNotices(t *testing.T, pc *testutil.PostgresContainer, migrationsPath, category, name string) string {
	t.Helper()
	path := filepath.Join(migrationsPath, category, name)
	body, err := os.ReadFile(path) //nolint:gosec // a path built from the repo's own migrations directory
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	db, err := openMigrationDB(pc.URL)
	if err != nil {
		t.Fatalf("openMigrationDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	_, execErr := db.Exec(string(body))
	log.SetOutput(prev)

	notices := buf.String()
	if execErr != nil {
		t.Fatalf("apply %s/%s: %v\nnotices:\n%s", category, name, execErr, notices)
	}
	if strings.TrimSpace(notices) == "" {
		t.Fatalf("%s/%s raised no NOTICE at all; the assertions below would be about an empty string", category, name)
	}
	return notices
}

// TestMigration170DownRemovesNoAccess_RealPostgres is the rollback's safety
// property, driven in BOTH owner shapes.
//
// An earlier version of 170_down ran REVOKE, and that was wrong in the
// direction that breaks a healthy deployment. A GRANT is not
// reference-counted: core/098's `GRANT ... ON ALL TABLES` and the up
// migration's per-table grant are THE SAME PRIVILEGE, so revoking once removes
// the access core/098 created rather than the access the migration added. On
// every house-shaped stack that would have left axonflow_app_role unable to
// read organizations, tenants, connectors and the rest - and the file's own
// "nothing was lost" branch could never print, because there is nothing for the
// privilege to fall back to.
//
// Both shapes are driven because the two are the whole question. In the
// SINGLE-OWNER shape the up migration re-stated an existing privilege, so the
// rollback must remove nothing. In the SPLIT-OWNER shape it granted something
// genuinely new, and the rollback must STILL remove nothing - an operator
// rolling back a backfill has not asked to revoke an application role's access
// to twenty tables, and a migration that did that quietly would be the more
// serious defect of the two.
func TestMigration170DownRemovesNoAccess_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}

	for _, shape := range []struct {
		name       string
		splitOwner bool
	}{
		{"single owner - the up migration re-stated an existing privilege", false},
		{"split owner - the up migration granted something new", true},
	} {
		t.Run(shape.name, func(t *testing.T) {
			pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
			t.Setenv("DEPLOYMENT_MODE", "community")
			applyChain(t, pc.DB, migrationsPath)

			applier := pc.DB
			if shape.splitOwner {
				for _, stmt := range []string{
					`CREATE ROLE downmigrator LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'downpw'`,
					`GRANT USAGE, CREATE ON SCHEMA public TO downmigrator`,
				} {
					if _, err := pc.DB.Exec(stmt); err != nil {
						t.Fatalf("seed the second migration role (%s): %v", stmt, err)
					}
				}
				u, perr := url.Parse(pc.URL)
				if perr != nil {
					t.Fatalf("parse container URL: %v", perr)
				}
				u.User = url.UserPassword("downmigrator", "downpw")
				splitDB, oerr := openMigrationDB(u.String())
				if oerr != nil {
					t.Fatalf("open as downmigrator: %v", oerr)
				}
				defer func() { _ = splitDB.Close() }()
				// Re-create core/169's tables under the second role so the up
				// migration has something genuinely new to grant. BOTH are
				// dropped: 169 forces RLS on each, and ALTER TABLE on one still
				// owned by the first role fails with "must be owner".
				for _, tbl := range []string{"identity_realm_epochs", "identity_trust_realms"} {
					if _, err := pc.DB.Exec(`DROP TABLE IF EXISTS ` + tbl + ` CASCADE`); err != nil {
						t.Fatalf("drop %s: %v", tbl, err)
					}
				}
				applyMigrationAs(t, splitDB, migrationsPath, "core", "169_identity_trust_realms.sql")
				applier = splitDB
			}

			applyMigrationAs(t, applier, migrationsPath, "core", "170_forcerls_grant_backfill.sql")

			// The privileges the app role holds AFTER the up migration.
			before := appRolePrivileges(t, pc.DB)
			if len(before) == 0 {
				t.Fatal("the app role holds no table privileges at all, so the comparison below is vacuous")
			}

			applyMigrationAs(t, applier, migrationsPath, "core", "170_forcerls_grant_backfill_down.sql")

			after := appRolePrivileges(t, pc.DB)
			var lost []string
			for table := range before {
				if !after[table] {
					lost = append(lost, table)
				}
			}
			sort.Strings(lost)
			if len(lost) > 0 {
				t.Errorf("the rollback removed axonflow_app_role's SELECT on %d table(s): %s.\n\nA GRANT is not "+
					"reference-counted - core/098's ON ALL TABLES and this migration's per-table grant are the same "+
					"privilege - so a REVOKE here takes away the access core/098 created, not the access the "+
					"migration added.", len(lost), strings.Join(lost, ", "))
			}
		})
	}
}

// appRolePrivileges renders which tables axonflow_app_role can SELECT.
//
// Rendered from has_table_privilege rather than from pg_class ACLs, because the
// question is what the role can DO, and an ACL can grant through membership as
// well as directly.
func appRolePrivileges(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`
		SELECT c.relname
		  FROM pg_catalog.pg_class c
		  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public' AND c.relkind = 'r'
		   AND has_table_privilege('axonflow_app_role', c.oid, 'SELECT')`)
	if err != nil {
		t.Fatalf("rendering app-role privileges: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scanning privileges: %v", err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating privileges: %v", err)
	}
	return out
}

// TestMigration170WarnsAboutTablesItCannotReach_RealPostgres drives the branch
// that reports a gap the migration COULD NOT close.
//
// The tolerance and the warning are one mechanism, and only half of it was
// under test. `GRANT` requires ownership, so on the split-owner deployment this
// migration exists for it will be REFUSED on the tables it does not own -
// unhandled, that aborts the whole run and leaves the deployment worse off than
// the gap. It is therefore swallowed per table. That swallow is exactly what
// would turn a real, un-closed gap into a silent success, so the migration
// re-reads has_table_privilege afterwards and RAISES A WARNING naming every
// (role, table) pair still unreachable, its owner, and the statement that
// owner must run.
//
// Nothing exercised that warning: every other fixture either owns the tables
// (so the grant lands) or already has the privilege (so nothing is unreachable).
// This builds the third shape - a table the migration role does NOT own and the
// application role CANNOT reach - and asserts both halves: the warning names
// the pair, and the pair really is still unreachable, so the warning is true
// rather than merely present.
func TestMigration170WarnsAboutTablesItCannotReach_RealPostgres(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	migrationsPath, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	pc := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	t.Setenv("DEPLOYMENT_MODE", "community")
	applyChain(t, pc.DB, migrationsPath)

	// A migration role that owns NOTHING. Unlike the load-bearing fixture, no
	// table is re-created under it, so every GRANT core/170 attempts is refused.
	for _, stmt := range []string{
		`CREATE ROLE ownsnothing LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'nothingpw'`,
		`GRANT USAGE ON SCHEMA public TO ownsnothing`,
	} {
		if _, err := pc.DB.Exec(stmt); err != nil {
			t.Fatalf("seed the non-owner migration role (%s): %v", stmt, err)
		}
	}

	// Take the privilege away as the OWNER, so there is something for the
	// migration to fail to restore. Without this the verification pass finds
	// the table reachable and the warning correctly stays silent.
	const target = "identity_trust_realms"
	if _, err := pc.DB.Exec(
		`REVOKE ALL ON ` + target + ` FROM axonflow_app_role`); err != nil {
		t.Fatalf("revoke the application role's access to %s: %v", target, err)
	}
	appDB := connectAs(t, pc.URL, "axonflow_app_role")
	defer func() { _ = appDB.Close() }()
	if _, err := appDB.Exec(`SELECT 1 FROM ` + target + ` LIMIT 1`); err == nil {
		t.Fatalf("axonflow_app_role can still read %s after the REVOKE, so there is no gap for the migration to "+
			"report and the assertions below would hold vacuously", target)
	}

	nonOwnerURL, err := url.Parse(pc.URL)
	if err != nil {
		t.Fatalf("parse container URL: %v", err)
	}
	nonOwnerURL.User = url.UserPassword("ownsnothing", "nothingpw")
	nonOwnerDB, err := openMigrationDB(nonOwnerURL.String())
	if err != nil {
		t.Fatalf("open as the non-owner role: %v", err)
	}
	defer func() { _ = nonOwnerDB.Close() }()

	// Capture the migration's own diagnostics. openMigrationDB installs the
	// runner's notice handler, which logs, so this is what an operator sees.
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	applyMigrationAs(t, nonOwnerDB, migrationsPath, "core", "170_forcerls_grant_backfill.sql")
	log.SetOutput(prev)
	diagnostics := buf.String()

	// The migration must not have ABORTED - that is the first half of the
	// mechanism, and a failed apply would have been reported by applyMigrationAs.
	if !strings.Contains(diagnostics, "STILL unreachable") {
		t.Fatalf("core/170 applied under a role that owns nothing and could grant nothing, and raised no "+
			"'STILL unreachable' warning. The per-table tolerance of insufficient_privilege then hides a real gap "+
			"in silence, which is the failure the warning exists to prevent.\ndiagnostics:\n%s", diagnostics)
	}
	if !strings.Contains(diagnostics, target) {
		t.Errorf("the warning fired but does not name %s, the one table that is genuinely unreachable; an operator "+
			"cannot act on a warning that does not say which table to grant on.\ndiagnostics:\n%s", target, diagnostics)
	}
	if !strings.Contains(diagnostics, "axonflow_app_role") {
		t.Errorf("the warning does not name the ROLE that cannot reach %s; the remedy it prints is a GRANT, which "+
			"needs both halves of the pair.\ndiagnostics:\n%s", target, diagnostics)
	}

	// The warning is TRUE. A warning that fires on a table the application role
	// can in fact reach would be worse than none: it would train an operator to
	// ignore it.
	if _, err := appDB.Exec(`SELECT 1 FROM ` + target + ` LIMIT 1`); err == nil {
		t.Errorf("core/170 warned that %s is still unreachable, but axonflow_app_role can read it", target)
	}

	// And the refusal was survivable: tables the role could not grant on did not
	// stop the migration, so a deployment applying this is not left mid-chain.
	var applied bool
	if err := pc.DB.QueryRow(
		`SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_tables WHERE tablename = $1)`, target).Scan(&applied); err != nil {
		t.Fatalf("re-read %s after the migration: %v", target, err)
	}
	if !applied {
		t.Errorf("%s no longer exists after core/170 ran under a non-owner; the migration must never drop anything", target)
	}
}
