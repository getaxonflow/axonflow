// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Real-Postgres verification of migrations/core/172 (#3786, v11 decision D1):
// static_policies and dynamic_policies become READ-ONLY to the application
// roles, and stay READABLE.
//
// # Why both directions are asserted
//
// The revoke is only half the requirement. ADR-065 Phase 2 keeps the legacy
// evaluator as the per-plane shadow COMPARATOR until each plane's activation
// entry, and a comparator that cannot read its own substrate compares nothing.
// A migration that removed writes AND reads would look correct in the diff, and
// the symptom on a deployment would be a missing decision-shadow window rather
// than a failed migration.
//
// # Why this needs a real database
//
// A GRANT is not observable from Go source. The privilege revoke is the entire
// mechanism, so the only evidence that it works is a connection AS THE APP ROLE
// being refused - which is also why every assertion here runs on env.AppRoleDSN
// after approletest.AssertCurrentUser has proven the connection really is that
// role. On the owner connection every statement below would succeed.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lib/pq"

	"axonflow/platform/agent/approletest"
)

const (
	migration172     = "../../migrations/core/172_legacy_policy_tables_read_only.sql"
	migration172Down = "../../migrations/core/172_legacy_policy_tables_read_only_down.sql"
)

// legacyPolicyTables is the population migration 172 addresses. Both are named
// because a migration that revoked on one and not the other would leave a
// second write path open, which is the shape D1 exists to close.
var legacyPolicyTables = []string{"static_policies", "dynamic_policies"}

// seededOrgScope is the org_id every seeded policy row carries.
//
// It has to be set on the connection or the app role sees NOTHING: both tables
// carry migration 018's tenant_isolation_select policy,
// `org_id::text = get_current_org_id()`, and an unset app.current_org_id
// matches no row. Measured against a migrated database rather than assumed -
// 101 static rows and 11 dynamic rows, all org_id 'global', which is the same
// static population #3786's census reports.
const seededOrgScope = "global"

// appRoleConn opens an app-role connection pinned to ONE physical connection
// and scoped to the seeded organization.
//
// SetMaxOpenConns(1) is load bearing rather than tidy: set_config(..., false)
// is SESSION scoped, and on a pool of N connections the next statement can land
// on a connection that never saw it - so a test would read zero rows
// intermittently and read it as a privilege refusal.
func appRoleConn(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	approletest.AssertCurrentUser(t, db, "axonflow_app_role")
	if _, err := db.Exec("SELECT set_config('app.current_org_id', $1, false)", seededOrgScope); err != nil {
		t.Fatalf("scoping the app-role session to %q: %v", seededOrgScope, err)
	}
	return db
}

func TestMigration172MakesTheLegacyPolicyTablesReadOnly_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	// THE premise. On the owner connection none of this proves anything.
	appRoleDB := appRoleConn(t, env.AppRoleDSN)

	// ANTI-VACUITY, FIRST. Every refusal below is about a privilege, and a
	// refusal is indistinguishable from an empty or absent table unless the
	// table is known to hold rows the app role can see. The seeds put 100+
	// rows in static_policies; a run where they are missing is a run where
	// this file is asserting nothing.
	for _, table := range legacyPolicyTables {
		var n int
		if err := appRoleDB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
			t.Fatalf("the app role cannot SELECT from %s, which migration 172's freeze must leave readable: %v", table, err)
		}
		if n == 0 {
			t.Fatalf("%s is empty under the app role, so both the read assertion and the write refusals below are vacuous", table)
		}
		t.Logf("%s: the app role reads %d row(s)", table, n)
	}

	for _, table := range legacyPolicyTables {
		for name, stmt := range map[string]string{
			"INSERT": "INSERT INTO " + table + " (policy_id, name, org_id) VALUES ('w1c-probe', 'probe', '" + seededOrgScope + "')",
			"UPDATE": "UPDATE " + table + " SET name = 'rewritten'",
			"DELETE": "DELETE FROM " + table,
		} {
			t.Run(table+"/"+name, func(t *testing.T) {
				_, err := appRoleDB.Exec(stmt)
				if err == nil {
					t.Fatalf("the app role executed %s on %s; after migration 172 the typed authoring model is the only write path", name, table)
				}
				// The refusal must be a PRIVILEGE refusal. An INSERT that
				// failed on a NOT NULL column would look identical to a
				// caller and would prove nothing about the grant.
				if !strings.Contains(err.Error(), "permission denied") {
					t.Fatalf("%s on %s failed for the wrong reason (want a privilege refusal): %v", name, table, err)
				}
			})
		}
	}
}

// TestMigration172LeavesTheShadowComparatorAbleToRead is the OTHER direction,
// asserted on its own rather than as a precondition of the refusals.
//
// A single test that read first and then wrote would report "the app role
// cannot read" and "the app role cannot write" as one failure, and the two
// mean opposite things about whether the migration is correct.
func TestMigration172LeavesTheShadowComparatorAbleToRead_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	appRoleDB := appRoleConn(t, env.AppRoleDSN)

	// ANTI-VACUITY. A SELECT that returns zero rows succeeds, so "the read
	// still works" is satisfied by a database where RLS hides everything -
	// which is the state this file was FIRST written into, and it passed.
	var seen int
	if err := appRoleDB.QueryRow(`SELECT COUNT(*) FROM static_policies`).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatal("the app role sees zero static_policies rows, so every query below succeeds while reading nothing")
	}

	// The columns the legacy READERS actually select, not SELECT *: a grant
	// can be column-scoped, and a bare COUNT(*) would not notice.
	for query, what := range map[string]string{
		"SELECT policy_id, category, pattern, severity, action FROM static_policies LIMIT 5":    "the effective read path",
		"SELECT policy_id, phase, action_request, action_response FROM static_policies LIMIT 5": "the runtime read path",
		"SELECT policy_id, policy_type, conditions, actions FROM dynamic_policies LIMIT 5":      "the dynamic read path",
		"SELECT COUNT(*) FROM dynamic_policies WHERE enabled = true":                            "the enabled-policy count",
	} {
		rows, err := appRoleDB.Query(query)
		if err != nil {
			t.Fatalf("%s is broken for the app role after migration 172: %v", what, err)
		}
		_ = rows.Close()
	}
}

// TestMigration172RollsBackCleanly is the down half, and it is a REAL rollback
// rather than the no-op that core/170's and enterprise/151's down migrations
// are: 172 removed privileges core/098 had granted, so putting them back is
// exactly what undoing it means.
func TestMigration172RollsBackCleanly_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = masterDB.Close() }()
	appRoleDB := appRoleConn(t, env.AppRoleDSN)

	apply := func(path string) {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if _, err := masterDB.Exec(string(body)); err != nil {
			t.Fatalf("applying %s: %v", path, err)
		}
	}

	// DOWN: writes come back.
	apply(migration172Down)
	if _, err := appRoleDB.Exec(
		`INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, org_id)
		 VALUES ('w1c-rollback-probe', 'probe', 'security-sqli', 'probe', 'low', 'warn', $1)`, seededOrgScope); err != nil {
		t.Fatalf("after the down migration the app role still cannot write static_policies: %v", err)
	}

	// UP AGAIN: writes go away again, on a database that has already carried
	// the migration once. Re-appliability is what an operator recovers with.
	apply(migration172)
	if _, err := appRoleDB.Exec(`DELETE FROM static_policies WHERE policy_id = 'w1c-rollback-probe'`); err == nil {
		t.Fatal("the re-applied migration did not revoke DELETE")
	}
	// And the read survives the round trip.
	var n int
	if err := appRoleDB.QueryRow(`SELECT COUNT(*) FROM static_policies`).Scan(&n); err != nil {
		t.Fatalf("SELECT is broken after down-then-up: %v", err)
	}
	if n == 0 {
		t.Fatal("static_policies is empty after the round trip, so the read assertion is vacuous")
	}
}

// TestTheCommunitySaasSweepNeverCascadesIntoALegacyPolicyTable_RealPG walks to
// the thing that EXECUTES, because the text does not say what it does.
//
// # The write site a source search cannot find
//
// cascadeDeleteCommunitySaasTenantData issues
// `fmt.Sprintf("DELETE FROM %s WHERE tenant_id = ANY($1)", table)` over a table
// list discovered at run time from information_schema - every public BASE TABLE
// carrying a varchar/text `tenant_id` column, minus an exclusion set. Nothing in
// that file spells "DELETE FROM dynamic_policies", so the write-surface census
// in tests/regression-test-required, which matches SQL verbs against table names
// in Go source, cannot see it. Neither can any grep.
//
// `dynamic_policies` HAS a varchar `tenant_id`. It was therefore in the cascade
// set, measured against a migrated database rather than reasoned about - which
// made it a twelfth write site on a legacy policy table, and one that
// migration 172 would break: the DELETE is refused with `permission denied` on
// a deployment connecting as an application role, and because the cascade
// returns on the first error inside the sweep's transaction, ONE refused table
// stops tenant termination entirely rather than skipping that table.
//
// This test is the pin, and it runs the real discovery function against a real
// migrated schema. A source-text assertion over the exclusion map would pass
// on a database where a later migration added `tenant_id` to some other policy
// table, which is the same blindness one layer up.
func TestTheCommunitySaasSweepNeverCascadesIntoALegacyPolicyTable_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = masterDB.Close() }()

	tables, err := discoverCommunitySaasCascadeTables(context.Background(), masterDB)
	if err != nil {
		t.Fatal(err)
	}
	// ANTI-VACUITY. An empty or tiny cascade set would make the exclusion
	// assertion below trivially true, and a discovery query that silently
	// returned nothing is exactly the state this test must not pass in.
	if len(tables) < 10 {
		t.Fatalf("the cascade set has %d table(s): %v. That is too few for the exclusion assertion below to mean anything.", len(tables), tables)
	}
	for _, table := range tables {
		for _, legacy := range legacyPolicyTables {
			if table == legacy {
				t.Errorf("the Community-SaaS termination sweep would DELETE from %s. After migration 172 that is refused, and "+
					"because the cascade returns on the first error inside the sweep transaction, it stops tenant termination "+
					"ENTIRELY rather than skipping this table. Add it to communitySaasSweepNonCascadeTables with a reason.", legacy)
			}
		}
	}

	// AND THE CONTROL: both legacy tables really do carry the varchar
	// tenant_id that puts a table in the cascade set, so their absence above is
	// the exclusion working rather than the discovery query never having been
	// able to find them.
	for _, legacy := range legacyPolicyTables {
		if !hasVarcharTenantID(t, masterDB, legacy) {
			t.Fatalf("%s does not carry a varchar tenant_id, so it could never have been in the cascade set and the "+
				"assertion above proves nothing about the exclusion", legacy)
		}
	}
}

// TestTheTypedAuthoringTablesAreOutOfTheCascadeSetByConstruction_RealPG asks
// the SAME question of the tables migration 155 creates, and gets the same
// answer for a DIFFERENT reason - which is why it is a separate test rather
// than three more names in the loop above.
//
// The legacy tables are out of the cascade set BY EXCLUSION: they carry a
// varchar `tenant_id`, the discovery query would find them, and
// communitySaasSweepNonCascadeTables takes them out. The typed-authoring
// tables are out of it BY CONSTRUCTION: they key on `org_id` and carry no
// `tenant_id` at all, so the discovery query cannot see them in the first
// place.
//
// Asserting only "not in the cascade set" for these three would be VACUOUS -
// trivially true of any table with no tenant_id, and it would stay green while
// the property that makes it true was removed. So the mechanism is asserted
// too, and it is the one that fails first and names the real risk: a later
// migration adding a `tenant_id` column to one of these tables would put it in
// the cascade set, where the same single refused DELETE stops tenant
// termination entirely.
func TestTheTypedAuthoringTablesAreOutOfTheCascadeSetByConstruction_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = masterDB.Close() }()

	// 155 is an ENTERPRISE migration and approletest applies migrations/core,
	// so it is applied here explicitly. Without it the three tables do not
	// exist and every assertion below is about nothing.
	body, err := os.ReadFile("../../migrations/enterprise/155_typed_authoring_persistence.sql")
	if err != nil {
		t.Fatalf("reading migration 155: %v", err)
	}
	if _, err := masterDB.Exec(string(body)); err != nil {
		t.Fatalf("applying migration 155: %v", err)
	}
	for _, table := range typedAuthoringTables {
		var present bool
		if err := masterDB.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, table).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Fatalf("%s does not exist after applying migration 155, so this test asserts nothing", table)
		}
	}

	tables, err := discoverCommunitySaasCascadeTables(context.Background(), masterDB)
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) < 10 {
		t.Fatalf("the cascade set has %d table(s): %v. Too few for the assertion below to mean anything.", len(tables), tables)
	}
	for _, table := range tables {
		for _, typed := range typedAuthoringTables {
			if table == typed {
				t.Errorf("the Community-SaaS termination sweep would DELETE from %s. Migration 155 revokes DELETE on it, and "+
					"the cascade returns on the first error inside the sweep transaction, so this stops tenant termination "+
					"ENTIRELY. Add it to communitySaasSweepNonCascadeTables with a reason.", typed)
			}
		}
	}

	// THE MECHANISM, which is what actually keeps them out and what a future
	// migration could remove without touching anything in this file.
	for _, typed := range typedAuthoringTables {
		if hasVarcharTenantID(t, masterDB, typed) {
			t.Errorf("%s has grown a varchar tenant_id. It is now discoverable by the Community-SaaS cascade sweep, which "+
				"would attempt a DELETE that migration 155 refuses - and one refused table stops tenant termination "+
				"entirely. Either drop the column or add the table to communitySaasSweepNonCascadeTables.", typed)
		}
	}
}

// typedAuthoringTables is what migrations core/176 (first shipped as
// enterprise/155) and core/181 create. Every one is append-only, so a cascade
// DELETE against any of them is refused.
var typedAuthoringTables = []string{
	"typed_policy_artifacts", "typed_policy_activations", "typed_policy_signing_keys",
	"typed_policy_audit",
}

// hasVarcharTenantID reports whether a table carries the column that puts it
// in the Community-SaaS cascade set. It reads the catalog rather than a list,
// because the discovery query does too.
func hasVarcharTenantID(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'tenant_id'
		  AND data_type IN ('character varying', 'text', 'character')
	`, table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// TestNothingInTheCatalogueWritesALegacyPolicyTableWithoutTheOwnersAuthority_RealPG
// is the THIRD door, closed the same way the second one was: by asking the
// thing that executes.
//
// # Three doors, three methods, and why a census of source text is not enough
//
// A migration that revokes a privilege breaks every consumer of that table,
// and consumers do not all look like consumers:
//
//  1. a literal SQL verb in Go source. Found by grep; pinned by
//     tests/regression-test-required/legacy_policy_write_surface_test.sh.
//  2. a statement ASSEMBLED at run time over a table list DISCOVERED at run
//     time. Invisible to grep; found by running the discovery function; pinned
//     by TestTheCommunitySaasSweepNeverCascadesIntoALegacyPolicyTable_RealPG.
//  3. SQL that lives in the DATABASE rather than in application source - a
//     function body, a trigger, a rule. Invisible to both of the above, and
//     invisible in the diff of the migration that breaks it.
//
// Door three is not hypothetical, and the way it was missed is the part worth
// keeping. migrations/core/060 defines activate_integration() as SECURITY
// INVOKER with `UPDATE static_policies SET enabled = true` in its body; the
// agent calls it as `SELECT activate_integration(...)` on every check_policy
// request. Its Go call site carries the comment "the call slips past the
// write-audit static test because it is lexically a SELECT" - so somebody knew
// the function evaded the guard, wrote it down AT THE SITE, and nothing carried
// that to a person changing a grant. A comment that documents a known evasion
// is a note to its author, not a control.
//
// This test is where that knowledge now lives. It reads pg_proc, pg_trigger
// and pg_rewrite on a migrated database and requires every writer it finds to
// be one this migration deliberately permits - which today means running with
// the OWNER's authority (prosecdef), the population migrations/core/172 does
// not bind.
//
// # What it still cannot see, stated rather than left to be discovered
//
// The match is over prosrc TEXT, so it covers `UPDATE static_policies`,
// `UPDATE ONLY static_policies`, `UPDATE public.static_policies` and the
// quoted spellings - but NOT a body that assembles the table name at run time,
// `EXECUTE format('UPDATE %I ...', t)`. That is door two's shape inside door
// three, and closing it needs a different instrument again: executing the
// function and observing the write, which is what
// TestTheIntegrationActivationFunctionStillWorksUnderTheAppRole_RealPG and
// TestTheDefinerFunctionCannotReachAnotherOrgsRowsOrEnableEverything_RealPG do
// for the one such function this tree has. Today NO function body in this
// schema assembles a legacy policy table name, which the assertion below pins
// so the gap cannot be entered silently.
func TestNothingInTheCatalogueWritesALegacyPolicyTableWithoutTheOwnersAuthority_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = masterDB.Close() }()

	// FUNCTIONS. prosrc is the body as stored, so this sees what actually runs
	// rather than what some file says. Matching is deliberately broad - any
	// mention of a write verb near the table name - because a false positive
	// here costs one line of triage and a false negative costs a production
	// incident.
	// ALL THREE PROPERTIES THE FAILURE MESSAGE PRESCRIBES ARE READ, not just
	// prosecdef. An earlier version selected the definer flag alone while its
	// own message said "make it SECURITY DEFINER (with SET search_path and
	// REVOKE EXECUTE FROM PUBLIC)" - so a new definer function with an
	// unpinned search_path and PUBLIC execute would have passed, and been
	// strictly worse than the SECURITY INVOKER function this census exists to
	// have caught. A guard that prescribes three things and checks one blesses
	// the other two.
	rows, err := masterDB.Query(`
		SELECT p.proname,
		       p.prosecdef,
		       COALESCE(array_to_string(p.proconfig, ','), '') AS config,
		       COALESCE(array_to_string(p.proacl, ','), '')    AS acl
		FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND p.prosrc ~* '(INSERT[[:space:]]+INTO|UPDATE|DELETE[[:space:]]+FROM|TRUNCATE)([[:space:]]+ONLY)?[[:space:]]+(public\\.)?"?(static_policies|dynamic_policies)'
		ORDER BY p.proname
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()

	type fn struct {
		name    string
		definer bool
		config  string
		acl     string
	}
	var writers []fn
	for rows.Next() {
		var f fn
		if err := rows.Scan(&f.name, &f.definer, &f.config, &f.acl); err != nil {
			t.Fatal(err)
		}
		writers = append(writers, f)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// ANTI-VACUITY. activate_integration IS a writer and must be found, or the
	// query is not doing what this test claims. It is the exact function this
	// census exists to have caught, so its absence means the census would not
	// have caught it either.
	found := false
	for _, w := range writers {
		if w.name == "activate_integration" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the catalogue census found no function named activate_integration among %d writer(s): %+v. "+
			"That function's body updates static_policies, so a census that cannot see it cannot see door three at all.", len(writers), writers)
	}

	for _, w := range writers {
		if !w.definer {
			t.Errorf("%s() writes a legacy policy table and runs as SECURITY INVOKER, so it executes with the CALLER's "+
				"privileges. After migrations/core/172 that call is refused for both application roles - and because the "+
				"write is inside a function body, nothing in Go source, in the write-surface census, or in the diff of "+
				"the migration that breaks it names this call. Make it SECURITY DEFINER (with SET search_path and "+
				"REVOKE EXECUTE FROM PUBLIC), or move the write out of the legacy table.", w.name)
		}
		if w.definer {
			// A DEFINER FUNCTION WITH AN UNPINNED search_path can be
			// redirected by a caller's schema into objects of the caller's
			// choosing, executed with the owner's privileges. It is the
			// classic definer attack and it is why every SECURITY DEFINER
			// helper in this tree (core/109's pattern) carries the setting.
			if !strings.Contains(w.config, "search_path=") {
				t.Errorf("%s() is SECURITY DEFINER with no pinned search_path, so its body can be redirected by a "+
					"caller's schema and executed with the owner's privileges. Add SET search_path = public, pg_temp.", w.name)
			}
			// AND EXECUTE MUST NOT BE PUBLIC.
			//
			// PUBLIC IS THE GRANTEE-LESS ENTRY, so the test is whether any ACL
			// item STARTS with '=' - not whether the string contains "=X/",
			// which every named grant also does ("postgres=X/postgres",
			// "axonflow_app_role=X/postgres"). A substring check here reported
			// a correctly-revoked function as public, which is the same
			// text-versus-structure error this whole census exists to replace.
			//
			// An EMPTY acl is the other spelling: it means default privileges,
			// and the default for a function IS EXECUTE to PUBLIC.
			public := w.acl == ""
			for _, item := range strings.Split(w.acl, ",") {
				if strings.HasPrefix(strings.TrimSpace(item), "=") {
					public = true
				}
			}
			if public {
				t.Errorf("%s() is SECURITY DEFINER and EXECUTE is available to PUBLIC (acl %q; an empty acl is the "+
					"default, which grants EXECUTE to PUBLIC, and a grantee-less entry is an explicit grant to it). "+
					"Revoke it and grant only to the application roles.", w.name, w.acl)
			}
		}
		t.Logf("catalogue writer: %s() security_definer=%t config=%q acl=%q", w.name, w.definer, w.config, w.acl)
	}

	// AND NO FUNCTION BODY ASSEMBLES A LEGACY TABLE NAME AT RUN TIME. That
	// spelling is invisible to the text match above, so its ABSENCE is what
	// makes the census's coverage claim true - and a function that started
	// doing it would need the behavioural instrument instead.
	var dynamicWriters []string
	drows, err := masterDB.Query(`
		SELECT p.proname FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND p.prosrc ~* 'EXECUTE[[:space:]]+format'
		  AND p.prosrc ~* '(static_policies|dynamic_policies)'
		ORDER BY p.proname
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = drows.Close() }()
	for drows.Next() {
		var name string
		if err := drows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		dynamicWriters = append(dynamicWriters, name)
	}
	if err := drows.Err(); err != nil {
		t.Fatal(err)
	}
	// EXACTLY ONE function is allowed to match, and only because it is covered
	// by the behavioural instrument this check's own error message asks for.
	//
	// enforce_legacy_policy_read_only() (migrations/core/172) matches on both
	// halves of the pattern: it runs EXECUTE format(...), and its closure query
	// names both legacy tables as the roots to walk from. What it assembles is
	// a REVOKE naming a VIEW - it has no DML in it at all - but that is a claim
	// about the body, and a claim about a body is what this census refuses to
	// accept. So it is covered instead by three tests that EXECUTE it and
	// observe what changes, named below and required to exist.
	behaviourallyCovered := map[string]string{
		"enforce_legacy_policy_read_only": "TestTheIndustryViewsAreBoundOnAFreshDeployment_RealPG",
	}
	var uncovered []string
	for _, name := range dynamicWriters {
		if _, ok := behaviourallyCovered[name]; !ok {
			uncovered = append(uncovered, name)
		}
	}
	if len(uncovered) > 0 {
		t.Errorf("%v assemble a legacy policy table name inside EXECUTE format(...). The text census above cannot see "+
			"what such a body writes, so this needs the behavioural instrument - execute it and observe the write - "+
			"rather than a wider regex.", uncovered)
	}

	// THE ALLOW-LIST CANNOT ROT INTO A BLANKET EXEMPTION. An entry naming a
	// function that no longer exists is an exemption with nothing behind it,
	// and it would sit here silently excusing the NEXT function that happened
	// to take the same name.
	for name, test := range behaviourallyCovered {
		found := false
		for _, seen := range dynamicWriters {
			if seen == name {
				found = true
			}
		}
		if !found {
			t.Errorf("%s() is allow-listed here as covered by %s, but no such function assembles a legacy table name "+
				"any more. Remove the entry rather than leaving an exemption with nothing behind it.", name, test)
		}

		// AND THE CITED TEST MUST EXIST. An exemption that names its own remedy
		// is worth nothing if the remedy cannot be performed: rename or delete
		// that test and this entry stands, citing coverage that is not there,
		// with everything still green.
		// SEARCHED ACROSS THE PACKAGE, not just this file. The covering test can
		// legitimately live in a sibling - and one did move, when the view
		// enforcer split out to migrations/core/174 and took its tests with it.
		// A file-scoped search reported the citation as dangling when it was
		// merely somewhere else, which is a false alarm in the direction that
		// gets a rot check deleted rather than fixed.
		peers, err := filepath.Glob("*_test.go")
		if err != nil {
			t.Fatal(err)
		}
		cited := false
		for _, f := range peers {
			body, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "func "+test+"(") {
				cited = true
				break
			}
		}
		if !cited {
			t.Errorf("the allow-list exempts %s() on the grounds that %s covers it behaviourally, and no such test "+
				"function exists anywhere in this package.", name, test)
		}
	}

	// TRIGGERS. A trigger function can write a table with nothing in
	// application source naming the write at all - the INSERT that fires it is
	// against some other table entirely.
	var triggerWriters []string
	trows, err := masterDB.Query(`
		SELECT DISTINCT t.tgname || ' on ' || c.relname || ' -> ' || p.proname
		FROM pg_catalog.pg_trigger t
		JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
		JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE NOT t.tgisinternal AND n.nspname = 'public'
		  AND p.prosrc ~* '(INSERT[[:space:]]+INTO|UPDATE|DELETE[[:space:]]+FROM|TRUNCATE)([[:space:]]+ONLY)?[[:space:]]+(public\\.)?"?(static_policies|dynamic_policies)'
		ORDER BY 1
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = trows.Close() }()
	for trows.Next() {
		var d string
		if err := trows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		triggerWriters = append(triggerWriters, d)
	}
	if err := trows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(triggerWriters) > 0 {
		t.Errorf("a trigger writes a legacy policy table: %v. After migration 172 the statement that FIRES it fails, "+
			"and the failing statement is against a different table entirely - which is the least legible form this "+
			"class takes.", triggerWriters)
	}

	// RULES. pg_rewrite rules other than the implicit SELECT rule of a view can
	// rewrite a statement into a write nobody wrote.
	//
	// NOT SCOPED TO `public`, deliberately, and this corrects a real asymmetry.
	// A DO INSTEAD rule on a TABLE is a live write path - the relation IS in the
	// enforcer's closure and its `relkind = 'v'` filter drops it, so this census
	// is what covers that shape. It used to be scoped to schema `public`, which
	// meant a rule on a table in any other schema was invisible to BOTH
	// instruments at once: the enforcer over-reached on schema and this census
	// under-reached, in opposite directions, over the same gap. The rule body is
	// matched with an optional `public.` qualifier for the same reason - a rule
	// written from another schema spells its target table qualified.
	var ruleWriters []string
	rrows, err := masterDB.Query(`
		SELECT n.nspname || '.' || c.relname || ' -> ' || r.rulename
		FROM pg_catalog.pg_rewrite r
		JOIN pg_catalog.pg_class c ON c.oid = r.ev_class
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE r.rulename <> '_RETURN'
		  AND n.nspname NOT LIKE 'pg\_temp%'
		  AND n.nspname NOT LIKE 'pg\_toast%'
		  AND n.nspname <> 'information_schema'
		  AND pg_catalog.pg_get_ruledef(r.oid) ~* '(INSERT[[:space:]]+INTO|UPDATE|DELETE[[:space:]]+FROM)[[:space:]]+(public\.)?(static_policies|dynamic_policies)'
		ORDER BY 1
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rrows.Close() }()
	for rrows.Next() {
		var d string
		if err := rrows.Scan(&d); err != nil {
			t.Fatal(err)
		}
		ruleWriters = append(ruleWriters, d)
	}
	if err := rrows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(ruleWriters) > 0 {
		t.Errorf("a rewrite rule writes a legacy policy table: %v", ruleWriters)
	}

	// ---------------------------------------------------------------------
	// A FOURTH DOOR: PRIVILEGE REACHED INDIRECTLY, THROUGH A ROLE OR AN OWNER.
	//
	// Every instrument above asks "what writes this table". None asks "who is
	// allowed to". A later migration can restore the write path without
	// containing a statement any of them recognise:
	//
	//   GRANT UPDATE ON static_policies TO some_helper_role;
	//   GRANT some_helper_role TO axonflow_app_role;
	//
	// The first line names no application role; the second names no verb and
	// no table. The write-surface census misses both, the catalogue census
	// sees no new object, and migration 172's own has_table_privilege check
	// ran once, before that migration existed. Table OWNERSHIP is the same
	// shape and is not exotic here - core/109 and core/149 both ALTER ... OWNER
	// TO as an established pattern, and an owner is not bound by a grant at
	// all.
	//
	// So this asks the privilege question directly, of the catalogue, on the
	// final schema: whatever route it came by, can an application role write?
	// ---------------------------------------------------------------------
	for _, role := range []string{"axonflow_app_role", "axonflow_platform_admin"} {
		for _, table := range legacyPolicyTables {
			var canWrite bool
			if err := masterDB.QueryRow(`
				SELECT has_table_privilege($1, $2, 'INSERT')
				    OR has_table_privilege($1, $2, 'UPDATE')
				    OR has_table_privilege($1, $2, 'DELETE')
				    OR has_table_privilege($1, $2, 'TRUNCATE')
				    OR has_any_column_privilege($1, $2, 'UPDATE')
				    OR has_any_column_privilege($1, $2, 'INSERT')
			`, role, table).Scan(&canWrite); err != nil {
				t.Fatal(err)
			}
			if canWrite {
				t.Errorf("%s can write %s on the final schema. has_table_privilege follows role MEMBERSHIP, so this is "+
					"true whether the privilege was granted directly or inherited through a role a later migration "+
					"granted - a route no source-text or catalogue-object census can see.", role, table)
			}

			// AND THE ROLE MUST NOT OWN THE TABLE. An owner is not bound by a
			// grant, so ALTER TABLE ... OWNER TO would restore the write path
			// while every privilege check above still reported false.
			var owner string
			if err := masterDB.QueryRow(`
				SELECT pg_get_userbyid(c.relowner) FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = 'public' AND c.relname = $1
			`, table).Scan(&owner); err != nil {
				t.Fatal(err)
			}
			if owner == role {
				t.Errorf("%s OWNS %s. An owner is not bound by a privilege revoke, so migration 172 constrains it not "+
					"at all - and every has_table_privilege assertion in this suite would still report false.", role, table)
			}
		}
	}

	// ANTI-VACUITY for both: the roles must EXIST, or every assertion above is
	// about nobody. has_table_privilege on an unknown role raises, so a silent
	// pass here would mean the loop never ran.
	var roles int
	if err := masterDB.QueryRow(
		`SELECT COUNT(*) FROM pg_catalog.pg_roles WHERE rolname IN ('axonflow_app_role','axonflow_platform_admin')`).Scan(&roles); err != nil {
		t.Fatal(err)
	}
	if roles != 2 {
		t.Fatalf("%d of the 2 application roles exist; the privilege and ownership assertions above are about nobody", roles)
	}

	// ---------------------------------------------------------------------
	// THE TRIGGER AND RULE RESULTS ABOVE ARE NEGATIVES, AND A SEARCH THAT
	// FINDS NOTHING LOOKS EXACTLY LIKE A SEARCH THAT CANNOT FIND ANYTHING.
	//
	// The function sweep has its own anti-vacuity - activate_integration must
	// be found - but the other two had none: an empty result was being read as
	// "no trigger writes these tables" when it is equally consistent with a
	// query that could never match. So both are shown a writer they must find.
	// Planted inside a transaction that is ROLLED BACK, so nothing survives
	// this test and no other lane inherits a half-mutated schema.
	// ---------------------------------------------------------------------
	tx, err := masterDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
		CREATE FUNCTION w1c_probe_trigger_fn() RETURNS TRIGGER AS $fn$
		BEGIN
			UPDATE static_policies SET enabled = true WHERE policy_id = 'never';
			RETURN NEW;
		END;
		$fn$ LANGUAGE plpgsql;
		CREATE TRIGGER w1c_probe_trigger AFTER INSERT ON integration_activations
			FOR EACH ROW EXECUTE FUNCTION w1c_probe_trigger_fn();
		CREATE VIEW w1c_probe_view AS SELECT * FROM static_policies;
		CREATE RULE w1c_probe_rule AS ON DELETE TO w1c_probe_view
			DO INSTEAD DELETE FROM dynamic_policies WHERE policy_id = 'never';
	`); err != nil {
		t.Fatalf("planting the trigger and rule probes: %v", err)
	}

	var planted int
	if err := tx.QueryRow(`
		SELECT COUNT(*) FROM pg_catalog.pg_trigger t
		JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
		WHERE NOT t.tgisinternal
		  AND p.prosrc ~* '(INSERT[[:space:]]+INTO|UPDATE|DELETE[[:space:]]+FROM|TRUNCATE)([[:space:]]+ONLY)?[[:space:]]+(public\\.)?"?(static_policies|dynamic_policies)'
	`).Scan(&planted); err != nil {
		t.Fatal(err)
	}
	if planted != 1 {
		t.Fatalf("the trigger census found %d planted writer(s), want 1; the empty result above was not evidence of anything", planted)
	}

	if err := tx.QueryRow(`
		SELECT COUNT(*) FROM pg_catalog.pg_rewrite r
		JOIN pg_catalog.pg_class c ON c.oid = r.ev_class
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE r.rulename <> '_RETURN'
		  AND n.nspname NOT LIKE 'pg\_temp%'
		  AND n.nspname NOT LIKE 'pg\_toast%'
		  AND n.nspname <> 'information_schema'
		  AND pg_catalog.pg_get_ruledef(r.oid) ~* '(INSERT[[:space:]]+INTO|UPDATE|DELETE[[:space:]]+FROM)[[:space:]]+(public\.)?(static_policies|dynamic_policies)'
	`).Scan(&planted); err != nil {
		t.Fatal(err)
	}
	if planted != 1 {
		t.Fatalf("the rule census found %d planted writer(s), want 1; the empty result above was not evidence of anything", planted)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("rolling back the probes: %v", err)
	}
	// AND THE ROLLBACK REALLY REMOVED THEM, so this test leaves the schema as
	// it found it for whatever runs next against this container.
	var left int
	if err := masterDB.QueryRow(
		`SELECT COUNT(*) FROM pg_catalog.pg_proc WHERE proname = 'w1c_probe_trigger_fn'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d probe object(s) survived the rollback", left)
	}
}

// TestTheIntegrationActivationFunctionStillWorksUnderTheAppRole_RealPG is the
// behavioural half of the fix, and it is the assertion that would have caught
// the defect in the first place.
//
// The census above is a property of the catalogue. This drives the actual call
// the agent makes, as the actual role it makes it as, on a database with 172
// applied - which is the only form that proves the integration policies still
// become enabled.
func TestTheIntegrationActivationFunctionStillWorksUnderTheAppRole_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	appRoleDB := appRoleConn(t, env.AppRoleDSN)

	// The shipped integration policies are seeded DISABLED by core/060 and are
	// enabled only by this function. Asserted first: if they are already
	// enabled, the activation below would report 0 and prove nothing.
	var disabled int
	if err := appRoleDB.QueryRow(
		`SELECT COUNT(*) FROM static_policies WHERE policy_id LIKE 'int_claude%' AND enabled = false`).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	if disabled == 0 {
		t.Fatal("no disabled int_claude% policies are present, so activating them cannot demonstrate anything")
	}

	var enabled int
	if err := appRoleDB.QueryRow(
		`SELECT activate_integration('claude-code', 'Claude Code', 'claude_code.', 'int_claude', 'runtime-e2e')`).Scan(&enabled); err != nil {
		t.Fatalf("the agent's integration activation call is refused for the app role after migration 172: %v\n"+
			"This runs on EVERY check_policy request. The function's write is to static_policies, which 172 revokes, "+
			"so it must run with the owner's authority (SECURITY DEFINER).", err)
	}
	if enabled != disabled {
		t.Fatalf("activate_integration enabled %d policies, expected %d", enabled, disabled)
	}

	// AND THE EFFECT, not only the return value.
	var stillDisabled int
	if err := appRoleDB.QueryRow(
		`SELECT COUNT(*) FROM static_policies WHERE policy_id LIKE 'int_claude%' AND enabled = false`).Scan(&stillDisabled); err != nil {
		t.Fatal(err)
	}
	if stillDisabled != 0 {
		t.Fatalf("%d int_claude%% policies are still disabled after activation", stillDisabled)
	}

	// AND THE DEFINER PRIVILEGE IS NOT A GENERAL WRITE PRIVILEGE. The role can
	// call the function; it still cannot write the table directly, which is
	// what makes this a re-homing rather than a hole.
	if _, err := appRoleDB.Exec(`UPDATE static_policies SET enabled = true WHERE policy_id LIKE 'int_claude%'`); err == nil {
		t.Fatal("the app role can write static_policies directly; the SECURITY DEFINER function was supposed to be the only route")
	}
}

// TestTheDefinerFunctionCannotReachAnotherOrgsRowsOrEnableEverything_RealPG is
// the bound SECURITY DEFINER removed and migration 172 writes back into the
// body.
//
// # What changed and why this test exists
//
// static_policies is ENABLE (not FORCE) ROW LEVEL SECURITY with
// `tenant_isolation_update USING (org_id = get_current_org_id())`. Under
// SECURITY INVOKER the application role was bound by that predicate. Under
// SECURITY DEFINER the body runs as the OWNER, for whom an un-FORCEd policy
// does not apply at all - so the same call would reach every organization's
// rows, and the caller-supplied p_policy_prefix would reach every POLICY,
// because an empty prefix makes the LIKE pattern '%'.
//
// Both bounds are now in the body. This test drives the function against rows
// belonging to another organization and against every prefix shape that could
// widen the match - the empty string, a bare wildcard, an underscore, an
// escape character and prefixes shorter than any real integration's - and it is
// deliberately NOT written as a count comparison: the previous test asserts
// `enabled == disabled` where both numbers come from the SAME RLS-scoped
// connection, so on an all-global fixture the two agree whether or not the
// bound exists. A cross-org row is the only input that separates them.
func TestTheDefinerFunctionCannotReachAnotherOrgsRowsOrEnableEverything_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = masterDB.Close() }()

	// A DISABLED int_* row belonging to a DIFFERENT organization. Inserted as
	// the owner, which is the only identity that can create it - which is
	// itself the point: the row is unreachable to the caller below except
	// through the definer function.
	const otherOrg = "org-elsewhere"
	if _, err := masterDB.Exec(`
		INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, tenant_id, org_id, enabled)
		VALUES ('int_claude_probe_other_org', 'probe', 'security-dangerous', 'probe', 'high', 'warn', $1, $1, false)
		ON CONFLICT (policy_id) DO NOTHING
	`, otherOrg); err != nil {
		t.Fatal(err)
	}
	var seeded int
	if err := masterDB.QueryRow(
		`SELECT COUNT(*) FROM static_policies WHERE policy_id = 'int_claude_probe_other_org' AND enabled = false`).Scan(&seeded); err != nil {
		t.Fatal(err)
	}
	if seeded != 1 {
		t.Fatalf("the cross-org probe row was not seeded (%d); this test would then pass without testing anything", seeded)
	}

	appRoleDB := appRoleConn(t, env.AppRoleDSN)

	// The real call, in the real scope: the agent wraps this in the 'global'
	// sentinel deliberately (#3048), which appRoleConn reproduces.
	if _, err := appRoleDB.Exec(
		`SELECT activate_integration('claude-code', 'Claude Code', 'claude_code.', 'int_claude', 'runtime-e2e')`); err != nil {
		t.Fatal(err)
	}

	// THE OTHER ORGANIZATION'S ROW IS UNTOUCHED.
	var stillDisabled bool
	if err := masterDB.QueryRow(
		`SELECT NOT enabled FROM static_policies WHERE policy_id = 'int_claude_probe_other_org'`).Scan(&stillDisabled); err != nil {
		t.Fatal(err)
	}
	if !stillDisabled {
		t.Fatal("activate_integration enabled a row belonging to another organization. SECURITY DEFINER runs as the OWNER, " +
			"for whom static_policies' ENABLE (not FORCE) row-level security does not apply, so the org predicate has to be " +
			"in the body - it is what tenant_isolation_update was providing before migration 172.")
	}

	// AND NO PREFIX WIDENS WHAT THE DEFINER PRIVILEGE REACHES.
	//
	// THE BLANK STRING IS NOT THE MECHANISM AND TESTING ONLY IT PROVED
	// NOTHING. The first version of this assertion drove `''` alone, on the
	// stated reasoning that "an empty prefix makes the LIKE pattern '%'" -
	// which named the pattern correctly and then guarded the input. `'%'` is
	// not empty, and under a LIKE it enabled every disabled policy in scope,
	// including rows with nothing to do with any integration. The mechanism is
	// the PATTERN, so the inputs that matter are the ones that ARE patterns.
	//
	// The fix has TWO halves and they must be asserted separately.
	//
	//   the LENGTH FLOOR   refuses anything under three characters
	//   starts_with()      removes pattern semantics from what survives it
	//
	// The first version of this table drove seven inputs of which every single
	// one was under three characters, so the floor accounted for all of them
	// and NOT ONE reached the match. Restoring `LIKE p_policy_prefix || '%'` -
	// the exact defect the round before had fixed - left every assertion here
	// green, while `'%a%'` enabled five policies. A table that cannot separate
	// the fixed code from the defect is not evidence about either.
	//
	// So the inputs below are in two classes, and the ones that MATTER are the
	// patterns long enough to pass the floor and reach starts_with().
	acceptedPatterns := 0
	for _, bad := range []struct {
		prefix      string
		why         string
		passesFloor bool
	}{
		// Refused by the length floor.
		{"", "the empty string, which under a LIKE is the pattern '%'", false},
		{"%", "a bare wildcard, which is NOT the empty string and was accepted by a guard that tested for one", false},
		{"_", "a single-character wildcard, the same class as %", false},
		{"%%", "two wildcards", false},
		{"\\", "a LIKE escape character", false},
		{"i", "one character - not a pattern, but far wider than any integration prefix", false},
		{"in", "two characters, same", false},

		// PASS the floor and reach the match. These are the only inputs in this
		// table that say anything about starts_with(); under a LIKE each of
		// them matches a broad swathe of static_policies.
		{"%a%", "three characters, and under a LIKE a substring wildcard matching most policy ids", true},
		{"%__", "a wildcard followed by two single-character wildcards", true},
		{"sys%", "the system-policy family under a wildcard - the widest single pattern that matters", true},
		{"_%_", "wildcards on both ends", true},
	} {
		var enabled int
		err := appRoleDB.QueryRow(`SELECT activate_integration('x', 'x', 'x', $1)`, bad.prefix).Scan(&enabled)
		if bad.passesFloor {
			// It must be ACCEPTED - if the floor refused it, this row is
			// testing the floor again and the pattern never reached the match.
			if err != nil {
				t.Errorf("prefix %q (%s) was refused before reaching the match, so it says nothing about starts_with(): %v",
					bad.prefix, bad.why, err)
				continue
			}
			acceptedPatterns++
			if enabled != 0 {
				t.Errorf("prefix %q (%s) reached the match and enabled %d policy(ies); the match still has pattern semantics",
					bad.prefix, bad.why, enabled)
			}
			continue
		}
		if err == nil && enabled > 0 {
			t.Errorf("prefix %q (%s) was accepted and enabled %d policy(ies). This function runs with the OWNER's "+
				"privileges and is the only write path into static_policies the application roles have after "+
				"migration 172.", bad.prefix, bad.why, enabled)
		}
	}

	// ANTI-VACUITY on the table itself: at least one input must have got past
	// the floor. This is the assertion whose absence let the whole table
	// collapse onto the floor once already.
	if acceptedPatterns == 0 {
		t.Error("no input reached the match; every row was refused by the length floor, so this table asserts nothing about starts_with()")
	}

	// AND THE CONTROL FOR ALL OF THAT: a well-formed prefix that is not one of
	// the shipped integrations matches nothing and is NOT an error. Without
	// this, every assertion above is satisfied by a function that refuses
	// everything.
	var none int
	if err := appRoleDB.QueryRow(
		`SELECT activate_integration('none', 'none', 'none', 'zzz_no_such_prefix')`).Scan(&none); err != nil {
		t.Fatalf("a well-formed prefix matching nothing was refused, so the refusals above prove only that the function "+
			"rejects things: %v", err)
	}
	if none != 0 {
		t.Fatalf("a prefix matching no policy enabled %d of them", none)
	}

	// NEGATIVE CONTROL: a real prefix that DOES match still enables its rows,
	// so the refusals above are about their own inputs and not about a
	// function that no longer works.
	var real int
	if err := appRoleDB.QueryRow(
		`SELECT activate_integration('openclaw', 'OpenClaw', 'openclaw.', 'int_openclaw', 'runtime-e2e')`).Scan(&real); err != nil {
		t.Fatalf("a well-formed activation was refused, so the assertions above prove nothing: %v", err)
	}
	if real == 0 {
		t.Fatal("a well-formed activation enabled nothing; starts_with() may not be matching what LIKE used to, and every " +
			"refusal above would then be satisfied by a function that matches nothing at all")
	}

	// THE GUARD AND THE MATCH MUST READ ONE STRING, NOT TWO.
	//
	// The length floor measures btrim(prefix). The match must use that same
	// trimmed value; when it read the RAW argument instead, a padded prefix
	// cleared a floor its own leading spaces had not been counted against and
	// then matched nothing - failing closed, returning 0, saying nothing.
	//
	// This has to be a POSITIVE to be worth anything. A padded prefix that
	// matches nothing is the expected outcome under BOTH readings, so an
	// assertion of zero cannot tell them apart; the row that first stood here
	// was exactly that and passed against the planted defect. So: plant a
	// disabled policy, activate it through a PADDED prefix, and require the
	// row to flip.
	if _, err := masterDB.Exec(
		`INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, org_id, enabled)
		 VALUES ('int_w1cpad_probe', 'padded prefix probe', 'integration', 'w1c-never-matches', 'low', 'warn', $1, false)`,
		seededOrgScope); err != nil {
		t.Fatalf("planting the padded-prefix probe: %v", err)
	}
	var padded int
	if err := appRoleDB.QueryRow(
		`SELECT activate_integration('w1cpad', 'W1C Pad', 'w1cpad.', $1, 'runtime-e2e')`,
		"  int_w1cpad").Scan(&padded); err != nil {
		t.Fatalf("a padded but otherwise well-formed prefix was refused: %v", err)
	}
	if padded != 1 {
		t.Errorf("a padded prefix enabled %d policy(ies), want 1: the length floor trims and the match does not, "+
			"so the two are reading different strings and the guard is measuring a value nothing uses", padded)
	}
}

// systemMediaPolicies is what migrations/core/173 seeds. Named individually
// because "five rows exist" is satisfied by five of anything.
var systemMediaPolicies = []string{
	"sys_media_nsfw_block", "sys_media_violence_warn", "sys_media_biometric_log",
	"sys_media_pii_block", "sys_media_sensitive_doc_warn",
}

// TestMigration173SeedsTheSystemMediaPoliciesOnAFreshStack_RealPG covers the
// gap migration 172 would otherwise open.
//
// These five governance rules appear in NO migration before 173: they were
// seeded only by platform/orchestrator/db_dynamic_policies.go, on the
// application connection, and its caller treated a failure as a log line. After
// 172 that INSERT is refused, so a FRESH stack would silently never get NSFW
// blocking, violence warning, biometric logging, media PII blocking or
// sensitive-document warning - while every EXISTING stack already holds the
// rows, which is why the gap is invisible everywhere anyone would inspect and
// bites only new deployments.
//
// #4026 removed the refused write rather than leaving it to fail: that boot path
// is now verifySystemMediaPolicies, a SELECT that reports absent rows at ERROR.
// So this migration is the ONLY writer of these rows, which is what makes the
// test below the thing that proves a fresh stack gets them at all.
//
// This harness IS a fresh stack: the container is created for the test and the
// orchestrator never runs against it, so the rows can only have come from the
// migration.
func TestMigration173SeedsTheSystemMediaPoliciesOnAFreshStack_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = masterDB.Close() }()
	if _, err := masterDB.Exec("SET row_security = off"); err != nil {
		t.Fatal(err)
	}

	for _, id := range systemMediaPolicies {
		var enabled bool
		var tier, policyType string
		err := masterDB.QueryRow(
			`SELECT enabled, tier, policy_type FROM dynamic_policies WHERE policy_id = $1`, id).Scan(&enabled, &tier, &policyType)
		if errors.Is(err, sql.ErrNoRows) {
			t.Errorf("%s is absent on a freshly migrated database. It exists in no migration before core/173, and after "+
				"core/172 the orchestrator's Go seeder cannot create it, so this deployment has no such governance rule.", id)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !enabled || tier != "system" || policyType != "media" {
			t.Errorf("%s: enabled=%t tier=%q policy_type=%q; the migration must reproduce the seeder's values exactly",
				id, enabled, tier, policyType)
		}
	}

	// RE-APPLIABLE, and the second application must change nothing: on every
	// existing stack the Go seeder created these rows long ago and the
	// migration is a no-op there.
	body, err := os.ReadFile("../../migrations/core/173_seed_system_media_policies.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := masterDB.Exec(string(body)); err != nil {
		t.Fatalf("re-applying migration 173 failed: %v", err)
	}
	var n int
	if err := masterDB.QueryRow(
		`SELECT COUNT(*) FROM dynamic_policies WHERE policy_id = ANY($1)`, pq.Array(systemMediaPolicies)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(systemMediaPolicies) {
		t.Fatalf("after re-applying 173 there are %d media policy rows, want %d; ON CONFLICT DO NOTHING should make it a no-op",
			n, len(systemMediaPolicies))
	}

	// DOWN, then UP again.
	downBody, err := os.ReadFile("../../migrations/core/173_seed_system_media_policies_down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := masterDB.Exec(string(downBody)); err != nil {
		t.Fatalf("migration 173 down failed: %v", err)
	}
	if err := masterDB.QueryRow(
		`SELECT COUNT(*) FROM dynamic_policies WHERE policy_id = ANY($1)`, pq.Array(systemMediaPolicies)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d media policy row(s) survived the down migration", n)
	}
	if _, err := masterDB.Exec(string(body)); err != nil {
		t.Fatalf("re-applying migration 173 after its down failed: %v", err)
	}
	if err := masterDB.QueryRow(
		`SELECT COUNT(*) FROM dynamic_policies WHERE policy_id = ANY($1)`, pq.Array(systemMediaPolicies)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(systemMediaPolicies) {
		t.Fatalf("after down-then-up there are %d media policy rows, want %d", n, len(systemMediaPolicies))
	}
}

// TestTheDefinerFunctionsCapabilitiesAreEachBounded is a CAPABILITY AUDIT, not
// another defect hunt.
//
// # Why this test has a different shape from the others
//
// Three review rounds each found a real, distinct defect in this one function -
// it ran as the caller, then it ran unbounded as the owner, then its bound was
// asserted against the wrong thing. Each round ended with "fixed", and twice
// that was wrong. An ABSENCE of findings cannot settle it, because absence is
// exactly what the first two rounds produced.
//
// So this enumerates what the function CAN DO and names the bound on each. It
// terminates when every capability has a bound with a live assertion, rather
// than when a reader fails to think of something.
//
//	capability                                  bound
//	------------------------------------------  --------------------------------
//	1. write integration_activations            the caller already holds direct
//	                                            write on it, so the definer adds
//	                                            no reach (asserted below)
//	2. set static_policies.enabled = true       prefix: starts_with + length >= 3
//	3.   ...in which organisations              org_id = get_current_org_id()
//	4.   ...writing which columns               `enabled` ONLY (asserted below)
//	5.   ...touching which rows                 enabled = false only; the write
//	                                            is monotone toward MORE
//	                                            enforcement, never less
//	6. who may EXECUTE it                       REVOKE FROM PUBLIC + GRANT to the
//	                                            two application roles
//	7. under which search_path                  pinned to public, pg_temp
//
// 2, 3, 6 and 7 are asserted by the tests above. 1, 4 and 5 are asserted here,
// and 1 is the one no round found: the function writes a SECOND table, and
// nothing had ever asked what bounds that.
func TestTheDefinerFunctionsCapabilitiesAreEachBounded_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = masterDB.Close() }()
	appRoleDB := appRoleConn(t, env.AppRoleDSN)

	// --- capability 1: the OTHER table this function writes ---------------
	//
	// integration_activations has no org_id, no tenant_id and no row-level
	// security, and the function INSERTs into it with caller-supplied
	// integration_id, display_name, connector_prefix and activated_by. The
	// bound is not a predicate: it is that the caller can already write that
	// table DIRECTLY, so running as the owner grants no reach it did not have.
	//
	// That bound is a fact about the grants rather than about this function,
	// which is exactly why it needs an assertion. The day a migration revokes
	// write on integration_activations from the application roles - the same
	// thing migration 172 does to the policy tables - this function silently
	// becomes a bypass of that revoke, and nothing else in this suite would
	// notice.
	for _, role := range []string{"axonflow_app_role", "axonflow_platform_admin"} {
		var direct bool
		if err := masterDB.QueryRow(`
			SELECT has_table_privilege($1, 'integration_activations', 'INSERT')
			   AND has_table_privilege($1, 'integration_activations', 'UPDATE')
		`, role).Scan(&direct); err != nil {
			t.Fatal(err)
		}
		if !direct {
			t.Errorf("%s can no longer write integration_activations directly, but activate_integration - which it may "+
				"EXECUTE - writes that table as the OWNER. The definer function is now a bypass of whatever revoked it. "+
				"Either restore the grant or bound the INSERT the way the static_policies UPDATE is bounded.", role)
		}
	}

	// --- capability 4 and 5: which columns, and in which direction --------
	//
	// Snapshotted whole and compared field by field, rather than asserting on
	// `enabled` alone: the point is that NOTHING ELSE moved, and a check that
	// only reads the column it expects to change cannot see the columns it
	// does not.
	type row struct {
		policyID, name, category, pattern, severity, action, tenantID, orgID string
		enabled                                                              bool
	}
	snapshot := func() map[string]row {
		out := map[string]row{}
		rows, err := masterDB.Query(`
			SELECT policy_id, name, COALESCE(category,''), COALESCE(pattern,''), COALESCE(severity,''),
			       COALESCE(action,''), COALESCE(tenant_id,''), COALESCE(org_id,''), enabled
			FROM static_policies WHERE policy_id LIKE 'int_%'`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.policyID, &r.name, &r.category, &r.pattern, &r.severity,
				&r.action, &r.tenantID, &r.orgID, &r.enabled); err != nil {
				t.Fatal(err)
			}
			out[r.policyID] = r
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	before := snapshot()
	if len(before) == 0 {
		t.Fatal("no int_% policies exist, so this audit is about nothing")
	}
	disabledBefore := 0
	for _, r := range before {
		if !r.enabled {
			disabledBefore++
		}
	}
	if disabledBefore == 0 {
		t.Fatal("every int_% policy is already enabled, so the write below changes nothing and the audit is vacuous")
	}

	var enabled int
	if err := appRoleDB.QueryRow(
		`SELECT activate_integration('claude-code', 'Claude Code', 'claude_code.', 'int_claude', 'capability-audit')`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}

	after := snapshot()
	if len(after) != len(before) {
		t.Fatalf("the function changed the NUMBER of int_%% rows (%d -> %d); it may only update", len(before), len(after))
	}
	changed, flipped := 0, 0
	for id, b := range before {
		a := after[id]
		if a.name != b.name || a.category != b.category || a.pattern != b.pattern ||
			a.severity != b.severity || a.action != b.action || a.tenantID != b.tenantID || a.orgID != b.orgID {
			t.Errorf("%s: a column other than `enabled` changed. before=%+v after=%+v", id, b, a)
			changed++
		}
		if a.enabled != b.enabled {
			flipped++
			// CAPABILITY 5: the write is MONOTONE toward more enforcement.
			// A function that could set enabled = false would be a
			// definer-privileged way to switch a control OFF, which is a
			// different and much worse capability than switching one on.
			if b.enabled && !a.enabled {
				t.Errorf("%s was DISABLED by activate_integration. The write must only ever enable: a definer-privileged "+
					"way to switch a control off is a different capability from one that switches a control on.", id)
			}
		}
	}
	if changed != 0 {
		t.Fatalf("%d row(s) had a column other than `enabled` rewritten", changed)
	}
	// ANTI-VACUITY for the column check: something must actually have moved,
	// or "nothing else changed" is satisfied by a call that did nothing.
	if flipped == 0 {
		t.Fatal("the activation flipped no row at all, so the column and direction assertions above are vacuous")
	}
	if flipped != enabled {
		t.Fatalf("the function reported enabling %d row(s) and %d changed; the return value must describe the write", enabled, flipped)
	}
}
