// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Behavioural proofs for enforce_legacy_policy_read_only(), the function
// migrations/core/174 installs to close the #3905 cross-tenant view write path.
//
// WHY THESE ARE A SEPARATE FILE FROM legacy_policy_view_write_paths_realpg_test.go.
// That file proves the ORDERING property - that industry views created after 174
// are bound by the boot-time call - which is the reason the function exists at
// all. These prove the function's own CAPABILITIES: which schemas it reaches,
// whether it is transitive, whether a temporary relation held by another session
// can stop it, and whether it is itself hardened against the privilege it holds.
//
// They were written alongside #3880's legacy-policy freeze and lived on that
// branch until the view closure split out into 174. Leaving them there would
// have made coverage for a MERGED security fix conditional on whether an
// unrelated feature ships, which is a routing accident rather than a decision.

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
)

// legacyPolicyViewClosure is the transitive set of views reaching either legacy
// policy table, derived through information_schema.
//
// IT IS DELIBERATELY NOT THE ENFORCER'S QUERY. The first version of this
// constant was a byte-for-byte copy of the pg_depend/pg_rewrite walk in
// migrations/core/174, under a comment asserting it was "asked here
// independently". A duplicated query agrees by construction just as surely as a
// shared one: it inherits every assumption of the original - the relkind
// filter, the schema handling, the join shape - and the two texts can also
// drift apart silently, since nothing pins them equal.
//
// information_schema.view_table_usage is a genuinely different path to the same
// fact: it is the SQL-standard view over the same dependency, maintained by
// PostgreSQL rather than assembled here. If the enforcer's catalogue walk is
// wrong, this does not repeat the error.
//
// Its one documented limitation is that it shows only relations the current
// user owns or has privileges on; these tests connect as the owner, for whom
// that is every relation in the schema. It also does not surface temporary
// views, which is why the temp-schema assertion below uses the catalogue form,
// and it filters to relkind in ('r','v','f','p'), so a materialized view in the
// middle of a chain truncates it - harmless, because a matview is not
// updatable and so is not a write path.
//
// IT IS NOT PINNED TO SCHEMA public, and it walks (schema, name) PAIRS rather
// than bare names. The first version did both wrong: it required
// `view_schema = 'public'` on every term, so a chain through a view in a
// `reporting` schema was invisible even when its endpoints were in public - a
// live auto-updatable write path that arrives writable through core/098's
// default privileges, absent from a census whose stated subject is "no relation
// in the closure is open". Joining on the bare name would also have collapsed
// two same-named views in different schemas into one node.
//
// That made the instrument strictly WEAKER than the enforcer it audits, which
// is the opposite of the point: an independent check that sees less than the
// thing it checks agrees with it for the wrong reason.
const legacyPolicyViewClosure = `
WITH RECURSIVE reached(sch, name) AS (
    SELECT t.view_schema::text, t.view_name::text
    FROM information_schema.view_table_usage t
    WHERE t.table_schema = 'public'
      AND t.table_name IN ('static_policies', 'dynamic_policies')
    UNION
    SELECT t2.view_schema::text, t2.view_name::text
    FROM information_schema.view_table_usage t2
    JOIN reached
      ON reached.sch = t2.table_schema::text
     AND reached.name = t2.table_name::text
)
SELECT r.sch AS nspname, r.name AS relname
FROM reached r
JOIN pg_catalog.pg_class c ON c.relname = r.name
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND n.nspname = r.sch
WHERE c.relkind = 'v'
ORDER BY r.sch, r.name`

// legacyPolicyViewClosureAllSchemas is the catalogue form, INCLUDING temporary
// and non-public schemas.
//
// It exists for one job: asserting that a relation the enforcer must cope with
// is genuinely in scope, as a precondition. It is not used to verify the
// enforcer's output - that would be the copy-of-the-original problem the
// constant above exists to avoid.
const legacyPolicyViewClosureAllSchemas = `
WITH RECURSIVE reached AS (
    SELECT c.oid
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname IN ('static_policies', 'dynamic_policies')
    UNION
    SELECT rw.ev_class
    FROM pg_catalog.pg_depend d
    JOIN pg_catalog.pg_rewrite rw ON rw.oid = d.objid AND d.classid = 'pg_rewrite'::regclass
    JOIN reached ON reached.oid = d.refobjid AND d.refclassid = 'pg_class'::regclass
    WHERE rw.ev_class <> d.refobjid
)
SELECT n.nspname, c.relname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN reached ON reached.oid = c.oid
WHERE c.relkind = 'v'
ORDER BY n.nspname, c.relname`

func legacyPolicyViews(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(legacyPolicyViewClosure)
	if err != nil {
		t.Fatalf("computing the view closure over the legacy policy tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var sch, name string
		if err := rows.Scan(&sch, &name); err != nil {
			t.Fatal(err)
		}
		out = append(out, sch+"."+name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAnAutoUpdatableViewIsNotAWritePathIntoALegacyPolicyTable_RealPG carries
// its own control, in-process, rather than relying on a planted defect run by
// hand.
//
// The refusal on its own is weak evidence: a role that never had the grant
// would produce exactly the same "permission denied", so the test would pass
// on a database where the view is not a write path at all and the assertion
// means nothing. So the test first GRANTS the write back, drives it, and
// requires it to succeed AND to have changed the underlying table - which is
// the pre-fix state, measured rather than described - and only then re-runs
// the enforcer and requires the refusal.
func TestAnAutoUpdatableViewIsNotAWritePathIntoALegacyPolicyTable_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ownerDB.Close() }()

	const view = "eu_ai_act_compliance_summary"

	// ANTI-VACUITY 1: the view has to exist and be auto-updatable, or the
	// whole test is about a relation nobody can write anyway.
	var updatable bool
	if err := ownerDB.QueryRow(
		`SELECT pg_relation_is_updatable($1::regclass, false) & 4 <> 0`, view,
	).Scan(&updatable); err != nil {
		t.Fatalf("asking whether %s is updatable: %v", view, err)
	}
	if !updatable {
		t.Fatalf("%s is not auto-updatable, so this test asserts nothing; if the view definition changed, the finding it guards changed with it", view)
	}

	// A row in a DIFFERENT org from the one the app-role session is scoped to.
	// static_policies is ENABLE (not FORCE) RLS, so a write through an
	// owner-owned view is bound by neither the grant nor the org policy - the
	// cross-org row is what makes that concrete rather than theoretical.
	const otherOrg = "w1c-other-org"
	if _, err := ownerDB.Exec(
		`INSERT INTO static_policies (policy_id, name, category, org_id, enabled, action, pattern)
		 VALUES ('w1c-view-probe', 'view probe', 'compliance-euaiact', $1, true, 'block', 'w1c-never-matches')`, otherOrg,
	); err != nil {
		t.Fatalf("planting the cross-org probe row: %v", err)
	}

	appRoleDB := viewWriteAppRoleConn(t, env.AppRoleDSN)

	// ANTI-VACUITY 2: the app role must not be able to see that row directly.
	// If it could, the view would not be adding any reach and the test would
	// be measuring RLS rather than the view.
	var visible int
	if err := appRoleDB.QueryRow(
		`SELECT COUNT(*) FROM static_policies WHERE policy_id = 'w1c-view-probe'`,
	).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("the app role can see the cross-org row directly (%d), so this test is not measuring the view", visible)
	}

	// ANTI-VACUITY 3: and it MUST be visible THROUGH the view, or every write
	// below matches zero rows and reports success while changing nothing -
	// which is exactly what a probe row carrying core/127's pre-canonical
	// category spelling did here, passing the refusals and failing the control.
	//
	// That the count is 1 is itself the reach: an owner-owned view is not
	// bound by static_policies' ENABLE (not FORCE) RLS, so the app role reads
	// a row through it that migration 018 hides from it directly.
	var throughView int
	if err := appRoleDB.QueryRow(
		`SELECT COUNT(*) FROM ` + view + ` WHERE policy_id = 'w1c-view-probe'`,
	).Scan(&throughView); err != nil {
		t.Fatalf("the app role cannot read %s at all, so the write assertions below are not about a reachable row: %v", view, err)
	}
	if throughView != 1 {
		t.Fatalf("the cross-org probe row is not visible through %s (%d rows), so every write below would match nothing and succeed vacuously", view, throughView)
	}

	writes := map[string]string{
		"UPDATE": `UPDATE ` + view + ` SET enabled = false WHERE policy_id = 'w1c-view-probe'`,
		"DELETE": `DELETE FROM ` + view + ` WHERE policy_id = 'w1c-view-probe'`,
	}

	// THE ASSERTION.
	for name, stmt := range writes {
		if _, err := appRoleDB.Exec(stmt); err == nil {
			t.Fatalf("the app role executed %s through %s and reached static_policies; the view is a write path migration 174 has not closed", name, view)
		} else if !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%s through %s failed for the wrong reason (want a privilege refusal): %v", name, view, err)
		}
	}

	// THE CONTROL. Restore the grant core/098 gave and 174 took away, and
	// require the write to succeed and to land in the table. Without this the
	// refusals above are consistent with a database where nothing was ever
	// writable through the view.
	if _, err := ownerDB.Exec(`GRANT UPDATE ON ` + view + ` TO axonflow_app_role`); err != nil {
		t.Fatalf("control: re-granting UPDATE on %s: %v", view, err)
	}
	if _, err := appRoleDB.Exec(writes["UPDATE"]); err != nil {
		t.Fatalf("control: with the grant restored the app role should be able to write through %s, and could not: %v", view, err)
	}
	var enabled bool
	if err := ownerDB.QueryRow(
		`SELECT enabled FROM static_policies WHERE policy_id = 'w1c-view-probe'`,
	).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("control: the write through the view reported success but static_policies is unchanged, so the view is not the write path this test claims it is")
	}
	t.Logf("control fires: with the 098 grant restored, the app role wrote a %q row through %s while scoped to %q", otherOrg, view, seededOrgScope)

	// AND THE ENFORCER CLOSES IT AGAIN - which is the property the boot-time
	// call depends on, as distinct from the property the migration established.
	var bound int
	if err := ownerDB.QueryRow(`SELECT enforce_legacy_policy_read_only()`).Scan(&bound); err != nil {
		t.Fatalf("re-running the enforcer: %v", err)
	}
	if bound == 0 {
		t.Fatal("the enforcer bound zero (view, role) pairs, so it is not the thing closing the door")
	}
	if _, err := appRoleDB.Exec(writes["UPDATE"]); err == nil {
		t.Fatalf("after the enforcer ran, the app role could still write through %s", view)
	}
}

// TestNoRelationReachingALegacyPolicyTableConfersWriteOnAnApplicationRole_RealPG
// is the census form: not "this view is closed" but "no relation in the
// closure is open", which is the claim the PR actually makes.
func TestNoRelationReachingALegacyPolicyTableConfersWriteOnAnApplicationRole_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ownerDB.Close() }()

	views := legacyPolicyViews(t, ownerDB)
	// ANTI-VACUITY: a closure that came back empty would satisfy every
	// assertion below. migrations/core carries exactly one such view; the
	// industry verticals add seven more, and those are covered by the
	// after-the-fact test below rather than here, because this fixture applies
	// migrations/core only.
	if len(views) == 0 {
		t.Fatal("the view closure over the legacy policy tables is empty, so this census checks nothing")
	}
	t.Logf("closure: %d view(s) reach a legacy policy table: %v", len(views), views)

	check := func(t *testing.T) []string {
		t.Helper()
		var open []string
		for _, v := range views {
			for _, role := range []string{"axonflow_app_role", "axonflow_platform_admin"} {
				var writable bool
				if err := ownerDB.QueryRow(`
					SELECT has_table_privilege($1, $2, 'INSERT')
					    OR has_table_privilege($1, $2, 'UPDATE')
					    OR has_table_privilege($1, $2, 'DELETE')
					    OR has_table_privilege($1, $2, 'TRUNCATE')
					    OR has_any_column_privilege($1, $2, 'INSERT')
					    OR has_any_column_privilege($1, $2, 'UPDATE')`,
					role, v).Scan(&writable); err != nil {
					t.Fatal(err)
				}
				if writable {
					open = append(open, role+" -> "+v)
				}
			}
		}
		return open
	}

	if open := check(t); len(open) != 0 {
		t.Fatalf("%d (role, view) pair(s) confer a write reaching a legacy policy table: %v", len(open), open)
	}

	// CONTROL, and specifically a COLUMN-level grant, because the relation-level
	// check alone would pass on one - and `enabled` is exactly the column the
	// legacy surfaces toggle.
	if _, err := ownerDB.Exec(`GRANT UPDATE (enabled) ON ` + views[0] + ` TO axonflow_app_role`); err != nil {
		t.Fatalf("control: planting a column-level grant on %s: %v", views[0], err)
	}
	if open := check(t); len(open) == 0 {
		t.Fatalf("control did not fire: a column-level GRANT UPDATE (enabled) on %s left the census green", views[0])
	}
	t.Logf("control fires: a column-level grant on %s is detected", views[0])

	// And the enforcer removes a column-level grant too - REVOKE on the
	// relation revokes the column privileges with it, which is documented
	// behaviour this test pins rather than assumes.
	if _, err := ownerDB.Exec(`SELECT enforce_legacy_policy_read_only()`); err != nil {
		t.Fatalf("re-running the enforcer after the control: %v", err)
	}
	if open := check(t); len(open) != 0 {
		t.Fatalf("the enforcer left %d pair(s) open after a column-level grant: %v", len(open), open)
	}
}

// TestAViewCreatedAfterMigration174IsBoundByTheEnforcer_RealPG is the test for
// the reason the enforcer is called from the boot path at all.
//
// It simulates what migrations/industry/travel/200 and industry/banking/{300,
// 302,401} do on a FRESH deployment: create a view over static_policies AFTER
// core/174 has already run. Seven of the eight such views in this tree are
// created that way, and industry migrations are numbered 200+ precisely so
// that they run last.
//
// The first assertion is the one that matters. It requires the new view to be
// WRITABLE the moment it is created - not as a bug to be fixed, but as the
// premise: if ALTER DEFAULT PRIVILEGES ever stops arming new views, this test
// starts passing for a reason that has nothing to do with the enforcer, and it
// says so instead.
func TestAViewCreatedAfterMigration174IsBoundByTheEnforcer_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ownerDB.Close() }()

	const view = "w1c_industry_probe_summary"
	if _, err := ownerDB.Exec(`CREATE VIEW ` + view + ` AS
		SELECT policy_id, name, category, org_id, enabled FROM static_policies`); err != nil {
		t.Fatalf("creating the post-174 view: %v", err)
	}
	t.Cleanup(func() { _, _ = ownerDB.Exec(`DROP VIEW IF EXISTS ` + view) })

	writable := func() bool {
		t.Helper()
		var w bool
		if err := ownerDB.QueryRow(
			`SELECT has_table_privilege('axonflow_app_role', $1, 'UPDATE')`, view,
		).Scan(&w); err != nil {
			t.Fatal(err)
		}
		return w
	}

	// THE PREMISE, asserted rather than assumed.
	if !writable() {
		t.Fatalf("a view created after core/174 was NOT granted UPDATE to the app role; ALTER DEFAULT PRIVILEGES no longer arms new views, so the gap this enforcer closes may no longer exist and the reasoning in core/174 needs revisiting")
	}
	t.Logf("premise holds: %s was writable by axonflow_app_role the moment it was created, with core/174 already applied", view)

	// It is also in the closure - a view the enforcer cannot SEE is one it
	// cannot bind, and the closure query is the half of this that a literal
	// list of view names would get wrong.
	found := false
	for _, v := range legacyPolicyViews(t, ownerDB) {
		if v == "public."+view {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s reaches static_policies but is not in the closure the enforcer walks", view)
	}

	if _, err := ownerDB.Exec(`SELECT enforce_legacy_policy_read_only()`); err != nil {
		t.Fatalf("running the enforcer: %v", err)
	}
	if writable() {
		t.Fatalf("%s is still writable by the app role after the enforcer ran; a fresh industry deployment would ship with the legacy write path open", view)
	}

	// AND THE BOOT PATH'S OWN WRAPPER, not just the SQL function it calls.
	// This is the code that actually runs on a deployment; asserting only the
	// function would leave the Go half - the presence probe and the decision to
	// treat absence differently from failure - uncovered.
	//
	// Re-granting first makes the call do WORK rather than confirm a state that
	// was already correct, which is the difference between exercising it and
	// watching it return.
	if _, err := ownerDB.Exec(`GRANT UPDATE ON ` + view + ` TO axonflow_app_role`); err != nil {
		t.Fatal(err)
	}
	if !writable() {
		t.Fatal("re-granting UPDATE did not make the view writable, so the call below has nothing to undo")
	}
	enforceLegacyPolicyReadOnly(ownerDB)
	if writable() {
		t.Fatalf("enforceLegacyPolicyReadOnly left %s writable by the app role", view)
	}

	// THE ABSENT-FUNCTION BRANCH. A schema predating core/174 must be a skip,
	// not a failure. The assertion is structural rather than textual: if the
	// wrapper treated absence as an error it would log.Fatal, which takes this
	// test binary down with it - so reaching the next line IS the assertion.
	if _, err := ownerDB.Exec(`DROP FUNCTION enforce_legacy_policy_read_only()`); err != nil {
		t.Fatal(err)
	}
	enforceLegacyPolicyReadOnly(ownerDB)
	t.Log("a schema without the enforcer is a skip, not a boot failure")
}

// TestTheEnforcerBindsViewsInEverySchemaAndIsUnmovedByATemporaryOne_RealPG is
// four measurements against one function, and every one of them was a live
// defect in the first version of it.
//
// The first version projected `relname` alone and revoked with %I on the bare
// name, which resolves against the FUNCTION's search_path rather than against
// the schema the relation is actually in. That is not a tidiness problem:
//
//   - a TEMP view over static_policies, held by ANY other session, made the
//     function raise `relation "..." does not exist` - and the caller treats a
//     failure as fatal, so it killed the agent at boot, killed this migration's
//     apply, and killed its rollback. Externally triggerable by an operator's
//     psql session, transient, and leaving nothing behind afterwards.
//   - a view in a NON-PUBLIC schema did the same thing permanently.
//   - and where the same name existed in two schemas, the REVOKE landed on the
//     WRONG relation.
//
// The fourth is the property the migration claims in prose and nothing tested:
// the closure is TRANSITIVE, so a view over a view is bound. A one-hop
// enforcer passed every other test in this file.
func TestTheEnforcerBindsViewsInEverySchemaAndIsUnmovedByATemporaryOne_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	ownerDB.SetMaxOpenConns(1)
	defer func() { _ = ownerDB.Close() }()

	// A SECOND SESSION holding a temp view, exactly as an operator's psql
	// would. It must stay open for the duration - a temp relation lives and
	// dies with its session, so a closed connection would test nothing.
	peer, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	peer.SetMaxOpenConns(1)
	defer func() { _ = peer.Close() }()
	if _, err := peer.Exec(`CREATE TEMP VIEW zz_operator_peek AS
		SELECT policy_id, org_id, enabled FROM public.static_policies`); err != nil {
		t.Fatalf("the peer session could not create its temp view: %v", err)
	}
	var peerSchema string
	if err := peer.QueryRow(`SELECT n.nspname FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relname = 'zz_operator_peek'`).Scan(&peerSchema); err != nil {
		t.Fatal(err)
	}
	// ANTI-VACUITY: the temp view must actually be in the closure, or its
	// presence proves nothing about how the enforcer handles it.
	var inClosure int
	if err := ownerDB.QueryRow(`SELECT COUNT(*) FROM (` + legacyPolicyViewClosureAllSchemas + `) q WHERE q.relname = 'zz_operator_peek'`).Scan(&inClosure); err != nil {
		t.Fatal(err)
	}
	if inClosure == 0 {
		t.Fatalf("the peer's temp view in %s is not in the closure, so this test does not exercise the case that killed the agent", peerSchema)
	}
	t.Logf("a peer session holds a temp view in %s, and it IS in the closure", peerSchema)

	// A PERMANENT view in a non-public schema - an analytics or reporting view
	// on an in-VPC stack. This one is a genuine bypass and must be BOUND, not
	// skipped: it is owned by the table owner, so writes through it run with
	// the owner's privileges.
	if _, err := ownerDB.Exec(`CREATE SCHEMA IF NOT EXISTS reporting`); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDB.Exec(`CREATE VIEW reporting.policy_report AS
		SELECT policy_id, name, category, org_id, enabled FROM public.static_policies`); err != nil {
		t.Fatal(err)
	}
	// A COLLIDING NAME in public, which is what made the bare-name REVOKE land
	// on the wrong relation.
	if _, err := ownerDB.Exec(`CREATE VIEW public.policy_report AS
		SELECT policy_id, name, category, org_id, enabled FROM public.dynamic_policies`); err != nil {
		t.Fatal(err)
	}
	// AND A VIEW OVER A VIEW, for the transitivity claim.
	if _, err := ownerDB.Exec(`CREATE VIEW public.policy_report_v2 AS
		SELECT policy_id, name, org_id, enabled FROM public.policy_report`); err != nil {
		t.Fatal(err)
	}
	// AND A CHAIN THAT PASSES THROUGH A NON-PUBLIC SCHEMA AND COMES BACK.
	// Both endpoints are in `public` and the middle is not, which is the shape
	// that defeated the first information_schema census: it pinned
	// `view_schema = 'public'` on every term, so the chain broke at the middle
	// and the endpoint vanished from a census whose subject is "no relation in
	// the closure is open". This one arrives writable through core/098's
	// default privileges, so it is a live path and not a shape exercise.
	if _, err := ownerDB.Exec(`CREATE VIEW public.top_over_reporting AS
		SELECT policy_id, name, org_id, enabled FROM reporting.policy_report`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = ownerDB.Exec(`DROP VIEW IF EXISTS public.top_over_reporting`)
		_, _ = ownerDB.Exec(`DROP VIEW IF EXISTS public.policy_report_v2`)
		_, _ = ownerDB.Exec(`DROP VIEW IF EXISTS public.policy_report`)
		_, _ = ownerDB.Exec(`DROP SCHEMA IF EXISTS reporting CASCADE`)
	})

	writable := func(schema, name string) bool {
		t.Helper()
		var w bool
		if err := ownerDB.QueryRow(
			`SELECT has_table_privilege('axonflow_app_role', ($1 || '.' || $2)::regclass, 'UPDATE')`,
			schema, name).Scan(&w); err != nil {
			t.Fatal(err)
		}
		return w
	}

	// PREMISE, and it is not uniform across the three - which is worth stating,
	// because assuming it was is what this test caught in its own first draft.
	//
	// core/098's ALTER DEFAULT PRIVILEGES is scoped `IN SCHEMA public`, so the
	// two views in public arrive writable and the one in `reporting` does NOT.
	// The non-public case is therefore not a silent bypass by default; its
	// hazard is that the enforcer RAISES on it, which is fatal to the caller.
	// An explicit grant is added so it is also a live write path here, because
	// an operator or a schema with its own default privileges can produce one
	// and the enforcer must bind it rather than merely survive it.
	for _, v := range [][2]string{{"public", "policy_report"}, {"public", "policy_report_v2"}, {"public", "top_over_reporting"}} {
		if !writable(v[0], v[1]) {
			t.Fatalf("%s.%s did not arrive writable; ALTER DEFAULT PRIVILEGES no longer arms new views in public, "+
				"so the gap core/174 reasons about may have changed shape", v[0], v[1])
		}
	}

	// AND THE INDEPENDENT CENSUS MUST SEE THE WHOLE CHAIN, not just the ends.
	// An auditing instrument that sees less than the thing it audits agrees
	// with it for the wrong reason.
	census := legacyPolicyViews(t, ownerDB)
	for _, want := range []string{"reporting.policy_report", "public.top_over_reporting"} {
		found := false
		for _, got := range census {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is an auto-updatable path into static_policies and is absent from the information_schema census (%v)", want, census)
		}
	}
	if writable("reporting", "policy_report") {
		t.Fatal("reporting.policy_report arrived writable, which means default privileges now reach outside schema public; " +
			"the reasoning in this test and in core/174 assumes they do not")
	}
	if _, err := ownerDB.Exec(`GRANT INSERT, UPDATE, DELETE ON reporting.policy_report TO axonflow_app_role`); err != nil {
		t.Fatal(err)
	}
	if !writable("reporting", "policy_report") {
		t.Fatal("the explicit grant on reporting.policy_report did not take, so the assertion below is vacuous")
	}

	// THE CALL. Under the first version this raised and took the agent with it.
	var revoked int
	if err := ownerDB.QueryRow(`SELECT enforce_legacy_policy_read_only()`).Scan(&revoked); err != nil {
		t.Fatalf("the enforcer raised while a peer session held a temp view over static_policies. "+
			"This is what killed the agent at boot, and it takes the migration apply and the rollback with it: %v", err)
	}
	t.Logf("the enforcer revoked %d (view, role) grant(s) with a peer temp view live", revoked)

	// EVERY permanent view bound, in whatever schema - including the one two
	// hops from the table.
	for _, v := range [][2]string{{"reporting", "policy_report"}, {"public", "policy_report"}, {"public", "policy_report_v2"}, {"public", "top_over_reporting"}} {
		if writable(v[0], v[1]) {
			t.Errorf("%s.%s is still writable by the app role after the enforcer ran", v[0], v[1])
		}
	}

	// AND THE TEMP VIEW IS UNTOUCHED, which is the deliberate half. A view's
	// writes run with the VIEW OWNER's privileges, so a temp view owned by an
	// application role buys that role nothing it does not already have - and a
	// temp view owned by anyone else is not ours to revoke.
	var tempStillThere int
	if err := peer.QueryRow(`SELECT COUNT(*) FROM pg_class WHERE relname = 'zz_operator_peek'`).Scan(&tempStillThere); err != nil {
		t.Fatal(err)
	}
	if tempStillThere != 1 {
		t.Errorf("the peer's temp view is gone (%d); the enforcer should leave temporary relations alone", tempStillThere)
	}
}

// TestTheEnforcerIsItselfHardened_RealPG asserts the properties the pg_proc
// census would have asserted if the function's body had happened to name a
// legacy table next to a write verb.
//
// It does not, so the census's three property checks never run on it, and the
// only census that names it is the dynamic-writer sweep - where the allow-list
// removes it with no property assertion at all. A SECURITY DEFINER function
// that REVOKEs is exactly the shape those properties exist for, so they are
// asserted here directly rather than left to a regex that happens not to match.
func TestTheEnforcerIsItselfHardened_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = masterDB.Close() }()

	var definer bool
	var config, acl sql.NullString
	if err := masterDB.QueryRow(`
		SELECT p.prosecdef,
		       array_to_string(p.proconfig, ','),
		       COALESCE(array_to_string(p.proacl, ','), '')
		FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public' AND p.proname = 'enforce_legacy_policy_read_only'`,
	).Scan(&definer, &config, &acl); err != nil {
		t.Fatalf("the enforcer is not in the catalogue at all: %v", err)
	}

	if !definer {
		t.Error("enforce_legacy_policy_read_only() is not SECURITY DEFINER, so it cannot REVOKE and the invariant is unenforced")
	}
	if !strings.Contains(config.String, "search_path=") {
		t.Errorf("enforce_legacy_policy_read_only() has no pinned search_path (proconfig %q); a definer function without one resolves names against the CALLER's path", config.String)
	}
	// PUBLIC is the grantee-less ACL entry, and an EMPTY acl means default
	// privileges - which for a function IS EXECUTE to PUBLIC.
	public := acl.String == ""
	for _, item := range strings.Split(acl.String, ",") {
		if strings.HasPrefix(strings.TrimSpace(item), "=") {
			public = true
		}
	}
	if public {
		t.Errorf("EXECUTE on enforce_legacy_policy_read_only() is available to PUBLIC (acl %q)", acl.String)
	}

	// AND NEITHER APPLICATION ROLE MAY EXECUTE IT. This is stronger than the
	// PUBLIC check and is the property 174's own comment claims: granting an
	// application role an owner-privileged REVOKE loop would hand back the
	// authority the migration exists to take away.
	for _, role := range []string{"axonflow_app_role", "axonflow_platform_admin"} {
		var may bool
		if err := masterDB.QueryRow(
			`SELECT has_function_privilege($1, 'public.enforce_legacy_policy_read_only()', 'EXECUTE')`, role,
		).Scan(&may); err != nil {
			t.Fatal(err)
		}
		if may {
			t.Errorf("%s may EXECUTE enforce_legacy_policy_read_only(); 174's own comment calls that "+
				"\"handing out the authority this migration exists to take away\"", role)
		}
	}
}
