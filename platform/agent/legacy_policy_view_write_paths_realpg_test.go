// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
)

// seededOrgScope is declared in legacy_policy_read_only_realpg_test.go, in the
// same package, with the measured row counts beside it. One declaration only.

// viewWriteAppRoleConn opens an app-role connection pinned to ONE physical
// connection and scoped to the seeded organization.
//
// SetMaxOpenConns(1) is load bearing: set_config(..., false) is SESSION scoped,
// so on a pool the next statement can land on a connection that never saw it.
func viewWriteAppRoleConn(t *testing.T, dsn string) *sql.DB {
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

// applyIndustryChain applies migrations/industry/<vertical>/*.sql in the order
// the migration runner would, which for this test is the entire point.
//
// Industry migrations are numbered 200+ SPECIFICALLY so that they run after
// core and enterprise (platform/agent/migration_helpers.go). That ordering is
// the whole risk: core/174 has already run by the time these views are created,
// and core/098's ALTER DEFAULT PRIVILEGES grants each one write as it appears.
// Inferring the outcome from the shape of the view definitions cannot see an
// ordering property, so this test creates them the way a deployment does.
func applyIndustryChain(t *testing.T, db *sql.DB) []string {
	t.Helper()
	// ENTERPRISE FIRST, THEN INDUSTRY, which is the order the runner uses and
	// is not optional here: industry/travel/201 creates objects over
	// `euaiact_exports`, an enterprise table, and fails outright without it.
	// The in-vpc-* modes that carry these verticals apply all three categories.
	var files []string
	for _, dir := range []string{
		"../../migrations/enterprise",
		"../../migrations/industry/travel",
		"../../migrations/industry/banking",
	} {
		matches, err := filepath.Glob(filepath.Join(dir, "*.sql"))
		if err != nil {
			t.Fatal(err)
		}
		var inDir []string
		for _, m := range matches {
			if strings.HasSuffix(m, "_down.sql") {
				continue
			}
			inDir = append(inDir, m)
		}
		sort.Strings(inDir)
		files = append(files, inDir...)
	}
	// Numeric prefixes are fixed-width, so a lexical sort WITHIN a directory is
	// the numeric one; asserted rather than assumed, because a 4-digit
	// migration would silently reorder the chain. The directories themselves
	// are ordered explicitly above and NOT re-sorted together, since enterprise
	// numbers (100-199) and industry numbers (200+) must not interleave.
	for _, f := range files {
		base := filepath.Base(f)
		if len(base) < 4 || base[3] != '_' {
			t.Fatalf("migration %q does not carry a 3-digit prefix, so the lexical sort is not the numeric one", base)
		}
	}

	applied := make([]string, 0, len(files))
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("applying %s: %v", f, err)
		}
		applied = append(applied, filepath.Base(f))
	}
	if len(applied) == 0 {
		t.Fatal("no enterprise or industry migrations were applied, so this test asserts nothing about the ordering it exists to check")
	}
	return applied
}

// industryPolicyViews are the views over static_policies that are actually
// AUTO-UPDATABLE, named individually because "some views were bound" is
// satisfied by any number of them.
//
// THE LIST IS FOUR, NOT SEVEN, AND THAT CORRECTION CAME FROM RUNNING IT.
// An earlier version listed every view whose definition selects from
// static_policies, on the reasoning that they were "the same shape". Driven
// against a real chain, three of them are not:
//
//	sebi_audit_retention_status  LEFT JOIN policy_violations + COUNT + GROUP BY
//	mas_audit_retention_status   same shape
//	mas_feat_pillar_coverage     COUNT(*) + GROUP BY
//
// A view with a join, an aggregate or a GROUP BY is not auto-updatable, so no
// write can be routed through it and it is not part of this class at all.
// Listing them here would have made this test assert something false, and
// listing them in the issue overstated the exposure - shape inference reading
// "selects from static_policies" as "is a write path".
//
// eu_ai_act_compliance_summary is NOT here either, for a different reason: it
// is created by core/014, so it exists when core/174 runs and is bound by the
// migration itself. This list is specifically the views created AFTER 174, by
// the industry chain, which are the ones only the boot-time call can reach.
var industryPolicyViews = []string{
	"sebi_compliance_summary",        // banking/300
	"rbi_free_ai_compliance_summary", // banking/302
	"rbi_pii_detection_summary",      // banking/302
	"mas_feat_compliance_summary",    // banking/401
}

// notAutoUpdatableViews select from static_policies and are NOT write paths.
// They are asserted explicitly rather than merely omitted, so that a future
// edit which removes an aggregate - turning one of them into an auto-updatable
// view - is caught here rather than silently widening the class.
var notAutoUpdatableViews = []string{
	"sebi_audit_retention_status",
	"mas_audit_retention_status",
	"mas_feat_pillar_coverage",
}

// TestTheIndustryViewsAreBoundOnAFreshDeployment_RealPG is the test the whole
// migration exists for, and it is an ORDERING test rather than a shape test.
//
// On a fresh in-vpc-banking or travel deployment the sequence is:
//
//	core/…/174 runs          <- binds the closure that exists NOW (one view)
//	industry/200…401 run     <- create SEVEN more, each granted write on sight
//	                            by core/098's ALTER DEFAULT PRIVILEGES
//	the agent calls the enforcer once more, after all DDL
//
// Take the last step away and seven cross-tenant write paths ship open. No
// inspection of the view definitions can see that, because nothing about their
// SQL is wrong - the defect is entirely in when they are created relative to
// the thing that binds them.
func TestTheIndustryViewsAreBoundOnAFreshDeployment_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	ownerDB.SetMaxOpenConns(1)
	defer func() { _ = ownerDB.Close() }()

	applied := applyIndustryChain(t, ownerDB)
	t.Logf("applied %d enterprise+industry migration(s) after core/174; the last is %s", len(applied), applied[len(applied)-1])

	writable := func(view string) bool {
		t.Helper()
		var w bool
		if err := ownerDB.QueryRow(`
			SELECT has_table_privilege('axonflow_app_role', $1, 'INSERT')
			    OR has_table_privilege('axonflow_app_role', $1, 'UPDATE')
			    OR has_table_privilege('axonflow_app_role', $1, 'DELETE')`, view).Scan(&w); err != nil {
			t.Fatal(err)
		}
		return w
	}
	updatable := func(view string) bool {
		t.Helper()
		var u bool
		if err := ownerDB.QueryRow(
			`SELECT pg_relation_is_updatable($1::regclass, false) & 4 <> 0`, view).Scan(&u); err != nil {
			t.Fatal(err)
		}
		return u
	}

	// THE PREMISE, and it is the finding rather than setup. Every one of these
	// must exist, be auto-updatable, and have arrived WRITABLE - created after
	// the migration that was supposed to bind them.
	openOnArrival := 0
	for _, v := range industryPolicyViews {
		var exists bool
		if err := ownerDB.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, v).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("%s was not created by the industry chain; this test is naming a view that no longer exists", v)
		}
		if !updatable(v) {
			t.Errorf("%s is not auto-updatable, so it is not the write path this test claims; if its definition changed, re-derive the list", v)
			continue
		}
		if writable(v) {
			openOnArrival++
		}
	}

	// AND THE OTHER DIRECTION: the views excluded from the list must still be
	// excluded for the stated reason. An aggregate removed from one of these
	// turns it into an auto-updatable write path, and this class would widen
	// with nothing reporting it.
	for _, v := range notAutoUpdatableViews {
		var exists bool
		if err := ownerDB.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, v).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			continue
		}
		if updatable(v) {
			t.Errorf("%s is now AUTO-UPDATABLE and is excluded from industryPolicyViews on the grounds that it is not. "+
				"Its definition has lost the join or aggregate that made it read-only, so it is a write path this test "+
				"is not covering - add it to the list.", v)
		}
	}
	if openOnArrival == 0 {
		t.Fatal("no industry view arrived writable, so the enforcer has nothing to do here and every assertion below would " +
			"hold of a function that returned immediately. Either core/098's ALTER DEFAULT PRIVILEGES no longer arms new " +
			"views, or the industry chain now runs before core - both change the reasoning in migrations/core/174.")
	}
	t.Logf("PREMISE: %d of %d auto-updatable industry views arrived WRITABLE by axonflow_app_role, created after core/174 had already run",
		openOnArrival, len(industryPolicyViews))

	// THE BOOT-PATH CALL, which is the thing under test - not the SQL function
	// directly, because "the agent calls it after all DDL" is the claim.
	enforceLegacyPolicyReadOnly(ownerDB)

	for _, v := range industryPolicyViews {
		if writable(v) {
			t.Errorf("%s is still writable by axonflow_app_role after the enforcer ran; a fresh industry deployment ships "+
				"with this cross-tenant write path open", v)
		}
	}
}

// TestAnIndustryViewCannotCrossTheOrgBoundary_RealPG drives the #3905
// measurement itself, on an industry view, before and after.
//
// The assertion that matters is the CONTRAST. Asserting only "the app role
// cannot write the view" would be answering the wrong question: at this point
// in the chain the role legitimately holds UPDATE on static_policies, so a
// check of table privilege says yes and always did. What changed is whether the
// write can leave the caller's organization.
func TestAnIndustryViewCannotCrossTheOrgBoundary_RealPG(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	ownerDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatal(err)
	}
	ownerDB.SetMaxOpenConns(1)
	defer func() { _ = ownerDB.Close() }()
	applyIndustryChain(t, ownerDB)

	const view = "sebi_compliance_summary"
	const otherOrg = "org-elsewhere-3905"

	// A row belonging to a DIFFERENT organization, in the category the view
	// selects. Read the predicate from the view itself rather than hardcoding a
	// category that a later canonicalisation migration may rename.
	var def string
	if err := ownerDB.QueryRow(`SELECT pg_get_viewdef($1::regclass, true)`, view).Scan(&def); err != nil {
		t.Fatal(err)
	}
	category := "compliance-sebi"
	if !strings.Contains(def, category) {
		t.Skipf("%s no longer selects on %q (definition changed); re-derive the probe category from: %s", view, category, def)
	}

	if _, err := ownerDB.Exec(`
		INSERT INTO static_policies (policy_id, name, category, org_id, enabled, action, pattern)
		VALUES ('w1c-3905-industry-probe', 'cross-org probe', $1, $2, true, 'block', 'w1c-never-matches')`,
		category, otherOrg); err != nil {
		t.Fatalf("planting the cross-org row: %v", err)
	}

	appRoleDB := viewWriteAppRoleConn(t, env.AppRoleDSN)

	// (a) invisible directly - so anything the app role does to it through the
	// view is reach it does not otherwise have.
	var direct int
	if err := appRoleDB.QueryRow(
		`SELECT COUNT(*) FROM static_policies WHERE policy_id = 'w1c-3905-industry-probe'`).Scan(&direct); err != nil {
		t.Fatal(err)
	}
	if direct != 0 {
		t.Fatalf("the app role can see the cross-org row directly (%d); this test is not measuring the view", direct)
	}

	// (b) and the app role legitimately holds UPDATE on the table. This is what
	// makes a table-privilege check the wrong question.
	var mayWriteTable bool
	if err := ownerDB.QueryRow(
		`SELECT has_table_privilege('axonflow_app_role','static_policies','UPDATE')`).Scan(&mayWriteTable); err != nil {
		t.Fatal(err)
	}
	// THE CONTRAST IS ONLY MEASURABLE WHILE THE TABLE GRANT SURVIVES, and
	// whether it does depends on which migrations this tree carries.
	//
	// On main today the role holds UPDATE, so the direct write is permitted and
	// ineffective, and (c)-vs-(d) is the whole finding. migrations/core/172
	// (#3786) revokes that grant, and on a tree carrying BOTH the direct write
	// is refused outright - a strictly stronger state in which the contrast
	// cannot be drawn because its first half no longer exists.
	//
	// Both are correct outcomes and this test asserts the right thing in each.
	// What it must not do is silently assert the weaker property on the
	// post-172 schema: "the write through the view is refused" is satisfied
	// there by the table revoke alone, with the view enforcer removed entirely.
	// So the org-crossing assertion below runs in both worlds, and the
	// permitted-but-ineffective half runs only where it can mean something.
	if !mayWriteTable {
		t.Log("this schema has revoked the app role's UPDATE on static_policies (migrations/core/172), so the direct " +
			"write is refused rather than ineffective; the cross-org assertions below still apply")
	}

	// (c) THE DIRECT CROSS-ORG WRITE. Where the grant survives it must succeed
	// and change nothing; where 172 has revoked it, it must be refused. Either
	// way it must not reach the other organization's row, which is asserted
	// immediately below and is the part that holds on both schemas.
	_, directErr := appRoleDB.Exec(
		`UPDATE static_policies SET enabled = false WHERE policy_id = 'w1c-3905-industry-probe'`)
	if mayWriteTable && directErr != nil {
		t.Fatalf("the app role holds UPDATE yet the direct write errored; the contrast this test measures is a write "+
			"that SUCCEEDS and matches nothing: %v", directErr)
	}
	if !mayWriteTable && directErr == nil {
		t.Fatal("the app role does NOT hold UPDATE on static_policies and the direct write was accepted anyway")
	}
	var afterDirect bool
	if err := ownerDB.QueryRow(
		`SELECT enabled FROM static_policies WHERE policy_id = 'w1c-3905-industry-probe'`).Scan(&afterDirect); err != nil {
		t.Fatal(err)
	}
	if !afterDirect {
		t.Fatal("the DIRECT cross-org UPDATE changed another organization's row: migration 018's tenant isolation is not " +
			"holding, which is a wider failure than the one this migration addresses")
	}

	// (d) THE SAME WRITE THROUGH THE VIEW, BEFORE THE ENFORCER RUNS: it LANDS.
	//
	// This half is the finding, and it is asserted rather than described. It is
	// also this test's anti-vacuity: without it, the refusal below is
	// indistinguishable from a view that was never a write path, and the test
	// would pass just as happily against a database where nothing was ever
	// reachable. #3905 measured this on core/014's view; this measures it on an
	// INDUSTRY view, which is the population that cannot be bound by a
	// migration at all.
	if _, err := appRoleDB.Exec(
		`UPDATE ` + view + ` SET enabled = false WHERE policy_id = 'w1c-3905-industry-probe'`); err != nil {
		t.Fatalf("BEFORE the enforcer, the write through %s should have been possible (that is the defect); it failed: %v", view, err)
	}
	var beforeEnforcer bool
	if err := ownerDB.QueryRow(
		`SELECT enabled FROM static_policies WHERE policy_id = 'w1c-3905-industry-probe'`).Scan(&beforeEnforcer); err != nil {
		t.Fatal(err)
	}
	if beforeEnforcer {
		t.Fatalf("BEFORE the enforcer, the write through %s changed nothing - so this view is not a cross-org write path "+
			"on this schema and the refusal asserted below would prove nothing", view)
	}
	t.Logf("MEASURED: before the enforcer, the app role scoped to %q changed a %q row through %s, "+
		"while the identical direct write in the same session matched nothing", seededOrgScope, otherOrg, view)

	// Put the row back, so the post-enforcer assertion is about the same state.
	if _, err := ownerDB.Exec(
		`UPDATE static_policies SET enabled = true WHERE policy_id = 'w1c-3905-industry-probe'`); err != nil {
		t.Fatal(err)
	}

	// THE FIX.
	enforceLegacyPolicyReadOnly(ownerDB)

	// (e) AND THE SAME WRITE IS NOW REFUSED, for the right reason.
	_, viewErr := appRoleDB.Exec(
		`UPDATE ` + view + ` SET enabled = false WHERE policy_id = 'w1c-3905-industry-probe'`)
	var afterView bool
	if err := ownerDB.QueryRow(
		`SELECT enabled FROM static_policies WHERE policy_id = 'w1c-3905-industry-probe'`).Scan(&afterView); err != nil {
		t.Fatal(err)
	}
	if !afterView {
		t.Fatalf("after the enforcer, the app role STILL changed another organization's row through %s", view)
	}
	if viewErr == nil {
		t.Errorf("the write through %s was accepted after the enforcer ran; it matched no row, which is luck rather than enforcement", view)
	} else if !strings.Contains(viewErr.Error(), "permission denied") {
		t.Errorf("the write through %s failed for the wrong reason (want a privilege refusal): %v", view, viewErr)
	}

	// AND THE DELETE, which is the more destructive half of the same path.
	_, delErr := appRoleDB.Exec(`DELETE FROM ` + view + ` WHERE policy_id = 'w1c-3905-industry-probe'`)
	var remaining int
	if err := ownerDB.QueryRow(
		`SELECT COUNT(*) FROM static_policies WHERE policy_id = 'w1c-3905-industry-probe'`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("the app role DELETED another organization's policy row through %s", view)
	}
	if delErr == nil {
		t.Errorf("the DELETE through %s was accepted", view)
	}
}
