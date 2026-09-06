package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Two source censuses over migrations/, each closing a CLASS that was found as
// an INSTANCE during the v10.3.0 pre-release review (#3635, #3636).
//
// Both defects are mechanical and checkable, and both were caught by a human
// reading the files rather than by anything in CI. That is the reason these
// exist: three FORCE-RLS tables landed in one release, two migrations got the
// GRANT block and one did not, and two down-migrations on one table needed
// identical row-security handling and only the later one got it. A property
// that a reader can verify by eye is one CI can verify every commit.
//
// They are STATIC. Neither can prove a grant is load-bearing at runtime - no
// harness in this tree splits the migration role from the table owner, so
// core/098's ALTER DEFAULT PRIVILEGES always covers the new tables and the
// grant is redundant in every existing fixture. That half is
// TestMigration170GrantsAreLoadBearing_RealPostgres, which builds the split
// deliberately. These two catch the omission at review time, where it is cheap.

// migrationsDirForCensus resolves migrations/ from this package's location.
func migrationsDirForCensus(t *testing.T) string {
	t.Helper()
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	dir := filepath.Join(root, "migrations")
	if _, err := os.Stat(dir); err != nil {
		// Not a skip. A census keyed on a directory that may be absent, and that
		// skips when it is absent, is invisible exactly where it stopped
		// running.
		t.Fatalf("migrations/ not found at %s: %v", dir, err)
	}
	return dir
}

// migrationFiles walks migrations/ and returns every .sql file, split into
// up-migrations and down-migrations.
func migrationFiles(t *testing.T) (up, down []string) {
	t.Helper()
	root := migrationsDirForCensus(t)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		if strings.HasSuffix(path, "_down.sql") {
			down = append(down, path)
			return nil
		}
		up = append(up, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking migrations/: %v", err)
	}
	sort.Strings(up)
	sort.Strings(down)
	if len(up) == 0 || len(down) == 0 {
		t.Fatalf("the walk found %d up and %d down migrations; a census that reached nothing reports clean", len(up), len(down))
	}
	return up, down
}

var (
	// A table is put under FORCE RLS by this statement, in every migration that
	// does it. Matched case-insensitively with flexible whitespace because SQL
	// permits both, not because any committed file varies.
	forceRLSRe = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+FORCE\s+ROW\s+LEVEL\s+SECURITY`)
	// A GRANT naming one of the two application roles. The ROLE is what makes it
	// the block this census is about: a GRANT to some other role does not give
	// the application its access back.
	appGrantRe = regexp.MustCompile(`(?is)GRANT\s+[^;]*?\sON\s+[^;]*?\sTO\s+(axonflow_app_role|axonflow_platform_admin)`)
	// The table list of a literal GRANT statement.
	grantTargetsRe = regexp.MustCompile(`(?is)GRANT\s+[A-Z, ]+?\s+ON\s+(?:TABLE\s+)?([^;]+?)\s+TO\s+`)
	// The dynamic form a backfill uses.
	formatGrantRe = regexp.MustCompile(`(?is)format\s*\(\s*'GRANT[^']*ON\s+%I\s+TO\s+%I'`)
	// A `FOREACH t IN ARRAY ARRAY[ ... ] LOOP` literal.
	tableArrayRe = regexp.MustCompile(`(?is)FOREACH\s+\w+\s+IN\s+ARRAY\s+ARRAY\[(.*?)\]\s+LOOP`)
	quotedNameRe = regexp.MustCompile(`'([a-z_][a-z0-9_]*)'`)
	// EXECUTE granted on a SECURITY DEFINER helper to an application role. This
	// is the OTHER way a table is legitimately reachable, and it is why the
	// census cannot simply demand a direct grant everywhere.
	fnGrantRe = regexp.MustCompile(`(?is)GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+([a-z_][a-z0-9_]*)\s*\([^)]*\)\s+TO\s+(?:axonflow_app_role|axonflow_platform_admin)`)
	// A count over a named table.
	countOverTableRe = regexp.MustCompile(`(?is)count\s*\(\s*\*\s*\)\s+INTO\s+\w+\s+FROM\s+([A-Za-z_][A-Za-z0-9_]*)`)
	// Row security disabled for the transaction.
	rowSecurityOffRe = regexp.MustCompile(`(?is)SET\s+LOCAL\s+row_security\s*=\s*off`)
	// The exemption marker. A migration may opt out of either census, and the
	// marker requires the WORD "because" after it, so an exemption cannot be a
	// bare token: a reviewer reading the diff sees an argument or sees nothing.
	censusExemptionRe = regexp.MustCompile(`(?i)axonflow:rls-census-exempt\s+because\s+\S+`)
)

// TestEveryForceRLSTableHasAnApplicationGrant is the #3636 class.
//
// A table under FORCE ROW LEVEL SECURITY that no migration grants to the
// application roles is relying entirely on core/098's ALTER DEFAULT PRIVILEGES,
// which binds to the role that EXECUTED it and covers only tables created
// afterwards BY THAT SAME OWNER - its own comment says "Scoped to the role that
// owns most tables (current_user at migration time)". A deployment applies the
// chain incrementally, one release at a time, and the migration credential can
// change between releases; any table created under a different role is then
// unreachable, and every access to it is a permission error at runtime.
//
// No fixture in this tree can see that failure: they all provision both roles
// under one owner, which enterprise/148 states in its own words ("it is
// invisible to the test suites"). So the property is checked statically here,
// and proved at runtime by TestMigration170GrantsAreLoadBearing_RealPostgres,
// which builds the split owner deliberately.
//
// THE CENSUS IS OVER TABLES, NOT FILES, and that is the difference between the
// property and a house style. The property is "the application can reach this
// table"; where the GRANT is written is not part of it, and demanding the same
// file would forbid the one instrument that can fix an ALREADY-DEPLOYED
// omission - a corrective migration. (The runner skips an applied migration
// before it reads the file, so editing the original reaches fresh installs
// only; see migrations/core/170.) A NEW migration that forces RLS and grants
// nowhere still fails, which is the case worth catching.
func TestEveryForceRLSTableHasAnApplicationGrant(t *testing.T) {
	up, _ := migrationFiles(t)
	root := migrationsDirForCensus(t)

	forcedIn := map[string]string{}  // table -> the migration that forced RLS on it
	grantedIn := map[string]string{} // table -> the migration that granted it
	fnGranted := map[string]string{} // SECURITY DEFINER function -> the migration that granted EXECUTE on it
	exempt := map[string]bool{}

	for _, path := range up {
		body, err := os.ReadFile(path) //nolint:gosec // walking a fixed repo subtree
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(body)
		rel, _ := filepath.Rel(root, path)

		for _, m := range forceRLSRe.FindAllStringSubmatch(text, -1) {
			table := strings.ToLower(m[1])
			if _, seen := forcedIn[table]; !seen {
				forcedIn[table] = rel
			}
			if censusExemptionRe.MatchString(text) {
				exempt[table] = true
			}
		}
		// Every table named in a GRANT to an application role, from either the
		// literal form (148, 149) or the format(...) form a backfill uses.
		for _, m := range appGrantRe.FindAllStringSubmatch(text, -1) {
			for _, table := range tablesNamedInGrant(m[0]) {
				if _, seen := grantedIn[table]; !seen {
					grantedIn[table] = rel
				}
			}
		}
		for _, table := range tablesNamedInFormatGrant(text) {
			if _, seen := grantedIn[table]; !seen {
				grantedIn[table] = rel
			}
		}
		for _, m := range fnGrantRe.FindAllStringSubmatch(text, -1) {
			fn := strings.ToLower(m[1])
			if _, seen := fnGranted[fn]; !seen {
				fnGranted[fn] = rel
			}
		}
	}

	if len(forcedIn) == 0 {
		t.Fatal("no migration was found to put a table under FORCE ROW LEVEL SECURITY. Either the pattern stopped " +
			"matching or the walk reached nothing; both report clean while checking nothing.")
	}
	if len(grantedIn) == 0 {
		t.Fatal("no migration was found to GRANT on any table. The grant pattern has stopped matching, and every " +
			"table below would be reported as ungranted for the wrong reason.")
	}

	// THERE ARE NO EXEMPTIONS, AND THE ONE THIS FILE USED TO CARRY WAS WRONG.
	//
	// An earlier revision exempted six tables reached through SECURITY DEFINER
	// helpers, on the rationale that "the application does not hold DML on
	// them". That is FALSE: core/098 runs
	// `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO
	// axonflow_app_role`, so the app role holds DML on every table that exists
	// when it runs, those six included. The helpers exist for pre-auth
	// VISIBILITY under row-level security - a cross-org lookup that returns
	// zero rows however much privilege the caller has - which is a different
	// axis from privilege, and conflating the two is what produced the
	// exemption.
	//
	// Rendered from a fresh chain rather than argued: 26 FORCE-RLS tables, zero
	// lacking the app role's SELECT or INSERT. So no table needs exempting, and
	// an exemption mechanism nothing uses is one the next author will reach for
	// without re-deriving whether it applies. The marker is still recognised -
	// see censusExemptionRe - so a future table CAN opt out with a written
	// reason, but nothing does today.

	var missing []string
	for table, declaredIn := range forcedIn {
		if exempt[table] || grantedIn[table] != "" {
			continue
		}
		missing = append(missing, table+" (forced by "+declaredIn+")")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these FORCE-RLS tables are granted to neither axonflow_app_role nor axonflow_platform_admin by any "+
			"migration:\n  %s\n\n"+
			"core/098's ALTER DEFAULT PRIVILEGES covers tables created afterwards BY THE SAME OWNER; a deployment "+
			"whose migration role changed between releases is not covered, and every access to the table is then a "+
			"permission error at runtime that no fixture in this tree can see, because they all provision both roles "+
			"under one owner.\n\n"+
			"Ship the role-existence-guarded block from migrations/enterprise/149_proof_execution_record.sql in the "+
			"migration that creates the table. For a table that has ALREADY been deployed, an edit reaches fresh "+
			"installs only - the runner skips an applied migration before it reads the file - so it needs a "+
			"corrective migration instead; migrations/core/170 is the worked example. Or opt out with a comment "+
			"containing `axonflow:rls-census-exempt because <reason>`.",
			strings.Join(missing, "\n  "))
	}

	// THE EDITION AXIS, which the census above cannot see and which the
	// community mirror enforces for real.
	//
	// "Granted somewhere" is not enough. migrations/core is published to the
	// community mirror and migrations/enterprise is NOT, so a table FORCED by a
	// core file and GRANTED only by an enterprise file is unreachable-by-census
	// in the mirror tree - this same test runs there, finds the FORCE, finds no
	// grant, and fails. It is not a theoretical split: it happened on #3636.
	// `customers` is created by enterprise/100 but forced by core/108, its grant
	// was written in enterprise/151, and the mirror simulation went red.
	//
	// Note the direction. A table forced by an ENTERPRISE migration may be
	// granted anywhere, because the mirror never sees the FORCE either, so
	// nothing is asked of it there. Only core-forced tables carry the
	// obligation, which is why this is not simply "the two files must match".
	//
	// Guarding it HERE rather than only in the mirror simulation is deliberate:
	// that simulation's package filter excludes platform/agent, so it never runs
	// this census at all. Before this assertion the class had no pre-sync guard
	// in this tree, and the first signal was a red board after the fact.
	var misplaced []string
	for table, forcedFile := range forcedIn {
		if exempt[table] || !strings.HasPrefix(forcedFile, "core/") {
			continue
		}
		grantedFile := grantedIn[table]
		if grantedFile == "" || strings.HasPrefix(grantedFile, "core/") {
			continue // absent is the check above's business, not this one
		}
		misplaced = append(misplaced, table+" (forced by "+forcedFile+", granted only by "+grantedFile+")")
	}
	sort.Strings(misplaced)
	if len(misplaced) > 0 {
		t.Errorf("these tables are FORCED by a core migration but GRANTED only by an enterprise one:\n  %s\n\n"+
			"migrations/core ships to the community mirror and migrations/enterprise does not, so in that tree the "+
			"FORCE is present and the grant is absent - and this same census runs there and fails. Move the grant "+
			"into the core migration; to_regclass makes the statement inert wherever the table does not exist, so "+
			"naming an Enterprise-created table in a core backfill costs nothing at runtime. The split is by what "+
			"FORCES a table, not by what creates it.",
			strings.Join(misplaced, "\n  "))
	}
}

// tablesNamedInGrant pulls the table list out of a literal
// `GRANT ... ON a, b TO role` statement.
func tablesNamedInGrant(stmt string) []string {
	m := grantTargetsRe.FindStringSubmatch(stmt)
	if m == nil {
		return nil
	}
	var out []string
	for _, raw := range strings.Split(m[1], ",") {
		name := strings.ToLower(strings.Trim(strings.TrimSpace(raw), `"`))
		if name != "" && !strings.ContainsAny(name, " (%") {
			out = append(out, name)
		}
	}
	return out
}

// tablesNamedInFormatGrant pulls table names out of the dynamic form a backfill
// migration uses: a `format('GRANT ... ON %I TO %I', t, r)` inside a loop over
// a literal table array.
//
// Read from the ARRAY rather than from the format string, because the format
// string names no table - which is exactly why a census that only understood
// the literal form reported a correctly-granted table as ungranted.
func tablesNamedInFormatGrant(text string) []string {
	if !formatGrantRe.MatchString(text) {
		return nil
	}
	var out []string
	for _, arr := range tableArrayRe.FindAllStringSubmatch(text, -1) {
		for _, m := range quotedNameRe.FindAllStringSubmatch(arr[1], -1) {
			out = append(out, strings.ToLower(m[1]))
		}
	}
	return out
}

// TestEveryDownMigrationCountingAFORCERLSTableDisablesRowSecurity is the #3635
// class.
//
// A down migration that counts rows on a FORCE-RLS table with no GUC set gets
// ZERO for every row, because `org_id = current_setting('app.current_org_id',
// true)` is NULL when the GUC is unset and NULL is not true. The count is not
// decoration: it is the operator's only signal about what a rollback destroys,
// and the table is usually dropped in the same transaction, so there is nothing
// left to re-count. Reporting a confident zero is strictly worse than reporting
// nothing.
//
// migrations/enterprise/150's down block diagnosed this precisely, named 146 by
// number as the cause, and fixed it only for itself. Two down-migrations on one
// table needing identical handling, with one of them fixed, is what a class
// check is for.
func TestEveryDownMigrationCountingAFORCERLSTableDisablesRowSecurity(t *testing.T) {
	up, down := migrationFiles(t)
	root := migrationsDirForCensus(t)

	// Which tables are under FORCE RLS anywhere in the tree. Derived from the
	// migrations themselves rather than listed here: a hand-written list is a
	// second declaration of the schema, and a second declaration is the drift
	// this check exists to catch.
	forced := map[string]string{}
	for _, path := range up {
		body, err := os.ReadFile(path) //nolint:gosec // walking a fixed repo subtree
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		for _, m := range forceRLSRe.FindAllStringSubmatch(string(body), -1) {
			forced[strings.ToLower(m[1])] = rel
		}
	}
	if len(forced) == 0 {
		t.Fatal("no FORCE-RLS table was found anywhere in migrations/, so every check below is vacuous")
	}

	checked := 0
	for _, path := range down {
		body, err := os.ReadFile(path) //nolint:gosec // walking a fixed repo subtree
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(body)
		rel, _ := filepath.Rel(root, path)
		if censusExemptionRe.MatchString(text) {
			continue
		}
		var offenders []string
		for _, m := range countOverTableRe.FindAllStringSubmatch(text, -1) {
			table := strings.ToLower(m[1])
			declaredIn, isForced := forced[table]
			if !isForced {
				continue
			}
			checked++
			if rowSecurityOffRe.MatchString(text) {
				continue
			}
			offenders = append(offenders, table+" (FORCE RLS set by "+declaredIn+")")
		}
		if len(offenders) > 0 {
			t.Errorf("%s counts rows on %s without disabling row security.\n\n"+
				"With the org GUC unset the isolation predicate is NULL for every row, so the count returns ZERO "+
				"however many rows there are - and the NOTICE prints a reassuring zero while the rollback discards "+
				"them. The table is normally dropped in the same transaction, so there is nothing left to re-count.\n\n"+
				"Copy the `SET LOCAL row_security = off` block from "+
				"migrations/enterprise/150_identity_org_settings_decision_shadow_down.sql, including its "+
				"BEGIN...EXCEPTION arm and its `counted` flag, so a role without BYPASSRLS reports the counts as "+
				"UNAVAILABLE rather than inventing a zero. Or opt out with a comment containing "+
				"`axonflow:rls-census-exempt because <reason>`.",
				rel, strings.Join(dedupeStrings(offenders), ", "))
		}
	}

	if checked == 0 {
		t.Fatal("no down migration was found to count rows on a FORCE-RLS table. Either the pattern stopped matching " +
			"or the walk reached nothing; both report clean while checking nothing.")
	}
}

// TestTheMigrationCensusesCanFail is the anti-vacuity half for both.
//
// The two checks above pass against the tree as committed, which is exactly
// what a broken regexp also produces. This drives each pattern over synthetic
// text carrying the defect and over text carrying the fix, so a pattern that
// stops matching is loud rather than reassuring.
func TestTheMigrationCensusesCanFail(t *testing.T) {
	forcedTable := `ALTER TABLE widgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE widgets FORCE  ROW LEVEL SECURITY;`
	grantBlock := `DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'axonflow_app_role') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON widgets TO axonflow_app_role;
    END IF;
END $$;`

	if !forceRLSRe.MatchString(forcedTable) {
		t.Error("the FORCE-RLS pattern no longer recognises a table being forced")
	}
	if got := forceRLSRe.FindStringSubmatch(forcedTable)[1]; got != "widgets" {
		t.Errorf("the FORCE-RLS pattern captured %q, not the table name", got)
	}
	if appGrantRe.MatchString(forcedTable) {
		t.Error("the grant pattern matched text containing no GRANT")
	}
	if !appGrantRe.MatchString(grantBlock) {
		t.Error("the grant pattern no longer recognises the block enterprise/148 and /149 ship")
	}
	// A grant to some OTHER role must not satisfy it: the application still
	// cannot reach the table.
	if appGrantRe.MatchString(`GRANT SELECT ON widgets TO reporting_reader;`) {
		t.Error("a grant to an unrelated role satisfied the application-grant pattern")
	}

	countingDown := `SELECT count(*) INTO n FROM widgets WHERE flag;`
	if !countOverTableRe.MatchString(countingDown) {
		t.Error("the count pattern no longer recognises a count into a variable")
	}
	if got := countOverTableRe.FindStringSubmatch(countingDown)[1]; got != "widgets" {
		t.Errorf("the count pattern captured %q, not the table name", got)
	}
	if rowSecurityOffRe.MatchString(countingDown) {
		t.Error("the row-security pattern matched text that does not disable it")
	}
	if !rowSecurityOffRe.MatchString(`    SET LOCAL row_security = off;`) {
		t.Error("the row-security pattern no longer recognises the disable statement")
	}

	// The exemption marker requires an argument. A bare token must not exempt.
	if censusExemptionRe.MatchString(`-- axonflow:rls-census-exempt`) {
		t.Error("a bare exemption marker with no reason was accepted; an exemption with no argument is how a gap gets grandfathered")
	}
	if !censusExemptionRe.MatchString(`-- axonflow:rls-census-exempt because this table is granted by core/098 under a single owner`) {
		t.Error("an exemption carrying a reason was not recognised")
	}
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
