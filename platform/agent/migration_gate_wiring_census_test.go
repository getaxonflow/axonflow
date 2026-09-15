// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// enterpriseBuildTag matches the build constraint the community sync strips
// by (#3270): a file carrying it is removed from the public mirror.
var enterpriseBuildTag = regexp.MustCompile(`(?m)^//go:build enterprise|^// \+build enterprise`)

// TestEveryRealPostgresMigrationTestIsWiredIntoTheGate replaces a guard that
// classified by FILENAME.
//
// `.github/workflows/migrations-gate.yml` used to census its own population
// with a glob:
//
//	for f in platform/agent/migration_*_realpg_test.go \
//	         platform/orchestrator/migration_*_realpg_test.go
//
// Only files whose NAME ends `_realpg_test.go` were examined, and the suffix is
// a convention some files follow and others do not. The guard reported "All
// migration-chain tests are wired into the gate." throughout. That sentence was
// true of the set it looked at and false of the set it named.
//
// THE NUMBERS, AND WHY AN EARLIER VERSION OF THIS PARAGRAPH HAD THEM WRONG.
// It first said "22 files ... 45 of the 83 real-PG migration tests". Those are
// FILE-level figures: they count every test in a file that opens Postgres
// somewhere, which over-counts exactly where the call graph was introduced to
// stop over-counting -- `migration_helpers_test.go` contributes 3 real-Postgres
// tests, not 21. Quoting a file-level count in the doc comment of the thing
// that replaced file-level counting is its own small instance of this PR's
// defect.
//
// The call-graph answer, measured on this tree: a population of 77
// migration-subject real-Postgres tests, ALL 77 of them wired into the gate.
// gateWiringExemptions is empty as of #4034 -- the seven entries it held read a
// DSN from the environment and now provision their own database.
//
// The two files it mattered most for were `migration_142_timestamptz_test.go`
// and `migration_142_133_upgrade_path_test.go`: the tests that caught
// `core/175` breaking a released migration's idempotency and failing to apply
// on the 142->133 upgrade path (#4007). Neither was in the gate, and the guard
// could not say so.
//
// # HOW THIS CLASSIFIES INSTEAD
//
// By what a test DOES, resolved through the package's own call graph. A test is
// real-Postgres when it reaches one of the known handle-openers -- directly, or
// through any chain of same-package helpers. That matters: three tests in
// `migration_helpers_test.go` reach `testutil.StartPostgres` only via
// `getTestDatabaseURLWithContainer`, while the other eighteen in that file are
// pure (version sorting, dependency extraction, path resolution). A file-level
// signal marks all twenty-one; the call graph marks three, which is the true
// answer and the reason this walks calls rather than grepping files.
//
// The POPULATION it selects from is every migration-subject test in both
// packages -- see isMigrationSubject, and read its comment before narrowing
// OR widening anything. The first version of this census kept the old guard's
// filename key and 13 `TestMigration<N>...` functions were outside it; the
// second keyed the function-name half on a PREFIX while its own bound sentence
// said "its function name", and two more proofs naming their migration
// mid-name were outside that.
//
// # WHAT IT CANNOT SEE, STATED
//
// Two bounds, and they are different in kind.
//
// The first is mechanical and closable. The closure is within `package agent`
// (and the orchestrator's own files, read separately). A test that reaches
// Postgres only through a helper in ANOTHER package, not named in
// realPGOpeners, is invisible here -- the same class of blindness as the suffix
// glob, one level out. realPGOpeners is therefore the thing to extend when a
// new opener appears; it is asserted non-empty below so it cannot be emptied
// into a vacuous pass, and TestTheOpenerSetCoversEveryTestutilOpener derives
// the one package it names by hand so that entry cannot go stale.
//
// The second is NOT closable and must not be papered over. Whether a test's
// SUBJECT is a migration is not recoverable from its syntax: a test of
// migration 172 and a test that merely applies 172 to get a table both apply
// the chain and query the result. isMigrationSubject therefore reads what the
// test SAYS it is about, and a migration proof that says so in neither its
// filename nor its function name is outside this census by construction. That
// is a naming convention to keep, not a classifier bug to fix.
func TestEveryRealPostgresMigrationTestIsWiredIntoTheGate(t *testing.T) {
	root := repoRootForGateCensus(t)

	// NOT ON THE COMMUNITY MIRROR. The subject is
	// .github/workflows/migrations-gate.yml, which the sync excludes by name
	// (it runs `go test -tags enterprise`, and the mirror ships only the
	// _community.go half of each build-tag pair). This file is NOT excluded,
	// so on the mirror it would run and fail on a missing workflow.
	//
	// KEYED ON ee/, NOT ON THE FILE'S ABSENCE: "the workflow is missing" is the
	// mirror's normal state and the enterprise tree's DEFECT, and a skip keyed
	// on absence would silence exactly the case this guard exists for.
	if _, err := os.Stat(filepath.Join(root, "ee")); os.IsNotExist(err) {
		t.Skip("no ee/ — community mirror tree, where migrations-gate.yml is not synced")
	}

	wfPath := filepath.Join(root, ".github", "workflows", "migrations-gate.yml")
	wfBytes, err := os.ReadFile(wfPath)
	if err != nil {
		t.Fatalf("read the gate workflow: %v", err)
	}
	wf := liveYAML(string(wfBytes))

	var all []realPGTest
	for _, dir := range []string{"platform/agent", "platform/orchestrator"} {
		all = append(all, realPGMigrationTests(t, filepath.Join(root, dir))...)
	}
	if len(all) == 0 {
		t.Fatal("the census found NO real-Postgres migration tests, which cannot be right — " +
			"a zero here means the classifier broke, not that the tree is clean")
	}

	var unwired, untagged []string
	for _, rt := range all {
		if _, excused := gateWiringExemptions[rt.name]; excused {
			continue
		}
		inRun, inPass := namedInRunFilter(wf, rt.name), namedInPassList(wf, rt.name)
		if !inRun || !inPass {
			why := "in neither the -run filter nor the PASS-assertion list"
			switch {
			case inRun && !inPass:
				why = "in a -run filter but NOT in any PASS-assertion list, so a skip would pass as a run"
			case !inRun && inPass:
				why = "in a PASS-assertion list but NOT in any -run filter, so it is asserted and never selected"
			}
			unwired = append(unwired, rt.name+"  ("+rt.file+", reached via "+rt.via+"): "+why)
			continue
		}
		// NAMED IS NOT RUNNABLE. `go test -run` on a pattern matching nothing
		// exits 0, so an enterprise-tagged test named in an untagged step is
		// silently never executed and the gate still passes. Require the step
		// that names it to carry -tags enterprise.
		if rt.enterpriseTagged && !namedInTaggedStep(wf, rt.name) {
			untagged = append(untagged, rt.name+"  ("+rt.file+")")
		}
	}
	sort.Strings(unwired)
	sort.Strings(untagged)
	if len(untagged) > 0 {
		t.Errorf("%d enterprise-tagged real-Postgres test(s) are NAMED in the gate but only in step(s) that do not pass `-tags enterprise`, so `go test -run` matches nothing there and EXITS 0 -- the gate reports success having run them zero times:\n  %s",
			len(untagged), strings.Join(untagged, "\n  "))
	}
	if len(unwired) > 0 {
		t.Errorf("%d of %d real-Postgres migration tests are not named in %s, so they never run there:\n  %s\n\n"+
			"Each must be added to that workflow's -run filter AND its PASS-assertion list, or listed in "+
			"gateWiringExemptions with a reason. Being outside the gate is not the same as being covered "+
			"elsewhere, and the difference is what #4021 is about.",
			len(unwired), len(all), "migrations-gate.yml", strings.Join(unwired, "\n  "))
	}

	// ANTI-VACUITY. An empty opener set classifies everything as pure and this
	// test then passes having asserted nothing — the exact failure mode of the
	// glob it replaces.
	if len(realPGOpeners) == 0 {
		t.Fatal("realPGOpeners is empty, so nothing can be classified real-Postgres and this census is vacuous")
	}
	for name := range gateWiringExemptions {
		if strings.TrimSpace(gateWiringExemptions[name]) == "" {
			t.Errorf("gateWiringExemptions[%q] has an empty reason; an exemption without one is an omission with a name", name)
		}
	}
}

// TestTheOpenerSetCoversEveryTestutilOpener keeps realPGOpeners honest about
// the ONE package it names by hand.
//
// `sql.Open` needs no maintenance: anything that opens a database from a DSN
// goes through it, including a fourth copy of the docker-run harness nobody has
// written yet. `testutil.StartPostgres` is different -- it returns an
// already-open *sql.DB, so a test using only it never calls sql.Open, and the
// census sees it solely because the name is listed. A name that is listed by
// hand is a name that goes stale, which is the defect this whole PR exists to
// remove; so rather than remember to update it, this derives the population it
// has to cover.
//
// Verified at the time of writing: platform/testutil exports exactly one such
// opener. This test is what says so a year from now.
func TestTheOpenerSetCoversEveryTestutilOpener(t *testing.T) {
	dir := filepath.Join(repoRootForGateCensus(t), "platform", "testutil")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	found := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			// An opener is an exported function HANDING BACK a live handle:
			// a *sql.DB, or the container type that carries one.
			var yields bool
			for _, res := range fn.Type.Results.List {
				switch typ := res.Type.(type) {
				case *ast.StarExpr:
					switch inner := typ.X.(type) {
					case *ast.Ident:
						yields = yields || inner.Name == "PostgresContainer"
					case *ast.SelectorExpr:
						yields = yields || inner.Sel.Name == "DB"
					}
				}
			}
			if !yields {
				continue
			}
			found++
			if !realPGOpeners["testutil."+fn.Name.Name] {
				t.Errorf("platform/testutil exports %s, which hands back a live Postgres handle, but realPGOpeners does not name it — "+
					"a migration test using only that opener never calls sql.Open and would be invisible to the wiring census (#4021)", fn.Name.Name)
			}
		}
	}
	if found == 0 {
		t.Fatal("found NO testutil opener at all; the detector broke rather than the package having none — " +
			"testutil.StartPostgres exists and returns *PostgresContainer")
	}
}

// realPGOpeners are the calls that OBTAIN a Postgres handle. They are
// behaviours, not harness names, and that distinction is the whole of round 1's
// finding 1.
//
// The first version listed five NAMES, one of which (`approletest.StartPostgres`)
// did not exist then -- that package exported only Setup/SetupAtVersion; #3894
// added it, and a test that uses it still reaches sql.Open -- and three of
// which were one harness copied three times: `startCountTestPostgres`,
// `startMig124Postgres` and `startMig127Postgres` are byte-similar
// `docker run postgres:15` wrappers, and only the first was listed. Ten
// real-Postgres migration tests were therefore invisible to a census whose
// entire purpose is that nothing real-Postgres is invisible. A name-keyed
// classifier is the same defect as the suffix glob it replaced, one level down:
// it sees the spellings someone remembered.
//
// `sql.Open` catches every path to a live database however the DSN was
// obtained -- the three harnesses, the env-DSN class, and any fourth copy
// nobody has written yet. `testutil.StartPostgres` catches the helpers that
// return an already-open *sql.DB without the test naming sql.Open itself.
// Measured over every migration_*_test.go in both packages: these two classify
// exactly the files that touch a database and none of the pure ones.
//
// `testutil.PostgresContainer` WAS in this map and has been removed: it is a
// TYPE, and the closure below matches CallExpr selectors, so it could never
// have matched anything. An entry that cannot fire is not a harmless extra --
// it reads as a third covered path and makes the set look broader than it is,
// which is the same misreporting this census exists to end. The type is still
// what TestTheOpenerSetCoversEveryTestutilOpener looks for in a RESULT
// position, where it belongs.
var realPGOpeners = map[string]bool{
	"sql.Open":               true,
	"testutil.StartPostgres": true,
}

// gateWiringExemptions names real-Postgres migration tests that are
// deliberately NOT in the gate, each with the reason. Empty reasons fail above:
// an exemption without one is an omission with a name.
//
// IT IS EMPTY, AND THAT IS THE POINT OF #4034. It held seven entries whose
// reason was "env-DSN class: needs a self-provisioning harness before it can be
// wired". Four read TEST_DATABASE_URL and three read DATABASE_URL -- a
// difference worth noticing, because an exemption written as "the env-DSN
// tests" and keyed on ONE variable name would have missed its own members.
//
// An exemption that names a remedy and is never revisited is how a stated gap
// becomes a permanent one: it reads as a decision every time anybody looks,
// while the tests inside it run nowhere on the pull_request tier. All seven now
// provision their own database (migration_realpg_harness_test.go) and are wired
// like anything else.
//
// THE BAR FOR ADDING ONE BACK. A reason must say what would have to change for
// the entry to go away, and that condition must be an observable somebody can
// check -- not "this is hard to run here". The seven that lived here met it,
// which is why they could be closed out rather than argued about.
var gateWiringExemptions = map[string]string{}

type realPGTest struct {
	name, file, via string
	// enterpriseTagged is true when the test's file carries
	// `//go:build enterprise`. A step that names such a test but does NOT pass
	// `-tags enterprise` cannot run it, and `go test -run` on a pattern that
	// matches nothing EXITS 0 -- so naming it there is worse than not naming
	// it: the gate reports success having run nothing. Measured on this PR's
	// own first attempt, where five of fifteen were named in an untagged step
	// and never executed.
	enterpriseTagged bool
}

// migrationSubjectRe matches a test function whose NAME names a migration,
// ANYWHERE in the name rather than only as a prefix.
//
// It was `^TestMigrations?[0-9]` and that was the SIXTH instance of this PR's
// defect, one notch narrower than the fifth: the bound sentence below says "in
// its filename or its function name", and a prefix anchor reads only one of the
// places a function name can say it. Two real migration proofs say it mid-name:
//
//	TestAViewCreatedAfterMigration174IsBoundByTheEnforcer_RealPG
//	    -- core/174's enforce_legacy_policy_read_only() must revoke a view
//	       created AFTER 174 ran
//	TestSystemPolicyCount_MigrationsAreSingleSourceOfTruth
//	    -- applies every core migration and asserts the seeded counts
//
// Three other functions match mid-name and are pure (`TestTheMigrationLoop…`,
// `Test…AgreesWithTheMigrationRunner`, `Test…MatchesTheMigrationCheck`); the
// opener closure excludes them, which is why widening the NAME rule does not
// need a second exclusion list. The population moves 75 -> 77 and both
// additions are wired.
var migrationSubjectRe = regexp.MustCompile(`Migrations?`)

// isMigrationSubject decides whether a real-Postgres test belongs to this
// gate's population -- i.e. whether its SUBJECT is a migration, as opposed to a
// test that merely applies migrations to build a schema and then asserts on
// something else.
//
// # WHY THIS IS A VOCABULARY AND NOT A SHAPE
//
// There is no structural difference between "tests migration 172" and "uses
// migration 172's table to test an RLS policy": both apply the chain and query
// the result. Sweeping every real-Postgres test in these packages into the gate
// would red it on the many that apply migrations as SETUP, and a guard that
// reds on correct code gets relaxed until it guards nothing.
//
// A NUMBER WAS QUOTED HERE WITH NO MEASURE ATTACHED and is removed rather than
// corrected. It said "48 real-Postgres test files apply migrations as setup",
// which came from one ad-hoc shell loop and is not reproducible from the
// sentence: a reader counting files, or tests, or applying a different marker
// for "applies migrations", gets a different figure and cannot tell which of
// you is wrong. The claim does not need a count -- it needs only that the set
// is large and honest, which the paragraph above says without one.
//
// So the population is the set of tests that SAY they are about a migration,
// in either of the two places this repo says it -- the filename or the function
// name, the latter ANYWHERE in the name and not only as a prefix -- and the
// bound is stated rather than implied: a real-Postgres migration test that
// names a migration in NEITHER is outside this census. That is a convention to
// keep, not a hole the classifier can close, because "what is this test about"
// is not recoverable from its syntax.
//
// # WHAT KEYING ON THE FILENAME ALONE COST
//
// The first version of this census kept the old guard's filename key and only
// widened it (`migration_*_realpg_test.go` -> `migration_*_test.go`). That is
// the SAME defect one notch out, and it was live: 13 `TestMigration<N>…`
// functions across 9 files sat outside the population, including migration 172
// (three tests), 173, 171, 154, 123, 122, 094, 082 and 076. Two of the files
// even carry `migration` in their names -- just not as a prefix
// (`audit_vocab_check_migration_realpg_test.go`,
// `decision_vocab_backfill_migration_test.go`). Widening the glob and calling
// the filename defect fixed is how the fifth instance of it ships inside the
// fix for the first four.
func isMigrationSubject(testName, fileName string) bool {
	return strings.Contains(fileName, "migration") || migrationSubjectRe.MatchString(testName)
}

// realPGMigrationTests builds the call graph of one directory's ENTIRE test
// package and returns every migration-subject Test function that transitively
// reaches a realPGOpener.
//
// The graph is built over all `*_test.go`, not only the migration-named ones,
// because a helper that opens Postgres need not live in a migration-named file
// -- restricting the parse to that subset would silently cut every chain
// leaving it, classifying a real-Postgres test as pure. Selection by subject
// happens after the closure, never before it.
func realPGMigrationTests(t *testing.T, dir string) []realPGTest {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	// calls[pkg][fn] = the set of same-package functions fn calls, plus any
	// opener it calls directly (recorded under its dotted name). Keyed by the
	// declaring package because a directory can hold both `agent` and
	// `agent_test`, and an edge between them would be fictional.
	calls := map[string]map[string]map[string]bool{}
	fileOf := map[string]string{}
	entOf := map[string]bool{}
	pkgOf := map[string]string{}
	var tests []string

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// enterpriseBuildTag (declared at the top of this file) is this
		// package's single definition of the sync's build-constraint
		// expression. It lived in hitl_twin_census_test.go until #4254 deleted
		// that census with the grant path; a second literal here would be a
		// weaker copy that could not see `// +build`.
		entTagged := enterpriseBuildTag.Match(raw)
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		pkg := f.Name.Name
		if calls[pkg] == nil {
			calls[pkg] = map[string]map[string]bool{}
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			fname := fn.Name.Name
			fileOf[fname] = name
			entOf[fname] = entTagged
			pkgOf[fname] = pkg
			if strings.HasPrefix(fname, "Test") && isMigrationSubject(fname, name) {
				tests = append(tests, fname)
			}
			set := map[string]bool{}
			ast.Inspect(fn, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := ce.Fun.(type) {
				case *ast.Ident:
					set[fun.Name] = true
				case *ast.SelectorExpr:
					if pkg, ok := fun.X.(*ast.Ident); ok {
						set[pkg.Name+"."+fun.Sel.Name] = true
					}
				}
				return true
			})
			calls[pkg][fname] = set
		}
	}

	// Transitive closure within one package: does `fn` reach an opener?
	memo := map[string]string{} // pkg+"."+fn -> the opener reached, "" if none
	var reaches func(pkg, fn string, seen map[string]bool) string
	reaches = func(pkg, fn string, seen map[string]bool) string {
		key := pkg + "." + fn
		if v, ok := memo[key]; ok {
			return v
		}
		if seen[key] {
			return ""
		}
		seen[key] = true
		for callee := range calls[pkg][fn] {
			if realPGOpeners[callee] {
				memo[key] = callee
				return callee
			}
		}
		for callee := range calls[pkg][fn] {
			if _, local := calls[pkg][callee]; !local {
				continue
			}
			if v := reaches(pkg, callee, seen); v != "" {
				memo[key] = v
				return v
			}
		}
		memo[key] = ""
		return ""
	}

	var out []realPGTest
	sort.Strings(tests)
	for _, tn := range tests {
		if via := reaches(pkgOf[tn], tn, map[string]bool{}); via != "" {
			out = append(out, realPGTest{name: tn, file: fileOf[tn], via: via, enterpriseTagged: entOf[tn]})
		}
	}
	return out
}

// namedInRunFilter and namedInPassList read the two places a test must appear,
// separately, because they fail differently and "somewhere in the file" hides
// both (round 1, finding 4).
//
// A name only in a `-run` filter runs but is never asserted, so a SKIP passes
// as a run -- the failure this whole gate exists to prevent. A name only in a
// PASS list is asserted and never selected, so the step reds for a test it
// never asked for. A name in a YAML COMMENT alone satisfied the old
// strings.Contains check and neither of these.
func namedInRunFilter(wf, test string) bool {
	for _, m := range runFilterRe.FindAllStringSubmatch(wf, -1) {
		for _, alt := range strings.Split(m[1], "|") {
			if strings.Trim(alt, "^$ ") == test {
				return true
			}
		}
	}
	return false
}

var runFilterRe = regexp.MustCompile(`-run '([^']*)'`)

func namedInPassList(wf, test string) bool {
	// ANY `for <var> in … do` block whose body greps `^--- PASS: $<var>`, not
	// one hard-coded loop variable. The gate uses `for want in` seven times and
	// `for t in` twice, and the first version of this function read only the
	// former -- so it reported three correctly-asserted migration-147 tests as
	// unasserted. That is the "reads one spelling" defect this whole PR is
	// about, committed inside the fix for it, which is why the loop variable is
	// now derived from the block rather than assumed.
	if strings.Contains(wf, `"^--- PASS: `+test+`"`) {
		return true
	}
	for _, m := range passLoopRe.FindAllStringSubmatch(wf, -1) {
		loopVar, names, body := m[1], m[2], m[3]
		// The block must actually assert a PASS on its own loop variable;
		// otherwise it is some other loop that happens to list names.
		if !strings.Contains(body, "--- PASS: $"+loopVar) &&
			!strings.Contains(body, "--- PASS: ${"+loopVar+"}") {
			continue
		}
		for _, line := range strings.Split(names, "\n") {
			if strings.Trim(line, " \\\t;") == test {
				return true
			}
		}
	}
	return false
}

// passLoopRe captures (loop variable, names, body) for a shell `for X in … do …
// done` whose body is checked above for a PASS assertion on X.
var passLoopRe = regexp.MustCompile(`(?s)for ([a-z]+) in((?:[^\n]*\\\n)*[^\n]*?);?\s*do(.*?)done`)

// namedInTaggedStep reports whether some `go test` invocation in the workflow
// both names this test and passes -tags enterprise. Scans each `go test ...`
// invocation up to its redirect, because a workflow has several and only the
// one naming the test is the one that has to carry the tag.
// EXACT, NOT SUBSTRING, and that is a defect this function had. It asked
// `strings.Contains(inv, test)`, so an enterprise-tagged test named
// `TestMigration1` would be reported as correctly tagged because
// `TestMigration112_…` appears in a tagged invocation -- and the two readers
// either side of it match a `-run` alternative EXACTLY. A guard whose three
// readers disagree about what "named" means answers three different questions
// and reports them as one.
func namedInTaggedStep(wf, test string) bool {
	for _, chunk := range strings.Split(wf, "go test ") {
		end := strings.Index(chunk, "| tee")
		if end < 0 {
			end = len(chunk)
		}
		inv := chunk[:end]
		if strings.Contains(inv, "-tags enterprise") && namedInRunFilter(inv, test) {
			return true
		}
	}
	return false
}

// TestTheThreeWorkflowReadersAgreeAboutWhatNAMEDMeans pins the property whose
// absence was round 3's finding: namedInTaggedStep substring-matched while its
// two siblings matched a -run alternative exactly, so a guard with three
// readers answered three different questions and reported them as one.
//
// It is a test rather than a comment because the defect is invisible on the
// real workflow -- every test named there today is also named exactly, so the
// substring version passes on this tree and fails only on a name that is a
// PREFIX of another. That is a shape no tree reliably contains, which is
// exactly when a fixture is the only instrument that can see it.
func TestTheThreeWorkflowReadersAgreeAboutWhatNAMEDMeans(t *testing.T) {
	const wf = `
      - name: tagged
        run: |
          go test -tags enterprise ./agent/ -run 'TestMigration112_Clean' | tee /tmp/a.log
      - name: untagged
        run: |
          go test ./agent/ -run 'TestMigration1' | tee /tmp/b.log
      - name: assert
        run: |
          for want in \
            TestMigration1 \
            TestMigration112_Clean
          do
            grep -q "^--- PASS: ${want}" /tmp/b.log
          done
`
	// TestMigration1 is a PREFIX of TestMigration112_Clean, and only the
	// UNTAGGED invocation names it. A substring reader says "tagged", which
	// would let an enterprise-tagged test sit in a step that cannot run it.
	if namedInTaggedStep(wf, "TestMigration1") {
		t.Error("namedInTaggedStep reported TestMigration1 as named in a `-tags enterprise` step; " +
			"it is named only in the UNTAGGED one, and matched the tagged step solely as a prefix of TestMigration112_Clean")
	}
	// The positive direction, so the assertion above cannot pass because the
	// reader stopped finding anything at all.
	if !namedInTaggedStep(wf, "TestMigration112_Clean") {
		t.Error("namedInTaggedStep did not find TestMigration112_Clean, which IS named in the tagged step; " +
			"without this the negative above would pass for a reader that matches nothing")
	}
	// And the two siblings agree on the same fixture.
	if !namedInRunFilter(wf, "TestMigration1") || !namedInPassList(wf, "TestMigration1") {
		t.Error("namedInRunFilter/namedInPassList disagree with the fixture; they are the readers namedInTaggedStep was aligned TO")
	}
}

// liveYAML drops comment lines, so every reader below answers about what the
// workflow RUNS rather than about what it says.
//
// It was originally inside namedInTaggedStep alone, which left the other two
// readers looking at prose: a step commented out wholesale still satisfied
// namedInRunFilter, and the test would then be reported as "in a -run filter
// but NOT in any PASS-assertion list" -- a true-sounding message naming the
// wrong defect, which is worse than silence because it sends the reader to the
// PASS list of a step that no longer exists. Stripping once, at the single
// place the file is read, is what keeps the three readers answering about the
// same document.
func liveYAML(wf string) string {
	var live []string
	for _, line := range strings.Split(wf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		live = append(live, line)
	}
	return strings.Join(live, "\n")
}

// repoRootForGateCensus walks up for the directory holding .github/.
func repoRootForGateCensus(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, ".github")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root (no .github/ found walking up)")
	return ""
}
