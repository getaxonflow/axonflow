package registry

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestMain enforces that every declared conformance case actually executed.
//
// This is the mechanism the registry check below cannot substitute for. A
// registry test can assert that a named test EXISTS; only this can assert that
// the test still exercises its case, because a test can be edited until its
// assertions no longer touch the property while keeping its name and signature.
//
// It is suppressed under a -run filter, because a filtered run legitimately
// executes a subset and failing a developer's single-test run would train
// everyone to ignore it. It is also suppressed when the run already failed:
// piling a completeness failure on a real one buries the real one, and a case
// whose test failed did in fact execute.
func TestMain(m *testing.M) {
	code := m.Run()
	if code != 0 {
		os.Exit(code)
	}
	if filtered := flag.Lookup("test.run"); filtered != nil && filtered.Value.String() != "" {
		os.Exit(code)
	}
	if missing := UnmarkedConformanceCases(); len(missing) > 0 {
		fmt.Fprintf(os.Stderr,
			"\nregistry conformance: %d case(s) were never executed: %s\n"+
				"Each case in the corpus must call MarkConformanceCase from the test that exercises it.\n"+
				"A case listed as covered in the ADR-065 disposition ledger but not executed here is coverage the ledger cannot see.\n",
			len(missing), strings.Join(missing, ", "))
		os.Exit(1)
	}
	os.Exit(code)
}

// testFuncPattern matches a top-level Go test function declaration.
var testFuncPattern = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)`)

// packageTestFiles reads every _test.go file in this package.
func packageTestFiles(t *testing.T) map[string]map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	out := map[string]map[string]bool{}
	total := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(filepath.Clean(name))
		if readErr != nil {
			t.Fatalf("reading %s: %v", name, readErr)
		}
		funcs := map[string]bool{}
		for _, m := range testFuncPattern.FindAllStringSubmatch(string(src), -1) {
			funcs[m[1]] = true
			total++
		}
		out[name] = funcs
	}
	// The anti-vacuity half. A broken pattern that matched nothing would make
	// every "the named test exists" assertion fail loudly, which is fine; a
	// pattern that matched EVERYTHING would make them all pass silently.
	if total == 0 {
		t.Fatalf("no test functions were found; the scanner is broken and every check below would pass vacuously")
	}
	return out
}

// TestConformanceCorpusIsWellFormed checks the corpus itself.
func TestConformanceCorpusIsWellFormed(t *testing.T) {
	for _, problem := range ConformanceCorpusProblems(RegistryConformanceCases()) {
		t.Error(problem)
	}
}

// TestConformanceCorpusGuardSelfTest drives the same checker over deliberately
// broken corpora, so a rule that stopped matching is caught on this commit
// rather than on the commit that needed it.
func TestConformanceCorpusGuardSelfTest(t *testing.T) {
	clean := RegistryConformanceCases()
	if problems := ConformanceCorpusProblems(clean); len(problems) > 0 {
		t.Fatalf("the committed corpus does not pass its own checker, so the mutations below prove nothing: %v", problems)
	}
	for name, tc := range map[string]struct {
		mutate func([]ConformanceCase) []ConformanceCase
		want   string
	}{
		"an identifier outside the range": {
			mutate: func(in []ConformanceCase) []ConformanceCase { in[0].ID = "AXC-201"; return in },
			want:   "outside the registry plane's",
		},
		"a duplicated identifier": {
			mutate: func(in []ConformanceCase) []ConformanceCase { in[1].ID = in[0].ID; return in },
			want:   "duplicates index",
		},
		"an unreviewable assertion": {
			mutate: func(in []ConformanceCase) []ConformanceCase { in[0].Asserts = "it works"; return in },
			want:   "not reviewable",
		},
		"a name that is not a test": {
			mutate: func(in []ConformanceCase) []ConformanceCase { in[0].TestName = "checkThing"; return in },
			want:   "not a Go test function name",
		},
		"a file that is not a test file": {
			mutate: func(in []ConformanceCase) []ConformanceCase { in[0].TestFile = "catalog.go"; return in },
			want:   "not a Go test file",
		},
		"a malformed source case": {
			mutate: func(in []ConformanceCase) []ConformanceCase { in[0].SourceCases = []string{"EX-4"}; return in },
			want:   "not of the form EX-NN",
		},
		"a missing title": {
			mutate: func(in []ConformanceCase) []ConformanceCase { in[0].Title = ""; return in },
			want:   "has no title",
		},
	} {
		t.Run("the checker refuses "+name, func(t *testing.T) {
			got := ConformanceCorpusProblems(tc.mutate(RegistryConformanceCases()))
			if len(got) == 0 {
				t.Fatalf("the checker accepted %s", name)
			}
			if !strings.Contains(strings.Join(got, "; "), tc.want) {
				t.Fatalf("the checker refused %s with the wrong message: %v", name, got)
			}
		})
	}
}

// TestEveryConformanceCaseNamesATestThatExists closes the gap between the
// corpus and the source.
func TestEveryConformanceCaseNamesATestThatExists(t *testing.T) {
	files := packageTestFiles(t)
	for _, c := range RegistryConformanceCases() {
		funcs, ok := files[c.TestFile]
		if !ok {
			t.Errorf("case %s names file %s, which is not in this package", c.ID, c.TestFile)
			continue
		}
		if !funcs[c.TestName] {
			t.Errorf("case %s names test %s in %s, which that file does not declare", c.ID, c.TestName, c.TestFile)
		}
	}
}

// TestMarkingAnUndeclaredCasePanics proves a typo in a mark is loud.
//
// Without it, a mistyped mark would satisfy nothing while looking like
// coverage, and the case it meant to mark would be reported as never executed
// with no clue why.
func TestMarkingAnUndeclaredCasePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("marking an undeclared case did not panic")
		}
	}()
	MarkConformanceCase("AXC-399")
}

// TestConformanceCasesAreHandedOutAsACopy proves a caller cannot mutate the
// package's own slice, which would make the corpus a function of test order.
func TestConformanceCasesAreHandedOutAsACopy(t *testing.T) {
	first := RegistryConformanceCases()
	if len(first) == 0 {
		t.Fatalf("the corpus is empty")
	}
	original := first[0].ID
	first[0].ID = "AXC-000"
	if RegistryConformanceCases()[0].ID != original {
		t.Fatalf("RegistryConformanceCases handed out the package's own slice")
	}
}

// ledgerPath is the ADR-065 disposition ledger, relative to this package.
//
// The ledger lives with the decision-core conformance suite, which cannot
// import this package's corpus without a cycle, so this package-side comparison
// is the direction that CAN exist and it reads the file directly.
const ledgerPath = "../conformance/disposition_ledger.tsv"

// TestLedgerCoverageCellsAgreeWithTheComputedCorpus is the drift gate, in the
// form #3570 established.
//
// The decision-core gate deliberately tolerates coverage identifiers that do
// not resolve there, because other workstreams cite their own corpora into the
// same cells. That tolerance is correct and it is also a hole: nothing on that
// side can notice when a cell names an AXC-3NN case this package no longer has,
// or when this package's SourceCases move and the cell does not. This is the
// only check that compares the two.
//
// It is a hard failure, not a skip, when the ledger is missing. A guard that
// skips where its subject is absent is invisible exactly where it stopped
// running.
func TestLedgerCoverageCellsAgreeWithTheComputedCorpus(t *testing.T) {
	src, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("reading the disposition ledger: %v (if the ledger moved, update ledgerPath; do not skip)", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(src), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("the ledger has no data rows")
	}
	col := map[string]int{}
	for i, name := range strings.Split(lines[0], "\t") {
		col[name] = i
	}
	idCol, okID := col["source_case_id"]
	covCol, okCov := col["coverage_case_ids"]
	if !okID || !okCov {
		t.Fatalf("the ledger header does not name source_case_id and coverage_case_ids: %q", lines[0])
	}

	inCorpus := map[string]bool{}
	for _, c := range RegistryConformanceCases() {
		inCorpus[c.ID] = true
	}
	computed := CoverageBySourceCase()
	if len(computed) == 0 {
		t.Fatalf("no case in the corpus cites a source case, so this gate would compare nothing")
	}

	rows := map[string]bool{}
	for i, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) <= idCol || len(fields) <= covCol {
			t.Fatalf("ledger line %d has %d fields, too few to read", i+2, len(fields))
		}
		srcID := strings.TrimSpace(fields[idCol])
		rows[srcID] = true

		// Identifiers are filtered by the PLANE's allocated range, not by
		// corpus membership. Filtering by membership let a cell cite a
		// nonexistent AXC-3xx id and pass, because the unknown id was
		// silently dropped before comparison - the exact drift this gate
		// exists to catch. EX-NN self-identifiers and other workstreams'
		// ranges are still out of scope.
		var cited []string
		for _, id := range strings.Split(fields[covCol], ",") {
			if id = strings.TrimSpace(id); registryCaseIDPattern.MatchString(id) {
				if !inCorpus[id] {
					t.Errorf("ledger row %s cites %s, which is in the registry plane's range but does not exist in the corpus", srcID, id)
					continue
				}
				cited = append(cited, id)
			}
		}
		sort.Strings(cited)
		if got, want := strings.Join(cited, ","), strings.Join(computed[srcID], ","); got != want {
			t.Errorf("ledger row %s cites registry-plane cases [%s]; the corpus computes [%s] - the TSV cell and the corpus's SourceCases have drifted",
				srcID, got, want)
		}
	}
	for srcID := range computed {
		if !rows[srcID] {
			t.Errorf("the corpus covers source case %s but the ledger has no row for it", srcID)
		}
	}
}

// TestConformanceIdentifiersDoNotCollideWithOtherPlanes proves the range
// allocation holds against the ranges the other planes own.
func TestConformanceIdentifiersDoNotCollideWithOtherPlanes(t *testing.T) {
	// AXC-001..AXC-199 is the decision core, AXC-200..AXC-299 the identity
	// plane. Both are stated in their own packages' documentation; this asserts
	// only that nothing here lands in either.
	for _, c := range RegistryConformanceCases() {
		var n int
		if _, err := fmt.Sscanf(c.ID, "AXC-%d", &n); err != nil {
			t.Errorf("case %s does not parse as AXC-NNN", c.ID)
			continue
		}
		if n < 300 || n > 399 {
			t.Errorf("case %s is outside AXC-300..AXC-399, which is the range this plane owns", c.ID)
		}
	}
}
