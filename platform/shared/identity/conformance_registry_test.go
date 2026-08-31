// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

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

// TestMain enforces that every conformance case applicable to this build
// actually executed.
//
// This is the mechanism the other two cannot substitute for. A registry test
// can check that a named test EXISTS; only this can check that the test still
// exercises its case, because a test can be edited until its assertions no
// longer touch the property while keeping its name and its signature.
//
// It is suppressed under a -run filter. A filtered run legitimately executes a
// subset, and failing a developer's single-test run because the other forty
// cases did not execute would train everyone to ignore this check. CI runs the
// package unfiltered, which is where it is meant to bite.
//
// It is also suppressed when the run already failed. Piling a completeness
// failure on top of a real one buries the real one, and a case whose test
// failed did in fact execute.
func TestMain(m *testing.M) {
	code := m.Run()

	if code != 0 {
		os.Exit(code)
	}
	if filtered := flag.Lookup("test.run"); filtered != nil && filtered.Value.String() != "" {
		os.Exit(code)
	}

	if missing := UnmarkedConformanceCases(conformanceEnterpriseBuild); len(missing) > 0 {
		fmt.Fprintf(os.Stderr,
			"\nidentity conformance: %d case(s) applicable to this build were never executed: %s\n"+
				"Each case in the corpus must call MarkConformanceCase from the test that exercises it.\n"+
				"A case listed as covered in the ADR-065 disposition ledger but not executed here is coverage the ledger cannot see.\n",
			len(missing), strings.Join(missing, ", "))
		os.Exit(1)
	}
	os.Exit(code)
}

// testFuncPattern matches a top-level Go test function declaration.
var testFuncPattern = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)`)

// testFileFacts is what the registry check needs to know about one _test.go
// file in this package.
type testFileFacts struct {
	// present records whether the file is on disk at all.
	present bool
	// enterprise records whether it carries the Enterprise build constraint.
	enterprise bool
	// funcs is the set of top-level test functions it declares.
	funcs map[string]bool
}

// packageTestFiles reads every _test.go file in this package.
//
// It is keyed BY FILE rather than by function name, because the question the
// registry check has to answer is per file: the community sync removes the
// enterprise half of every build-tag pair, so in the published mirror an
// Enterprise-only case's file is not on disk, and only a per-file view can tell
// that apart from a function that was renamed or deleted by mistake.
// enterpriseSourceRe is the community sync's definition of enterprise-only
// source (.github/workflows/sync-community-repo.yml and
// .github/scripts/check-enterprise-leak.sh). Kept byte-identical at every site
// by tests/regression-test-required/enterprise_tag_regex_single_definition_test.sh.
var enterpriseSourceRe = regexp.MustCompile(`(?m)^//go:build enterprise|^// \+build enterprise`)

func packageTestFiles(t *testing.T) map[string]testFileFacts {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	out := map[string]testFileFacts{}
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
		text := string(src)
		facts := testFileFacts{
			present: true,
			// Classified by the community sync's OWN expression (anchored at
			// start of line, covering the legacy `// +build` form), because
			// the question is "will the sync strip this file". A bare
			// strings.Contains on the directive text counted the phrase
			// wherever a comment quoted it, and missed the legacy form.
			enterprise: enterpriseSourceRe.Match(src),
			funcs:      map[string]bool{},
		}
		for _, m := range testFuncPattern.FindAllStringSubmatch(text, -1) {
			facts.funcs[m[1]] = true
			total++
		}
		out[name] = facts
	}
	if total == 0 {
		t.Fatalf("no test functions were found; the scanner is broken and every check below would pass vacuously")
	}
	return out
}

// TestConformanceCorpusIsWellFormed checks the corpus itself.
//
// The scanner-found-nothing guard in packageTestFunctions is the anti-vacuity
// half: without it, a broken regex would make every "the named test exists"
// assertion below fail loudly, which is fine, but a regex that matched
// EVERYTHING would make them all pass silently.
func TestConformanceCorpusIsWellFormed(t *testing.T) {
	cases := IdentityConformanceCases()
	if len(cases) == 0 {
		t.Fatalf("the conformance corpus is empty")
	}

	idPattern := regexp.MustCompile(`^AXC-2\d\d$`)
	seenID := map[string]bool{}
	files := packageTestFiles(t)

	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			if !idPattern.MatchString(c.ID) {
				t.Fatalf("id %q is outside the identity plane's AXC-200 to AXC-299 allocation", c.ID)
			}
			if seenID[c.ID] {
				t.Fatalf("id %q is declared twice", c.ID)
			}
			seenID[c.ID] = true

			if strings.TrimSpace(c.Title) == "" {
				t.Errorf("case %s has no title", c.ID)
			}
			if strings.TrimSpace(c.Asserts) == "" {
				t.Errorf("case %s does not state what it asserts, so a reviewer cannot check the test against it", c.ID)
			}
			if c.Edition != ConformanceAnyEdition && c.Edition != ConformanceEnterpriseOnly {
				t.Errorf("case %s declares unknown edition %d", c.ID, int(c.Edition))
			}
			for _, src := range c.SourceCases {
				if !regexp.MustCompile(`^EX-\d\d$`).MatchString(src) {
					t.Errorf("case %s cites source case %q, which is not an EX-NN identifier", c.ID, src)
				}
			}

			if strings.TrimSpace(c.TestFile) == "" {
				t.Fatalf("case %s does not name the file its test lives in", c.ID)
			}
			facts, onDisk := files[c.TestFile]
			if !onDisk {
				// The ONLY tolerated absence: the community sync removes the
				// enterprise half of every build-tag pair, so in the published
				// mirror an Enterprise-only case's file is genuinely not there.
				// An any-edition case's file missing is always a defect, and so
				// is an Enterprise-only file missing from the Enterprise
				// repository, which is what the second condition catches.
				if c.Edition == ConformanceEnterpriseOnly && !conformanceEnterpriseBuild {
					return
				}
				t.Fatalf("case %s names file %q, which is not in this package", c.ID, c.TestFile)
			}
			if !facts.funcs[c.TestName] {
				t.Fatalf("case %s names test %q, which is not declared in %s", c.ID, c.TestName, c.TestFile)
			}
			// The edition declared on the case must match where its test
			// actually lives. A case marked any-edition whose test is
			// Enterprise-tagged would be required in a community build and
			// could never run there, and one marked Enterprise-only whose test
			// is untagged silently loses its completeness check in community
			// builds.
			if (c.Edition == ConformanceEnterpriseOnly) != facts.enterprise {
				t.Errorf("case %s declares edition %s but its test %q lives in %s, which is %s file",
					c.ID, c.Edition, c.TestName, c.TestFile,
					map[bool]string{true: "an Enterprise-tagged", false: "an untagged"}[facts.enterprise])
			}
		})
	}
}

// TestConformanceMarkingRejectsUnknownCases pins that a test cannot claim
// coverage of a case the corpus does not contain.
//
// Without the panic, a typo in a case id would leave the real case unmarked AND
// record a mark nobody reads, so the completeness check would fail with a
// confusing message about a case whose test plainly exists.
func TestConformanceMarkingRejectsUnknownCases(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("MarkConformanceCase accepted an id that is not in the corpus")
		}
	}()
	MarkConformanceCase("AXC-999")
}

// TestCoverageBySourceCaseIsComputedNotTranscribed pins the mapping that feeds
// the ADR-065 disposition ledger.
//
// The ledger's coverage_case_ids cells are edited by hand into a TSV that lives
// with the decision-core conformance suite. Computing the values here means the
// hand edit is checkable against something executable rather than against a
// list in a commit message.
func TestCoverageBySourceCaseIsComputedNotTranscribed(t *testing.T) {
	coverage := CoverageBySourceCase()
	if len(coverage) == 0 {
		t.Fatalf("no source case has identity-plane coverage")
	}

	// The six source cases this session's brief names must each have coverage.
	// They are the identity-realm cases of the source specification, and a
	// coverage cell for any of them that cited nothing would be the ledger
	// recording a source case as covered by nothing.
	for _, src := range []string{"EX-13", "EX-14", "EX-27", "EX-45", "EX-46", "EX-47"} {
		ids, ok := coverage[src]
		if !ok || len(ids) == 0 {
			t.Errorf("source case %s has no identity-plane conformance coverage", src)
			continue
		}
		if !sort.StringsAreSorted(ids) {
			t.Errorf("coverage for %s is not sorted: %v", src, ids)
		}
		for _, id := range ids {
			found := false
			for _, c := range IdentityConformanceCases() {
				if c.ID == id {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("coverage for %s cites %s, which is not in the corpus", src, id)
			}
		}
	}

	// The summary renders one line per case with a stable column count, which
	// is what makes it usable in a PR body and in an operator report.
	summary := ConformanceCorpusSummary()
	lines := strings.Split(strings.TrimSuffix(summary, "\n"), "\n")
	if len(lines) != len(IdentityConformanceCases()) {
		t.Fatalf("the summary has %d lines for %d cases", len(lines), len(IdentityConformanceCases()))
	}
	for _, line := range lines {
		if got := len(strings.Split(line, "\t")); got != 4 {
			t.Fatalf("summary line %q has %d columns, want 4", line, got)
		}
	}
}

// TestIdentityConformanceCasesHandsOutACopy pins that the corpus cannot be
// edited by a consumer, since the ledger cites it.
func TestIdentityConformanceCasesHandsOutACopy(t *testing.T) {
	first := IdentityConformanceCases()
	if len(first) == 0 {
		t.Fatalf("empty corpus")
	}
	originalID := first[0].ID
	first[0].ID = "AXC-000"

	if IdentityConformanceCases()[0].ID != originalID {
		t.Fatalf("IdentityConformanceCases handed out the package's own slice")
	}
}

// identityLedgerPath is the ADR-065 disposition ledger, relative to this
// package. The ledger lives with the decision-core conformance suite in a
// different Go module, so it cannot import this package's corpus; this test is
// the direction of the comparison that CAN exist, and it reads the file
// directly. The path resolves in the community mirror too: the sync does not
// exclude platform/decision, and this file is untagged.
const identityLedgerPath = "../../decision/conformance/disposition_ledger.tsv"

// TestLedgerCoverageCellsAgreeWithTheComputedCorpus closes the drift the
// round-three review demonstrated: AXC-279 was added with SourceCases EX-47
// AFTER the ledger's coverage cells were edited, CoverageBySourceCase then
// disagreed with the TSV, and NO gate compared them. The decision-core gate
// deliberately tolerates identifiers that do not resolve there, because other
// workstreams cite their own corpora into the same cells, so this package-side
// comparison is the only check that can catch the next such drift.
//
// It is deliberately a hard failure, not a skip, when the ledger is missing: a
// guard that skips where its subject is absent is invisible exactly where it
// stopped running.
func TestLedgerCoverageCellsAgreeWithTheComputedCorpus(t *testing.T) {
	src, err := os.ReadFile(identityLedgerPath)
	if err != nil {
		t.Fatalf("reading the disposition ledger: %v (if the ledger moved, update identityLedgerPath; do not skip)", err)
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
	for _, c := range IdentityConformanceCases() {
		inCorpus[c.ID] = true
	}

	computed := CoverageBySourceCase()
	rows := map[string]bool{}
	for i, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) <= idCol || len(fields) <= covCol {
			t.Fatalf("ledger line %d has %d fields, too few to read", i+2, len(fields))
		}
		srcID := strings.TrimSpace(fields[idCol])
		rows[srcID] = true

		// Identifiers are filtered by the PLANE's allocated range
		// (AXC-200..299), not by corpus membership. Membership filtering let
		// a cell cite a nonexistent in-range id and pass, because the
		// unknown id was silently dropped before comparison. EX-NN
		// self-identifiers and other workstreams' AXC ranges stay out of
		// scope.
		var cited []string
		identityPlanePattern := regexp.MustCompile(`^AXC-2\d\d$`)
		for _, id := range strings.Split(fields[covCol], ",") {
			if id = strings.TrimSpace(id); identityPlanePattern.MatchString(id) {
				if !inCorpus[id] {
					t.Errorf("ledger row %s cites %s, which is in the identity plane's range but does not exist in the corpus", srcID, id)
					continue
				}
				cited = append(cited, id)
			}
		}
		sort.Strings(cited)

		if got, want := strings.Join(cited, ","), strings.Join(computed[srcID], ","); got != want {
			t.Errorf("ledger row %s cites identity-plane cases [%s]; the corpus computes [%s] - the TSV cell and the corpus's SourceCases have drifted", srcID, got, want)
		}
	}

	// The other direction: a corpus case citing a source case the ledger has
	// no row for is a citation into nothing, which the per-row loop above
	// cannot see.
	for srcID := range computed {
		if !rows[srcID] {
			t.Errorf("the corpus covers source case %s but the ledger has no row for it", srcID)
		}
	}
}
