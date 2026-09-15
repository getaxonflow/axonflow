// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// StagedMirrorEnv names the directory holding a community copy staged by
// scripts/ci/simulate-community-mirror.sh. The staged-copy test below is driven
// by that script rather than staging anything itself: staging replays the sync's
// whole rsync chain and takes minutes, which is not a cost a unit test should
// carry, and the script already runs on every pull request in test.yml's
// mirror-simulation lane and at seven points in sync-community-repo.yml.
const StagedMirrorEnv = "AXONFLOW_STAGED_MIRROR"

// stagedMirrorReport is what one pass over the enterprise-classified rows found.
type stagedMirrorReport struct {
	// Findings are the defects, each naming the file it is about.
	Findings []string
	// RowsChecked, EnterpriseFiles and TwinFiles are the population this pass
	// actually looked at. They exist so a caller can refuse a pass that
	// asserted about almost nothing.
	RowsChecked     int
	EnterpriseFiles int
	TwinFiles       int
	// RowsWithNoEnterpriseFile are rows whose implementation list names no
	// enterprise-only file. Every assertion about such a row would run over an
	// empty slice, so they are reported rather than skipped.
	RowsWithNoEnterpriseFile []string
}

// checkStagedMirror is the whole rule, as a function, so that the real staged
// copy and the synthetic fixtures in TestTheStagedMirrorCheckCanFail drive
// IDENTICAL logic. A self-test that re-implements the check proves only that two
// implementations agree.
//
// root is the enterprise checkout. staged is a community copy. The edition of a
// file is decided by SourceEdition - the sync's own classifier - never by a
// second spelling of the build-constraint rule.
func checkStagedMirror(root, staged string) (stagedMirrorReport, error) {
	var rep stagedMirrorReport
	for _, e := range Load().Entries {
		if e.Classification != ClassEnterpriseImplementation && e.Classification != ClassEnterpriseProtocol {
			continue
		}
		rep.RowsChecked++

		var enterprise, community []string
		for _, impl := range e.Implementation {
			files, err := goFilesUnder(root, impl)
			if err != nil {
				return rep, fmt.Errorf("%s: listing %s: %w", e.ID, impl, err)
			}
			for _, f := range files {
				ed, err := SourceEdition(root, f)
				if err != nil {
					return rep, fmt.Errorf("%s: classifying %s: %w", e.ID, f, err)
				}
				if ed == "enterprise" {
					enterprise = append(enterprise, f)
				} else {
					community = append(community, f)
				}
			}
		}

		if len(enterprise) == 0 {
			rep.RowsWithNoEnterpriseFile = append(rep.RowsWithNoEnterpriseFile, e.ID)
			continue
		}
		rep.EnterpriseFiles += len(enterprise)
		rep.TwinFiles += len(community)

		for _, f := range enterprise {
			if _, err := os.Stat(filepath.Join(staged, f)); err == nil {
				rep.Findings = append(rep.Findings, fmt.Sprintf(
					"LEAK: %s is enterprise-only source (%s, classified %q) and it SURVIVED into "+
						"the staged community copy. The sync publishes that copy to the public mirror",
					f, e.ID, e.Classification))
			}
		}
		// The other direction, and it is not decoration: an exclusion written one
		// character too wide strips the community twin as well, and the mirror
		// then ships a package that does not compile. `go vet` on the staged copy
		// catches that only where the twin is imported by something else staged.
		for _, f := range community {
			if _, err := os.Stat(filepath.Join(staged, f)); err != nil {
				rep.Findings = append(rep.Findings, fmt.Sprintf(
					"OVER-STRIPPED: %s is community source (%s) and is MISSING from the staged "+
						"copy; the mirror would ship this capability's enterprise half removed and "+
						"its community half removed too", f, e.ID))
			}
		}
	}
	return rep, nil
}

// ANTI-VACUITY FLOORS, and they are not a count of the population. The guard is
// the per-file comparison in checkStagedMirror; these two only refuse a pass
// that ran over almost nothing. Both are compared against bounds well below the
// measured truth (22 rows and 237 enterprise-only files at the time of writing).
// A pinned count would go stale the day a file moves and would teach the next
// author to raise it until it matched; a floor beneath the true count stays
// valid across ordinary movement and still catches the population silently
// collapsing.
const (
	minStagedMirrorRows            = 20
	minStagedMirrorEnterpriseFiles = 150
)

// TestEnterpriseImplementationIsAbsentFromTheStagedMirror is #3591's acceptance
// criterion as an assertion: the community staging copy contains no
// enterprise_implementation source.
//
// # WHY THIS RUNS ON THE ENTERPRISE SIDE, WHICH IS THE OPPOSITE OF ITS NEIGHBOURS
//
// Every other tree-reading test in this package SKIPS when TreeIsCommunityMirror
// is true, because the enterprise halves are stripped there and their subject is
// gone. This one skips for the mirror for a DIFFERENT and stronger reason, and a
// reader who conflates the two will "fix" it into a test that cannot fail:
//
// the registry carries no per-path edition. Entry.Implementation is a flat
// []string and only the ROW has build_tag and sync. circuit.breaker names
// platform/agent/circuitbreaker/handler.go and .../circuitbreaker_community.go,
// and on the mirror those two arrive as an unordered pair with the evidence that
// distinguishes them - the build constraint - deleted by the very sync under
// test. A mirror-side check could assert only "at least one of this row's paths
// is absent", which a typo in the registry satisfies.
//
// It would also be vacuous rather than merely weak. goFilesUnder returns no
// files and NO error for an absent path, deliberately, so the mirror's correct
// state is not a red test in the public repository. "No file under this row
// resolves to enterprise" is then a loop over an empty set: it passes with every
// helper behaving exactly as documented.
//
// The enterprise tree holds BOTH halves, so it can compute which files are
// enterprise-only and then assert those exact files are absent from the staged
// copy while their community twins survive. That is decidable here and nowhere
// else.
//
// # WHAT IT DOES NOT ASSERT
//
// Not "one path absent, one present". Two rows falsify that shape:
// saas.plugin_license names platform/agent/billing, which survives the staging
// as an EMPTY directory, and saas.portal_proxy keeps platform/agent/proxy.go
// while losing its ee/ path. The unit is the FILE, and a directory that survives
// holding no Go file is indistinguishable from an absent one here.
func TestEnterpriseImplementationIsAbsentFromTheStagedMirror(t *testing.T) {
	staged := os.Getenv(StagedMirrorEnv)
	if staged == "" {
		t.Skipf("%s is unset: this test is driven by scripts/ci/simulate-community-mirror.sh, "+
			"which stages a copy and points this variable at it. TestTheStagedMirrorCheckCanFail "+
			"exercises the same rule over fixtures and needs no staging", StagedMirrorEnv)
	}
	root := repoRoot(t)
	if TreeIsCommunityMirror(root) {
		t.Skip("community mirror checkout: the enterprise halves are stripped here, so the " +
			"partition this test computes cannot be computed at all. This is NOT the neighbouring " +
			"tests' skip, which is about their subject being absent - see the header")
	}
	if fi, err := os.Stat(staged); err != nil || !fi.IsDir() {
		t.Fatalf("%s=%q is not a directory (%v); a staged copy that does not exist would make "+
			"every absence assertion trivially true", StagedMirrorEnv, staged, err)
	}
	// A staged copy is only the mirror if the sync's wholesale exclusion applied.
	// Without this, a caller pointing the variable at the enterprise tree itself
	// would see every enterprise file "present" and read as a wall of leaks.
	if _, err := os.Stat(filepath.Join(staged, "ee")); err == nil {
		t.Fatalf("%s=%q still contains ee/, so it is not a staged community copy", StagedMirrorEnv, staged)
	}

	rep, err := checkStagedMirror(root, staged)
	if err != nil {
		t.Fatalf("checking the staged copy: %v", err)
	}
	for _, f := range rep.Findings {
		t.Error(f)
	}
	if len(rep.RowsWithNoEnterpriseFile) > 0 {
		t.Fatalf("%d row(s) classified enterprise_implementation or enterprise_protocol name no "+
			"enterprise-only file, so nothing was asserted about them: %v. Either the "+
			"classification is aspirational or the implementation list was trimmed",
			len(rep.RowsWithNoEnterpriseFile), rep.RowsWithNoEnterpriseFile)
	}
	if rep.RowsChecked < minStagedMirrorRows {
		t.Fatalf("only %d enterprise-classified row(s) checked (floor %d); the population "+
			"collapsed and this test is asserting about almost nothing", rep.RowsChecked, minStagedMirrorRows)
	}
	if rep.EnterpriseFiles < minStagedMirrorEnterpriseFiles {
		t.Fatalf("only %d enterprise-only file(s) checked (floor %d); either the tree lost its "+
			"enterprise source or SourceEdition stopped recognising it",
			rep.EnterpriseFiles, minStagedMirrorEnterpriseFiles)
	}
	t.Logf("checked %d enterprise-classified rows: %d enterprise-only files absent from the "+
		"staged copy, %d community twins present", rep.RowsChecked, rep.EnterpriseFiles, rep.TwinFiles)
}

// TestTheStagedMirrorCheckCanFail is the boundary's proof, and it needs no
// staging: it builds a synthetic staged copy holding only the community twins of
// the enterprise-classified rows, which is what a CORRECT sync produces for
// those paths, and then breaks it in each direction.
//
// A guard that has only ever been observed passing is a comment. This runs on
// every pull request, where the env-driven test above skips.
func TestTheStagedMirrorCheckCanFail(t *testing.T) {
	root := repoRoot(t)
	if TreeIsCommunityMirror(root) {
		t.Skip("community mirror checkout: the enterprise halves needed to build the fixture " +
			"are stripped here")
	}

	// The fixture: every community file of every enterprise-classified row, and
	// no enterprise file. Built from the real registry and the real tree, so it
	// cannot drift from what the check reads.
	staged := t.TempDir()
	var twins, enterprise []string
	for _, e := range Load().Entries {
		if e.Classification != ClassEnterpriseImplementation && e.Classification != ClassEnterpriseProtocol {
			continue
		}
		for _, impl := range e.Implementation {
			files, err := goFilesUnder(root, impl)
			if err != nil {
				t.Fatalf("%s: %v", e.ID, err)
			}
			for _, f := range files {
				ed, err := SourceEdition(root, f)
				if err != nil {
					t.Fatalf("%s: %v", e.ID, err)
				}
				if ed == "enterprise" {
					enterprise = append(enterprise, f)
					continue
				}
				twins = append(twins, f)
				dst := filepath.Join(staged, f)
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dst, []byte("package fixture\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if len(twins) == 0 || len(enterprise) == 0 {
		t.Fatalf("fixture is degenerate: %d twin(s), %d enterprise file(s). Both must be "+
			"non-empty or the cases below cannot distinguish anything", len(twins), len(enterprise))
	}

	// 1. The correct shape passes.
	rep, err := checkStagedMirror(root, staged)
	if err != nil {
		t.Fatalf("clean fixture: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("a correctly staged fixture produced %d finding(s); the check reds on correct "+
			"behaviour: %v", len(rep.Findings), rep.Findings)
	}

	// 2. A LEAK is caught and NAMED. The planted file is enterprise by build tag,
	// which is how 142 of the 237 are held - an rsync-level mutant cannot reach
	// that half at all.
	leaked := enterprise[0]
	dst := filepath.Join(staged, leaked)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("package leaked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = checkStagedMirror(root, staged)
	if err != nil {
		t.Fatalf("leak fixture: %v", err)
	}
	if n := countFindings(rep.Findings, "LEAK: "+leaked); n != 1 {
		t.Errorf("planting %s produced %d LEAK finding(s) naming it, want 1. Findings: %v",
			leaked, n, rep.Findings)
	}
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}

	// 3. An OVER-STRIP is caught and NAMED.
	twin := twins[0]
	if err := os.Remove(filepath.Join(staged, twin)); err != nil {
		t.Fatal(err)
	}
	rep, err = checkStagedMirror(root, staged)
	if err != nil {
		t.Fatalf("over-strip fixture: %v", err)
	}
	if n := countFindings(rep.Findings, "OVER-STRIPPED: "+twin); n != 1 {
		t.Errorf("removing the twin %s produced %d OVER-STRIPPED finding(s) naming it, want 1. "+
			"Findings: %v", twin, n, rep.Findings)
	}
}

func countFindings(findings []string, prefix string) int {
	var n int
	for _, f := range findings {
		if strings.HasPrefix(f, prefix) {
			n++
		}
	}
	return n
}
