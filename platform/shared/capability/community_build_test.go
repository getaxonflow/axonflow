// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goListPkg is the subset of `go list -json` this census reads.
//
// The shape and runGoList below are a deliberate near-copy of
// platform/shared/identity/principal_comparison_scan_test.go's, which is the
// tree's established way to ask the COMPILER what a build configuration
// admits. They are copied rather than imported because that one lives in
// `package identity`'s test files and this census is in `package capability`;
// a test helper is not importable across packages. The duplication is stated
// here rather than left for a reader to find: if that one gains a flag this
// needs, copy it too rather than letting the two drift into different
// questions asked the same way.
type goListPkg struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Error      *struct{ Err string }
}

// noConfigurationForTags is what `go list` says about a package whose every
// file is behind a build constraint the current tag set does not satisfy.
//
// It is NOT an error for this census. A package all of whose files are
// enterprise-only - platform/agent/billing is one, nine files, every one
// tagged - has no community configuration BY CONSTRUCTION, and that is the
// boundary working rather than a hole in it.
const noConfigurationForTags = "build constraints exclude all Go files"

// runGoList runs `go list -e -json` in dir under one tag set.
//
// -e so a package with no configuration under these tags comes back as a
// RECORD carrying .Error rather than as a non-zero exit with nothing on
// stdout; the caller can then tell that case from a real failure.
//
// GOFLAGS is cleared so an ambient -mod or -tags from the parent `go test` run
// cannot change what the child resolves. A census that inherited -tags
// enterprise from its own invocation would report the enterprise file set as
// the community one and pass.
func runGoList(dir, tags string, args ...string) ([]goListPkg, error) {
	full := []string{"list", "-e", "-json"}
	if tags != "" {
		full = append(full, "-tags", tags)
	}
	full = append(full, args...)
	cmd := exec.Command("go", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s in %s: %v\n%s", strings.Join(full, " "), dir, err, errb.String())
	}
	dec := json.NewDecoder(&out)
	var pkgs []goListPkg
	for {
		var p goListPkg
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decoding go list output from %s: %w", dir, err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// eeIsASeparateModule is the one configuration this census cannot read, with
// its reason, following the convention in principal_comparison_census_test.go:
// a configuration skipped silently is a configuration reported as clean.
//
// MEASURED, not assumed: ee/go.mod exists, and from the platform module
// `go list ./../ee/platform/proofcustody/` answers "directory
// ../ee/platform/proofcustody outside main module or its selected
// dependencies".
const eeIsASeparateModule = "ee/ is a separate Go module; the platform module cannot list it"

// TestTheCompilerAgreesWithTheRegistryAboutEnterpriseImplementation asks the
// COMPILER, rather than a regex, whether each file the registry names is in the
// build it is supposed to be in.
//
// # WHAT IT ASSERTS, AND WHY EACH DIRECTION CAN FAIL
//
//  1. Every file of an enterprise-classified row that SourceEdition calls
//     enterprise must be COMPILED BY the `enterprise` build. It fails when a
//     file is deleted or renamed while the registry still names it, and when a
//     constraint excludes it from the very build it exists for.
//
//  2. Every file of such a row that SourceEdition calls community must be
//     COMPILED BY the untagged build. This is the one thing here that no
//     registry-declaration guard can see: SourceEdition decides by matching
//     `^//go:build enterprise`, and the compiler evaluates the whole
//     constraint expression. A file carrying `//go:build !enterprise && ignore`
//     is community to the regex and absent from every build to the compiler,
//     and this direction is what notices.
//
// # WHAT IT DELIBERATELY DOES NOT ASSERT, AND WHICH GUARD OWNS THAT
//
// It does NOT assert that an enterprise-only file is ABSENT from the untagged
// build. That assertion cannot fail, and the mutant proves it rather than the
// reasoning: strip `//go:build enterprise` from
// platform/agent/circuitbreaker/handler.go and SourceEdition returns
// "community" for it, because SourceEdition reads the same line the mutant
// removed. The expectation and the observation move together, so the check
// stays green.
//
// That class IS guarded, by TestEditionFactsMatchTheTree in registry_test.go,
// whose expectation comes from somewhere the mutant cannot reach - the
// registry's DECLARED build_tag. Under the same mutant it reds with:
//
//	circuit.breaker declares build_tag "split"; its implementation files say
//	"none". The tree is the authority here - a row cannot edit what a build
//	constraint says
//
// The general rule is worth stating where the next author will read it: a
// guard whose expected value is derived from the signal the mutant perturbs is
// vacuously unkillable, however careful the assertion is. A per-file edition
// declaration independent of the build tag would make the absent direction
// checkable; there is none today, which is filed separately.
//
// # WHY PER FILE, AND WHY THE FILE'S OWN DIRECTORY
//
// platform/agent alone carries six of these rows, so a package-level assertion
// there would be about hundreds of unrelated files. And a row's implementation
// path is not always a package: compliance.reports names
// platform/orchestrator/compliancereport, whose renderer/ SUBPACKAGE holds six
// more files. goFilesUnder walks recursively; `go list` on one directory does
// not. The package listed is therefore the one holding the FILE.
func TestTheCompilerAgreesWithTheRegistryAboutEnterpriseImplementation(t *testing.T) {
	root := repoRoot(t)
	if TreeIsCommunityMirror(root) {
		t.Skip("community mirror checkout: the enterprise halves are stripped, so `go list -tags " +
			"enterprise` cannot resolve the platform module at all (fourteen packages left with " +
			"\"build constraints exclude all Go files\"). This census is about the ENTERPRISE " +
			"tree's two configurations")
	}
	platform := filepath.Join(root, "platform")

	type dirKey struct{ dir, tags string }
	type listing struct {
		files    map[string]bool
		noConfig bool
		failure  string
	}
	cache := map[dirKey]listing{}
	filesOf := func(dir, tags string) listing {
		k := dirKey{dir, tags}
		if l, ok := cache[k]; ok {
			return l
		}
		l := listing{files: map[string]bool{}}
		pkgs, err := runGoList(platform, tags, "./"+strings.TrimPrefix(dir, "platform/"))
		if err != nil {
			l.failure = err.Error()
			cache[k] = l
			return l
		}
		for _, p := range pkgs {
			if p.Error != nil {
				if strings.Contains(p.Error.Err, noConfigurationForTags) {
					l.noConfig = true
				} else {
					l.failure = p.Error.Err
				}
			}
			for _, f := range p.GoFiles {
				l.files[f] = true
			}
		}
		cache[k] = l
		return l
	}

	var rowsChecked, enterpriseChecked, twinsChecked, eeSkipped int

	for _, e := range Load().Entries {
		if e.Classification != ClassEnterpriseImplementation && e.Classification != ClassEnterpriseProtocol {
			continue
		}
		var rowCounted bool
		for _, impl := range e.Implementation {
			files, err := goFilesUnder(root, impl)
			if err != nil {
				t.Errorf("%s: %v", e.ID, err)
				continue
			}
			for _, f := range files {
				if strings.HasPrefix(f, "ee/") {
					eeSkipped++
					continue
				}
				ed, err := SourceEdition(root, f)
				if err != nil {
					t.Errorf("%s: %v", e.ID, err)
					continue
				}
				dir := filepath.Dir(f)
				base := filepath.Base(f)

				if ed == "enterprise" {
					tagged := filesOf(dir, "enterprise")
					if tagged.failure != "" {
						t.Errorf("%s: %s could not be listed under `enterprise` (%s), so this "+
							"census says nothing about %s", e.ID, dir, tagged.failure, f)
						continue
					}
					enterpriseChecked++
					rowCounted = true
					if tagged.noConfig {
						t.Errorf("%s: the `enterprise` build of %s has no configuration at all, so "+
							"%s is in no binary", e.ID, dir, f)
					} else if !tagged.files[base] {
						t.Errorf("%s: %s is named by the registry but the `enterprise` build of %s "+
							"does not compile it; the row names a file the enterprise binary does "+
							"not have", e.ID, f, dir)
					}
					continue
				}

				untagged := filesOf(dir, "")
				if untagged.failure != "" {
					t.Errorf("%s: %s could not be listed untagged (%s), so this census says nothing "+
						"about %s", e.ID, dir, untagged.failure, f)
					continue
				}
				twinsChecked++
				rowCounted = true
				if untagged.noConfig {
					t.Errorf("%s: %s reads as community source, but %s has NO untagged "+
						"configuration; the community half of this capability is in no build. A "+
						"build constraint the classifier's regex does not evaluate is the usual "+
						"cause", e.ID, f, dir)
				} else if !untagged.files[base] {
					t.Errorf("%s: %s reads as community source but the UNTAGGED build of %s does "+
						"not compile it. SourceEdition matches `^//go:build enterprise` only; the "+
						"compiler evaluates the whole constraint, and this is where the two "+
						"disagree", e.ID, f, dir)
				}
			}
		}
		if rowCounted {
			rowsChecked++
		}
	}

	if eeSkipped == 0 {
		t.Errorf("no enterprise-classified row names a file under ee/, so the declared exemption "+
			"(%q) is stale and must be removed", eeIsASeparateModule)
	} else {
		t.Logf("not listed: %d file(s) under ee/ - %s", eeSkipped, eeIsASeparateModule)
	}

	// ANTI-VACUITY FLOORS. Bounds well under the measured truth (20 rows, 142
	// enterprise-only files outside ee/, 20 twins): a pinned count goes stale
	// the day a file moves, and a floor beneath the true count still catches
	// the population collapsing.
	const (
		minRows       = 15
		minEnterprise = 100
		minTwins      = 10
	)
	if rowsChecked < minRows {
		t.Fatalf("only %d row(s) were checked (floor %d); the population collapsed", rowsChecked, minRows)
	}
	if enterpriseChecked < minEnterprise {
		t.Fatalf("only %d enterprise-only file(s) were checked (floor %d)", enterpriseChecked, minEnterprise)
	}
	if twinsChecked < minTwins {
		t.Fatalf("only %d community twin(s) were checked (floor %d); the direction that catches a "+
			"constraint the classifier cannot read is asserting about almost nothing",
			twinsChecked, minTwins)
	}
	t.Logf("checked %d rows: %d enterprise-only files compiled by the `enterprise` build, %d "+
		"community twins compiled by the untagged build", rowsChecked, enterpriseChecked, twinsChecked)
}

// TestTheCommunityBuildCensusReproducesItsBaseline states the measured shape of
// the boundary as numbers, through the census's own instrument.
//
// The counts are asserted as a RATIO rather than pinned: each of these packages
// must hold strictly fewer files untagged than under `enterprise`, because that
// difference is the enterprise implementation. Pinning 1-vs-24 would go stale on
// any ordinary edit; asserting the inequality plus a non-empty community half
// stays true and still fails the moment a package stops splitting - which is
// what happens if its enterprise files are deleted or lose their constraint
// wholesale.
func TestTheCommunityBuildCensusReproducesItsBaseline(t *testing.T) {
	root := repoRoot(t)
	if TreeIsCommunityMirror(root) {
		t.Skip("community mirror checkout: only one configuration exists here")
	}
	platform := filepath.Join(root, "platform")
	dirs := []string{
		"shared/requirements/reservation",
		"shared/requirements/proof",
		"agent/hitl",
		"agent/circuitbreaker",
		"orchestrator/rbi",
		"orchestrator/compliancereport",
		"agent/node_enforcement",
	}
	var split int
	for _, d := range dirs {
		u, err := runGoList(platform, "", "./"+d)
		if err != nil {
			t.Errorf("%s untagged: %v", d, err)
			continue
		}
		e, err := runGoList(platform, "enterprise", "./"+d)
		if err != nil {
			t.Errorf("%s enterprise: %v", d, err)
			continue
		}
		un, en := countGoFiles(u), countGoFiles(e)
		t.Logf("  %-38s untagged=%d enterprise=%d", d, un, en)
		if un == 0 {
			t.Errorf("%s compiles NO file in the untagged build; a community build cannot import it "+
				"at all, which is a different boundary from the one this row declares", d)
		}
		if en <= un {
			t.Errorf("%s compiles %d file(s) untagged and %d under `enterprise`; this package no "+
				"longer splits, so the enterprise implementation is either gone or no longer gated", d, un, en)
		} else {
			split++
		}
	}
	if split != len(dirs) {
		t.Errorf("only %d of %d baseline packages still split by build tag", split, len(dirs))
	}
}

func countGoFiles(pkgs []goListPkg) int {
	var n int
	for _, p := range pkgs {
		n += len(p.GoFiles)
	}
	return n
}
