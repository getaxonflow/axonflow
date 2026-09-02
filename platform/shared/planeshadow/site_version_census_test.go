// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryObservationSiteStampsItsVersion is the protection behind
// Observation.SiteVersion (#3564 round 2).
//
// # WHY A TEST AND NOT A REFUSAL
//
// The other two reset stamps are computed inside this package and cannot be
// omitted. SiteVersion cannot be: go:embed reaches only inside a package
// directory, so the digest of an observation site has to be computed by the
// site's own package and handed over as data. That leaves exactly the shape a
// struct field always leaves, which is a field a new call site forgets.
//
// Refusing an observation with no SiteVersion was the obvious alternative and
// is the wrong trade. An unstamped site is a COVERAGE gap in the reset rule,
// not a corrupt comparison: the record is still a true statement about the
// migration, and dropping it would cost a plane its denominator to punish a
// missing digest. So the observation is kept, and the gap is closed here, on
// the PR that opens it.
//
// # WHY THE AST AND NOT A GREP
//
// A regex over `SiteVersion:` is beaten by the change that matters most - a
// NEW call site that never had the field - because the absence of a line is
// not something a line-matching scan can see at a particular place. The walk
// below finds every composite literal of this package's Observation type in
// the tree and checks the keys IT has, so a new site fails on the PR that adds
// it.
func TestEveryObservationSiteStampsItsVersion(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}

	sites, filesParsed := observationLiteralSites(t, root)

	// ANTI-VACUITY, AND THE FLOOR IS THREE, NOT TWO.
	//
	// A scan that stopped matching - a renamed package alias, a walk rooted at
	// the wrong directory - finds zero literals and reports every site as
	// compliant, which is the failure this floor exists to catch.
	//
	// The number is the count of EVALUATOR ENTRY POINTS, not of substrates, and
	// the difference is a whole third of the coverage. The twelve planes reach
	// nineteen call sites but only three evaluators:
	//
	//	shared/policy   UnifiedPolicyEngine        static substrate,  8 planes
	//	orchestrator    DatabaseDynamicPolicyEngine dynamic substrate, 4 planes
	//	agent           TierAwarePolicyEngine       proxy_tier
	//
	// proxy_tier is NOT a third substrate - it reads static_policies - but it is
	// a third EVALUATOR: it resolves through GetEffective, reads
	// static_policies.action, and never touches the shared engine, which is why
	// it needs an observation site of its own. A floor of two would let that
	// site disappear and still pass, and it is the site with the fewest readers.
	if filesParsed == 0 {
		t.Fatalf("the scan parsed no files under %s; it is reporting about itself, not about the tree", root)
	}
	if len(sites) < 3 {
		t.Fatalf("found %d planeshadow.Observation literal(s) outside this package; the THREE evaluator entry points each have one, so a smaller number means the scan stopped matching or a site was removed (parsed %d files):\n  %v",
			len(sites), filesParsed, sortedSiteNames(sites))
	}

	// AND THE THREE ARE NAMED, so a loss says WHICH rather than that a count
	// fell. A count tells an operator the coverage shrank; the name tells them
	// which evaluator stopped contributing to the window, which is the question
	// they will actually have.
	for pkg, why := range map[string]string{
		"platform/shared/policy/": "the static substrate's evaluator - eight of the twelve planes",
		"platform/orchestrator/":  "the dynamic substrate's evaluator - four planes",
		"platform/agent/":         "the tier engine - proxy_tier, the only plane that reads static_policies.action",
	} {
		found := false
		for site := range sites {
			if strings.HasPrefix(site, pkg) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no planeshadow.Observation literal under %s (%s).\n"+
				"That evaluator contributes NOTHING to the window, and gate 18 is stated per\n"+
				"plane - so the planes it serves have no evidence at all while the others read\n"+
				"healthy. Sites found: %v", pkg, why, sortedSiteNames(sites))
		}
	}

	var unstamped []string
	for site, stamped := range sites {
		if !stamped {
			unstamped = append(unstamped, site)
		}
	}
	sort.Strings(unstamped)
	if len(unstamped) > 0 {
		t.Fatalf("these observation sites build a planeshadow.Observation without a SiteVersion: %v\n"+
			"A site's own changes - which row facts it reports, how it attributes a phase, whether a capped\n"+
			"redaction is marked shadowed - move what BOTH sides of the diff see while every digest computed\n"+
			"inside planeshadow stays byte-identical. Without the stamp that change is an ADR-065 gate-18\n"+
			"window reset nothing observed, and the window on either side of it reads as one longer window.\n"+
			"Add a `//go:embed <this file>` digest to the site's package and pass it as SiteVersion.",
			unstamped)
	}
}

// TestTheSiteVersionCensusSeesAnUnstampedLiteral is the census's own survivor.
//
// A census that cannot FAIL proves nothing about the tree it passed over, and
// the failure mode is silent in the reassuring direction. The input is planted
// IN PROCESS rather than written to disk: a `go test -overlay` mutant is
// invisible to a scan that reads files itself, so the only way to exercise
// this scanner's judgement is to hand it a parsed file directly.
func TestTheSiteVersionCensusSeesAnUnstampedLiteral(t *testing.T) {
	const stamped = `package p
import "axonflow/platform/shared/planeshadow"
func good() {
	planeshadow.Observe(nil, planeshadow.Observation{Plane: "decision", SiteVersion: "abc"})
}
`
	const bare = `package p
import "axonflow/platform/shared/planeshadow"
func bad() {
	planeshadow.Observe(nil, planeshadow.Observation{Plane: "decision"})
}
`
	if got := siteVersionKeysIn(t, stamped); len(got) != 1 || !got["p.go::good"] {
		t.Fatalf("the scanner did not see a STAMPED literal as stamped: %v", got)
	}
	if got := siteVersionKeysIn(t, bare); len(got) != 1 || got["p.go::bad"] {
		t.Fatalf("the scanner reported an UNSTAMPED literal as stamped, so a real one would pass this census: %v", got)
	}
}

// sortedSiteNames renders the discovered sites for a failure message.
func sortedSiteNames(sites map[string]bool) []string {
	out := make([]string, 0, len(sites))
	for s := range sites {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// siteVersionKeysIn parses one in-memory file and returns site -> stamped.
func siteVersionKeysIn(t *testing.T, src string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the planted input: %v", err)
	}
	out := map[string]bool{}
	collectObservationLiterals(f, "p.go", out)
	return out
}

// observationLiteralSites walks the tree and returns "<file>::<func>" ->
// whether that literal set SiteVersion, plus the number of files parsed.
func observationLiteralSites(t *testing.T, root string) (map[string]bool, int) {
	t.Helper()
	sites := map[string]bool{}
	parsed := 0

	// The two binaries plus the shared tree. ee/platform is included because an
	// enterprise-only plane could grow its own site there; its absence on the
	// community mirror is the mirror being the mirror, and the Stat guard below
	// treats it as such rather than as a finding.
	for _, dir := range []string{"platform/agent", "platform/orchestrator", "platform/shared", "ee/platform"} {
		abs := filepath.Join(root, dir)
		if _, err := os.Stat(abs); err != nil {
			continue
		}
		err := filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				// Parseability is the build's business. Failing here would
				// report an unrelated syntax error somewhere in the tree as a
				// missing version stamp.
				return nil
			}
			parsed++
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			collectObservationLiterals(f, rel, sites)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}
	return sites, parsed
}

// collectObservationLiterals records every planeshadow.Observation composite
// literal in f, keyed by "<rel>::<enclosing func>", with the value reporting
// whether it set SiteVersion.
func collectObservationLiterals(f *ast.File, rel string, out map[string]bool) {
	// The package may be imported under an alias, so the selector's package
	// name is resolved from THIS file's import list rather than assumed to be
	// "planeshadow". An alias is exactly how a site would slip past a scan
	// that hard-coded the name.
	pkgNames := map[string]bool{}
	for _, imp := range f.Imports {
		if imp.Path == nil || strings.Trim(imp.Path.Value, `"`) != "axonflow/platform/shared/planeshadow" {
			continue
		}
		if imp.Name != nil {
			pkgNames[imp.Name.Name] = true
		} else {
			pkgNames["planeshadow"] = true
		}
	}
	if len(pkgNames) == 0 {
		return
	}

	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		site := rel + "::" + fd.Name.Name
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "Observation" {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || !pkgNames[ident.Name] {
				return true
			}
			stamped := false
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "SiteVersion" {
					stamped = true
				}
			}
			// CONJUNCTION rather than assignment: a function containing two
			// literals, one stamped and one not, must report as UNSTAMPED.
			// Overwriting would let the second literal's answer erase the
			// first's, and the compliant one is the likelier to come second.
			if prev, seen := out[site]; seen {
				out[site] = prev && stamped
			} else {
				out[site] = stamped
			}
			return true
		})
	}
}
