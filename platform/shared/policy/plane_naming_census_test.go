package policy

import (
	"io/fs"

	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryPolicyCallSiteNamesItsPlane is the protection behind
// EvalOptions.Plane and the two variadic shadowPlane parameters (#3564).
//
// # WHY A TEST AND NOT THE COMPILER
//
// The plane is DATA the evaluators cannot derive: one entry point serves eight
// planes, and one helper (evaluateInputPolicies) serves two. It therefore has
// to arrive from the caller, and there are exactly two shapes for that - a
// required parameter, which the compiler enforces, and a struct field or
// variadic, which it does not.
//
// TierShadowContext is required, because it had six call sites. EvalOptions
// .Plane and the MCP helpers' shadowPlane are not, because making them
// required would have churned roughly forty existing test call sites for no
// behavioural reason. The protection moves here instead, and it is DERIVED
// from legacy_call_sites.tsv - the same artifact the compiler's plane model is
// pinned to, in both directions - so a new call site fails on the PR that adds
// it rather than on the day someone reads a denominator.
//
// # WHAT A MISSING PLANE COSTS
//
// The observation is refused and counted under `refused`. That is loud, and it
// is the reason the zero value is refused rather than defaulted: a defaulted
// plane would move a denominator an operator reads to decide whether that
// plane may cut over, silently, from a bug.
func TestEveryPolicyCallSiteNamesItsPlane(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	census := readCensusWithPlanes(t, callSiteCensusPath)
	if len(census) == 0 {
		t.Fatalf("%s is empty; an empty census would let this test pass while asserting nothing", callSiteCensusPath)
	}

	// planesNamed maps "<repo-relative file>::<func>" to the planes its body
	// names, and callers maps a callee name to the functions that call it.
	planesNamed, callers, files := scanPlaneNaming(t, root, census)

	// ANTI-VACUITY, DERIVED RATHER THAN CALIBRATED. The scan must have parsed
	// the files the census names and must have found plane references at all;
	// a scanner that silently stopped matching would otherwise report every
	// row as unnamed, which reads as a regression in the tree rather than as a
	// broken test - and, worse, a scanner that matched NOTHING and a census
	// with no rows both produce a green run.
	if len(files) == 0 {
		t.Fatal("no census file was parsed; the scanner is not looking at the tree")
	}
	total := 0
	for _, ps := range planesNamed {
		total += len(ps)
	}
	if total == 0 {
		t.Fatal("no function in any censused file names an enforcement plane; the scanner stopped matching")
	}
	// AND the community rows must still be a real population after the strip.
	// Without this, a sync that started deleting community files too would
	// make this test pass by having nothing left to check.
	community := 0
	for _, row := range census {
		if row.edition == "community" {
			community++
		}
	}
	if community < 2 {
		t.Fatalf("only %d community census row(s); a tree with no community call sites is not a "+
			"tree this test can say anything about", community)
	}

	mirror := treeIsCommunityMirror(root)
	var missing, strippedButPresent []string
	stripped := 0
	for _, row := range census {
		plane, file, fn := row.plane, row.file, row.function
		site := file + "::" + fn
		if planesNamed[site][plane] {
			continue
		}
		if mirror && row.edition == "enterprise" {
			// On the mirror an enterprise-only file is stripped, so it names
			// no plane because it is not there.
			//
			// THE ABSENCE IS CHECKED, NOT ASSUMED. A row labelled enterprise
			// whose file IS present has no excuse: either the label is wrong
			// or the call site moved, and both are findings on the mirror as
			// much as here. This is the arm that stops the edition column
			// becoming a blanket exemption.
			if _, statErr := os.Stat(filepath.Join(root, file)); statErr == nil {
				strippedButPresent = append(strippedButPresent, site+" (plane "+plane+")")
				continue
			}
			stripped++
			continue
		}
		// The function does not name the plane itself. That is legitimate for
		// a SHARED helper - evaluateInputPolicies serves /decide and MCP and
		// takes the plane as a parameter - so the plane must then be named by
		// something that calls it. Checked one level up only: a two-level
		// indirection would mean the plane travels through a function that
		// neither names it nor is named by the census, which is a shape this
		// codebase does not have and should not acquire silently.
		named := false
		for _, caller := range callers[fn] {
			if planesNamed[caller][plane] {
				named = true
				break
			}
		}
		if !named {
			missing = append(missing, site+" (plane "+plane+")")
		}
	}
	sort.Strings(missing)
	sort.Strings(strippedButPresent)
	for _, m := range strippedButPresent {
		t.Errorf("this is a community tree and census row %s is labelled enterprise, yet its file "+
			"IS present and names no plane.\nEither the file is mislabelled enterprise or the "+
			"call site moved. The label is verified in the enterprise tree; fix it there.", m)
	}
	if mirror && stripped > 0 {
		t.Logf("community tree: %d enterprise-only census row(s) are absent, as the sync's build-tag strip makes them", stripped)
	}
	for _, m := range missing {
		t.Errorf("call site %s does not name its enforcement plane, and neither does any caller of it.\n"+
			"Set EvalOptions.Plane (static substrate), OrchestratorRequest.ShadowPlane (dynamic),\n"+
			"TierShadowContext.Plane (proxy tier), or pass the plane to the shared helper.\n"+
			"An observation with no plane is REFUSED and counted, so this plane contributes\n"+
			"nothing to ADR-065 gate 18's window while every other plane reads healthy.", m)
	}

	// THE OTHER DIRECTION. A plane named in production source that the census
	// does not carry means either the census is stale or somebody invented a
	// plane; both make the denominator wrong, in opposite directions.
	censusPlanes := map[string]bool{}
	for _, row := range census {
		censusPlanes[row.plane] = true
	}
	for site, planes := range planesNamed {
		for p := range planes {
			if !censusPlanes[p] {
				t.Errorf("%s names plane %q, which %s does not carry. Either the census is\n"+
					"stale - in which case the compiler's plane model is too, and it is the\n"+
					"gate's denominator - or this is a plane nobody declared.",
					site, p, callSiteCensusPath)
			}
		}
	}
}

// planeCensusRow is one census row WITH its plane.
//
// readCensus (the sibling completeness test's loader) keys on
// (file, evaluator, function) and drops the plane column, because that test is
// about whether the tree and the artifact agree on the CALL SITES. This test is
// about the PLANE each site is attributed to, so it needs the column that one
// discards - and it re-parses rather than widening the shared loader, which
// would change the other test's key shape.
type planeCensusRow struct {
	plane    string
	file     string
	function string
	// edition is what the community sync does to this row's file. It is
	// carried because on the PUBLIC MIRROR an enterprise-only file is absent
	// by construction, and a row whose file is gone must not be reported as a
	// plane that failed to name itself - that would make this test red on
	// every mirror pull request for a file that is exactly where it should be.
	//
	// The column is only allowed to say that because the ENTERPRISE tree,
	// where every censused file exists, verifies it against the file's real
	// build constraint on every run (TestLegacyCallSiteCensusIsComplete's
	// editionMismatch arm). A row labelled community in an enterprise-tagged
	// file would otherwise be an expected absence on the mirror hiding a real
	// one. This test consumes that verification rather than repeating it: one
	// mechanism, checked once.
	edition string
}

// readCensusWithPlanes parses the census keeping the plane column. The header
// is asserted, so a shifted column is a hard failure rather than a value
// landing quietly in the wrong field.
func readCensusWithPlanes(t *testing.T, path string) []planeCensusRow {
	t.Helper()
	src, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(src), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("%s has no data rows", path)
	}
	const wantHeader = "plane\tevaluator\tfile\tfunction\tpasses_action_overrides\tedition"
	if lines[0] != wantHeader {
		t.Fatalf("%s header is %q, want %q", path, lines[0], wantHeader)
	}
	var out []planeCensusRow
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			t.Fatalf("%s: row %q has %d fields, want 6", path, line, len(f))
		}
		out = append(out, planeCensusRow{plane: f[0], file: f[2], function: f[3], edition: f[5]})
	}
	return out
}

// planeConstToID maps a legacycompile.PlaneX identifier to the plane string.
//
// It is derived from plane.go rather than restated, so a renamed constant or a
// changed identifier fails here instead of silently matching nothing - which
// would make every census row report as unnamed and read as a tree regression.
func planeConstToID(t *testing.T, root string) map[string]string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "platform/decision/legacycompile/plane.go"))
	if err != nil {
		t.Fatalf("reading the compiler's plane model: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Plane") || !strings.Contains(line, " Plane = \"") {
			continue
		}
		name, rest, ok := strings.Cut(line, " Plane = \"")
		if !ok {
			continue
		}
		id, _, ok := strings.Cut(rest, "\"")
		if !ok {
			continue
		}
		out[strings.TrimSpace(name)] = id
	}
	if len(out) == 0 {
		t.Fatal("no Plane constants parsed out of plane.go; the extraction, not the tree, is what broke")
	}
	return out
}

// scanPlaneNaming parses every file the census names and reports, per
// function, which planes its body names, plus a callee -> callers index.
func scanPlaneNaming(t *testing.T, root string, census []planeCensusRow) (map[string]map[string]bool, map[string][]string, map[string]bool) {
	t.Helper()
	consts := planeConstToID(t, root)

	// EVERY production Go file under the two binaries' trees, not only the
	// files the census names.
	//
	// The census names the file containing each EVALUATOR call. For a shared
	// helper the plane is named by a CALLER, and that caller lives wherever it
	// lives - /decide's is in decision_handler.go, which the census has no row
	// for because it contains no evaluator call. Scanning only censused files
	// made the decide plane unresolvable and reported it as unwired, which is
	// the false-positive direction; scanning the tree resolves it from the
	// place the plane is actually named.
	files := map[string]bool{}
	for _, row := range census {
		files[row.file] = true
	}
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
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return nil
			}
			files[rel] = true
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}

	planesNamed := map[string]map[string]bool{}
	callers := map[string][]string{}
	parsed := map[string]bool{}

	for rel := range files {
		abs := filepath.Join(root, rel)
		if _, err := os.Stat(abs); err != nil {
			// On the community mirror an enterprise-tagged censused file is
			// absent, which is the mirror being the mirror and not a finding.
			// The edition column is what says which; the sibling census test
			// owns that classification, and duplicating it here would be a
			// second mechanism to keep in step.
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, abs, nil, 0)
		if err != nil {
			// A file this scan cannot parse is not a finding about the plane
			// wiring, and failing on it would make an unrelated syntax error
			// in some other package report as a missing plane. The build is
			// what owns parseability.
			continue
		}
		parsed[rel] = true
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			site := rel + "::" + fd.Name.Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.SelectorExpr:
					// legacycompile.PlaneX
					if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "legacycompile" {
						if id, known := consts[v.Sel.Name]; known {
							if planesNamed[site] == nil {
								planesNamed[site] = map[string]bool{}
							}
							planesNamed[site][id] = true
						}
					}
				case *ast.CallExpr:
					switch fn := v.Fun.(type) {
					case *ast.Ident:
						callers[fn.Name] = append(callers[fn.Name], site)
					case *ast.SelectorExpr:
						callers[fn.Sel.Name] = append(callers[fn.Sel.Name], site)
					}
				}
				return true
			})
		}
	}
	return planesNamed, callers, parsed
}

// TestPlaneNamingCensusCatchesAPlantedOmission is the census's own failing
// input.
//
// It is IN-PROCESS by necessity: this guard reads the tree with os.ReadFile and
// go/parser, and a `go test -overlay` mutant changes what the COMPILER sees and
// not what those return, so no overlay mutant can ever reach it
// ([[feedback_an_overlay_mutant_is_invisible_to_a_source_reading_guard]]). It
// feeds the scanner a synthetic file with the plane removed and requires the
// omission to be reported.
func TestPlaneNamingCensusCatchesAPlantedOmission(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	consts := planeConstToID(t, root)
	if len(consts) < 10 {
		t.Fatalf("only %d plane constants parsed; the extraction is broken and every row would report as unnamed", len(consts))
	}

	// Control: a body that names a plane is detected.
	named := planesInSource(t, `package p
import "axonflow/platform/decision/legacycompile"
func handler() {
	_ = legacycompile.PlaneGatewayRequest
}`, consts)
	if !named["handler"]["gateway_request"] {
		t.Fatal("the scanner did not detect a plane the body plainly names; every census row would report as unnamed")
	}

	// The plant: the same handler with the plane dropped.
	plantless := planesInSource(t, `package p
func handler() {
	_ = 1
}`, consts)
	if len(plantless["handler"]) != 0 {
		t.Fatalf("the scanner reported planes %v for a body that names none; it is matching something other than the constants", plantless["handler"])
	}

	// And a plane the model does not declare must NOT be detected, which is
	// what makes the other-direction arm of the census meaningful.
	invented := planesInSource(t, `package p
import "axonflow/platform/decision/legacycompile"
func handler() {
	_ = legacycompile.PlaneConnectorExecution
}`, consts)
	if len(invented["handler"]) != 0 {
		t.Fatalf("the scanner resolved an undeclared plane constant to %v", invented["handler"])
	}
}

// planesInSource runs the census's own matching over one synthetic file.
func planesInSource(t *testing.T, src string, consts map[string]string) map[string]map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "planted.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the planted source: %v", err)
	}
	out := map[string]map[string]bool{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		out[fd.Name.Name] = map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "legacycompile" {
				return true
			}
			if id, known := consts[sel.Sel.Name]; known {
				out[fd.Name.Name][id] = true
			}
			return true
		})
	}
	return out
}
