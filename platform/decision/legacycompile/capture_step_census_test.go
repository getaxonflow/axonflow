// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// captureEnv is the variable every real-capture test reads.
const captureEnv = "AXONFLOW_LEGACY_CAPTURE_DIR"

// captureTestsOutsideTheStep classifies every test that reaches a read of
// captureEnv and is NOT run by test.yml's real-capture step, with the reason.
// TestEveryCaptureBackedTestIsRunByTheCaptureStep holds this table equal to
// the derived set in both directions, so a new capture test anywhere in the
// repository fails until somebody decides which kind it is.
var captureTestsOutsideTheStep = map[string]string{
	"platform/shared/policy TestDetectorCensusMatchesTheMigratedDatabase": "detectorCaptureDir PRODUCES a capture under TEST_PG_INTEGRATION=1, " +
		"which test.yml's 'Test platform/ - enterprise tag + real-Postgres integration' step sets for every package in the platform module " +
		"but compatmutation; that lane does not run on pull_request",
	"platform/shared/policy TestSupersessionLedgerIsCompleteAndHonest": "detectorCaptureDir PRODUCES a capture under TEST_PG_INTEGRATION=1, " +
		"which the same Real-PG platform step sets; that lane does not run on pull_request",
	"platform/shared/policy TestGenerateDetectorCensus": "a regeneration tool: it also requires AXONFLOW_DETECTOR_CENSUS_UPDATE=1 and REWRITES " +
		"detectors_census.tsv, so running it in CI would change the file it exists to produce rather than verify it",
}

// TestEveryCaptureBackedTestIsRunByTheCaptureStep holds every test that needs a
// real capture to a place that runs it, derived from the code rather than
// listed (#4064).
//
// A test that needs a capture SKIPS without one, so an unrun capture test is
// green on every CI job while verifying nothing. Until #4064 four were in that
// state, and three hand-rolled sweeps of the population gave three different
// answers. Three of the four reach the variable through captureDirOrSkip, and
// one reads it directly, which a sweep keyed on the helper's name could not see.
// So this census keys on what a test DOES, across the whole repository.
//
// A function READS the capture when it calls os.Getenv with the variable's
// name, spelled as a literal or as a package-level constant holding it. It has
// a FALLBACK when the same function also calls os.Getenv("TEST_PG_INTEGRATION"),
// which is how a test that produces its own capture is told from one that must
// be handed one. A Test function needs a capture when it reaches such a
// function through calls to package-level functions. Every package in the
// repository whose source mentions the variable is parsed whole.
//
// THE TWO RULES:
//   - A capture-only test under platform/decision, which is the module the
//     capture step runs in, must be named by one of that step's
//     `run_real <package> <Test>` lines, and every such line must name one.
//   - Every other capture-reaching test must be classified in
//     captureTestsOutsideTheStep with its reason.
//
// WHAT IT DOES NOT FOLLOW, stated rather than assumed:
//   - It follows no calls through method values, function variables or other
//     packages.
//   - It refuses the reads it cannot model instead of passing over them. The
//     name handed to os.LookupEnv or syscall.Getenv fails the census, and so
//     does a non-test function that reads the capture with no test reaching it.
func TestEveryCaptureBackedTestIsRunByTheCaptureStep(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	if onCommunityMirror(repoRoot) {
		t.Skip("community mirror tree: the sync excludes .github/workflows/test.yml and scripts/legacy-policy-capture.sh, " +
			"so no real-capture step exists here to hold, and every capture-backed test skips on this tree by design. " +
			"This census runs on the enterprise tree, where a missing test.yml is fatal.")
	}
	tests := captureBackedTests(t, repoRoot)
	named := captureStepRunReal(t, filepath.Join(repoRoot, ".github", "workflows", "test.yml"))

	inStep, outside := map[string]bool{}, map[string]bool{}
	for key, onlyCapture := range tests {
		if onlyCapture && strings.HasPrefix(key, "platform/decision/") {
			inStep[key] = true
		} else {
			outside[key] = true
		}
	}
	if len(inStep) == 0 || len(named) == 0 {
		t.Fatalf("derived %d capture-only test(s) under platform/decision and parsed %d run_real line(s); one side is empty, so this census would compare nothing",
			len(inStep), len(named))
	}

	disagree := func(want, have map[string]bool) []string {
		var out []string
		for key := range want {
			if !have[key] {
				out = append(out, key)
			}
		}
		sort.Strings(out)
		return out
	}
	if unnamed := disagree(inStep, named); len(unnamed) > 0 {
		t.Errorf("%d test(s) need a capture and are not run by test.yml's real-capture step, so they SKIP on every CI job: %v\n"+
			"add `run_real <package> <Test>` for each to that step", len(unnamed), unnamed)
	}
	if stale := disagree(named, inStep); len(stale) > 0 {
		t.Errorf("%d run_real line(s) in test.yml's real-capture step name a test that does not exist or does not need a capture: %v",
			len(stale), stale)
	}

	classified := map[string]bool{}
	for key, reason := range captureTestsOutsideTheStep {
		classified[key] = true
		if strings.TrimSpace(reason) == "" {
			t.Errorf("captureTestsOutsideTheStep[%q] carries no reason; an unexplained classification is an exemption nobody can review", key)
		}
	}
	if unclassified := disagree(outside, classified); len(unclassified) > 0 {
		t.Errorf("%d test(s) reach a read of %s outside the capture step and are not classified in captureTestsOutsideTheStep: %v\n"+
			"say where each runs, or why it must not", len(unclassified), captureEnv, unclassified)
	}
	if staleClass := disagree(classified, outside); len(staleClass) > 0 {
		t.Errorf("%d captureTestsOutsideTheStep entr(ies) name a test that does not exist or no longer reaches the capture: %v",
			len(staleClass), staleClass)
	}
	t.Logf("capture-backed tests: %d run by the capture step, %d classified outside it", len(inStep), len(outside))
}

// captureBackedTests returns, for every Test function under root that reaches
// a read of captureEnv, "<repo-relative package dir> <Test>" mapped to whether
// every read it reaches is capture-only (no TEST_PG_INTEGRATION fallback).
func captureBackedTests(t *testing.T, root string) map[string]bool {
	t.Helper()
	dirs := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "node_modules" || name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), captureEnv) {
			dirs[filepath.Dir(path)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	out := map[string]bool{}
	for dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		var parsed []*ast.File
		for _, f := range files {
			file, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			parsed = append(parsed, file)
		}

		envConsts := map[string]bool{}
		for _, file := range parsed {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if i < len(vs.Values) && stringLiteralIs(vs.Values[i], captureEnv) {
							envConsts[name.Name] = true
						}
					}
				}
			}
		}
		namesTheEnv := func(e ast.Expr) bool {
			if stringLiteralIs(e, captureEnv) {
				return true
			}
			id, ok := e.(*ast.Ident)
			return ok && envConsts[id.Name]
		}

		calls := map[string]map[string]bool{}
		reads := map[string]bool{}
		fallback := map[string]bool{}
		inTestFile := map[string]bool{}
		for _, file := range parsed {
			isTest := strings.HasSuffix(fset.Position(file.Package).Filename, "_test.go")
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Body == nil {
					continue
				}
				name := fn.Name.Name
				inTestFile[name] = isTest
				if calls[name] == nil {
					calls[name] = map[string]bool{}
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch fun := call.Fun.(type) {
					case *ast.Ident:
						calls[name][fun.Name] = true
					case *ast.SelectorExpr:
						pkg, ok := fun.X.(*ast.Ident)
						if !ok || len(call.Args) != 1 {
							return true
						}
						switch {
						case pkg.Name == "os" && fun.Sel.Name == "Getenv" && namesTheEnv(call.Args[0]):
							reads[name] = true
						case pkg.Name == "os" && fun.Sel.Name == "Getenv" && stringLiteralIs(call.Args[0], "TEST_PG_INTEGRATION"):
							fallback[name] = true
						case namesTheEnv(call.Args[0]) && ((pkg.Name == "os" && fun.Sel.Name == "LookupEnv") || (pkg.Name == "syscall" && fun.Sel.Name == "Getenv")):
							t.Errorf("%s: %s.%s reads %s in a shape this census does not model; read it with os.Getenv so the tests behind it are derived",
								fset.Position(call.Pos()), pkg.Name, fun.Sel.Name, captureEnv)
						}
					}
					return true
				})
			}
		}

		rel, err := filepath.Rel(root, dir)
		if err != nil {
			t.Fatal(err)
		}
		pkg := filepath.ToSlash(rel)
		reachedReaders := map[string]bool{}
		for name := range calls {
			if !strings.HasPrefix(name, "Test") || !inTestFile[name] {
				continue
			}
			onlyCapture, any := true, false
			for reader := range reads {
				if !reachesFrom(calls, name, reader) {
					continue
				}
				any = true
				reachedReaders[reader] = true
				if fallback[reader] {
					onlyCapture = false
				}
			}
			if any {
				out[pkg+" "+name] = onlyCapture
			}
		}
		for reader := range reads {
			if !strings.HasPrefix(reader, "Test") && !reachedReaders[reader] {
				t.Errorf("%s %s reads %s and no Test function reaches it; either this census's call graph is missing an edge, or the helper is dead",
					pkg, reader, captureEnv)
			}
		}
	}
	return out
}

// onCommunityMirror reports whether the tree under root is the published
// community mirror rather than the enterprise repository.
//
// It is the same derivation as platform/shared/policy's isCommunityMirrorTree
// (#3807), spelled again here because that one is in another module's test
// file and cannot be imported. The signal is the sync's own outcome:
// .github/workflows/lint.yml is synced and .github/workflows/sync-community-repo.yml
// is excluded, so "lint present, sync absent" is true only on the mirror. On
// the enterprise tree the sync workflow exists, so this census can never skip
// there.
func onCommunityMirror(root string) bool {
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows", "lint.yml")); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(root, ".github", "workflows", "sync-community-repo.yml"))
	return os.IsNotExist(err)
}

func reachesFrom(calls map[string]map[string]bool, from, to string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(n string) bool {
		if n == to {
			return true
		}
		if seen[n] {
			return false
		}
		seen[n] = true
		for callee := range calls[n] {
			if walk(callee) {
				return true
			}
		}
		return false
	}
	return walk(from)
}

func stringLiteralIs(e ast.Expr, want string) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	return err == nil && s == want
}

// runRealLine matches one `run_real <package> <Test>` call in the capture step.
var runRealLine = regexp.MustCompile(`^\s*run_real\s+(\S+)\s+(Test[A-Za-z0-9_]+)\s*$`)

// captureStepRunReal returns "<repo-relative package dir> <Test>" for every
// run_real line in test.yml, and fails unless exactly one step defines
// run_real. That step runs from platform/decision, so its package arguments
// are relative to that directory.
func captureStepRunReal(t *testing.T, workflow string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatalf("reading %s: %v", workflow, err)
	}
	if n := strings.Count(string(b), "run_real() {"); n != 1 {
		t.Fatalf("%s defines run_real %d time(s); this census reads exactly one real-capture step", workflow, n)
	}
	named := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if m := runRealLine.FindStringSubmatch(line); m != nil {
			pkg := strings.TrimSuffix(strings.TrimPrefix(m[1], "./"), "/")
			named["platform/decision/"+pkg+" "+m[2]] = true
		}
	}
	return named
}
