// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"
)

// compilerOwnedPathsSource is the file whose const block is the population.
const compilerOwnedPathsSource = "compile.go"

// wellKnownPathConstants reads the const block that declares PrincipalIDPath
// and returns every string constant in it, by name and value.
//
// THE POPULATION IS DERIVED, NOT LISTED. CompilerOwnedPaths() is a hand-written
// slice, and a hand-written slice of well-known things is one entry short the
// day somebody declares a sixth - the reader of the slice then reports a clean
// answer about a path nobody checked. Deriving the population from the
// declaration makes the omission a build failure instead.
//
// It anchors on the CONST BLOCK rather than on a line range or a count: a
// comment sweep moves every line number in this file (#3840) and a count cannot
// see a swap. The block is located by the constant that must be in it.
func wellKnownPathConstants(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, compilerOwnedPathsSource, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", compilerOwnedPathsSource, err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		found := map[string]string{}
		anchored := false
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("unquoting %s = %s: %v", vs.Names[0].Name, lit.Value, err)
			}
			if vs.Names[0].Name == "PrincipalIDPath" {
				anchored = true
			}
			found[vs.Names[0].Name] = val
		}
		if anchored {
			return found
		}
	}
	t.Fatalf("no const block in %s declares PrincipalIDPath; this test cannot name its own population",
		compilerOwnedPathsSource)
	return nil
}

// TestCompilerOwnedPathsCoversEveryWellKnownPath is the completeness direction:
// every well-known path the compiler declares is returned by the enumerator
// another producer consults.
//
// A path missing from the enumerator is worse than an absent enumerator: a
// producer that asks and is told "not owned" maps a second currency onto it
// and gets a clean answer for its trouble.
func TestCompilerOwnedPathsCoversEveryWellKnownPath(t *testing.T) {
	declared := wellKnownPathConstants(t)
	if len(declared) < 5 {
		t.Fatalf("the const block yielded %d string constants; the scan found too few to be reading the "+
			"block this test is about, so nothing below is an assertion", len(declared))
	}

	owned := map[string]bool{}
	for _, p := range CompilerOwnedPaths() {
		if owned[p] {
			t.Errorf("CompilerOwnedPaths() returns %q twice", p)
		}
		owned[p] = true
	}

	var missing []string
	for name, val := range declared {
		if !owned[val] {
			missing = append(missing, name+" = "+strconv.Quote(val))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf(`%d well-known path constant(s) are declared in %s and are NOT returned by CompilerOwnedPaths():

  %v

Add them. A producer outside this package asks CompilerOwnedPaths() whether a
path's currency is decided here; a path the enumerator omits is one it can map
a second meaning onto and be told that is fine.`, len(missing), compilerOwnedPathsSource, missing)
	}
}

// TestCompilerOwnedPathsReturnsNothingUndeclared is the other direction. An
// entry with no declaration is a path this package does not own, and claiming
// it would stop another producer from using a path that is genuinely free.
func TestCompilerOwnedPathsReturnsNothingUndeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, val := range wellKnownPathConstants(t) {
		declared[val] = true
	}
	if len(declared) == 0 {
		t.Fatal("the scan found no declared paths, so this direction asserts nothing")
	}
	for _, p := range CompilerOwnedPaths() {
		if !declared[p] {
			t.Errorf("CompilerOwnedPaths() returns %q, which no constant in %s declares; "+
				"this package does not own it", p, compilerOwnedPathsSource)
		}
	}
}

// TestWellKnownPathScannerFindsAPlantedConstant is the anti-vacuity control.
//
// Both directions above are satisfied by a scanner that finds NOTHING and a
// scanner that finds everything, and only one of those is this one. The
// control drives the same extraction over a source that declares a sixth
// well-known path and requires it to come back.
//
// It parses a STRING rather than editing compile.go, so the mutation is
// present by construction and cannot be the "mutant that never reached its
// target" failure: if the extraction stopped working the planted constant
// would be absent and this fails.
func TestWellKnownPathScannerFindsAPlantedConstant(t *testing.T) {
	const planted = `package pdp

const (
	PrincipalIDPath     = "principal.id"
	PrincipalGroupsPath = "principal.groups"
	PlantedSixthPath    = "principal.planted_sixth"
)
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "planted.go", planted, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing the planted source: %v", err)
	}
	found := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			val, _ := strconv.Unquote(lit.Value)
			found[vs.Names[0].Name] = val
		}
	}
	if got := found["PlantedSixthPath"]; got != "principal.planted_sixth" {
		t.Fatalf("the extraction did not return the planted sixth path (got %q); the two directions above "+
			"are passing against a scanner that cannot see a new constant", got)
	}
	owned := map[string]bool{}
	for _, p := range CompilerOwnedPaths() {
		owned[p] = true
	}
	if owned["principal.planted_sixth"] {
		t.Fatal("CompilerOwnedPaths() returns the planted path, so the completeness direction cannot fail")
	}
}
