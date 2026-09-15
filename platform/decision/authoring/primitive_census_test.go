// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestNoProductionCodeReachesTheRootAgnosticPrimitives holds the boundary
// system_authority.go draws (#4047).
//
// The organization authority is bound on the constructor every transport uses
// (NewAPI / NewAPIWithBackend). The package-level Publish and the NewStore
// constructors stay root-agnostic, because they are the primitives the fixture
// world exercises - and that is safe exactly while no production code calls
// them. A transport that built its store with NewStore would have a store that
// admits a system-root artifact from any key its trust store authorizes, which
// is the defect this change closed, reachable again through a constructor.
//
// So the rule is a census rather than a sentence: outside this package, no
// non-test file may call authoring.Publish, authoring.NewStore or
// authoring.NewStoreWithBackend. The walk resolves each file's OWN import name
// for the package, so an alias does not hide a call.
func TestNoProductionCodeReachesTheRootAgnosticPrimitives(t *testing.T) {
	root := repoRootFromAuthoring(t)
	primitives := map[string]bool{"Publish": true, "NewStore": true, "NewStoreWithBackend": true}

	parsed, importers := 0, 0
	var hits []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".next", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Dir(path) == filepath.Join(root, "platform", "decision", "authoring") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		parsed++
		name, ok := authoringImportName(f)
		if !ok {
			return nil
		}
		importers++
		rel, _ := filepath.Rel(root, path)
		if name == "." {
			// A dot import makes every call unqualified, so no selector below
			// could see one. Reported rather than skipped.
			hits = append(hits, rel+": dot-imports the authoring package, so its calls cannot be censused")
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == name && primitives[sel.Sel.Name] {
				hits = append(hits, fmt.Sprintf("%s:%d: authoring.%s", rel, fset.Position(sel.Pos()).Line, sel.Sel.Name))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// ANTI-VACUITY: a walk that saw nothing, or no importer of the package,
	// would pass having checked nothing.
	if parsed < 200 {
		t.Fatalf("the walk parsed only %d Go files; it is not seeing the tree", parsed)
	}
	if importers < 3 {
		t.Fatalf("only %d production file(s) import the authoring package; the transports import it, so this walk is not finding them", importers)
	}
	sort.Strings(hits)
	if len(hits) > 0 {
		t.Fatalf("production code reaches a root-agnostic authoring primitive:\n  %s\n\n"+
			"A store or publication built this way is bound to no authority and admits a system-root artifact from "+
			"any key its trust store holds (#4047). Build the authoring plane with authoring.NewAPIWithBackend, which "+
			"binds the organization authority; the system root is signed only by authoring.SystemAuthority.",
			strings.Join(hits, "\n  "))
	}
}

// authoringImportName returns the name a file refers to the authoring package
// by, and whether it imports the package at all.
func authoringImportName(f *ast.File) (string, bool) {
	for _, imp := range f.Imports {
		if imp.Path == nil || imp.Path.Value != `"axonflow/platform/decision/authoring"` {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name, true
		}
		return "authoring", true
	}
	return "", false
}
