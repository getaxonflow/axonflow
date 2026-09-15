// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryActivatingTransportInstallsAnActivator is the check that
// authoring.Activator's doc comment claims (#3895).
//
// # WHY IT EXISTS: THE COMMENT CLAIMED A CENSUS THAT DID NOT EXIST
//
// An earlier version of that comment said "platform/shared/authoringedition
// hands every transport an activator, and a census in that package holds them
// to it". Neither the hand-out nor the census was ever written. Nothing failed,
// because nothing checks prose - and the transport the imaginary census would
// have caught was the Enterprise customer portal, which activates against
// DURABLE storage and was doing so with no production dry run at all, while the
// community route, whose artifacts do not survive a restart, had one.
//
// So the rule is enforced here instead: a package that calls Promote, Rollback
// or Withdraw on an authoring API is a package that ACTIVATES, and it must also
// call WithActivator. Without the activator, activation flips the pointer
// without ever building the engine that would enforce the result, and a
// document that cannot be enforced becomes active - discovered at the first
// real request rather than at the activation.
//
// # THE POPULATION IS DERIVED FROM THE SOURCE, NOT LISTED
//
// It walks the tree for the call expressions rather than naming the transports,
// so a THIRD transport is covered on the day it is written. A list would be one
// entry short exactly when it mattered, which is how the portal came to be
// missing in the first place.
func TestEveryActivatingTransportInstallsAnActivator(t *testing.T) {
	root := repoRootFromAuthoring(t)

	activates := map[string]string{}  // package dir -> first file seen calling Promote/Rollback/Withdraw
	installs := map[string]struct{}{} // package dir -> calls WithActivator
	parsed := 0

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
		// This package defines the verbs; it is not a transport.
		if filepath.Dir(path) == filepath.Join(root, "platform", "decision", "authoring") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return nil
		}
		parsed++
		// ONLY FILES THAT IMPORT THIS PACKAGE. `Promote`, `Rollback` and
		// `Withdraw` are ordinary method names - `tx.Rollback()` from
		// database/sql is all over this tree - so a bare selector match reports
		// nine unrelated files and the real finding drowns. The import is the cheap, derived way to ask
		// "is this a caller of OUR verbs" without a type checker, and a
		// transport that activates typed policy necessarily imports the package
		// whose API it is activating through.
		if !importsAuthoring(f) {
			return nil
		}
		dir := filepath.Dir(path)
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Promote", "Rollback", "Withdraw":
				if _, seen := activates[dir]; !seen {
					rel, _ := filepath.Rel(root, path)
					activates[dir] = rel
				}
			case "WithActivator":
				installs[dir] = struct{}{}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// ANTI-VACUITY. A walk that parsed nothing, or found no activating package,
	// would pass having checked nothing - which is the shape this whole test
	// exists to answer for.
	if parsed < 200 {
		t.Fatalf("the walk parsed only %d Go files; it is not seeing the tree and every result below is meaningless", parsed)
	}
	if len(activates) == 0 {
		t.Fatal("no package outside platform/decision/authoring calls Promote, Rollback or Withdraw. Either the activation " +
			"verbs were renamed, or this walk stopped finding them - and in both cases this test is now checking nothing")
	}

	var missing []string
	for dir, file := range activates {
		if _, ok := installs[dir]; !ok {
			missing = append(missing, file)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("these packages ACTIVATE typed policy and never install an activator:\n  %s\n\n"+
			"Activation without one flips the active digest without building the engine that would enforce the "+
			"result, so a document that cannot be enforced becomes active and the failure arrives at the first "+
			"request instead of at the activation. Install activation.Activator on the API these call.",
			strings.Join(missing, "\n  "))
	}
}

// importsAuthoring reports whether a file imports the typed authoring package.
func importsAuthoring(f *ast.File) bool {
	for _, imp := range f.Imports {
		if imp.Path != nil && imp.Path.Value == `"axonflow/platform/decision/authoring"` {
			return true
		}
	}
	return false
}

// repoRootFromAuthoring walks up to the directory holding both module roots.
func repoRootFromAuthoring(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "platform", "decision", "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("community mirror or a partial checkout: the repository root was not found from here")
	return ""
}
