// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestThePackageReadsNoEnvironmentAndNoDeploymentMode walks every non-test
// file of this package and fails on ANY environment read (os.Getenv,
// os.LookupEnv, os.Environ, os.ExpandEnv) and on the literal DEPLOYMENT_MODE
// anywhere in the source, comments included.
//
// The ruling is that a limit is read from the signed licence and that
// DEPLOYMENT_MODE never grants one. A grep is the cheap half; the AST walk is
// the half a reformat cannot beat, and an `os` import at all is reported so
// the next reader sees the boundary rather than infers it.
//
// Positive control: add `_ = os.Getenv("X")` to any file here and this test
// names the file and line. So does the aliased form `goos "os"; goos.Getenv`,
// which an earlier version caught on the import check alone.
//
// WHAT IT STILL DOES NOT CATCH, stated so nobody reads more into it than it
// proves: an INDIRECT read, such as shelling out through os/exec. The claim
// this test supports is "no direct environment read, and no mention of the
// deployment-mode variable" - not "this package cannot learn anything about
// the environment by any route". The default tier reader it calls does read
// AXONFLOW_LICENSE_KEY, which is the design and lives in
// platform/agent/license, not here.
func TestThePackageReadsNoEnvironmentAndNoDeploymentMode(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		if strings.Contains(string(src), "DEPLOYMENT_MODE") {
			t.Errorf("%s mentions DEPLOYMENT_MODE; the deployment mode is not an input to a tier limit", name)
		}
		f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		// THE LOCAL NAME, NOT THE PACKAGE NAME. R3 round 1 (L2) measured that
		// the AST arm below only recognised a selector whose receiver is
		// literally `os`, so `goos "os"; goos.Getenv(...)` tripped the import
		// check alone. Binding the alias here makes both arms see it.
		envAliases := map[string]bool{"os": true}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "os" || path == "axonflow/platform/shared/deploymode" {
				t.Errorf("%s imports %q; this package must not read the environment or the deployment mode", name, path)
			}
			if path == "os" || strings.HasSuffix(path, "/os") {
				if imp.Name != nil {
					envAliases[imp.Name.Name] = true
				}
			}
		}
		full, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(full, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || !envAliases[pkg.Name] {
				return true
			}
			switch sel.Sel.Name {
			case "Getenv", "LookupEnv", "Environ", "ExpandEnv":
				t.Errorf("%s: %s.%s at %s", name, pkg.Name, sel.Sel.Name, fset.Position(sel.Pos()))
			}
			return true
		})
	}
	if scanned < 5 {
		t.Fatalf("scanned only %d non-test files; the census is not looking at the package", scanned)
	}
}
