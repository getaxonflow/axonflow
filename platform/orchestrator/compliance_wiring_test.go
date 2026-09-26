// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run.go is the only wiring of the compliance readers (#4249, master's round 1
// on #4401): each of the three module configs is handed complianceActiveEffects,
// and complianceTypedAuthoring has exactly one writer, Run. Deleting any of
// these compiles and keeps every reader cell green, while a regulator's report
// would say no activation reader is wired, so the wiring is pinned by parsing.
func TestRunWiresTheComplianceSeamIntoEveryReader(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatalf("parse run.go: %v", err)
	}
	want := map[string]int{"sebi.SEBIModuleConfig": 0, "ojk.OJKModuleConfig": 0, "ussecurities.ModuleConfig": 0}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		name := pkg.Name + "." + sel.Sel.Name
		if _, tracked := want[name]; !tracked {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, kok := kv.Key.(*ast.Ident)
			val, vok := kv.Value.(*ast.Ident)
			if kok && vok && key.Name == "ActiveEffects" && val.Name == "complianceActiveEffects" {
				want[name]++
			}
		}
		return true
	})
	for name, n := range want {
		if n != 1 {
			t.Errorf("run.go builds %s with ActiveEffects: complianceActiveEffects %d time(s); want exactly 1, or its reports say no activation reader is wired", name, n)
		}
	}

	// The seam's single writer: one assignment to complianceTypedAuthoring in
	// this package's non-test source, inside Run.
	writers := []string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == "complianceTypedAuthoring" {
						writers = append(writers, e.Name()+":"+fd.Name.Name)
					}
				}
				return true
			})
		}
	}
	if len(writers) != 1 || writers[0] != "run.go:Run" {
		t.Errorf("complianceTypedAuthoring is written at %v; want exactly once, in run.go's Run", writers)
	}
}
