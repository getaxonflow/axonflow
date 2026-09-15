// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// TestEvaluateCarriesTheCallsFactsToTheSharedEnforcer holds the conversion to
// the shared enforcer's call to carry a facts set unchanged, and evaluate to go
// through that conversion. A facts set dropped here would read as no facts on
// every agent plane, which the field mirror (TestTheAgentCallShapesMirrorTheSharedEnforcer)
// cannot see: it compares the fields each side declares, not what crosses.
func TestEvaluateCarriesTheCallsFactsToTheSharedEnforcer(t *testing.T) {
	facts := contract.AttributeSet{
		"env.environment": contract.Known("production", contract.ProvPlatform, 1, time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)),
	}
	if got := sharedCall(anchoredCall{orgID: "org-a", requestID: "req-1", facts: facts}).Facts; !reflect.DeepEqual(got, facts) {
		t.Fatalf("the shared call carries facts %v; want %v", got, facts)
	}
	if got := sharedCall(anchoredCall{orgID: "org-a", requestID: "req-1"}).Facts; got != nil {
		t.Fatalf("a call with no facts crossed with %v; want nil", got)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "decision_enforcing_seam.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var evaluate *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "evaluate" && fn.Recv != nil {
			evaluate = fn
		}
	}
	if evaluate == nil {
		t.Fatal("PREMISE: decision_enforcing_seam.go declares no evaluate method")
	}
	converts := false
	ast.Inspect(evaluate.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "sharedCall" {
				converts = true
			}
		}
		return true
	})
	if !converts {
		t.Fatal("evaluate does not build its shared call through sharedCall, so what it carries is not the conversion this test holds")
	}
}

// TestNoAgentSeamStatesFactsOnItsCall holds, as a fact about this package's
// source, that no agent seam states facts on its call.
//
// The shared enforcer refuses a fact at a detector path only when it built that
// detector for the request, so a seam that ran an observation could state, as a
// fact, a detector it chose not to run. Every agent seam hands the engine its
// detector facts through the observation alone, and this test is what makes
// that a fact rather than an assumption. The first seam that needs facts
// deletes this test on purpose, and says in its change why its facts cannot
// contradict its observation.
func TestNoAgentSeamStatesFactsOnItsCall(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	literals := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				id, ok := x.Type.(*ast.Ident)
				if !ok || id.Name != "anchoredCall" {
					return true
				}
				literals++
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "facts" {
							t.Errorf("%s: an anchoredCall states facts", fset.Position(kv.Pos()))
						}
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "facts" {
						t.Errorf("%s: a seam assigns facts on its call", fset.Position(sel.Pos()))
					}
				}
			}
			return true
		})
	}
	if literals < 2 {
		t.Fatalf("PREMISE: found %d anchoredCall literals; the decide and response seams build at least two, so the parse read the wrong files", literals)
	}
}
