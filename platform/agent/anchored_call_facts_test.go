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

// TestOnlyTheRequestPassStatesRefundFacts holds the sole agent seam that may
// state caller arguments on its call.
//
// The shared enforcer refuses a fact at a detector path only when it built that
// detector for the request, so a seam that ran an observation could state, as a
// fact, a detector it chose not to run. Every agent seam hands the engine its
// detector facts through the observation alone. The refund amount is a caller
// argument, not a detector finding, so it cannot contradict the observation.
func TestOnlyTheRequestPassStatesRefundFacts(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	literals := 0
	refundSites := 0
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
							value, ok := kv.Value.(*ast.SelectorExpr)
							if name != "decision_enforcing_seam.go" || !ok || value.Sel.Name != "refundFacts" {
								t.Errorf("%s: an anchoredCall states facts outside the refund argument seam", fset.Position(kv.Pos()))
							}
							refundSites++
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
	if refundSites != 1 {
		t.Fatalf("found %d refund fact seam sites, want one", refundSites)
	}
}

// TestOnlyTheRequestPassStatesAdmittedFacts holds the one route an agent seam
// has to a fact that needs the ADMITTED principal (#3330): anchoredCall's
// admittedFacts is set in decideRequestPass alone, from riskScoreFacts alone.
// The route exists for the Engine B risk score and is not a general licence:
// a second site, or another producer, fails here, and the enforcer refuses any
// admitted fact outside anchoredenforcer.AdmittedFactPrefix
// (TestAdmittedFactsAreConfinedToTheScorerNamespace). The caller refund
// argument route above is separate and cannot state a scorer or detector fact.
func TestOnlyTheRequestPassStatesAdmittedFacts(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var sites []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				var value ast.Expr
				switch x := n.(type) {
				case *ast.CompositeLit:
					if id, ok := x.Type.(*ast.Ident); ok && id.Name == "anchoredCall" {
						for _, el := range x.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok {
								if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "admittedFacts" {
									value = kv.Value
								}
							}
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "admittedFacts" && i < len(x.Rhs) {
							value = x.Rhs[i]
						}
					}
				}
				if value == nil {
					return true
				}
				producer := ""
				if call, ok := value.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok {
						producer = id.Name
					}
				}
				sites = append(sites, fn.Name.Name+"<-"+producer+"@"+fset.Position(value.Pos()).String())
				return true
			})
		}
	}
	if len(sites) != 1 || !strings.HasPrefix(sites[0], "decideRequestPass<-riskScoreFacts@") {
		t.Fatalf("admittedFacts is set at %v; want exactly once, in decideRequestPass, from riskScoreFacts", sites)
	}
}
