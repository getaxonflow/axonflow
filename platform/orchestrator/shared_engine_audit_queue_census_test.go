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

// THE ORCHESTRATOR'S SHARED ENGINE HAS NO AUDIT QUEUE, BY DESIGN (#4249 comment
// 5705939386). In this process the shared engine is the response plane's
// detector layer and authors no verdict; the audit_logs decision row records
// every orchestrator evaluation. A queue here would write policy_violations
// rows that duplicate that row, and double-write with the agent's for a request
// that crosses both planes. So every construction of a shared engine in this
// package passes a nil audit queue, and this census holds it: a change that
// wires one has to delete this test, and with it the reason.
func TestTheOrchestratorsSharedEngineIsBuiltWithNoAuditQueue(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	constructions := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// An engine built elsewhere and handed to SetGlobalEngine would
			// escape the check below, so SetGlobalEngine's argument must be
			// the construction itself.
			if sel.Sel.Name == "SetGlobalEngine" {
				if len(call.Args) != 1 {
					return true
				}
				inner, ok := call.Args[0].(*ast.CallExpr)
				innerSel, selOK := func() (*ast.SelectorExpr, bool) {
					if !ok {
						return nil, false
					}
					s, ok := inner.Fun.(*ast.SelectorExpr)
					return s, ok
				}()
				if !ok || !selOK || innerSel.Sel.Name != "NewUnifiedPolicyEngine" {
					t.Errorf("%s: SetGlobalEngine is given an engine built elsewhere; build it in the call with NewUnifiedPolicyEngine so this census sees its audit queue",
						fset.Position(call.Pos()))
				}
				return true
			}
			if sel.Sel.Name != "NewUnifiedPolicyEngine" && sel.Sel.Name != "InitGlobalEngine" {
				return true
			}
			constructions++
			pos := fset.Position(call.Pos())
			if len(call.Args) != 3 {
				t.Errorf("%s: %s takes %d arguments; this census expects (db, config, auditQueue)", pos, sel.Sel.Name, len(call.Args))
				return true
			}
			if ident, ok := call.Args[2].(*ast.Ident); !ok || ident.Name != "nil" {
				t.Errorf("%s: the orchestrator's shared engine is given an audit queue (%s); it is nil by design (#4249 comment 5705939386)",
					pos, string(src[fset.Position(call.Args[2].Pos()).Offset:fset.Position(call.Args[2].End()).Offset]))
			}
			return true
		})
	}
	// ANTI-VACUITY: run.go builds the engine.
	if constructions == 0 {
		t.Fatal("no shared engine construction found in the orchestrator package; the census is reading the wrong place")
	}
}
