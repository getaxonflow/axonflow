// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The gate's own chain test is where the per-mode check runs, so it is pinned
// there: a chain test that stopped calling it would still pass every mode.
func TestTheGateChainTestHoldsSeededPolicyIDsToTheCensus(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "migration_chain_realpg_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TestMigrationChainAppliesCleanly_RealPostgres" {
			continue
		}
		calls := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "assertSeededPolicyIDsAreShipped" {
					calls = true
				}
			}
			return !calls
		})
		if !calls {
			t.Fatal("TestMigrationChainAppliesCleanly_RealPostgres no longer calls assertSeededPolicyIDsAreShipped: " +
				"the migrations gate would stop holding each mode's seeded policy ids to the census (#4126 D4b)")
		}
		return
	}
	t.Fatal("TestMigrationChainAppliesCleanly_RealPostgres is not in migration_chain_realpg_test.go")
}
