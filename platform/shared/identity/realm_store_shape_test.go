// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestLoadIssuesExactlyOneQuery is the DETERMINISTIC half of the atomicity
// guard.
//
// The behavioural half - "a load's realms and epoch always describe each
// other", in the real-Postgres suite - races a reader against a writer and
// requires `epoch == len(realms)` on every sample. It catches the semantic
// regression, but it is PROBABILISTIC: the window a two-statement Load leaves
// open is narrow, and measured over twenty runs against the restored
// two-statement form it stayed green once. A guard that lands green 5% of the
// time on a real regression is a guard that will eventually let one through.
//
// So the STRUCTURE is pinned too, and this half cannot be flaky: rls.WithOrgScope
// opens a READ COMMITTED transaction, where each STATEMENT takes a fresh
// snapshot, so "realms and epoch come from one snapshot" is exactly the claim
// "Load issues one query". Counting them is a total check where racing for the
// window is not.
//
// It parses the source rather than using reflection because a function's body
// is not reachable at run time.
func TestLoadIssuesExactlyOneQuery(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "realm_store.go", nil, 0)
	if err != nil {
		t.Fatalf("parse realm_store.go: %v", err)
	}

	var load *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Load" || fn.Recv == nil {
			continue
		}
		load = fn
	}
	if load == nil {
		t.Fatal("no method named Load in realm_store.go; this guard is asserting about a function that no longer exists")
	}

	var queries []string
	ast.Inspect(load.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// Every way of asking PostgreSQL a question through database/sql.
		switch sel.Sel.Name {
		case "QueryContext", "QueryRowContext", "Query", "QueryRow", "ExecContext", "Exec":
			queries = append(queries, sel.Sel.Name)
		}
		return true
	})

	if len(queries) != 1 {
		t.Fatalf("Load issues %d statements (%s), want exactly 1.\n"+
			"rls.WithOrgScope opens a READ COMMITTED transaction, where each STATEMENT takes a fresh snapshot - so two statements do NOT see one view, and a write committing between them is visible to the second and not the first. A replica would then hold a realm set missing a peer's realm while reporting an epoch that says it is current, and every proof it mints binds a current-looking epoch to a stale configuration.",
			len(queries), strings.Join(queries, ", "))
	}
}
