// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"
)

// TestRegisteredPathsMatchTheExportedConstants pins the one thing that writing
// the registration paths as string literals gives up.
//
// wire.go registers with literals, not with BasePath/ByIDPath/DownloadPath,
// because the portal's proxy census and the policy-gate census
// (ee/platform/customer-portal/{orchestrator_proxy_census,policy_route_gate_coverage}_test.go)
// AST-walk this file and fail loudly on any path they cannot resolve to a
// literal - an unresolvable path could hide a proxy-reachable or ungated route
// from the census, so "use a constant" is not available here.
//
// The cost is that the constants and the registrations can now drift: changing
// BasePath would move the middleware carve-out in read_scope.go and the
// handlers' own self-description while leaving the SERVED path where it was.
// This test is what makes that drift a failure. It fails in the OWNING package,
// so the author sees it before the portal's census does.
func TestRegisteredPathsMatchTheExportedConstants(t *testing.T) {
	got := registeredPathLiterals(t, "wire.go")

	want := []string{
		BasePath,       // POST collection (gorilla) + ServeMux collection
		BasePath + "/", // ServeMux by-id prefix handler
		ByIDPath,       // GET poll
		DownloadPath,   // GET artifact
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("wire.go registers %d literal paths %q, expected exactly %d %q.\n"+
			"A registration added or removed without updating this list means the route set changed; "+
			"say so here AND classify it in the portal's proxy census.", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("registered path %d is %q, but the constants say %q. The literal in wire.go and the "+
				"constant in handlers.go have drifted: the served path is the literal, everything that "+
				"reasons about the route (read_scope.go's carve-out, the error bodies) uses the constant.",
				i, got[i], want[i])
		}
	}
}

// TestEveryRegisteredPathIsALiteral is the guard the census itself applies,
// re-applied here so a regression fails in this package rather than only in a
// different module's test run.
func TestEveryRegisteredPathIsALiteral(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "wire.go", nil, 0)
	if err != nil {
		t.Fatalf("parse wire.go: %v", err)
	}

	var nonLiteral int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !isRouteRegistrationName(sel.Sel.Name) || len(call.Args) == 0 {
			return true
		}
		if _, isLit := stringLitValue(call.Args[0]); !isLit {
			nonLiteral++
			t.Errorf("%s: route path is not a string literal. The portal's route census cannot resolve it "+
				"and will fail the build; more importantly, a path it cannot resolve is a route nobody "+
				"classified as proxy-reachable or not.", fset.Position(call.Args[0].Pos()))
		}
		return true
	})

	// Positive control: if the walk stopped recognising registrations entirely
	// it would report zero non-literals and pass vacuously.
	if got := len(registeredPathLiterals(t, "wire.go")); got == 0 {
		t.Fatalf("the AST walk found no route registrations at all in wire.go - this guard is vacuous")
	}
	_ = nonLiteral
}

// registeredPathLiterals returns the sorted, deduplicated string-literal first
// arguments of every HandleFunc/Handle call in the named file.
func registeredPathLiterals(t *testing.T, filename string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !isRouteRegistrationName(sel.Sel.Name) || len(call.Args) == 0 {
			return true
		}
		if v, isLit := stringLitValue(call.Args[0]); isLit {
			seen[v] = true
		}
		return true
	})

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func stringLitValue(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

// isRouteRegistrationName reports whether a selector name registers a route
// path as its first argument.
//
// M5 of the #3241 round-2 record: this walk originally recognised only
// HandleFunc and Handle, so a route registered as
//
//	r.Path("/api/v1/compliance/reports/{id}").HandlerFunc(m.handleByID).Methods("GET")
//
// was invisible to it - and a guard that silently stops seeing a registration
// is worse than no guard, because the drift assertion above then passes on a
// route set it never looked at.
//
// gorilla/mux carries four spellings that take the path first. All four are
// listed rather than the two this file happens to use today: the point of the
// guard is the registration someone adds LATER, and they will not check which
// spellings it understands.
func isRouteRegistrationName(name string) bool {
	switch name {
	case "HandleFunc", "Handle", "Path", "PathPrefix":
		return true
	}
	return false
}
