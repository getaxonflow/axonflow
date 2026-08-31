// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateUserTokenHasExactlyOneProductionCaller is the guard that makes
// the HS256 adapter a guard.
//
// The adapter lives in adaptedValidateUserToken, not in validateUserToken
// itself, because validateUserToken cannot carry the authenticated
// organization and has some thirty test callers. That placement is only safe
// while adaptedValidateUserToken is the ONLY production caller, and the first
// version of this change proved that is not something to leave to discipline:
// it wired the adapter into ResolveUser and shipped with
// resolveAuditReadAuthority still calling validateUserToken directly, so a
// token from an undeclared issuer was refused everywhere except the one
// surface where it buys tenant-wide audit read.
//
// This walks the package AST rather than grepping, because a grep for the
// function NAME matches its own definition, its doc comment, and any string
// that happens to contain it. What must be counted is CALL EXPRESSIONS, and
// bare REFERENCES: taking the function's address bypasses the adapter exactly
// as a direct call does.
//
// NEITHER THIS GUARD NOR ITS SIBLING IS COVERED BY THE MUTATION GATE, and the
// reason is structural rather than an omission: both read their target from
// DISK at test runtime (os.ReadDir / parser.ParseFile), and `go test -overlay`
// redirects only what the compiler reads. A mutant of the source they inspect
// would not reach them. They are instead written so that each check has a
// stated failing input, and the anti-vacuity floors below fire when the walk
// reads nothing or finds nothing.
func TestValidateUserTokenHasExactlyOneProductionCaller(t *testing.T) {
	const target = "validateUserToken"
	const permitted = "adaptedValidateUserToken"

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	callers := map[string][]string{} // enclosing func -> files
	referenced := map[token.Pos]string{}
	scanned := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		scanned++

		// The declaration's own name node, so it can be excluded by POSITION.
		declPos := token.NoPos
		for _, decl := range file.Decls {
			if fn, isFn := decl.(*ast.FuncDecl); isFn && fn.Recv == nil && fn.Name.Name == target {
				declPos = fn.Name.Pos()
			}
		}

		// THE WHOLE FILE, not just function bodies. An earlier version walked
		// only fn.Body, so a package-level `var _ = mustUser(validateUserToken(...))`
		// was invisible - a file-scope initializer is not inside any FuncDecl.
		enclosingOf := func(pos token.Pos) string {
			for _, decl := range file.Decls {
				fn, isFn := decl.(*ast.FuncDecl)
				if !isFn || fn.Body == nil {
					continue
				}
				if pos < fn.Pos() || pos > fn.End() {
					continue
				}
				// RECEIVER-QUALIFIED. Comparing the bare name would silently
				// permit a method that happens to share the permitted
				// function's name.
				if fn.Recv != nil {
					return "(method)." + fn.Name.Name
				}
				return fn.Name.Name
			}
			return "(file scope)"
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if ident, isIdent := node.Fun.(*ast.Ident); isIdent && ident.Name == target {
					callers[enclosingOf(node.Pos())] = append(callers[enclosingOf(node.Pos())], name)
				}
			case *ast.Ident:
				// A FUNCTION VALUE is not a CallExpr, so `f := validateUserToken`
				// followed by `f(...)` is invisible to a call-only walk. Taking
				// the function's address is the same bypass as calling it.
				//
				// THE DECLARATION IS EXCLUDED BY POSITION, NOT BY node.Obj. An
				// earlier version skipped any identifier whose Obj resolved to
				// a FuncDecl - and the parser links EVERY same-file reference
				// to it, so a function value taken inside the 3000-line file
				// the target is declared in was silently skipped. Only the
				// declaration's own name node sits at declPos.
				if node.Name != target || (declPos.IsValid() && node.Pos() == declPos) {
					return true
				}
				referenced[node.Pos()] = enclosingOf(node.Pos())
			}
			return true
		})
	}

	// Anti-vacuity: a walk that parsed nothing, or that found the target
	// nowhere, would report a clean result for a package it never read. The
	// floor is DERIVED - there must be at least one caller, because
	// adaptedValidateUserToken is one - rather than a number chosen to match
	// today's tree.
	if scanned == 0 {
		t.Fatalf("no non-test Go files were parsed; this guard read nothing")
	}
	if len(callers) == 0 {
		t.Fatalf("no call to %s was found in %d files; either it was renamed (re-anchor this guard) or the walk is broken", target, scanned)
	}

	// Every bare reference must sit inside a call this walk already counted,
	// or inside the permitted function. A reference the call walk did not see
	// is a function VALUE, which is the same bypass as a call.
	for pos, enclosing := range referenced {
		_ = pos
		if enclosing == permitted {
			continue
		}
		if _, counted := callers[enclosing]; counted {
			continue
		}
		t.Errorf("%s is REFERENCED (not called) from %s. Taking the function's address bypasses %s exactly as a direct call would.",
			target, enclosing, permitted)
	}

	for enclosing, files := range callers {
		if enclosing == permitted {
			continue
		}
		t.Errorf(
			"%s is called from %s (%v).\n"+
				"The ADR-065 identity compat adapter for the HS256 path lives in %s, so a direct call bypasses it: "+
				"under enforce, a credential the organization's trust realms refuse would be accepted on this path and refused on every other. "+
				"Route it through %s, or move the adapter if this call genuinely cannot carry an authenticated organization.",
			target, enclosing, files, permitted, permitted)
	}
}

// TestAdaptedValidateUserTokenStillRunsTheAdapter is the other half of the
// guard.
//
// TestValidateUserTokenHasExactlyOneProductionCaller proves the CALL GRAPH:
// everything reaches validateUserToken through adaptedValidateUserToken. It
// says nothing about whether that function still runs the adapter. Deleting
// the CompatResolve block passes it, and the runtime suite would catch that -
// but only in the one workflow that boots a stack, and only for the paths it
// drives.
func TestAdaptedValidateUserTokenStillRunsTheAdapter(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "identity_compat.go", nil, 0)
	if err != nil {
		t.Fatalf("parse identity_compat.go: %v", err)
	}

	var found bool
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "adaptedValidateUserToken" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, isSel := n.(*ast.SelectorExpr)
			if !isSel || sel.Sel.Name != "CompatResolve" {
				return true
			}
			found = true
			return false
		})
	}
	if !found {
		t.Fatalf("adaptedValidateUserToken no longer calls CompatResolve.\n" +
			"The HS256 path's adapter is gone: every caller still routes through this function, so the call-graph guard stays green while the plane is unadapted.")
	}
}

// TestTheGuardCatchesAFunctionValueInTheDeclaringFile proves the walk on
// synthetic input, because the shape it must catch does not exist in the tree
// (and must not): a guard that has never been shown to fire is
// indistinguishable from one that cannot.
//
// The specific hole this pins: go/parser links EVERY same-file reference to
// the FuncDecl, so excluding the declaration by node.Obj also excluded a
// function VALUE taken inside the file the target is declared in - which is
// run.go, three thousand lines long.
func TestTheGuardCatchesAFunctionValueInTheDeclaringFile(t *testing.T) {
	const target = "validateUserToken"

	for _, tc := range []struct {
		name string
		src  string
		want bool // want a reference or call to be found
	}{
		{
			name: "the declaration alone is not a caller",
			src:  "package p\nfunc validateUserToken(a, b string) (int, error) { return 0, nil }\n",
			want: false,
		},
		{
			name: "a function VALUE in the declaring file",
			src: "package p\nfunc validateUserToken(a, b string) (int, error) { return 0, nil }\n" +
				"func sneaky() { f := validateUserToken; _, _ = f(\"x\", \"y\") }\n",
			want: true,
		},
		{
			name: "a package-level function value in the declaring file",
			src: "package p\nfunc validateUserToken(a, b string) (int, error) { return 0, nil }\n" +
				"var hook = validateUserToken\n",
			want: true,
		},
		{
			name: "a direct call in the declaring file",
			src: "package p\nfunc validateUserToken(a, b string) (int, error) { return 0, nil }\n" +
				"func direct() { _, _ = validateUserToken(\"x\", \"y\") }\n",
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "run.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			declPos := token.NoPos
			for _, decl := range file.Decls {
				if fn, isFn := decl.(*ast.FuncDecl); isFn && fn.Recv == nil && fn.Name.Name == target {
					declPos = fn.Name.Pos()
				}
			}
			found := false
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					if ident, isIdent := node.Fun.(*ast.Ident); isIdent && ident.Name == target {
						found = true
					}
				case *ast.Ident:
					if node.Name == target && !(declPos.IsValid() && node.Pos() == declPos) {
						found = true
					}
				}
				return true
			})
			if found != tc.want {
				t.Fatalf("found = %v, want %v.\nThe guard's exclusion of the declaration is by POSITION for exactly this case; excluding by node.Obj skips every same-file reference.", found, tc.want)
			}
		})
	}
}
