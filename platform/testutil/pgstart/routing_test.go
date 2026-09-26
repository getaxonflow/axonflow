// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pgstart

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Both Real-PG container helpers start under this package's rule, and every
// deadline they set DERIVES from pgstart.Window: a helper that went back to a
// hard-coded deadline, overrode the window after reading it, or passed some
// other duration to a wait would put the flake back while every cell above
// stayed green.
//
// Per helper function: exactly one assignment from pgstart.Window, never
// reassigned; the pgstart.Waiter's Window field and every duration handed to a
// wait (WithStartupTimeout, WithStartupTimeoutDefault, WithDeadline, the
// startupWait helper) is that variable; and no time.Now().Add deadline.
// testutil's startupWait is held to the same rule over its parameter, and must
// wait on the published port.
func TestBothContainerHelpersStartUnderTheOneRule(t *testing.T) {
	approle := parseFile(t, "../../agent/approletest/setup.go")
	testutil := parseFile(t, "../postgres.go")

	for _, h := range []struct {
		file string
		fset *token.FileSet
		fn   *ast.FuncDecl
	}{
		{"setup.go", approle.fset, funcNamed(t, approle, "startPostgresContainer")},
		{"postgres.go", testutil.fset, funcNamed(t, testutil, "StartPostgres")},
	} {
		window := windowVar(t, h.file, h.fn)
		checkDerives(t, h.file+" "+h.fn.Name.Name, h.fset, h.fn.Body, window, true)
	}

	sw := funcNamed(t, testutil, "startupWait")
	params := sw.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 {
		t.Fatalf("PREMISE: startupWait takes one duration parameter")
	}
	checkDerives(t, "postgres.go startupWait", testutil.fset, sw.Body, params[0].Names[0].Name, false)
	if !callsName(sw.Body, "wait.ForListeningPort") {
		t.Errorf("postgres.go startupWait does not wait on wait.ForListeningPort")
	}
}

type parsed struct {
	fset *token.FileSet
	file *ast.File
}

func parseFile(t *testing.T, path string) parsed {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return parsed{fset, f}
}

func funcNamed(t *testing.T, p parsed, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range p.file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
			return fd
		}
	}
	t.Fatalf("PREMISE: no function %s; the census reads nothing", name)
	return nil
}

// windowVar returns the variable fn assigns from pgstart.Window.
func windowVar(t *testing.T, file string, fn *ast.FuncDecl) string {
	t.Helper()
	var names []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		if call, ok := as.Rhs[0].(*ast.CallExpr); ok && callName(call.Fun) == "pgstart.Window" {
			if id, ok := as.Lhs[0].(*ast.Ident); ok {
				names = append(names, id.Name)
			}
		}
		return true
	})
	if len(names) != 1 {
		t.Fatalf("%s's %s assigns from pgstart.Window %d times (%v); want once", file, fn.Name.Name, len(names), names)
	}
	return names[0]
}

// checkDerives holds every deadline in body to the variable window: it is
// assigned at most once (fromWindow: exactly the pgstart.Window assignment;
// otherwise, a parameter, never), the Waiter's Window field and every duration
// handed to a wait is window, and no time.Now().Add deadline appears.
func checkDerives(t *testing.T, where string, fset *token.FileSet, body *ast.BlockStmt, window string, fromWindow bool) {
	t.Helper()
	assigns := 0
	sawWaiter := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if id, ok := l.(*ast.Ident); ok && id.Name == window {
					assigns++
				}
			}
		case *ast.IncDecStmt:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == window {
				assigns++
			}
		case *ast.CompositeLit:
			if callName(x.Type) == "pgstart.Waiter" {
				sawWaiter = true
				field := ""
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok && callName(kv.Key) == "Window" {
						field = callName(kv.Value)
					}
				}
				if field != window {
					t.Errorf("%s: pgstart.Waiter's Window is %q, not the identifier %s read from pgstart.Window (pass that identifier itself, not a copy or another duration)", where, field, window)
				}
			}
		case *ast.CallExpr:
			name := callName(x.Fun)
			if name == "time.Now().Add" {
				t.Errorf("%s keeps a deadline of its own at %s", where, fset.Position(x.Pos()))
			}
			if isWaitDuration(name) {
				if len(x.Args) != 1 || callName(x.Args[0]) != window {
					t.Errorf("%s: %s at %s is not given the identifier %s read from pgstart.Window (pass that identifier itself, not a copy or another duration)", where, name, fset.Position(x.Pos()), window)
				}
			}
		}
		return true
	})
	want := 0
	if fromWindow {
		want = 1
		if !sawWaiter {
			t.Errorf("%s builds no pgstart.Waiter", where)
		}
	}
	if assigns != want {
		t.Errorf("%s assigns %s %d times; want %d: the window is read from pgstart.Window and never overridden", where, window, assigns, want)
	}
}

func isWaitDuration(name string) bool {
	for _, suffix := range []string{".WithStartupTimeout", ".WithStartupTimeoutDefault", ".WithDeadline"} {
		if len(name) >= len(suffix) && name[len(name)-len(suffix):] == suffix {
			return true
		}
	}
	return name == "startupWait"
}

func callsName(body *ast.BlockStmt, want string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && callName(c.Fun) == want {
			found = true
		}
		return true
	})
	return found
}

// callName renders an expression: pkg.Fn, x.Method, or time.Now().Add for a
// method on a call.
func callName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return callName(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		return callName(x.Fun) + "()"
	case *ast.CompositeLit:
		return callName(x.Type) + "{}"
	}
	return ""
}
