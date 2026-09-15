// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package retiredenvtest is what a binary's tests use to prove its boot path
// refuses a retired configuration: the refusal is called where nothing can skip
// it, and its error ends the process.
//
// retiredenv's own tests hold what Refuse returns. They cannot see a boot path
// that stopped calling it, or that logs its error and carries on - and no
// behavioural test drives a binary's boot in-process - so without this check
// either edit would pass every Go test and ship a process that starts in a
// posture its configuration misdescribes.
package retiredenvtest

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

// fatalCalls end the process.
var fatalCalls = map[string]bool{"log.Fatal": true, "log.Fatalf": true, "log.Fatalln": true, "os.Exit": true}

// BootRefusalProblems reports, for the Go file at path, every call in calls that
// fn does not refuse on. A call is refused on when a statement of fn's own body
// - not one nested under any condition - has the shape
//
//	if err := <call>(); err != nil {
//		log.Fatalf(...) // or log.Fatal, log.Fatalln, os.Exit
//	}
//
// Each call is named as rendered, for example "retiredenv.Refuse".
func BootRefusalProblems(path, fn string, calls ...string) ([]string, error) {
	fset, body, err := funcBody(path, fn)
	if err != nil {
		return nil, err
	}
	fatal := map[string]bool{} // call -> its error ends the process
	for _, stmt := range body.List {
		ifs, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		if call := refusalCall(fset, ifs); call != "" {
			fatal[call] = fatal[call] || endsTheProcess(fset, ifs.Body)
		}
	}
	var problems []string
	for _, call := range calls {
		ends, called := fatal[call]
		switch {
		case !called:
			problems = append(problems, fmt.Sprintf("%s: %s does not refuse on %s() as a statement of its own body, so a process that sets what it refuses can start", path, fn, call))
		case !ends:
			problems = append(problems, fmt.Sprintf("%s: %s calls %s() but its error does not end the process, so a refusal is logged and ignored", path, fn, call))
		}
	}
	return problems, nil
}

// UncalledAtTopLevel reports every callee in calls that fn, in the Go file at
// path, does not call as a statement of its own body: the link from a boot
// entry point to the function that holds a refusal.
func UncalledAtTopLevel(path, fn string, calls ...string) ([]string, error) {
	fset, body, err := funcBody(path, fn)
	if err != nil {
		return nil, err
	}
	called := map[string]bool{}
	for _, stmt := range body.List {
		if expr, ok := stmt.(*ast.ExprStmt); ok {
			if call, ok := expr.X.(*ast.CallExpr); ok {
				called[render(fset, call.Fun)] = true
			}
		}
	}
	var problems []string
	for _, c := range calls {
		if !called[c] {
			problems = append(problems, fmt.Sprintf("%s: %s does not call %s() as a statement of its own body, so the refusal it holds can be skipped", path, fn, c))
		}
	}
	return problems, nil
}

// RequireFatalBootRefusal fails t with every problem BootRefusalProblems finds.
func RequireFatalBootRefusal(t testing.TB, path, fn string, calls ...string) {
	t.Helper()
	report(t, path, fn, calls, BootRefusalProblems)
}

// RequireTopLevelCall fails t with every problem UncalledAtTopLevel finds.
func RequireTopLevelCall(t testing.TB, path, fn string, calls ...string) {
	t.Helper()
	report(t, path, fn, calls, UncalledAtTopLevel)
}

func report(t testing.TB, path, fn string, calls []string, check func(string, string, ...string) ([]string, error)) {
	t.Helper()
	problems, err := check(path, fn, calls...)
	if err != nil {
		t.Fatalf("reading the boot path: %v", err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// funcBody parses the Go file at path and returns fn's body.
func funcBody(path, fn string) (*token.FileSet, *ast.BlockStmt, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, nil, err
	}
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok && f.Recv == nil && f.Name.Name == fn && f.Body != nil {
			return fset, f.Body, nil
		}
	}
	return nil, nil, fmt.Errorf("%s declares no func %s", path, fn)
}

// refusalCall returns the rendered callee of `if err := <call>(); err != nil`,
// or "".
func refusalCall(fset *token.FileSet, ifs *ast.IfStmt) string {
	assign, ok := ifs.Init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !isIdent(assign.Lhs[0], "err") {
		return ""
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return ""
	}
	cond, ok := ifs.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ || !isIdent(cond.X, "err") || !isIdent(cond.Y, "nil") {
		return ""
	}
	return render(fset, call.Fun)
}

// endsTheProcess reports whether a statement of body is a call that ends it.
func endsTheProcess(fset *token.FileSet, body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		if expr, ok := stmt.(*ast.ExprStmt); ok {
			if call, ok := expr.X.(*ast.CallExpr); ok && fatalCalls[render(fset, call.Fun)] {
				return true
			}
		}
	}
	return false
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func render(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, e); err != nil {
		return ""
	}
	return b.String()
}
