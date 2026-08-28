//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package usinsurance

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
)

// Community-build tests for the US insurance module stub.
//
// These compile ONLY in a `!enterprise` build, which is the point: they are the
// thing that fails if the stub stops covering what the (untagged) run.go
// touches, and no enterprise test run can substitute for them.

func TestCommunityStub_ConstructsAndRegistersNothing(t *testing.T) {
	m, err := NewModule(nil)
	if err != nil {
		t.Fatalf("NewModule: %v", err)
	}
	if m == nil {
		t.Fatal("NewModule returned nil")
	}
	if m.IsHealthy() {
		t.Error("the community stub must not report healthy")
	}
	if got := m.HealthCheck()["usinsurance"]; got != "disabled" {
		t.Errorf("HealthCheck usinsurance = %q, want disabled", got)
	}

	r := mux.NewRouter()
	m.RegisterRoutesWithMux(r)

	// A route that was never registered must 404. Serving a request proves it
	// through the path a customer actually takes, rather than by walking the
	// router.
	//
	// This matters more here than on a typical module: the exhibits are a
	// filing artifact, and a community build answering these routes at all
	// would be an Enterprise feature leaking into an unlicensed edition.
	for _, path := range []string{
		"/api/v1/usinsurance/inventory",
		"/api/v1/usinsurance/oversight",
		"/api/v1/usinsurance/data-sources",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			req := httptest.NewRequest(method, path, nil)
			req.Header.Set("X-Org-ID", "acme-org")
			req.Header.Set("X-Tenant-ID", "acme-tenant")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusNotFound {
				t.Errorf("%s %s in a community build: got %d, want 404", method, path, rr.Code)
			}
		}
	}

	// The http.ServeMux registration surface must be a no-op too.
	sm := http.NewServeMux()
	m.RegisterRoutes(sm)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/usinsurance/inventory", nil)
	rr := httptest.NewRecorder()
	sm.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("ServeMux registration in a community build: got %d, want 404", rr.Code)
	}
}

// TestCommunityStubCoversRunGoSurface is the guard named in the stub's package
// comment.
//
// platform/orchestrator/run.go carries NO build tag, so it compiles in both
// editions and every symbol it touches on this package must exist in BOTH
// files. A missing one is a compile error in the community build, which is the
// loud failure; the quiet one is a symbol that exists only in the enterprise
// file, because the enterprise build then compiles and only the community job
// fails, with a worse message and further from the change.
//
// Both sides are PARSED rather than hand-listed. The sibling facade's version
// of this test hand-listed the provided side, and that made it pass on a stub
// that had lost a field: the hand-written entry stayed true after the field was
// deleted, so the guard named for catching exactly that missed it.
func TestCommunityStubCoversRunGoSurface(t *testing.T) {
	const runGo = "../run.go"
	src, err := os.ReadFile(runGo)
	if err != nil {
		t.Fatalf("read %s: %v", runGo, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, runGo, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", runGo, err)
	}

	used := map[string]bool{}
	methods := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok && ident.Name == "usinsurance" {
				used[node.Sel.Name] = true
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "usInsuranceModule" {
				methods[sel.Sel.Name] = true
			}
		}
		return true
	})

	if len(used) == 0 {
		t.Fatal("run.go references no usinsurance symbols - the wiring is missing, or this parser no longer matches it")
	}
	if len(methods) == 0 {
		t.Error("run.go calls no method on usInsuranceModule - route registration is missing")
	}

	provided, providedMethods := parseCommunityStub(t)
	for name := range used {
		if !provided[name] {
			t.Errorf("run.go uses usinsurance.%s, which the community stub does not declare", name)
		}
	}
	for m := range methods {
		if !providedMethods[m] {
			t.Errorf("run.go calls usInsuranceModule.%s(), which the community stub does not declare", m)
		}
	}
}

// parseCommunityStub reads THIS build's stub file and reports the top-level
// names and the methods it declares on Module.
func parseCommunityStub(t *testing.T) (names map[string]bool, methods map[string]bool) {
	t.Helper()
	const stub = "usinsurance_community.go"
	src, err := os.ReadFile(stub)
	if err != nil {
		t.Fatalf("read %s: %v", stub, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, stub, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", stub, err)
	}

	names = map[string]bool{}
	methods = map[string]bool{}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				names[d.Name.Name] = true
				continue
			}
			methods[d.Name.Name] = true
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					names[s.Name.Name] = true
				case *ast.ValueSpec:
					for _, ident := range s.Names {
						names[ident.Name] = true
					}
				}
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("the community stub declares nothing - this parser no longer matches the file")
	}
	return names, methods
}

// TestCommunityStubDeclaresNoReadSurface.
//
// The stub must not accidentally grow a working implementation. If any of the
// exhibit query helpers or the Service type appear in a community build, the
// edition gate has been breached in the file whose entire job is to hold it.
func TestCommunityStubDeclaresNoReadSurface(t *testing.T) {
	names, _ := parseCommunityStub(t)
	for _, forbidden := range []string{"Service", "NewService", "ExhibitData", "Framework"} {
		if names[forbidden] {
			t.Errorf("the community stub declares %q; the exhibit read surface must exist only in the enterprise build", forbidden)
		}
	}
}
