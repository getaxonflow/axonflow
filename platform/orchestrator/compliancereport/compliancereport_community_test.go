//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package compliancereport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// Community-build tests for the compliance report facade stub.
//
// These compile ONLY in a `!enterprise` build, which is the point: they are the
// thing that fails if the stub stops covering what the (untagged) run.go
// touches, and no enterprise test run can substitute for them.

func TestCommunityStub_ConstructsAndRegistersNothing(t *testing.T) {
	m, err := NewModule(ModuleConfig{})
	if err != nil {
		t.Fatalf("NewModule: %v", err)
	}
	if m == nil {
		t.Fatal("NewModule returned nil")
	}
	if m.IsHealthy() {
		t.Error("the community stub must not report healthy")
	}
	if got := m.HealthCheck()["report_facade"]; got != "disabled" {
		t.Errorf("HealthCheck report_facade = %q, want disabled", got)
	}

	r := mux.NewRouter()
	m.RegisterRoutesWithMux(r)

	// A route that was never registered must 404. Walking the router would
	// prove the same thing, but serving a request proves it through the path a
	// customer actually takes.
	for _, path := range []string{
		"/api/v1/compliance/reports",
		"/api/v1/compliance/reports/creport-1",
		"/api/v1/compliance/reports/creport-1/download",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/reports", nil)
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
// files. A missing one is a compile error in the community build - which is
// the loud failure - but a ModuleConfig FIELD that exists only in the
// enterprise file is the quiet one: the enterprise build compiles, the
// community build fails, and it fails in CI rather than here.
//
// This test parses run.go and asserts every `compliancereport.X` selector it
// uses, and every ModuleConfig field it sets, is present in this build. It
// reads the real file rather than a hand-listed inventory, so a new usage in
// run.go is covered without anyone remembering to update a list.
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
	fields := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok && ident.Name == "compliancereport" {
				used[node.Sel.Name] = true
			}
		case *ast.CompositeLit:
			sel, ok := node.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "compliancereport" || sel.Sel.Name != "ModuleConfig" {
				return true
			}
			for _, elt := range node.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						fields[key.Name] = true
					}
				}
			}
		}
		return true
	})

	if len(used) == 0 {
		t.Fatal("run.go references no compliancereport symbols - the wiring is missing, or this parser no longer matches it")
	}

	// Both sides are now PARSED. Hand-listing the provided side made this test
	// pass on a stub that had lost a field: `providedFields["Licenses"] = true`
	// stayed true after the field was deleted, so the guard named for catching
	// exactly that missed it and the failure surfaced as a build error in a
	// different job with a worse message.
	provided, providedFields, providedMethods := parseCommunityStub(t)

	for name := range used {
		if !provided[name] {
			t.Errorf("run.go uses compliancereport.%s, which the community stub does not declare", name)
		}
	}

	for f := range fields {
		if !providedFields[f] {
			t.Errorf("run.go sets ModuleConfig.%s, which the community stub does not declare", f)
		}
	}
	if len(fields) == 0 {
		t.Error("run.go constructs no compliancereport.ModuleConfig literal - the construction wiring is missing")
	}

	// Methods run.go calls on the module value. Parsed the same way so a new
	// call site is covered automatically.
	methods := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "complianceReportModule" {
			methods[sel.Sel.Name] = true
		}
		return true
	})
	for m := range methods {
		if !providedMethods[m] {
			t.Errorf("run.go calls complianceReportModule.%s(), which the community stub does not declare", m)
		}
	}
	if len(methods) == 0 {
		t.Error("run.go calls no method on complianceReportModule - route registration is missing")
	}

	t.Logf("run.go compliancereport surface: symbols=%v fields=%v methods=%v",
		sortedKeys(used), sortedKeys(fields), sortedKeys(methods))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCommunityStubDeclaresNoEnterpriseSurface pins that the stub does not
// accidentally grow real behaviour. If someone adds a renderer or a service
// here, the Enterprise feature has leaked into the community edition.
func TestCommunityStubDeclaresNoEnterpriseSurface(t *testing.T) {
	src, err := os.ReadFile("compliancereport_community.go")
	if err != nil {
		t.Fatalf("read stub: %v", err)
	}
	for _, forbidden := range []string{"renderer.", "rls.WithOrgScope", "cloudstorage.NewStorageBackend"} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("the community stub references %q - Enterprise behaviour has leaked into the community build", forbidden)
		}
	}
}

// parseCommunityStub reads compliancereport_community.go and returns what it
// actually declares: package-level symbols, ModuleConfig fields, and methods on
// *Module.
//
// Derived rather than hand-listed, for the same reason the "used" side is
// derived from run.go: a list that has to be kept in step with the file it
// describes is a list that eventually disagrees with it, and this test is the
// one place where that disagreement would go unnoticed.
func parseCommunityStub(t *testing.T) (symbols, fields, methods map[string]bool) {
	t.Helper()
	const stub = "compliancereport_community.go"
	src, err := os.ReadFile(stub)
	if err != nil {
		t.Fatalf("read %s: %v", stub, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, stub, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", stub, err)
	}

	symbols = map[string]bool{}
	fields = map[string]bool{}
	methods = map[string]bool{}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				symbols[ts.Name.Name] = true
				st, ok := ts.Type.(*ast.StructType)
				if !ok || ts.Name.Name != "ModuleConfig" || st.Fields == nil {
					continue
				}
				for _, f := range st.Fields.List {
					for _, n := range f.Names {
						fields[n.Name] = true
					}
				}
			}
		case *ast.FuncDecl:
			if d.Recv == nil {
				symbols[d.Name.Name] = true
				continue
			}
			methods[d.Name.Name] = true
		}
	}

	// The parse must have found SOMETHING, or an unrelated refactor that
	// renamed the file would make every assertion above vacuously true.
	if len(symbols) == 0 || len(fields) == 0 || len(methods) == 0 {
		t.Fatalf("parsed %s but found symbols=%v fields=%v methods=%v - the parser no longer matches the stub",
			stub, sortedKeys(symbols), sortedKeys(fields), sortedKeys(methods))
	}
	return symbols, fields, methods
}

// TestParseCommunityStubDiscriminates is the parser's own self-test.
//
// It deliberately hard-codes NOTHING about what the stub should contain. An
// earlier revision listed all eight ModuleConfig fields and four methods, which
// (a) re-introduced exactly the hand-list this parser replaced and (b)
// over-claimed: it demanded RegisterRoutes and HealthCheck, which run.go never
// calls, so deleting an unused stub method would have reddened the self-test
// while the guard it tests stayed green.
//
// What it asserts instead: the parser finds SOMETHING in each category, it
// finds the specific things the REAL guard depends on, and it does not
// hallucinate. That is the whole of its job.
func TestParseCommunityStubDiscriminates(t *testing.T) {
	symbols, fields, methods := parseCommunityStub(t)

	// The three entry points run.go cannot compile without, in any edition.
	for _, want := range []string{"Module", "ModuleConfig", "NewModule"} {
		if !symbols[want] {
			t.Errorf("parser did not find the %s declaration", want)
		}
	}

	// Non-emptiness, so a parser that silently matched nothing would fail here
	// rather than making every assertion in the real guard vacuously true.
	if len(fields) == 0 {
		t.Error("parser found no ModuleConfig fields")
	}
	if len(methods) == 0 {
		t.Error("parser found no methods on *Module")
	}

	// Negative controls: the parser must not report things that are not there.
	for _, absent := range []string{"NoSuchField", "Renderer", "Service"} {
		if fields[absent] {
			t.Errorf("parser reported a ModuleConfig field %q that does not exist", absent)
		}
	}
	for _, absent := range []string{"Render", "CreateReport", "DownloadURL"} {
		if methods[absent] {
			t.Errorf("parser reported a method %q that does not exist on the stub", absent)
		}
	}

	t.Logf("community stub declares: symbols=%v fields=%v methods=%v",
		sortedKeys(symbols), sortedKeys(fields), sortedKeys(methods))
}
