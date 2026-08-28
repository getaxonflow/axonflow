//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package usbanking

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// TestCommunityStub_ConstructsAndRegistersNothing pins the community contract:
// the module constructs, registers no route, and reports itself unhealthy.
func TestCommunityStub_ConstructsAndRegistersNothing(t *testing.T) {
	m, err := NewModule(ModuleConfig{})
	if err != nil {
		t.Fatalf("NewModule: %v", err)
	}
	if m == nil {
		t.Fatal("NewModule returned nil")
	}
	if m.IsHealthy() {
		t.Error("the community stub reports itself healthy; the US examination package is an Enterprise feature")
	}
	if got := m.HealthCheck()["usbanking_evidence"]; got != "disabled" {
		t.Errorf("HealthCheck reports %q, want disabled", got)
	}

	// A community build must serve NO route: the regulator is absent, so the
	// facade answers 404 rather than 409, which is the documented community
	// behaviour for every regulator.
	r := mux.NewRouter()
	m.RegisterRoutesWithMux(r)
	req, err := http.NewRequest(http.MethodGet, "/api/v1/usbanking/exam-readiness", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	var match mux.RouteMatch
	if r.Match(req, &match) {
		t.Error("the community stub registered /api/v1/usbanking/exam-readiness")
	}

	// And the ServeMux surface likewise. A nil mux must not panic either: run.go
	// is untagged and calls into this stub.
	m.RegisterRoutes(http.NewServeMux())
	m.RegisterRoutes(nil)
	m.RegisterRoutesWithMux(nil)
}

// TestCommunityStubCoversRunGoSurface is the same guard the compliance report
// facade carries, for the same reason.
//
// run.go has NO build tag and is compiled in both editions, so every
// usbanking.X symbol it names, every ModuleConfig field it sets and every
// method it calls must exist in THIS file too. Without this, a symbol added on
// the enterprise side alone breaks the community build - in a different CI job,
// with a worse message.
//
// Both sides are PARSED rather than hand-listed: a list kept in step with the
// file it describes is a list that eventually disagrees with it.
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
	methods := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok && ident.Name == "usbanking" {
				used[node.Sel.Name] = true
			}
		case *ast.CompositeLit:
			sel, ok := node.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "usbanking" || sel.Sel.Name != "ModuleConfig" {
				return true
			}
			for _, elt := range node.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						fields[key.Name] = true
					}
				}
			}
		case *ast.CallExpr:
			sel, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "usbankingModule" {
				methods[sel.Sel.Name] = true
			}
		}
		return true
	})

	if len(used) == 0 {
		t.Fatal("run.go references no usbanking symbols - the wiring is missing, or this parser no longer matches it")
	}
	if len(fields) == 0 {
		t.Error("run.go constructs no usbanking.ModuleConfig literal - the construction wiring is missing")
	}
	if len(methods) == 0 {
		t.Error("run.go calls no method on usbankingModule - route registration is missing")
	}

	provided, providedFields, providedMethods := parseCommunityStub(t)
	for name := range used {
		if !provided[name] {
			t.Errorf("run.go uses usbanking.%s, which the community stub does not declare", name)
		}
	}
	for f := range fields {
		if !providedFields[f] {
			t.Errorf("run.go sets ModuleConfig.%s, which the community stub does not declare", f)
		}
	}
	for m := range methods {
		if !providedMethods[m] {
			t.Errorf("run.go calls usbankingModule.%s(), which the community stub does not declare", m)
		}
	}

	t.Logf("run.go usbanking surface: symbols=%v fields=%v methods=%v",
		sortedKeys(used), sortedKeys(fields), sortedKeys(methods))
}

// TestCommunityStubDeclaresNoEnterpriseSurface pins that the stub does not grow
// real behaviour. If a query, an RLS wrap or a scope type appears here, the
// Enterprise feature has leaked into the community edition.
func TestCommunityStubDeclaresNoEnterpriseSurface(t *testing.T) {
	src, err := os.ReadFile("usbanking_community.go")
	if err != nil {
		t.Fatalf("read stub: %v", err)
	}
	for _, forbidden := range []string{
		"rls.WithOrgScope",
		"SELECT",
		"audit_logs",
		"hitl_approval_queue",
		"llm_provider_configs",
		"tenantscope.",
	} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("the community stub references %q - Enterprise behaviour has leaked into the community build", forbidden)
		}
	}
}

// parseCommunityStub reads usbanking_community.go and returns what it actually
// declares.
func parseCommunityStub(t *testing.T) (symbols, fields, methods map[string]bool) {
	t.Helper()
	const stub = "usbanking_community.go"
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
	if len(symbols) == 0 || len(fields) == 0 || len(methods) == 0 {
		t.Fatalf("parsed %s but found symbols=%v fields=%v methods=%v - the parser no longer matches the stub",
			stub, sortedKeys(symbols), sortedKeys(fields), sortedKeys(methods))
	}
	return symbols, fields, methods
}

// TestParseCommunityStubDiscriminates is the parser's own self-test: a parser
// that silently matched nothing would make every assertion above vacuously
// true.
func TestParseCommunityStubDiscriminates(t *testing.T) {
	symbols, fields, methods := parseCommunityStub(t)
	for _, want := range []string{"Module", "ModuleConfig", "NewModule"} {
		if !symbols[want] {
			t.Errorf("parser did not find the %s declaration", want)
		}
	}
	if !fields["DB"] {
		t.Error("parser did not find ModuleConfig.DB")
	}
	if !methods["RegisterRoutesWithMux"] || !methods["IsHealthy"] {
		t.Errorf("parser did not find the methods run.go depends on: %v", sortedKeys(methods))
	}
	if symbols["NewPostgresRepository"] || symbols["NewService"] {
		t.Error("the parser reports enterprise-only constructors in the community stub")
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
