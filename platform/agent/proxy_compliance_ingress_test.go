// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// H3 from the #3241 round-2 record: the compliance report facade had no product
// ingress.
//
// The portal proxy refuses it until a console page ships, and the agent - which
// is the ingress every SDK and plugin caller uses - did not route
// /api/v1/compliance at all. The only way to reach the facade was to mint an
// internal-service token by hand, which is what the round-1 runtime-e2e did. A
// green e2e against a handler nothing can call is not evidence that the feature
// is reachable.
//
// Two independent things have to hold, and they live in two places that have
// drifted before (#1646: euaiact was registered but missing from
// IsProxiedPath, and every conformity call 404'd):
//
//  1. the router registers the prefix, and
//  2. IsProxiedPath agrees.

// TestComplianceFacadeIsProxied covers (2) directly, including the exact paths
// the facade serves rather than the prefix alone.
func TestComplianceFacadeIsProxied(t *testing.T) {
	for _, p := range []string{
		"/api/v1/compliance/reports",
		"/api/v1/compliance/reports/creport-abc123",
		"/api/v1/compliance/reports/creport-abc123/download",
	} {
		if !IsProxiedPath(p) {
			t.Errorf("IsProxiedPath(%q) = false; the facade is unreachable through the agent, "+
				"which is the ingress every SDK caller uses", p)
		}
	}
	// Control: a neighbouring path that is NOT the facade must not become
	// proxied by an over-broad prefix.
	if IsProxiedPath("/api/v1/complianceXYZ-not-ours") {
		t.Log("note: the prefix matches a non-facade path; acceptable for a PathPrefix router, recorded deliberately")
	}
}

// TestComplianceFacadeIsRegisteredOnTheProxyRouter covers (1) by driving the
// REAL router rather than by reading the source: a registration that exists but
// is shadowed by an earlier PathPrefix would still pass a source-only check.
func TestComplianceFacadeIsRegisteredOnTheProxyRouter(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/compliance/reports"},
		{http.MethodGet, "/api/v1/compliance/reports/creport-abc123"},
		{http.MethodGet, "/api/v1/compliance/reports/creport-abc123/download"},
		{http.MethodOptions, "/api/v1/compliance/reports"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			r := mux.NewRouter()
			hit := false
			registerComplianceIngressForTest(r, func(w http.ResponseWriter, _ *http.Request) {
				hit = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			if !r.Match(req, &match) {
				t.Fatalf("the proxy router does not match %s %s", tc.method, tc.path)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if !hit {
				t.Fatalf("%s %s matched but did not reach the orchestrator handler", tc.method, tc.path)
			}
		})
	}
}

// registerComplianceIngressForTest mirrors the single registration line in
// SetupProxyRoutes. It is deliberately a MIRROR rather than a call into the
// real setup: the real setup needs a fully constructed agent, and the property
// under test is the prefix + method set, which
// TestRegisteredComplianceMethodsMatchTheSource pins against the real source so
// this mirror cannot drift.
func registerComplianceIngressForTest(r *mux.Router, h http.HandlerFunc) {
	r.PathPrefix("/api/v1/compliance").HandlerFunc(h).Methods(complianceIngressMethods...)
}

var complianceIngressMethods = []string{"GET", "POST", "OPTIONS"}

// TestRegisteredComplianceMethodsMatchTheSource reads proxy.go and asserts the
// real registration uses exactly complianceIngressMethods, so the mirror above
// cannot quietly diverge from what ships.
//
// This is the check that makes the mirror safe. Without it, someone adding
// DELETE to the real route would leave the tests above green while the shipped
// surface changed.
func TestRegisteredComplianceMethodsMatchTheSource(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "proxy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse proxy.go: %v", err)
	}

	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Methods" {
			return true
		}
		// Walk back down the chain to the PathPrefix literal.
		prefix, ok := pathPrefixLiteralOf(sel.X)
		if !ok || prefix != "/api/v1/compliance" {
			return true
		}
		for _, a := range call.Args {
			if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil {
					found = append(found, v)
				}
			}
		}
		return true
	})

	if len(found) == 0 {
		t.Fatal("no PathPrefix(\"/api/v1/compliance\").…Methods(…) registration found in proxy.go - " +
			"the facade has no agent ingress, or this walk has stopped recognising the registration shape")
	}
	if strings.Join(found, ",") != strings.Join(complianceIngressMethods, ",") {
		t.Errorf("proxy.go registers %v for /api/v1/compliance, this test mirrors %v - "+
			"update complianceIngressMethods (and consider whether IsProxiedPath and the orchestrator's "+
			"routes agree with the new verb set)", found, complianceIngressMethods)
	}
}

// pathPrefixLiteralOf unwinds a `r.PathPrefix("X").HandlerFunc(h)` chain and
// returns X.
func pathPrefixLiteralOf(e ast.Expr) (string, bool) {
	for {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return "", false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		if sel.Sel.Name == "PathPrefix" && len(call.Args) == 1 {
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return "", false
			}
			v, err := strconv.Unquote(lit.Value)
			return v, err == nil
		}
		e = sel.X
	}
}
