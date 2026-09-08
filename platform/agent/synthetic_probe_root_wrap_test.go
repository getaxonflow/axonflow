// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// TestTheAgentRootHandlerStampsTheSyntheticProbe is the ONE thing that can be
// forgotten about #3817's design, so it is the one thing pinned here.
//
// The design deliberately has no per-handler census: the stamp is applied once,
// at the root, so there is no second site to forget. That trade moves the entire
// risk onto a single wrap - and a wrap is exactly what a refactor deletes
// without any test noticing, because every handler below it keeps working. The
// symptom would be silent and wrong rather than loud: every canary comparison on
// every plane filed under synthetic="false", inflating the ORGANIC volume the
// ADR-065 coverage gate is read against.
//
// It drives the assembled handler rather than the middleware, because the
// middleware's own behaviour is already pinned in
// planeshadow/synthetic_label_test.go. What is unproven without this is that the
// binary uses it.
func TestTheAgentRootHandlerStampsTheSyntheticProbe(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   bool
	}{
		{"the canary's header reaches the innermost handler", "1", true},
		{"an ordinary request is ORGANIC", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen, reached bool
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				seen = sharedidentity.SyntheticProbeFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			if tc.header != "" {
				req.Header.Set(sharedidentity.SyntheticProbeHeader, tc.header)
			}
			buildAgentHandler(inner).ServeHTTP(httptest.NewRecorder(), req)

			if !reached {
				t.Fatal("the assembled handler never called the inner handler; the assertion below " +
					"would pass over nothing")
			}
			if seen != tc.want {
				t.Fatalf("the inner handler saw synthetic=%v, want %v. The decision-shadow "+
					"observation sites read this off the context several layers down, and they "+
					"receive no request of their own (#3817).", seen, tc.want)
			}
		})
	}
}

// TestTheServedHandlerIsTheAssembledOne closes the gap the test above cannot
// see: buildAgentHandler could be correct and unused.
//
// initServerImmediately builds its handler inside a goroutine and hands it
// straight to ListenAndServe, so there is no value a test can reach. The wiring
// is therefore asserted structurally, on the source, which is the same shape
// site_version_census_test.go and the Authenticate-caller census use for facts
// that live in a call rather than in a value.
func TestTheServedHandlerIsTheAssembledOne(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatalf("parse run.go: %v", err)
	}

	var found, wrapped bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != "initServerImmediately" {
			return true
		}
		found = true
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "buildAgentHandler" {
				wrapped = true
			}
			return true
		})
		return true
	})

	if !found {
		t.Fatal("initServerImmediately is not in run.go any more; this census is guarding nothing. " +
			"Point it at whatever function now builds the served handler.")
	}
	if !wrapped {
		t.Fatal("initServerImmediately does not call buildAgentHandler. Whatever it serves instead " +
			"is not carrying sharedidentity.SyntheticProbeMiddleware, so the synthetic-probe " +
			"context value is never set and EVERY decision-shadow comparison on this binary - " +
			"canary included - is recorded as ORGANIC tenant traffic, into the volume the " +
			"ADR-065 coverage gate reads (#3817).")
	}
}

// TestTheSyntheticStampIsNotDuplicatedInTheAgent keeps the design's one claim
// honest: ONE stamping site, so there is nothing to keep in step.
//
// A second stamp is not a bug on its own - the value is idempotent - but it is
// the beginning of two definitions of one word, which is how the identity axis
// and this one would drift. If a second site is ever genuinely needed, this test
// is where the reason gets written down.
func TestTheSyntheticStampIsNotDuplicatedInTheAgent(t *testing.T) {
	sites := callSitesOf(t, "SyntheticProbeMiddleware")
	if len(sites) != 1 {
		t.Fatalf("SyntheticProbeMiddleware is CALLED at %d non-test sites in package agent (%v); "+
			"the design is ONE root wrap, which is why there is no per-handler census, and a "+
			"second stamping site is a second definition of one word. If a second is genuinely "+
			"needed, say why here.", len(sites), sites)
	}
	if !strings.HasPrefix(sites[0], "run.go:") {
		t.Fatalf("the single stamping site is %s, not run.go; the root wrap moved and "+
			"TestTheServedHandlerIsTheAssembledOne is pointed at the wrong function", sites[0])
	}
}

// callSitesOf returns "file.go:N" for every CALL of a selector with this name
// in every non-test Go file of this package.
//
// A call-site walk rather than a line grep, because the property is "the stamp
// is applied once" and a mention in a doc comment applies nothing. The grep
// version of this test failed on its own explanatory comment, which is the
// classic way a census ends up measuring its own prose.
func callSitesOf(t *testing.T, name string) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	var out []string
	scanned := 0
	for _, e := range entries {
		file := e.Name()
		if e.IsDir() || !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, parseErr := parser.ParseFile(fset, file, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", file, parseErr)
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
				out = append(out, fmt.Sprintf("%s:%d", file, fset.Position(call.Pos()).Line))
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("the walk parsed zero non-test Go files; it cannot vacuously report one site")
	}
	return out
}
