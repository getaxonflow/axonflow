// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestEveryResolveTokenCallerStampsTheSyntheticProbe is the census that keeps
// #3602's canary tag honest at the one adapter call site that has no request
// of its own.
//
// # THE GAP THIS CLOSES
//
// sharedidentity.ResolveToken is the SHARED choke point for the per-user token
// paths (hs256 AND oidc on the fleet/MCP plane). Its own doc says "every caller
// of ResolveToken is covered by construction, including one added tomorrow" -
// true for the counterfactual RECORD, because the adapter is wired inside the
// function. It is NOT automatically true for the synthetic tag, because that
// fact lives on the HTTP request and the resolver receives only a context and a
// token.
//
// So the tag travels on the context, and a caller that forgets to stamp it
// silently files probe traffic under synthetic="false" - into the ORGANIC
// volume the coverage gate reads. That is a wrong number, not a crash, and it
// would be found by nobody.
//
// R3 round 1 on #3607 found exactly this: four of five adapter call sites set
// Synthetic and the fifth - this one, the shared choke point - did not. A
// census is the answer rather than a comment, for the same reason
// TestEveryAuthenticateCallerStampsContext is.
//
// # WHY AN AST WALK AND NOT A GREP
//
// A grep for the two names on the same LINE is beaten by an ordinary
// reformat; a grep for both anywhere in the FILE is beaten by two unrelated
// functions. The unit is the function body, which is what an AST walk gives
// and a regex does not.
func TestEveryResolveTokenCallerStampsTheSyntheticProbe(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	var findings []string
	scanned, callersFound := 0, 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		f, parseErr := parser.ParseFile(fset, name, src, parser.ParseComments)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		scanned++

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			var callsResolve, callsStamp bool
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "ResolveToken":
					callsResolve = true
				case "ContextWithSyntheticProbe":
					callsStamp = true
				}
				return true
			})
			if callsResolve {
				callersFound++
				if !callsStamp {
					findings = append(findings, name+"::"+fn.Name.Name)
				}
			}
			return true
		})
	}

	// Anti-vacuity, both axes. A package that parsed no files, or that
	// contained no ResolveToken caller at all, would report a clean sweep
	// having checked nothing - and the second is the likelier accident, since
	// a rename of the function would produce it silently.
	if scanned == 0 {
		t.Fatal("the census parsed zero non-test Go files; it cannot vacuously pass")
	}
	if callersFound == 0 {
		t.Fatal("the census found NO caller of ResolveToken in package agent. Either the " +
			"per-user token paths moved, or the call is now spelled in a way this walk does " +
			"not recognise. Either way this test is no longer guarding anything.")
	}

	if len(findings) > 0 {
		t.Errorf("these functions call sharedidentity.ResolveToken without first calling "+
			"sharedidentity.ContextWithSyntheticProbe:\n  - %s\n\n"+
			"Fix by passing sharedidentity.ContextWithSyntheticProbe(r.Context(), auth.Synthetic) "+
			"as the context. Without it, canary comparisons on the per-user token paths are filed "+
			"as ORGANIC traffic and inflate the volume the ADR-065 coverage gate reads (#3602).",
			strings.Join(findings, "\n  - "))
	}
}
