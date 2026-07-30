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

// TestEveryAuthenticateCallerStampsContext is the structural regression
// guard for the class of bug #2319 + its sibling fix in mcp_handler.go +
// proxy.go: every direct caller of Authenticate(r, ...) that proceeds to
// serve a request from within the agent process must stamp the four auth
// context keys (TenantID/OrgID/ClientID/AuthKind) so downstream readers
// of {Tenant,Org,Client}IDFromContext + AuthKindFromContext see the
// authenticated identity rather than the default fallback.
//
// Two canonical stamp shapes are accepted:
//   - apiAuthMiddleware (auth.go:569) writes the four keys inline via
//     context.WithValue. Treated as the canonical middleware path.
//   - All other Authenticate callers write through stampAuthContext
//     (run.go:160) which is the canonical helper extracted from PR #2315.
//
// Allowlisted exceptions (these do not stamp + the rationale is captured
// in code/comments):
//   - authenticator.go: defines Authenticate itself — no caller to stamp.
//   - mcp_server_handler.go::authenticateMCPSession: internal helper that
//     wraps Authenticate and returns *AuthResult (post-#2328 refactor) for
//     its callers to stamp. The helper itself does not serve a request.
//     Its 3 production callers (deleteMCPSession path, handleMCPInitialize)
//     stamp via stampAuthContext using the returned *AuthResult.
//     #3077 R3 renamed the body from authenticateMCPServerRequest, which is
//     now the 9-return convenience wrapper around it and calls Authenticate
//     only transitively — the allowlist follows the Authenticate call site,
//     not the old name, so the guard's coverage is unchanged.
//   - *_test.go files: tests drive Authenticate directly without serving
//     real downstream code; assertions on stamping live in dedicated tests.
//
// Scope: this test walks ONLY the top-level platform/agent/*.go files.
// Sub-packages under platform/agent/ (circuitbreaker, hitl, license,
// marketplace, node_enforcement, policy, rbi, sqli, connectors/) are
// NOT walked. None call Authenticate today; a future contributor who
// adds an Authenticate caller in a sub-package would silently pass this
// audit. Widen `dir` and/or recurse if/when that happens.
//
// Mutation test: removing the stampAuthContext call from any non-
// allowlisted Authenticate-calling function fails this test.
func TestEveryAuthenticateCallerStampsContext(t *testing.T) {
	// Allowlist: filenames OR file+function pairs that may call
	// Authenticate without stamping. File+function pairs use the form
	// "filename.go::funcName" so that an unrelated future function with
	// the same name in a different file does not silently inherit the
	// exception.
	allowFiles := map[string]string{
		"authenticator.go": "defines Authenticate itself",
	}
	allowFuncs := map[string]string{
		// #2328 (partial): the helper now returns *AuthResult (pos 8) so
		// callers CAN stamp. Two production callers stamp via
		// stampAuthContext (deleteMCPSession path + handleMCPInitialize).
		// The third caller — resolveMCPSession's fallback — discards the
		// AuthResult because the *http.Request lives in the caller's scope
		// (requireMCPAuth → handleMCPToolsList/Call/Ping). Stamping there
		// requires extending mcpSession to carry *Client + AuthKind so
		// cache-hit replay can re-stamp without re-authenticating. Filed
		// for a paired follow-up sub-session.
		"mcp_server_handler.go::authenticateMCPSession": "internal helper — wraps Authenticate and returns *AuthResult; not all callers stamp yet (resolveMCPSession fallback path is a known gap). #3077 R3: this is the renamed body of authenticateMCPServerRequest, which is now a wrapper that does not call Authenticate directly and so is not scanned.",
	}

	dir := "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read agent dir: %v", err)
	}

	fset := token.NewFileSet()
	var findings []string

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		if reason, ok := allowFiles[e.Name()]; ok {
			t.Logf("skipping %s — %s", e.Name(), reason)
			continue
		}
		path := filepath.Join(dir, e.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		// Walk each function in the file. For each function body, look
		// for direct calls to Authenticate(...) and verify the same
		// function body also calls stampAuthContext(...) or contains
		// the inline middleware-writer pattern
		// (context.WithValue(..., ContextKeyAuthKind, ...)).
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			fnName := fn.Name.Name
			qualified := e.Name() + "::" + fnName
			if reason, ok := allowFuncs[qualified]; ok {
				t.Logf("skipping %s — %s", qualified, reason)
				return true
			}

			var callsAuthenticate, callsStamp, writesAuthKindInline bool
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch callee := call.Fun.(type) {
				case *ast.Ident:
					switch callee.Name {
					case "Authenticate":
						callsAuthenticate = true
					case "stampAuthContext":
						callsStamp = true
					}
				case *ast.SelectorExpr:
					// context.WithValue(..., ContextKeyAuthKind, ...) — the
					// inline middleware-writer pattern in apiAuthMiddleware.
					if id, ok := callee.X.(*ast.Ident); ok && id.Name == "context" && callee.Sel.Name == "WithValue" {
						if len(call.Args) >= 2 {
							if keyID, ok := call.Args[1].(*ast.Ident); ok && keyID.Name == "ContextKeyAuthKind" {
								writesAuthKindInline = true
							}
						}
					}
				}
				return true
			})

			if callsAuthenticate && !callsStamp && !writesAuthKindInline {
				findings = append(findings, e.Name()+"::"+fnName+
					" calls Authenticate(...) but does not call stampAuthContext "+
					"or write ContextKeyAuthKind inline — close the gap by adding "+
					"`r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))` "+
					"after the Authenticate err-check, or extend allowFuncs with a justification.")
			}
			return true
		})
	}

	if len(findings) > 0 {
		t.Errorf("Authenticate callers missing context-stamp (sibling of #2319):\n  - %s",
			strings.Join(findings, "\n  - "))
	}
}
