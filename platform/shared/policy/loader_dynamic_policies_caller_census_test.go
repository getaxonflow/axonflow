// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestCrossOrgDynamicPolicyReadersHaveNoUnauditedSecondCaller is the #3322
// item 5 follow-up to Saurabh's #3319 review of the RLS read allowlist
// (platform/agent/rls_read_audit_test.go, rlsReadAllowlist entries for
// "platform/shared/policy/loader.go::CountAllDynamicPolicies" and
// "::RefreshDynamicPolicies").
//
// RefreshDynamicPolicies and CountAllDynamicPolicies (loader.go) take a
// *sql.DB directly rather than resolving their own pool — their safety is a
// CALLER CONTRACT ("pass a cross-org/BYPASSRLS pool"), not something the
// compiler, or the RLS read audit's AST walker, can verify through a
// parameter. The allowlist entries justify today's shape by grep: exactly
// one caller, DatabaseDynamicPolicyEngine (platform/orchestrator/
// db_dynamic_policies.go), which always passes e.crossOrgDB(). Nothing
// stops a second, unaudited caller anywhere else in this module — including
// platform/agent, which also imports this package — from passing an
// app-role-scoped pool and silently reproducing the #3039 zero-row-
// through-RLS class with no red build, no log line, nothing.
//
// This test pins the single-caller invariant the allowlist entries assert
// only in prose: it walks every non-test .go file under platform/ +
// ee/platform/ and fails if either function is called from anywhere other
// than the one (file, enclosing-function) site recorded in
// wantSoleDynamicPolicyReaderCaller. A new call site — a second caller
// acquiring one of these functions — turns this test red, forcing a
// deliberate decision (prove the new caller's pool is genuinely cross-org,
// then update both this test and the allowlist justification) instead of
// letting the exposure ship unnoticed.
func TestCrossOrgDynamicPolicyReadersHaveNoUnauditedSecondCaller(t *testing.T) {
	repoRoot, err := findDynamicPolicyCallerCensusRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	callers := map[string]map[string]bool{
		"CountAllDynamicPolicies": {},
		"RefreshDynamicPolicies":  {},
	}

	scanDirs := []string{
		filepath.Join(repoRoot, "platform"),
		filepath.Join(repoRoot, "ee", "platform"),
	}

	for _, root := range scanDirs {
		if _, statErr := os.Stat(root); statErr != nil {
			if os.IsNotExist(statErr) {
				continue // ee/platform absent on a community-sync checkout
			}
			t.Fatalf("stat %s: %v", root, statErr)
		}

		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", ".claude":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)

			src, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("read %s: %v", rel, readErr)
			}
			fset := token.NewFileSet()
			f, parseErr := parser.ParseFile(fset, path, src, 0)
			if parseErr != nil {
				t.Fatalf("parse %s: %v", rel, parseErr)
			}

			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				fnName := fn.Name.Name
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					name := dynamicPolicyReaderCalleeName(call)
					if sites, tracked := callers[name]; tracked {
						sites[rel+"::"+fnName] = true
					}
					return true
				})
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", root, walkErr)
		}
	}

	names := make([]string, 0, len(wantSoleDynamicPolicyReaderCaller))
	for name := range wantSoleDynamicPolicyReaderCaller {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		wantKey := wantSoleDynamicPolicyReaderCaller[name]
		sites := callers[name]

		if !sites[wantKey] {
			t.Errorf("%s: expected sole caller %s not found (found call sites: %v) — the known caller moved; "+
				"update wantSoleDynamicPolicyReaderCaller deliberately rather than let this check go stale",
				name, wantKey, sortedKeys(sites))
			continue
		}
		if len(sites) > 1 {
			extra := sortedKeys(sites)
			t.Errorf("%s acquired a SECOND caller beyond %s: %v. "+
				"This function takes *sql.DB directly on a caller CONTRACT (\"pass a cross-org/BYPASSRLS pool\") "+
				"that the RLS read audit's AST walker cannot verify through a parameter — an app-role-scoped pool "+
				"here reproduces the #3039 zero-row-through-RLS class silently. Verify the new caller genuinely "+
				"passes a cross-org pool, then update BOTH wantSoleDynamicPolicyReaderCaller here AND the "+
				"allowlist justification at platform/agent/rls_read_audit_test.go (rlsReadAllowlist, the "+
				"loader.go::%s entry).", name, wantKey, extra, name)
		}
	}
}

// wantSoleDynamicPolicyReaderCaller is the single production call site each
// function is allowlisted for today (verified by grep at #3319/#3322 time —
// see platform/agent/rls_read_audit_test.go's rlsReadAllowlist entries for
// the same two functions).
var wantSoleDynamicPolicyReaderCaller = map[string]string{
	"CountAllDynamicPolicies": "platform/orchestrator/db_dynamic_policies.go::seedDefaultData",
	"RefreshDynamicPolicies":  "platform/orchestrator/db_dynamic_policies.go::refreshPolicies",
}

// dynamicPolicyReaderCalleeName returns the identifier name of a call
// expression's function -- "Foo" for both Foo(...) and pkg.Foo(...) -- or ""
// when the callee is not a simple identifier/selector (a method value, a
// call through a field, etc.), which none of this file's tracked functions
// are ever invoked as.
func dynamicPolicyReaderCalleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	default:
		return ""
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

// findDynamicPolicyCallerCensusRepoRoot walks up from the working directory
// to the repo root, anchored on the presence of platform/. Duplicated from
// platform/agent/rls_write_audit_test.go's unexported findRepoRoot — this
// test lives in a different package and that helper is not reusable across
// packages.
func findDynamicPolicyCallerCensusRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		if st, statErr := os.Stat(filepath.Join(dir, "platform")); statErr == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
