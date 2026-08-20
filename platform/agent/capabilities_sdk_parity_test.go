// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// The agent and the orchestrator each serve /health with their own copy of the
// SDK min/recommended maps. RUNBOOK_RELEASE_PREP.md Step 2 lists "agent vs
// orchestrator drift" as failure mode 1 and records that the orchestrator copy
// HAS drifted in a real train. Until now nothing enforced it: the orchestrator
// carries a literal pin test (TestSDKCompatibilityPinnedToReleaseTrain) while
// the agent side only asserted the maps were non-empty, so a bump applied to
// one file and not the other produced two different answers on the two ports
// with zero CI signal, and the check lived only in a human's checklist.
//
// The PLUGIN maps do not need this: since #3229 both planes read them from
// platform/shared/plugincompat, so that half is structurally closed. The SDK
// maps are still per-file literals, so this test is the guard for them.
//
// It compares the SOURCE literals rather than calling both constructors,
// because agent and orchestrator are separate packages and the orchestrator's
// getSDKCompatibility is unexported. Reading the literals is also the stronger
// assertion: it fails on a drift introduced anywhere in either file, including
// one a future refactor hides behind a helper.
func TestSDKCompatibilityMapsMatchOrchestrator(t *testing.T) {
	const (
		recommended = "RecommendedSDKVersion"
		minimum     = "MinSDKVersion"
	)

	agentMaps := parseVersionMaps(t, "capabilities.go", recommended, minimum)
	orchMaps := parseVersionMaps(t, filepath.Join("..", "orchestrator", "capabilities.go"), recommended, minimum)

	for _, field := range []string{recommended, minimum} {
		a, ok := agentMaps[field]
		if !ok {
			t.Fatalf("agent capabilities.go: no %s map literal found; the parity guard cannot run vacuously", field)
		}
		o, ok := orchMaps[field]
		if !ok {
			t.Fatalf("orchestrator capabilities.go: no %s map literal found; the parity guard cannot run vacuously", field)
		}
		// Anti-vacuity: an empty map on both sides would compare "equal".
		if len(a) == 0 {
			t.Fatalf("agent %s parsed as empty; the parser is not reading what it claims to", field)
		}
		if len(a) != len(o) {
			t.Errorf("%s: agent has %d entries, orchestrator has %d (agent=%v orchestrator=%v)",
				field, len(a), len(o), a, o)
			continue
		}
		for lang, want := range a {
			if got, ok := o[lang]; !ok {
				t.Errorf("%s: orchestrator is missing key %q (agent has %q)", field, lang, want)
			} else if got != want {
				t.Errorf("%s[%q]: agent = %q, orchestrator = %q; the two /health ports would disagree",
					field, lang, want, got)
			}
		}
	}
}

// parseVersionMaps returns, for each requested field name, the string->string
// pairs of the map composite literal assigned to it. A field assigned anything
// other than a literal map of string constants is deliberately not reported, so
// the caller's "no map literal found" check fires rather than a silent pass.
func parseVersionMaps(t *testing.T, path string, fields ...string) map[string]map[string]string {
	t.Helper()

	wanted := make(map[string]bool, len(fields))
	for _, f := range fields {
		wanted[f] = true
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	out := make(map[string]map[string]string)
	ast.Inspect(file, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		ident, ok := kv.Key.(*ast.Ident)
		if !ok || !wanted[ident.Name] {
			return true
		}
		lit, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			return true
		}
		pairs := make(map[string]string, len(lit.Elts))
		for _, elt := range lit.Elts {
			entry, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			k, kOK := stringLit(entry.Key)
			v, vOK := stringLit(entry.Value)
			if kOK && vOK {
				pairs[k] = v
			}
		}
		if len(pairs) > 0 {
			out[ident.Name] = pairs
		}
		return true
	})
	return out
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}
