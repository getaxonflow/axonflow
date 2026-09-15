// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"testing"
)

// TestTheEnforcementSeamGatesTheConstructCheck reads the seam's own source and
// requires that the edition-construct refusal is wired to the RESOLVED gate
// rather than to a literal.
//
// # WHY A SOURCE CENSUS RATHER THAN A BEHAVIOURAL TEST
//
// The behaviour this pins is a NEGATIVE at the far end of a long path: a
// deployment whose licence has lapsed, whose operator has declared a licence
// transition, and whose active document spends an Enterprise construct must
// keep getting decisions. Driving that in-process needs a booted enforcer, a
// signed artifact, a licence read and an environment - and the assertion would
// still be "no 503 happened", which passes for a hundred unrelated reasons.
//
// What actually decides it is one expression. If it is ever replaced by `true`,
// every such deployment gets HTTP 503 on /api/v1/decide and withheld MCP
// responses (decision_handler.go, mcp_response_enforcing_seam.go) - the outage
// LicenceTransitionMode exists to prevent, reached through the seam instead of
// the healthcheck (#4094). If it is replaced by `false`, the chokepoint is
// decorative and an imported or directly-inserted document is enforced
// unchecked. So the expression is what this test reads.
//
// # TWO ARMS, SINCE THE ENFORCER MOVED TO platform/shared/anchoredenforcer
//
// The edition is resolved from the licence in THIS process, so the expression
// lives here, in seamEditionBoundary, and this arm reads it and requires that
// the enforcer is built with it. The activation that consumes it is the shared
// enforcer's, and its arm is TestTheActivationTakesTheEditionBoundaryFromTheProcess
// in that package. Each arm plants its own positives.
//
// It is deliberately NOT a grep: a grep for the call would be satisfied by the
// name appearing in a comment, and this file's own comments name it repeatedly.
func TestTheEnforcementSeamGatesTheConstructCheck(t *testing.T) {
	const file = "decision_enforcing_seam.go"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("reading %s: %v", file, err)
	}
	if err := seamEditionBoundaryWiring(src); err != nil {
		t.Fatalf("%s: %v", file, err)
	}

	// PLANTED POSITIVES: each mutant must be refused, or the census above is
	// satisfied by anything.
	for name, mutate := range map[string]func(string) string{
		"a literal true refusal": func(s string) string {
			return regexp.MustCompile(`return edition\.Profile, edition\.EnforcesConstructBoundary\(\)`).ReplaceAllString(s, "return edition.Profile, true")
		},
		"a literal false refusal": func(s string) string {
			return regexp.MustCompile(`return edition\.Profile, edition\.EnforcesConstructBoundary\(\)`).ReplaceAllString(s, "return edition.Profile, false")
		},
		"a profile that is not the resolved one": func(s string) string {
			return regexp.MustCompile(`return edition\.Profile, `).ReplaceAllString(s, "return authoring.Profile{}, ")
		},
		"an enforcer built with another boundary": func(s string) string {
			return regexp.MustCompile(`EditionBoundary:\s*seamEditionBoundary,`).ReplaceAllString(s, "EditionBoundary: func(context.Context) (authoring.Profile, bool) { return authoring.Profile{}, true },")
		},
	} {
		t.Run("planted "+name, func(t *testing.T) {
			mutant := mutate(string(src))
			if mutant == string(src) {
				t.Fatalf("the mutation did not apply, so this positive control proves nothing")
			}
			if err := seamEditionBoundaryWiring([]byte(mutant)); err == nil {
				t.Fatalf("the census accepted %s", name)
			}
		})
	}
}

// seamEditionBoundaryWiring reports why src does not resolve the edition
// boundary from the licence and build the enforcer with it, or nil when it does.
func seamEditionBoundaryWiring(src []byte) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "decision_enforcing_seam.go", src, 0)
	if err != nil {
		return err
	}
	var (
		resolved, returned bool
		results            []string
		builtWith          []string
	)
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			if x.Name.Name != "seamEditionBoundary" || x.Recv != nil {
				return true
			}
			ast.Inspect(x.Body, func(m ast.Node) bool {
				switch y := m.(type) {
				case *ast.AssignStmt:
					if len(y.Lhs) == 1 && len(y.Rhs) == 1 && exprText(fset, y.Lhs[0]) == "edition" && exprText(fset, y.Rhs[0]) == "authoringedition.Resolve(ctx)" {
						resolved = true
					}
				case *ast.ReturnStmt:
					returned = true
					results = results[:0]
					for _, r := range y.Results {
						results = append(results, exprText(fset, r))
					}
				}
				return true
			})
			return false
		case *ast.CompositeLit:
			sel, ok := x.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Options" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "anchoredenforcer" {
				return true
			}
			for _, elt := range x.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok && exprText(fset, kv.Key) == "EditionBoundary" {
					builtWith = append(builtWith, exprText(fset, kv.Value))
				}
			}
		}
		return true
	})
	const want = "edition.EnforcesConstructBoundary()"
	switch {
	case !resolved:
		return fmt.Errorf("seamEditionBoundary does not resolve `edition := authoringedition.Resolve(ctx)`")
	case !returned || len(results) != 2:
		return fmt.Errorf("seamEditionBoundary returns %v, want (edition.Profile, %s)", results, want)
	case results[1] != want:
		return fmt.Errorf("seamEditionBoundary wires the refusal to %s, want %s.\n"+
			"A literal `true` turns a lapsed licence into an outage: an activation error on this path is HTTP 503 "+
			"on /api/v1/decide and a withheld MCP response, which is exactly what LicenceTransitionMode exists to "+
			"prevent (#4094). A literal `false` makes the chokepoint decorative", results[1], want)
	case results[0] != "edition.Profile":
		return fmt.Errorf("seamEditionBoundary returns the profile %s, want edition.Profile; the check would refuse the INPUT on "+
			"every activation rather than the document", results[0])
	case len(builtWith) != 1 || builtWith[0] != "seamEditionBoundary":
		return fmt.Errorf("the enforcer is built with EditionBoundary %v, want exactly seamEditionBoundary; any other boundary is "+
			"not the one this process resolved from its licence", builtWith)
	}
	return nil
}

// exprText is admission_nodb_census_test.go's renderer, reused deliberately:
// two spellings of "render this expression back to source" in one package is
// how two censuses come to disagree about what the source says.
