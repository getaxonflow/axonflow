// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"regexp"
	"testing"
)

// TestTheActivationTakesTheEditionBoundaryFromTheProcess reads the enforcer's
// own source and requires that the activation's edition-construct refusal and
// its profile are both the values the process's edition boundary returned,
// never a literal.
//
// It is the shared half of the agent's TestTheEnforcementSeamGatesTheConstructCheck.
// The edition is resolved from the licence in the process that holds it, and
// that half asserts the resolution; this half asserts that what it resolved is
// what the activation is built with. A literal `true` here turns a lapsed
// licence into an outage (an activation error is HTTP 503 on /api/v1/decide
// and a withheld response); a literal `false` makes the chokepoint decorative.
//
// A source census, not a behavioural test, for the agent half's reason: the
// behaviour is a negative at the far end of a long path, and the one
// expression is what decides it.
func TestTheActivationTakesTheEditionBoundaryFromTheProcess(t *testing.T) {
	const file = "enforcer.go"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := editionBoundaryWiring(src); err != nil {
		t.Fatalf("%s: %v", file, err)
	}

	// PLANTED POSITIVES: each mutant must be refused, or the census above is
	// satisfied by anything.
	for name, mutate := range map[string]func(string) string{
		"a literal true refusal": func(s string) string {
			return regexp.MustCompile(`RefuseConstructsOutsideEdition:\s*refuseOutsideEdition,`).ReplaceAllString(s, "RefuseConstructsOutsideEdition: true,")
		},
		"a literal false refusal": func(s string) string {
			return regexp.MustCompile(`RefuseConstructsOutsideEdition:\s*refuseOutsideEdition,`).ReplaceAllString(s, "RefuseConstructsOutsideEdition: false,")
		},
		"a profile not from the boundary": func(s string) string {
			return regexp.MustCompile(`(?m)^(\s*)Profile:\s*profile,`).ReplaceAllString(s, "${1}Profile: authoring.Profile{},")
		},
		"a boundary that is not the process's": func(s string) string {
			return regexp.MustCompile(`e\.editionBoundary\(ctx\)`).ReplaceAllString(s, "func(context.Context) (authoring.Profile, bool) { return authoring.Profile{}, true }(ctx)")
		},
	} {
		t.Run("planted "+name, func(t *testing.T) {
			mutant := mutate(string(src))
			if mutant == string(src) {
				t.Fatalf("the mutation did not apply, so this positive control proves nothing")
			}
			if err := editionBoundaryWiring([]byte(mutant)); err == nil {
				t.Fatalf("the census accepted %s", name)
			}
		})
	}
}

// editionBoundaryWiring reports why src does not build ActivationFor's
// activation.Inputs from the enforcer's editionBoundary, or nil when it does.
func editionBoundaryWiring(src []byte) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "enforcer.go", src, 0)
	if err != nil {
		return err
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "ActivationFor" && fd.Recv != nil {
			fn = fd
		}
	}
	if fn == nil {
		return fmt.Errorf("no Enforcer.ActivationFor method")
	}
	var profileVar, refuseVar string
	var profileVal, refuseVal string
	inputs := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == 2 && len(x.Rhs) == 1 && render(fset, x.Rhs[0]) == "e.editionBoundary(ctx)" {
				profileVar, refuseVar = render(fset, x.Lhs[0]), render(fset, x.Lhs[1])
			}
		case *ast.CompositeLit:
			sel, ok := x.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Inputs" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "activation" {
				return true
			}
			inputs++
			for _, elt := range x.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch render(fset, kv.Key) {
				case "Profile":
					profileVal = render(fset, kv.Value)
				case "RefuseConstructsOutsideEdition":
					refuseVal = render(fset, kv.Value)
				}
			}
		}
		return true
	})
	switch {
	case inputs != 1:
		return fmt.Errorf("ActivationFor builds %d activation.Inputs literals, want exactly one", inputs)
	case profileVar == "" || refuseVar == "":
		return fmt.Errorf("ActivationFor does not take its profile and refusal from e.editionBoundary(ctx)")
	case refuseVal != refuseVar:
		return fmt.Errorf("RefuseConstructsOutsideEdition is %q, want %q, the value the process's edition boundary returned", refuseVal, refuseVar)
	case profileVal != profileVar:
		return fmt.Errorf("Profile is %q, want %q, the profile the process's edition boundary returned", profileVal, profileVar)
	}
	return nil
}

func render(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, n); err != nil {
		return ""
	}
	return b.String()
}
