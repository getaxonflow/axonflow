// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestEveryFamilyHasExactlyOneAlgebra pins ADR-065's "one algebra per family"
// in the form that survives consolidation (#3891): the algebra lives in
// platform/decision/contract, and this package has none.
//
// WHAT THIS IS, AND WHAT IT IS NOT. An independent review planted ten evasions
// of an earlier version of this check and every one returned zero findings -
// an if/else chain on the family, a tagless switch, a map filled in `init()`,
// `var`-backed keys, a type alias, `"disc" + "losure"`, `strings.EqualFold`,
// a rank table split under the threshold. That is not a bug that was fixed; it
// is the ceiling of the technique. An AST heuristic cannot prove the absence
// of a dispatch that a determined author is willing to spell differently, and
// this comment used to claim it did.
//
// So: THIS IS A TRIPWIRE FOR ACCIDENTAL REINTRODUCTION, not a gate against a
// determined one. It refuses exactly the shapes enumerated below and nothing
// more, and each is proved on a planted positive so the check cannot silently
// stop seeing them:
//
//   - a `switch` with a case naming a family, whether as a contract identifier
//     or as a bare string literal or package-scoped string constant;
//   - a composite literal keyed by 2+ family names or 3+ obligation type names,
//     whatever its key type is declared as, including when the constants and
//     the table are in DIFFERENT FILES of this package;
//   - any reference to a contract.Family* identifier other than FamilyOf.
//
// THE ACTUAL GATE IS BEHAVIOURAL and lives in two places that cannot be spelled
// around, because they read results rather than source:
// TestNoNumericRankingAcrossFamilies composes one obligation of every family
// and requires all of them to survive, which a severity ranking cannot do; and
// consumes_algebra_test.go drives the same LITERALS through Plan that
// contract's golden table pins, so a planner that started deciding composition
// itself would have to reproduce the canonical answer exactly to stay green.
func TestEveryFamilyHasExactlyOneAlgebra(t *testing.T) {
	typesPerFamily := map[contract.ObligationFamily]int{}
	for _, typ := range contract.AllObligationTypes() {
		fam, err := contract.FamilyOf(typ)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		typesPerFamily[fam]++
	}
	for _, fam := range contract.AllObligationFamilies() {
		if typesPerFamily[fam] == 0 {
			t.Errorf("family %q owns no type; its algebra could never run", fam)
		}
	}

	findings := familyDispatchIn(t, packageSources(t))
	if len(findings) != 0 {
		t.Fatalf("this package decides composition semantics again:\n  %s\n"+
			"The ONE algebra is contract.ComposeObligations; the planner consumes its outcome and must not dispatch on a family.",
			strings.Join(findings, "\n  "))
	}
}

// TestFamilyDispatchDetectorSeesAPlantedSwitch is the positive control: the
// detector above must report each of the three shapes when they are present,
// or its clean report means nothing.
func TestFamilyDispatchDetectorSeesAPlantedSwitch(t *testing.T) {
	planted := map[string]string{
		"planted_switch.go": `package obligation
import "axonflow/platform/decision/contract"
func plantedSwitch(fam contract.ObligationFamily) int {
	switch fam {
	case contract.FamilyDisclosure:
		return 1
	}
	return 0
}
`,
		"planted_map.go": `package obligation
import "axonflow/platform/decision/contract"
var plantedTable = map[contract.ObligationFamily]func() error{}
`,
		"planted_alias.go": `package obligation
import c "axonflow/platform/decision/contract"
var plantedFamily = c.FamilyRouting
`,
	}
	for name, src := range planted {
		findings := familyDispatchIn(t, map[string]string{name: src})
		if len(findings) == 0 {
			t.Errorf("%s: the detector saw nothing in a file that dispatches on a family; every clean report it gives is worthless", name)
		}
	}
	// THE FILE THAT DEFEATED THE FIRST VERSION OF THIS GUARD, kept verbatim.
	// It imports nothing from contract and names no contract identifier: a
	// local string type carries the family dispatch table and a bare
	// map[string]int carries a duplicated disclosure rank. The guard skipped
	// the file entirely and reported clean. Each of the three shapes is
	// asserted separately, so a future narrowing that catches only one of them
	// is a failure rather than a pass.
	for _, planted := range []struct {
		name string
		src  string
	}{
		{"a local family type keying a dispatch table", `package obligation
type famKey string
const (famDisclosure famKey = "disclosure"; famApproval famKey = "approval")
var plantedAlgebras = map[famKey]func() int{famDisclosure: func() int { return 1 }, famApproval: func() int { return 2 }}
`},
		{"a duplicated disclosure rank keyed by type name", `package obligation
var plantedRank = map[string]int{"field_remove": 0, "field_redact": 1, "field_hash": 2, "field_mask": 3, "field_annotate": 4}
`},
		{"a switch on a bare string naming families", `package obligation
func plantedDispatch(f string) int {
	switch f {
	case "disclosure":
		return 1
	case "approval":
		return 2
	}
	return 0
}
`},
	} {
		if findings := familyDispatchIn(t, map[string]string{"planted.go": planted.src}); len(findings) == 0 {
			t.Errorf("%s: the detector saw nothing in a file that imports nothing from contract. This is the exact hole an independent review proved: a guard that can only see the spelling it expects is the shape it exists to prevent.", planted.name)
		}
	}

	// THE SPLIT-FILE EVASION, which defeated the second version of this guard.
	// The constant lives in one file and the table in another; Go constants are
	// package-scoped, so this is one dispatch table however it is spread.
	if findings := familyDispatchIn(t, map[string]string{
		"consts.go": `package obligation
type famKey string
const famDisclosure famKey = "disclosure"
const famApproval famKey = "approval"
`,
		"table.go": `package obligation
var plantedSplit = map[famKey]func() int{famDisclosure: func() int { return 1 }, famApproval: func() int { return 2 }}
`,
	}); len(findings) == 0 {
		t.Error("the detector saw nothing when the constants and the table were split across two files of ONE package. Go constants are package-scoped; resolving them per file is a hole an independent review walked through.")
	}

	// And the detector is quiet on a file that only names a TYPE, which the
	// planner legitimately does everywhere.
	quiet := familyDispatchIn(t, map[string]string{"quiet.go": `package obligation
import "axonflow/platform/decision/contract"
var quietType = contract.ObFieldRedact
func quietFn(o contract.Obligation) (contract.ObligationFamily, error) { return contract.FamilyOf(o.Type) }
`})
	if len(quiet) != 0 {
		t.Errorf("the detector flags a file that merely names a type or asks FamilyOf: %v", quiet)
	}
}

// packageSources reads every non-test Go file of this package.
func packageSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = string(src)
	}
	if len(out) == 0 {
		t.Fatal("no package sources found; the guard would be vacuous")
	}
	return out
}

// familyDispatchIn parses each source and returns a finding per family
// dispatch it contains. Import aliases are resolved from the file's own import
// declarations, so `c.FamilyRouting` is seen as well as `contract.FamilyRouting`.
func familyDispatchIn(t *testing.T, sources map[string]string) []string {
	t.Helper()
	var findings []string
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)

	// PASS ONE: collect string constants across the WHOLE PACKAGE.
	//
	// Go constants are package-scoped, so a dispatch table in one file can be
	// keyed by a constant declared in another. The first version of this guard
	// resolved constants per file and an independent review defeated it by
	// splitting its own planted evasion across two files. Collecting first is
	// both more correct and strictly stronger.
	constValue := map[string]string{}
	parsed := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, name := range names {
		f, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed[name] = f
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						constValue[ident.Name] = strings.Trim(bl.Value, "`\"")
					}
				}
			}
		}
	}

	// PASS TWO: scan.
	for _, name := range names {
		f := parsed[name]
		contractAliases := map[string]bool{}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) != "axonflow/platform/decision/contract" {
				continue
			}
			alias := "contract"
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			contractAliases[alias] = true
		}
		// NO FILE-LEVEL SKIP. An earlier version of this guard returned here
		// when the file imported nothing from contract, and an independent
		// review defeated it in one file: a local `type famKey string` with a
		// `map[famKey]func() int` dispatch table and a duplicated
		// `map[string]int` disclosure rank sat in the package and the guard
		// was silent, because neither names a contract identifier. A guard
		// that can only see the spelling it expects is the shape it exists to
		// prevent. The literal-based checks below run on EVERY file.
		_ = contractAliases
		isFamilyIdent := func(e ast.Expr) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || !contractAliases[pkg.Name] {
				return false
			}
			return strings.HasPrefix(sel.Sel.Name, "Family") && sel.Sel.Name != "FamilyOf"
		}
		isFamilyType := func(e ast.Expr) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			pkg, ok := sel.X.(*ast.Ident)
			return ok && contractAliases[pkg.Name] && sel.Sel.Name == "ObligationFamily"
		}
		// The canonical family and type NAMES, as string literals. A dispatch
		// table keyed by a LOCAL type still has to spell them.
		familyNames := map[string]bool{}
		for _, fam := range contract.AllObligationFamilies() {
			familyNames[string(fam)] = true
		}
		typeNames := map[string]bool{}
		for _, typ := range contract.AllObligationTypes() {
			typeNames[string(typ)] = true
		}
		litValue := func(e ast.Expr) (string, bool) {
			switch v := e.(type) {
			case *ast.BasicLit:
				if v.Kind != token.STRING {
					return "", false
				}
				return strings.Trim(v.Value, "`\""), true
			case *ast.Ident:
				if got, ok := constValue[v.Name]; ok {
					return got, true
				}
			}
			return "", false
		}
		// countNamed reports how many of the given literal expressions name a
		// member of `want`. Two or more is a table, not a mention.
		countNamed := func(exprs []ast.Expr, want map[string]bool) int {
			n := 0
			for _, e := range exprs {
				if v, ok := litValue(e); ok && want[v] {
					n++
				}
			}
			return n
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				// A map literal whose KEYS spell two or more family names, or
				// three or more obligation type names, is a dispatch table or
				// a rank table however its key type is declared.
				var keys []ast.Expr
				for _, elt := range x.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						keys = append(keys, kv.Key)
					}
				}
				if len(keys) == 0 {
					return true
				}
				if countNamed(keys, familyNames) >= 2 {
					findings = append(findings, name+": "+fset.Position(x.Pos()).String()+": composite literal keyed by 2+ obligation FAMILY names (a family dispatch table, whatever its key type is declared as)")
				}
				if countNamed(keys, typeNames) >= 3 {
					findings = append(findings, name+": "+fset.Position(x.Pos()).String()+": composite literal keyed by 3+ obligation TYPE names (a second disclosure rank or family map)")
				}
			case *ast.SwitchStmt:
				for _, stmt := range x.Body.List {
					cc, ok := stmt.(*ast.CaseClause)
					if !ok {
						continue
					}
					for _, e := range cc.List {
						if isFamilyIdent(e) {
							findings = append(findings, name+": "+fset.Position(x.Pos()).String()+": switch with a family case")
							return false
						}
					}
					if countNamed(cc.List, familyNames) >= 1 {
						findings = append(findings, name+": "+fset.Position(x.Pos()).String()+": switch with a case naming an obligation family as a string literal")
						return false
					}
				}
			case *ast.MapType:
				if isFamilyType(x.Key) {
					findings = append(findings, name+": "+fset.Position(x.Pos()).String()+": map keyed by contract.ObligationFamily")
				}
			case *ast.SelectorExpr:
				if isFamilyIdent(x) {
					findings = append(findings, name+": "+fset.Position(x.Pos()).String()+": references "+x.Sel.Name)
				}
			}
			return true
		})
	}
	return findings
}
