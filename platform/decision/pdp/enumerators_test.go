package pdp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The enumerators in this package exist so the layer above can walk the
// authoring vocabulary rather than restate it: the save-time check relay, the
// published JSON Schema and the mutation harness all derive their lists from
// them. That only works while the enumerator IS the declaration. A hand
// maintained list that has fallen one value behind is worse than no list,
// because everything downstream keeps reporting complete coverage of a set that
// is missing a member, and the missing member is the new one nobody has tested.
//
// The gates below therefore do not compare an enumerator against a second list
// written in a test. They parse THIS PACKAGE'S SOURCE, collect every constant
// of the relevant type, and hold the enumerator to what the compiler actually
// declares.

// constantsOfType returns the VALUES of every top-level constant in this
// package declared with the given type name.
func constantsOfType(t *testing.T, typeName string) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the package source: %v", err)
	}
	var out []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				var currentType string
				for _, spec := range gen.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					// A const block carries the type on the first spec that
					// names one, and later specs inherit it only when they have
					// no values of their own. Both forms appear in this package.
					if ident, ok := vs.Type.(*ast.Ident); ok {
						currentType = ident.Name
					} else if vs.Type == nil && len(vs.Values) == 0 {
						// inherits the previous spec's type and value
					} else if vs.Type == nil {
						currentType = ""
					}
					if currentType != typeName {
						continue
					}
					for _, v := range vs.Values {
						lit, ok := v.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						s, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatalf("unquoting %s: %v", lit.Value, err)
						}
						out = append(out, s)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// enumeratorProblems is a PURE function returning what is wrong, rather than a
// helper that fails a test directly.
//
// That shape is what lets the control below observe its refusal. A helper that
// called t.Fatalf could only be exercised by handing it a synthetic *testing.T,
// which unwinds the calling goroutine and takes the control with it, so the one
// branch that guarantees every gate here is non-vacuous would itself be the one
// branch nothing could check.
func enumeratorProblems(typeName string, declared, enumerated []string, exempt ...string) []string {
	if len(declared) == 0 {
		return []string{fmt.Sprintf("no constants of type %s were found in the package source, so this gate is asserting nothing", typeName)}
	}
	skip := map[string]struct{}{}
	for _, e := range exempt {
		skip[e] = struct{}{}
	}
	have := map[string]struct{}{}
	for _, v := range enumerated {
		have[v] = struct{}{}
	}
	var problems []string
	for _, v := range declared {
		if _, ok := skip[v]; ok {
			if _, listed := have[v]; listed {
				problems = append(problems, fmt.Sprintf("%s value %q is exempt from the enumerator and is listed by it", typeName, v))
			}
			continue
		}
		if _, ok := have[v]; !ok {
			problems = append(problems, fmt.Sprintf("%s value %q is declared in this package and is not returned by its enumerator", typeName, v))
		}
	}
	for _, v := range enumerated {
		found := false
		for _, d := range declared {
			if d == v {
				found = true
			}
		}
		if !found {
			problems = append(problems, fmt.Sprintf("the %s enumerator returns %q, which this package does not declare", typeName, v))
		}
	}
	sort.Strings(problems)
	return problems
}

func assertEnumerates(t *testing.T, typeName string, declared []string, enumerated []string, exempt ...string) {
	t.Helper()
	for _, p := range enumeratorProblems(typeName, declared, enumerated, exempt...) {
		t.Error(p)
	}
}

func TestAllValueTypesEnumeratesEveryDeclaredValueType(t *testing.T) {
	assertEnumerates(t, "ValueType", constantsOfType(t, "ValueType"), stringSlice(AllValueTypes()))
}

func TestAllCompareOpsEnumeratesEveryDeclaredOperator(t *testing.T) {
	assertEnumerates(t, "CompareOp", constantsOfType(t, "CompareOp"), stringSlice(AllCompareOps()))
}

func TestAllCondKindsEnumeratesEveryDeclaredKind(t *testing.T) {
	assertEnumerates(t, "CondKind", constantsOfType(t, "CondKind"), stringSlice(AllCondKinds()))
}

func TestAllRootsEnumeratesEveryDeclaredRoot(t *testing.T) {
	assertEnumerates(t, "Root", constantsOfType(t, "Root"), stringSlice(AllRoots()))
}

// TestAllAbsenceHandlingsEnumeratesEveryDeclarableHandling exempts the zero
// value ON PURPOSE, and the exemption is asserted rather than assumed:
// AbsentUnspecified is the absence of a declaration, not one of the choices, and
// a schema offering it as an enum member would invite an author to select the
// thing the validator exists to refuse.
func TestAllAbsenceHandlingsEnumeratesEveryDeclarableHandling(t *testing.T) {
	assertEnumerates(t, "AbsenceHandling", constantsOfType(t, "AbsenceHandling"),
		stringSlice(AllAbsenceHandlings()), string(AbsentUnspecified))
}

// TestAllRulesEnumeratesEveryDeclaredRule is the one that matters most, because
// the layer above renders an operator-facing explanation per rule and holds its
// table to this list. A rule declared here and missing from AllRules would
// reach a portal as a refusal whose explanation says the explanation is
// missing.
func TestAllRulesEnumeratesEveryDeclaredRule(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "policy.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var declared []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Rule") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				declared = append(declared, s)
			}
		}
	}
	sort.Strings(declared)
	if len(declared) < 10 {
		t.Fatalf("only %d Rule constants were found in policy.go, which is fewer than this validator declares; the scan has stopped working", len(declared))
	}
	assertEnumerates(t, "Rule", declared, AllRules())
}

func stringSlice[T ~string](in []T) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, string(v))
	}
	return out
}

// TestTheEnumeratorScanCanFail is the anti-vacuity control for the scan itself.
//
// Every gate above is a comparison against a list the scan produced, so a scan
// that silently returned nothing would report every enumerator as complete. The
// assertEnumerates helper refuses an empty declared set, and this is what proves
// the refusal fires rather than being an unreachable branch.
func TestTheEnumeratorScanCanFail(t *testing.T) {
	if got := constantsOfType(t, "NoSuchTypeExistsHere"); len(got) != 0 {
		t.Fatalf("the scan invented %d constants of a type that does not exist: %v", len(got), got)
	}
	if problems := enumeratorProblems("NoSuchTypeExistsHere", nil, nil); len(problems) != 1 {
		t.Fatalf("an empty declared set produced %d problems, expected exactly one; every gate above would otherwise pass against a broken scan: %v", len(problems), problems)
	}
	// And the two directions of drift, so neither half of the comparison can be
	// deleted while the gates keep reporting complete coverage.
	if problems := enumeratorProblems("Probe", []string{"a", "b"}, []string{"a"}); len(problems) != 1 {
		t.Fatalf("a value declared and not enumerated produced %d problems: %v", len(problems), problems)
	}
	if problems := enumeratorProblems("Probe", []string{"a"}, []string{"a", "b"}); len(problems) != 1 {
		t.Fatalf("a value enumerated and not declared produced %d problems: %v", len(problems), problems)
	}
	if problems := enumeratorProblems("Probe", []string{"a", "b"}, []string{"a"}, "b"); len(problems) != 0 {
		t.Fatalf("an exempt value was reported as missing: %v", problems)
	}
	if problems := enumeratorProblems("Probe", []string{"a", "b"}, []string{"a", "b"}, "b"); len(problems) != 1 {
		t.Fatalf("an exempt value that IS enumerated was accepted: %v", problems)
	}
}
