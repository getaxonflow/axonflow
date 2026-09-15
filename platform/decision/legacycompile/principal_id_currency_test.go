// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/pdp"
)

// collidingFieldPaths returns the (field, path) pairs in a legacy field mapping
// that land on a path the PDP compiler owns.
//
// It takes the mapping as an argument rather than reading defaultFieldPaths
// directly, so the control below can drive the SAME function over a planted
// mapping. A check whose only caller is the real data cannot be shown to fire.
func collidingFieldPaths(mapping map[string]string, owned []string) []string {
	ownedSet := make(map[string]bool, len(owned))
	for _, p := range owned {
		ownedSet[p] = true
	}
	var out []string
	for field, path := range mapping {
		if ownedSet[path] {
			out = append(out, field+" -> "+path)
		}
	}
	sort.Strings(out)
	return out
}

// TestNoLegacyConditionFieldLandsOnACompilerOwnedPath is the currency guard for
// #3936.
//
// Five attribute paths have their VALUE decided by the PDP compiler, because it
// renders a policy's own identifiers into the literal side of the comparison it
// emits - `principal.id == "User::realm:alice"`. A legacy condition field
// mapped onto one of them gives that path a second currency, and nothing says
// so: shadow.Case.Request writes the legacy value over the canonical one, and
// deriveSchema widens the resulting type collision to TypeAny in silence.
//
// The owned set is ASKED FOR rather than listed here. A list of five well-known
// paths written in this file is five paths on the day it was written, and the
// entry it is missing is the one nobody checked.
func TestNoLegacyConditionFieldLandsOnACompilerOwnedPath(t *testing.T) {
	owned := pdp.CompilerOwnedPaths()
	if len(owned) < 5 {
		t.Fatalf("pdp.CompilerOwnedPaths() returned %d paths; too few to be the well-known set, so "+
			"nothing below is an assertion", len(owned))
	}
	if len(defaultFieldPaths) < 20 {
		t.Fatalf("defaultFieldPaths holds %d entries; too few to be the legacy vocabulary, so "+
			"nothing below is an assertion", len(defaultFieldPaths))
	}

	if bad := collidingFieldPaths(defaultFieldPaths, owned); len(bad) > 0 {
		t.Errorf(`%d legacy condition field(s) map onto a path the PDP compiler owns:

  %s

Those paths carry a currency this package does not choose: pdp.compileScope
renders a policy's own identifiers into the literal side of the comparison, so
`+"`principal.id`"+` holds a canonical rendered principal and nothing else may put
a different value in it. Give the legacy field a path of this compiler's own -
`+"`principal.legacy_user_id`"+` is the precedent - so the compiled condition and
the attribute the shadow supplies still move together. See #3936.`,
			len(bad), strings.Join(bad, "\n  "))
	}
}

// TestCollisionScannerSeesAPlantedCollision is the anti-vacuity control.
//
// The assertion above passes if collidingFieldPaths always returns nothing, and
// that is indistinguishable from a clean mapping by its result alone. The
// control drives the same function over a mapping that deliberately collides
// and requires the collision back, by name.
//
// The planted mapping holds ONLY the collision plus one non-colliding entry -
// a control fixture contains only the form it names - so a pass cannot come
// from some other row.
func TestCollisionScannerSeesAPlantedCollision(t *testing.T) {
	planted := map[string]string{
		"user.id":    pdp.PrincipalIDPath,
		"user.email": "principal.email",
	}
	got := collidingFieldPaths(planted, pdp.CompilerOwnedPaths())
	want := "user.id -> " + pdp.PrincipalIDPath
	if len(got) != 1 || got[0] != want {
		t.Fatalf("the scanner returned %v for a mapping that collides on exactly one field; want [%q]. "+
			"The guard above is passing against an instrument that cannot see a collision.", got, want)
	}
	if len(collidingFieldPaths(map[string]string{"user.email": "principal.email"}, pdp.CompilerOwnedPaths())) != 0 {
		t.Fatal("the scanner reports a collision for a mapping that has none; it would fire on anything")
	}
}

// TestLegacyConditionFieldsIsTheWholeMapping pins the enumerator to the map it
// claims to enumerate.
//
// LegacyConditionFields() is what a guard in another package uses as its
// population. An enumerator that drifts from the map turns every such guard
// into a guard over a subset, and a subset produces a clean answer about the
// entries it never looked at.
func TestLegacyConditionFieldsIsTheWholeMapping(t *testing.T) {
	fields := LegacyConditionFields()
	if len(fields) != len(defaultFieldPaths) {
		t.Fatalf("LegacyConditionFields() returned %d fields for a mapping of %d", len(fields), len(defaultFieldPaths))
	}
	for _, f := range fields {
		if _, ok := defaultFieldPaths[f]; !ok {
			t.Errorf("LegacyConditionFields() returns %q, which defaultFieldPaths does not map", f)
		}
	}
	if !sort.StringsAreSorted(fields) {
		t.Errorf("LegacyConditionFields() is not sorted; callers rely on a stable order for a stable failure message")
	}
}

// TestLegacyUserIDResolvesToItsOwnPath is the positive statement of the fix: a
// reader should not have to infer it from the absence of a failure above.
func TestLegacyUserIDResolvesToItsOwnPath(t *testing.T) {
	var o Options
	for _, field := range []string{"user.id", "user_id"} {
		if got := o.AttributePathFor(field); got != "principal.legacy_user_id" {
			t.Errorf("AttributePathFor(%q) = %q, want %q", field, got, "principal.legacy_user_id")
		}
	}
	// The neighbouring principal.* mappings are unchanged. #3152 bound the
	// user.* family to authentication-derived headers by putting it in the
	// principal namespace, and this correction must not have moved any of it
	// out.
	for field, want := range map[string]string{
		"user.email":     "principal.email",
		"user.role":      "principal.role",
		"user.region":    "principal.region",
		"user.tenant_id": "principal.tenant_id",
	} {
		if got := o.AttributePathFor(field); got != want {
			t.Errorf("AttributePathFor(%q) = %q, want %q; #3152's namespace binding moved", field, got, want)
		}
	}
}

// scopeLiteralFieldsIn returns, for every `pdp.Scope{...}` composite literal in
// src, the field names it sets - one entry per literal, rendered as
// "<decl>: <fields>" so a failure names where to look.
//
// It is a TYPE-DIRECTED walk over the syntax rather than a grep, because the
// three instances of the identifier-comparison class this belongs to were each
// spelled differently and a grep for one found neither other (#3878).
func scopeLiteralFieldsIn(t *testing.T, filename, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", filename, err)
	}
	var out []string
	var enclosing string
	ast.Inspect(f, func(n ast.Node) bool {
		if fd, ok := n.(*ast.FuncDecl); ok {
			enclosing = fd.Name.Name
		}
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := cl.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Scope" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "pdp" {
			return true
		}
		var fields []string
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				fields = append(fields, "<positional>")
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				fields = append(fields, "<computed>")
				continue
			}
			fields = append(fields, key.Name)
		}
		sort.Strings(fields)
		out = append(out, enclosing+": pdp.Scope{"+strings.Join(fields, ",")+"}")
		return true
	})
	return out
}

// TestNoCompilerPathConstructsAPrincipalScope is the STRUCTURAL half of the
// #3936 reachability ruling, and it exists because the other half is
// corpus-dependent.
//
// activation.TestNoActivatedDocumentSelectsOnNamedPrincipals censuses what this
// compiler produced - the shipped corpus and the organization template - and
// what an anchored engine activates beside them, which is the strongest evidence
// available about the rows anybody thought to write down - and says nothing
// about a row shape the corpus does not contain. This reads the compiler
// instead: every `pdp.Scope` literal in the package, whatever row produced it.
//
// Together they answer different halves of one question. Either alone reports a
// clean answer about the half it cannot see.
func TestNoCompilerPathConstructsAPrincipalScope(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	// THE DENOMINATOR IS NAMED, NOT COUNTED. A count floor is a number
	// somebody has to keep in step with a directory listing, and the day it is
	// wrong it is wrong in the direction that fails a correct tree. These two
	// files are the row compilers: they are where a pdp.Scope is built, and a
	// walk that did not read both has not read the compiler whatever its file
	// count says.
	mustRead := map[string]bool{"static.go": false, "dynamic.go": false}
	byFile := map[string][]string{}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		scanned++
		if _, required := mustRead[name]; required {
			mustRead[name] = true
		}
		byFile[name] = scopeLiteralFieldsIn(t, name, string(b))
	}
	for name, read := range mustRead {
		if !read {
			t.Fatalf("the walk did not read %s; it is one of the two row compilers, so nothing below is "+
				"an assertion about this package", name)
		}
		if len(byFile[name]) == 0 {
			t.Fatalf("the walk read %s and found no pdp.Scope literal in it; the row compiler builds one, "+
				"so the walk is not seeing what it is looking for", name)
		}
	}

	var literals []string
	for name, lits := range byFile {
		for _, l := range lits {
			literals = append(literals, name+" "+l)
		}
	}
	sort.Strings(literals)
	t.Logf("%d pdp.Scope literal(s) across %d non-test source files: %v", len(literals), scanned, literals)

	for _, lit := range literals {
		if strings.Contains(lit, "Principals") {
			t.Errorf(`a compiler path constructs a principal-scoped policy: %s

#3936 IS NOW REACHABLE FROM THIS COMPILER. Its documents are loaded into the
anchored engine, and pdp.compileScope renders a
scope principal into a string equality on principal.id INCLUDING the principal
type - so the policy applies to one classification of a subject and not to
another spelling of the same subject. Re-open #3936 and decide the currency
before this ships.`, lit)
		}
	}
}

// TestTheScopeLiteralWalkSeesAPlantedPrincipalScope is the anti-vacuity
// control: the walk is driven over a source that DOES construct one.
func TestTheScopeLiteralWalkSeesAPlantedPrincipalScope(t *testing.T) {
	const planted = `package legacycompile

func a() { scope := pdp.Scope{Organization: true}; _ = scope }
func b() { scope := pdp.Scope{Principals: nil}; _ = scope }
`
	got := scopeLiteralFieldsIn(t, "planted.go", planted)
	if len(got) != 2 {
		t.Fatalf("the walk found %d pdp.Scope literals in a source with exactly two: %v", len(got), got)
	}
	sort.Strings(got)
	if got[0] != "a: pdp.Scope{Organization}" || got[1] != "b: pdp.Scope{Principals}" {
		t.Fatalf("the walk returned %v; it is not attributing literals to their enclosing function or not "+
			"reading their field names, so the assertion above cannot fire", got)
	}
}
