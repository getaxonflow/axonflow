// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// EVERY TypedAuthoringRouteHandler LITERAL DECLARES db (#3975).
//
// #3975 gave the handler a `db *sql.DB` field, and a MISSING STRUCT FIELD
// ALWAYS COMPILES. So adding a required field produces no build failure, no vet
// finding and no lint anywhere: the first signal is a runtime behaviour change
// in whichever construction forgot it, which here means a handler that silently
// keeps the in-process store and loses every publication on restart - the exact
// defect #3975 was filed for, reintroduced by an omission nobody could see.
//
// The population is small today (the constructor and two test helpers) and that
// is precisely when a census is cheap to add and worth having: the third
// literal is the one that will forget.
//
// WHY go/parser AND NOT A TYPE CHECKER. A parse reads a file REGARDLESS of its
// build constraints, so a literal inside a file behind `//go:build enterprise`
// - or any tag combination nobody thought to run - is still counted. A
// type-checking census would have to run once per tag set and would still miss
// a combination. The cost is that the match is on the literal's SPELLING, which
// is sound here for a reason specific to this type: TypedAuthoringRouteHandler
// is exported but every one of its fields is unexported, so no package outside
// this one can build a populated literal at all. The census is therefore
// complete over the set that can exist, and this test asserts that premise
// rather than assuming it.
//
// WHAT IT DOES NOT SEE, said rather than implied: a handler assembled
// field-by-field into a `var h TypedAuthoringRouteHandler` produces no
// composite literal. That construction fails closed - db is nil, the route
// reports persistence "process" - so it degrades to the pre-#3975 behaviour
// rather than to a false claim of durability, which is the outcome this census
// exists to protect and the reason it is not chased further.

// handlerTypeName is the literal this census pins.
const handlerTypeName = "TypedAuthoringRouteHandler"

type handlerLiteral struct {
	file  string
	line  int
	hasDB bool
}

// collectHandlerLiterals parses every Go file in this package - tests included,
// because two of the three literals are in a test - and reports each composite
// literal of the handler type with whether it names db.
func collectHandlerLiterals(t *testing.T) (lits []handlerLiteral, filesScanned int) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", e.Name(), perr)
		}
		filesScanned++
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			// Both spellings: `TypedAuthoringRouteHandler{...}` in this package,
			// and a qualified `orchestrator.TypedAuthoringRouteHandler{...}`
			// which cannot populate the unexported fields but is still counted
			// so the census does not go quiet if the type is ever moved.
			var named bool
			switch tn := cl.Type.(type) {
			case *ast.Ident:
				named = tn.Name == handlerTypeName
			case *ast.SelectorExpr:
				named = tn.Sel.Name == handlerTypeName
			}
			if !named {
				return true
			}
			lit := handlerLiteral{file: e.Name(), line: fset.Position(cl.Pos()).Line}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "db" {
					lit.hasDB = true
				}
			}
			lits = append(lits, lit)
			return true
		})
	}
	return lits, filesScanned
}

func TestEveryTypedAuthoringHandlerLiteralDeclaresItsDB(t *testing.T) {
	lits, filesScanned := collectHandlerLiterals(t)

	// ANTI-VACUITY IN BOTH DIRECTIONS. A census that scanned nothing, and a
	// census that matched nothing, both report clean. The floors are stated as
	// the facts they are: this package is large, and the literals are the
	// constructor plus the two test helpers.
	if filesScanned < 50 {
		t.Fatalf("the walk scanned %d Go file(s) in this package; that is far too few for platform/orchestrator, so the census is reading the wrong directory", filesScanned)
	}
	if len(lits) < 3 {
		t.Fatalf("found %d %s literal(s); the constructor and both test helpers build one, so fewer than three means the match has stopped working rather than that literals were removed",
			len(lits), handlerTypeName)
	}

	var missing []string
	for _, l := range lits {
		if !l.hasDB {
			missing = append(missing, l.file+":"+itoa(l.line))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these %s literal(s) do not name the db field:\n  %s\n\n"+
			"A missing struct field always compiles, so nothing else in the toolchain will tell you. A handler built "+
			"without db keeps the IN-PROCESS store and loses every publication on restart while reporting "+
			"persistence \"process\" - which is the defect #3975 exists to fix, reintroduced silently.\n\n"+
			"Set it explicitly. `db: nil` is a legitimate and useful value - it is the in-process posture every unit "+
			"test in this package asserts against - but it has to be WRITTEN, so the choice is visible to a reader and "+
			"to this census.",
			handlerTypeName, strings.Join(missing, "\n  "))
	}

	t.Logf("%d %s literal(s) across %d file(s), all declaring db", len(lits), handlerTypeName, filesScanned)
}

// TestTheHandlerFieldsAreUnexportedSoTheCensusIsComplete asserts the premise
// the census rests on.
//
// The spelling-based match above is complete ONLY because no package outside
// this one can build a populated TypedAuthoringRouteHandler literal. That is
// true while every field is unexported, and it stops being true the moment
// somebody exports one - at which point a literal in another package could set
// it, this census would never look there, and it would keep reporting clean.
//
// So the premise is checked rather than trusted, and this is the test that
// fails on the day it stops holding.
func TestTheHandlerFieldsAreUnexportedSoTheCensusIsComplete(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, dir, nil, 0)
	if err != nil {
		t.Fatalf("parsing the package: %v", err)
	}
	var exported []string
	found := false
	for _, p := range pkg {
		for _, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok || ts.Name.Name != handlerTypeName {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				found = true
				for _, field := range st.Fields.List {
					for _, name := range field.Names {
						if name.IsExported() {
							exported = append(exported, name.Name)
						}
					}
				}
				return true
			})
		}
	}
	if !found {
		t.Fatalf("no declaration of %s was found in this package; the census above is pinning a type that has moved", handlerTypeName)
	}
	sort.Strings(exported)
	if len(exported) > 0 {
		t.Errorf("%s now has exported field(s) %v.\n\n"+
			"TestEveryTypedAuthoringHandlerLiteralDeclaresItsDB only scans THIS package, and it is complete solely "+
			"because no other package can populate a literal of this type. An exported field breaks that: a literal "+
			"elsewhere could set it, omit db, and never be seen. Either un-export the field, or widen the census to "+
			"the whole tree and delete this test.",
			handlerTypeName, exported)
	}
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
