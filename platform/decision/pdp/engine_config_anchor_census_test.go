// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// EVERY ENGINE DECLARES ITS ANCHOR, CENSUSED STRUCTURALLY (#3884)
//
// `EngineConfig.SystemCorpus` is required and an unset one is refused at
// `NewEngine`. That refusal is the control; this is what stops it being
// discovered by whoever runs the job that happens to cover the caller nobody
// updated.
//
// # WHY A CENSUS AND NOT A COMPILER ERROR
//
// A missing struct field ALWAYS compiles. Adding a required field to a config
// struct therefore produces no build failure, no vet finding and no lint - the
// first signal is a runtime refusal in whichever test happens to construct one.
// When this field was added, `go build ./...` and `go vet ./...` were clean
// across every module and one caller was still unset:
// `platform/shared/identity/directory_deletion_test.go`, which is
// `//go:build enterprise` in a DIFFERENT module that `replace`s to this one, so
// it is invisible to an untagged build of this module and its red would have
// landed after the merge, on somebody else. R3 found it; this census is what
// finds the next one.
//
// # WHY IT PARSES RATHER THAN TYPE-CHECKS
//
// `go/parser` reads a file regardless of its build constraints, which is
// exactly the property needed: the caller that was missed was hidden behind a
// build tag, and a type-checking census would have to be run once per tag set
// per module and would still miss a tag combination nobody thought of. The cost
// is that this matches on the literal's NAME rather than on its resolved type,
// so it is deliberately over-inclusive - see `isEngineConfigLiteral`.

// pdpImportPath is the package whose `EngineConfig` this census is about.
const pdpImportPath = "axonflow/platform/decision/pdp"

// engineConfigTypeName is the type's name, without any package qualifier.
//
// THE QUALIFIER IS RESOLVED PER FILE FROM ITS OWN IMPORTS rather than matched
// as the literal string "pdp.". R3 evaded the earlier version with
// `import xpdp "axonflow/platform/decision/pdp"`: the file was scanned, the
// literal was not counted, and the census reported a clean tree. A name-based
// match is under-inclusive on an alias in exactly the way it is over-inclusive
// on a bare identifier, and only the second was stated.
const engineConfigTypeName = "EngineConfig"

// otherEngineConfigTypes are same-named types in other packages that this
// name-based match would otherwise claim. They are enumerated rather than
// skipped by heuristic, so a THIRD `EngineConfig` in the tree fails this census
// instead of being silently excused - which is the failure mode of every
// "ignore the ones that look unrelated" rule.
var otherEngineConfigTypes = map[string]string{
	"platform/shared/policy/types.go": "sharedpolicy.EngineConfig, the unified policy engine's configuration; a different type with no authority root",
}

func TestEveryEngineConfigDeclaresASystemCorpusAnchor(t *testing.T) {
	root := repoRootFromPDP(t)

	var missing []string
	scanned, literals := 0, 0
	exempted := map[string]int{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", ".venv", "target", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if _, known := otherEngineConfigTypes[rel]; known {
			exempted[rel]++
			return nil
		}
		scanned++
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// A file this census cannot parse is a file it cannot clear, and
			// silently skipping it is how a caller hides. Generated and
			// example trees are already excluded by the directory rules above.
			t.Errorf("%s: cannot be parsed, so this census cannot clear it: %v", rel, parseErr)
			return nil
		}
		// Every local name this file binds to the pdp package, alias included.
		// A file that does not import it can still hold a bare `EngineConfig`
		// literal - that is this package's own files - so the bare identifier
		// is always a candidate.
		qualifiers := map[string]bool{}
		for _, imp := range f.Imports {
			if imp.Path == nil || strings.Trim(imp.Path.Value, `"`) != pdpImportPath {
				continue
			}
			if imp.Name != nil {
				qualifiers[imp.Name.Name] = true
				continue
			}
			qualifiers["pdp"] = true
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isEngineConfigLiteral(lit, qualifiers) {
				return true
			}
			literals++
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "SystemCorpus" {
					return true
				}
			}
			missing = append(missing, fmt.Sprintf("%s:%d", rel, fset.Position(lit.Pos()).Line))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	// Anti-vacuity in both directions. A walk that found no Go files, or found
	// them and matched no literal, would report a clean tree having checked
	// nothing - and "zero rows" is an ABSENT answer, not a clean one.
	if scanned < 100 {
		t.Fatalf("scanned %d Go file(s) under %s; the walk did not reach the tree", scanned, root)
	}
	if literals == 0 {
		t.Fatalf("scanned %d Go file(s) and matched no EngineConfig literal; either the spellings in "+
			"engineConfigLiteralNames have changed or this census is looking in the wrong place", scanned)
	}
	// THE EXEMPTIONS MUST STILL BE LIVE. A row naming a file that has been
	// renamed or deleted excuses nothing today and would excuse whatever
	// occupies that path tomorrow - the pre-armed-exemption shape. And a row
	// whose file no longer holds the type it names is a whole file left blind
	// for a reason that has stopped being true.
	for rel, reason := range otherEngineConfigTypes {
		if exempted[rel] == 0 {
			t.Errorf("the exemption for %s (%s) matched no file in the walk; a stale exemption excuses whatever takes that path next", rel, reason)
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("the exemption for %s cannot be read: %v", rel, err)
			continue
		}
		if !strings.Contains(string(b), engineConfigTypeName) {
			t.Errorf("the exemption for %s (%s) names a file that no longer mentions %s; the whole file is exempt for a reason "+
				"that has stopped being true", rel, reason, engineConfigTypeName)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d EngineConfig literal(s) declare no SystemCorpus anchor: %v\n"+
			"A missing struct field always compiles, so this is invisible to build, vet and lint, and NewEngine's refusal "+
			"lands wherever that caller is first constructed - which may be a tagged job on another tier. Set it to "+
			"AnchorToShippedCorpus() to activate the corpus this binary shipped with, or to Unanchored(reason) to say in "+
			"words why this engine activates a system document that is not it.", len(missing), missing)
	}
	t.Logf("scanned %d Go file(s); %d EngineConfig literal(s), all anchored", scanned, literals)
}

// isEngineConfigLiteral reports whether a composite literal names EngineConfig,
// bare or under any local name this file binds to the pdp package.
func isEngineConfigLiteral(lit *ast.CompositeLit, qualifiers map[string]bool) bool {
	switch t := lit.Type.(type) {
	case *ast.Ident:
		return t.Name == engineConfigTypeName
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && t.Sel.Name == engineConfigTypeName && qualifiers[pkg.Name]
	}
	return false
}

// repoRootFromPDP walks up to the repository root.
func repoRootFromPDP(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "platform", "decision", "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root from the pdp package")
	return ""
}
