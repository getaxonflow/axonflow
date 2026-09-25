// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// membershipSourceSites is every production site that renders a GROUP
// identifier a subject's closure can hold (NewGroupID / MustNewGroupID), keyed
// "<file relative to platform/>|<enclosing function>|<realm argument>", each
// with why the realm it renders under is not `oidc`.
//
// WHY IT IS PINNED (#4249). Declaring the `oidc` realm made it interactive in
// the deployment vocabulary, so an installed pack's approver pool now names
// Group::oidc:<group>. That entry admits nobody only while no membership
// source renders an oidc-qualified group. A new site - an IdP groups claim, a
// second directory (#4249 row 5695931684) - fails here and has to answer the
// question before it can land, instead of silently giving the pool members.
var membershipSourceSites = map[string]string{
	"shared/identity/directory.go|MustNewGroupID|realm": "the constructor itself: its realm is its caller's, and every caller is listed here",
	// NormalizeSCIM takes the realm from SCIMIngestOptions; it has no
	// production caller, and a caller must name a realm, which this census
	// then lists.
	"shared/identity/directory_scim.go|NormalizeSCIM|opts.Realm":               "SCIM ingest normalization: the realm is the ingest's options, set by a caller listed here (none in production today)",
	"shared/identity/directory_scim.go|scanMembershipDisagreements|opts.Realm": "NormalizeSCIM's disagreement scan, under the same ingest options",

	// SCOPE-SIDE, NOT MEMBERSHIP: these name or parse a group a POLICY refers
	// to, never a group a subject's closure holds. Listed so a membership
	// source written in either shape still has to be censused.
	"decision/legacycompile/compile.go|GroupIDFor|concat":                                                     "renders an ADR-060 segment's group id for a compiled policy scope, under the importer's --realm",
	"decision/legacycompile/static.go|policyFor|ParseID(KindGroup, opts.GroupIDFor(row.SegmentID))":           "parses that scope id for a static row",
	"decision/legacycompile/dynamic.go|dynamicPolicyFor|ParseID(KindGroup, opts.GroupIDFor(row.SegmentID))":   "parses that scope id for a dynamic row",
	"decision/pdp/policy.go|checkAuthorityRule|ParseID(KindGroup, s)":                                         "validates a policy's group references",
	"decision/pdp/policy.go|validateApprovalObligation|ParseID(KindGroup, strings.TrimSpace(raw))":            "validates an approval obligation's eligible entries",
	"decision/pdp/policy.go|validateApprovalRealms|ParseID(KindGroup, raw)":                                   "validates an approval pool's realms",
	"decision/contract/obligation.go|decodeApprovalParams|ParseID(KindGroup, raw)":                            "parses an approval pool's eligible entries",
	"decision/policypack/policypack.go|Instantiate|concat":                                                    "THE APPROVER POOL ITSELF: names the pack's group in every interactive realm, `oidc` included where declared - a name, which nothing here makes anyone hold",
	"decision/conformance/world.go|group|concat":                                                              "the conformance world's fixture groups, in its own realms",
	"decision/conformance/world.go|group|MustParseID(KindGroup, \"Group::\" + RealmWorkspace + \":\" + name)": "the same fixture group, parsed",
	// The one live membership source (#4249, principal.groups): every SCIM
	// group a subject's closure holds is rendered under the directory's own
	// qualifier, whichever realm admitted the subject; the test below pins
	// that qualifier is not the OIDC realm.
	"shared/identity/directory_scim_projection.go|ResolveClosure|SCIMDirectoryGroupRealm": "the SCIM closure projection: SCIMDirectoryGroupRealm, pinned != BuiltinRealmOIDC",
}

// TestNoMembershipSourceRendersAnOIDCQualifiedGroup walks every non-test Go
// file under platform/ and ee/, and fails on a group constructor call whose
// realm argument names the OIDC realm, on a site not in the census, and on a
// census entry that no longer exists.
func TestNoMembershipSourceRendersAnOIDCQualifiedGroup(t *testing.T) {
	roots := []string{filepath.Join("..", ".."), filepath.Join("..", "..", "..", "ee")}
	platformRoot, _ := filepath.Abs(roots[0])
	fset := token.NewFileSet()
	found := map[string]bool{}
	scanned := 0
	for i, root := range roots {
		if _, err := os.Stat(root); err != nil {
			if i > 0 && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			t.Fatalf("root %s: %v", root, err)
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "vendor", "testdata", ".git":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			scanned++
			abs, _ := filepath.Abs(path)
			rel, rerr := filepath.Rel(platformRoot, abs)
			if rerr != nil || strings.HasPrefix(rel, "..") {
				rel = abs
			}
			for _, decl := range file.Decls {
				fn, isFn := decl.(*ast.FuncDecl)
				enclosing := "<package scope>"
				if isFn {
					enclosing = fn.Name.Name
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					// A group identifier built by concatenation: a binary + whose
					// left-most operand is a string literal starting "Group::".
					if bin, ok := n.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
						left := ast.Expr(bin)
						for {
							b, ok := left.(*ast.BinaryExpr)
							if !ok || b.Op != token.ADD {
								break
							}
							left = b.X
						}
						if lit, ok := left.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.HasPrefix(strings.Trim(lit.Value, "`\""), "Group::") {
							var expr strings.Builder
							_ = printer.Fprint(&expr, fset, bin)
							if namesOIDCRealm(expr.String()) {
								t.Errorf("%s: %s concatenates a group under the OIDC realm (%s)", rel, enclosing, expr.String())
							}
							found[filepath.ToSlash(rel)+"|"+enclosing+"|concat"] = true
							return false
						}
					}
					call, ok := n.(*ast.CallExpr)
					if !ok || len(call.Args) == 0 {
						return true
					}
					name := ""
					switch f := call.Fun.(type) {
					case *ast.Ident:
						name = f.Name
					case *ast.SelectorExpr:
						name = f.Sel.Name
					}
					// fmt.Sprintf with a format starting "Group::".
					if name == "Sprintf" && len(call.Args) >= 1 {
						if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.HasPrefix(strings.Trim(lit.Value, "`\""), "Group::") {
							var expr strings.Builder
							_ = printer.Fprint(&expr, fset, call)
							if namesOIDCRealm(expr.String()) {
								t.Errorf("%s: %s formats a group under the OIDC realm (%s)", rel, enclosing, expr.String())
							}
							found[filepath.ToSlash(rel)+"|"+enclosing+"|Sprintf"] = true
						}
						return true
					}
					if (name == "ParseID" || name == "MustParseID") && len(call.Args) >= 2 {
						kind := ""
						switch k := call.Args[0].(type) {
						case *ast.SelectorExpr:
							kind = k.Sel.Name
						case *ast.Ident:
							kind = k.Name
						}
						if kind == "KindGroup" {
							var arg strings.Builder
							_ = printer.Fprint(&arg, fset, call.Args[1])
							if namesOIDCRealm(arg.String()) {
								t.Errorf("%s: %s parses a group under the OIDC realm (%s)", rel, enclosing, arg.String())
							}
							found[filepath.ToSlash(rel)+"|"+enclosing+"|"+name+"(KindGroup, "+arg.String()+")"] = true
						}
						return true
					}
					if name != "NewGroupID" && name != "MustNewGroupID" {
						return true
					}
					if enclosing == "MustNewGroupID" && name == "NewGroupID" {
						// The constructor wrapping itself.
						enclosing, name = "MustNewGroupID", "MustNewGroupID"
					}
					var arg strings.Builder
					_ = printer.Fprint(&arg, fset, call.Args[0])
					realm := arg.String()
					if namesOIDCRealm(realm) {
						t.Errorf("%s: %s renders a group under the OIDC realm (%s): an installed pack's approver pool names Group::oidc:<group>, so this gives it members", rel, enclosing, realm)
					}
					found[filepath.ToSlash(rel)+"|"+enclosing+"|"+realm] = true
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if SCIMDirectoryGroupRealm == BuiltinRealmOIDC {
		t.Errorf("the SCIM closure projection renders groups under %q, the OIDC realm", SCIMDirectoryGroupRealm)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files; the walk is not reading the tree", scanned)
	}
	var unlisted, gone, stripped []string
	for k := range found {
		if _, ok := membershipSourceSites[k]; !ok {
			unlisted = append(unlisted, k)
		}
	}
	// On a community-mirror checkout (no ee/ beside platform/), the sync also
	// deletes platform/ files that build only for the enterprise edition, and
	// a census entry in such a file cannot be found there. An entry is excused
	// only when its whole FILE is absent on a mirror: an entry whose file is
	// present but whose site is gone still fails, on both trees, and on the
	// enterprise tree every entry must be found as before.
	_, eeErr := os.Stat(roots[1])
	onMirror := errors.Is(eeErr, fs.ErrNotExist)
	for k := range membershipSourceSites {
		if found[k] {
			continue
		}
		if onMirror {
			file := strings.SplitN(k, "|", 2)[0]
			if _, err := os.Stat(filepath.Join(platformRoot, filepath.FromSlash(file))); errors.Is(err, fs.ErrNotExist) {
				stripped = append(stripped, k)
				continue
			}
		}
		gone = append(gone, k)
	}
	sort.Strings(unlisted)
	sort.Strings(gone)
	sort.Strings(stripped)
	if len(stripped) > 0 {
		t.Logf("a community-mirror checkout: %d census entries are in files the sync strips, and are asserted on the enterprise tree: %v", len(stripped), stripped)
	}
	if len(unlisted) > 0 {
		t.Errorf("group membership sources not in the census: %v. Add each with why its realm can never be `oidc`, or, if it can, the approver pool of every installed pack gains members (#4249)", unlisted)
	}
	if len(gone) > 0 {
		t.Errorf("census entries with no site in the tree: %v", gone)
	}
}

// namesOIDCRealm reports whether rendered source names the OIDC realm: the
// identifier, the bare literal, or a literal qualifier inside a group id.
func namesOIDCRealm(src string) bool {
	return strings.Contains(src, "BuiltinRealmOIDC") || strings.Contains(src, `"oidc"`) || strings.Contains(src, "::oidc:")
}
