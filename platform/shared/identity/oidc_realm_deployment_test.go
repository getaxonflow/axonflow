// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The deployment half of the tenant OIDC realm (#4249): the predicate behind
// HasOIDC, what the vocabulary declares from it, and that BuiltinRealms - the
// runtime registration list - never gains a sixth realm.

// noIODB is a non-nil *sql.DB that fails any use. Every constructor the
// predicate reaches is documented as doing no I/O; a connection attempt here
// fails the test rather than dialling anything.
func noIODB(t *testing.T) *sql.DB {
	t.Helper()
	db := sql.OpenDB(refusingConnector{})
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type refusingConnector struct{}

func (refusingConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("the deployment predicate must not open a connection")
}
func (refusingConnector) Driver() driver.Driver { return nil }

// TestDeclaredOIDCRealmIsDeclaredIffTheDeploymentWiresTheSource drives the
// four cells of HasOIDC x HasDirectory, each field on its own.
func TestDeclaredOIDCRealmIsDeclaredIffTheDeploymentWiresTheSource(t *testing.T) {
	var unset DirectorySource
	for _, tc := range []struct {
		dep       BuiltinRealmDeployment
		declared  bool
		directory DirectorySource
	}{
		{BuiltinRealmDeployment{}, false, unset},
		{BuiltinRealmDeployment{HasDirectory: true}, false, unset},
		{BuiltinRealmDeployment{HasOIDC: true}, true, DirectorySourceNone},
		{BuiltinRealmDeployment{HasOIDC: true, HasDirectory: true}, true, DirectorySourceSCIM},
	} {
		got, ok := DeclaredOIDCRealm(tc.dep)
		if ok != tc.declared {
			t.Fatalf("%+v: declared=%v, want %v", tc.dep, ok, tc.declared)
		}
		if !ok {
			if got != (DeclaredRealm{}) {
				t.Fatalf("%+v: an undeclared realm carries attributes %+v", tc.dep, got)
			}
			continue
		}
		if got.RealmID != BuiltinRealmOIDC {
			t.Fatalf("%+v: realm id %q, want %q", tc.dep, got.RealmID, BuiltinRealmOIDC)
		}
		if got.Interactive != InteractiveHuman || !got.Interactive.CanAnswer() {
			t.Fatalf("%+v: interactive %q; a person signs in at the IdP", tc.dep, got.Interactive)
		}
		if got.Directory != tc.directory {
			t.Fatalf("%+v: directory %q, want %q", tc.dep, got.Directory, tc.directory)
		}
		if got.Directory.HasGroupGraph() != tc.dep.HasDirectory {
			t.Fatalf("%+v: group graph %v, want %v", tc.dep, got.Directory.HasGroupGraph(), tc.dep.HasDirectory)
		}
	}
}

// TestBuiltinRealmsNeverGainTheOIDCRealm: BuiltinRealms is what ensureBuiltins
// registers for every organization, so HasOIDC must not move it. A sixth realm
// named oidc would fail validation (no issuer is knowable at deployment level)
// or collide with the organization's real OIDC realm.
func TestBuiltinRealmsNeverGainTheOIDCRealm(t *testing.T) {
	want := []RealmID{BuiltinRealmMinted, BuiltinRealmAPICredential, BuiltinRealmInternalService, BuiltinRealmCommunity, BuiltinRealmTrustedHeader}
	for _, dep := range []BuiltinRealmDeployment{
		{}, {HasOIDC: true}, {HasOIDC: true, HasDirectory: true, HasRevocation: true, HasCAEP: true},
	} {
		realms := BuiltinRealms(fixtureOrg, dep)
		if len(realms) != len(want) {
			t.Fatalf("%+v: %d built-in realms, want exactly %d", dep, len(realms), len(want))
		}
		for i, r := range realms {
			if r.RealmID != want[i] {
				t.Fatalf("%+v: built-in realm %d is %q, want %q", dep, i, r.RealmID, want[i])
			}
		}
		without := dep
		without.HasOIDC = false
		for i, r := range BuiltinRealms(fixtureOrg, without) {
			if r.Directory != realms[i].Directory || r.Revocation != realms[i].Revocation || r.Interactive != realms[i].Interactive {
				t.Fatalf("%+v: HasOIDC moved built-in realm %q's attributes", dep, r.RealmID)
			}
		}
	}
}

// TestOIDCRealmSourceWiringIsFalseWithoutADatabase: a nil database wires no
// source on either build.
func TestOIDCRealmSourceWiringIsFalseWithoutADatabase(t *testing.T) {
	configs, wired, err := OIDCRealmSourceWiring(nil)
	if wired || configs != nil || err == nil {
		t.Fatalf("nil db: configs=%v wired=%v err=%v; want nil, false and an error", configs, wired, err)
	}
}

// TestNewDBOIDCConfigProviderHasExactlyOneProductionCaller makes "one
// predicate" a guarantee: a second production call site would be a second
// copy of the question HasOIDC answers, free to drift from it.
//
// It walks the AST of every non-test Go file under platform/ and ee/, counting
// call expressions AND bare references (taking the function's address is a
// call site too), and fails when the walk reads nothing.
func TestNewDBOIDCConfigProviderHasExactlyOneProductionCaller(t *testing.T) {
	const target = "NewDBOIDCConfigProvider"
	const permitted = "OIDCRealmSourceWiring"
	roots := []string{filepath.Join("..", ".."), filepath.Join("..", "..", "..", "ee")}
	fset := token.NewFileSet()
	var sites []string
	scanned := 0
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			// ee/ is absent from the community mirror; platform/ never is.
			if root != roots[0] && errors.Is(err, fs.ErrNotExist) {
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
			for _, decl := range file.Decls {
				fn, isFn := decl.(*ast.FuncDecl)
				var declName *ast.Ident
				if isFn {
					declName = fn.Name
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					var name string
					switch x := n.(type) {
					case *ast.Ident:
						if x == declName {
							return true
						}
						name = x.Name
					case *ast.SelectorExpr:
						name = x.Sel.Name
						if name == target {
							sites = append(sites, enclosing(fn, isFn)+" in "+path)
						}
						return false
					}
					if name == target {
						sites = append(sites, enclosing(fn, isFn)+" in "+path)
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files; the walk is not reading the tree", scanned)
	}
	if len(sites) != 1 || !strings.HasPrefix(sites[0], permitted+" in ") {
		t.Fatalf("%s is referenced from %v; the only production reference must be %s, the one predicate behind HasOIDC", target, sites, permitted)
	}
}

func enclosing(fn *ast.FuncDecl, isFn bool) string {
	if !isFn {
		return "<package scope>"
	}
	return fn.Name.Name
}
