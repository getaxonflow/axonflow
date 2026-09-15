// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axonflow/platform/agent/license"
)

// A LICENCE THAT NAMES NO ORGANIZATION IS REFUSED AT EVERY SURFACE IT CAN
// ARRIVE ON: the process licence at boot, and a client licence at
// authentication. One table, because the claim is that no surface admits one.
func TestALicenceNamingNoOrganizationIsRefusedAtEverySurface(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	utrSetupTestKeypair(t)
	const org = "org-licensed"

	boot := func(licenceKey string) error {
		result, err := license.ValidateLicense(context.Background(), licenceKey)
		if err != nil || !result.Valid {
			t.Fatalf("PREMISE: the minted licence does not validate: %v %+v", err, result)
		}
		return refuseOrgLessLicence(result)
	}
	authenticate := func(licenceKey string) error {
		prevDB := authDB
		authDB = nil
		t.Cleanup(func() { authDB = prevDB })
		const clientID = "org-less-licence-client"
		knownClients[clientID] = &ClientAuth{
			ClientID: clientID, LicenseKey: licenceKey, Name: clientID, TenantID: clientID,
			Permissions: []string{"query"}, RateLimit: 1000, Enabled: true,
		}
		t.Cleanup(func() { delete(knownClients, clientID) })
		req := httptest.NewRequest(http.MethodPost, "/api/v1/decide", nil)
		setOAuth2BasicAuth(req, clientID, licenceKey)
		auth, authErr := Authenticate(req, &AuthHints{})
		if authErr != nil {
			if authErr.HTTPStatus != http.StatusUnauthorized {
				t.Fatalf("the refusal is HTTP %d; a credential that cannot be admitted is a 401", authErr.HTTPStatus)
			}
			return errorString(authErr.Message)
		}
		if auth.OrgID != org {
			t.Fatalf("an admitted licence authenticated to %q; want %q, the organization it names", auth.OrgID, org)
		}
		return nil
	}

	for _, surface := range []struct {
		name  string
		check func(licenceKey string) error
	}{
		{"boot: the process licence", boot},
		{"authentication: a client licence", authenticate},
	} {
		t.Run(surface.name, func(t *testing.T) {
			err := surface.check(utrGenTestLicenseKey("Enterprise", ""))
			// §1.8 is the PRD section that specifies this refusal and requires it
			// to name that section.
			if err == nil || !strings.Contains(err.Error(), "deployment_id") || !strings.Contains(err.Error(), "org_id") || !strings.Contains(err.Error(), "§1.8") {
				t.Fatalf("a licence naming no organization got %v; want a refusal naming deployment_id, org_id and PRD §1.8", err)
			}
			if err := surface.check(utrGenTestLicenseKey("Enterprise", org)); err != nil {
				t.Fatalf("CONTROL: a licence naming %q was refused: %v", org, err)
			}
		})
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

// TestEveryLicenceValidationRefusesALicenceNamingNoOrganization is the census
// beside the table above: every production function that validates a licence
// calls refuseOrgLessLicence, so a new authentication path cannot admit an
// organization-less credential. validateServiceLicense is the one exemption, by
// name: it gates a connector operation with a SERVICE licence, and the request's
// organization and subject come from Authenticate, never from that licence.
func TestEveryLicenceValidationRefusesALicenceNamingNoOrganization(t *testing.T) {
	exempt := map[string]string{
		"validateServiceLicense": "a service licence gates a connector operation; the request's organization comes from Authenticate",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	validators := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			validates, refuses := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					if x, ok := fun.X.(*ast.Ident); ok && x.Name == "license" && (fun.Sel.Name == "ValidateLicense" || fun.Sel.Name == "ValidateWithRetry") {
						validates = true
					}
				case *ast.Ident:
					if fun.Name == "refuseOrgLessLicence" {
						refuses = true
					}
				}
				return true
			})
			if !validates {
				continue
			}
			validators++
			if _, ok := exempt[fn.Name.Name]; ok {
				continue
			}
			if !refuses {
				t.Errorf("%s (%s) validates a licence and never calls refuseOrgLessLicence, so it would admit a licence naming no organization",
					fn.Name.Name, fset.Position(fn.Pos()))
			}
		}
	}
	// The boot check, the whitelist path, the two database paths and the service
	// licence gate: fewer means the census is not reading the package.
	if validators < 5 {
		t.Fatalf("found %d functions validating a licence; the census is not reading the package", validators)
	}
}
