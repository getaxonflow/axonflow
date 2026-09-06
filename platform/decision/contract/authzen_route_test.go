package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE THIRD COPY OF THE ROUTE AND HEADER IS THE HAND-WRITTEN ONE (#3603).
//
// AuthZENRoutePath and AuthZENProfileHeader are declared once here, published
// into the surface artifact by cmd/authzen-codegen, and generated into every
// SDK from it. The OpenAPI document under docs/api is the one declaration
// nothing generates: it is what the published API reference renders and what a
// customer generating a client from the spec receives. This test is the check
// that it names the same route and the same header as the code that serves
// them, so a rename here without the spec - or in the spec without here - is
// red rather than a wire mismatch a customer finds.

const agentOpenAPIRelPath = "docs/api/agent-api.yaml"

func TestAuthZENRouteAndHeaderMatchTheOpenAPIDocument(t *testing.T) {
	// This package is platform/decision/contract; the repository root is three up.
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, agentOpenAPIRelPath))
	if err != nil {
		if _, eeErr := os.Stat(filepath.Join(root, "ee")); eeErr == nil {
			t.Fatalf("%s is missing on an enterprise tree (ee/ exists at %s): %v", agentOpenAPIRelPath, root, err)
		}
		t.Skipf("%s is absent and this tree has no ee/, so this is a checkout the sync stripped the spec from; the document is asserted on the enterprise tree", agentOpenAPIRelPath)
	}
	spec := string(raw)

	// The path is a top-level key under `paths:` - two-space indented, with a
	// colon - not merely a substring in prose, which the handler's own doc
	// comments would satisfy.
	pathKey := regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(AuthZENRoutePath) + `:\s*$`)
	if !pathKey.MatchString(spec) {
		t.Errorf("%s declares no path %q; the contract serves the AuthZEN surface there (AuthZENRoutePath)", agentOpenAPIRelPath, AuthZENRoutePath)
	}
	// The method is the operation under that path.
	idx := pathKey.FindStringIndex(spec)
	if idx != nil {
		after := spec[idx[1]:]
		if end := strings.Index(after, "\n  /"); end >= 0 {
			after = after[:end]
		}
		if !regexp.MustCompile(`(?m)^    ` + strings.ToLower(AuthZENRouteMethod) + `:\s*$`).MatchString(after) {
			t.Errorf("%s does not declare %s under %s; the contract serves the surface with that method (AuthZENRouteMethod)", agentOpenAPIRelPath, AuthZENRouteMethod, AuthZENRoutePath)
		}
		// The header is a declared parameter of that operation.
		header := regexp.MustCompile(`(?m)^\s+name: ` + regexp.QuoteMeta(AuthZENProfileHeader) + `\s*$`)
		if !header.MatchString(after) {
			t.Errorf("%s does not declare the request header %q on %s %s; the contract negotiates the profile with it (AuthZENProfileHeader)", agentOpenAPIRelPath, AuthZENProfileHeader, AuthZENRouteMethod, AuthZENRoutePath)
		}
	}
}

// TestAuthZENRouteConstantsAreWellFormed pins the shape a generated SDK relies
// on: an absolute path with no trailing slash, an upper-case method, a header
// name in canonical HTTP form.
func TestAuthZENRouteConstantsAreWellFormed(t *testing.T) {
	if !strings.HasPrefix(AuthZENRoutePath, "/api/v1/") || strings.HasSuffix(AuthZENRoutePath, "/") {
		t.Errorf("AuthZENRoutePath %q must be an absolute /api/v1/ path with no trailing slash", AuthZENRoutePath)
	}
	if AuthZENRouteMethod != strings.ToUpper(AuthZENRouteMethod) {
		t.Errorf("AuthZENRouteMethod %q must be upper case", AuthZENRouteMethod)
	}
	if !regexp.MustCompile(`^X-Axonflow-[A-Za-z0-9-]+$`).MatchString(AuthZENProfileHeader) {
		t.Errorf("AuthZENProfileHeader %q must be an X-Axonflow-* header in canonical form", AuthZENProfileHeader)
	}
}
