package agent

import (
	"testing"

	"axonflow/platform/decision/contract"
)

// TestAuthZENHandlerPathIsTheContractsRoute pins the one place the AuthZEN
// route is spelled outside the contract. The handler keeps a literal because
// platform/shared/capability's route census resolves only package-local
// constants (see the comment on authzenHandlerPath); this test is what makes
// that literal a guarded copy rather than a second source (#3603).
func TestAuthZENHandlerPathIsTheContractsRoute(t *testing.T) {
	if authzenHandlerPath != contract.AuthZENRoutePath {
		t.Fatalf("authzenHandlerPath = %q but contract.AuthZENRoutePath = %q; the handler is registered on a route the contract does not declare - change the contract, regenerate the surface artifact, and the SDKs follow", authzenHandlerPath, contract.AuthZENRoutePath)
	}
	if authzenProfileHeader != contract.AuthZENProfileHeader {
		t.Fatalf("authzenProfileHeader = %q but contract.AuthZENProfileHeader = %q", authzenProfileHeader, contract.AuthZENProfileHeader)
	}
}
