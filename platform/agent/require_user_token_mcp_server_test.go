// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3476 Phase B — the MCP-server plane's authenticateMCPSession
// (mcp_server_handler.go): when the caller's org resolves
// require_user_token=true, a token-less AuthKindEnterprise caller must be
// REJECTED (a non-nil error, mirroring the resolveErr != nil branch just
// above it) instead of falling through to the pseudo-identity/header path.
//
// These tests drive authenticateMCPServerRequest (the untagged wrapper around
// authenticateMCPSession) with a real *http.Request, authenticated via the
// minted-license whitelist fixture from mcp_rest_user_token_rejected_test.go
// (utrInjectMintedWhitelistEntry / utrSetupTestKeypair / utrGenTestLicenseKey)
// — NOT withEnterpriseWhitelist, which only validates in the community build
// (see mcp_identity_test.go) and would silently skip under `-tags enterprise`.
// The require_user_token resolver is wired via installTestRequireUserTokenCache
// (require_user_token_test.go), no real DB needed.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

const rutMCPServerOrg = "rut-mcpserver-org"

// rutMCPServerReq builds an enterprise-authenticated MCP-server request using
// the minted whitelist license, with an optional per-user token attached.
func rutMCPServerReq(t *testing.T, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	req.Header.Set("Authorization", utrBasicAuthHeader())
	if token != "" {
		req.Header.Set("X-User-Token", token)
	}
	return req
}

// setupRUTMCPServerTest wires enterprise mode + the minted whitelist client
// (no real DB, both build lanes) and resets the shared per-user-token
// validator registry.
func setupRUTMCPServerTest(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	// The minted whitelist license (utrGenTestLicenseKey) carries no org_id
	// claim, so auth.OrgID resolves to "" and ResolveRequireUserToken
	// substitutes getDeploymentOrgID() (documented, deliberate — see
	// require_user_token.go). Pin ORG_ID so the fake reader can be keyed on a
	// known value instead of the "local-dev-org" fallback.
	t.Setenv("ORG_ID", rutMCPServerOrg)
	origAuthDB := authDB
	authDB = nil
	t.Cleanup(func() { authDB = origAuthDB })
	utrInjectMintedWhitelistEntry(t)
	sharedidentity.ResetRegistryForTest()
	t.Cleanup(sharedidentity.ResetRegistryForTest)
}

// --- 1. Flag OFF: compatibility path intact -- a token-less enterprise
// caller still resolves (no error) via the pseudo-identity/header fallback. ---

func TestAuthenticateMCPSession_RequireUserToken_FlagOff_AbsentToken_StillResolves(t *testing.T) {
	setupRUTMCPServerTest(t)
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{rutMCPServerOrg: false}}, time.Minute)

	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(rutMCPServerReq(t, ""))
	if err != nil {
		t.Fatalf("flag off: token-less enterprise caller must still resolve via the compat fallback: %v", err)
	}
}

// --- 2. Flag ON: a token-less enterprise caller is REJECTED (non-nil error),
// mirroring the resolveErr != nil branch's rejection shape. ---

func TestAuthenticateMCPSession_RequireUserToken_FlagOn_AbsentToken_Rejected(t *testing.T) {
	setupRUTMCPServerTest(t)
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{rutMCPServerOrg: true}}, time.Minute)

	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(rutMCPServerReq(t, ""))
	if err == nil {
		t.Fatal("flag on: token-less enterprise caller must be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "user token is required") {
		t.Errorf("rejection error must name the cause (user token required); got: %v", err)
	}
}

// --- 3. Flag ON: a caller presenting a VALID per-user token is unaffected. ---

func TestAuthenticateMCPSession_RequireUserToken_FlagOn_ValidToken_Unaffected(t *testing.T) {
	setupRUTMCPServerTest(t)
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{rutMCPServerOrg: true}}, time.Minute)
	if err := sharedidentity.RegisterValidator(stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id: &sharedidentity.ValidatedIdentity{
			Email: "alice@corp.example", Role: "member", Validated: true,
			Source: sharedidentity.ValidatorNameHS256,
		},
	}); err != nil {
		t.Fatalf("RegisterValidator: %v", err)
	}

	_, _, _, userEmail, _, _, _, _, err := authenticateMCPServerRequest(rutMCPServerReq(t, "tok"))
	if err != nil {
		t.Fatalf("flag on + valid token: must resolve, not reject: %v", err)
	}
	if userEmail != "alice@corp.example" {
		t.Errorf("userEmail = %q, want alice@corp.example (the validated token identity)", userEmail)
	}
}

// --- 4. An unreadable posture fails closed at THIS gate point. ---

func TestAuthenticateMCPSession_RequireUserToken_ReaderError_FailsClosed_AbsentTokenRejected(t *testing.T) {
	setupRUTMCPServerTest(t)
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{err: errors.New("db down")}, time.Minute)

	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(rutMCPServerReq(t, ""))
	if err == nil {
		t.Fatal("posture-read error must fail closed: token-less enterprise caller must be rejected")
	}
	if !strings.Contains(err.Error(), "user token is required") {
		t.Errorf("fail-closed rejection error must name the cause; got: %v", err)
	}
}

// --- Correctness constraint: the gate is AuthKindEnterprise-only. Community
// mode never reaches the Enterprise branch at all, so a token-less community
// caller must never be rejected regardless of the flag. ---

func TestAuthenticateMCPSession_RequireUserToken_FlagOn_CommunityCallerUnaffected(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{rutMCPServerOrg: true}}, time.Minute)

	req := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)
	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("community caller must never be rejected by the require_user_token gate: %v", err)
	}
}

// --- The no-validator suppression vector (#2932 shape).
//
// sharedidentity.ResolveToken returns (nil, nil) for TWO distinct inputs: no
// token at all, and a token presented in a deployment where no per-user-token
// validator registered. Both land on the pseudo-identity/header fallback. A
// gate keyed on `perUserToken == ""` would close only the first, leaving an
// org that opted in suppressible by sending ANY junk string on a deployment
// whose validators failed to register — a plane that looks like it enforces
// while it does not. The gate is keyed on `vid == nil` so both are closed.
//
// The pair is what makes this meaningful: the SAME request (a token presented,
// no validator registered) is served with the flag off and rejected with it
// on, so this cannot pass by the plane simply refusing everything.

func TestAuthenticateMCPSession_RequireUserToken_FlagOff_TokenButNoValidator_StillResolves(t *testing.T) {
	setupRUTMCPServerTest(t) // leaves the validator registry EMPTY
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{rutMCPServerOrg: false}}, time.Minute)

	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(rutMCPServerReq(t, "some-token-no-validator-can-read"))
	if err != nil {
		t.Fatalf("flag off: a token with no registered validator must still resolve least-privilege "+
			"(the #2932 fail-safe is unchanged when the org has not opted in): %v", err)
	}
}

func TestAuthenticateMCPSession_RequireUserToken_FlagOn_TokenButNoValidator_Rejected(t *testing.T) {
	setupRUTMCPServerTest(t) // leaves the validator registry EMPTY
	t.Setenv(EnvRequireUserToken, "")
	installTestRequireUserTokenCache(t,
		&fakeRequireUserTokenReader{rows: map[string]bool{rutMCPServerOrg: true}}, time.Minute)

	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(rutMCPServerReq(t, "some-token-no-validator-can-read"))
	if err == nil {
		t.Fatal("flag on: a token no validator can read yields NO verified identity, so the caller " +
			"must be rejected rather than served on the least-privilege fallback — otherwise " +
			"presenting junk is a working suppression vector for an org that opted in")
	}
	if !strings.Contains(err.Error(), "user token is required") {
		t.Errorf("rejection error must name the cause (user token required); got: %v", err)
	}
}
