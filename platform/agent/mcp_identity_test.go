// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// --- extractPerUserToken ---

func TestExtractPerUserToken(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"x-user-token", map[string]string{"X-User-Token": "  tok-abc  "}, "tok-abc"},
		{"bearer", map[string]string{"Authorization": "Bearer tok-xyz"}, "tok-xyz"},
		{"bearer-case-insensitive", map[string]string{"Authorization": "bearer tok-2"}, "tok-2"},
		{"basic-not-a-token", map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}, ""},
		{"x-user-token-wins", map[string]string{"X-User-Token": "primary", "Authorization": "Bearer secondary"}, "primary"},
		{"none", map[string]string{}, ""},
		{"empty-bearer", map[string]string{"Authorization": "Bearer "}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/", nil)
			for k, v := range c.headers {
				req.Header.Set(k, v)
			}
			if got := extractPerUserToken(req); got != c.want {
				t.Errorf("extractPerUserToken = %q, want %q", got, c.want)
			}
		})
	}
}

// --- authenticateMCPServerRequest: enterprise per-user-token surface ---
//
// These drive the REAL auth surface (whitelisted enterprise Basic credential +
// a per-user token). The concrete HS256/OIDC validators are Enterprise-BUILD
// only, so in the community test build the shared registry is empty; we inject
// a fake validator through the shared RegisterValidator seam to exercise the
// fleet-plane wiring (resolve → {email, role}) that consumes it.

// stubFleetValidator is a shared TokenValidator that returns a fixed identity
// or error, injected into the process-wide registry the resolver iterates.
type stubFleetValidator struct {
	name string
	id   *sharedidentity.ValidatedIdentity
	err  error
}

func (s stubFleetValidator) Name() string { return s.name }
func (s stubFleetValidator) Validate(_ context.Context, _, _ string) (*sharedidentity.ValidatedIdentity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.id, nil
}

// orgCapturingValidator records the orgID it is called with so a test can
// assert the wiring passes the CREDENTIAL org (never a forgeable header) into
// the resolver.
type orgCapturingValidator struct {
	captured *string
	id       *sharedidentity.ValidatedIdentity
}

func (v orgCapturingValidator) Name() string { return sharedidentity.ValidatorNameHS256 }
func (v orgCapturingValidator) Validate(_ context.Context, orgID, _ string) (*sharedidentity.ValidatedIdentity, error) {
	*v.captured = orgID
	return v.id, nil
}

// withFleetValidator resets the shared registry and registers v for the test.
func withFleetValidator(t *testing.T, v sharedidentity.TokenValidator) {
	t.Helper()
	sharedidentity.ResetRegistryForTest()
	t.Cleanup(sharedidentity.ResetRegistryForTest)
	if err := sharedidentity.RegisterValidator(v); err != nil {
		t.Fatalf("RegisterValidator: %v", err)
	}
}

// withEnterpriseWhitelist puts the process in enterprise mode with the
// in-memory whitelist auth path (the whitelist license keys only validate in
// the community build — CI runs it).
func withEnterpriseWhitelist(t *testing.T) {
	t.Helper()
	if !isCommunityBuild {
		t.Skip("enterprise whitelist license keys only validate in the community build")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origDB := authDB
	authDB = nil // force the whitelist path
	t.Cleanup(func() { authDB = origDB })
}

// enterpriseTokenRequest builds an enterprise-authenticated MCP request for the
// healthcare-demo whitelist client with the given per-user token attached.
func enterpriseTokenRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("POST", "/", nil)
	setBasicAuth(req, "healthcare-demo", knownClients["healthcare-demo"].LicenseKey)
	if token != "" {
		req.Header.Set("X-User-Token", token)
	}
	return req
}

func TestAuthMCP_Enterprise_ValidToken_YieldsRealIdentityAndRole(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		// A validator always returns a canonicalized email + normalized role.
		id: &sharedidentity.ValidatedIdentity{
			Email:     "alice@corp.com",
			Role:      "member",
			Validated: true,
			Source:    sharedidentity.ValidatorNameHS256,
		},
	})

	_, _, userID, userEmail, userRole, _, _, _, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, "tok"))
	if err != nil {
		t.Fatalf("valid token must authenticate: %v", err)
	}
	if userEmail != "alice@corp.com" {
		t.Errorf("userEmail = %q, want alice@corp.com", userEmail)
	}
	if userRole != "member" {
		t.Errorf("userRole = %q, want member", userRole)
	}
	if userRole == "unknown" {
		t.Error(`userRole must not be the legacy "unknown" sentinel for a validated caller`)
	}
	if userID != "alice@corp.com" {
		t.Errorf("userID should mirror the canonical email, got %q", userID)
	}
}

// TestAuthMCP_Enterprise_CanonicalKeyReadEqualsWrite is the #2920 silent-
// failure guard: the identity a TOKEN-authenticated read resolves to must be
// byte-identical to the identity a HEADER-attributed write stamps for the SAME
// user, regardless of source casing.
func TestAuthMCP_Enterprise_CanonicalKeyReadEqualsWrite(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id: &sharedidentity.ValidatedIdentity{
			Email: sharedidentity.CanonicalEmail("Bob@Corp.Com"), Role: "member", Validated: true,
		},
	})
	t.Setenv("AXONFLOW_TRUST_IDENTITY_HEADERS", "true")

	// Read side: a validated token.
	_, _, _, readEmail, _, _, _, _, rerr := authenticateMCPServerRequest(enterpriseTokenRequest(t, "tok"))
	if rerr != nil {
		t.Fatalf("token read: %v", rerr)
	}

	// Write side: the SAME user attributed via the X-User-Email header, no token.
	wreq := enterpriseTokenRequest(t, "")
	wreq.Header.Set("X-User-Email", "bob@corp.com")
	_, _, _, writeEmail, _, _, _, _, werr := authenticateMCPServerRequest(wreq)
	if werr != nil {
		t.Fatalf("header write: %v", werr)
	}

	if readEmail != writeEmail {
		t.Fatalf("canonical key mismatch: token-read %q != header-write %q", readEmail, writeEmail)
	}
	if readEmail != "bob@corp.com" {
		t.Errorf("canonical key = %q, want bob@corp.com", readEmail)
	}
}

// TestAuthMCP_Enterprise_ResolverReceivesCredentialOrg proves the wiring feeds
// the resolver the AUTHENTICATED credential org — never a client-asserted
// header. If a regression passed a forgeable header (e.g. X-Org-Id / a header
// email) as the resolve org, a token minted for another org could validate.
func TestAuthMCP_Enterprise_ResolverReceivesCredentialOrg(t *testing.T) {
	withEnterpriseWhitelist(t)
	var gotOrg string
	withFleetValidator(t, orgCapturingValidator{
		captured: &gotOrg,
		id:       &sharedidentity.ValidatedIdentity{Email: "u@corp.com", Role: "member", Validated: true},
	})
	t.Setenv("AXONFLOW_TRUST_IDENTITY_HEADERS", "true")

	req := enterpriseTokenRequest(t, "tok")
	req.Header.Set("X-User-Email", "attacker@evil.com") // a forgeable header — must NOT reach the resolve org

	_, credOrg, _, _, _, _, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if gotOrg == "" {
		t.Fatal("resolver received an empty org — credential org not plumbed through")
	}
	if gotOrg != credOrg {
		t.Fatalf("resolver org %q != credential org %q — a non-credential value was passed", gotOrg, credOrg)
	}
	if gotOrg == "attacker@evil.com" {
		t.Fatal("SECURITY: a client-asserted header value reached the resolver org")
	}
}

func TestAuthMCP_Enterprise_InvalidTokenRejected(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		err:  sharedidentity.ErrTokenInvalid,
	})
	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, "tampered"))
	if err == nil {
		t.Fatal("an invalid per-user token must be REJECTED, not downgraded")
	}
}

func TestAuthMCP_Enterprise_RevokedTokenRejected(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		err:  sharedidentity.ErrTokenRevoked,
	})
	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, "revoked"))
	if err == nil {
		t.Fatal("a revoked per-user token must be REJECTED")
	}
}

func TestAuthMCP_Enterprise_ForgedHeaderNoTokenIsLeastPrivilege(t *testing.T) {
	withEnterpriseWhitelist(t)
	// Even if a validator WOULD return admin, a request with NO token never
	// reaches it — attribution only, never an elevated role.
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id:   &sharedidentity.ValidatedIdentity{Email: "attacker@evil.com", Role: "admin", Validated: true},
	})
	t.Setenv("AXONFLOW_TRUST_IDENTITY_HEADERS", "true")

	req := enterpriseTokenRequest(t, "") // no token
	req.Header.Set("X-User-Email", "attacker@evil.com")

	_, _, _, userEmail, userRole, _, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("no-token caller should authenticate (attribution-only): %v", err)
	}
	if userRole != "" {
		t.Errorf("forged-header no-token caller must be least-privilege, got role %q", userRole)
	}
	if userRole == "admin" {
		t.Error("SECURITY: a forged header yielded admin")
	}
	if userEmail != "attacker@evil.com" {
		t.Errorf("attribution should still record the (canonical) header, got %q", userEmail)
	}
}

func TestAuthMCP_Enterprise_NoValidatorsIsLeastPrivilege(t *testing.T) {
	withEnterpriseWhitelist(t)
	// Empty registry (the community-build reality: per-user token validators
	// are Enterprise-only). A presented token is IGNORED → least-privilege,
	// never rejected, never elevated.
	sharedidentity.ResetRegistryForTest()
	t.Cleanup(sharedidentity.ResetRegistryForTest)

	_, _, _, _, userRole, _, _, _, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, "some-token"))
	if err != nil {
		t.Fatalf("no-validator deployment must not reject a token-bearing caller: %v", err)
	}
	if userRole != "" {
		t.Errorf("no-validator caller must be least-privilege, got %q", userRole)
	}
}

// TestAuthMCP_CommunityModeIgnoresPerUserToken proves the community bypass is
// unchanged: per-user-token resolution runs ONLY in enterprise mode, so a
// community caller — even one presenting a token with a validator registered —
// takes the least-privilege path and is not rejected.
func TestAuthMCP_CommunityModeIgnoresPerUserToken(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id:   &sharedidentity.ValidatedIdentity{Email: "x@corp.com", Role: "admin", Validated: true},
	})

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-User-Token", "tok")

	_, _, _, userEmail, userRole, _, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("community mode must ignore the token and authenticate: %v", err)
	}
	if userRole != "" {
		t.Errorf("community caller must be least-privilege, got role %q", userRole)
	}
	if userEmail != "mcp-client:community" {
		t.Errorf("community caller should use the client-scoped pseudo-identity, got %q", userEmail)
	}
}

// --- #2989 (ADR-060 P2): fleet-plane segment resolution wiring ---

// fakeSegmentResolver is a call-counting sharedidentity.IdentityAttributeResolver
// double, mirroring stubFleetValidator's shape — injected via
// setFleetSegmentResolver so a test can assert WHETHER and HOW segment
// resolution ran without a real SCIM-backed database.
type fakeSegmentResolver struct {
	mu       sync.Mutex
	calls    int
	resolved sharedidentity.ResolvedIdentity
	err      error
}

func (f *fakeSegmentResolver) Resolve(_ context.Context, _, _ string) (sharedidentity.ResolvedIdentity, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return sharedidentity.ResolvedIdentity{}, f.err
	}
	return f.resolved, nil
}

func (f *fakeSegmentResolver) ResolveRole(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (f *fakeSegmentResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// withFleetSegmentResolver wires r as the process-wide fleet segment
// resolver for the test's lifetime.
func withFleetSegmentResolver(t *testing.T, r sharedidentity.IdentityAttributeResolver) {
	t.Helper()
	setFleetSegmentResolver(r)
	t.Cleanup(ResetFleetSegmentResolverForTest)
}

// TestAuthMCP_Enterprise_InvalidToken_SegmentResolutionNeverInvoked is the
// #2989 Real-World-Path contract: segment resolution must NEVER run on an
// absent/invalid/rejected per-user token — only after a TokenValidator has
// already produced a validated identity. An invalid token here must reject
// (as TestAuthMCP_Enterprise_InvalidTokenRejected already proves) AND the
// segment resolver must see zero calls.
func TestAuthMCP_Enterprise_InvalidToken_SegmentResolutionNeverInvoked(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		err:  sharedidentity.ErrTokenInvalid,
	})
	fake := &fakeSegmentResolver{}
	withFleetSegmentResolver(t, fake)

	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, "tampered"))
	if err == nil {
		t.Fatal("an invalid per-user token must be REJECTED")
	}
	if fake.callCount() != 0 {
		t.Fatalf("segment resolution must NOT run on a rejected/invalid token, calls=%d", fake.callCount())
	}
}

// TestAuthMCP_Enterprise_NoToken_SegmentResolutionNeverInvoked proves the
// legacy shared-credential (no per-user token) path never resolves segments
// either — segments are per-user, so there is no identity to resolve them
// for.
func TestAuthMCP_Enterprise_NoToken_SegmentResolutionNeverInvoked(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id:   &sharedidentity.ValidatedIdentity{Email: "unused@corp.com", Role: "admin", Validated: true},
	})
	fake := &fakeSegmentResolver{}
	withFleetSegmentResolver(t, fake)

	_, _, _, _, _, _, _, _, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, ""))
	if err != nil {
		t.Fatalf("no-token caller should authenticate (attribution-only): %v", err)
	}
	if fake.callCount() != 0 {
		t.Fatalf("segment resolution must NOT run when no per-user token was presented, calls=%d", fake.callCount())
	}
}

// TestAuthMCP_Enterprise_ValidToken_SegmentsResolvedObservabilityOnly proves
// a successful per-user-token validation resolves segments exactly once
// (session-create phase, #3473) for observability — the RETURN value is no
// longer threaded onto AuthResult (AuthResult.Segments / mcpSession.
// userSegments were deleted as write-only fields, #3473): nothing reads a
// session-scoped segment set anymore, so the only externally-observable
// effect of a successful resolution here is that the resolver was called.
func TestAuthMCP_Enterprise_ValidToken_SegmentsResolvedObservabilityOnly(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id:   &sharedidentity.ValidatedIdentity{Email: "alice@corp.com", Role: "developer", Validated: true},
	})
	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Role:     "developer",
		Segments: []sharedidentity.Segment{{ID: "grp-finance", DisplayName: "finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	_, _, _, _, userRole, _, _, auth, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, "tok"))
	if err != nil {
		t.Fatalf("valid token must authenticate: %v", err)
	}
	if userRole != "developer" {
		t.Fatalf("ResolveRole/vid.Role must stay unaffected by segment wiring, got %q", userRole)
	}
	if auth == nil {
		t.Fatal("expected a non-nil AuthResult")
	}
	if fake.callCount() != 1 {
		t.Fatalf("segment resolver calls = %d, want exactly 1", fake.callCount())
	}
}

// TestAuthMCP_Enterprise_SegmentResolutionError_DoesNotFailAuth proves a
// session-create segment-resolution failure must not reject the request or
// perturb the already-validated role — its `ok` return is discarded at the
// call site (mcp_server_handler.go), so nothing downstream can be perturbed
// by it in the first place (#3473).
func TestAuthMCP_Enterprise_SegmentResolutionError_DoesNotFailAuth(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id:   &sharedidentity.ValidatedIdentity{Email: "alice@corp.com", Role: "developer", Validated: true},
	})
	fake := &fakeSegmentResolver{err: errors.New("segment query failed")}
	withFleetSegmentResolver(t, fake)

	_, _, _, _, userRole, _, _, auth, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, "tok"))
	if err != nil {
		t.Fatalf("a segment resolution error must not fail the whole request: %v", err)
	}
	if userRole != "developer" {
		t.Fatalf("role must be unaffected by a segment resolution error, got %q", userRole)
	}
	if auth == nil {
		t.Fatal("expected a non-nil AuthResult even after a segment resolution error")
	}
	if fake.callCount() != 1 {
		t.Fatalf("segment resolver calls = %d, want exactly 1 (resolution still attempted for observability)", fake.callCount())
	}
}

// TestAuthMCP_Enterprise_NoSegmentResolverWired_NoPanic covers the
// community-build reality (registerFleetValidators never wires
// fleetSegmentResolver there) and any construction failure: no panic, auth
// otherwise unaffected.
func TestAuthMCP_Enterprise_NoSegmentResolverWired_NoPanic(t *testing.T) {
	withEnterpriseWhitelist(t)
	withFleetValidator(t, stubFleetValidator{
		name: sharedidentity.ValidatorNameHS256,
		id:   &sharedidentity.ValidatedIdentity{Email: "alice@corp.com", Role: "developer", Validated: true},
	})
	ResetFleetSegmentResolverForTest()
	t.Cleanup(ResetFleetSegmentResolverForTest)

	_, _, _, _, userRole, _, _, auth, err := authenticateMCPServerRequest(enterpriseTokenRequest(t, "tok"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected a non-nil AuthResult with no resolver wired")
	}
	if userRole != "developer" {
		t.Fatalf("role must be unaffected by an absent segment resolver, got %q", userRole)
	}
}

// resolveUserSegments' own direct contract tests (nil resolver, empty
// org/email, empty set, error fail-closed, success, and the phase-label
// split) live in segment_policy_gate_test.go, where the function itself is
// now defined (#3473 collapsed this file's former P2-era resolveUserSegments
// into that file's P3 resolveSegmentsForPolicy, which took over the freed
// name) — no duplicate coverage here.
