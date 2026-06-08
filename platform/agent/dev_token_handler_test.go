// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Unit coverage for the dev-mode token endpoint (#2541): the FAIL-CLOSED
// environment gate, the mint+inherit handler, JWT algorithm pinning, and the
// tenant-inherit fallback in validateUserToken. No partner names — generic
// acme-ops / x-tenant-* identities only.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// withJWTSecret swaps the package-level jwtSecret for the duration of a test.
func withJWTSecret(t *testing.T, secret string) {
	t.Helper()
	orig := jwtSecret
	jwtSecret = []byte(secret)
	t.Cleanup(func() { jwtSecret = orig })
}

// clearGateEnv unsets every env var the gate reads, so each case starts from a
// known all-unset (production / fail-closed) baseline.
func clearGateEnv(t *testing.T) {
	t.Helper()
	t.Setenv("ENVIRONMENT", "")
	t.Setenv("DEPLOYMENT_MODE", "")
	t.Setenv("DEPLOYMENT_KIND", "")
}

func TestDevTokenEndpointEnabled_FailClosedMatrix(t *testing.T) {
	cases := []struct {
		name        string
		environment string
		deployMode  string
		deployKind  string
		want        bool
	}{
		// The load-bearing fail-closed cases:
		{"all unset → production (fail closed)", "", "", "", false},
		{"ENVIRONMENT=production", "production", "", "", false},
		{"ENVIRONMENT unrecognized", "prod-eu", "", "", false},
		{"ENVIRONMENT whitespace only", "   ", "", "", false},
		{"DEPLOYMENT_KIND=production", "", "", "production", false},
		{"DEPLOYMENT_MODE=saas (not community)", "", "saas", "", false},
		{"DEPLOYMENT_MODE=in-vpc-enterprise", "", "in-vpc-enterprise", "", false},
		// Explicit non-prod signals enable it:
		{"ENVIRONMENT=development", "development", "", "", true},
		{"ENVIRONMENT=dev", "dev", "", "", true},
		{"ENVIRONMENT=staging", "staging", "", "", true},
		{"ENVIRONMENT=local", "local", "", "", true},
		{"ENVIRONMENT=test (NOT in the pinned allowlist → off)", "test", "", "", false},
		{"ENVIRONMENT=qa (unrecognized → off)", "qa", "", "", false},
		{"ENVIRONMENT=DEV (case-insensitive)", "DEV", "", "", true},
		{"ENVIRONMENT=dev with spaces", "  dev ", "", "", true},
		{"DEPLOYMENT_MODE=community", "", "community", "", true},
		{"DEPLOYMENT_KIND=dev", "", "", "dev", true},
		{"DEPLOYMENT_KIND=staging", "", "", "staging", true},
		// Precedence: an explicit prod ENVIRONMENT does NOT veto an explicit
		// non-prod DEPLOYMENT_MODE/KIND (any one explicit non-prod signal is
		// enough) — but neither does an explicit prod signal flip an all-unset
		// case to true.
		{"prod ENVIRONMENT + community mode → enabled", "production", "community", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearGateEnv(t)
			if c.environment != "" {
				t.Setenv("ENVIRONMENT", c.environment)
			}
			if c.deployMode != "" {
				t.Setenv("DEPLOYMENT_MODE", c.deployMode)
			}
			if c.deployKind != "" {
				t.Setenv("DEPLOYMENT_KIND", c.deployKind)
			}
			if got := devTokenEndpointEnabled(); got != c.want {
				t.Errorf("devTokenEndpointEnabled() = %v, want %v (ENVIRONMENT=%q MODE=%q KIND=%q)",
					got, c.want, c.environment, c.deployMode, c.deployKind)
			}
		})
	}
}

// TestDevTokenEndpointEnabled_DoesNotReuseFailOpenHelpers pins the regression
// that the gate must NOT inherit the fail-open default of isCommunityMode()
// (true on unset DEPLOYMENT_MODE) or getDeploymentKind() (unset → "dev").
func TestDevTokenEndpointEnabled_DoesNotReuseFailOpenHelpers(t *testing.T) {
	clearGateEnv(t)
	// Sanity: the legacy helpers DO fail open on this exact unset state...
	if !isCommunityMode() {
		t.Fatal("precondition: isCommunityMode() should be true on unset DEPLOYMENT_MODE")
	}
	if getDeploymentKind() != "dev" {
		t.Fatal("precondition: getDeploymentKind() should default to 'dev' on unset")
	}
	// ...yet the gate must still be CLOSED, because nothing is EXPLICITLY non-prod.
	if devTokenEndpointEnabled() {
		t.Error("FAIL-CLOSED VIOLATED: dev-token gate is open on an all-unset env (would expose the minter in production)")
	}
}

func TestDevTokenHandler_MintsInheritedToken(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	t.Setenv("DEPLOYMENT_MODE", "evaluation") // non-community so validateUserToken actually parses

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", nil)
	// Simulate apiAuthMiddleware having stamped the authenticated identity.
	ctx := context.WithValue(req.Context(), ContextKeyClientID, "acme-ops")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "acme-org")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	devTokenHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		UserToken string `json:"user_token"`
		TenantID  string `json:"tenant_id"`
		OrgID     string `json:"org_id"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TenantID != "acme-ops" {
		t.Errorf("response tenant_id = %q, want acme-ops (forced to Basic username)", resp.TenantID)
	}
	if resp.OrgID != "acme-org" {
		t.Errorf("response org_id = %q, want acme-org", resp.OrgID)
	}
	if resp.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", resp.ExpiresIn)
	}

	// The minted token must validate AND carry tenant_id == the Basic username.
	user, err := validateUserToken(resp.UserToken, "acme-ops")
	if err != nil {
		t.Fatalf("minted token failed validation: %v", err)
	}
	if user.TenantID != "acme-ops" {
		t.Errorf("validated token TenantID = %q, want acme-ops", user.TenantID)
	}
	if user.OrgID != "acme-org" {
		t.Errorf("validated token OrgID = %q, want acme-org", user.OrgID)
	}
}

// TestDevTokenHandler_RejectsInternalServiceAuthKind pins the R3-round-2 fix:
// the internal-service auth path carries a header-derived (caller-chosen) org_id
// (authenticator.go:132-135), so the minter must refuse it rather than sign an
// arbitrary org_id into a portable token.
func TestDevTokenHandler_RejectsInternalServiceAuthKind(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", nil)
	ctx := context.WithValue(req.Context(), ContextKeyClientID, "orchestrator-internal")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "attacker-chosen-org")
	ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindInternalService)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	devTokenHandler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for internal-service auth kind (must not mint a header-derived org_id token); body=%s", rec.Code, rec.Body.String())
	}
}

func TestDevTokenHandler_UnauthenticatedWhenContextEmpty(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", nil) // no identity in context
	rec := httptest.NewRecorder()
	devTokenHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when no authenticated identity in context", rec.Code)
	}
}

func TestValidateUserToken_AlgPinning(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	t.Setenv("DEPLOYMENT_MODE", "evaluation") // non-community so parsing runs

	claims := jwt.MapClaims{"tenant_id": "acme-ops", "org_id": "acme-org"}

	t.Run("rejects alg:none", func(t *testing.T) {
		noneTok, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
			SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("build none token: %v", err)
		}
		if _, err := validateUserToken(noneTok, "acme-ops"); err == nil {
			t.Error("alg:none token was ACCEPTED — algorithm pinning failed")
		}
	})

	t.Run("rejects RS256 (asymmetric)", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("gen rsa key: %v", err)
		}
		rsTok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(rsaKey)
		if err != nil {
			t.Fatalf("build RS256 token: %v", err)
		}
		if _, err := validateUserToken(rsTok, "acme-ops"); err == nil {
			t.Error("RS256 token was ACCEPTED — algorithm pinning failed (alg-confusion exposure)")
		}
	})

	t.Run("accepts a correctly-signed HS256 token", func(t *testing.T) {
		hsTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
		if err != nil {
			t.Fatalf("build HS256 token: %v", err)
		}
		if _, err := validateUserToken(hsTok, "acme-ops"); err != nil {
			t.Errorf("valid HS256 token rejected: %v", err)
		}
	})

	t.Run("rejects HS256 signed with the wrong secret", func(t *testing.T) {
		badTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("not-the-secret"))
		if err != nil {
			t.Fatalf("build bad HS256 token: %v", err)
		}
		if _, err := validateUserToken(badTok, "acme-ops"); err == nil {
			t.Error("HS256 token with wrong secret was ACCEPTED")
		}
	})
}

// TestValidateUserToken_FailsClosedOnEmptySecret pins the #2541 hardening: in a
// non-community mode that requires a user_token, an unconfigured JWT_SECRET must
// make validation REJECT every token rather than HMAC-verify against the empty
// key (which would accept tokens forged with that same empty key).
func TestValidateUserToken_FailsClosedOnEmptySecret(t *testing.T) {
	withJWTSecret(t, "") // empty secret
	t.Setenv("DEPLOYMENT_MODE", "evaluation")

	// A token "signed" with the empty key — the forgery this guard must block.
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"tenant_id": "acme-ops"}).SignedString([]byte(""))
	if err != nil {
		t.Fatalf("build forged token: %v", err)
	}
	if _, err := validateUserToken(forged, "acme-ops"); err == nil {
		t.Error("token validated against an EMPTY JWT_SECRET was ACCEPTED — fail-open forgery hole")
	}
}

func TestValidateUserToken_TenantInherit(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	t.Setenv("DEPLOYMENT_MODE", "evaluation")

	mint := func(claims jwt.MapClaims) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		return s
	}

	t.Run("omitted tenant_id inherits the credential tenant (not tenant_1)", func(t *testing.T) {
		tok := mint(jwt.MapClaims{"role": "evaluator"}) // no tenant_id claim
		user, err := validateUserToken(tok, "acme-ops")
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if user.TenantID != "acme-ops" {
			t.Errorf("inherited TenantID = %q, want acme-ops (must NOT be the legacy tenant_1 sentinel)", user.TenantID)
		}
		if user.TenantID == "tenant_1" {
			t.Error("regression: tenant_id fell back to tenant_1 instead of inheriting the credential tenant")
		}
	})

	t.Run("explicit tenant_id is preserved unchanged", func(t *testing.T) {
		tok := mint(jwt.MapClaims{"tenant_id": "x-tenant-explicit"})
		user, err := validateUserToken(tok, "acme-ops")
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if user.TenantID != "x-tenant-explicit" {
			t.Errorf("explicit TenantID = %q, want x-tenant-explicit (explicit-match path must be unchanged)", user.TenantID)
		}
	})

	t.Run("omitted tenant_id with empty expected falls back to legacy sentinel", func(t *testing.T) {
		tok := mint(jwt.MapClaims{"role": "evaluator"})
		user, err := validateUserToken(tok, "")
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if user.TenantID != "tenant_1" {
			t.Errorf("degenerate fallback TenantID = %q, want tenant_1 when no credential tenant is available", user.TenantID)
		}
	})
}

// sanity: the minted token's body is a standard JWT (three dot-separated parts)
// so downstream SDKs/tools parse it like any generate-jwt.sh token.
func TestDevTokenHandler_TokenShape(t *testing.T) {
	withJWTSecret(t, "unit-test-secret-key")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dev/token", nil)
	ctx := context.WithValue(req.Context(), ContextKeyClientID, "acme-ops")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "acme-org")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	devTokenHandler(rec, req)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	tok, _ := resp["user_token"].(string)
	if parts := strings.Split(tok, "."); len(parts) != 3 {
		t.Errorf("minted token is not a 3-part JWT: %q", tok)
	}
}
