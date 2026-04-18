// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	serviceauth "axonflow/platform/shared/serviceauth"
)

// setBasicAuth sets the Authorization header to Basic base64(clientID:clientSecret).
func setBasicAuth(r *http.Request, clientID, clientSecret string) {
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(clientID+":"+clientSecret)))
}

// =============================================================================
// Auth Matrix — table-driven tests for Authenticate()
// =============================================================================

func TestAuthenticate_CommunityMode(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	t.Run("no credentials defaults to community", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		result, authErr := Authenticate(req, nil)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.Kind != AuthKindCommunity {
			t.Errorf("expected AuthKindCommunity, got %v", result.Kind)
		}
		if result.ClientID != "community" {
			t.Errorf("expected clientID 'community', got %q", result.ClientID)
		}
		if result.TenantID != "community" {
			t.Errorf("expected tenantID 'community', got %q", result.TenantID)
		}
	})

	t.Run("basic auth present uses header client ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		setBasicAuth(req, "my-client", "any-secret")
		result, authErr := Authenticate(req, nil)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.ClientID != "my-client" {
			t.Errorf("expected clientID 'my-client', got %q", result.ClientID)
		}
		if result.TenantID != "my-client" {
			t.Errorf("expected tenantID 'my-client', got %q", result.TenantID)
		}
	})

	t.Run("body hints used when no header", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		hints := &AuthHints{ClientID: "body-client"}
		result, authErr := Authenticate(req, hints)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.ClientID != "body-client" {
			t.Errorf("expected clientID 'body-client', got %q", result.ClientID)
		}
	})

	t.Run("header takes priority over hints", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		setBasicAuth(req, "header-client", "secret")
		hints := &AuthHints{ClientID: "body-client"}
		result, authErr := Authenticate(req, hints)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.ClientID != "header-client" {
			t.Errorf("expected header-client to win, got %q", result.ClientID)
		}
	})

	t.Run("orgID comes from deployment", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		result, authErr := Authenticate(req, nil)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		expected := getDeploymentOrgID()
		if result.OrgID != expected {
			t.Errorf("expected orgID %q, got %q", expected, result.OrgID)
		}
	})
}

func TestAuthenticate_Enterprise_Whitelist(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("uses community whitelist keys that don't validate with enterprise Ed25519 signing")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	// Save and restore authDB
	origDB := authDB
	authDB = nil // force whitelist path
	defer func() { authDB = origDB }()

	t.Run("valid whitelist credentials", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		setBasicAuth(req, "healthcare-demo", knownClients["healthcare-demo"].LicenseKey)
		result, authErr := Authenticate(req, nil)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.Kind != AuthKindEnterprise {
			t.Errorf("expected AuthKindEnterprise, got %v", result.Kind)
		}
		if result.TenantID != "healthcare_tenant" {
			t.Errorf("expected tenantID 'healthcare_tenant', got %q", result.TenantID)
		}
	})

	t.Run("missing credentials returns 401", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		_, authErr := Authenticate(req, nil)
		if authErr == nil {
			t.Fatal("expected error for missing credentials")
		}
		if authErr.Code != "missing_credentials" {
			t.Errorf("expected code 'missing_credentials', got %q", authErr.Code)
		}
		if authErr.HTTPStatus != http.StatusUnauthorized {
			t.Errorf("expected HTTP 401, got %d", authErr.HTTPStatus)
		}
	})

	t.Run("invalid credentials returns 401", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		setBasicAuth(req, "healthcare-demo", "wrong-license-key")
		_, authErr := Authenticate(req, nil)
		if authErr == nil {
			t.Fatal("expected error for invalid credentials")
		}
		if authErr.Code != "invalid_credentials" {
			t.Errorf("expected code 'invalid_credentials', got %q", authErr.Code)
		}
		if authErr.HTTPStatus != http.StatusUnauthorized {
			t.Errorf("expected HTTP 401, got %d", authErr.HTTPStatus)
		}
	})

	t.Run("unknown client returns 401", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		setBasicAuth(req, "nonexistent-client", "some-key")
		_, authErr := Authenticate(req, nil)
		if authErr == nil {
			t.Fatal("expected error for unknown client")
		}
		if authErr.HTTPStatus != http.StatusUnauthorized {
			t.Errorf("expected HTTP 401, got %d", authErr.HTTPStatus)
		}
	})
}

func TestAuthenticate_InternalService(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	// Save and restore
	origDB := authDB
	authDB = nil
	origValidator := internalTokenValidator
	defer func() {
		authDB = origDB
		internalTokenValidator = origValidator
	}()

	t.Run("valid HMAC token in hints", func(t *testing.T) {
		secret := "test-internal-secret-32chars-min!"
		internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
		gen := serviceauth.NewTokenGenerator(secret, nil)
		token := serviceauth.GetInternalServiceToken(gen)

		req := httptest.NewRequest("POST", "/mcp/resources/query", nil)
		hints := &AuthHints{
			ClientID:  serviceauth.ClientID,
			UserToken: token,
			TenantID:  "my-tenant",
		}
		result, authErr := Authenticate(req, hints)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.Kind != AuthKindInternalService {
			t.Errorf("expected AuthKindInternalService, got %v", result.Kind)
		}
		if result.TenantID != "my-tenant" {
			t.Errorf("expected tenantID 'my-tenant', got %q", result.TenantID)
		}
		if result.ClientID != serviceauth.ClientID {
			t.Errorf("expected clientID %q, got %q", serviceauth.ClientID, result.ClientID)
		}
	})

	t.Run("invalid HMAC falls through to enterprise (missing creds)", func(t *testing.T) {
		secret := "test-internal-secret-32chars-min!"
		internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)

		req := httptest.NewRequest("POST", "/mcp/resources/query", nil)
		// No Basic auth header — after failing HMAC, falls through to enterprise which needs creds
		hints := &AuthHints{
			ClientID:  serviceauth.ClientID,
			UserToken: "invalid-hmac-token",
		}
		_, authErr := Authenticate(req, hints)
		if authErr == nil {
			t.Fatal("expected error when HMAC fails and no Basic auth present")
		}
		if authErr.Code != "missing_credentials" {
			t.Errorf("expected code 'missing_credentials', got %q", authErr.Code)
		}
	})

	t.Run("nil hints skips internal service detection", func(t *testing.T) {
		internalTokenValidator = nil // no validator

		req := httptest.NewRequest("POST", "/api/request", nil)
		_, authErr := Authenticate(req, nil)
		if authErr == nil {
			t.Fatal("expected error for missing credentials (nil hints, no Basic auth)")
		}
		if authErr.Code != "missing_credentials" {
			t.Errorf("expected 'missing_credentials', got %q", authErr.Code)
		}
	})

	t.Run("tenantID defaults to clientID when not in hints", func(t *testing.T) {
		secret := "test-internal-secret-32chars-min!"
		internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
		gen := serviceauth.NewTokenGenerator(secret, nil)
		token := serviceauth.GetInternalServiceToken(gen)

		req := httptest.NewRequest("POST", "/mcp/resources/query", nil)
		hints := &AuthHints{
			ClientID:  serviceauth.ClientID,
			UserToken: token,
			// TenantID intentionally empty
		}
		result, authErr := Authenticate(req, hints)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.TenantID != serviceauth.ClientID {
			t.Errorf("expected tenantID to default to clientID %q, got %q", serviceauth.ClientID, result.TenantID)
		}
	})

	t.Run("orgID propagated from X-Org-ID header", func(t *testing.T) {
		secret := "test-internal-secret-32chars-min!"
		internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
		gen := serviceauth.NewTokenGenerator(secret, nil)
		token := serviceauth.GetInternalServiceToken(gen)

		req := httptest.NewRequest("POST", "/mcp/resources/query", nil)
		req.Header.Set("X-Org-ID", "healthcare-org")
		hints := &AuthHints{
			ClientID:  serviceauth.ClientID,
			UserToken: token,
			TenantID:  "my-tenant",
		}
		result, authErr := Authenticate(req, hints)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.OrgID != "healthcare-org" {
			t.Errorf("expected orgID 'healthcare-org' from X-Org-ID header, got %q", result.OrgID)
		}
	})

	t.Run("orgID empty when no X-Org-ID header", func(t *testing.T) {
		secret := "test-internal-secret-32chars-min!"
		internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
		gen := serviceauth.NewTokenGenerator(secret, nil)
		token := serviceauth.GetInternalServiceToken(gen)

		req := httptest.NewRequest("POST", "/mcp/resources/query", nil)
		// No X-Org-ID header
		hints := &AuthHints{
			ClientID:  serviceauth.ClientID,
			UserToken: token,
			TenantID:  "my-tenant",
		}
		result, authErr := Authenticate(req, hints)
		if authErr != nil {
			t.Fatalf("expected no error, got: %v", authErr)
		}
		if result.OrgID != "" {
			t.Errorf("expected empty orgID when no X-Org-ID header, got %q", result.OrgID)
		}
	})
}

// =============================================================================
// ResolveUser tests
// =============================================================================

func TestResolveUser_Community(t *testing.T) {
	auth := &AuthResult{Kind: AuthKindCommunity, TenantID: "my-tenant"}
	user, authErr := ResolveUser(auth, "")
	if authErr != nil {
		t.Fatalf("expected no error, got: %v", authErr)
	}
	if user.Role != "admin" {
		t.Errorf("expected role 'admin', got %q", user.Role)
	}
	if user.TenantID != "my-tenant" {
		t.Errorf("expected tenantID 'my-tenant', got %q", user.TenantID)
	}
}

func TestResolveUser_CommunitySaaS(t *testing.T) {
	auth := &AuthResult{Kind: AuthKindCommunitySaaS, TenantID: "cs_test"}
	user, authErr := ResolveUser(auth, "")
	if authErr != nil {
		t.Fatalf("expected no error, got: %v", authErr)
	}
	if user.Role != "evaluator" {
		t.Errorf("expected role 'evaluator', got %q", user.Role)
	}
	if user.TenantID != "cs_test" {
		t.Errorf("expected tenantID 'cs_test', got %q", user.TenantID)
	}
}

func TestResolveUser_InternalService(t *testing.T) {
	auth := &AuthResult{Kind: AuthKindInternalService, TenantID: "internal-tenant"}
	user, authErr := ResolveUser(auth, "")
	if authErr != nil {
		t.Fatalf("expected no error, got: %v", authErr)
	}
	if user.Role != "service" {
		t.Errorf("expected role 'service', got %q", user.Role)
	}
}

func TestResolveUser_Enterprise_MissingToken(t *testing.T) {
	// Enterprise mode requires a token
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	auth := &AuthResult{Kind: AuthKindEnterprise, TenantID: "tenant_1"}
	_, authErr := ResolveUser(auth, "")
	if authErr == nil {
		t.Fatal("expected error for missing user token in enterprise mode")
	}
	if authErr.Code != "invalid_user_token" {
		t.Errorf("expected code 'invalid_user_token', got %q", authErr.Code)
	}
}

// =============================================================================
// AuthError struct tests
// =============================================================================

func TestAuthError_ImplementsError(t *testing.T) {
	err := &AuthError{
		Code:       "test_error",
		Message:    "test message",
		HTTPStatus: 401,
	}
	if err.Error() != "test message" {
		t.Errorf("Error() should return message, got %q", err.Error())
	}
}

func TestAuthKind_String(t *testing.T) {
	tests := []struct {
		kind AuthKind
		want string
	}{
		{AuthKindCommunity, "community"},
		{AuthKindCommunitySaaS, "community-saas"},
		{AuthKindEnterprise, "enterprise"},
		{AuthKindInternalService, "internal-service"},
		{AuthKind(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("AuthKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

// =============================================================================
// Additional coverage tests
// =============================================================================

func TestAuthenticate_Enterprise_ValidAuth_Fields(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("uses community whitelist keys that don't validate with enterprise Ed25519 signing")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origDB := authDB
	authDB = nil
	defer func() { authDB = origDB }()

	req := httptest.NewRequest("POST", "/api/request", nil)
	setBasicAuth(req, "ecommerce-demo", knownClients["ecommerce-demo"].LicenseKey)
	result, authErr := Authenticate(req, nil)
	if authErr != nil {
		t.Fatalf("expected no error, got: %v", authErr)
	}
	// OrgID comes from license validation — should be non-empty for valid licenses
	if result.Client.TenantID != "ecommerce_tenant" {
		t.Errorf("expected tenantID 'ecommerce_tenant', got %q", result.Client.TenantID)
	}
	if result.Client.LicenseTier == "" {
		t.Error("expected LicenseTier to be populated")
	}
	if !result.Client.Enabled {
		t.Error("expected client to be enabled")
	}
}

func TestAuthenticate_Enterprise_DisabledClient(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origDB := authDB
	authDB = nil
	defer func() { authDB = origDB }()

	// Temporarily disable a client
	client := knownClients["client_2"]
	origEnabled := client.Enabled
	client.Enabled = false
	defer func() { client.Enabled = origEnabled }()

	req := httptest.NewRequest("POST", "/api/request", nil)
	setBasicAuth(req, "client_2", client.LicenseKey)
	_, authErr := Authenticate(req, nil)
	if authErr == nil {
		t.Fatal("expected error for disabled client")
	}
	// Note: the whitelist validateClientCredentials checks Enabled before returning,
	// so this comes back as "invalid_credentials" not "client_disabled"
	if authErr.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("expected HTTP 401, got %d", authErr.HTTPStatus)
	}
}

func TestAuthenticate_Enterprise_OnlyClientIDNoSecret(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origDB := authDB
	authDB = nil
	defer func() { authDB = origDB }()

	req := httptest.NewRequest("POST", "/api/request", nil)
	// Set only the client ID, no secret
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("healthcare-demo:")))
	_, authErr := Authenticate(req, nil)
	if authErr == nil {
		t.Fatal("expected error for missing secret")
	}
	if authErr.Code != "missing_credentials" {
		t.Errorf("expected code 'missing_credentials', got %q", authErr.Code)
	}
}

func TestResolveUser_Enterprise_InvalidJWT(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	auth := &AuthResult{Kind: AuthKindEnterprise, TenantID: "tenant_1"}
	_, authErr := ResolveUser(auth, "invalid-jwt-token")
	if authErr == nil {
		t.Fatal("expected error for invalid JWT")
	}
	if authErr.Code != "invalid_user_token" {
		t.Errorf("expected code 'invalid_user_token', got %q", authErr.Code)
	}
	if authErr.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("expected HTTP 401, got %d", authErr.HTTPStatus)
	}
}

func TestResolveUser_UnknownKind(t *testing.T) {
	auth := &AuthResult{Kind: AuthKind(99), TenantID: "test"}
	_, authErr := ResolveUser(auth, "")
	if authErr == nil {
		t.Fatal("expected error for unknown auth kind")
	}
	if authErr.Code != "unknown_auth_kind" {
		t.Errorf("expected code 'unknown_auth_kind', got %q", authErr.Code)
	}
}

// =============================================================================
// Characterization tests — freeze existing behavior before migration
// =============================================================================

func TestAuthenticate_CommunityMode_CharacterizationBehavior(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	t.Run("community mode always succeeds regardless of credentials", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/request", nil)
		setBasicAuth(req, "garbage", "garbage")
		result, authErr := Authenticate(req, nil)
		if authErr != nil {
			t.Fatalf("community mode should never fail auth, got: %v", authErr)
		}
		if result.Kind != AuthKindCommunity {
			t.Errorf("expected AuthKindCommunity, got %v", result.Kind)
		}
		// In community mode, clientID comes from Basic auth header even though
		// credentials aren't validated
		if result.ClientID != "garbage" {
			t.Errorf("expected clientID from header, got %q", result.ClientID)
		}
	})
}

func TestAuthenticate_Enterprise_InternalServiceFallthrough(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("uses community whitelist keys that don't validate with enterprise Ed25519 signing")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	origDB := authDB
	authDB = nil
	origValidator := internalTokenValidator
	defer func() {
		authDB = origDB
		internalTokenValidator = origValidator
	}()

	t.Run("internal service with invalid HMAC but valid Basic auth succeeds as enterprise", func(t *testing.T) {
		secret := "test-internal-secret-32chars-min!"
		internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)

		req := httptest.NewRequest("POST", "/mcp/resources/query", nil)
		// Valid enterprise Basic auth
		setBasicAuth(req, "healthcare-demo", knownClients["healthcare-demo"].LicenseKey)
		// Invalid HMAC in hints — should fall through to enterprise
		hints := &AuthHints{
			ClientID:  "not-orchestrator",
			UserToken: "bad-token",
		}
		result, authErr := Authenticate(req, hints)
		if authErr != nil {
			t.Fatalf("expected enterprise auth to succeed after HMAC fallthrough, got: %v", authErr)
		}
		if result.Kind != AuthKindEnterprise {
			t.Errorf("expected AuthKindEnterprise, got %v", result.Kind)
		}
	})
}
