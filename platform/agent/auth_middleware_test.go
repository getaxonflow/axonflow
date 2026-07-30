// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/lib/pq"
)

// TestTenantIDFromContext verifies the context helper extracts tenant correctly.
func TestTenantIDFromContext(t *testing.T) {
	t.Run("returns value when set", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyTenantID, "my-tenant")
		got := TenantIDFromContext(ctx)
		if got != "my-tenant" {
			t.Errorf("TenantIDFromContext() = %q, want %q", got, "my-tenant")
		}
	})

	t.Run("returns empty when not set", func(t *testing.T) {
		got := TenantIDFromContext(context.Background())
		if got != "" {
			t.Errorf("TenantIDFromContext() = %q, want empty", got)
		}
	})

	t.Run("returns empty for wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyTenantID, 123)
		got := TenantIDFromContext(ctx)
		if got != "" {
			t.Errorf("TenantIDFromContext() = %q, want empty for wrong type", got)
		}
	})
}

// TestOrgIDFromContext verifies the org ID context helper.
func TestOrgIDFromContext(t *testing.T) {
	t.Run("returns value when set", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyOrgID, "my-org")
		got := OrgIDFromContext(ctx)
		if got != "my-org" {
			t.Errorf("OrgIDFromContext() = %q, want %q", got, "my-org")
		}
	})

	t.Run("returns empty when not set", func(t *testing.T) {
		got := OrgIDFromContext(context.Background())
		if got != "" {
			t.Errorf("OrgIDFromContext() = %q, want empty", got)
		}
	})
}

// TestClientIDFromContext verifies the client ID context helper.
func TestClientIDFromContext(t *testing.T) {
	t.Run("returns value when set", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyClientID, "client-1")
		got := ClientIDFromContext(ctx)
		if got != "client-1" {
			t.Errorf("ClientIDFromContext() = %q, want %q", got, "client-1")
		}
	})

	t.Run("returns empty when not set", func(t *testing.T) {
		got := ClientIDFromContext(context.Background())
		if got != "" {
			t.Errorf("ClientIDFromContext() = %q, want empty", got)
		}
	})
}

// TestAPIAuthMiddleware_CommunityMode_NoAuth verifies community mode passes
// requests through without auth and defaults tenant to "community".
func TestAPIAuthMiddleware_CommunityMode_NoAuth(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	var capturedTenant, capturedOrg, capturedClient string
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantIDFromContext(r.Context())
		capturedOrg = OrgIDFromContext(r.Context())
		capturedClient = ClientIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
	if capturedTenant != "community" {
		t.Errorf("Expected tenant 'community', got %q", capturedTenant)
	}
	if capturedOrg != "local-dev-org" {
		t.Errorf("Expected org 'local-dev-org', got %q", capturedOrg)
	}
	if capturedClient != "community" {
		t.Errorf("Expected client 'community', got %q", capturedClient)
	}
}

// TestAPIAuthMiddleware_CommunityMode_WithBasicAuth verifies community mode
// uses the clientId from Basic auth when provided.
func TestAPIAuthMiddleware_CommunityMode_WithBasicAuth(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	var capturedTenant string
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	req.SetBasicAuth("my-custom-client", "any-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
	if capturedTenant != "my-custom-client" {
		t.Errorf("Expected tenant 'my-custom-client', got %q", capturedTenant)
	}
}

// TestAPIAuthMiddleware_EnterpriseMode_NoAuth verifies enterprise mode rejects
// unauthenticated requests with 401.
func TestAPIAuthMiddleware_EnterpriseMode_NoAuth(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for unauthenticated request")
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rr.Code)
	}
}

// TestAPIAuthMiddleware_CORSPreflight verifies OPTIONS requests pass through
// without authentication.
func TestAPIAuthMiddleware_CORSPreflight(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	called := false
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("OPTIONS", "/api/v1/static-policies", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// #3092: a preflight is TERMINATED at the auth boundary, not forwarded.
	// This assertion used to read `if !called` — i.e. it pinned the bypass in
	// place as intended behaviour. A genuine browser preflight never gets this
	// far (rs/cors answers it outside the router), so nothing legitimate
	// depended on the passthrough; what did reach here was a non-preflight
	// OPTIONS reaching an auth-gated handler anonymously.
	if called {
		t.Error("OPTIONS must not reach the auth-gated handler (#3092)")
	}
	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

// TestAPIAuthMiddleware_IgnoresXTenantIDHeader verifies the middleware accepts
// requests with deprecated X-Tenant-ID header but uses auth-derived tenant.
func TestAPIAuthMiddleware_IgnoresXTenantIDHeader(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	var capturedTenant string
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	req.Header.Set("X-Tenant-ID", "old-sdk-tenant")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Request should pass through (accept and ignore header during transition)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
	// Auth-derived tenant should be used, not the header value
	if capturedTenant != "community" {
		t.Errorf("Expected auth-derived tenant 'community', got %q", capturedTenant)
	}
}

// TestAPIAuthMiddleware_EnterpriseMode_InvalidCredentials verifies invalid
// Basic auth credentials are rejected.
func TestAPIAuthMiddleware_EnterpriseMode_InvalidCredentials(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for invalid credentials")
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	// Set malformed Basic auth (missing colon separator)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("no-colon")))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", rr.Code)
	}
}

// TestAPIAuthMiddleware_EnterpriseMode_ValidCredentials verifies enterprise mode
// with valid credentials from the knownClients whitelist.
func TestAPIAuthMiddleware_EnterpriseMode_ValidCredentials(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("uses community whitelist keys that don't validate with enterprise Ed25519 signing")
	}
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	oldAuthDB := authDB
	authDB = nil
	defer func() { authDB = oldAuthDB }()

	var capturedTenant, capturedClient string
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantIDFromContext(r.Context())
		capturedClient = ClientIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Use the actual license key from knownClients whitelist
	licenseKey := knownClients["client_1"].LicenseKey
	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	req.SetBasicAuth("client_1", licenseKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if capturedTenant == "" {
		t.Error("Expected non-empty tenant from auth")
	}
	if capturedClient != "client_1" {
		t.Errorf("Expected client 'client_1', got %q", capturedClient)
	}
}

// TestAPIAuthMiddleware_EnterpriseMode_WrongPassword verifies wrong credentials rejected.
func TestAPIAuthMiddleware_EnterpriseMode_WrongPassword(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	oldAuthDB := authDB
	authDB = nil
	defer func() { authDB = oldAuthDB }()

	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	req.SetBasicAuth("client_1", "wrong_password")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong password, got %d", rr.Code)
	}
}

// TestAPIAuthMiddleware_UnsetDeploymentMode_RequiresAuth pins the #3096
// behaviour change at the middleware.
//
// This test previously asserted the opposite — that an unset DEPLOYMENT_MODE
// authenticated nobody and defaulted the tenant to "community". That was the
// defect: forgetting to configure a deployment mode disabled authentication.
// An unset mode now takes the enterprise path, so an anonymous request is
// rejected instead of being handed a default tenant.
func TestAPIAuthMiddleware_UnsetDeploymentMode_RequiresAuth(t *testing.T) {
	os.Unsetenv("DEPLOYMENT_MODE")

	oldAuthDB := authDB
	authDB = nil
	defer func() { authDB = oldAuthDB }()

	handlerRan := false
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRan = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if handlerRan {
		t.Error("an anonymous request reached the handler with DEPLOYMENT_MODE unset (#3096)")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestExtractClientID_EdgeCases verifies Basic auth clientId extraction edge cases.
func TestExtractClientID_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		auth     string
		expected string
	}{
		{"valid basic auth", "Basic " + base64.StdEncoding.EncodeToString([]byte("myid:mysecret")), "myid"},
		{"empty auth header", "", ""},
		{"bearer token (not basic)", "Bearer some-token", ""},
		{"malformed base64", "Basic not-valid-base64!!!", ""},
		{"empty client id", "Basic " + base64.StdEncoding.EncodeToString([]byte(":secret")), ""},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), "nocolon"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			got := extractClientID(req)
			if got != tt.expected {
				t.Errorf("extractClientID() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestExtractClientSecret_EdgeCases verifies Basic auth secret extraction edge cases.
func TestExtractClientSecret_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		auth     string
		expected string
	}{
		{"valid basic auth", "Basic " + base64.StdEncoding.EncodeToString([]byte("myid:mysecret")), "mysecret"},
		{"empty auth", "", ""},
		{"bearer token", "Bearer some-token", ""},
		{"empty secret", "Basic " + base64.StdEncoding.EncodeToString([]byte("myid:")), ""},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			got := extractClientSecret(req)
			if got != tt.expected {
				t.Errorf("extractClientSecret() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestValidateClientCredentials_WhitelistPath tests credential validation.
func TestValidateClientCredentials_WhitelistPath(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("uses community whitelist keys that don't validate with enterprise Ed25519 signing")
	}
	ctx := context.Background()

	t.Run("valid credentials", func(t *testing.T) {
		licenseKey := knownClients["client_1"].LicenseKey
		client, err := validateClientCredentials(ctx, "client_1", licenseKey)
		if err != nil {
			t.Fatalf("Expected success, got error: %v", err)
		}
		if client == nil {
			t.Fatal("Expected non-nil client")
		}
		if client.ID != "client_1" {
			t.Errorf("Expected client ID 'client_1', got %q", client.ID)
		}
	})

	t.Run("unknown client", func(t *testing.T) {
		_, err := validateClientCredentials(ctx, "unknown", "any-secret")
		if err == nil {
			t.Error("Expected error for unknown client")
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		_, err := validateClientCredentials(ctx, "client_1", "wrong-secret")
		if err == nil {
			t.Error("Expected error for wrong secret")
		}
	})

	t.Run("empty client id", func(t *testing.T) {
		_, err := validateClientCredentials(ctx, "", "any-secret")
		if err == nil {
			t.Error("Expected error for empty client ID")
		}
	})

	t.Run("empty secret", func(t *testing.T) {
		_, err := validateClientCredentials(ctx, "client_1", "")
		if err == nil {
			t.Error("Expected error for empty secret")
		}
	})
}

// TestCheckRateLimit_Disabled verifies rate limiting with disabled/high limits.
func TestCheckRateLimit_Disabled(t *testing.T) {
	// Should not be rate limited with 0 limit (disabled)
	err := checkRateLimit("test-rate-client", 0)
	if err != nil {
		t.Errorf("Expected no rate limit with limit=0, got: %v", err)
	}

	// Should not be rate limited with high limit
	err = checkRateLimit("test-rate-client-2", 10000)
	if err != nil {
		t.Errorf("Expected no rate limit with high limit, got: %v", err)
	}
}

// TestGetRateLimitStatus_Unknown verifies rate limit status for unknown client.
func TestGetRateLimitStatus_Unknown(t *testing.T) {
	count, limit, resetTime := getRateLimitStatus("nonexistent-client")
	if count != 0 || limit != 0 {
		t.Errorf("Expected 0/0 for unknown client, got %d/%d", count, limit)
	}
	if !resetTime.IsZero() {
		t.Error("Expected zero reset time for unknown client")
	}
}

// TestCreateAPIKey_CustomerNotFound_Middleware tests API key creation with missing customer.
func TestCreateAPIKey_CustomerNotFound_Middleware(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT").WillReturnError(fmt.Errorf("no rows"))

	_, err = createAPIKey(context.Background(), db, "nonexistent", "test-key", 30)
	if err == nil {
		t.Error("Expected error for nonexistent customer")
	}
}

// TestRevokeAPIKey_Success_Middleware tests API key revocation.
func TestRevokeAPIKey_Success_Middleware(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE api_keys").WillReturnResult(sqlmock.NewResult(0, 1))

	err = revokeAPIKey(context.Background(), db, "key-1", "admin", "test revocation")
	if err != nil {
		t.Errorf("Expected success, got: %v", err)
	}
}

// TestRevokeAPIKey_NotFound_Middleware tests API key revocation when key not found.
func TestRevokeAPIKey_NotFound_Middleware(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE api_keys").WillReturnResult(sqlmock.NewResult(0, 0))

	err = revokeAPIKey(context.Background(), db, "nonexistent", "admin", "test")
	if err == nil {
		t.Error("Expected error for nonexistent key")
	}
}

// TestProxyAuthMiddleware_CommunityMode_InjectsTenantFromBasicAuth verifies that
// the proxy middleware injects X-Tenant-ID from Basic auth clientId in community mode.
func TestProxyAuthMiddleware_CommunityMode_InjectsTenantFromBasicAuth(t *testing.T) {
	// Force community mode. #3096: naming the mode is now required — clearing
	// the license key alone no longer selects the community posture.
	t.Setenv("DEPLOYMENT_MODE", "community")

	oldLicense := os.Getenv("AXONFLOW_LICENSE_KEY")
	os.Unsetenv("AXONFLOW_LICENSE_KEY")
	defer func() {
		if oldLicense != "" {
			os.Setenv("AXONFLOW_LICENSE_KEY", oldLicense)
		}
	}()

	// Backend handler that checks the X-Tenant-ID header
	var receivedTenantID string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTenantID = r.Header.Get("X-Tenant-ID")
		w.WriteHeader(http.StatusOK)
	})

	handler := proxyAuthMiddleware(backend)

	t.Run("injects clientId as tenant from Basic auth", func(t *testing.T) {
		receivedTenantID = ""
		req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
		creds := base64.StdEncoding.EncodeToString([]byte("my-org:my-secret"))
		req.Header.Set("Authorization", "Basic "+creds)
		w := httptest.NewRecorder()

		handler(w, req)

		if receivedTenantID != "my-org" {
			t.Errorf("Expected X-Tenant-ID 'my-org', got '%s'", receivedTenantID)
		}
	})

	t.Run("defaults to community when no auth", func(t *testing.T) {
		receivedTenantID = ""
		req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		if receivedTenantID != "community" {
			t.Errorf("Expected X-Tenant-ID 'community', got '%s'", receivedTenantID)
		}
	})

	t.Run("overrides explicit X-Tenant-ID with server-derived identity", func(t *testing.T) {
		receivedTenantID = ""
		req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
		req.Header.Set("X-Tenant-ID", "explicit-tenant") // Client-supplied, should NOT be trusted
		w := httptest.NewRecorder()

		handler(w, req)

		// In community mode without Basic auth, tenant defaults to "community".
		// The agent never trusts client-supplied X-Tenant-ID — it always derives from auth.
		if receivedTenantID != "community" {
			t.Errorf("Expected X-Tenant-ID 'community' (server-derived), got '%s'", receivedTenantID)
		}
	})

	// #3092: the preflight is answered at the proxy auth boundary and never
	// forwarded to the orchestrator, so the backend must not observe it.
	t.Run("CORS preflight is terminated, not proxied", func(t *testing.T) {
		receivedTenantID = ""
		req := httptest.NewRequest("OPTIONS", "/api/v1/dynamic-policies", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Expected 204 for OPTIONS, got %d", w.Code)
		}
		if receivedTenantID != "" {
			t.Errorf("preflight was proxied to the backend (tenant %q)", receivedTenantID)
		}
	})
}

// TestProxyAuthMiddleware_DB_Integration tests proxy auth with a real database.
// This test only runs in CI where DATABASE_URL is set.
func TestProxyAuthMiddleware_DB_Integration(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping test database: %v", err)
	}

	t.Run("rejects invalid credentials against real DB", func(t *testing.T) {
		_, err := validateClientCredentialsDB(context.Background(), db, "nonexistent-client", "bad-secret")
		if err == nil {
			t.Error("Expected error for invalid credentials against real DB")
		}
	})

	t.Run("rejects empty credentials against real DB", func(t *testing.T) {
		_, err := validateClientCredentialsDB(context.Background(), db, "", "")
		if err == nil {
			t.Error("Expected error for empty credentials against real DB")
		}
	})
}

// TestAPIAuthMiddleware_CommunityMode_DefaultsTenant verifies the API auth
// middleware defaults to "community" tenant in community mode.
func TestAPIAuthMiddleware_CommunityMode_DefaultsTenant(t *testing.T) {
	// #3096: community mode must now be declared explicitly. This test used to
	// reach it by clearing the license key and letting an unset DEPLOYMENT_MODE
	// fall through to the community default — the very default that change
	// removed. Naming the mode keeps the test about tenant defaulting.
	t.Setenv("DEPLOYMENT_MODE", "community")

	oldLicense := os.Getenv("AXONFLOW_LICENSE_KEY")
	os.Unsetenv("AXONFLOW_LICENSE_KEY")
	defer func() {
		if oldLicense != "" {
			os.Setenv("AXONFLOW_LICENSE_KEY", oldLicense)
		}
	}()

	var capturedTenant string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := apiAuthMiddleware(backend)

	t.Run("no auth yields community tenant", func(t *testing.T) {
		capturedTenant = ""
		req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
		if capturedTenant != "community" {
			t.Errorf("Expected tenant 'community', got '%s'", capturedTenant)
		}
	})

	t.Run("Basic auth clientId becomes tenant", func(t *testing.T) {
		capturedTenant = ""
		req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
		creds := base64.StdEncoding.EncodeToString([]byte("test-org:"))
		req.Header.Set("Authorization", "Basic "+creds)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}
		if capturedTenant != "test-org" {
			t.Errorf("Expected tenant 'test-org', got '%s'", capturedTenant)
		}
	})
}

// TestExtractClientID tests the Basic auth client ID extraction helper.
func TestExtractClientID_Middleware(t *testing.T) {
	tests := []struct {
		name     string
		authHdr  string
		expected string
	}{
		{"valid Basic auth", "Basic " + base64.StdEncoding.EncodeToString([]byte("myorg:mysecret")), "myorg"},
		{"empty secret", "Basic " + base64.StdEncoding.EncodeToString([]byte("myorg:")), "myorg"},
		{"no auth header", "", ""},
		{"Bearer token", "Bearer some-token", ""},
		{"invalid base64", "Basic !!!invalid!!!", ""},
		{"empty client", "Basic " + base64.StdEncoding.EncodeToString([]byte(":secret")), ""},
		{"just colon", "Basic " + base64.StdEncoding.EncodeToString([]byte(":")), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.authHdr != "" {
				req.Header.Set("Authorization", tt.authHdr)
			}
			got := extractClientID(req)
			if got != tt.expected {
				t.Errorf("extractClientID() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestExtractClientSecret tests the Basic auth client secret extraction helper.
func TestExtractClientSecret_Middleware(t *testing.T) {
	tests := []struct {
		name     string
		authHdr  string
		expected string
	}{
		{"valid Basic auth", "Basic " + base64.StdEncoding.EncodeToString([]byte("myorg:mysecret")), "mysecret"},
		{"empty secret", "Basic " + base64.StdEncoding.EncodeToString([]byte("myorg:")), ""},
		{"no auth header", "", ""},
		{"Bearer token", "Bearer some-token", ""},
		{"invalid base64", "Basic !!!invalid!!!", ""},
		{"long secret", "Basic " + base64.StdEncoding.EncodeToString([]byte("org:AXON-abc123.def456")), "AXON-abc123.def456"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.authHdr != "" {
				req.Header.Set("Authorization", tt.authHdr)
			}
			got := extractClientSecret(req)
			if got != tt.expected {
				t.Errorf("extractClientSecret() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestProxyAuthMiddleware_EnterpriseMode_RequiresAuth verifies that enterprise
// mode rejects unauthenticated requests.
func TestProxyAuthMiddleware_EnterpriseMode_RequiresAuth(t *testing.T) {
	// Force enterprise mode via DEPLOYMENT_MODE
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := proxyAuthMiddleware(backend)

	t.Run("rejects request with no auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}
	})

	t.Run("rejects request with empty credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
		creds := base64.StdEncoding.EncodeToString([]byte(":"))
		req.Header.Set("Authorization", "Basic "+creds)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}
	})

	// #3092: terminated here too — an unauthenticated preflight must not be
	// forwarded to the orchestrator in enterprise mode either.
	t.Run("CORS preflight is terminated in enterprise mode", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/v1/dynamic-policies", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("Expected 204 for OPTIONS, got %d", w.Code)
		}
	})
}

// TestIsCommunityMode tests the community mode detection.
func TestIsCommunityMode(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	// #3096: an unset DEPLOYMENT_MODE must NOT confer the community posture.
	// Community bypasses authentication and license validation entirely, so it
	// has to be asked for by name; forgetting to configure a mode now yields
	// the enterprise posture, matching isAdminAuthRequired's deny-by-default.
	t.Run("empty DEPLOYMENT_MODE is NOT community", func(t *testing.T) {
		os.Unsetenv("DEPLOYMENT_MODE")
		if isCommunityMode() {
			t.Error("unset DEPLOYMENT_MODE must fail closed to the enterprise posture (#3096)")
		}
	})

	t.Run("unrecognised DEPLOYMENT_MODE is not community", func(t *testing.T) {
		os.Setenv("DEPLOYMENT_MODE", "communtiy") // typo
		if isCommunityMode() {
			t.Error("a typo'd DEPLOYMENT_MODE must not confer the community posture")
		}
	})

	// Not trimmed and not case-folded on purpose: every widening of this
	// predicate disables authentication. See the doc comment on isCommunityMode.
	t.Run("whitespace-padded DEPLOYMENT_MODE is not community", func(t *testing.T) {
		os.Setenv("DEPLOYMENT_MODE", " community ")
		if isCommunityMode() {
			t.Error("a whitespace-padded mode must fail closed, not widen the community set")
		}
	})

	t.Run("community DEPLOYMENT_MODE is community", func(t *testing.T) {
		os.Setenv("DEPLOYMENT_MODE", "community")
		if !isCommunityMode() {
			t.Error("Expected community mode when DEPLOYMENT_MODE=community")
		}
	})

	t.Run("enterprise DEPLOYMENT_MODE is not community", func(t *testing.T) {
		os.Setenv("DEPLOYMENT_MODE", "enterprise")
		if isCommunityMode() {
			t.Error("Expected non-community mode when DEPLOYMENT_MODE=enterprise")
		}
	})
}
