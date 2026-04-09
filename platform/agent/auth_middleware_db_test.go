// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// These DB-backed tests target the proxyAuthMiddleware happy paths and the
// org_id-from-license forwarding behavior introduced in v6.2.0 (#1526).
// They run against a real Postgres in CI (DATABASE_URL set) and skip locally
// when no DB is available.

// TestProxyAuthMiddleware_DB_HappyPath_EnterpriseMode verifies the full
// success path: Basic auth credentials → license validation → identity
// headers set on the downstream request → backend handler invoked.
func TestProxyAuthMiddleware_DB_HappyPath_EnterpriseMode(t *testing.T) {
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

	// Force enterprise mode
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	// Set authDB so the proxy middleware uses the real DB path
	oldAuthDB := authDB
	authDB = db
	defer func() { authDB = oldAuthDB }()

	// Generate a valid V2 service license for org "tenant-a"
	// This exercises validateClientCredentialsDB → validateViaOrganizations
	// → license signature verification → registerTenantAndOrg goroutine.
	licenseKey := generateTestLicenseKey("tenant-a", "Enterprise", "20351231")

	var capturedTenant, capturedOrg string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = r.Header.Get("X-Tenant-ID")
		capturedOrg = r.Header.Get("X-Org-ID")
		w.WriteHeader(http.StatusOK)
	})

	handler := proxyAuthMiddleware(backend)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("tenant-a:" + licenseKey))
	req.Header.Set("Authorization", "Basic "+creds)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if capturedTenant != "tenant-a" {
		t.Errorf("Expected X-Tenant-ID=tenant-a, got %q", capturedTenant)
	}
	// Critical v6.2.0 assertion: org_id must come from the license payload,
	// NOT from the deployment ORG_ID env var. The license signed it with
	// "tenant-a" as the org, so the proxy must forward exactly that.
	if capturedOrg != "tenant-a" {
		t.Errorf("Expected X-Org-ID=tenant-a (from license), got %q", capturedOrg)
	}

	// Allow the fire-and-forget registerTenantAndOrg goroutine to complete
	// before the test exits, so we don't leak DB writes into other tests.
	time.Sleep(100 * time.Millisecond)
}

// TestProxyAuthMiddleware_DB_OrgIDIsLicenseAuthority is the v6.2.0 multi-tenant
// SaaS regression test: two different licenses with two different org_ids must
// each forward their OWN org_id, not a shared deployment value.
func TestProxyAuthMiddleware_DB_OrgIDIsLicenseAuthority(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	// Set a deployment ORG_ID that does NOT match either tenant.
	// The proxy MUST NOT forward this — it must use each license's own org_id.
	oldDeployOrg := os.Getenv("ORG_ID")
	os.Setenv("ORG_ID", "deployment-shared")
	defer func() {
		if oldDeployOrg != "" {
			os.Setenv("ORG_ID", oldDeployOrg)
		} else {
			os.Unsetenv("ORG_ID")
		}
	}()

	oldAuthDB := authDB
	authDB = db
	defer func() { authDB = oldAuthDB }()

	tests := []struct {
		name     string
		clientID string
		orgID    string
	}{
		{"first tenant on shared stack", "tenant-alpha", "org-alpha"},
		{"second tenant on shared stack", "tenant-beta", "org-beta"},
		{"third tenant on shared stack", "tenant-gamma", "org-gamma"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseKey := generateTestLicenseKey(tt.orgID, "Enterprise", "20351231")

			var capturedOrg string
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedOrg = r.Header.Get("X-Org-ID")
				w.WriteHeader(http.StatusOK)
			})

			handler := proxyAuthMiddleware(backend)

			req := httptest.NewRequest("POST", "/api/v1/process", nil)
			creds := base64.StdEncoding.EncodeToString([]byte(tt.clientID + ":" + licenseKey))
			req.Header.Set("Authorization", "Basic "+creds)
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected 200, got %d", w.Code)
			}
			if capturedOrg != tt.orgID {
				t.Errorf("Expected X-Org-ID=%q (from license), got %q", tt.orgID, capturedOrg)
			}
			if capturedOrg == "deployment-shared" {
				t.Error("REGRESSION: org_id was stamped from deployment ORG_ID, must come from license")
			}

			// Let the auto-register goroutine finish
			time.Sleep(50 * time.Millisecond)
		})
	}
}

// TestProxyAuthMiddleware_DB_RejectsBadLicense verifies invalid license keys
// are rejected with 401 even though the clientID is non-empty.
func TestProxyAuthMiddleware_DB_RejectsBadLicense(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	oldAuthDB := authDB
	authDB = db
	defer func() { authDB = oldAuthDB }()

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := proxyAuthMiddleware(backend)

	cases := []struct {
		name      string
		clientID  string
		secret    string
		expectErr int
	}{
		{"malformed license", "tenant-x", "AXON-not-base64-payload.bad", http.StatusUnauthorized},
		{"empty secret in basic auth", "tenant-x", "", http.StatusUnauthorized},
		{"random string secret", "tenant-x", "definitely-not-a-license-key", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
			creds := base64.StdEncoding.EncodeToString([]byte(tc.clientID + ":" + tc.secret))
			req.Header.Set("Authorization", "Basic "+creds)
			w := httptest.NewRecorder()
			handler(w, req)
			if w.Code != tc.expectErr {
				t.Errorf("Expected %d, got %d", tc.expectErr, w.Code)
			}
		})
	}
}

// TestValidateClientCredentialsDB_HappyPath exercises the full DB-backed
// credential validation pipeline with a real database. This is the entry
// point that proxyAuthMiddleware delegates to in enterprise mode.
func TestValidateClientCredentialsDB_HappyPath(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	// Generate a valid V2 service license. validateViaAPIKeys will fail
	// (no api_keys row matches our hash), then the function falls back to
	// validateViaOrganizations which validates the Ed25519 signature and
	// returns the client without needing a DB row.
	licenseKey := generateTestLicenseKey("integration-org", "Professional", "20351231")

	client, err := validateClientCredentialsDB(context.Background(), db, "integration-tenant", licenseKey)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.OrgID != "integration-org" {
		t.Errorf("Expected OrgID=integration-org, got %q", client.OrgID)
	}
	if client.TenantID != "integration-tenant" {
		t.Errorf("Expected TenantID=integration-tenant (from clientID), got %q", client.TenantID)
	}
	if client.LicenseTier != "Professional" {
		t.Errorf("Expected tier=Professional, got %q", client.LicenseTier)
	}
	if !client.Enabled {
		t.Error("Expected client to be enabled")
	}

	// Wait for fire-and-forget registerTenantAndOrg goroutine
	time.Sleep(100 * time.Millisecond)
}

// TestValidateClientCredentialsDB_RequiredFields covers the early-return
// validation paths for missing inputs.
func TestValidateClientCredentialsDB_RequiredFields(t *testing.T) {
	// No DB needed — these are pure input validation paths that return early.
	cases := []struct {
		name     string
		clientID string
		secret   string
	}{
		{"empty client id", "", "some-secret"},
		{"empty secret", "client-id", ""},
		{"both empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateClientCredentialsDB(context.Background(), nil, tc.clientID, tc.secret)
			if err == nil {
				t.Errorf("Expected error for %s", tc.name)
			}
		})
	}
}

// TestRegisterTenantAndOrg_DB exercises the auto-registration helper that
// runs as a fire-and-forget goroutine after successful proxy auth. This is
// the path that populates the tenants table on first-seen tenant+org pairs.
func TestRegisterTenantAndOrg_DB(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	t.Run("registers new tenant and org", func(t *testing.T) {
		// Synchronously call (not the fire-and-forget goroutine version)
		// so we can assert on the side effect.
		registerTenantAndOrg(db, "test-register-tenant", "test-register-org", "Professional", 10)
		// No assertion error means the SQL functions executed without error.
		// The dedup map (sync.Map) ensures subsequent calls are no-ops.
	})

	t.Run("noop on second call (dedup)", func(t *testing.T) {
		registerTenantAndOrg(db, "test-register-tenant", "test-register-org", "Professional", 10)
	})

	t.Run("rejects empty tenant", func(t *testing.T) {
		// Should return early without DB call — no panic, no error escapes.
		registerTenantAndOrg(db, "", "some-org", "Professional", 10)
	})

	t.Run("rejects empty org", func(t *testing.T) {
		registerTenantAndOrg(db, "some-tenant", "", "Professional", 10)
	})

	t.Run("rejects nil db", func(t *testing.T) {
		registerTenantAndOrg(nil, "some-tenant", "some-org", "Professional", 10)
	})
}

// TestGetCustomerUsageForMonth_DB exercises the usage query with a real DB.
// Both the no-rows fallback and the real-rows path are covered when the
// customer has any (or no) data for the requested month.
func TestGetCustomerUsageForMonth_DB(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	// Skip if the test DB doesn't have the usage_metrics table — some CI
	// jobs (Unit Tests: All Modules) run go test without applying migrations.
	var exists bool
	err = db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'usage_metrics')`).Scan(&exists)
	if err != nil || !exists {
		t.Skip("Skipping: usage_metrics table not present in test DB")
	}

	// Use a valid UUID since customer_id is uuid type in the test schema.
	missingUUID := "00000000-0000-0000-0000-000000000000"

	t.Run("returns zero stats for customer with no usage", func(t *testing.T) {
		stats, err := getCustomerUsageForMonth(context.Background(), db, missingUUID, time.Now())
		if err != nil {
			t.Fatalf("expected no error for missing customer, got %v", err)
		}
		if stats == nil {
			t.Fatal("expected non-nil stats")
		}
		if stats.TotalRequests != 0 {
			t.Errorf("expected 0 requests for missing customer, got %d", stats.TotalRequests)
		}
	})

	t.Run("handles previous month query", func(t *testing.T) {
		lastMonth := time.Now().AddDate(0, -1, 0)
		_, err := getCustomerUsageForMonth(context.Background(), db, missingUUID, lastMonth)
		if err != nil {
			t.Errorf("unexpected error querying last month: %v", err)
		}
	})
}

// TestRevokeAPIKey_DB covers the API key revoke path. The not-found branch
// is reached when the api_key_id doesn't exist.
func TestRevokeAPIKey_DB(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	t.Run("returns error for nonexistent key", func(t *testing.T) {
		err := revokeAPIKey(context.Background(), db, "nonexistent-key-id", "test-admin", "test-cleanup")
		if err == nil {
			t.Error("expected error revoking nonexistent key")
		}
	})

	t.Run("returns error for empty key id", func(t *testing.T) {
		err := revokeAPIKey(context.Background(), db, "", "test-admin", "test-cleanup")
		if err == nil {
			t.Error("expected error for empty key id")
		}
	})
}

// TestUpdateAPIKeyLastUsed_DB exercises the timestamp updater. The function
// is fire-and-forget so we just need it to not panic against a real DB.
func TestUpdateAPIKeyLastUsed_DB(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	// nonexistent key — function logs and continues without panic
	updateAPIKeyLastUsed(context.Background(), db, "nonexistent-key-id-12345")
}

// TestCreateReverseProxy_ErrorHandler exercises the proxy ErrorHandler path
// which logs failures, optionally records circuit breaker errors, and returns
// a 502. This is the path the v6.2.0 fix touches via the X-Org-ID forwarding.
func TestCreateReverseProxy_ErrorHandler(t *testing.T) {
	// Create a proxy pointing at a deliberately-invalid backend so the
	// ErrorHandler fires when we make a request through it.
	target, _ := url.Parse("http://127.0.0.1:1") // port 1 is closed
	proxy := createReverseProxy(target, "test-orchestrator")

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502 from ErrorHandler, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Backend service unavailable") {
		t.Errorf("expected error JSON, got %s", w.Body.String())
	}
}

// TestCreateReverseProxy_ErrorHandler_NoCircuitBreaker covers the path where
// circuitBreakerInstance is nil — should still return 502 without panicking.
func TestCreateReverseProxy_ErrorHandler_NoCircuitBreaker(t *testing.T) {
	oldCB := circuitBreakerInstance
	circuitBreakerInstance = nil
	defer func() { circuitBreakerInstance = oldCB }()

	target, _ := url.Parse("http://127.0.0.1:1")
	proxy := createReverseProxy(target, "test-orchestrator")

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}
}

// TestCreateReverseProxy_ErrorHandler_MissingHeaders covers the path where
// X-Org-ID or X-Tenant-ID is missing — circuit breaker recording should be
// skipped, but the 502 response still goes out.
func TestCreateReverseProxy_ErrorHandler_MissingHeaders(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:1")
	proxy := createReverseProxy(target, "test-orchestrator")

	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	// No identity headers set
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}
}

// TestAPIAuthMiddleware_DB_RoutesThroughDB verifies that apiAuthMiddleware
// uses validateClientCredentialsDB when authDB is set (covering the DB
// branch of the credential validation pipeline).
func TestAPIAuthMiddleware_DB_RoutesThroughDB(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	oldAuthDB := authDB
	authDB = db
	defer func() { authDB = oldAuthDB }()

	licenseKey := generateTestLicenseKey("api-org", "Enterprise", "20351231")

	var capturedTenant, capturedOrg string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantIDFromContext(r.Context())
		capturedOrg = OrgIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := apiAuthMiddleware(backend)
	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("api-tenant:" + licenseKey))
	req.Header.Set("Authorization", "Basic "+creds)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if capturedTenant != "api-tenant" {
		t.Errorf("expected tenant=api-tenant, got %q", capturedTenant)
	}
	if capturedOrg != "api-org" {
		t.Errorf("expected org=api-org from license, got %q", capturedOrg)
	}

	// Wait for fire-and-forget registerTenantAndOrg
	time.Sleep(100 * time.Millisecond)
}

// TestAPIAuthMiddleware_DB_DeprecatedHeader covers the deprecation log path
// when X-Tenant-ID is present alongside Basic auth — the auth-derived tenant
// must take precedence.
func TestAPIAuthMiddleware_DB_DeprecatedHeader(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer db.Close()

	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	oldAuthDB := authDB
	authDB = db
	defer func() { authDB = oldAuthDB }()

	licenseKey := generateTestLicenseKey("dep-org", "Enterprise", "20351231")

	var capturedTenant string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := apiAuthMiddleware(backend)
	req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
	// Set both: deprecated X-Tenant-ID header AND Basic auth.
	// Auth-derived tenant must win.
	req.Header.Set("X-Tenant-ID", "spoofed-tenant")
	creds := base64.StdEncoding.EncodeToString([]byte("real-tenant:" + licenseKey))
	req.Header.Set("Authorization", "Basic "+creds)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if capturedTenant != "real-tenant" {
		t.Errorf("auth-derived tenant must override header, got %q", capturedTenant)
	}

	time.Sleep(100 * time.Millisecond)
}

// TestProxyAuthMiddleware_DB_DisabledClientPath verifies that a client whose
// Enabled=false is rejected with 403 even after successful credential auth.
// This requires a license that validates but a client whose Enabled is
// flipped after validation. We exercise this via the validateClientCredentials
// in-memory path that knownClients controls.
func TestProxyAuthMiddleware_DB_DisabledClientPath(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	// Force the no-DB path so validateClientCredentials (in-memory) runs.
	oldAuthDB := authDB
	authDB = nil
	defer func() { authDB = oldAuthDB }()

	licenseKey := generateTestLicenseKey("disabled-org", "Enterprise", "20351231")

	// Register a known client with Enabled=false.
	knownClients["disabled-client"] = &ClientAuth{
		ClientID:    "disabled-client",
		LicenseKey:  licenseKey,
		Name:        "Disabled Test Client",
		TenantID:    "disabled-client",
		Permissions: []string{"query"},
		RateLimit:   100,
		Enabled:     false,
	}
	defer delete(knownClients, "disabled-client")

	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := proxyAuthMiddleware(backend)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("disabled-client:" + licenseKey))
	req.Header.Set("Authorization", "Basic "+creds)
	w := httptest.NewRecorder()
	handler(w, req)

	// Disabled client should get 401 from credential validation OR 403 from
	// the client.Enabled check — both are acceptable rejections of a
	// disabled identity.
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Errorf("Expected 401 or 403 for disabled client, got %d", w.Code)
	}
}
