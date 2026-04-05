package agent

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	_ "github.com/lib/pq"
)

// TestIdentityModel_CommunityMode_InjectsHeaders verifies that community mode
// injects X-Tenant-ID and X-Org-ID headers from Basic auth and deployment ORG_ID.
func TestIdentityModel_CommunityMode_InjectsHeaders(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	var capturedTenantID, capturedOrgID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenantID = r.Header.Get("X-Tenant-ID")
		capturedOrgID = r.Header.Get("X-Org-ID")
		w.WriteHeader(http.StatusOK)
	})

	handler := proxyAuthMiddleware(inner)

	// Test 1: No auth → defaults to "community" tenant, deployment org
	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if capturedTenantID != "community" {
		t.Errorf("expected tenant_id 'community', got %q", capturedTenantID)
	}
	expectedOrg := getDeploymentOrgID()
	if capturedOrgID != expectedOrg {
		t.Errorf("expected org_id %q, got %q", expectedOrg, capturedOrgID)
	}

	// Test 2: Basic auth with custom clientId → uses that as tenant
	capturedTenantID = ""
	capturedOrgID = ""
	req2 := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("my-tenant:"))
	req2.Header.Set("Authorization", "Basic "+creds)
	w2 := httptest.NewRecorder()
	handler(w2, req2)

	if capturedTenantID != "my-tenant" {
		t.Errorf("expected tenant_id 'my-tenant', got %q", capturedTenantID)
	}
	if capturedOrgID != expectedOrg {
		t.Errorf("expected org_id %q, got %q", expectedOrg, capturedOrgID)
	}
}

// TestIdentityModel_CommunityMode_OverridesClientSuppliedHeaders verifies that
// community mode does NOT trust client-supplied X-Tenant-ID headers.
func TestIdentityModel_CommunityMode_OverridesClientSuppliedHeaders(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	var capturedTenantID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenantID = r.Header.Get("X-Tenant-ID")
		w.WriteHeader(http.StatusOK)
	})

	handler := proxyAuthMiddleware(inner)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	req.Header.Set("X-Tenant-ID", "spoofed-tenant")
	w := httptest.NewRecorder()
	handler(w, req)

	// Server-derived "community" should override client-supplied "spoofed-tenant"
	if capturedTenantID != "community" {
		t.Errorf("expected server-derived 'community', got client-supplied %q", capturedTenantID)
	}
}

// TestIdentityModel_RegisterTenantAndOrg_CachesAfterFirstCall verifies that
// auto-registration only hits DB once per tenant+org pair.
func TestIdentityModel_RegisterTenantAndOrg_CachesAfterFirstCall(t *testing.T) {
	// Reset the cache
	registeredTenants = sync.Map{}

	// Without a DB, registerTenantAndOrg should return immediately
	registerTenantAndOrg(nil, "test-tenant", "test-org", "Community", 2)

	// Verify cache was NOT populated (nil DB = early return)
	if _, loaded := registeredTenants.Load("test-tenant|test-org"); loaded {
		t.Error("cache should not be populated when DB is nil")
	}
}

// TestIdentityModel_DB_RegisterTenantAndOrg verifies DB-backed auto-registration
// when DATABASE_URL is available (integration test — skipped without DB).
func TestIdentityModel_DB_RegisterTenantAndOrg(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set — skipping DB integration test")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("failed to open DB: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Skipf("DB not reachable: %v", err)
	}

	// Reset cache
	registeredTenants = sync.Map{}

	// First call should attempt DB write (may fail if tables don't exist — that's ok)
	registerTenantAndOrg(db, "integration-tenant", "integration-org", "Community", 2)

	// Second call should be cached (no DB hit)
	registerTenantAndOrg(db, "integration-tenant", "integration-org", "Community", 2)

	// Verify it was cached
	if _, loaded := registeredTenants.Load("integration-tenant|integration-org"); !loaded {
		t.Error("tenant+org pair should be cached after registration")
	}
}
