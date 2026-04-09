// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// These DB-backed tests run against a real PostgreSQL in CI (DATABASE_URL set).
// They skip locally when no DB is available. This is the same pattern used in
// auth_middleware_db_test.go and mcp_handler_auth_test.go.

func getTestDBForCSAAS(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("Skipping DB integration test: DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping: %v", err)
	}

	// Check if community_saas_registrations table exists (migration 068)
	var exists bool
	err = db.QueryRow(`SELECT EXISTS (
		SELECT FROM information_schema.tables
		WHERE table_name = 'community_saas_registrations'
	)`).Scan(&exists)
	if err != nil || !exists {
		t.Skip("Skipping: community_saas_registrations table not found (migration 068 not applied)")
	}
	return db
}

func TestHandleCommunityRegister_DB_Success(t *testing.T) {
	db := getTestDBForCSAAS(t)
	defer db.Close()

	handler := handleCommunityRegister(db)
	body := `{"label":"test-e2e"}`
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.99:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp registrationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if !strings.HasPrefix(resp.TenantID, "cs_") {
		t.Errorf("tenant_id should have cs_ prefix, got %s", resp.TenantID)
	}
	if len(resp.Secret) != 32 {
		t.Errorf("secret should be 32 hex chars, got %d chars", len(resp.Secret))
	}
	if len(resp.SecretPrefix) != 8 {
		t.Errorf("secret_prefix should be 8 chars, got %d", len(resp.SecretPrefix))
	}
	if resp.Secret[:8] != resp.SecretPrefix {
		t.Errorf("secret_prefix should match first 8 chars of secret")
	}
	if resp.Endpoint != communitySaasTryEndpoint {
		t.Errorf("Expected endpoint %s, got %s", communitySaasTryEndpoint, resp.Endpoint)
	}
	if resp.Note == "" {
		t.Error("note should not be empty")
	}

	// Verify expiry is approximately 30 days from now
	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("Failed to parse expires_at: %v", err)
	}
	expectedExpiry := time.Now().Add(30 * 24 * time.Hour)
	diff := expectedExpiry.Sub(expiresAt)
	if diff < -1*time.Hour || diff > 1*time.Hour {
		t.Errorf("expires_at should be ~30 days from now, diff: %v", diff)
	}

	// Clean up
	db.Exec("DELETE FROM community_saas_registrations WHERE tenant_id = $1", resp.TenantID)
	db.Exec("DELETE FROM tenants WHERE tenant_id = $1", resp.TenantID)
}

func TestValidateCommunityRegistration_DB_FullLifecycle(t *testing.T) {
	db := getTestDBForCSAAS(t)
	defer db.Close()

	// Register a tenant
	handler := handleCommunityRegister(db)
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.100:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Registration failed: %d %s", rr.Code, rr.Body.String())
	}

	var resp registrationResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	ctx := context.Background()

	// Valid secret should pass
	err := validateCommunityRegistration(ctx, db, resp.TenantID, resp.Secret)
	if err != nil {
		t.Errorf("Valid secret should pass: %v", err)
	}

	// Wrong secret should fail
	err = validateCommunityRegistration(ctx, db, resp.TenantID, "wrong-secret-12345678901234567890")
	if err != ErrInvalidSecret {
		t.Errorf("Expected ErrInvalidSecret, got %v", err)
	}

	// Unknown tenant should fail
	err = validateCommunityRegistration(ctx, db, "cs_nonexistent-uuid", resp.Secret)
	if err != ErrRegistrationNotFound {
		t.Errorf("Expected ErrRegistrationNotFound, got %v", err)
	}

	// Disable the tenant
	db.Exec("UPDATE community_saas_registrations SET disabled_at = NOW() WHERE tenant_id = $1", resp.TenantID)
	err = validateCommunityRegistration(ctx, db, resp.TenantID, resp.Secret)
	if err != ErrRegistrationDisabled {
		t.Errorf("Expected ErrRegistrationDisabled, got %v", err)
	}

	// Re-enable and expire
	db.Exec("UPDATE community_saas_registrations SET disabled_at = NULL, expires_at = NOW() - INTERVAL '1 day' WHERE tenant_id = $1", resp.TenantID)
	err = validateCommunityRegistration(ctx, db, resp.TenantID, resp.Secret)
	if err != ErrRegistrationExpired {
		t.Errorf("Expected ErrRegistrationExpired, got %v", err)
	}

	// Clean up
	db.Exec("DELETE FROM community_saas_registrations WHERE tenant_id = $1", resp.TenantID)
	db.Exec("DELETE FROM tenants WHERE tenant_id = $1", resp.TenantID)
}

func TestCheckDailyLimitDB_FullLifecycle(t *testing.T) {
	db := getTestDBForCSAAS(t)
	defer db.Close()

	// Check if daily_usage table exists
	var exists bool
	db.QueryRow(`SELECT EXISTS (
		SELECT FROM information_schema.tables
		WHERE table_name = 'community_saas_daily_usage'
	)`).Scan(&exists)
	if !exists {
		t.Skip("community_saas_daily_usage table not found")
	}

	tenantID := "cs_test-daily-limit-" + time.Now().Format("20060102150405")
	ctx := context.Background()

	// Requests 1-5 should all succeed (cap is 5)
	// Each call to checkDailyLimitDB increments the counter then checks > cap.
	// count=1 → not >5 ✓, count=2 → not >5 ✓, ..., count=5 → not >5 ✓
	for i := 1; i <= 5; i++ {
		err := checkDailyLimitDB(ctx, tenantID, 5, db)
		if err != nil {
			t.Errorf("Request %d (at or under cap) should succeed: %v", i, err)
		}
	}

	// 6th request: count becomes 6, which is >5 → should fail
	err := checkDailyLimitDB(ctx, tenantID, 5, db)
	if err != ErrDailyLimitExceeded {
		t.Errorf("6th request (over cap) should return ErrDailyLimitExceeded, got %v", err)
	}

	// Clean up
	db.Exec("DELETE FROM community_saas_daily_usage WHERE tenant_id = $1", tenantID)
}

func TestHandleCommunityRegister_DB_ContentTypeVariants(t *testing.T) {
	db := getTestDBForCSAAS(t)
	defer db.Close()

	tests := []struct {
		name        string
		contentType string
		expectCode  int
	}{
		{"application/json", "application/json", http.StatusCreated},
		{"with charset", "application/json; charset=utf-8", http.StatusCreated},
		{"text/plain", "text/plain", http.StatusUnsupportedMediaType},
		{"empty (allowed)", "", http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := handleCommunityRegister(db)
			req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(`{}`))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			req.RemoteAddr = "10.0.0.200:12345"
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectCode {
				t.Errorf("Content-Type %q: expected %d, got %d: %s",
					tt.contentType, tt.expectCode, rr.Code, rr.Body.String())
			}

			// Clean up created registrations
			if rr.Code == http.StatusCreated {
				var resp registrationResponse
				json.Unmarshal(rr.Body.Bytes(), &resp)
				db.Exec("DELETE FROM community_saas_registrations WHERE tenant_id = $1", resp.TenantID)
				db.Exec("DELETE FROM tenants WHERE tenant_id = $1", resp.TenantID)
			}
		})
	}
}

func TestHandleCommunityRegister_DB_LabelTooLong(t *testing.T) {
	db := getTestDBForCSAAS(t)
	defer db.Close()

	handler := handleCommunityRegister(db)
	longLabel := strings.Repeat("x", maxLabelLength+1)
	body := `{"label":"` + longLabel + `"}`
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.201:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for long label, got %d", rr.Code)
	}
}

func TestHandleCommunityRegister_DB_InvalidJSON(t *testing.T) {
	db := getTestDBForCSAAS(t)
	defer db.Close()

	handler := handleCommunityRegister(db)
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.202:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestHandleCommunityRegister_DB_OversizedBody(t *testing.T) {
	db := getTestDBForCSAAS(t)
	defer db.Close()

	handler := handleCommunityRegister(db)
	bigBody := `{"label":"` + strings.Repeat("x", maxRequestBodySize+100) + `"}`
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.203:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 413 for oversized body, got %d", rr.Code)
	}
}
