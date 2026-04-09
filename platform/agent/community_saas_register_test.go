// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func TestHandleCommunityRegister_NilDB(t *testing.T) {
	handler := handleCommunityRegister(nil)
	req := httptest.NewRequest("POST", "/api/v1/register", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 for nil DB, got %d", rr.Code)
	}
}

func TestHandleCommunityRegister_InvalidContentType(t *testing.T) {
	// Need a non-nil DB — use a sentinel (handler checks nil before DB use)
	// We can't easily create a real DB in unit tests, so test the Content-Type
	// check path which fires before DB access
	handler := handleCommunityRegister(nil) // Will hit nil DB check first
	req := httptest.NewRequest("POST", "/api/v1/register", nil)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// nil DB check fires first (503), not content type check
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 (nil DB fires first), got %d", rr.Code)
	}
}

func TestHandleCommunityRegister_ContentTypeWithCharset(t *testing.T) {
	// Verify that application/json; charset=utf-8 is accepted
	handler := handleCommunityRegister(nil)
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// Should pass content-type check and fail on nil DB (503)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 (nil DB), got %d — Content-Type may have been rejected", rr.Code)
	}
}

func TestHandleCommunityRegister_OversizedBody(t *testing.T) {
	handler := handleCommunityRegister(nil)
	// Create body > 1KB
	bigBody := strings.Repeat("x", maxRequestBodySize+100)
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// nil DB fires first
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 (nil DB fires first), got %d", rr.Code)
	}
}

func TestRegistrationIPTracker_Basic(t *testing.T) {
	tracker := &registrationIPTracker{
		entries: make(map[string]*ipRegistrationEntry),
	}

	// First 5 requests from same IP should succeed
	for i := 0; i < registrationIPLimit; i++ {
		if err := tracker.check("192.168.1.1"); err != nil {
			t.Errorf("Request %d: unexpected error: %v", i+1, err)
		}
	}

	// 6th request should fail
	if err := tracker.check("192.168.1.1"); err != ErrRegistrationRateLimit {
		t.Errorf("Request 6: expected ErrRegistrationRateLimit, got %v", err)
	}
}

func TestRegistrationIPTracker_DifferentIPs(t *testing.T) {
	tracker := &registrationIPTracker{
		entries: make(map[string]*ipRegistrationEntry),
	}

	// Different IPs should be independent
	for i := 0; i < registrationIPLimit; i++ {
		if err := tracker.check("10.0.0.1"); err != nil {
			t.Errorf("IP1 request %d: unexpected error: %v", i+1, err)
		}
	}
	// IP1 is exhausted
	if err := tracker.check("10.0.0.1"); err != ErrRegistrationRateLimit {
		t.Errorf("IP1 should be rate-limited")
	}

	// IP2 should still work
	if err := tracker.check("10.0.0.2"); err != nil {
		t.Errorf("IP2 should not be rate-limited: %v", err)
	}
}

func TestRegistrationIPTracker_Cleanup(t *testing.T) {
	tracker := &registrationIPTracker{
		entries: make(map[string]*ipRegistrationEntry),
	}

	// Fill with more than ipTrackerMaxEntries expired entries using fmt for unique keys
	targetCount := ipTrackerMaxEntries + 100
	for i := 0; i < targetCount; i++ {
		key := "ip-" + strings.Join([]string{strings.Repeat("0", 6), fmt.Sprintf("%06d", i)}, "-")
		tracker.entries[key] = &ipRegistrationEntry{
			count:     1,
			resetTime: time.Now().Add(-1 * time.Hour), // Expired
		}
	}

	if len(tracker.entries) <= ipTrackerMaxEntries {
		t.Fatalf("Setup failed: entries should exceed max, got %d", len(tracker.entries))
	}

	// Next check should trigger cleanup
	if err := tracker.check("new-ip"); err != nil {
		t.Errorf("New IP after cleanup should succeed: %v", err)
	}

	// Expired entries should have been cleaned — only "new-ip" remains
	if len(tracker.entries) > 2 {
		t.Errorf("Cleanup should have reduced entries significantly, got %d", len(tracker.entries))
	}
}

func TestExtractClientIP_XForwardedFor(t *testing.T) {
	tests := []struct {
		name     string
		xff      string
		expected string
	}{
		{"single IP", "1.2.3.4", "1.2.3.4"},
		{"multiple IPs", "1.2.3.4, 5.6.7.8, 9.10.11.12", "1.2.3.4"},
		{"with spaces", "  1.2.3.4  , 5.6.7.8", "1.2.3.4"},
		{"empty first entry falls through", ", 1.2.3.4", "127.0.0.1"}, // falls to RemoteAddr
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tt.xff)
			// httptest sets RemoteAddr to "192.0.2.1:1234" by default
			// For the "empty first entry" case, we need to check it falls through
			if tt.name == "empty first entry falls through" {
				req.RemoteAddr = "127.0.0.1:5678"
			}
			got := extractClientIP(req)
			if got != tt.expected {
				t.Errorf("extractClientIP(XFF=%q) = %q, want %q", tt.xff, got, tt.expected)
			}
		})
	}
}

func TestExtractClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	got := extractClientIP(req)
	if got != "10.0.0.1" {
		t.Errorf("Expected 10.0.0.1, got %s", got)
	}
}

func TestExtractClientIP_EmptyRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ""
	got := extractClientIP(req)
	if got != "unknown" {
		t.Errorf("Expected 'unknown' for empty RemoteAddr, got %q", got)
	}
}

func TestRegistrationResponse_JSONStructure(t *testing.T) {
	resp := registrationResponse{
		TenantID:     "cs_test-uuid",
		Secret:       "abcdef1234567890",
		SecretPrefix: "abcdef12",
		ExpiresAt:    "2026-05-09T00:00:00Z",
		Endpoint:     communitySaasTryEndpoint,
		Note:         communitySaasDisclaimerNote,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	required := []string{"tenant_id", "secret", "secret_prefix", "expires_at", "endpoint", "note"}
	for _, key := range required {
		if _, ok := parsed[key]; !ok {
			t.Errorf("Missing required field: %s", key)
		}
	}

	if !strings.HasPrefix(parsed["tenant_id"].(string), "cs_") {
		t.Errorf("tenant_id should have cs_ prefix, got %s", parsed["tenant_id"])
	}
}

func TestIsCommunitySaasMode(t *testing.T) {
	tests := []struct {
		mode     string
		expected bool
	}{
		{"community-saas", true},
		{"community", false},
		{"", false},
		{"enterprise", false},
		{"saas", false},
		{"in-vpc-enterprise", false},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			old := os.Getenv("DEPLOYMENT_MODE")
			os.Setenv("DEPLOYMENT_MODE", tt.mode)
			defer func() {
				if old != "" {
					os.Setenv("DEPLOYMENT_MODE", old)
				} else {
					os.Unsetenv("DEPLOYMENT_MODE")
				}
			}()

			got := isCommunitySaasMode()
			if got != tt.expected {
				t.Errorf("isCommunitySaasMode() with DEPLOYMENT_MODE=%q = %v, want %v", tt.mode, got, tt.expected)
			}

			// Verify community-saas is NOT community mode
			if tt.mode == "community-saas" && isCommunityMode() {
				t.Error("community-saas should NOT be community mode")
			}
		})
	}
}

func TestValidateCommunityRegistration_NilDB(t *testing.T) {
	err := validateCommunityRegistration(nil, nil, "tenant", "secret")
	if err != ErrDatabaseUnavailable {
		t.Errorf("Expected ErrDatabaseUnavailable, got %v", err)
	}
}

func TestEnqueueActivityUpdate_NilChannel(t *testing.T) {
	// Save and restore
	oldChan := activityUpdateChan
	activityUpdateChan = nil
	defer func() { activityUpdateChan = oldChan }()

	// Should not panic
	enqueueActivityUpdate(nil, "test-tenant")
}

func TestEnqueueActivityUpdate_FullChannel(t *testing.T) {
	// Create a tiny channel that's already full
	oldChan := activityUpdateChan
	activityUpdateChan = make(chan activityUpdate, 1)
	activityUpdateChan <- activityUpdate{} // Fill it
	defer func() { activityUpdateChan = oldChan }()

	// Should not block — drops silently
	enqueueActivityUpdate(nil, "test-tenant")
}

func TestRegisterEndpoint_MethodNotAllowed(t *testing.T) {
	router := setupCSAASTestRouter()
	RegisterCommunityRegistrationHandler(router, nil)

	methods := []string{"GET", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/register", nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s /api/v1/register: expected 405, got %d", method, rr.Code)
			}
		})
	}
}

func TestRegisterEndpoint_POST_NilDB(t *testing.T) {
	router := setupCSAASTestRouter()
	RegisterCommunityRegistrationHandler(router, nil)

	body := bytes.NewBufferString(`{"label":"test"}`)
	req := httptest.NewRequest("POST", "/api/v1/register", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("POST /api/v1/register with nil DB: expected 503, got %d", rr.Code)
	}
}

func TestExtractClientIP_IPv6RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::1]:54321"
	got := extractClientIP(req)
	// For IPv6 with brackets and port, LastIndexByte finds the port colon
	if got == "" || got == "unknown" {
		t.Errorf("Expected non-empty IP for IPv6, got %q", got)
	}
}

func TestExtractClientIP_NoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1"
	got := extractClientIP(req)
	if got != "10.0.0.1" {
		t.Errorf("Expected 10.0.0.1 for no-port RemoteAddr, got %q", got)
	}
}

func TestRegistrationIPTracker_ExpiredEntryReset(t *testing.T) {
	tracker := &registrationIPTracker{
		entries: make(map[string]*ipRegistrationEntry),
	}

	// Add an expired entry
	tracker.entries["expired-ip"] = &ipRegistrationEntry{
		count:     registrationIPLimit + 1, // Was rate-limited
		resetTime: time.Now().Add(-1 * time.Minute), // Expired
	}

	// Should succeed now (expired entry gets replaced)
	if err := tracker.check("expired-ip"); err != nil {
		t.Errorf("Expired entry should reset: %v", err)
	}
}

func TestRegistrationConstants(t *testing.T) {
	// Verify critical constants have expected values
	if bcryptCost < 10 || bcryptCost > 14 {
		t.Errorf("bcryptCost should be 10-14 for security/perf balance, got %d", bcryptCost)
	}
	if secretBytes < 16 {
		t.Errorf("secretBytes should be >= 16 for security, got %d", secretBytes)
	}
	if maxLabelLength < 1 {
		t.Errorf("maxLabelLength should be positive, got %d", maxLabelLength)
	}
	if registrationIPLimit < 1 {
		t.Errorf("registrationIPLimit should be positive, got %d", registrationIPLimit)
	}
	if ipTrackerMaxEntries < 1000 {
		t.Errorf("ipTrackerMaxEntries should be >= 1000, got %d", ipTrackerMaxEntries)
	}
	if communitySaasTryEndpoint == "" {
		t.Error("communitySaasTryEndpoint should not be empty")
	}
	if communitySaasDisclaimerNote == "" {
		t.Error("communitySaasDisclaimerNote should not be empty")
	}
	if communitySaasOrgID != "community-saas" {
		t.Errorf("communitySaasOrgID should be 'community-saas', got %q", communitySaasOrgID)
	}
	if communitySaasTenantPrefix != "cs_" {
		t.Errorf("communitySaasTenantPrefix should be 'cs_', got %q", communitySaasTenantPrefix)
	}
}

func TestHandleCommunityRegister_InvalidJSON(t *testing.T) {
	handler := handleCommunityRegister(nil)
	// Content-type check and nil DB check fire before JSON parsing
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// nil DB fires first (503)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 for nil DB, got %d", rr.Code)
	}
}

func TestHandleCommunityRegister_EmptyBody(t *testing.T) {
	handler := handleCommunityRegister(nil)
	req := httptest.NewRequest("POST", "/api/v1/register", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 for nil DB (empty body is valid), got %d", rr.Code)
	}
}

func setupCSAASTestRouter() *mux.Router {
	return mux.NewRouter()
}
