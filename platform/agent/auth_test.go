// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"context"
	"testing"
	"time"
)

// TestValidateClientLicense tests the whitelist-based client authentication
func TestValidateClientLicense(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		clientID    string
		licenseKey  string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid healthcare demo client",
			clientID:    "healthcare-demo",
			licenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6ImhlYWx0aGNhcmUiLCJzZXJ2aWNlX25hbWUiOiJoZWFsdGhjYXJlLWRlbW8iLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSIsImNvbm5lY3RvcnMiLCJwbGFubmluZyJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-b9870d1f",
			expectError: false,
		},
		{
			name:        "valid ecommerce demo client",
			clientID:    "ecommerce-demo",
			licenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6ImVjb21tZXJjZSIsInNlcnZpY2VfbmFtZSI6ImVjb21tZXJjZS1kZW1vIiwic2VydmljZV90eXBlIjoiY2xpZW50LWFwcGxpY2F0aW9uIiwicGVybWlzc2lvbnMiOlsicXVlcnkiLCJsbG0iLCJjb25uZWN0b3JzIl0sImV4cGlyZXNfYXQiOiIyMDM1MTEyNyJ9-e40f5f5d",
			expectError: false,
		},
		{
			name:        "valid loadtest client",
			clientID:    "loadtest",
			licenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6ImxvYWR0ZXN0Iiwic2VydmljZV9uYW1lIjoibG9hZHRlc3QiLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-8cc4ef10",
			expectError: false,
		},
		{
			name:        "missing client ID",
			clientID:    "",
			licenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6InRlc3QiLCJzZXJ2aWNlX25hbWUiOiJ0ZXN0Iiwic2VydmljZV90eXBlIjoiY2xpZW50LWFwcGxpY2F0aW9uIiwicGVybWlzc2lvbnMiOlsicXVlcnkiXSwiZXhwaXJlc19hdCI6IjIwMzUxMTI3In0-abc12345",
			expectError: true,
			errorMsg:    "client ID required",
		},
		{
			name:        "missing license key",
			clientID:    "healthcare-demo",
			licenseKey:  "",
			expectError: true,
			errorMsg:    "license key required",
		},
		{
			name:        "unknown client",
			clientID:    "unknown-client",
			licenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6InVua25vd24iLCJzZXJ2aWNlX25hbWUiOiJ1bmtub3duIiwic2VydmljZV90eXBlIjoiY2xpZW50LWFwcGxpY2F0aW9uIiwicGVybWlzc2lvbnMiOlsicXVlcnkiXSwiZXhwaXJlc19hdCI6IjIwMzUxMTI3In0-abc12345",
			expectError: true,
			errorMsg:    "not found in whitelist",
		},
		{
			name:        "invalid license key for known client",
			clientID:    "healthcare-demo",
			licenseKey:  "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6Indyb25nIiwic2VydmljZV9uYW1lIjoid3JvbmciLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-wrong123",
			expectError: true,
			errorMsg:    "invalid license key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := validateClientLicense(ctx, tt.clientID, tt.licenseKey)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorMsg)
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}

				if client != nil {
					t.Error("Expected nil client on error")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}

				if client == nil {
					t.Fatal("Expected non-nil client")
				}

				// Verify client properties
				if client.ID != tt.clientID {
					t.Errorf("Expected client ID '%s', got '%s'", tt.clientID, client.ID)
				}

				if client.TenantID == "" {
					t.Error("Expected non-empty tenant ID")
				}

				if len(client.Permissions) == 0 {
					t.Error("Expected non-empty permissions")
				}

				if client.RateLimit <= 0 {
					t.Error("Expected positive rate limit")
				}

				if !client.Enabled {
					t.Error("Expected client to be enabled")
				}

				if client.LicenseTier == "" {
					t.Error("Expected non-empty license tier")
				}
			}
		})
	}
}

// TestValidateClientLicensePermissions tests permission handling
func TestValidateClientLicensePermissions(t *testing.T) {
	ctx := context.Background()

	// Test healthcare demo permissions (V2 license format)
	client, err := validateClientLicense(ctx, "healthcare-demo", "AXON-V2-eyJ0aWVyIjoiUExVUyIsInRlbmFudF9pZCI6ImhlYWx0aGNhcmUiLCJzZXJ2aWNlX25hbWUiOiJoZWFsdGhjYXJlLWRlbW8iLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSIsImNvbm5lY3RvcnMiLCJwbGFubmluZyJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-b9870d1f")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Healthcare demo should have planning permission
	if !hasPermission(client.Permissions, "planning") {
		t.Error("Healthcare demo should have planning permission")
	}

	// Test legacy client (should not have planning) - V2 license format
	client2, err := validateClientLicense(ctx, "client_1", "AXON-V2-eyJ0aWVyIjoiRU5UIiwidGVuYW50X2lkIjoiY2xpZW50MSIsInNlcnZpY2VfbmFtZSI6ImNsaWVudDEiLCJzZXJ2aWNlX3R5cGUiOiJjbGllbnQtYXBwbGljYXRpb24iLCJwZXJtaXNzaW9ucyI6WyJxdWVyeSIsImxsbSJdLCJleHBpcmVzX2F0IjoiMjAzNTExMjcifQ-22b4e980")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if hasPermission(client2.Permissions, "planning") {
		t.Error("Legacy client should not have planning permission")
	}
}

// TestCheckRateLimit tests the in-memory rate limiting
func TestCheckRateLimit(t *testing.T) {
	// Reset rate limit map for clean test
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	clientID := "test-client-rate-limit"
	limit := 10 // 10 requests per minute

	// First 10 requests should succeed
	for i := 0; i < limit; i++ {
		err := checkRateLimit(clientID, limit)
		if err != nil {
			t.Errorf("Request %d should succeed, got error: %v", i+1, err)
		}
	}

	// 11th request should fail (rate limit exceeded)
	err := checkRateLimit(clientID, limit)
	if err == nil {
		t.Error("Expected rate limit error on 11th request")
	}

	if err != nil && !contains(err.Error(), "rate limit exceeded") {
		t.Errorf("Expected 'rate limit exceeded' error, got: %v", err)
	}
}

// TestCheckRateLimitReset tests rate limit window reset
func TestCheckRateLimitReset(t *testing.T) {
	// Reset rate limit map
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	clientID := "test-client-reset"
	limit := 5

	// Use up the limit
	for i := 0; i < limit; i++ {
		_ = checkRateLimit(clientID, limit)
	}

	// Next request should fail
	err := checkRateLimit(clientID, limit)
	if err == nil {
		t.Error("Expected rate limit error")
	}

	// Manually reset the time window
	rateLimitMu.Lock()
	if entry, exists := rateLimitMap[clientID]; exists {
		entry.mu.Lock()
		entry.ResetTime = time.Now().Add(-1 * time.Second) // Force reset
		entry.mu.Unlock()
	}
	rateLimitMu.Unlock()

	// Now request should succeed (new window)
	err = checkRateLimit(clientID, limit)
	if err != nil {
		t.Errorf("Expected success after window reset, got error: %v", err)
	}
}

// TestCheckRateLimitConcurrent tests concurrent rate limit checks
func TestCheckRateLimitConcurrent(t *testing.T) {
	// Reset rate limit map
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	clientID := "test-client-concurrent"
	limit := 100

	// Run 50 concurrent requests (should all succeed)
	concurrency := 50
	results := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			results <- checkRateLimit(clientID, limit)
		}()
	}

	// Collect results
	successCount := 0
	for i := 0; i < concurrency; i++ {
		if err := <-results; err == nil {
			successCount++
		}
	}

	if successCount != concurrency {
		t.Errorf("Expected %d successful requests, got %d", concurrency, successCount)
	}

	// Verify count is correct
	count, _, _ := getRateLimitStatus(clientID)
	if count != concurrency {
		t.Errorf("Expected count %d, got %d", concurrency, count)
	}
}

// TestGetRateLimitStatus tests rate limit status retrieval
func TestGetRateLimitStatus(t *testing.T) {
	// Reset rate limit map
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	// Use a known client from the whitelist
	clientID := "healthcare-demo"
	clientAuth := knownClients[clientID]
	if clientAuth == nil {
		t.Fatal("healthcare-demo not found in knownClients")
	}
	limit := clientAuth.RateLimit

	// Make some requests
	requestCount := 5
	for i := 0; i < requestCount; i++ {
		_ = checkRateLimit(clientID, limit)
	}

	// Get status
	count, returnedLimit, resetTime := getRateLimitStatus(clientID)

	if count != requestCount {
		t.Errorf("Expected count %d, got %d", requestCount, count)
	}

	if returnedLimit != limit {
		t.Errorf("Expected limit %d, got %d", limit, returnedLimit)
	}

	if resetTime.IsZero() {
		t.Error("Expected non-zero reset time")
	}

	if !resetTime.After(time.Now()) {
		t.Error("Reset time should be in the future")
	}
}

// TestGetRateLimitStatusUnknownClient tests status for unknown client
func TestGetRateLimitStatusUnknownClient(t *testing.T) {
	count, limit, resetTime := getRateLimitStatus("unknown-client-xyz")

	if count != 0 {
		t.Errorf("Expected count 0 for unknown client, got %d", count)
	}

	if limit != 0 {
		t.Errorf("Expected limit 0 for unknown client, got %d", limit)
	}

	if !resetTime.IsZero() {
		t.Error("Expected zero reset time for unknown client")
	}
}

// TestRateLimitDifferentClients tests that rate limits are per-client
func TestRateLimitDifferentClients(t *testing.T) {
	// Reset rate limit map
	rateLimitMu.Lock()
	rateLimitMap = make(map[string]*RateLimitEntry)
	rateLimitMu.Unlock()

	client1 := "client-1"
	client2 := "client-2"
	limit := 5

	// Max out client1's rate limit
	for i := 0; i < limit; i++ {
		_ = checkRateLimit(client1, limit)
	}

	// Client1 should be rate limited
	err := checkRateLimit(client1, limit)
	if err == nil {
		t.Error("Expected rate limit error for client1")
	}

	// Client2 should NOT be rate limited
	err = checkRateLimit(client2, limit)
	if err != nil {
		t.Errorf("Client2 should not be rate limited: %v", err)
	}

	// Verify separate counts
	count1, _, _ := getRateLimitStatus(client1)
	count2, _, _ := getRateLimitStatus(client2)

	if count1 != limit+1 { // limit + 1 failed attempt
		t.Errorf("Client1 count should be %d, got %d", limit+1, count1)
	}

	if count2 != 1 {
		t.Errorf("Client2 count should be 1, got %d", count2)
	}
}

// TestClientAuthStructure tests the ClientAuth data structure
func TestClientAuthStructure(t *testing.T) {
	// Verify all known clients have required fields
	for clientID, auth := range knownClients {
		t.Run(clientID, func(t *testing.T) {
			if auth.ClientID != clientID {
				t.Errorf("ClientID mismatch: expected '%s', got '%s'", clientID, auth.ClientID)
			}

			if auth.LicenseKey == "" {
				t.Error("LicenseKey should not be empty")
			}

			if auth.Name == "" {
				t.Error("Name should not be empty")
			}

			if auth.TenantID == "" {
				t.Error("TenantID should not be empty")
			}

			if auth.RateLimit <= 0 {
				t.Error("RateLimit should be positive")
			}

			if !auth.Enabled {
				t.Error("Client should be enabled")
			}

			if len(auth.Permissions) == 0 {
				t.Error("Permissions should not be empty")
			}

			// Verify license key format
			if !contains(auth.LicenseKey, "AXON-") {
				t.Error("License key should start with 'AXON-'")
			}
		})
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func hasPermission(permissions []string, permission string) bool {
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	return false
}
