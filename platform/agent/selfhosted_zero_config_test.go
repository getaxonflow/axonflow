// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
)

// TestSelfHostedMode_ZeroConfig_WhitespaceToken tests edge cases with whitespace tokens.
// Note: Empty string token ("") is already tested in selfhosted_security_test.go.
func TestSelfHostedMode_ZeroConfig_WhitespaceToken(t *testing.T) {
	t.Setenv("SELF_HOSTED_MODE", "true")
	t.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", SelfHostedModeAcknowledgment)
	t.Setenv("ENVIRONMENT", "development")

	// Whitespace-only tokens should also be accepted
	user, err := validateUserToken("   ", "test-tenant")

	if err != nil {
		t.Fatalf("Zero-config self-hosted should accept whitespace token, got error: %v", err)
	}

	if user == nil {
		t.Fatal("Expected user to be returned for zero-config self-hosted")
	}

	if user.Role != "admin" {
		t.Errorf("Expected admin role, got: %s", user.Role)
	}
}

// TestSelfHostedMode_ZeroConfig_FirstTimeUser tests the "first run" experience
// where a brand new user has no credentials configured at all.
// This is the scenario that was broken before PR #89.
func TestSelfHostedMode_ZeroConfig_FirstTimeUser(t *testing.T) {
	// Simulate first-time user environment
	t.Setenv("SELF_HOSTED_MODE", "true")
	t.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", SelfHostedModeAcknowledgment)
	t.Setenv("ENVIRONMENT", "development")

	// First-time user with no token and default tenant
	user, err := validateUserToken("", "default")

	if err != nil {
		t.Fatalf("First-time user should not fail auth: %v", err)
	}

	if user == nil {
		t.Fatal("Expected user to be returned")
	}

	// Verify admin permissions are granted for first-time user
	expectedPerms := []string{"query", "llm", "mcp_query", "admin"}
	for _, perm := range expectedPerms {
		found := false
		for _, userPerm := range user.Permissions {
			if userPerm == perm {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected permission %q to be present for first-time user", perm)
		}
	}
}

// TestSelfHostedMode_ZeroConfig_EmptyTenantID tests that empty tenant ID works.
// This covers the edge case where user provides token but no tenant context.
func TestSelfHostedMode_ZeroConfig_EmptyTenantID(t *testing.T) {
	t.Setenv("SELF_HOSTED_MODE", "true")
	t.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", SelfHostedModeAcknowledgment)
	t.Setenv("ENVIRONMENT", "development")

	tests := []struct {
		name     string
		token    string
		tenantID string
	}{
		{"token with empty tenant", "some-token", ""},
		{"no token with empty tenant", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := validateUserToken(tt.token, tt.tenantID)

			if err != nil {
				t.Fatalf("Self-hosted should accept empty tenant ID: %v", err)
			}

			if user == nil {
				t.Fatal("Expected user to be returned")
			}

			if user.Role != "admin" {
				t.Errorf("Expected admin role, got: %s", user.Role)
			}

			// TenantID should be whatever was passed (even empty)
			if user.TenantID != tt.tenantID {
				t.Errorf("Expected tenant ID %q, got: %s", tt.tenantID, user.TenantID)
			}
		})
	}
}

// TestSelfHostedMode_ZeroConfig_StillBlockedInProduction ensures that
// even with zero-config, production environments are protected.
func TestSelfHostedMode_ZeroConfig_StillBlockedInProduction(t *testing.T) {
	t.Setenv("SELF_HOSTED_MODE", "true")
	t.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", SelfHostedModeAcknowledgment)
	t.Setenv("ENVIRONMENT", "production")

	// Even with empty token, production should be blocked
	_, err := validateUserToken("", "test-tenant")

	if err == nil {
		t.Fatal("Zero-config in production should still be blocked")
	}

	if !containsIgnoreCase(err.Error(), "not allowed in production") {
		t.Errorf("Error should indicate production is blocked, got: %v", err)
	}
}
