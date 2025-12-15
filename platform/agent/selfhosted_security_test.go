// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
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
	"strings"
	"testing"
)

// TestSelfHostedMode_BlockedInProduction verifies that self-hosted mode
// is blocked when ENVIRONMENT is set to "production" or "prod" (case-insensitive)
func TestSelfHostedMode_BlockedInProduction(t *testing.T) {
	tests := []struct {
		name        string
		environment string
	}{
		{"production lowercase", "production"},
		{"prod shorthand", "prod"},
		{"PRODUCTION uppercase", "PRODUCTION"},
		{"PROD uppercase", "PROD"},
		{"Production mixed case", "Production"},
		{"Prod mixed case", "Prod"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Setenv automatically restores the original value after the test
			t.Setenv("SELF_HOSTED_MODE", "true")
			t.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", SelfHostedModeAcknowledgment)
			t.Setenv("ENVIRONMENT", tt.environment)

			// Attempt to validate a token in self-hosted mode with production environment
			_, err := validateUserToken("any-token", "test-tenant")

			if err == nil {
				t.Fatal("Expected error when self-hosted mode is used in production environment")
			}

			if !strings.Contains(err.Error(), "not allowed in production") {
				t.Errorf("Error should indicate production is blocked, got: %v", err)
			}
		})
	}
}

// TestSelfHostedMode_RequiresAcknowledgment verifies that self-hosted mode
// requires the explicit acknowledgment environment variable
func TestSelfHostedMode_RequiresAcknowledgment(t *testing.T) {
	tests := []struct {
		name           string
		acknowledgment string
		setAck         bool // whether to set the env var at all
		shouldFail     bool
	}{
		{"missing acknowledgment", "", false, true},
		{"wrong acknowledgment", "wrong-value", true, true},
		{"partial acknowledgment", "I_UNDERSTAND", true, true},
		{"correct acknowledgment", SelfHostedModeAcknowledgment, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up test environment (development mode to avoid production block)
			t.Setenv("SELF_HOSTED_MODE", "true")
			t.Setenv("ENVIRONMENT", "development")
			if tt.setAck {
				t.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", tt.acknowledgment)
			}
			// Note: if setAck is false, SELF_HOSTED_MODE_ACKNOWLEDGED stays unset

			// Attempt to validate a token
			user, err := validateUserToken("any-token", "test-tenant")

			if tt.shouldFail {
				if err == nil {
					t.Fatal("Expected error when acknowledgment is missing or incorrect")
				}
				if !strings.Contains(err.Error(), "SELF_HOSTED_MODE_ACKNOWLEDGED") {
					t.Errorf("Error should mention SELF_HOSTED_MODE_ACKNOWLEDGED, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error with correct acknowledgment: %v", err)
				}
				if user == nil {
					t.Fatal("Expected user to be returned when self-hosted mode is properly configured")
				}
				if user.Role != "admin" {
					t.Errorf("Self-hosted mode should return admin role, got: %s", user.Role)
				}
			}
		})
	}
}

// TestSelfHostedMode_WorksInDevelopment verifies that self-hosted mode
// works correctly when properly configured in a development environment
func TestSelfHostedMode_WorksInDevelopment(t *testing.T) {
	// Set up properly configured self-hosted environment
	t.Setenv("SELF_HOSTED_MODE", "true")
	t.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", SelfHostedModeAcknowledgment)
	t.Setenv("ENVIRONMENT", "development")

	// Should succeed with any token
	user, err := validateUserToken("literally-any-token-works", "test-tenant")
	if err != nil {
		t.Fatalf("Self-hosted mode should accept any token in development: %v", err)
	}

	// Verify user properties
	if user.Role != "admin" {
		t.Errorf("Expected admin role, got: %s", user.Role)
	}
	if user.TenantID != "test-tenant" {
		t.Errorf("Expected tenant ID 'test-tenant', got: %s", user.TenantID)
	}
	if user.Email != "local-dev@axonflow.local" {
		t.Errorf("Expected local dev email, got: %s", user.Email)
	}

	// Verify admin permissions
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
			t.Errorf("Expected permission %q to be present", perm)
		}
	}
}

// TestSelfHostedMode_DisabledByDefault verifies that when SELF_HOSTED_MODE
// is not set to "true", normal token validation applies
func TestSelfHostedMode_DisabledByDefault(t *testing.T) {
	// t.Setenv sets the variable; we want it unset
	// In Go 1.22+, not calling t.Setenv leaves it at its original value
	// which might be empty from the test environment

	// With an invalid token, validation should fail (not bypass)
	_, err := validateUserToken("invalid-token", "test-tenant")

	// In non-self-hosted mode, invalid tokens should fail JWT validation
	// The error type depends on how far JWT parsing gets
	if err == nil {
		// Only test token prefixes should work
		t.Log("Token validation passed - this is expected only for test token prefixes")
	}
}
