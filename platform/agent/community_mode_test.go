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
	"testing"
)

// TestCommunityMode_BypassesAuthentication verifies that community mode
// bypasses authentication, allowing any token or no token.
func TestCommunityMode_BypassesAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		token    string
		tenantID string
	}{
		{"community mode with empty token", "community", "", "test-tenant"},
		{"community mode with any token", "community", "any-token-works", "test-tenant"},
		{"empty mode (default) with empty token", "", "", "test-tenant"},
		{"empty mode (default) with any token", "", "any-token-works", "test-tenant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tt.mode)

			user, err := validateUserToken(tt.token, tt.tenantID)

			if err != nil {
				t.Fatalf("Community mode should accept any token: %v", err)
			}

			if user == nil {
				t.Fatal("Expected user to be returned")
			}

			if user.Role != "admin" {
				t.Errorf("Expected admin role, got: %s", user.Role)
			}

			if user.TenantID != tt.tenantID {
				t.Errorf("Expected tenant ID %q, got: %s", tt.tenantID, user.TenantID)
			}
		})
	}
}

// TestCommunityMode_IsCommunityModeFunction tests the isCommunityMode helper.
func TestCommunityMode_IsCommunityModeFunction(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected bool
	}{
		{"community mode", "community", true},
		{"empty mode (default)", "", true},
		{"enterprise mode", "enterprise", false},
		{"saas mode", "saas", false},
		{"in-vpc-enterprise mode", "in-vpc-enterprise", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tt.mode)

			result := isCommunityMode()

			if result != tt.expected {
				t.Errorf("isCommunityMode() = %v, want %v for DEPLOYMENT_MODE=%q", result, tt.expected, tt.mode)
			}
		})
	}
}

// TestEnterpriseMode_RequiresToken verifies that enterprise mode
// requires a valid token (doesn't bypass authentication).
func TestEnterpriseMode_RequiresToken(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	// Empty token should fail in enterprise mode
	_, err := validateUserToken("", "test-tenant")

	if err == nil {
		t.Fatal("Enterprise mode should require a token")
	}
}

// TestCommunityMode_AdminPermissions verifies that community mode
// grants admin permissions to the synthetic user.
func TestCommunityMode_AdminPermissions(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	user, err := validateUserToken("", "test-tenant")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

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
