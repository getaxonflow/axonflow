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
		// #3096: the two "empty mode (default)" rows were removed. An unset
		// DEPLOYMENT_MODE no longer bypasses authentication — that is now
		// covered by TestUnsetDeploymentMode_DoesNotBypassAuthentication below,
		// which asserts the opposite outcome.
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
		// #3096: unset is no longer the community default — it fails closed to
		// the enterprise posture, so forgetting to configure a mode cannot
		// disable authentication.
		{"empty mode (unset) is not community", "", false},
		{"enterprise mode", "enterprise", false},
		{"saas mode", "saas", false},
		{"in-vpc-enterprise mode", "in-vpc-enterprise", false},
		{"community-saas is its own mode", "community-saas", false},
		{"unrecognised mode fails closed", "not-a-real-mode", false},
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

// TestUnsetDeploymentMode_DoesNotBypassAuthentication is the #3096 regression
// test: the rows it replaces in TestCommunityMode_BypassesAuthentication used
// to assert that an unset DEPLOYMENT_MODE handed out a synthetic admin user
// for any token, or none at all.
//
// validateUserToken (run.go) returns `local-dev@axonflow.local` with role
// admin and the query/llm/mcp_query/admin permission set when isCommunityMode()
// is true. Reaching that on an unset mode meant an operator who never
// configured DEPLOYMENT_MODE was serving admin authority to unauthenticated
// callers.
func TestUnsetDeploymentMode_DoesNotBypassAuthentication(t *testing.T) {
	for _, token := range []string{"", "any-token-works"} {
		name := "empty token"
		if token != "" {
			name = "arbitrary token"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", "")

			user, err := validateUserToken(token, "test-tenant")
			if err == nil {
				t.Fatalf("unset DEPLOYMENT_MODE must not bypass authentication; got user %+v", user)
			}
			if user != nil {
				t.Errorf("no user must be minted on the failure path, got %+v", user)
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
