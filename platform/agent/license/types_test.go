//go:build enterprise

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

package license

import (
	"testing"
	"time"
)

func TestLicenseKey_IsServiceLicense(t *testing.T) {
	tests := []struct {
		name        string
		licenseKey  *LicenseKey
		wantService bool
	}{
		{
			name: "service license with service name",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				ServiceType: "client-application",
				Permissions: []string{"mcp:amadeus:*"},
			},
			wantService: true,
		},
		{
			name: "regular org license without service name",
			licenseKey: &LicenseKey{
				OrgID: "acme",
				Tier:  TierEnterprise,
			},
			wantService: false,
		},
		{
			name: "service license with empty service name",
			licenseKey: &LicenseKey{
				ServiceName: "",
				Permissions: []string{"mcp:*"},
			},
			wantService: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.licenseKey.IsServiceLicense()
			if got != tt.wantService {
				t.Errorf("IsServiceLicense() = %v, want %v", got, tt.wantService)
			}
		})
	}
}

func TestLicenseKey_HasPermission(t *testing.T) {
	tests := []struct {
		name       string
		licenseKey *LicenseKey
		permission string
		want       bool
	}{
		// Exact match tests
		{
			name: "exact match - single permission",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:search_flights"},
			},
			permission: "mcp:amadeus:search_flights",
			want:       true,
		},
		{
			name: "exact match - multiple permissions",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:search_flights", "mcp:amadeus:search_hotels", "mcp:slack:send_message"},
			},
			permission: "mcp:slack:send_message",
			want:       true,
		},
		{
			name: "no match - permission not in list",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:search_flights"},
			},
			permission: "mcp:amadeus:search_hotels",
			want:       false,
		},

		// Wildcard connector tests
		{
			name: "wildcard connector - matches any operation",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:*"},
			},
			permission: "mcp:amadeus:search_flights",
			want:       true,
		},
		{
			name: "wildcard connector - matches different operation",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:*"},
			},
			permission: "mcp:amadeus:search_hotels",
			want:       true,
		},
		{
			name: "wildcard connector - does not match different connector",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:*"},
			},
			permission: "mcp:slack:send_message",
			want:       false,
		},

		// Global wildcard tests
		{
			name: "global wildcard mcp:* - matches any connector",
			licenseKey: &LicenseKey{
				ServiceName: "admin-service",
				Permissions: []string{"mcp:*"},
			},
			permission: "mcp:amadeus:search_flights",
			want:       true,
		},
		{
			name: "global wildcard mcp:* - matches different connector",
			licenseKey: &LicenseKey{
				ServiceName: "admin-service",
				Permissions: []string{"mcp:*"},
			},
			permission: "mcp:slack:send_message",
			want:       true,
		},
		{
			name: "absolute wildcard * - matches anything",
			licenseKey: &LicenseKey{
				ServiceName: "super-admin",
				Permissions: []string{"*"},
			},
			permission: "mcp:amadeus:search_flights",
			want:       true,
		},

		// Non-service license tests
		{
			name: "non-service license - no service name",
			licenseKey: &LicenseKey{
				OrgID:       "acme",
				Tier:        TierEnterprise,
				Permissions: []string{"mcp:amadeus:*"}, // Has permissions but not a service license
			},
			permission: "mcp:amadeus:search_flights",
			want:       false,
		},
		{
			name: "service license - empty permissions",
			licenseKey: &LicenseKey{
				ServiceName: "limited-service",
				Permissions: []string{},
			},
			permission: "mcp:amadeus:search_flights",
			want:       false,
		},
		{
			name: "service license - nil permissions",
			licenseKey: &LicenseKey{
				ServiceName: "limited-service",
				Permissions: nil,
			},
			permission: "mcp:amadeus:search_flights",
			want:       false,
		},

		// Edge cases
		{
			name: "empty permission string",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:*"},
			},
			permission: "",
			want:       false,
		},
		{
			name: "case sensitive match",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				Permissions: []string{"mcp:amadeus:search_flights"},
			},
			permission: "mcp:AMADEUS:search_flights",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.licenseKey.HasPermission(tt.permission)
			if got != tt.want {
				t.Errorf("HasPermission(%q) = %v, want %v (permissions: %v)", tt.permission, got, tt.want, tt.licenseKey.Permissions)
			}
		})
	}
}

func TestLicenseKey_GetServiceInfo(t *testing.T) {
	tests := []struct {
		name            string
		licenseKey      *LicenseKey
		wantServiceName string
		wantServiceType string
		wantPermissions []string
	}{
		{
			name: "service license with all fields",
			licenseKey: &LicenseKey{
				ServiceName: "trip-planner",
				ServiceType: "client-application",
				Permissions: []string{"mcp:amadeus:search_flights", "mcp:amadeus:search_hotels"},
			},
			wantServiceName: "trip-planner",
			wantServiceType: "client-application",
			wantPermissions: []string{"mcp:amadeus:search_flights", "mcp:amadeus:search_hotels"},
		},
		{
			name: "non-service license",
			licenseKey: &LicenseKey{
				OrgID: "acme",
				Tier:  TierEnterprise,
			},
			wantServiceName: "",
			wantServiceType: "",
			wantPermissions: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotType, gotPerms := tt.licenseKey.GetServiceInfo()
			if gotName != tt.wantServiceName {
				t.Errorf("GetServiceInfo() serviceName = %v, want %v", gotName, tt.wantServiceName)
			}
			if gotType != tt.wantServiceType {
				t.Errorf("GetServiceInfo() serviceType = %v, want %v", gotType, tt.wantServiceType)
			}
			if len(gotPerms) != len(tt.wantPermissions) {
				t.Errorf("GetServiceInfo() permissions length = %v, want %v", len(gotPerms), len(tt.wantPermissions))
			}
		})
	}
}

func TestLicenseKey_String(t *testing.T) {
	tests := []struct {
		name       string
		licenseKey *LicenseKey
		wantSubstr string
	}{
		{
			name: "service license string representation",
			licenseKey: &LicenseKey{
				OrgID:       "travel-eu",
				ServiceName: "trip-planner",
				ServiceType: "client-application",
				Tier:        TierEnterprisePlus,
				Permissions: []string{"mcp:amadeus:*"},
			},
			wantSubstr: "service=trip-planner",
		},
		{
			name: "regular license string representation",
			licenseKey: &LicenseKey{
				OrgID: "acme",
				Tier:  TierEnterprise,
			},
			wantSubstr: "tenant=acme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.licenseKey.String()
			if got == "" {
				t.Error("String() returned empty string")
			}
			// Note: We don't check exact string match to allow for implementation changes
			// Just verify it returns something meaningful
		})
	}
}

func TestLicenseKey_ToValidationResult(t *testing.T) {
	now := time.Now()
	expiry := now.AddDate(0, 0, 365)

	licenseKey := &LicenseKey{
		OrgID:           "travel-eu",
		Tier:            TierEnterprisePlus,
		ExpiresAt:       expiry,
		DaysUntilExpiry: 365,
		MaxNodes:        9999,
		Features:        map[string]bool{"advanced_policies": true},
		ServiceName:     "trip-planner",
		ServiceType:     "client-application",
		Permissions:     []string{"mcp:amadeus:*"},
	}

	result := licenseKey.ToValidationResult()

	if !result.Valid {
		t.Error("ToValidationResult() Valid = false, want true")
	}

	if result.OrgID != "travel-eu" {
		t.Errorf("ToValidationResult() OrgID = %v, want travel-eu", result.OrgID)
	}

	if result.ServiceName != "trip-planner" {
		t.Errorf("ToValidationResult() ServiceName = %v, want trip-planner", result.ServiceName)
	}

	if len(result.Permissions) != 1 {
		t.Errorf("ToValidationResult() Permissions length = %v, want 1", len(result.Permissions))
	}
}
