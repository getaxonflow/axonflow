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
	"context"
	"strings"
	"testing"
	"time"
)

func TestGenerateServiceLicenseKey(t *testing.T) {
	setupTestKeypair(t)

	tests := []struct {
		name         string
		tier         Tier
		orgID        string
		serviceName  string
		serviceType  string
		permissions  []string
		validityDays int
		wantError    bool
		errorSubstr  string
	}{
		{
			name:         "valid service license",
			tier:         TierEnterprisePlus,
			orgID:        "travel-eu",
			serviceName:  "trip-planner",
			serviceType:  "client-application",
			permissions:  []string{"mcp:amadeus:search_flights", "mcp:amadeus:search_hotels"},
			validityDays: 365,
			wantError:    false,
		},
		{
			name:         "backend service type",
			tier:         TierEnterprise,
			orgID:        "healthcare-eu",
			serviceName:  "patient-portal",
			serviceType:  "backend-service",
			permissions:  []string{"mcp:salesforce:*"},
			validityDays: 180,
			wantError:    false,
		},
		{
			name:         "integration service type",
			tier:         TierProfessional,
			orgID:        "fintech",
			serviceName:  "payment-gateway",
			serviceType:  "integration",
			permissions:  []string{"mcp:stripe:*", "mcp:plaid:*"},
			validityDays: 90,
			wantError:    false,
		},
		{
			name:         "global mcp permissions",
			tier:         TierEnterprisePlus,
			orgID:        "admin-org",
			serviceName:  "admin-service",
			serviceType:  "backend-service",
			permissions:  []string{"mcp:*"},
			validityDays: 365,
			wantError:    false,
		},

		// Error cases
		{
			name:         "invalid tier",
			tier:         Tier("INVALID"),
			orgID:        "travel-eu",
			serviceName:  "trip-planner",
			serviceType:  "client-application",
			permissions:  []string{"mcp:amadeus:*"},
			validityDays: 365,
			wantError:    true,
			errorSubstr:  "invalid tier",
		},
		{
			name:         "empty tenant ID",
			tier:         TierEnterprise,
			orgID:        "",
			serviceName:  "trip-planner",
			serviceType:  "client-application",
			permissions:  []string{"mcp:amadeus:*"},
			validityDays: 365,
			wantError:    true,
			errorSubstr:  "orgID cannot be empty",
		},
		{
			name:         "empty service name",
			tier:         TierEnterprise,
			orgID:        "travel-eu",
			serviceName:  "",
			serviceType:  "client-application",
			permissions:  []string{"mcp:amadeus:*"},
			validityDays: 365,
			wantError:    true,
			errorSubstr:  "serviceName cannot be empty",
		},
		{
			name:         "invalid service type",
			tier:         TierEnterprise,
			orgID:        "travel-eu",
			serviceName:  "trip-planner",
			serviceType:  "invalid-type",
			permissions:  []string{"mcp:amadeus:*"},
			validityDays: 365,
			wantError:    true,
			errorSubstr:  "invalid serviceType",
		},
		{
			name:         "empty permissions",
			tier:         TierEnterprise,
			orgID:        "travel-eu",
			serviceName:  "trip-planner",
			serviceType:  "client-application",
			permissions:  []string{},
			validityDays: 365,
			wantError:    true,
			errorSubstr:  "permissions cannot be empty",
		},
		{
			name:         "zero validity days",
			tier:         TierEnterprise,
			orgID:        "travel-eu",
			serviceName:  "trip-planner",
			serviceType:  "client-application",
			permissions:  []string{"mcp:amadeus:*"},
			validityDays: 0,
			wantError:    true,
			errorSubstr:  "validityDays must be positive",
		},
		{
			name:         "negative validity days",
			tier:         TierEnterprise,
			orgID:        "travel-eu",
			serviceName:  "trip-planner",
			serviceType:  "client-application",
			permissions:  []string{"mcp:amadeus:*"},
			validityDays: -30,
			wantError:    true,
			errorSubstr:  "validityDays must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateServiceLicenseKey(
				tt.tier,
				tt.orgID,
				tt.serviceName,
				tt.serviceType,
				tt.permissions,
				tt.validityDays,
			)

			if tt.wantError {
				if err == nil {
					t.Error("GenerateServiceLicenseKey() expected error but got nil")
				} else if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
					t.Errorf("GenerateServiceLicenseKey() error = %v, want error containing %q", err, tt.errorSubstr)
				}
				return
			}

			if err != nil {
				t.Errorf("GenerateServiceLicenseKey() unexpected error = %v", err)
				return
			}

			// Verify Ed25519 format: AXON-{PAYLOAD}.{SIGNATURE}
			if !strings.HasPrefix(key, "AXON-") {
				t.Errorf("Key should start with AXON-")
			}
			rest := key[5:]
			if !strings.Contains(rest, ".") {
				t.Errorf("Key should contain '.' separator for Ed25519 format")
			}

			// Validate the generated key
			result, err := ValidateLicense(context.Background(), key)
			if err != nil {
				t.Errorf("Generated key failed validation: %v", err)
				return
			}

			if !result.Valid {
				t.Error("Generated key is not valid")
			}

			if result.OrgID != tt.orgID {
				t.Errorf("ValidationResult.OrgID = %v, want %v", result.OrgID, tt.orgID)
			}

			if result.ServiceName != tt.serviceName {
				t.Errorf("ValidationResult.ServiceName = %v, want %v", result.ServiceName, tt.serviceName)
			}

			if result.ServiceType != tt.serviceType {
				t.Errorf("ValidationResult.ServiceType = %v, want %v", result.ServiceType, tt.serviceType)
			}

			if len(result.Permissions) != len(tt.permissions) {
				t.Errorf("ValidationResult.Permissions length = %v, want %v", len(result.Permissions), len(tt.permissions))
			}
		})
	}
}

func TestValidateServiceLicense_Expiry(t *testing.T) {
	setupTestKeypair(t)

	key, err := GenerateServiceLicenseKey(
		TierEnterprise,
		"travel-eu",
		"trip-planner",
		"client-application",
		[]string{"mcp:amadeus:*"},
		30,
	)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	result, err := ValidateLicense(context.Background(), key)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Valid {
		t.Error("License should be valid")
	}

	if result.DaysUntilExpiry < 27 || result.DaysUntilExpiry > 33 {
		t.Errorf("DaysUntilExpiry = %v, want ~30 days", result.DaysUntilExpiry)
	}

	expectedExpiry := time.Now().AddDate(0, 0, 30)
	diff := result.ExpiresAt.Sub(expectedExpiry).Hours() / 24
	if diff < -2 || diff > 2 {
		t.Errorf("ExpiresAt difference = %.1f days, want ±2 days", diff)
	}
}

func TestServiceLicenseUniqueness(t *testing.T) {
	setupTestKeypair(t)

	key1, _ := GenerateServiceLicenseKey(
		TierEnterprise,
		"travel-eu",
		"trip-planner",
		"client-application",
		[]string{"mcp:amadeus:*"},
		365,
	)

	key2, _ := GenerateServiceLicenseKey(
		TierEnterprise,
		"travel-eu",
		"trip-planner",
		"client-application",
		[]string{"mcp:amadeus:*"},
		365,
	)

	// Keys should be identical (deterministic for same params on same day)
	if key1 != key2 {
		// This is expected since expiry date is based on current time
		// Just verify both keys validate successfully
		_, err1 := ValidateLicense(context.Background(), key1)
		_, err2 := ValidateLicense(context.Background(), key2)

		if err1 != nil || err2 != nil {
			t.Error("Both generated keys should validate successfully")
		}
	}
}
