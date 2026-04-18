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
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateLicense(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	// Generate valid test licenses
	validENT, _ := GenerateLicenseKey(TierEnterprise, "testorg", 365)
	validPRO, _ := GenerateLicenseKey(TierProfessional, "startup", 365)
	validPLUS, _ := GenerateLicenseKey(TierEnterprisePlus, "bigcorp", 365)

	tests := []struct {
		name          string
		licenseKey    string
		wantValid     bool
		wantTier      Tier
		wantError     bool
		errorContains string
	}{
		{
			name:       "Valid ENT license",
			licenseKey: validENT,
			wantValid:  true,
			wantTier:   TierEnterprise,
			wantError:  false,
		},
		{
			name:       "Valid PRO license",
			licenseKey: validPRO,
			wantValid:  true,
			wantTier:   TierProfessional,
			wantError:  false,
		},
		{
			name:       "Valid PLUS license",
			licenseKey: validPLUS,
			wantValid:  true,
			wantTier:   TierEnterprisePlus,
			wantError:  false,
		},
		{
			name:      "Empty license key returns Community",
			licenseKey: "",
			wantValid: true,
			wantTier:  TierCommunity,
		},
		{
			name:          "Invalid prefix",
			licenseKey:    "INVALID-ENT-testorg-20261028-abc12345",
			wantValid:     false,
			wantError:     true,
			errorContains: "prefix",
		},
		{
			name:          "V2 format deprecated",
			licenseKey:    "AXON-V2-eyJ0aWVyIjoiRU5UIn0-abc12345",
			wantValid:     false,
			wantError:     true,
			errorContains: "no longer supported",
		},
		{
			name:          "V1 format deprecated",
			licenseKey:    "AXON-ENT-testorg-20261028-ffffffff",
			wantValid:     false,
			wantError:     true,
			errorContains: "no longer supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateLicense(ctx, tt.licenseKey)

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errorContains)
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Valid != tt.wantValid {
				t.Errorf("Expected Valid=%v, got %v", tt.wantValid, result.Valid)
			}

			if tt.wantValid && result.Tier != tt.wantTier {
				t.Errorf("Expected tier %s, got %s", tt.wantTier, result.Tier)
			}
		})
	}
}

func TestValidateLicenseFeatures(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	tests := []struct {
		name     string
		tier     Tier
		features []string
	}{
		{
			name: "EVALUATION features",
			tier: TierEvaluation,
			features: []string{
				"audit_logging",
				"basic_support",
			},
		},
		{
			name: "PRO features",
			tier: TierProfessional,
			features: []string{
				"audit_logging",
				"basic_support",
			},
		},
		{
			name: "ENT features",
			tier: TierEnterprise,
			features: []string{
				"multi_tenant",
				"advanced_policies",
				"sla_guarantee",
				"audit_logging",
				"priority_support",
				"custom_connectors",
			},
		},
		{
			name: "PLUS features",
			tier: TierEnterprisePlus,
			features: []string{
				"multi_tenant",
				"advanced_policies",
				"sla_guarantee",
				"audit_logging",
				"custom_connectors",
				"unlimited_nodes",
				"24x7_support",
				"dedicated_sa",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			days := 365
			if tt.tier == TierEvaluation {
				days = 90
			}
			key, err := GenerateLicenseKey(tt.tier, "testorg", days)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			result, err := ValidateLicense(ctx, key)
			if err != nil {
				t.Fatalf("Validation failed: %v", err)
			}

			for _, feature := range tt.features {
				if !result.Features[feature] {
					t.Errorf("Expected feature '%s' to be enabled for tier %s", feature, tt.tier)
				}
			}
		})
	}
}

func TestValidateLicenseNodeLimits(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	tests := []struct {
		name     string
		tier     Tier
		maxNodes int
	}{
		{"EVALUATION tier", TierEvaluation, 2},
		{"PRO tier", TierProfessional, 10},
		{"ENT tier", TierEnterprise, 50},
		{"PLUS tier", TierEnterprisePlus, 9999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			days := 365
			if tt.tier == TierEvaluation {
				days = 90
			}
			key, err := GenerateLicenseKey(tt.tier, "testorg", days)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			result, err := ValidateLicense(ctx, key)
			if err != nil {
				t.Fatalf("Validation failed: %v", err)
			}

			if result.MaxNodes != tt.maxNodes {
				t.Errorf("Expected MaxNodes=%d for tier %s, got %d", tt.maxNodes, tt.tier, result.MaxNodes)
			}
		})
	}
}

func TestValidateLicenseExpiry(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	key, err := GenerateLicenseKey(TierProfessional, "testorg", 30)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	result, err := ValidateLicense(ctx, key)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("License should be valid")
	}

	if result.DaysUntilExpiry < 29 || result.DaysUntilExpiry > 31 {
		t.Errorf("Expected DaysUntilExpiry ~30, got %d", result.DaysUntilExpiry)
	}

	if result.ExpiresAt.Before(time.Now()) {
		t.Errorf("Expiry date should be in the future")
	}
}

func TestValidateLicenseGracePeriod(t *testing.T) {
	if GracePeriodDays != 7 {
		t.Errorf("Expected GracePeriodDays=7, got %d", GracePeriodDays)
	}
}

func TestValidateLicenseCaching(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	key, err := GenerateLicenseKey(TierProfessional, "testorg", 365)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	result1, err := ValidateLicense(ctx, key)
	if err != nil {
		t.Fatalf("First validation failed: %v", err)
	}

	result2, err := ValidateLicense(ctx, key)
	if err != nil {
		t.Fatalf("Second validation failed: %v", err)
	}

	if result1.Tier != result2.Tier {
		t.Errorf("Cached result differs from original")
	}
}

func TestIsEnterpriseTier(t *testing.T) {
	setupTestKeypair(t)

	ctx := context.Background()

	// Generate ENT license
	key, err := GenerateServiceLicenseKey(TierEnterprise, "acme", "platform", "backend-service", []string{"mcp:*:*"}, 365)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	os.Setenv("AXONFLOW_LICENSE_KEY", key)
	defer os.Unsetenv("AXONFLOW_LICENSE_KEY")

	if !IsEnterpriseTier(ctx) {
		t.Error("Should detect Enterprise tier")
	}
}

func BenchmarkValidateLicense(b *testing.B) {
	os.Setenv("AXONFLOW_EVAL_SIGNING_KEY", "b58iLWB8r+Fezjj0cUWFzXi471GlFtKvvYSWi1gbIC4=")
	os.Setenv("AXONFLOW_ENT_SIGNING_KEY", "fifqSWAaVJy1qk89VwvqXYnXmlSCF3VfGRiK4e1kF0g=")
	b.Cleanup(func() {
		os.Unsetenv("AXONFLOW_EVAL_SIGNING_KEY")
		os.Unsetenv("AXONFLOW_ENT_SIGNING_KEY")
	})

	ctx := context.Background()
	key, _ := GenerateLicenseKey(TierProfessional, "testorg", 365)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ValidateLicense(ctx, key)
		if err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// Helper function
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
