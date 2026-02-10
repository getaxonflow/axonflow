//go:build !enterprise

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
)

func TestValidateLicense(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		licenseKey    string
		expectedValid bool
		expectedTier  Tier
		expectedOrgID string
		checkMessage  bool
		expectedMsg   string
	}{
		{
			name:          "empty license key - Community mode",
			licenseKey:    "",
			expectedValid: true,
			expectedTier:  TierCommunity,
			expectedOrgID: "community",
			checkMessage:  true,
			expectedMsg:   "Community mode - no license required",
		},
		{
			name:          "invalid format - falls back to Community",
			licenseKey:    "INVALID-LICENSE-KEY",
			expectedValid: true,
			expectedTier:  TierCommunity,
			expectedOrgID: "community",
		},
		{
			name:          "V2 format - rejected, falls back to Community",
			licenseKey:    "AXON-V2-eyJ0aWVyIjoiRU5UIn0-abc12345",
			expectedValid: true,
			expectedTier:  TierCommunity,
			expectedOrgID: "community",
		},
		{
			name:          "V1 format - rejected, falls back to Community",
			licenseKey:    "AXON-ENT-testorg-20261028-abc12345",
			expectedValid: true,
			expectedTier:  TierCommunity,
			expectedOrgID: "community",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateLicense(ctx, tt.licenseKey)
			if err != nil {
				t.Errorf("ValidateLicense() error = %v, want nil", err)
				return
			}

			if result.Valid != tt.expectedValid {
				t.Errorf("ValidateLicense() Valid = %v, want %v", result.Valid, tt.expectedValid)
			}
			if result.Tier != tt.expectedTier {
				t.Errorf("ValidateLicense() Tier = %v, want %v", result.Tier, tt.expectedTier)
			}
			if result.OrgID != tt.expectedOrgID {
				t.Errorf("ValidateLicense() OrgID = %v, want %v", result.OrgID, tt.expectedOrgID)
			}
			if tt.checkMessage && result.Message != tt.expectedMsg {
				t.Errorf("ValidateLicense() Message = %v, want %v", result.Message, tt.expectedMsg)
			}

			// Verify Community features
			if result.Features == nil {
				t.Error("ValidateLicense() Features = nil, want non-nil map")
			}
			if communityMode, ok := result.Features["community_mode"]; !ok || !communityMode {
				t.Error("ValidateLicense() Features['community_mode'] should be true")
			}
		})
	}
}

func TestValidateLicense_ValidV2License(t *testing.T) {
	// GenerateLicenseKey is enterprise-only in community builds
	_, err := GenerateLicenseKey(TierEnterprise, "test-org", 365)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}
}

func TestValidateLicense_ExpiredV2License(t *testing.T) {
	// GenerateLicenseKey is enterprise-only in community builds
	_, err := GenerateLicenseKey(TierProfessional, "expired-org", -30)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}
}

func TestValidateWithRetry(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		licenseKey    string
		maxAttempts   int
		expectedValid bool
		expectedTier  Tier
	}{
		{
			name:          "valid license - single attempt",
			licenseKey:    "",
			maxAttempts:   1,
			expectedValid: true,
			expectedTier:  TierCommunity,
		},
		{
			name:          "valid license - multiple attempts",
			licenseKey:    "",
			maxAttempts:   3,
			expectedValid: true,
			expectedTier:  TierCommunity,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateWithRetry(ctx, tt.licenseKey, tt.maxAttempts)
			if err != nil {
				t.Errorf("ValidateWithRetry() error = %v, want nil", err)
				return
			}

			if result.Valid != tt.expectedValid {
				t.Errorf("ValidateWithRetry() Valid = %v, want %v", result.Valid, tt.expectedValid)
			}
			if result.Tier != tt.expectedTier {
				t.Errorf("ValidateWithRetry() Tier = %v, want %v", result.Tier, tt.expectedTier)
			}
		})
	}
}

func TestGetCommunityFeatures(t *testing.T) {
	features := getCommunityFeatures()

	if features == nil {
		t.Fatal("getCommunityFeatures() returned nil, want non-nil map")
	}

	expectedFeatures := map[string]bool{
		"multi_tenant":      false,
		"advanced_policies": false,
		"sla_guarantee":     false,
		"audit_logging":     true,
		"basic_support":     false,
		"community_mode":    true,
	}

	for key, expectedValue := range expectedFeatures {
		if value, ok := features[key]; !ok {
			t.Errorf("getCommunityFeatures() missing key %q", key)
		} else if value != expectedValue {
			t.Errorf("getCommunityFeatures()[%q] = %v, want %v", key, value, expectedValue)
		}
	}

	if len(features) != len(expectedFeatures) {
		t.Errorf("getCommunityFeatures() has %d features, want %d", len(features), len(expectedFeatures))
	}
}

func TestGenerateLicenseKey(t *testing.T) {
	_, err := GenerateLicenseKey(TierProfessional, "test-org", 365)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}
}

func TestGenerateLicenseKey_RoundTrip(t *testing.T) {
	_, err := GenerateLicenseKey(TierProfessional, "test-org", 365)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}
}

func TestLicenseKey_GenerationNotAvailableInCommunity(t *testing.T) {
	_, err := GenerateLicenseKey(TierEnterprise, "healthcare", 365)
	if err == nil {
		t.Error("GenerateLicenseKey() should return error in Community builds")
	}

	if !strings.Contains(err.Error(), "Enterprise") {
		t.Errorf("GenerateLicenseKey() error should mention Enterprise upgrade, got: %v", err)
	}

	_, err = GenerateServiceLicenseKey(TierEnterprise, "test", "service", "backend-service", []string{"perm"}, 365)
	if err == nil {
		t.Error("GenerateServiceLicenseKey() should return error in Community builds")
	}
}

func TestTierConstants(t *testing.T) {
	tiers := []Tier{
		TierProfessional,
		TierEnterprise,
		TierEnterprisePlus,
		TierEvaluation,
		TierCommunity,
	}

	expectedValues := []string{"Professional", "Enterprise", "Plus", "Evaluation", "Community"}

	for i, tier := range tiers {
		if string(tier) != expectedValues[i] {
			t.Errorf("Tier[%d] = %v, want %v", i, tier, expectedValues[i])
		}
	}
}

func TestTierLimits(t *testing.T) {
	if CommunityLimits.TenantPolicies != 20 {
		t.Errorf("CommunityLimits.TenantPolicies = %d, want 20", CommunityLimits.TenantPolicies)
	}
	if CommunityLimits.OrgPolicies != 0 {
		t.Errorf("CommunityLimits.OrgPolicies = %d, want 0", CommunityLimits.OrgPolicies)
	}
	if CommunityLimits.CustomPolicyConnectors != 2 {
		t.Errorf("CommunityLimits.CustomPolicyConnectors = %d, want 2", CommunityLimits.CustomPolicyConnectors)
	}
	if CommunityLimits.AuditRetentionDays != 3 {
		t.Errorf("CommunityLimits.AuditRetentionDays = %d, want 3", CommunityLimits.AuditRetentionDays)
	}

	if EvaluationLimits.TenantPolicies != 50 {
		t.Errorf("EvaluationLimits.TenantPolicies = %d, want 50", EvaluationLimits.TenantPolicies)
	}
	if EvaluationLimits.OrgPolicies != 5 {
		t.Errorf("EvaluationLimits.OrgPolicies = %d, want 5", EvaluationLimits.OrgPolicies)
	}
	if EvaluationLimits.CustomPolicyConnectors != 5 {
		t.Errorf("EvaluationLimits.CustomPolicyConnectors = %d, want 5", EvaluationLimits.CustomPolicyConnectors)
	}
	if EvaluationLimits.AuditRetentionDays != 14 {
		t.Errorf("EvaluationLimits.AuditRetentionDays = %d, want 14", EvaluationLimits.AuditRetentionDays)
	}

	if EnterpriseLimits.TenantPolicies != -1 {
		t.Errorf("EnterpriseLimits.TenantPolicies = %d, want -1", EnterpriseLimits.TenantPolicies)
	}
	if EnterpriseLimits.OrgPolicies != -1 {
		t.Errorf("EnterpriseLimits.OrgPolicies = %d, want -1", EnterpriseLimits.OrgPolicies)
	}
	if EnterpriseLimits.CustomPolicyConnectors != -1 {
		t.Errorf("EnterpriseLimits.CustomPolicyConnectors = %d, want -1", EnterpriseLimits.CustomPolicyConnectors)
	}
}

func TestGetTierLimits(t *testing.T) {
	tests := []struct {
		name     string
		tier     Tier
		expected TierLimits
	}{
		{"Community tier", TierCommunity, CommunityLimits},
		{"Evaluation tier", TierEvaluation, EvaluationLimits},
		{"Enterprise tier", TierEnterprise, EnterpriseLimits},
		{"EnterprisePlus tier", TierEnterprisePlus, EnterpriseLimits},
		{"Professional tier", TierProfessional, EnterpriseLimits},
		{"Unknown tier defaults to Community", Tier("UNKNOWN"), CommunityLimits},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := GetTierLimits(tt.tier)
			if limits.TenantPolicies != tt.expected.TenantPolicies {
				t.Errorf("TenantPolicies = %d, want %d", limits.TenantPolicies, tt.expected.TenantPolicies)
			}
			if limits.OrgPolicies != tt.expected.OrgPolicies {
				t.Errorf("OrgPolicies = %d, want %d", limits.OrgPolicies, tt.expected.OrgPolicies)
			}
			if limits.CustomPolicyConnectors != tt.expected.CustomPolicyConnectors {
				t.Errorf("CustomPolicyConnectors = %d, want %d", limits.CustomPolicyConnectors, tt.expected.CustomPolicyConnectors)
			}
		})
	}
}

func TestGetCurrentTier(t *testing.T) {
	ctx := context.Background()

	// Without license key, should return Community
	t.Setenv("AXONFLOW_LICENSE_KEY", "")
	tier := GetCurrentTier(ctx)
	if tier != TierCommunity {
		t.Errorf("GetCurrentTier() = %v, want %v", tier, TierCommunity)
	}

	// With invalid license key, should return Community
	t.Setenv("AXONFLOW_LICENSE_KEY", "invalid-key")
	tier = GetCurrentTier(ctx)
	if tier != TierCommunity {
		t.Errorf("GetCurrentTier() with invalid key = %v, want %v", tier, TierCommunity)
	}
}

func TestGetCurrentLimits(t *testing.T) {
	ctx := context.Background()

	// Without license key, should return Community limits
	t.Setenv("AXONFLOW_LICENSE_KEY", "")
	limits := GetCurrentLimits(ctx)
	if limits.TenantPolicies != CommunityLimits.TenantPolicies {
		t.Errorf("GetCurrentLimits().TenantPolicies = %d, want %d", limits.TenantPolicies, CommunityLimits.TenantPolicies)
	}
}

func TestValidateLicense_UnknownTier(t *testing.T) {
	ctx := context.Background()

	result, err := ValidateLicense(ctx, "")
	if err != nil {
		t.Errorf("ValidateLicense() error = %v, want nil", err)
	}

	if result.Tier != TierCommunity {
		t.Errorf("ValidateLicense() with empty key should default to TierCommunity, got %v", result.Tier)
	}
}

func TestValidationResult_CommunityMode(t *testing.T) {
	ctx := context.Background()

	// In Community mode, validating any non-Ed25519 license returns Community tier
	result, err := ValidateLicense(ctx, "any-license-key")
	if err != nil {
		t.Fatalf("ValidateLicense() error = %v", err)
	}

	if !result.Valid {
		t.Error("ValidationResult.Valid should be true in Community mode")
	}
	if result.Tier != TierCommunity {
		t.Errorf("ValidationResult.Tier should be Community in Community mode, got %v", result.Tier)
	}
	if result.OrgID != "community" {
		t.Errorf("ValidationResult.OrgID should be 'community' in Community mode, got %v", result.OrgID)
	}
	if result.MaxNodes != 9999 {
		t.Errorf("ValidationResult.MaxNodes should be 9999 (unlimited) in Community mode, got %v", result.MaxNodes)
	}
	if result.ExpiresAt.IsZero() {
		t.Error("ValidationResult.ExpiresAt should not be zero")
	}
	if result.Message == "" {
		t.Error("ValidationResult.Message should not be empty")
	}
	if result.Features == nil {
		t.Error("ValidationResult.Features should not be nil")
	}
}

func TestIsEnterpriseTier(t *testing.T) {
	tests := []struct {
		name       string
		licenseKey string
		expected   bool
	}{
		{"empty license key", "", false},
		{"invalid license key", "invalid-key", false},
		{"random string", "some-random-garbage", false},
		// Old V2 format licenses should be rejected in Ed25519 mode
		{"old V2 license format", "AXON-V2-eyJ0aWVyIjoiRU5UIiwidGVuYW50X2lkIjoidGVzdCIsImV4cGlyZXNfYXQiOiIyMDI3MDEwMSJ9-5c7fa412", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AXONFLOW_LICENSE_KEY", tt.licenseKey)
			ctx := context.Background()
			if IsEnterpriseTier(ctx) != tt.expected {
				t.Errorf("IsEnterpriseTier()=%v, want %v for AXONFLOW_LICENSE_KEY=%q", IsEnterpriseTier(ctx), tt.expected, tt.licenseKey)
			}
		})
	}
}

func TestGetCurrentTier_WithOldFormats(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		licenseKey string
		expected   Tier
	}{
		{"empty key returns Community", "", TierCommunity},
		{"invalid key returns Community", "invalid", TierCommunity},
		// Old V2 format licenses should fall back to Community
		{"old V2 basic license", "AXON-V2-eyJleHBpcmVzX2F0IjoiMjAyNzAxMDEiLCJ0ZW5hbnRfaWQiOiJ0ZXN0IiwidGllciI6IkJBU0lDIn0-33d3727d", TierCommunity},
		{"old V2 enterprise license", "AXON-V2-eyJ0aWVyIjoiRU5UIiwidGVuYW50X2lkIjoidGVzdCIsImV4cGlyZXNfYXQiOiIyMDI3MDEwMSJ9-5c7fa412", TierCommunity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("AXONFLOW_LICENSE_KEY", tt.licenseKey)
			tier := GetCurrentTier(ctx)
			if tier != tt.expected {
				t.Errorf("GetCurrentTier()=%v, want %v", tier, tt.expected)
			}
		})
	}
}

func TestValidateHMACSecretAtStartup_NoOp(t *testing.T) {
	err := ValidateHMACSecretAtStartup()
	if err != nil {
		t.Errorf("ValidateHMACSecretAtStartup() should be no-op, got: %v", err)
	}
}
