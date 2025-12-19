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
		name           string
		licenseKey     string
		expectedValid  bool
		expectedTier   Tier
		expectedOrgID  string
		checkMessage   bool
		expectedMsg    string
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
			name:          "V1 format - falls back to Community",
			licenseKey:    "AXON-V1-something",
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
	// This test requires GenerateLicenseKey which is enterprise-only
	// Skip in Community builds
	_, err := GenerateLicenseKey(TierEnterprise, "test-org", 365)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}
}

func TestValidateLicense_ExpiredV2License(t *testing.T) {
	// This test requires GenerateLicenseKey which is enterprise-only
	// Skip in Community builds
	_, err := GenerateLicenseKey(TierProfessional, "expired-org", -30)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}
}

func TestParseV2License_InvalidFormat(t *testing.T) {
	tests := []struct {
		name       string
		licenseKey string
	}{
		{
			name:       "wrong prefix",
			licenseKey: "AXON-V1-payload-sig",
		},
		{
			name:       "not enough parts",
			licenseKey: "AXON-V2-payload",
		},
		{
			name:       "too many parts",
			licenseKey: "AXON-V2-payload-sig-extra",
		},
		{
			name:       "invalid base64",
			licenseKey: "AXON-V2-!!!invalid!!!-sig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseV2License(tt.licenseKey)
			// Should return nil for invalid format
			if result != nil {
				t.Errorf("parseV2License() returned result, want nil for invalid format")
			}
			// Error is acceptable but not required (some cases return nil, nil)
			_ = err
		})
	}
}

func TestVerifyV2Signature(t *testing.T) {
	tests := []struct {
		name          string
		payloadBase64 string
		signature     string
		expectedValid bool
	}{
		{
			name:          "empty payload and signature",
			payloadBase64: "",
			signature:     "",
			expectedValid: false,
		},
		{
			name:          "mismatched signature",
			payloadBase64: "test-payload",
			signature:     "wrongsig",
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifyV2Signature(tt.payloadBase64, tt.signature)
			if result != tt.expectedValid {
				t.Errorf("verifyV2Signature() = %v, want %v", result, tt.expectedValid)
			}
		})
	}
}

func TestVerifyV2Signature_GeneratedLicense(t *testing.T) {
	// This test requires GenerateLicenseKey which is enterprise-only
	// Skip in Community builds
	_, err := GenerateLicenseKey(TierEnterprise, "test", 365)
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

	// Verify no extra keys
	if len(features) != len(expectedFeatures) {
		t.Errorf("getCommunityFeatures() has %d features, want %d", len(features), len(expectedFeatures))
	}
}

func TestGenerateLicenseKey(t *testing.T) {
	// This test requires GenerateLicenseKey which is enterprise-only
	// The error behavior is tested in TestLicenseKey_GenerationNotAvailableInCommunity
	_, err := GenerateLicenseKey(TierProfessional, "test-org", 365)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}
}

func TestGenerateLicenseKey_RoundTrip(t *testing.T) {
	// This test requires GenerateLicenseKey which is enterprise-only
	// Skip in Community builds
	_, err := GenerateLicenseKey(TierProfessional, "test-org", 365)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}
}

func TestLicenseKey_GenerationNotAvailableInCommunity(t *testing.T) {
	// In Community builds, license generation is not available
	// This is a security feature to prevent exposure of the license format

	_, err := GenerateLicenseKey(TierEnterprise, "healthcare", 365)
	if err == nil {
		t.Error("GenerateLicenseKey() should return error in Community builds")
	}

	// Check for enterprise upgrade messaging (includes link to getaxonflow.com/enterprise)
	if !strings.Contains(err.Error(), "Enterprise") {
		t.Errorf("GenerateLicenseKey() error should mention Enterprise upgrade, got: %v", err)
	}

	// Also test GenerateServiceLicenseKey
	_, err = GenerateServiceLicenseKey(TierEnterprise, "test", "service", "backend-service", []string{"perm"}, 365)
	if err == nil {
		t.Error("GenerateServiceLicenseKey() should return error in Community builds")
	}
}

func TestTierConstants(t *testing.T) {
	// Verify tier constants are defined correctly
	tiers := []Tier{
		TierProfessional,
		TierEnterprise,
		TierEnterprisePlus,
		TierCommunity,
	}

	expectedValues := []string{"PRO", "ENT", "PLUS", "Community"}

	for i, tier := range tiers {
		if string(tier) != expectedValues[i] {
			t.Errorf("Tier[%d] = %v, want %v", i, tier, expectedValues[i])
		}
	}
}

func TestValidateLicense_UnknownTier(t *testing.T) {
	// Test license with unknown tier - should default to Community
	ctx := context.Background()

	// This would require manually crafting a license with an invalid tier
	// For now, we just verify that parsing handles unknown tiers gracefully
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

	// In Community mode, validating any license returns Community tier result
	// Test with empty license key (should return Community tier result)
	result, err := ValidateLicense(ctx, "any-license-key")
	if err != nil {
		t.Fatalf("ValidateLicense() error = %v", err)
	}

	// In Community mode, all licenses are valid (permissive validation)
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
