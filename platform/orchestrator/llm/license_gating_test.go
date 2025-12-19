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

package llm

import (
	"context"
	"testing"
)

func TestCommunityLicenseValidator_GetCurrentTier(t *testing.T) {
	v := NewCommunityLicenseValidator()
	ctx := context.Background()

	tier := v.GetCurrentTier(ctx)
	if tier != LicenseTierCommunity {
		t.Errorf("GetCurrentTier() = %q, want %q", tier, LicenseTierCommunity)
	}
}

func TestCommunityLicenseValidator_IsProviderAllowed(t *testing.T) {
	v := NewCommunityLicenseValidator()
	ctx := context.Background()

	tests := []struct {
		name         string
		providerType ProviderType
		want         bool
	}{
		{"Ollama allowed", ProviderTypeOllama, true},
		{"OpenAI allowed", ProviderTypeOpenAI, true},
		{"Anthropic allowed", ProviderTypeAnthropic, true},
		{"Gemini allowed", ProviderTypeGemini, true},
		{"Bedrock not allowed", ProviderTypeBedrock, false},
		{"Custom not allowed", ProviderTypeCustom, false},
		{"Unknown not allowed", ProviderType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.IsProviderAllowed(ctx, tt.providerType)
			if got != tt.want {
				t.Errorf("IsProviderAllowed(%q) = %v, want %v", tt.providerType, got, tt.want)
			}
		})
	}
}

func TestCommunityLicenseValidator_ValidateLicense(t *testing.T) {
	v := NewCommunityLicenseValidator()
	ctx := context.Background()

	// Community validator always returns nil (no license required)
	err := v.ValidateLicense(ctx, "any-key")
	if err != nil {
		t.Errorf("ValidateLicense() = %v, want nil", err)
	}
}

func TestCommunityLicenseValidator_GetFeatures(t *testing.T) {
	v := NewCommunityLicenseValidator()
	features := v.GetFeatures()

	// Check some expected Community features
	expectedEnabled := []string{"multi_provider", "load_balancing", "health_checks", "audit_logging", "metrics_collection"}
	for _, f := range expectedEnabled {
		if !features[f] {
			t.Errorf("Feature %q should be enabled in Community", f)
		}
	}

	// Check some expected enterprise-only features
	expectedDisabled := []string{"bedrock_provider", "custom_providers", "advanced_routing"}
	for _, f := range expectedDisabled {
		if features[f] {
			t.Errorf("Feature %q should be disabled in Community", f)
		}
	}

	// Verify returned map is a copy (modifying it shouldn't affect validator)
	features["test_feature"] = true
	features2 := v.GetFeatures()
	if features2["test_feature"] {
		t.Error("GetFeatures() should return a copy, not the original map")
	}
}

func TestGetTierForProvider(t *testing.T) {
	tests := []struct {
		providerType ProviderType
		want         LicenseTier
	}{
		{ProviderTypeOllama, LicenseTierCommunity},
		{ProviderTypeOpenAI, LicenseTierCommunity},
		{ProviderTypeAnthropic, LicenseTierCommunity},
		{ProviderTypeGemini, LicenseTierCommunity},
		{ProviderTypeBedrock, LicenseTierProfessional},
		{ProviderTypeCustom, LicenseTierProfessional},
		{ProviderType("unknown"), LicenseTierProfessional}, // Unknown defaults to Professional
	}

	for _, tt := range tests {
		t.Run(string(tt.providerType), func(t *testing.T) {
			got := GetTierForProvider(tt.providerType)
			if got != tt.want {
				t.Errorf("GetTierForProvider(%q) = %q, want %q", tt.providerType, got, tt.want)
			}
		})
	}
}

func TestIsCommunityProvider(t *testing.T) {
	tests := []struct {
		providerType ProviderType
		want         bool
	}{
		{ProviderTypeOllama, true},
		{ProviderTypeOpenAI, true},
		{ProviderTypeAnthropic, true},
		{ProviderTypeGemini, true},
		{ProviderTypeBedrock, false},
		{ProviderTypeCustom, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.providerType), func(t *testing.T) {
			got := IsCommunityProvider(tt.providerType)
			if got != tt.want {
				t.Errorf("IsCommunityProvider(%q) = %v, want %v", tt.providerType, got, tt.want)
			}
		})
	}
}

func TestGetCommunityProviders(t *testing.T) {
	providers := GetCommunityProviders()

	if len(providers) < 4 {
		t.Errorf("GetCommunityProviders() returned %d providers, want at least 4", len(providers))
	}

	// Check that expected Community providers are in the list
	expected := map[ProviderType]bool{
		ProviderTypeOllama:    false,
		ProviderTypeOpenAI:    false,
		ProviderTypeAnthropic: false,
		ProviderTypeGemini:    false,
	}

	for _, p := range providers {
		if _, ok := expected[p]; ok {
			expected[p] = true
		}
	}

	for p, found := range expected {
		if !found {
			t.Errorf("Expected Community provider %q not found in GetCommunityProviders()", p)
		}
	}
}

func TestGetEnterpriseProviders(t *testing.T) {
	providers := GetEnterpriseProviders()

	if len(providers) < 2 {
		t.Errorf("GetEnterpriseProviders() returned %d providers, want at least 2", len(providers))
	}

	// Check that expected Enterprise providers are in the list
	expected := map[ProviderType]bool{
		ProviderTypeBedrock: false,
		ProviderTypeCustom:  false,
	}

	for _, p := range providers {
		if _, ok := expected[p]; ok {
			expected[p] = true
		}
	}

	for p, found := range expected {
		if !found {
			t.Errorf("Expected Enterprise provider %q not found in GetEnterpriseProviders()", p)
		}
	}
}

func TestTierSatisfiesRequirement(t *testing.T) {
	tests := []struct {
		name         string
		currentTier  LicenseTier
		requiredTier LicenseTier
		want         bool
	}{
		// Same tier
		{"Community meets Community", LicenseTierCommunity, LicenseTierCommunity, true},
		{"PRO meets PRO", LicenseTierProfessional, LicenseTierProfessional, true},
		{"ENT meets ENT", LicenseTierEnterprise, LicenseTierEnterprise, true},
		{"PLUS meets PLUS", LicenseTierEnterprisePlus, LicenseTierEnterprisePlus, true},

		// Higher tier meets lower requirement
		{"PRO meets Community", LicenseTierProfessional, LicenseTierCommunity, true},
		{"ENT meets Community", LicenseTierEnterprise, LicenseTierCommunity, true},
		{"ENT meets PRO", LicenseTierEnterprise, LicenseTierProfessional, true},
		{"PLUS meets all", LicenseTierEnterprisePlus, LicenseTierCommunity, true},

		// Lower tier doesn't meet higher requirement
		{"Community doesn't meet PRO", LicenseTierCommunity, LicenseTierProfessional, false},
		{"Community doesn't meet ENT", LicenseTierCommunity, LicenseTierEnterprise, false},
		{"PRO doesn't meet ENT", LicenseTierProfessional, LicenseTierEnterprise, false},
		{"ENT doesn't meet PLUS", LicenseTierEnterprise, LicenseTierEnterprisePlus, false},

		// Unknown tier
		{"Unknown current tier", LicenseTier("unknown"), LicenseTierCommunity, false},
		{"Unknown required tier", LicenseTierCommunity, LicenseTier("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TierSatisfiesRequirement(tt.currentTier, tt.requiredTier)
			if got != tt.want {
				t.Errorf("TierSatisfiesRequirement(%q, %q) = %v, want %v",
					tt.currentTier, tt.requiredTier, got, tt.want)
			}
		})
	}
}

func TestLicenseError_Error(t *testing.T) {
	t.Run("with provider type", func(t *testing.T) {
		err := &LicenseError{
			ProviderType: ProviderTypeBedrock,
			RequiredTier: LicenseTierProfessional,
			CurrentTier:  LicenseTierCommunity,
			Message:      "upgrade required",
		}

		errStr := err.Error()
		if errStr == "" {
			t.Error("Error() returned empty string")
		}
		// Should contain key information
		if len(errStr) < 20 {
			t.Errorf("Error() seems too short: %q", errStr)
		}
	})

	t.Run("without provider type", func(t *testing.T) {
		err := &LicenseError{
			Message: "generic license error",
		}

		errStr := err.Error()
		if errStr != "license error: generic license error" {
			t.Errorf("Error() = %q, want %q", errStr, "license error: generic license error")
		}
	})
}

func TestValidateProviderAccess(t *testing.T) {
	// Save and restore default validator
	originalValidator := DefaultValidator
	defer func() { DefaultValidator = originalValidator }()

	// Use Community validator for tests
	DefaultValidator = NewCommunityLicenseValidator()
	ctx := context.Background()

	t.Run("allowed provider", func(t *testing.T) {
		err := ValidateProviderAccess(ctx, ProviderTypeOpenAI)
		if err != nil {
			t.Errorf("ValidateProviderAccess(OpenAI) = %v, want nil", err)
		}
	})

	t.Run("disallowed provider", func(t *testing.T) {
		err := ValidateProviderAccess(ctx, ProviderTypeBedrock)
		if err == nil {
			t.Error("ValidateProviderAccess(Bedrock) = nil, want error")
		}

		licErr, ok := err.(*LicenseError)
		if !ok {
			t.Fatalf("Expected LicenseError, got %T", err)
		}

		if licErr.ProviderType != ProviderTypeBedrock {
			t.Errorf("ProviderType = %q, want %q", licErr.ProviderType, ProviderTypeBedrock)
		}
		if licErr.RequiredTier != LicenseTierProfessional {
			t.Errorf("RequiredTier = %q, want %q", licErr.RequiredTier, LicenseTierProfessional)
		}
		if licErr.CurrentTier != LicenseTierCommunity {
			t.Errorf("CurrentTier = %q, want %q", licErr.CurrentTier, LicenseTierCommunity)
		}
	})
}

func TestSetDefaultValidator(t *testing.T) {
	// Save and restore default validator
	originalValidator := DefaultValidator
	defer func() { DefaultValidator = originalValidator }()

	// Create a mock validator
	mockValidator := &mockLicenseValidator{tier: LicenseTierEnterprise}
	SetDefaultValidator(mockValidator)

	if DefaultValidator != mockValidator {
		t.Error("SetDefaultValidator() did not set the validator")
	}
}

// mockLicenseValidator is a test helper
type mockLicenseValidator struct {
	tier     LicenseTier
	features map[string]bool
}

func (m *mockLicenseValidator) GetCurrentTier(ctx context.Context) LicenseTier {
	return m.tier
}

func (m *mockLicenseValidator) IsProviderAllowed(ctx context.Context, providerType ProviderType) bool {
	requiredTier := GetTierForProvider(providerType)
	return TierSatisfiesRequirement(m.tier, requiredTier)
}

func (m *mockLicenseValidator) ValidateLicense(ctx context.Context, licenseKey string) error {
	return nil
}

func (m *mockLicenseValidator) GetFeatures() map[string]bool {
	return m.features
}
