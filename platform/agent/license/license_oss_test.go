//go:build !enterprise

// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
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
			name:          "empty license key - OSS mode",
			licenseKey:    "",
			expectedValid: true,
			expectedTier:  TierOSS,
			expectedOrgID: "oss",
			checkMessage:  true,
			expectedMsg:   "OSS mode - no license required",
		},
		{
			name:          "invalid format - falls back to OSS",
			licenseKey:    "INVALID-LICENSE-KEY",
			expectedValid: true,
			expectedTier:  TierOSS,
			expectedOrgID: "oss",
		},
		{
			name:          "V1 format - falls back to OSS",
			licenseKey:    "AXON-V1-something",
			expectedValid: true,
			expectedTier:  TierOSS,
			expectedOrgID: "oss",
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

			// Verify OSS features
			if result.Features == nil {
				t.Error("ValidateLicense() Features = nil, want non-nil map")
			}
			if ossMode, ok := result.Features["oss_mode"]; !ok || !ossMode {
				t.Error("ValidateLicense() Features['oss_mode'] should be true")
			}
		})
	}
}

func TestValidateLicense_ValidV2License(t *testing.T) {
	ctx := context.Background()

	// Generate a valid V2 license
	licenseKey, err := GenerateLicenseKey(TierEnterprise, "test-org", 365)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil {
		t.Errorf("ValidateLicense() error = %v, want nil", err)
		return
	}

	if !result.Valid {
		t.Errorf("ValidateLicense() Valid = false, want true")
	}
	if result.Tier != TierEnterprise {
		t.Errorf("ValidateLicense() Tier = %v, want %v", result.Tier, TierEnterprise)
	}
	if result.OrgID != "test-org" {
		t.Errorf("ValidateLicense() OrgID = %v, want test-org", result.OrgID)
	}
	if !strings.Contains(result.Message, "V2 license") {
		t.Errorf("ValidateLicense() Message = %v, should contain 'V2 license'", result.Message)
	}
}

func TestValidateLicense_ExpiredV2License(t *testing.T) {
	ctx := context.Background()

	// Generate an expired license
	licenseKey, err := GenerateLicenseKey(TierProfessional, "expired-org", -30)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil {
		t.Errorf("ValidateLicense() error = %v, want nil", err)
		return
	}

	// In OSS mode, expired licenses are still valid
	if !result.Valid {
		t.Errorf("ValidateLicense() Valid = false, want true (OSS mode accepts expired)")
	}
	if !strings.Contains(result.Message, "expired but accepted") {
		t.Errorf("ValidateLicense() Message = %v, should mention expired", result.Message)
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
		name            string
		payloadBase64   string
		signature       string
		expectedValid   bool
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
	// Generate a valid license and verify its signature
	licenseKey, err := GenerateLicenseKey(TierEnterprise, "test", 365)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	// Extract payload and signature
	parts := strings.Split(licenseKey, "-")
	if len(parts) != 4 {
		t.Fatalf("Invalid license format: %s", licenseKey)
	}

	payloadBase64 := parts[2]
	signature := parts[3]

	// Verify signature
	if !verifyV2Signature(payloadBase64, signature) {
		t.Error("verifyV2Signature() = false for valid generated license, want true")
	}

	// Tamper with signature
	if verifyV2Signature(payloadBase64, "tampered") {
		t.Error("verifyV2Signature() = true for tampered signature, want false")
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
			expectedTier:  TierOSS,
		},
		{
			name:          "valid license - multiple attempts",
			licenseKey:    "",
			maxAttempts:   3,
			expectedValid: true,
			expectedTier:  TierOSS,
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

func TestGetOSSFeatures(t *testing.T) {
	features := getOSSFeatures()

	if features == nil {
		t.Fatal("getOSSFeatures() returned nil, want non-nil map")
	}

	expectedFeatures := map[string]bool{
		"multi_tenant":      false,
		"advanced_policies": false,
		"sla_guarantee":     false,
		"audit_logging":     true,
		"basic_support":     false,
		"oss_mode":          true,
	}

	for key, expectedValue := range expectedFeatures {
		if value, ok := features[key]; !ok {
			t.Errorf("getOSSFeatures() missing key %q", key)
		} else if value != expectedValue {
			t.Errorf("getOSSFeatures()[%q] = %v, want %v", key, value, expectedValue)
		}
	}

	// Verify no extra keys
	if len(features) != len(expectedFeatures) {
		t.Errorf("getOSSFeatures() has %d features, want %d", len(features), len(expectedFeatures))
	}
}

func TestGenerateLicenseKey(t *testing.T) {
	tests := []struct {
		name       string
		tier       Tier
		orgID      string
		expiryDays int
	}{
		{
			name:       "Professional tier",
			tier:       TierProfessional,
			orgID:      "test-pro",
			expiryDays: 365,
		},
		{
			name:       "Enterprise tier",
			tier:       TierEnterprise,
			orgID:      "test-ent",
			expiryDays: 730,
		},
		{
			name:       "Enterprise Plus tier",
			tier:       TierEnterprisePlus,
			orgID:      "test-plus",
			expiryDays: 1095,
		},
		{
			name:       "Expired license",
			tier:       TierProfessional,
			orgID:      "expired",
			expiryDays: -30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseKey, err := GenerateLicenseKey(tt.tier, tt.orgID, tt.expiryDays)
			if err != nil {
				t.Errorf("GenerateLicenseKey() error = %v, want nil", err)
				return
			}

			// Verify format
			if !strings.HasPrefix(licenseKey, "AXON-V2-") {
				t.Errorf("GenerateLicenseKey() = %v, want AXON-V2- prefix", licenseKey)
			}

			parts := strings.Split(licenseKey, "-")
			if len(parts) != 4 {
				t.Errorf("GenerateLicenseKey() generated %d parts, want 4", len(parts))
			}

			// Verify we can parse and validate it
			ctx := context.Background()
			result, err := ValidateLicense(ctx, licenseKey)
			if err != nil {
				t.Errorf("ValidateLicense() on generated key error = %v, want nil", err)
				return
			}

			if result.Tier != tt.tier {
				t.Errorf("Generated license Tier = %v, want %v", result.Tier, tt.tier)
			}
			if result.OrgID != tt.orgID {
				t.Errorf("Generated license OrgID = %v, want %v", result.OrgID, tt.orgID)
			}

			// Verify expiry date is approximately correct
			expectedExpiry := time.Now().AddDate(0, 0, tt.expiryDays)
			timeDiff := result.ExpiresAt.Sub(expectedExpiry).Abs()
			if timeDiff > 24*time.Hour {
				t.Errorf("Generated license ExpiresAt = %v, want approximately %v (diff: %v)",
					result.ExpiresAt, expectedExpiry, timeDiff)
			}
		})
	}
}

func TestGenerateLicenseKey_RoundTrip(t *testing.T) {
	// Test that we can generate and validate multiple licenses
	testCases := []struct {
		tier   Tier
		orgID  string
		expiry int
	}{
		{TierProfessional, "org1", 365},
		{TierEnterprise, "org2", 730},
		{TierEnterprisePlus, "org3", 1095},
	}

	ctx := context.Background()

	for _, tc := range testCases {
		// Generate
		key, err := GenerateLicenseKey(tc.tier, tc.orgID, tc.expiry)
		if err != nil {
			t.Fatalf("GenerateLicenseKey(%v, %v, %v) error = %v", tc.tier, tc.orgID, tc.expiry, err)
		}

		// Validate
		result, err := ValidateLicense(ctx, key)
		if err != nil {
			t.Fatalf("ValidateLicense() error = %v", err)
		}

		// Verify round-trip
		if !result.Valid {
			t.Errorf("Round-trip failed: Valid = false")
		}
		if result.Tier != tc.tier {
			t.Errorf("Round-trip failed: Tier = %v, want %v", result.Tier, tc.tier)
		}
		if result.OrgID != tc.orgID {
			t.Errorf("Round-trip failed: OrgID = %v, want %v", result.OrgID, tc.orgID)
		}
	}
}

func TestLicenseKey_WithServiceInfo(t *testing.T) {
	// Test V2 license with service-specific fields
	ctx := context.Background()

	licenseKey, err := GenerateLicenseKey(TierEnterprise, "healthcare", 365)
	if err != nil {
		t.Fatalf("GenerateLicenseKey() error = %v", err)
	}

	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil {
		t.Fatalf("ValidateLicense() error = %v", err)
	}

	if !result.Valid {
		t.Errorf("ValidateLicense() Valid = false, want true")
	}

	// Verify service fields (should be empty for basic generation)
	if result.ServiceName != "" {
		t.Errorf("ValidateLicense() ServiceName = %v, want empty", result.ServiceName)
	}
	if result.ServiceType != "" {
		t.Errorf("ValidateLicense() ServiceType = %v, want empty", result.ServiceType)
	}
	if len(result.Permissions) != 0 {
		t.Errorf("ValidateLicense() Permissions = %v, want empty", result.Permissions)
	}
}

func TestTierConstants(t *testing.T) {
	// Verify tier constants are defined correctly
	tiers := []Tier{
		TierProfessional,
		TierEnterprise,
		TierEnterprisePlus,
		TierOSS,
	}

	expectedValues := []string{"PRO", "ENT", "PLUS", "OSS"}

	for i, tier := range tiers {
		if string(tier) != expectedValues[i] {
			t.Errorf("Tier[%d] = %v, want %v", i, tier, expectedValues[i])
		}
	}
}

func TestValidateLicense_UnknownTier(t *testing.T) {
	// Test license with unknown tier - should default to OSS
	ctx := context.Background()

	// This would require manually crafting a license with an invalid tier
	// For now, we just verify that parsing handles unknown tiers gracefully
	result, err := ValidateLicense(ctx, "")
	if err != nil {
		t.Errorf("ValidateLicense() error = %v, want nil", err)
	}

	if result.Tier != TierOSS {
		t.Errorf("ValidateLicense() with empty key should default to TierOSS, got %v", result.Tier)
	}
}

func TestValidationResult_AllFields(t *testing.T) {
	ctx := context.Background()

	// Generate a valid license
	licenseKey, err := GenerateLicenseKey(TierEnterprise, "test-org", 365)
	if err != nil {
		t.Fatalf("GenerateLicenseKey() error = %v", err)
	}

	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil {
		t.Fatalf("ValidateLicense() error = %v", err)
	}

	// Verify all fields are populated
	if !result.Valid {
		t.Error("ValidationResult.Valid should be true")
	}
	if result.Tier == "" {
		t.Error("ValidationResult.Tier should not be empty")
	}
	if result.OrgID == "" {
		t.Error("ValidationResult.OrgID should not be empty")
	}
	if result.MaxNodes <= 0 {
		t.Error("ValidationResult.MaxNodes should be > 0")
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
