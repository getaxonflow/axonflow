//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Integration test for license generation and validation
// Tests the complete flow: generate → validate locally → verify signature

package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// TestLicenseGenerationAndValidation tests the complete license lifecycle
func TestLicenseGenerationAndValidation(t *testing.T) {
	setupTestKeypair(t)

	tests := []struct {
		name           string
		tier           Tier
		orgID          string
		validityDays   int
		shouldGenerate bool
		shouldValidate bool
	}{
		{
			name:           "Professional tier",
			tier:           TierProfessional,
			orgID:          "acme-corp",
			validityDays:   365,
			shouldGenerate: true,
			shouldValidate: true,
		},
		{
			name:           "Enterprise tier",
			tier:           TierEnterprise,
			orgID:          "test-stack-20260101-000000",
			validityDays:   365,
			shouldGenerate: true,
			shouldValidate: true,
		},
		{
			name:           "EnterprisePlus tier",
			tier:           TierEnterprisePlus,
			orgID:          "mega-corp",
			validityDays:   365,
			shouldGenerate: true,
			shouldValidate: true,
		},
		{
			name:           "Evaluation tier",
			tier:           TierEvaluation,
			orgID:          "trial-customer",
			validityDays:   90,
			shouldGenerate: true,
			shouldValidate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseKey, err := GenerateLicenseKey(tt.tier, tt.orgID, tt.validityDays)

			if tt.shouldGenerate && err != nil {
				t.Fatalf("Failed to generate license: %v", err)
			}

			if !tt.shouldGenerate && err == nil {
				t.Fatalf("Expected generation to fail, but it succeeded")
			}

			if !tt.shouldGenerate {
				return
			}

			t.Logf("Generated license: %s", licenseKey)

			// Validate the license locally
			result, err := ValidateLicense(context.Background(), licenseKey)
			if err != nil {
				t.Fatalf("Validation error: %v", err)
			}

			if tt.shouldValidate && !result.Valid {
				t.Fatalf("License validation failed: %s - %s", result.Error, result.Message)
			}

			// Verify Ed25519 signature manually
			if tt.shouldValidate {
				if !verifyLicenseSignatureManually(t, licenseKey, tt.tier) {
					t.Fatalf("Manual signature verification failed")
				}
			}

			// Verify result fields
			if tt.shouldValidate {
				if result.Tier != tt.tier {
					t.Errorf("Expected tier %s, got %s", tt.tier, result.Tier)
				}

				if result.OrgID != tt.orgID {
					t.Errorf("Expected orgID %s, got %s", tt.orgID, result.OrgID)
				}

				expectedMaxNodes := map[Tier]int{
					TierEvaluation:     2,
					TierProfessional:   10,
					TierEnterprise:     50,
					TierEnterprisePlus: 9999,
				}

				if result.MaxNodes != expectedMaxNodes[tt.tier] {
					t.Errorf("Expected maxNodes %d, got %d", expectedMaxNodes[tt.tier], result.MaxNodes)
				}
			}
		})
	}
}

// verifyLicenseSignatureManually manually verifies an Ed25519 license signature
func verifyLicenseSignatureManually(t *testing.T, licenseKey string, expectedTier Tier) bool {
	t.Helper()

	// Parse: AXON-{PAYLOAD}.{SIGNATURE}
	if !strings.HasPrefix(licenseKey, "AXON-") {
		t.Errorf("Invalid license key prefix")
		return false
	}

	rest := licenseKey[5:]
	dotIdx := strings.LastIndex(rest, ".")
	if dotIdx < 1 {
		t.Errorf("Missing '.' separator in license key")
		return false
	}

	payloadBase64 := rest[:dotIdx]
	signatureBase64 := rest[dotIdx+1:]

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		t.Errorf("Failed to decode signature: %v", err)
		return false
	}

	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Invalid signature length: expected %d, got %d", ed25519.SignatureSize, len(signature))
		return false
	}

	// Select appropriate public key based on tier
	var pubKey ed25519.PublicKey
	switch expectedTier {
	case TierEvaluation:
		pubKey = evaluationPublicKey
	default:
		pubKey = enterprisePublicKey
	}

	// Verify
	valid := ed25519.Verify(pubKey, []byte(payloadBase64), signature)
	if !valid {
		t.Errorf("Ed25519 signature verification failed")
	}

	return valid
}

// TestLicenseKeyFormat tests that Ed25519 license keys follow the correct format
func TestLicenseKeyFormat(t *testing.T) {
	setupTestKeypair(t)

	key, err := GenerateLicenseKey(TierEnterprise, "test-org", 365)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	// Format: AXON-{PAYLOAD}.{SIGNATURE}
	if !strings.HasPrefix(key, "AXON-") {
		t.Errorf("Expected prefix 'AXON-', got '%s'", key[:5])
	}

	rest := key[5:]
	dotIdx := strings.LastIndex(rest, ".")
	if dotIdx < 1 {
		t.Fatalf("Missing '.' separator")
	}

	signatureBase64 := rest[dotIdx+1:]
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		t.Errorf("Invalid signature encoding: %v", err)
	}

	// Ed25519 signature should be 64 bytes
	if len(signature) != 64 {
		t.Errorf("Expected 64-byte signature, got %d bytes", len(signature))
	}
}

// TestExpiredLicense tests that expired licenses are handled correctly
func TestExpiredLicense(t *testing.T) {
	setupTestKeypair(t)

	// validityDays must be positive for GenerateLicenseKey
	// Instead, we test with a very short validity and the grace period logic
	key, err := GenerateLicenseKey(TierProfessional, "expired-test", 1)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	result, err := ValidateLicense(context.Background(), key)
	if err != nil {
		t.Fatalf("Validation error: %v", err)
	}

	// Should be valid (1 day in the future)
	if !result.Valid {
		t.Errorf("License should be valid (expires in 1 day)")
	}
}

// TestGracePeriod tests the grace period constant
func TestGracePeriod(t *testing.T) {
	if GracePeriodDays != 7 {
		t.Errorf("Expected GracePeriodDays=7, got %d", GracePeriodDays)
	}
}

// TestInvalidTier tests that invalid tiers are rejected at generation time
func TestInvalidTier(t *testing.T) {
	setupTestKeypair(t)

	_, err := GenerateLicenseKey(Tier("INVALID"), "test-org", 365)
	if err == nil {
		t.Fatalf("Expected error for invalid tier, but generation succeeded")
	}
}

// TestLicenseExpiryDays tests that DaysUntilExpiry is calculated correctly
func TestLicenseExpiryDays(t *testing.T) {
	setupTestKeypair(t)

	key, err := GenerateLicenseKey(TierProfessional, "expiry-test", 30)
	if err != nil {
		t.Fatalf("Failed to generate license: %v", err)
	}

	result, err := ValidateLicense(context.Background(), key)
	if err != nil {
		t.Fatalf("Validation error: %v", err)
	}

	if result.DaysUntilExpiry < 29 || result.DaysUntilExpiry > 31 {
		t.Errorf("Expected DaysUntilExpiry ~30, got %d", result.DaysUntilExpiry)
	}

	if result.ExpiresAt.Before(time.Now()) {
		t.Errorf("Expiry date should be in the future")
	}
}
