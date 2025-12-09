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

// Package license provides license validation for AxonFlow Agent.
// This is the OSS stub - it parses V2 license keys but doesn't enforce
// signature validation. All parseable V2 licenses are considered valid.
package license

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Tier represents the license tier
type Tier string

const (
	TierProfessional   Tier = "PRO"
	TierEnterprise     Tier = "ENT"
	TierEnterprisePlus Tier = "PLUS"
	TierOSS            Tier = "OSS" // OSS tier - unlimited usage
)

// defaultHMACSecret is used for test license validation in OSS mode
const defaultHMACSecret = "axonflow-license-secret-2025-change-in-production"

// ValidationResult contains the result of license validation
type ValidationResult struct {
	Valid           bool
	Tier            Tier
	OrgID           string
	MaxNodes        int
	ExpiresAt       time.Time
	DaysUntilExpiry int
	GracePeriodDays int
	Error           string
	Message         string
	Features        map[string]bool

	// Service identity fields (optional - only for service licenses)
	ServiceName string   `json:"service_name,omitempty"`
	ServiceType string   `json:"service_type,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// ServiceLicensePayload represents the JSON payload in a V2 service license
type ServiceLicensePayload struct {
	Tier        string   `json:"tier"`
	TenantID    string   `json:"tenant_id"`
	ServiceName string   `json:"service_name,omitempty"`
	ServiceType string   `json:"service_type,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	ExpiresAt   string   `json:"expires_at"` // Format: YYYYMMDD
}

// ValidateHMACSecretAtStartup is a no-op in OSS builds.
// OSS builds don't require HMAC secret validation since they don't generate
// or strictly validate licenses.
func ValidateHMACSecretAtStartup() error {
	return nil
}

// ValidateLicense validates an AxonFlow license key.
// OSS stub: Parses V2 licenses to extract metadata, but doesn't enforce strict validation.
// For non-V2 licenses or parse errors, returns a default OSS result.
func ValidateLicense(ctx context.Context, licenseKey string) (*ValidationResult, error) {
	// Try to parse as V2 license
	if strings.HasPrefix(licenseKey, "AXON-V2-") {
		result, err := parseV2License(licenseKey)
		if err == nil && result != nil {
			return result, nil
		}
		// If V2 parsing fails, fall through to default OSS result
	}

	// Default: Return OSS mode result for non-V2 or unparseable licenses
	return &ValidationResult{
		Valid:           true,
		Tier:            TierOSS,
		OrgID:           "oss",
		MaxNodes:        9999, // Unlimited in OSS mode
		ExpiresAt:       time.Now().AddDate(100, 0, 0), // Far future
		DaysUntilExpiry: 36500,
		GracePeriodDays: 0,
		Error:           "",
		Message:         "OSS mode - no license required",
		Features:        getOSSFeatures(),
	}, nil
}

// parseV2License parses a V2 license key and extracts its metadata
// Format: AXON-V2-{BASE64_JSON}-{SIGNATURE}
func parseV2License(licenseKey string) (*ValidationResult, error) {
	parts := strings.Split(licenseKey, "-")
	if len(parts) != 4 || parts[0] != "AXON" || parts[1] != "V2" {
		return nil, nil // Not a valid V2 format
	}

	payloadBase64 := parts[2]
	signature := parts[3]

	// Decode base64 JSON payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, err
	}

	// Parse JSON payload
	var payload ServiceLicensePayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, err
	}

	// Validate tier
	tier := Tier(payload.Tier)
	if tier != TierProfessional && tier != TierEnterprise && tier != TierEnterprisePlus {
		tier = TierOSS // Default to OSS for unknown tiers
	}

	// Parse expiry date (format: YYYYMMDD)
	expiry, err := time.Parse("20060102", payload.ExpiresAt)
	if err != nil {
		expiry = time.Now().AddDate(100, 0, 0) // Default to far future
	}

	// Verify signature using default HMAC secret (for tests)
	// In OSS mode, we're lenient but still verify to support tests
	if !verifyV2Signature(payloadBase64, signature) {
		return nil, nil // Invalid signature, fall through to default OSS
	}

	// Check if expired (but in OSS mode, we're lenient)
	now := time.Now()
	daysUntilExpiry := int(expiry.Sub(now).Hours() / 24)

	// In OSS mode, expired licenses still work (grace period is unlimited)
	valid := true
	message := "V2 license parsed in OSS mode"
	if now.After(expiry) {
		message = "V2 license expired but accepted in OSS mode"
	}

	return &ValidationResult{
		Valid:           valid,
		Tier:            tier,
		OrgID:           payload.TenantID,
		MaxNodes:        9999, // Unlimited in OSS mode
		ExpiresAt:       expiry,
		DaysUntilExpiry: daysUntilExpiry,
		GracePeriodDays: 0,
		Error:           "",
		Message:         message,
		Features:        getOSSFeatures(),
		ServiceName:     payload.ServiceName,
		ServiceType:     payload.ServiceType,
		Permissions:     payload.Permissions,
	}, nil
}

// verifyV2Signature verifies the HMAC-SHA256 signature of a V2 license payload
func verifyV2Signature(payloadBase64, providedSignature string) bool {
	h := hmac.New(sha256.New, []byte(defaultHMACSecret))
	h.Write([]byte(payloadBase64))
	calculatedHash := hex.EncodeToString(h.Sum(nil))
	calculatedSignature := calculatedHash[:8]
	return hmac.Equal([]byte(calculatedSignature), []byte(providedSignature))
}

// ValidateWithRetry validates a license with automatic retry on transient failures.
// OSS stub: Always returns valid immediately (no retries needed).
func ValidateWithRetry(ctx context.Context, licenseKey string, maxAttempts int) (*ValidationResult, error) {
	return ValidateLicense(ctx, licenseKey)
}

// getOSSFeatures returns the features enabled in OSS mode
func getOSSFeatures() map[string]bool {
	return map[string]bool{
		"multi_tenant":      false,
		"advanced_policies": false,
		"sla_guarantee":     false,
		"audit_logging":     true,
		"basic_support":     false, // Community support only
		"oss_mode":          true,
	}
}

// GenerateLicenseKey is not available in OSS builds.
// License generation is an enterprise-only feature to prevent exposure of the
// license key format and signing algorithm.
func GenerateLicenseKey(tier Tier, orgID string, expiryDays int) (string, error) {
	return "", fmt.Errorf("license generation is not available in OSS builds - " +
		"upgrade to Enterprise at https://getaxonflow.com/enterprise for license management")
}

// GenerateServiceLicenseKey is not available in OSS builds.
// License generation is an enterprise-only feature to prevent exposure of the
// license key format and signing algorithm.
func GenerateServiceLicenseKey(tier Tier, tenantID, serviceName, serviceType string, permissions []string, expiryDays int) (string, error) {
	return "", fmt.Errorf("license generation is not available in OSS builds - " +
		"upgrade to Enterprise at https://getaxonflow.com/enterprise for license management")
}
