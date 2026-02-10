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

// Package license provides license validation for AxonFlow Agent.
// This is the Community build - it validates Ed25519-signed licenses using
// embedded public keys. Invalid or expired licenses fall back to Community
// tier defaults.
package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ValidateLicense validates an AxonFlow license key.
// Supports Ed25519-signed format: AXON-{PAYLOAD}.{SIGNATURE}
// Rejects old V2 (HMAC) and V1 formats with a clear error.
// For empty or missing licenses, returns Community mode result.
func ValidateLicense(ctx context.Context, licenseKey string) (*ValidationResult, error) {
	if licenseKey == "" {
		return &ValidationResult{
			Valid:           true,
			Tier:            TierCommunity,
			OrgID:           "community",
			MaxNodes:        9999,
			ExpiresAt:       time.Now().AddDate(100, 0, 0),
			DaysUntilExpiry: 36500,
			Features:        getCommunityFeatures(),
			Limits:          CommunityLimits,
			Message:         "Community mode - no license required",
		}, nil
	}

	// Must start with AXON- prefix
	if !strings.HasPrefix(licenseKey, "AXON-") {
		return communityFallback("invalid license key prefix"), nil
	}

	// Reject old V2 format
	if strings.HasPrefix(licenseKey, "AXON-V2-") {
		return communityFallback("V2 license format no longer supported — request a new license at https://getaxonflow.com/evaluation-license"), nil
	}

	// Check for Ed25519 format: must contain "." separator after AXON- prefix
	rest := licenseKey[5:]
	if !strings.Contains(rest, ".") {
		return communityFallback("V1 license format no longer supported — request a new license at https://getaxonflow.com/evaluation-license"), nil
	}

	// Parse and validate Ed25519 license
	return validateEd25519License(licenseKey)
}

// validateEd25519License validates an Ed25519-signed license key.
// Format: AXON-{BASE64URL(JSON_PAYLOAD)}.{BASE64URL(ED25519_SIGNATURE)}
func validateEd25519License(licenseKey string) (*ValidationResult, error) {
	rest := licenseKey[5:]

	dotIdx := strings.LastIndex(rest, ".")
	if dotIdx < 1 {
		return communityFallback("invalid license format"), nil
	}

	payloadBase64 := rest[:dotIdx]
	signatureBase64 := rest[dotIdx+1:]

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return communityFallback("invalid payload encoding"), nil
	}

	// Parse JSON payload
	var payload ServiceLicensePayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return communityFallback("invalid payload JSON"), nil
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return communityFallback("invalid signature encoding"), nil
	}

	if len(signature) != ed25519.SignatureSize {
		return communityFallback("invalid signature length"), nil
	}

	// Determine tier and select appropriate public key.
	tier := normalizeTier(payload.Tier)

	// Verify Ed25519 signature
	if !verifyEd25519Signature([]byte(payloadBase64), signature, tier) {
		return communityFallback("invalid license signature"), nil
	}

	// Validate tier
	switch tier {
	case TierEvaluation, TierProfessional, TierEnterprise, TierEnterprisePlus:
		// valid
	default:
		return communityFallback("unknown license tier"), nil
	}

	// Parse expiry date
	expiry, err := time.Parse("20060102", payload.ExpiresAt)
	if err != nil {
		return communityFallback("invalid expiry date"), nil
	}

	// Use tier defaults for limits. Payload limits are ignored — the tier
	// determines resource limits, not the license payload. This prevents
	// a signed payload from granting limits above the tier ceiling.
	limits := GetTierLimits(tier)

	// Check expiry
	now := time.Now()
	daysUntilExpiry := int(expiry.Sub(now).Hours() / 24)

	// Set max nodes based on tier
	maxNodes := 2
	switch tier {
	case TierProfessional:
		maxNodes = 10
	case TierEnterprise:
		maxNodes = 50
	case TierEnterprisePlus:
		maxNodes = 9999
	}

	result := &ValidationResult{
		Valid:           true,
		Tier:            tier,
		OrgID:           payload.TenantID,
		MaxNodes:        maxNodes,
		ExpiresAt:       expiry,
		DaysUntilExpiry: daysUntilExpiry,
		Features:        getFeatures(tier),
		Limits:          limits,
		ServiceName:     payload.ServiceName,
		ServiceType:     payload.ServiceType,
		Permissions:     payload.Permissions,
		Email:           payload.Email,
		LicenseID:       payload.LicenseID,
	}

	// Check if expired (7-day grace period matches enterprise build)
	if now.After(expiry) {
		daysExpired := int(now.Sub(expiry).Hours() / 24)
		if daysExpired <= 7 {
			result.GracePeriodDays = 7 - daysExpired
			result.Message = fmt.Sprintf("License expired %d days ago, %d days of grace period remaining",
				daysExpired, result.GracePeriodDays)
		} else {
			result.Valid = false
			result.Error = "LICENSE_EXPIRED"
			result.Message = fmt.Sprintf("License expired on %s (grace period ended)", expiry.Format("2006-01-02"))
		}
	} else if daysUntilExpiry <= 30 {
		result.Message = fmt.Sprintf("License expires in %d days", daysUntilExpiry)
	}

	return result, nil
}

// getFeatures returns the features enabled for a given tier
func getFeatures(tier Tier) map[string]bool {
	features := make(map[string]bool)

	switch tier {
	case TierEvaluation:
		features["audit_logging"] = true
		features["basic_support"] = true

	case TierProfessional:
		features["multi_tenant"] = false
		features["advanced_policies"] = false
		features["sla_guarantee"] = false
		features["audit_logging"] = true
		features["basic_support"] = true

	case TierEnterprise:
		features["multi_tenant"] = true
		features["advanced_policies"] = true
		features["sla_guarantee"] = true
		features["audit_logging"] = true
		features["priority_support"] = true
		features["custom_connectors"] = true

	case TierEnterprisePlus:
		features["multi_tenant"] = true
		features["advanced_policies"] = true
		features["sla_guarantee"] = true
		features["audit_logging"] = true
		features["24x7_support"] = true
		features["custom_connectors"] = true
		features["dedicated_sa"] = true
		features["unlimited_nodes"] = true

	default:
		return getCommunityFeatures()
	}

	return features
}

// getCommunityFeatures returns the features enabled in Community mode
func getCommunityFeatures() map[string]bool {
	return map[string]bool{
		"multi_tenant":      false,
		"advanced_policies": false,
		"sla_guarantee":     false,
		"audit_logging":     true,
		"basic_support":     false,
		"community_mode":    true,
	}
}

// communityFallback returns a Community mode result with a message
func communityFallback(msg string) *ValidationResult {
	return &ValidationResult{
		Valid:           true,
		Tier:            TierCommunity,
		OrgID:           "community",
		MaxNodes:        9999,
		ExpiresAt:       time.Now().AddDate(100, 0, 0),
		DaysUntilExpiry: 36500,
		Features:        getCommunityFeatures(),
		Limits:          CommunityLimits,
		Message:         msg,
	}
}

// ValidateWithRetry validates a license with automatic retry on transient failures.
// Community stub: Always returns valid immediately (no retries needed).
func ValidateWithRetry(ctx context.Context, licenseKey string, maxAttempts int) (*ValidationResult, error) {
	return ValidateLicense(ctx, licenseKey)
}

// IsEnterpriseTier checks if the current license is Enterprise or Enterprise Plus.
func IsEnterpriseTier(ctx context.Context) bool {
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		return false
	}
	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil || result == nil || !result.Valid {
		return false
	}
	if time.Now().After(result.ExpiresAt) {
		return false
	}
	return result.Tier == TierEnterprise || result.Tier == TierEnterprisePlus
}

// IsEvaluationOrHigherTier checks if the AXONFLOW_LICENSE_KEY environment variable
// contains a valid Evaluation, Enterprise, or EnterprisePlus license.
func IsEvaluationOrHigherTier(ctx context.Context) bool {
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		return false
	}
	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil || result == nil || !result.Valid {
		return false
	}
	if time.Now().After(result.ExpiresAt) {
		return false
	}
	return result.Tier == TierEvaluation || result.Tier == TierProfessional || result.Tier == TierEnterprise || result.Tier == TierEnterprisePlus
}

// GetCurrentTier returns the current license tier based on AXONFLOW_LICENSE_KEY.
// Returns TierCommunity if no valid license is found or if the license is expired.
func GetCurrentTier(ctx context.Context) Tier {
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		return TierCommunity
	}
	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil || result == nil || !result.Valid {
		return TierCommunity
	}
	if time.Now().After(result.ExpiresAt) {
		return TierCommunity
	}
	return result.Tier
}

// GetCurrentLimits returns the resource limits based on the current license.
// If the license is expired, returns Community limits (graceful degradation).
func GetCurrentLimits(ctx context.Context) TierLimits {
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		return CommunityLimits
	}
	result, err := ValidateLicense(ctx, licenseKey)
	if err != nil || result == nil || !result.Valid {
		return CommunityLimits
	}
	if time.Now().After(result.ExpiresAt) {
		return CommunityLimits
	}
	return result.Limits
}

// GenerateLicenseKey is not available in Community builds.
func GenerateLicenseKey(tier Tier, orgID string, expiryDays int) (string, error) {
	return "", fmt.Errorf("license generation is not available in Community builds - " +
		"upgrade to Enterprise at https://getaxonflow.com/enterprise for license management")
}

// GenerateServiceLicenseKey is not available in Community builds.
func GenerateServiceLicenseKey(tier Tier, tenantID, serviceName, serviceType string, permissions []string, expiryDays int) (string, error) {
	return "", fmt.Errorf("license generation is not available in Community builds - " +
		"upgrade to Enterprise at https://getaxonflow.com/enterprise for license management")
}
