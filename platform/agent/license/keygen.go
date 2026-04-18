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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// maxEvaluationDays is the hard limit for Evaluation license validity.
// Defense in depth: enforced at generation time in addition to validation time.
const maxEvaluationDays = 90

// getSigningKey loads the Ed25519 private key from environment variables.
// For EVALUATION tier: reads AXONFLOW_EVAL_SIGNING_KEY
// For Professional/Enterprise/Plus tiers: reads AXONFLOW_ENT_SIGNING_KEY
// The env var contains a base64-encoded 32-byte Ed25519 seed.
func getSigningKey(tier Tier) (ed25519.PrivateKey, error) {
	var envVar string
	switch tier {
	case TierEvaluation:
		envVar = "AXONFLOW_EVAL_SIGNING_KEY"
	default: // Professional, Enterprise, Plus
		envVar = "AXONFLOW_ENT_SIGNING_KEY"
	}

	seedB64 := os.Getenv(envVar)
	if seedB64 == "" {
		return nil, fmt.Errorf("signing key not configured: set %s environment variable (base64-encoded Ed25519 seed)", envVar)
	}

	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signing key in %s: %w", envVar, err)
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid signing key in %s: expected %d bytes, got %d", envVar, ed25519.SeedSize, len(seed))
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

// GenerateLicenseKey is DEPRECATED - use GenerateServiceLicenseKey instead
// V1 license format (AXON-TIER-ORG-EXPIRY-SIG) is no longer supported
// See ADR-007 for migration guide
//
// Deprecated: This function will be removed in a future version.
// Use GenerateServiceLicenseKey for all new license generation.
func GenerateLicenseKey(tier Tier, orgID string, validityDays int) (string, error) {
	// Redirect to V2 format with default service settings
	return GenerateServiceLicenseKey(
		tier,
		orgID,
		"platform",        // default service name
		"backend-service", // default service type
		[]string{"mcp:*:*", "llm:*:*"}, // full permissions for platform
		validityDays,
	)
}

// GenerateServiceLicenseKey generates an Ed25519-signed license key with permissions.
// Format: AXON-{BASE64URL(JSON_PAYLOAD)}.{BASE64URL(ED25519_SIGNATURE)}
// See ADR-032 for format specification.
func GenerateServiceLicenseKey(
	tier Tier,
	orgID string,
	serviceName string,
	serviceType string,
	permissions []string,
	validityDays int,
) (string, error) {
	// Validate inputs
	if tier != TierEvaluation && tier != TierProfessional && tier != TierEnterprise && tier != TierEnterprisePlus {
		return "", fmt.Errorf("invalid tier: %s (must be Evaluation, Professional, Enterprise, or Plus)", tier)
	}

	if orgID == "" {
		return "", fmt.Errorf("orgID cannot be empty")
	}

	if serviceName == "" {
		return "", fmt.Errorf("serviceName cannot be empty for service licenses")
	}

	if serviceType != "client-application" && serviceType != "backend-service" && serviceType != "integration" {
		return "", fmt.Errorf("invalid serviceType: %s (must be client-application, backend-service, or integration)", serviceType)
	}

	if len(permissions) == 0 {
		return "", fmt.Errorf("permissions cannot be empty for service licenses")
	}

	if validityDays <= 0 {
		return "", fmt.Errorf("validityDays must be positive")
	}

	// Enforce 90-day max for Evaluation tier (defense in depth)
	if tier == TierEvaluation && validityDays > maxEvaluationDays {
		return "", fmt.Errorf("Evaluation licenses cannot exceed %d days (requested %d)", maxEvaluationDays, validityDays)
	}

	// Calculate dates
	now := time.Now()
	issuedStr := now.Format("20060102")
	expiryDate := now.AddDate(0, 0, validityDays)
	expiryStr := expiryDate.Format("20060102")

	// Create JSON payload
	payload := ServiceLicensePayload{
		Tier:        string(tier),
		OrgID:       orgID,
		ServiceName: serviceName,
		ServiceType: serviceType,
		Permissions: permissions,
		IssuedAt:    issuedStr,
		ExpiresAt:   expiryStr,
	}

	// Encode payload as JSON
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}

	// Encode as base64url (no padding)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Get the appropriate signing key
	privateKey, err := getSigningKey(tier)
	if err != nil {
		return "", fmt.Errorf("failed to load signing key: %w", err)
	}

	// Sign the base64url-encoded payload with Ed25519
	signature := ed25519.Sign(privateKey, []byte(payloadBase64))

	// Encode signature as base64url (no padding)
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	// Construct license key: AXON-{PAYLOAD}.{SIGNATURE}
	licenseKey := fmt.Sprintf("AXON-%s.%s", payloadBase64, signatureBase64)

	return licenseKey, nil
}

// Example usage for generating license keys (Ed25519 format)
func ExampleGenerateLicenseKey() {
	// Generate a 1-year Enterprise license for Acme Corp
	// Note: GenerateLicenseKey now returns Ed25519-signed format internally
	key, err := GenerateServiceLicenseKey(
		TierEnterprise,
		"acme",
		"platform",
		"backend-service",
		[]string{"mcp:*:*", "llm:*:*"},
		365,
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("License Key: %s\n", key)

	// Validate the generated key
	result, err := ValidateLicense(context.Background(), key)
	if err != nil {
		fmt.Printf("Validation Error: %v\n", err)
		return
	}

	fmt.Printf("Valid: %v\n", result.Valid)
	fmt.Printf("Tier: %s\n", result.Tier)
	fmt.Printf("Max Nodes: %d\n", result.MaxNodes)
	fmt.Printf("Expires: %s\n", result.ExpiresAt.Format("2006-01-02"))
}

// ExampleGenerateServiceLicenseKey shows how to generate a service license
func ExampleGenerateServiceLicenseKey() {
	// Generate a 1-year service license for trip planner with Amadeus permissions
	key, err := GenerateServiceLicenseKey(
		TierEnterprisePlus,
		"travel-eu",
		"trip-planner",
		"client-application",
		[]string{"mcp:amadeus:search_flights", "mcp:amadeus:search_hotels", "mcp:amadeus:lookup_airport"},
		365,
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Service License Key: %s\n", key)

	// Validate the generated key
	result, err := ValidateLicense(context.Background(), key)
	if err != nil {
		fmt.Printf("Validation Error: %v\n", err)
		return
	}

	fmt.Printf("Valid: %v\n", result.Valid)
	fmt.Printf("Tenant: %s\n", result.OrgID)
	fmt.Printf("Service: %s (%s)\n", result.ServiceName, result.ServiceType)
	fmt.Printf("Permissions: %v\n", result.Permissions)
	fmt.Printf("Expires: %s\n", result.ExpiresAt.Format("2006-01-02"))
}
