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
	"strings"
	"time"

	"github.com/google/uuid"
)

// maxEvaluationDays is the hard limit for Evaluation license validity.
// Defense in depth: enforced at generation time in addition to validation time.
const maxEvaluationDays = 90

// getSigningKey loads the Ed25519 private key from environment variables.
// For EVALUATION tier: reads AXONFLOW_EVAL_SIGNING_KEY
// For Professional/Enterprise/Plus tiers: reads AXONFLOW_ENT_SIGNING_KEY
// For plugin-claim tiers (W4, ADR-049): reads AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY
// (separate keypair so a plugin-claim leak only forges plugin tokens, not full
// self-hosted enterprise licenses with unlimited node counts)
// All env vars contain a base64-encoded 32-byte Ed25519 seed.
func getSigningKey(tier Tier) (ed25519.PrivateKey, error) {
	var envVar string
	switch tier {
	case TierEvaluation:
		envVar = "AXONFLOW_EVAL_SIGNING_KEY"
	case TierPluginClaimed, TierPluginSubscription:
		envVar = "AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY"
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

// =============================================================================
// W4 plugin-claim license generation (per ADR-049)
// =============================================================================

// PluginClaimLicenseInput collects the inputs needed to issue a plugin-claim
// license token. Required fields: TenantID, ClaimedByEmail, ValidityDays.
// JTI defaults to a fresh UUID v4 if empty. KID defaults to "v3-2026-05-04"
// (the inaugural plugin-claim signing key) if empty.
type PluginClaimLicenseInput struct {
	TenantID       string // cs_<uuid> binding the token to a community-saas tenant (required)
	ClaimedByEmail string // email associated with the paid claim (required)
	ValidityDays   int    // how long the token is valid (use 0 for no expiry — Pro v1 one-time pricing)
	JTI            string // optional unique token id (UUID v7). Auto-generated if empty.
	KID            string // optional signing key id (e.g. "v3-2026-05-04"). Defaults if empty.
	Tier           Tier   // TierPluginClaimed (Pro v1) or TierPluginSubscription (Premium v2 — not issued in v1)
}

// defaultPluginClaimKID is the kid value baked into v1 tokens when caller
// doesn't override. Must match the AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY in
// AWS Secrets Manager. Operators rotating the signing key should pass an
// updated kid to GeneratePluginClaimLicense so older tokens continue to
// validate against the previous key during the dual-validate window
// (per ADR-049 section 3).
const defaultPluginClaimKID = "v3-2026-05-04"

// GeneratePluginClaimLicense issues a fresh plugin-claim license token signed
// with the AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY Ed25519 keypair (separate from
// the eval/ent keys per ADR-049 section 1's blast-radius isolation rationale).
//
// Returned token format mirrors the existing service-license format:
//
//	AXON-{BASE64URL(JSON_PAYLOAD)}.{BASE64URL(ED25519_SIGNATURE)}
//
// Validation in agent middleware (W4 PR D) MUST check:
//  1. Ed25519 signature verifies against the plugin-claim public key
//  2. payload.aud == "community_saas_plugin"
//  3. payload.origin == "plugin"
//  4. payload.tier ∈ {plugin-claimed, plugin-subscription}
//  5. payload.expires_at > now (if set)
//  6. plugin_user_licenses row exists with matching jti AND revoked_at IS NULL
//
// Steps 1–5 are token-side. Step 6 is DB-side. Together they enforce per-token
// revocation (chargeback / dispute) and tier-aware entitlements.
func GeneratePluginClaimLicense(in PluginClaimLicenseInput) (string, error) {
	if in.TenantID == "" {
		return "", fmt.Errorf("TenantID cannot be empty for plugin-claim licenses")
	}
	if in.ClaimedByEmail == "" {
		return "", fmt.Errorf("ClaimedByEmail cannot be empty for plugin-claim licenses")
	}
	if in.Tier == "" {
		in.Tier = TierPluginClaimed
	}
	if in.Tier != TierPluginClaimed && in.Tier != TierPluginSubscription {
		return "", fmt.Errorf("invalid plugin-claim tier: %s (must be plugin-claimed or plugin-subscription)", in.Tier)
	}
	if in.ValidityDays < 0 {
		return "", fmt.Errorf("ValidityDays cannot be negative")
	}
	if in.JTI == "" {
		in.JTI = uuid.NewString()
	}
	if in.KID == "" {
		in.KID = defaultPluginClaimKID
	}

	now := time.Now()
	issuedStr := now.Format("20060102")
	var expiryStr string
	if in.ValidityDays > 0 {
		expiryStr = now.AddDate(0, 0, in.ValidityDays).Format("20060102")
	}
	// For Pro v1 (one-time payment), ValidityDays == 0 means "no token expiry"
	// — entitlements live in plugin_user_licenses DB row and revocation is
	// the sole expiry mechanism. We still set a far-future date in the
	// payload so existing parsers that require expires_at don't break.
	if expiryStr == "" {
		expiryStr = now.AddDate(100, 0, 0).Format("20060102")
	}

	payload := ServiceLicensePayload{
		Tier:      string(in.Tier),
		OrgID:     communitySaasOrgIDForLicense, // plugin-claim tokens use a fixed org_id
		IssuedAt:  issuedStr,
		ExpiresAt: expiryStr,

		// W4 plugin-claim claims
		TenantID: in.TenantID,
		Aud:      ExpectedPluginClaimAudience,
		JTI:      in.JTI,
		KID:      in.KID,
		Origin:   ExpectedPluginClaimOrigin,
		Email:    in.ClaimedByEmail,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode plugin-claim payload: %w", err)
	}
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	privateKey, err := getSigningKey(in.Tier)
	if err != nil {
		return "", fmt.Errorf("failed to load plugin-claim signing key: %w", err)
	}

	signature := ed25519.Sign(privateKey, []byte(payloadBase64))
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("AXON-%s.%s", payloadBase64, signatureBase64), nil
}

// communitySaasOrgIDForLicense is the OrgID stamped into plugin-claim license
// tokens. Plugin-claim is a SaaS-hosted product line — the customer doesn't
// have their own org_id in the self-hosted sense. Using a fixed value here
// makes license payloads consistent and easy to identify in audit logs.
const communitySaasOrgIDForLicense = "community-saas"

// ValidatePluginClaimToken does the token-side validation steps for a
// plugin-claim license: signature verification + audience + origin + tier
// + expiry. Returns the decoded payload on success so the caller (agent
// middleware) can continue to step 6 (plugin_user_licenses DB lookup by
// jti / tenant_id).
//
// Returns *PluginClaimValidationError for plugin-claim-specific failures
// (audience mismatch, origin mismatch, wrong tier). Returns plain error for
// signature / encoding / parse failures. Caller can use errors.As to
// distinguish the two failure modes.
func ValidatePluginClaimToken(licenseKey string) (*ServiceLicensePayload, error) {
	// Inline parse + verify rather than reuse validateEd25519License: the
	// existing path is hard-coded to the eval/ent key set and would reject
	// our plugin-claim tier as unknown before we get to verify the
	// signature with the plugin-claim public key.
	if !strings.HasPrefix(licenseKey, "AXON-") {
		return nil, fmt.Errorf("invalid plugin-claim license format: missing AXON- prefix")
	}
	rest := licenseKey[5:]
	dotIdx := strings.LastIndex(rest, ".")
	if dotIdx < 1 {
		return nil, fmt.Errorf("invalid plugin-claim license format: missing signature separator")
	}
	payloadBase64 := rest[:dotIdx]
	signatureBase64 := rest[dotIdx+1:]

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid plugin-claim payload encoding: %w", err)
	}
	var payload ServiceLicensePayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("invalid plugin-claim payload JSON: %w", err)
	}

	// Tier check FIRST — pick the right verification key
	tier := Tier(payload.Tier)
	if !IsPluginTier(tier) {
		return nil, &PluginClaimValidationError{Reason: fmt.Sprintf("token tier %q is not a plugin-claim tier", payload.Tier)}
	}

	// Signature verification with plugin-claim public key
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid plugin-claim signature encoding: %w", err)
	}
	pubKey, err := getPluginClaimPublicKey()
	if err != nil {
		return nil, fmt.Errorf("plugin-claim public key not configured: %w", err)
	}
	if !ed25519.Verify(pubKey, []byte(payloadBase64), signature) {
		return nil, &PluginClaimValidationError{Reason: "Ed25519 signature verification failed"}
	}

	// Audience check
	if payload.Aud != ExpectedPluginClaimAudience {
		return nil, &PluginClaimValidationError{Reason: fmt.Sprintf("aud %q does not match expected %q", payload.Aud, ExpectedPluginClaimAudience)}
	}

	// Origin check
	if payload.Origin != ExpectedPluginClaimOrigin {
		return nil, &PluginClaimValidationError{Reason: fmt.Sprintf("origin %q does not match expected %q", payload.Origin, ExpectedPluginClaimOrigin)}
	}

	// TenantID required
	if payload.TenantID == "" {
		return nil, &PluginClaimValidationError{Reason: "tenant_id is empty"}
	}

	// JTI required (used for DB lookup + revocation)
	if payload.JTI == "" {
		return nil, &PluginClaimValidationError{Reason: "jti is empty"}
	}

	// Expiry check — payload uses YYYYMMDD format
	if payload.ExpiresAt != "" {
		expiry, perr := time.Parse("20060102", payload.ExpiresAt)
		if perr != nil {
			return nil, &PluginClaimValidationError{Reason: fmt.Sprintf("invalid expires_at format %q: %v", payload.ExpiresAt, perr)}
		}
		// Add 24h grace so a token expiring "today" stays valid through the
		// end of the day in any timezone — same behavior as eval/ent tokens.
		if time.Now().After(expiry.Add(24 * time.Hour)) {
			return nil, &PluginClaimValidationError{Reason: "token expired"}
		}
	}

	return &payload, nil
}

// getPluginClaimPublicKey loads the Ed25519 public verification key used to
// validate plugin-claim license tokens. Reads AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY
// (the seed) and derives the public key from it — the seed → public-key
// derivation is deterministic so the two are equivalent.
//
// Operational note: ideally a verifier would only have access to the public
// key (so a verifier compromise cannot issue forgeries). Today the agent
// holds the seed because the same env var feeds both signing
// (axonflow-billing) and verification (agent middleware) paths. PR D will
// split this so verifiers receive a pubkey-only secret
// (AXONFLOW_PLUGIN_CLAIMED_PUBLIC_KEY) and signers keep the seed; this
// function is the indirection point that change will route through.
func getPluginClaimPublicKey() (ed25519.PublicKey, error) {
	priv, err := getSigningKey(TierPluginClaimed)
	if err != nil {
		return nil, err
	}
	return priv.Public().(ed25519.PublicKey), nil
}
