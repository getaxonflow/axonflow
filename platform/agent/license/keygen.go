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
// For SaaS Plugin tiers (Pro / Premium per ADR-050 §1): reads
// AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY. The env var name is preserved
// across the 2026-05-05 rename so existing AWS Secrets Manager bindings
// stay valid; see ADR-049 §1 for the blast-radius isolation rationale —
// a SaaS-plugin signer leak forges only Pro/Premium tokens, not self-
// hosted Enterprise licenses with unlimited node counts.
// All env vars contain a base64-encoded 32-byte Ed25519 seed.
func getSigningKey(tier Tier) (ed25519.PrivateKey, error) {
	var envVar string
	switch tier {
	case TierEvaluation:
		envVar = "AXONFLOW_EVAL_SIGNING_KEY"
	case TierPro, TierPremium:
		envVar = "AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY"
	default: // Professional, Enterprise, Plus
		envVar = "AXONFLOW_ENT_SIGNING_KEY"
	}

	seedB64 := strings.TrimSpace(os.Getenv(envVar))
	if seedB64 == "" {
		return nil, fmt.Errorf("signing key not configured: set %s environment variable (base64-encoded Ed25519 seed)", envVar)
	}

	// Accept any of the four common base64 dialects an operator might paste
	// into AWS Secrets Manager / a deploy env: standard, raw-standard
	// (no padding), URL-safe, raw-URL-safe. Operators have repeatedly
	// pasted the unpadded form and hit "illegal base64 data at input byte
	// 40" — all four dialects decode the same 32-byte seed; let any of
	// them succeed instead of forcing a manual re-paste with a trailing '='.
	// Surface a single composite error if all four fail (so we don't
	// dump four near-identical decode errors).
	seed, decodeErr := decodeBase64Tolerant(seedB64)
	if decodeErr != nil {
		return nil, fmt.Errorf("invalid signing key in %s: %w", envVar, decodeErr)
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid signing key in %s: expected %d bytes, got %d", envVar, ed25519.SeedSize, len(seed))
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

// decodeBase64Tolerant tries the four common base64 dialects in order:
// standard (with padding), raw-standard (no padding), URL-safe (with
// padding), raw-URL-safe (no padding). Returns the first successful
// decode. If all fail, returns the standard-encoding error since that's
// the canonical/expected form.
//
// Why this exists: operators paste signing-key seeds into Secrets Manager
// from various sources (Stripe Dashboard, openssl rand output, in-house
// keygen tools). Different sources emit different dialects. base64.
// StdEncoding rejects unpadded values with a confusing "illegal base64
// data at input byte N" error. Tolerant decode here makes the secret-
// bootstrap path one less footgun in the V1 launch path.
func decodeBase64Tolerant(s string) ([]byte, error) {
	if seed, err := base64.StdEncoding.DecodeString(s); err == nil {
		return seed, nil
	}
	if seed, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return seed, nil
	}
	if seed, err := base64.URLEncoding.DecodeString(s); err == nil {
		return seed, nil
	}
	if seed, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return seed, nil
	}
	// All four failed — return the StdEncoding error (canonical form)
	// since that's what we document operators to use.
	_, err := base64.StdEncoding.DecodeString(s)
	return nil, err
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
		"platform",                     // default service name
		"backend-service",              // default service type
		[]string{"mcp:*:*", "llm:*:*"}, // full permissions for platform
		validityDays,
	)
}

// GenerateServiceLicenseKey generates an Ed25519-signed license key with
// permissions. Format: AXON-{BASE64URL(JSON_PAYLOAD)}.{BASE64URL(ED25519_SIGNATURE)}
// See ADR-032 for format specification.
//
// Wraps GenerateServiceLicenseKeyWithAud with the default
// `axonflow.self_hosted.full` aud — every existing call site issues
// self-hosted-full licenses and that's the safe default per ADR-050 §1.
// New issuance paths (Plugin In-VPC eval with `axonflow.self_hosted.plugin`,
// future SDK product) call GenerateServiceLicenseKeyWithAud directly.
func GenerateServiceLicenseKey(
	tier Tier,
	orgID string,
	serviceName string,
	serviceType string,
	permissions []string,
	validityDays int,
) (string, error) {
	return GenerateServiceLicenseKeyWithAud(tier, orgID, serviceName, serviceType, permissions, validityDays, AudSelfHostedFull)
}

// GenerateServiceLicenseKeyWithAud generates an Ed25519-signed license
// key with an explicit `aud` claim. Per ADR-050 §3 the aud must be in
// the self-hosted accept list — `axonflow.self_hosted.{plugin,sdk,full}`.
// Other values are rejected (cross-quadrant licenses cannot be issued
// from this generator; SaaS Plugin tokens go through
// GeneratePluginClaimLicense instead).
//
// `aud == ""` is treated as `axonflow.self_hosted.full` for backward
// compatibility with the original GenerateServiceLicenseKey signature.
func GenerateServiceLicenseKeyWithAud(
	tier Tier,
	orgID string,
	serviceName string,
	serviceType string,
	permissions []string,
	validityDays int,
	aud string,
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

	// Validate the aud override (or fall through to the self-hosted-full
	// default for backward compatibility). Cross-quadrant aud values are
	// rejected — the SaaS Plugin signer is a different keypair entirely.
	if aud == "" {
		aud = AudSelfHostedFull
	}
	switch aud {
	case AudSelfHostedFull, AudSelfHostedPlugin, AudSelfHostedSDK:
		// valid self-hosted aud
	default:
		return "", fmt.Errorf("invalid aud %q for self-hosted license generator (must be one of axonflow.self_hosted.{plugin,sdk,full}); SaaS Plugin tokens use GeneratePluginClaimLicense", aud)
	}

	// Calculate dates
	now := time.Now()
	issuedStr := now.Format("20060102")
	expiryDate := now.AddDate(0, 0, validityDays)
	expiryStr := expiryDate.Format("20060102")

	// Create JSON payload. Self-hosted tokens carry the explicit aud per
	// ADR-050 §1; the matrix validator-loader rejects anything else at
	// agent boot. Tokens predating the rename have empty aud and fall
	// through via the §8 fallback in the validator.
	//
	// V3 license payload (ADR-052 §3 + ADR-054): mint BOTH `deployment_id`
	// (new) and `org_id` (legacy) with the same value. V2-only readers see
	// the legacy field and keep validating; V3 readers prefer the new
	// field. Operators inspecting payload JSON now have an unambiguous
	// deployment-identity field name instead of conflating with customer
	// row org_id.
	payload := ServiceLicensePayload{
		Tier:         string(tier),
		DeploymentID: orgID,
		OrgID:        orgID,
		ServiceName:  serviceName,
		ServiceType:  serviceType,
		Permissions:  permissions,
		IssuedAt:     issuedStr,
		ExpiresAt:    expiryStr,
		Aud:          aud,
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
// SaaS Plugin license generation (Pro / Premium per ADR-049 + ADR-050)
// =============================================================================

// PluginClaimLicenseInput collects the inputs needed to issue a SaaS Plugin
// license token (Pro or Premium). Required fields: TenantID, ClaimedByEmail,
// ValidityDays. JTI defaults to a fresh UUID v4 if empty. KID defaults to
// "v3-2026-05-04" (the inaugural plugin-claim signing key) if empty. IssuedAt
// defaults to time.Now() if zero.
type PluginClaimLicenseInput struct {
	TenantID       string    // cs_<uuid> binding the token to a community-saas tenant (required)
	ClaimedByEmail string    // email associated with the paid claim (required)
	ValidityDays   int       // how long the token is valid (use 0 for no expiry — Pro v1 one-time pricing)
	JTI            string    // optional unique token id (UUID v7). Auto-generated if empty.
	KID            string    // optional signing key id (e.g. "v3-2026-05-04"). Defaults if empty.
	Tier           Tier      // TierPro (V1) or TierPremium (placeholder, not sold V1)
	IssuedAt       time.Time // optional issuance timestamp. When zero, uses time.Now(). Set explicitly to re-mint a byte-identical token from a prior issuance (Ed25519 is deterministic; same JTI + KID + IssuedAt + payload = same signature). Used by the in-agent Stripe webhook for idempotency.
}

// defaultPluginClaimKID is the kid value baked into v1 tokens when caller
// doesn't override. Must match the AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY in
// AWS Secrets Manager. Operators rotating the signing key should pass an
// updated kid to GeneratePluginClaimLicense so older tokens continue to
// validate against the previous key during the dual-validate window
// (per ADR-049 section 3).
const defaultPluginClaimKID = "v3-2026-05-04"

// GeneratePluginClaimLicense issues a fresh SaaS Plugin license token signed
// with the AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY Ed25519 keypair (separate from
// the eval/ent keys per ADR-049 section 1's blast-radius isolation rationale).
//
// Returned token format mirrors the existing service-license format:
//
//	AXON-{BASE64URL(JSON_PAYLOAD)}.{BASE64URL(ED25519_SIGNATURE)}
//
// Validation in validateCommunitySaasAuth (per ADR-049 §3) MUST check:
//  1. Ed25519 signature verifies against the plugin-claim public key
//  2. payload.aud is in the SaaS Plugin path accept list (today
//     `community_saas_plugin`; the rename to `axonflow.saas.plugin` per
//     ADR-050 §1 lands in the per-quadrant validator PR — issue #1883)
//  3. payload.tier ∈ {Pro, Premium}
//  4. payload.expires_at > now (if set)
//  5. plugin_user_licenses row exists with matching jti AND revoked_at IS NULL
//     AND tenant_id matches the token's tenant_id
//
// Steps 1–4 are token-side. Step 5 is DB-side. Together they enforce per-token
// revocation (chargeback / dispute) and tier-aware enforcement.
func GeneratePluginClaimLicense(in PluginClaimLicenseInput) (string, error) {
	if in.TenantID == "" {
		return "", fmt.Errorf("TenantID cannot be empty for SaaS Plugin licenses")
	}
	if in.ClaimedByEmail == "" {
		return "", fmt.Errorf("ClaimedByEmail cannot be empty for SaaS Plugin licenses")
	}
	if in.Tier == "" {
		in.Tier = TierPro
	}
	if !IsSaasPluginTier(in.Tier) {
		return "", fmt.Errorf("invalid SaaS Plugin tier: %s (must be Pro or Premium)", in.Tier)
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

	now := in.IssuedAt
	if now.IsZero() {
		now = time.Now()
	}
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
		OrgID:     communitySaasOrgIDForLicense, // SaaS Plugin tokens use a fixed org_id
		IssuedAt:  issuedStr,
		ExpiresAt: expiryStr,

		// SaaS Plugin claims (per ADR-050 §1 + §2). `Origin` is intentionally
		// NOT set — it was redundant with the third aud segment and is
		// dropped per ADR-050 §2.
		TenantID: in.TenantID,
		Aud:      AudSaaSPlugin,
		JTI:      in.JTI,
		KID:      in.KID,
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
// SaaS Plugin license: signature verification + audience accept-list +
// tier + expiry. Returns the decoded payload on success so the caller
// (validateCommunitySaasAuth) can continue to the plugin_user_licenses
// DB lookup.
//
// Returns *PluginClaimValidationError for SaaS Plugin-specific failures
// (audience mismatch, wrong tier). Returns plain error for signature /
// encoding / parse failures. Caller can use errors.As to distinguish the
// two failure modes.
//
// The audience check delegates to ValidateForSaasPluginPath so the
// accept-list contract from ADR-050 §3 is the single source of truth
// (today: AudSaaSPlugin or AudSaaSFull). The deprecated `origin` check
// is removed per ADR-050 §2.
func ValidatePluginClaimToken(licenseKey string) (*ServiceLicensePayload, error) {
	// Inline parse + verify rather than reuse validateEd25519License: the
	// existing path is hard-coded to the eval/ent key set and would reject
	// our SaaS Plugin tier as unknown before we get to verify the
	// signature with the plugin-claim public key.
	if !strings.HasPrefix(licenseKey, "AXON-") {
		return nil, fmt.Errorf("invalid SaaS Plugin license format: missing AXON- prefix")
	}
	rest := licenseKey[5:]
	dotIdx := strings.LastIndex(rest, ".")
	if dotIdx < 1 {
		return nil, fmt.Errorf("invalid SaaS Plugin license format: missing signature separator")
	}
	payloadBase64 := rest[:dotIdx]
	signatureBase64 := rest[dotIdx+1:]

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid SaaS Plugin payload encoding: %w", err)
	}
	var payload ServiceLicensePayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("invalid SaaS Plugin payload JSON: %w", err)
	}

	// Tier check FIRST — picks the right verification key set
	tier := Tier(payload.Tier)
	if !IsSaasPluginTier(tier) {
		return nil, &PluginClaimValidationError{Reason: fmt.Sprintf("token tier %q is not a SaaS Plugin tier", payload.Tier)}
	}

	// Signature verification with plugin-claim public key
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid SaaS Plugin signature encoding: %w", err)
	}
	pubKey, err := getPluginClaimPublicKey()
	if err != nil {
		return nil, fmt.Errorf("plugin-claim public key not configured: %w", err)
	}
	if !ed25519.Verify(pubKey, []byte(payloadBase64), signature) {
		return nil, &PluginClaimValidationError{Reason: "Ed25519 signature verification failed"}
	}

	// Audience check via the SaaS Plugin path validator (ADR-050 §3
	// accept-list contract). Tokens with `aud=axonflow.saas.full` also
	// pass here per the accept list — the SaaS Full quadrant ships later.
	if err := ValidateForSaasPluginPath(&payload); err != nil {
		return nil, err
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

// pluginClaimPublicKeyEnv is the verifier-only env var. When set, the agent
// middleware uses it to verify token signatures WITHOUT touching the signing
// seed — so a runtime compromise of the agent's verifier path cannot forge
// new tokens. Operators set ONLY this env var on agent containers; only the
// axonflow-billing service holds AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY.
//
// Format: base64-encoded 32-byte Ed25519 public key (one line, no padding
// added — std encoding is fine since 32 bytes always pads cleanly).
const pluginClaimPublicKeyEnv = "AXONFLOW_PLUGIN_CLAIMED_PUBLIC_KEY"

// getPluginClaimPublicKey loads the Ed25519 public verification key used to
// validate plugin-claim license tokens.
//
// Resolution order (first non-empty wins):
//
//  1. AXONFLOW_PLUGIN_CLAIMED_PUBLIC_KEY — base64 32-byte pubkey, verifier-only
//  2. AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY (seed) — derive pubkey from seed
//
// (1) is the production posture for agent / verifier deployments per
// ADR-049: a runtime compromise of the agent cannot issue forged tokens
// because the seed is never present. Only axonflow-billing receives the
// seed; everywhere else gets the pubkey alone.
//
// (2) is the dev / single-process / backward-compatibility path: when no
// pubkey env is set, fall back to deriving from the seed (which still
// requires the seed env var to be present, so a verifier-only deployment
// without either set fails closed at boot).
func getPluginClaimPublicKey() (ed25519.PublicKey, error) {
	if b64 := os.Getenv(pluginClaimPublicKeyEnv); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 in %s: %w", pluginClaimPublicKeyEnv, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key length in %s: got %d bytes, want %d",
				pluginClaimPublicKeyEnv, len(raw), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(raw), nil
	}

	priv, err := getSigningKey(TierPro)
	if err != nil {
		return nil, fmt.Errorf("no %s set and signing seed unavailable: %w", pluginClaimPublicKeyEnv, err)
	}
	return priv.Public().(ed25519.PublicKey), nil
}
