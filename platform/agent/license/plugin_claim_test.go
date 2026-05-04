//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// generateTestPluginClaimSigningKey creates a fresh Ed25519 keypair, base64-
// encodes the seed, sets the env var so getSigningKey(TierPluginClaimed)
// returns it, and registers a t.Cleanup to unset it. Returns the
// base64-encoded seed for any caller that needs to inspect it.
func generateTestPluginClaimSigningKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	seedB64 := base64.StdEncoding.EncodeToString(priv.Seed())
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", seedB64)
	return seedB64
}

// =============================================================================
// Tier helpers — IsPluginTier, IsPaidTier, tierRank for plugin-claim
// =============================================================================

func TestIsPluginTier(t *testing.T) {
	cases := map[Tier]bool{
		TierPluginClaimed:      true,
		TierPluginSubscription: true,
		TierEvaluation:         false,
		TierProfessional:       false,
		TierEnterprise:         false,
		TierEnterprisePlus:     false,
		TierCommunity:          false,
	}
	for tier, want := range cases {
		got := IsPluginTier(tier)
		if got != want {
			t.Errorf("IsPluginTier(%q) = %v, want %v", tier, got, want)
		}
	}
}

func TestIsPaidTier_PluginClaimedNotIncluded(t *testing.T) {
	// Critical: plugin-claim is a SEPARATE product line. Existing callers
	// that gate features (LLM matrix, MAP plans, EU AI Act templates) on
	// IsPaidTier must NOT see plugin-claim as a "paid tier" — those features
	// remain self-hosted-only.
	if IsPaidTier(TierPluginClaimed) {
		t.Error("plugin-claim must NOT be classified as a self-hosted paid tier")
	}
	if IsPaidTier(TierPluginSubscription) {
		t.Error("plugin-subscription must NOT be classified as a self-hosted paid tier")
	}
	// Sanity: existing tiers still work as expected
	if !IsPaidTier(TierProfessional) {
		t.Error("Professional should remain a paid tier")
	}
}

func TestTierRank_PluginClaimReturnsSentinel(t *testing.T) {
	// Plugin-claim tiers return -1 (sentinel) so any rank-based comparison
	// against them yields predictable "not comparable" results.
	if got := tierRank(TierPluginClaimed); got != -1 {
		t.Errorf("tierRank(TierPluginClaimed) = %d, want -1 sentinel", got)
	}
	if got := tierRank(TierPluginSubscription); got != -1 {
		t.Errorf("tierRank(TierPluginSubscription) = %d, want -1 sentinel", got)
	}
}

// =============================================================================
// GeneratePluginClaimLicense — input validation
// =============================================================================

func TestGeneratePluginClaimLicense_RequiresTenantID(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	_, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		ClaimedByEmail: "alice@example.com",
		Tier:           TierPluginClaimed,
	})
	if err == nil || !strings.Contains(err.Error(), "TenantID") {
		t.Errorf("expected TenantID-required error, got %v", err)
	}
}

func TestGeneratePluginClaimLicense_RequiresEmail(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	_, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID: "cs_abc",
		Tier:     TierPluginClaimed,
	})
	if err == nil || !strings.Contains(err.Error(), "ClaimedByEmail") {
		t.Errorf("expected ClaimedByEmail-required error, got %v", err)
	}
}

func TestGeneratePluginClaimLicense_RejectsInvalidTier(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	_, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_abc",
		ClaimedByEmail: "alice@example.com",
		Tier:           TierEnterprise, // wrong tier — must be plugin-*
	})
	if err == nil || !strings.Contains(err.Error(), "invalid plugin-claim tier") {
		t.Errorf("expected invalid-tier error, got %v", err)
	}
}

func TestGeneratePluginClaimLicense_RejectsNegativeValidityDays(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	_, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_abc",
		ClaimedByEmail: "alice@example.com",
		Tier:           TierPluginClaimed,
		ValidityDays:   -1,
	})
	if err == nil || !strings.Contains(err.Error(), "ValidityDays") {
		t.Errorf("expected ValidityDays error, got %v", err)
	}
}

func TestGeneratePluginClaimLicense_DefaultsTierToPluginClaimed(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	tok, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_abc",
		ClaimedByEmail: "alice@example.com",
		// Tier omitted — should default to TierPluginClaimed
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	payload, err := ValidatePluginClaimToken(tok)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if payload.Tier != string(TierPluginClaimed) {
		t.Errorf("default tier should be plugin-claimed, got %q", payload.Tier)
	}
}

// =============================================================================
// Generate + Validate roundtrip — happy path
// =============================================================================

func TestPluginClaimLicense_GenerateAndValidate_Roundtrip(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	tok, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_abc123",
		ClaimedByEmail: "alice@example.com",
		Tier:           TierPluginClaimed,
		ValidityDays:   365,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if !strings.HasPrefix(tok, "AXON-") {
		t.Errorf("token should start with AXON-, got: %s", tok[:30])
	}
	if !strings.Contains(tok, ".") {
		t.Errorf("token should contain '.' separator")
	}

	payload, err := ValidatePluginClaimToken(tok)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if payload.TenantID != "cs_abc123" {
		t.Errorf("tenant_id mismatch: got %q", payload.TenantID)
	}
	if payload.Email != "alice@example.com" {
		t.Errorf("email mismatch: got %q", payload.Email)
	}
	if payload.Aud != ExpectedPluginClaimAudience {
		t.Errorf("aud mismatch: got %q", payload.Aud)
	}
	if payload.Origin != ExpectedPluginClaimOrigin {
		t.Errorf("origin mismatch: got %q", payload.Origin)
	}
	if payload.Tier != string(TierPluginClaimed) {
		t.Errorf("tier mismatch: got %q", payload.Tier)
	}
	if payload.JTI == "" {
		t.Error("jti should be auto-generated")
	}
	if payload.KID == "" {
		t.Error("kid should default")
	}
	if payload.KID != defaultPluginClaimKID {
		t.Errorf("kid should default to %q, got %q", defaultPluginClaimKID, payload.KID)
	}
}

func TestPluginClaimLicense_CustomJTIAndKIDPreserved(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	customJTI := "01H8ZF3CUSTOM123456"
	customKID := "v4-2026-06-01"
	tok, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_abc",
		ClaimedByEmail: "x@y.com",
		Tier:           TierPluginClaimed,
		ValidityDays:   30,
		JTI:            customJTI,
		KID:            customKID,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	payload, err := ValidatePluginClaimToken(tok)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if payload.JTI != customJTI {
		t.Errorf("jti not preserved: got %q want %q", payload.JTI, customJTI)
	}
	if payload.KID != customKID {
		t.Errorf("kid not preserved: got %q want %q", payload.KID, customKID)
	}
}

// =============================================================================
// Validate — security-critical rejections
// =============================================================================

func TestValidatePluginClaimToken_RejectsBadSignature(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	tok, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_abc",
		ClaimedByEmail: "x@y.com",
		Tier:           TierPluginClaimed,
		ValidityDays:   30,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	// Tamper: flip the last character of the signature
	tampered := tok[:len(tok)-1] + "A"
	if tampered[:len(tampered)-1] == tok[:len(tok)-1] && tampered[len(tampered)-1:] == tok[len(tok)-1:] {
		t.Skip("tamper produced same character — try again")
	}
	_, err = ValidatePluginClaimToken(tampered)
	if err == nil {
		t.Error("tampered signature must not validate")
	}
	var pcvErr *PluginClaimValidationError
	if !errors.As(err, &pcvErr) {
		// Could be either a PluginClaimValidationError or a base64 decode error
		// depending on which character was flipped. Accept both.
		if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "encoding") {
			t.Errorf("expected signature or encoding error, got: %v", err)
		}
	}
}

func TestValidatePluginClaimToken_RejectsBadAudience(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	// Build a payload with wrong aud + sign + try to validate
	priv, _ := getSigningKey(TierPluginClaimed)
	payload := ServiceLicensePayload{
		Tier:      string(TierPluginClaimed),
		OrgID:     "community-saas",
		IssuedAt:  "20260504",
		ExpiresAt: "21260504",
		TenantID:  "cs_abc",
		Aud:       "wrong_audience", // <-- malicious / accidental
		JTI:       "test-jti",
		KID:       "test-kid",
		Origin:    ExpectedPluginClaimOrigin,
		Email:     "x@y.com",
	}
	pj, _ := jsonMarshal(payload)
	pb := base64.RawURLEncoding.EncodeToString(pj)
	sig := ed25519.Sign(priv, []byte(pb))
	sb := base64.RawURLEncoding.EncodeToString(sig)
	tok := "AXON-" + pb + "." + sb

	_, err := ValidatePluginClaimToken(tok)
	if err == nil {
		t.Fatal("token with wrong aud must not validate")
	}
	var pcvErr *PluginClaimValidationError
	if !errors.As(err, &pcvErr) {
		t.Errorf("expected PluginClaimValidationError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Errorf("error should mention aud: %v", err)
	}
}

func TestValidatePluginClaimToken_RejectsBadOrigin(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	priv, _ := getSigningKey(TierPluginClaimed)
	payload := ServiceLicensePayload{
		Tier:      string(TierPluginClaimed),
		OrgID:     "community-saas",
		IssuedAt:  "20260504",
		ExpiresAt: "21260504",
		TenantID:  "cs_abc",
		Aud:       ExpectedPluginClaimAudience,
		JTI:       "test-jti",
		KID:       "test-kid",
		Origin:    "self_hosted_enterprise", // <-- wrong context
		Email:     "x@y.com",
	}
	pj, _ := jsonMarshal(payload)
	pb := base64.RawURLEncoding.EncodeToString(pj)
	sig := ed25519.Sign(priv, []byte(pb))
	sb := base64.RawURLEncoding.EncodeToString(sig)
	tok := "AXON-" + pb + "." + sb

	_, err := ValidatePluginClaimToken(tok)
	if err == nil {
		t.Fatal("token with wrong origin must not validate")
	}
	var pcvErr *PluginClaimValidationError
	if !errors.As(err, &pcvErr) {
		t.Errorf("expected PluginClaimValidationError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "origin") {
		t.Errorf("error should mention origin: %v", err)
	}
}

func TestValidatePluginClaimToken_RejectsNonPluginTier(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	priv, _ := getSigningKey(TierPluginClaimed)
	payload := ServiceLicensePayload{
		Tier:      string(TierEnterprise), // <-- wrong tier
		OrgID:     "community-saas",
		IssuedAt:  "20260504",
		ExpiresAt: "21260504",
		TenantID:  "cs_abc",
		Aud:       ExpectedPluginClaimAudience,
		JTI:       "test-jti",
		KID:       "test-kid",
		Origin:    ExpectedPluginClaimOrigin,
		Email:     "x@y.com",
	}
	pj, _ := jsonMarshal(payload)
	pb := base64.RawURLEncoding.EncodeToString(pj)
	sig := ed25519.Sign(priv, []byte(pb))
	sb := base64.RawURLEncoding.EncodeToString(sig)
	tok := "AXON-" + pb + "." + sb

	_, err := ValidatePluginClaimToken(tok)
	if err == nil {
		t.Fatal("token with non-plugin tier must not validate as plugin-claim")
	}
	var pcvErr *PluginClaimValidationError
	if !errors.As(err, &pcvErr) {
		t.Errorf("expected PluginClaimValidationError, got %T: %v", err, err)
	}
}

func TestValidatePluginClaimToken_RejectsExpired(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	priv, _ := getSigningKey(TierPluginClaimed)
	payload := ServiceLicensePayload{
		Tier:      string(TierPluginClaimed),
		OrgID:     "community-saas",
		IssuedAt:  "20240101",
		ExpiresAt: "20240102", // 2 years in the past
		TenantID:  "cs_abc",
		Aud:       ExpectedPluginClaimAudience,
		JTI:       "test-jti",
		KID:       "test-kid",
		Origin:    ExpectedPluginClaimOrigin,
		Email:     "x@y.com",
	}
	pj, _ := jsonMarshal(payload)
	pb := base64.RawURLEncoding.EncodeToString(pj)
	sig := ed25519.Sign(priv, []byte(pb))
	sb := base64.RawURLEncoding.EncodeToString(sig)
	tok := "AXON-" + pb + "." + sb

	_, err := ValidatePluginClaimToken(tok)
	if err == nil {
		t.Fatal("expired token must not validate")
	}
	var pcvErr *PluginClaimValidationError
	if !errors.As(err, &pcvErr) {
		t.Errorf("expected PluginClaimValidationError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expired: %v", err)
	}
}

func TestValidatePluginClaimToken_RejectsMissingTenantID(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	priv, _ := getSigningKey(TierPluginClaimed)
	payload := ServiceLicensePayload{
		Tier:      string(TierPluginClaimed),
		OrgID:     "community-saas",
		IssuedAt:  "20260504",
		ExpiresAt: "21260504",
		// TenantID intentionally empty
		Aud:    ExpectedPluginClaimAudience,
		JTI:    "test-jti",
		KID:    "test-kid",
		Origin: ExpectedPluginClaimOrigin,
		Email:  "x@y.com",
	}
	pj, _ := jsonMarshal(payload)
	pb := base64.RawURLEncoding.EncodeToString(pj)
	sig := ed25519.Sign(priv, []byte(pb))
	sb := base64.RawURLEncoding.EncodeToString(sig)
	tok := "AXON-" + pb + "." + sb

	_, err := ValidatePluginClaimToken(tok)
	if err == nil {
		t.Fatal("token without tenant_id must not validate")
	}
}

func TestValidatePluginClaimToken_RejectsMissingJTI(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	priv, _ := getSigningKey(TierPluginClaimed)
	payload := ServiceLicensePayload{
		Tier:      string(TierPluginClaimed),
		OrgID:     "community-saas",
		IssuedAt:  "20260504",
		ExpiresAt: "21260504",
		TenantID:  "cs_abc",
		Aud:       ExpectedPluginClaimAudience,
		// JTI intentionally empty
		KID:    "test-kid",
		Origin: ExpectedPluginClaimOrigin,
		Email:  "x@y.com",
	}
	pj, _ := jsonMarshal(payload)
	pb := base64.RawURLEncoding.EncodeToString(pj)
	sig := ed25519.Sign(priv, []byte(pb))
	sb := base64.RawURLEncoding.EncodeToString(sig)
	tok := "AXON-" + pb + "." + sb

	_, err := ValidatePluginClaimToken(tok)
	if err == nil {
		t.Fatal("token without jti must not validate")
	}
}

func TestValidatePluginClaimToken_RejectsBadFormat(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	cases := map[string]string{
		"missing prefix":            "no-prefix-here.signature",
		"empty":                     "",
		"prefix only":               "AXON-",
		"no signature separator":    "AXON-payload-no-dot",
		"invalid base64 in payload": "AXON-!!!.signature",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ValidatePluginClaimToken(tok)
			if err == nil {
				t.Errorf("malformed token %q should not validate", name)
			}
		})
	}
}

// =============================================================================
// Cross-context: a self-hosted enterprise license must NOT validate as plugin-claim
// =============================================================================

func TestValidatePluginClaimToken_RejectsEnterpriseLicense(t *testing.T) {
	// Set up the enterprise signing key so we can issue a real enterprise token
	_, ePriv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("AXONFLOW_ENT_SIGNING_KEY", base64.StdEncoding.EncodeToString(ePriv.Seed()))
	// Also set the plugin-claim key so the test can derive the public key
	generateTestPluginClaimSigningKey(t)

	// Issue an enterprise license via the standard flow
	entTok, err := GenerateServiceLicenseKey(
		TierEnterprise, "acme",
		"trip-planner", "client-application",
		[]string{"mcp:*"},
		365)
	if err != nil {
		t.Fatalf("GenerateServiceLicenseKey: %v", err)
	}

	// Try to validate as a plugin-claim token — must be rejected.
	// (The enterprise token has tier=Enterprise which fails IsPluginTier
	// AND has no aud/origin claims set.)
	_, err = ValidatePluginClaimToken(entTok)
	if err == nil {
		t.Fatal("enterprise license must NOT validate as plugin-claim token")
	}
	t.Logf("correctly rejected enterprise token: %v", err)
}

// =============================================================================
// Helpers
// =============================================================================

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
