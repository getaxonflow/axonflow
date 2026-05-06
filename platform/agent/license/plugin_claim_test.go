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
// encodes the seed, sets the env var so getSigningKey(TierPro)
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
// Tier helpers — IsSaasPluginTier, IsPaidTier, tierRank for SaaS Plugin tiers
// =============================================================================

func TestIsSaasPluginTier(t *testing.T) {
	cases := map[Tier]bool{
		TierPro:            true,
		TierPremium:        true,
		TierFree:           false, // Free is the absence-of-token baseline, never carried in a token
		TierEvaluation:     false,
		TierProfessional:   false,
		TierEnterprise:     false,
		TierEnterprisePlus: false,
		TierCommunity:      false,
	}
	for tier, want := range cases {
		got := IsSaasPluginTier(tier)
		if got != want {
			t.Errorf("IsSaasPluginTier(%q) = %v, want %v", tier, got, want)
		}
		// IsPluginTier is the legacy alias — same answer.
		if got2 := IsPluginTier(tier); got2 != want {
			t.Errorf("IsPluginTier(%q) (legacy alias) = %v, want %v", tier, got2, want)
		}
	}
}

func TestIsPaidTier_SaasPluginNotIncluded(t *testing.T) {
	// Critical: SaaS Plugin is a SEPARATE product line. Existing callers
	// that gate features (LLM matrix, MAP plans, EU AI Act templates) on
	// IsPaidTier must NOT see Pro/Premium as a "paid tier" — those features
	// remain self-hosted-only.
	if IsPaidTier(TierPro) {
		t.Error("SaaS Plugin Pro must NOT be classified as a self-hosted paid tier")
	}
	if IsPaidTier(TierPremium) {
		t.Error("SaaS Plugin Premium must NOT be classified as a self-hosted paid tier")
	}
	// Sanity: existing tiers still work as expected
	if !IsPaidTier(TierProfessional) {
		t.Error("Professional should remain a paid tier")
	}
}

func TestTierRank_SaasPluginReturnsSentinel(t *testing.T) {
	// SaaS Plugin tiers return -1 (sentinel) so any rank-based comparison
	// against them yields predictable "not comparable" results.
	if got := tierRank(TierPro); got != -1 {
		t.Errorf("tierRank(TierPro) = %d, want -1 sentinel", got)
	}
	if got := tierRank(TierPremium); got != -1 {
		t.Errorf("tierRank(TierPremium) = %d, want -1 sentinel", got)
	}
	if got := tierRank(TierFree); got != -1 {
		t.Errorf("tierRank(TierFree) = %d, want -1 sentinel", got)
	}
}

// =============================================================================
// GeneratePluginClaimLicense — input validation
// =============================================================================

func TestGeneratePluginClaimLicense_RequiresTenantID(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	_, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		ClaimedByEmail: "alice@example.com",
		Tier:           TierPro,
	})
	if err == nil || !strings.Contains(err.Error(), "TenantID") {
		t.Errorf("expected TenantID-required error, got %v", err)
	}
}

func TestGeneratePluginClaimLicense_RequiresEmail(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	_, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID: "cs_abc",
		Tier:     TierPro,
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
	if err == nil || !strings.Contains(err.Error(), "invalid SaaS Plugin tier") {
		t.Errorf("expected invalid-tier error, got %v", err)
	}
}

func TestGeneratePluginClaimLicense_RejectsNegativeValidityDays(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	_, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_abc",
		ClaimedByEmail: "alice@example.com",
		Tier:           TierPro,
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
		// Tier omitted — should default to TierPro
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	payload, err := ValidatePluginClaimToken(tok)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if payload.Tier != string(TierPro) {
		t.Errorf("default tier should be Pro, got %q", payload.Tier)
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
		Tier:           TierPro,
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
		t.Errorf("aud mismatch: got %q want %q", payload.Aud, ExpectedPluginClaimAudience)
	}
	if payload.Aud != AudSaaSPlugin {
		t.Errorf("aud should be the canonical AudSaaSPlugin (axonflow.saas.plugin), got %q", payload.Aud)
	}
	// `origin` claim deprecated per ADR-050 §2 — the third aud segment now
	// carries the scope. New tokens MUST NOT set origin.
	if payload.Origin != "" {
		t.Errorf("origin should be empty on new tokens (deprecated per ADR-050 §2), got %q", payload.Origin)
	}
	if payload.Tier != string(TierPro) {
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
		Tier:           TierPro,
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
		Tier:           TierPro,
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
	priv, _ := getSigningKey(TierPro)
	payload := ServiceLicensePayload{
		Tier:      string(TierPro),
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

// TestValidatePluginClaimToken_RejectsCrossQuadrantAud locks in the
// ADR-050 §3 accept-list contract for the SaaS Plugin path: a token with
// `aud=axonflow.self_hosted.full` (a self-hosted Enterprise license
// pasted as X-License-Token by mistake) MUST be rejected with a clear
// "wrong aud" error. Replaces the deprecated `RejectsBadOrigin` test —
// `origin` was dropped per ADR-050 §2 in favor of the third aud segment.
func TestValidatePluginClaimToken_RejectsCrossQuadrantAud(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	priv, _ := getSigningKey(TierPro)
	payload := ServiceLicensePayload{
		Tier:      string(TierPro),
		OrgID:     "community-saas",
		IssuedAt:  "20260504",
		ExpiresAt: "21260504",
		TenantID:  "cs_abc",
		Aud:       AudSelfHostedFull, // <-- wrong quadrant for SaaS Plugin path
		JTI:       "test-jti",
		KID:       "test-kid",
		Email:     "x@y.com",
	}
	pj, _ := jsonMarshal(payload)
	pb := base64.RawURLEncoding.EncodeToString(pj)
	sig := ed25519.Sign(priv, []byte(pb))
	sb := base64.RawURLEncoding.EncodeToString(sig)
	tok := "AXON-" + pb + "." + sb

	_, err := ValidatePluginClaimToken(tok)
	if err == nil {
		t.Fatal("token with cross-quadrant aud must not validate as SaaS Plugin")
	}
	var pcvErr *PluginClaimValidationError
	if !errors.As(err, &pcvErr) {
		t.Errorf("expected PluginClaimValidationError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "aud") {
		t.Errorf("error should mention aud: %v", err)
	}
}

func TestValidatePluginClaimToken_RejectsNonPluginTier(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	priv, _ := getSigningKey(TierPro)
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
		t.Fatal("token with non-SaaS-Plugin tier must not validate as a SaaS Plugin token")
	}
	var pcvErr *PluginClaimValidationError
	if !errors.As(err, &pcvErr) {
		t.Errorf("expected PluginClaimValidationError, got %T: %v", err, err)
	}
}

func TestValidatePluginClaimToken_RejectsExpired(t *testing.T) {
	generateTestPluginClaimSigningKey(t)
	priv, _ := getSigningKey(TierPro)
	payload := ServiceLicensePayload{
		Tier:      string(TierPro),
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
	priv, _ := getSigningKey(TierPro)
	payload := ServiceLicensePayload{
		Tier:      string(TierPro),
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
	priv, _ := getSigningKey(TierPro)
	payload := ServiceLicensePayload{
		Tier:      string(TierPro),
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
// Cross-context: a self-hosted enterprise license must NOT validate as a
// SaaS Plugin token.
// =============================================================================

func TestValidatePluginClaimToken_RejectsEnterpriseLicense(t *testing.T) {
	// Set up the enterprise signing key so we can issue a real enterprise token
	_, ePriv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("AXONFLOW_ENT_SIGNING_KEY", base64.StdEncoding.EncodeToString(ePriv.Seed()))
	// Also set the SaaS Plugin key so the test can derive the public key
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

	// Try to validate as a SaaS Plugin token — must be rejected.
	// (The enterprise token has tier=Enterprise which fails IsSaasPluginTier
	// AND has no aud/origin claims set.)
	_, err = ValidatePluginClaimToken(entTok)
	if err == nil {
		t.Fatal("enterprise license must NOT validate as a SaaS Plugin token")
	}
	t.Logf("correctly rejected enterprise token: %v", err)
}

// =============================================================================
// Pubkey-only verifier secret split (GAP-1)
//
// Production posture per ADR-049: agent / verifier deployments hold ONLY the
// pubkey, not the seed. axonflow-billing is the only service holding the
// seed. These tests prove:
//
//   1. When AXONFLOW_PLUGIN_CLAIMED_PUBLIC_KEY is set, the verifier accepts
//      tokens signed by the matching seed — without the seed env var being
//      set in the verifier's environment.
//   2. A verifier configured with ONLY the pubkey CANNOT issue tokens (it
//      lacks the seed needed for signing).
//   3. A pubkey that does NOT match the signer is rejected.
//   4. An invalid base64 in AXONFLOW_PLUGIN_CLAIMED_PUBLIC_KEY surfaces an
//      explicit error rather than silently falling back to the seed.
//   5. A wrong-length pubkey (e.g. truncated) is rejected at boot.
// =============================================================================

func TestVerifier_AcceptsTokenWithPubkeyOnly_NoSeedAvailable(t *testing.T) {
	// 1. Issuer-only environment: generate keypair, set the seed, issue a
	//    token, capture the pubkey for the verifier env.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", base64.StdEncoding.EncodeToString(priv.Seed()))
	tok, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_pubkey_only_test",
		ClaimedByEmail: "verifier@example.com",
		Tier:           TierPro,
		ValidityDays:   30,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 2. Verifier-only environment: REPLACE the seed env var with empty,
	//    set ONLY the pubkey. This simulates an agent container that has
	//    been configured per ADR-049 production posture.
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", "")
	t.Setenv(pluginClaimPublicKeyEnv, base64.StdEncoding.EncodeToString(pub))

	// 3. Verifier should accept the token using the pubkey alone.
	payload, err := ValidatePluginClaimToken(tok)
	if err != nil {
		t.Fatalf("Validate with pubkey-only verifier failed: %v", err)
	}
	if payload.TenantID != "cs_pubkey_only_test" {
		t.Errorf("payload tenant_id mismatch: got %q", payload.TenantID)
	}
}

func TestVerifier_PubkeyOnly_CannotSign(t *testing.T) {
	// Pubkey-only verifier environment — no seed.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", "")
	t.Setenv(pluginClaimPublicKeyEnv, base64.StdEncoding.EncodeToString(pub))

	// Attempting to issue must fail because the seed is required for signing.
	_, err = GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_test",
		ClaimedByEmail: "x@y.com",
		Tier:           TierPro,
		ValidityDays:   30,
	})
	if err == nil {
		t.Fatal("Generate should have failed without signing seed — this means the verifier has more privilege than intended")
	}
}

func TestVerifier_PubkeyMismatchRejected(t *testing.T) {
	// Issuer with one keypair
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", base64.StdEncoding.EncodeToString(priv.Seed()))
	tok, err := GeneratePluginClaimLicense(PluginClaimLicenseInput{
		TenantID:       "cs_mismatch",
		ClaimedByEmail: "alice@example.com",
		Tier:           TierPro,
		ValidityDays:   30,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verifier with a DIFFERENT keypair's pubkey
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey wrong: %v", err)
	}
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", "")
	t.Setenv(pluginClaimPublicKeyEnv, base64.StdEncoding.EncodeToString(wrongPub))

	if _, err := ValidatePluginClaimToken(tok); err == nil {
		t.Fatal("verifier with wrong pubkey must reject the token")
	}
}

func TestPubkeyEnv_InvalidBase64SurfacesError(t *testing.T) {
	t.Setenv(pluginClaimPublicKeyEnv, "!!!not base64!!!")
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", "")
	if _, err := getPluginClaimPublicKey(); err == nil {
		t.Fatal("invalid base64 in pubkey env should error, not silently fall back to seed")
	} else if !strings.Contains(err.Error(), pluginClaimPublicKeyEnv) {
		t.Errorf("error should reference the env var name, got: %v", err)
	}
}

func TestPubkeyEnv_WrongLengthRejected(t *testing.T) {
	// 16-byte string base64-encoded — not a valid Ed25519 pubkey (32 bytes)
	t.Setenv(pluginClaimPublicKeyEnv, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", "")
	if _, err := getPluginClaimPublicKey(); err == nil {
		t.Fatal("wrong-length pubkey should be rejected at boot")
	} else if !strings.Contains(err.Error(), "length") {
		t.Errorf("error should mention length: %v", err)
	}
}

func TestPubkeyEnv_FallbackToSeedWhenUnset(t *testing.T) {
	// No pubkey env, but seed set — should fall back to derive-from-seed
	// (backward compatibility for v7.7.0-and-earlier deployments that haven't
	// migrated to the pubkey-only posture yet).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	t.Setenv(pluginClaimPublicKeyEnv, "")
	t.Setenv("AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY", base64.StdEncoding.EncodeToString(priv.Seed()))

	pub, err := getPluginClaimPublicKey()
	if err != nil {
		t.Fatalf("seed-fallback should succeed when seed env is set: %v", err)
	}
	if !pub.Equal(priv.Public()) {
		t.Error("derived pubkey does not match expected pubkey from seed")
	}
}

// =============================================================================
// Helpers
// =============================================================================

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
