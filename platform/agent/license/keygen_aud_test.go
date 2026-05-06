//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestGenerateServiceLicenseKeyWithAud_Default verifies that the
// backward-compat wrapper (GenerateServiceLicenseKey) emits a token
// carrying `axonflow.self_hosted.full` — the locked default.
func TestGenerateServiceLicenseKeyWithAud_Default(t *testing.T) {
	t.Setenv("AXONFLOW_ENT_SIGNING_KEY", testEntSeed())

	key, err := GenerateServiceLicenseKey(
		TierEnterprise, "acme", "platform", "backend-service",
		[]string{"mcp:*:*"}, 365)
	if err != nil {
		t.Fatalf("GenerateServiceLicenseKey: %v", err)
	}
	payload := parsePayloadForTest(t, key)
	if payload.Aud != AudSelfHostedFull {
		t.Errorf("default aud should be %q, got %q", AudSelfHostedFull, payload.Aud)
	}
}

// TestGenerateServiceLicenseKeyWithAud_PluginOverride verifies that the
// future Plugin In-VPC eval issuance path produces a token with
// `axonflow.self_hosted.plugin`.
func TestGenerateServiceLicenseKeyWithAud_PluginOverride(t *testing.T) {
	t.Setenv("AXONFLOW_ENT_SIGNING_KEY", testEntSeed())

	key, err := GenerateServiceLicenseKeyWithAud(
		TierEnterprise, "acme", "platform", "backend-service",
		[]string{"mcp:*:*"}, 365, AudSelfHostedPlugin)
	if err != nil {
		t.Fatalf("GenerateServiceLicenseKeyWithAud: %v", err)
	}
	payload := parsePayloadForTest(t, key)
	if payload.Aud != AudSelfHostedPlugin {
		t.Errorf("aud override should be honored, got %q", payload.Aud)
	}
}

// TestGenerateServiceLicenseKeyWithAud_SDKOverride verifies the future
// SDK product path.
func TestGenerateServiceLicenseKeyWithAud_SDKOverride(t *testing.T) {
	t.Setenv("AXONFLOW_ENT_SIGNING_KEY", testEntSeed())

	key, err := GenerateServiceLicenseKeyWithAud(
		TierEnterprise, "acme", "platform", "backend-service",
		[]string{"mcp:*:*"}, 365, AudSelfHostedSDK)
	if err != nil {
		t.Fatalf("GenerateServiceLicenseKeyWithAud: %v", err)
	}
	payload := parsePayloadForTest(t, key)
	if payload.Aud != AudSelfHostedSDK {
		t.Errorf("aud override should be honored, got %q", payload.Aud)
	}
}

// TestGenerateServiceLicenseKeyWithAud_RejectsCrossQuadrantAud verifies
// that an attempt to issue a self-hosted license with a SaaS aud is
// rejected — SaaS Plugin tokens are issued by GeneratePluginClaimLicense
// with a different signing key.
func TestGenerateServiceLicenseKeyWithAud_RejectsCrossQuadrantAud(t *testing.T) {
	t.Setenv("AXONFLOW_ENT_SIGNING_KEY", testEntSeed())

	cases := []string{AudSaaSPlugin, AudSaaSSDK, AudSaaSFull, "axonflow.unknown.something", "anything-else"}
	for _, badAud := range cases {
		t.Run(badAud, func(t *testing.T) {
			_, err := GenerateServiceLicenseKeyWithAud(
				TierEnterprise, "acme", "platform", "backend-service",
				[]string{"mcp:*:*"}, 365, badAud)
			if err == nil {
				t.Fatalf("expected error for cross-quadrant aud %q, got nil", badAud)
			}
			if !strings.Contains(err.Error(), "invalid aud") {
				t.Errorf("error should mention invalid aud, got: %v", err)
			}
		})
	}
}

// TestGenerateServiceLicenseKeyWithAud_EmptyAudFallsBack verifies that
// passing aud="" preserves the backward-compat behavior — the resulting
// token carries `axonflow.self_hosted.full`.
func TestGenerateServiceLicenseKeyWithAud_EmptyAudFallsBack(t *testing.T) {
	t.Setenv("AXONFLOW_ENT_SIGNING_KEY", testEntSeed())

	key, err := GenerateServiceLicenseKeyWithAud(
		TierEnterprise, "acme", "platform", "backend-service",
		[]string{"mcp:*:*"}, 365, "")
	if err != nil {
		t.Fatalf("GenerateServiceLicenseKeyWithAud: %v", err)
	}
	payload := parsePayloadForTest(t, key)
	if payload.Aud != AudSelfHostedFull {
		t.Errorf("empty aud should fall back to %q, got %q", AudSelfHostedFull, payload.Aud)
	}
}

// =============================================================================
// Test fixtures (private to this file)
// =============================================================================

// testEntSeed returns a base64-encoded 32-byte Ed25519 seed for the
// enterprise signing key. The seed is fixed so tests don't depend on
// time-of-day entropy; the actual public-key verification path runs
// against the production-burned-in key, so these tests bypass Validate
// and inspect the payload directly via parsePayloadForTest.
func testEntSeed() string {
	// Exactly 32 bytes encoded — needed for ed25519.NewKeyFromSeed.
	const seed32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 'A' bytes
	return base64.StdEncoding.EncodeToString([]byte(seed32))
}

// parsePayloadForTest peels the payload base64 segment off the token
// and unmarshals it. Bypasses signature verification — these tests
// exercise the issuance path's aud handling, not the signer/verifier
// loop (covered separately by validation_test.go).
func parsePayloadForTest(t *testing.T, key string) *ServiceLicensePayload {
	t.Helper()
	if !strings.HasPrefix(key, "AXON-") {
		t.Fatalf("expected AXON- prefix, got: %s", key[:min(10, len(key))])
	}
	rest := key[5:]
	dot := strings.LastIndex(rest, ".")
	if dot < 1 {
		t.Fatalf("expected . separator")
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest[:dot])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload ServiceLicensePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return &payload
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
