// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Mirrored at ee/platform/agent/license/fincrime_grant_ee_test.go. This copy is
// untagged so Community and Enterprise builds exercise the same negatives.

package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func finCrimeGrantTestKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	evalSeed := make([]byte, ed25519.SeedSize)
	entSeed := make([]byte, ed25519.SeedSize)
	for i := range evalSeed {
		evalSeed[i] = byte(i + 1)
		entSeed[i] = byte(i + 65)
	}
	evalPriv := ed25519.NewKeyFromSeed(evalSeed)
	entPriv := ed25519.NewKeyFromSeed(entSeed)
	restore := OverridePublicKeysForTest(evalPriv.Public().(ed25519.PublicKey), entPriv.Public().(ed25519.PublicKey))
	t.Cleanup(restore)
	return evalPriv, entPriv
}

func validFinCrimePayload(tier Tier, deploymentID, tenantID string, allowance int64) ServiceLicensePayload {
	grant, err := newFinCrimeSelfHostedGrant(deploymentID, tenantID, allowance)
	if err != nil {
		panic(err)
	}
	return ServiceLicensePayload{
		Tier:                       string(tier),
		DeploymentID:               deploymentID,
		OrgID:                      deploymentID,
		ServiceName:                "platform",
		ServiceType:                "backend-service",
		Permissions:                []string{"fincrime:score"},
		IssuedAt:                   "20261106",
		ExpiresAt:                  "20991231",
		Aud:                        AudSelfHostedFull,
		SelfHostedCapabilityGrants: []SelfHostedCapabilityGrant{grant},
	}
}

func requireLicenseRejected(t *testing.T, key, contains string) {
	t.Helper()
	result, err := ValidateLicense(context.Background(), key)
	if err != nil {
		if !strings.Contains(err.Error(), contains) {
			t.Fatalf("rejection %q does not contain %q", err, contains)
		}
		return
	}
	if result == nil || result.Tier != TierCommunity {
		t.Fatalf("license was not refused: result=%+v err=%v", result, err)
	}
	if !strings.Contains(result.Message, contains) {
		t.Fatalf("community fallback %q does not contain %q", result.Message, contains)
	}
}

func TestFinCrimeGrantValidatesAndResolvesOnlyForItsSignedTenant(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	payload := validFinCrimePayload(TierEnterprise, "deployment-a", "tenant-a", 750)

	result, err := ValidateLicense(context.Background(), SignPayloadForTest(entPriv, payload))
	if err != nil || result == nil || !result.Valid {
		t.Fatalf("valid signed FinCrime grant rejected: result=%+v err=%v", result, err)
	}
	if got, ok := result.FinCrimeScoreRequestAllowance("tenant-a"); !ok || got != 750 {
		t.Fatalf("allowance = %d, %v; want 750, true", got, ok)
	}
	if got, ok := result.FinCrimeScoreRequestAllowance("tenant-b"); ok || got != 0 {
		t.Fatalf("foreign-tenant allowance = %d, %v; want 0, false", got, ok)
	}
}

func TestLegacyLicenseWithoutCapabilityGrantRemainsValid(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	payload := ServiceLicensePayload{
		Tier:      string(TierEnterprise),
		OrgID:     "legacy-deployment",
		ExpiresAt: "20991231",
	}
	result, err := ValidateLicense(context.Background(), SignPayloadForTest(entPriv, payload))
	if err != nil || result == nil || !result.Valid || result.Tier != TierEnterprise {
		t.Fatalf("legacy license rejected: result=%+v err=%v", result, err)
	}
	if got, ok := result.FinCrimeScoreRequestAllowance("any-tenant"); ok || got != 0 {
		t.Fatalf("legacy license acquired FinCrime allowance = %d, %v", got, ok)
	}
}

func TestExpiredFinCrimeGrantCannotResolveAllowance(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	payload := validFinCrimePayload(TierEnterprise, "deployment-a", "tenant-a", 750)
	payload.ExpiresAt = "20200101"

	result, err := ValidateLicense(context.Background(), SignPayloadForTest(entPriv, payload))
	if err != nil || result == nil {
		t.Fatalf("expired license validation returned result=%+v err=%v", result, err)
	}
	if result.Valid {
		t.Fatalf("expired license remained valid: %+v", result)
	}
	if got, ok := result.FinCrimeScoreRequestAllowance("tenant-a"); ok || got != 0 {
		t.Fatalf("expired license allowance = %d, %v; want 0, false", got, ok)
	}
}

func TestEvaluationCannotCarryFinCrimeGrant(t *testing.T) {
	evalPriv, _ := finCrimeGrantTestKeys(t)
	payload := validFinCrimePayload(TierEvaluation, "trial-deployment", "trial-tenant", 10)
	requireLicenseRejected(t, SignPayloadForTest(evalPriv, payload), "not eligible")
}

func TestFinCrimeGrantFailsClosedOnUnknownOrAmbiguousClaims(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	tests := []struct {
		name string
		edit func(*ServiceLicensePayload)
		want string
	}{
		{"unknown grant version", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Version = "2.0" }, "unknown self-hosted capability grant version"},
		{"unknown module", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Module = "payments" }, "unknown self-hosted capability module"},
		{"unknown capability", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Capabilities[0].ID = "fincrime.future" }, "unknown self-hosted FinCrime capability"},
		{"unknown capability version", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Capabilities[0].Version = "2.0" }, "unknown version"},
		{"duplicate capability", func(p *ServiceLicensePayload) {
			p.SelfHostedCapabilityGrants[0].Capabilities = append(p.SelfHostedCapabilityGrants[0].Capabilities, p.SelfHostedCapabilityGrants[0].Capabilities[0])
		}, "duplicate self-hosted FinCrime capability"},
		{"missing policy pack", func(p *ServiceLicensePayload) {
			p.SelfHostedCapabilityGrants[0].Capabilities = p.SelfHostedCapabilityGrants[0].Capabilities[1:]
		}, "missing \"fincrime.policy_pack\""},
		{"missing scorer", func(p *ServiceLicensePayload) {
			p.SelfHostedCapabilityGrants[0].Capabilities = p.SelfHostedCapabilityGrants[0].Capabilities[:1]
		}, "missing \"fincrime.risk_scoring\""},
		{"unknown limit", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Limits[0].ID = "fincrime.tokens" }, "unknown self-hosted FinCrime limit"},
		{"unknown period", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Limits[0].Period = "day" }, "unknown self-hosted FinCrime score-request period"},
		{"zero allowance", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Limits[0].Allowance = 0 }, "finite and positive"},
		{"negative allowance", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Limits[0].Allowance = -1 }, "finite and positive"},
		{"wrong deployment", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].DeploymentID = "deployment-b" }, "deployment scope does not match"},
		{"blank tenant", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].TenantID = " " }, "invalid tenant scope"},
		{"duplicate tenant grant", func(p *ServiceLicensePayload) {
			p.SelfHostedCapabilityGrants = append(p.SelfHostedCapabilityGrants, p.SelfHostedCapabilityGrants[0])
		}, "duplicate self-hosted capability grant"},
		{"legacy outer deployment", func(p *ServiceLicensePayload) { p.DeploymentID = "" }, "explicit canonical deployment_id"},
		{"saas audience", func(p *ServiceLicensePayload) { p.Aud = AudSaaSFull }, "self-hosted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := validFinCrimePayload(TierEnterprise, "deployment-a", "tenant-a", 750)
			test.edit(&payload)
			requireLicenseRejected(t, SignPayloadForTest(entPriv, payload), test.want)
		})
	}
}

func TestTamperingWithSignedScoreAllowanceInvalidatesTheSignature(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	key := SignPayloadForTest(entPriv, validFinCrimePayload(TierEnterprise, "deployment-a", "tenant-a", 750))
	rest := strings.TrimPrefix(key, "AXON-")
	dot := strings.LastIndex(rest, ".")
	raw, err := base64.RawURLEncoding.DecodeString(rest[:dot])
	if err != nil {
		t.Fatal(err)
	}
	var payload ServiceLicensePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload.SelfHostedCapabilityGrants[0].Limits[0].Allowance = 751
	tampered, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	tamperedKey := "AXON-" + base64.RawURLEncoding.EncodeToString(tampered) + "." + rest[dot+1:]
	requireLicenseRejected(t, tamperedKey, "signature")
}
