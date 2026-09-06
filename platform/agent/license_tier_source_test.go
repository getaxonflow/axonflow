// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"axonflow/platform/agent/license"
	sharedpolicy "axonflow/platform/shared/policy"
)

// This file pins #3709 row 1 from the side that can see both halves: the REAL
// validator in platform/agent/license and the connector ceiling in
// platform/shared/policy, joined by the source this package registers at init.
//
// It runs under both build tags (no constraint), so the community validator's
// "Valid Community result with a Message" and the enterprise validator's
// error are both driven through the same seam.

// sixConnectorsUnderCommunityMode is the fixture every case shares: a
// community-posture deployment - the posture whose run.go skips
// license.ValidateWithRetry, so nothing but this seam ever verifies the key -
// with six connectors configured, one over the Evaluation ceiling of five and
// four over the Community ceiling of two. The three tiers this file talks
// about therefore produce three DIFFERENT counts.
func sixConnectorsUnderCommunityMode(t *testing.T) sharedpolicy.DynamicPolicyConfig {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "community")
	cfg := sharedpolicy.DefaultDynamicPolicyConfig()
	cfg.EnabledConnectors = []string{"postgres", "mysql", "redis", "snowflake", "bigquery", "mongodb"}
	if n := len(cfg.EnabledConnectors); n <= cfg.MaxCustomPolicyConnectorsEvaluation || cfg.MaxCustomPolicyConnectorsEvaluation <= cfg.MaxCustomPolicyConnectorsCommunity {
		t.Fatalf("test bug: %d connectors against ceilings community=%d evaluation=%d cannot tell the tiers apart",
			n, cfg.MaxCustomPolicyConnectorsCommunity, cfg.MaxCustomPolicyConnectorsEvaluation)
	}
	return cfg
}

func testLicenceKeypair(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	t.Cleanup(license.OverridePublicKeysForTest(pub, pub))
	return priv
}

func licenceNamingTier(priv ed25519.PrivateKey, tier string, expires time.Time) string {
	return license.SignPayloadForTest(priv, license.ServiceLicensePayload{
		Tier:      tier,
		OrgID:     "wt3709-org",
		IssuedAt:  time.Now().UTC().Format("20060102"),
		ExpiresAt: expires.Format("20060102"),
	})
}

// TestVerifiedLicenceTierAnswersWithTheVerifiedRead pins the registered
// function's own contract: "" when the key grants nothing, the tier's name
// when license.GetCurrentTier verifies it.
//
// It does NOT observe the registration. The registered source is package
// state in sharedpolicy with no accessor, and the registration is pinned by
// BEHAVIOUR in TestConnectorCeilingFollowsTheVerifiedLicenceRead: with the
// init deleted, the valid-key rows there report the community ceiling
// (mutant M7 in the PR body). R3 round 1 caught the earlier name of this test
// claiming what only that other test proves.
func TestVerifiedLicenceTierAnswersWithTheVerifiedRead(t *testing.T) {
	priv := testLicenceKeypair(t)
	in30d := time.Now().AddDate(0, 0, 30)

	t.Setenv("AXONFLOW_LICENSE_KEY", "")
	if got := verifiedLicenceTier(context.Background()); got != "" {
		t.Fatalf("verifiedLicenceTier() with no key = %q, want \"\" (grants nothing)", got)
	}
	t.Setenv("AXONFLOW_LICENSE_KEY", licenceNamingTier(priv, string(license.TierEvaluation), in30d))
	if got := verifiedLicenceTier(context.Background()); got != string(license.TierEvaluation) {
		t.Fatalf("verifiedLicenceTier() with a valid Evaluation key = %q, want Evaluation", got)
	}
}

// TestConnectorCeilingFollowsTheVerifiedLicenceRead is the row's unhappy
// paths, first-class and each its own named assertion: absent key, forged
// signature (NOTASIG!), expired key, wrong tier string - each resolves to the
// COMMUNITY ceiling - and the valid key resolves to ITS tier, which is the
// control that makes the four refusals evidence rather than a ceiling that
// never lifts.
//
// Every case is driven through sharedpolicy.EnforceCustomPolicyConnectorLimit,
// the consumer, so the assertion is a connector COUNT: what an operator sees.
func TestConnectorCeilingFollowsTheVerifiedLicenceRead(t *testing.T) {
	priv := testLicenceKeypair(t)
	cfg := sixConnectorsUnderCommunityMode(t)
	now := time.Now()
	in30d := now.AddDate(0, 0, 30)

	genuineEnterprise := licenceNamingTier(priv, string(license.TierEnterprise), in30d)

	cases := []struct {
		name string
		key  string
		want int // connectors kept
	}{
		{"absent key -> community ceiling", "", cfg.MaxCustomPolicyConnectorsCommunity},
		{"forged signature NOTASIG! naming Enterprise -> community ceiling",
			license.ForgeSignatureForTest(genuineEnterprise), cfg.MaxCustomPolicyConnectorsCommunity},
		{"expired Enterprise key, well signed -> community ceiling",
			licenceNamingTier(priv, string(license.TierEnterprise), now.AddDate(0, 0, -30)), cfg.MaxCustomPolicyConnectorsCommunity},
		{"expired key inside the grace window -> community ceiling",
			licenceNamingTier(priv, string(license.TierEnterprise), now.AddDate(0, 0, -1)), cfg.MaxCustomPolicyConnectorsCommunity},
		{"wrong tier string Platinum, well signed -> community ceiling",
			licenceNamingTier(priv, "Platinum", in30d), cfg.MaxCustomPolicyConnectorsCommunity},
		{"malformed key -> community ceiling, not the old evaluation fallback",
			"AXON-not-a-key", cfg.MaxCustomPolicyConnectorsCommunity},
		{"valid Evaluation key -> evaluation ceiling",
			licenceNamingTier(priv, string(license.TierEvaluation), in30d), cfg.MaxCustomPolicyConnectorsEvaluation},
		{"valid Enterprise key -> unlimited",
			genuineEnterprise, len(cfg.EnabledConnectors)},
		{"valid Professional key -> unlimited",
			licenceNamingTier(priv, string(license.TierProfessional), in30d), len(cfg.EnabledConnectors)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AXONFLOW_LICENSE_KEY", tc.key)
			kept := sharedpolicy.EnforceCustomPolicyConnectorLimit(cfg)
			if len(kept) != tc.want {
				t.Fatalf("EnforceCustomPolicyConnectorLimit kept %d of %d connectors (%v), want %d",
					len(kept), len(cfg.EnabledConnectors), kept, tc.want)
			}
			// The validating consumer must agree with the truncating one.
			err := sharedpolicy.ValidateCustomPolicyConnectorLimit(cfg)
			if tc.want < len(cfg.EnabledConnectors) && err == nil {
				t.Errorf("ValidateCustomPolicyConnectorLimit accepted %d connectors under a ceiling of %d", len(cfg.EnabledConnectors), tc.want)
			}
			if tc.want == len(cfg.EnabledConnectors) && err != nil {
				t.Errorf("ValidateCustomPolicyConnectorLimit refused an unlimited deployment: %v", err)
			}
		})
	}
}

// driveLicenceTierRefusals is the write-site driver the metric label-domain
// census runs (metric_label_domain_test.go, runEveryDriver): a forged, an
// expired and a malformed key, each through the REAL validator via the agent's
// registered source, so axonflow_license_tier_read_rejected_total ends the
// census with series under three of its five declared classes.
func driveLicenceTierRefusals(t *testing.T) {
	t.Helper()
	priv := testLicenceKeypair(t)
	in30d := time.Now().AddDate(0, 0, 30)
	for _, key := range []string{
		license.ForgeSignatureForTest(licenceNamingTier(priv, string(license.TierEnterprise), in30d)),
		licenceNamingTier(priv, string(license.TierEnterprise), time.Now().AddDate(0, 0, -30)),
		"AXON-not-a-key",
	} {
		t.Setenv("AXONFLOW_LICENSE_KEY", key)
		if got := verifiedLicenceTier(context.Background()); got != "" {
			t.Fatalf("driver: a refused key resolved to %q; the driver is not reaching a refusal", got)
		}
	}
}

// TestARefusedKeyIsObservableNotMerelyRefused: the DoD line. A forged key must
// leave a trace a fleet reader can count - here the verified read's own
// outcome, which is what feeds axonflow_license_tier_read_rejected_total and
// the [license] log line (pinned in platform/agent/license/tier_read_test.go).
func TestARefusedKeyIsObservableNotMerelyRefused(t *testing.T) {
	priv := testLicenceKeypair(t)
	forged := license.ForgeSignatureForTest(licenceNamingTier(priv, string(license.TierEnterprise), time.Now().AddDate(0, 0, 30)))
	t.Setenv("AXONFLOW_LICENSE_KEY", forged)

	read := license.ReadCurrentTier(context.Background())
	if !read.Rejected || read.ReasonClass != license.TierReadRejectedSignature {
		t.Fatalf("a forged key was not reported as a signature rejection: %+v", read)
	}
	if got := verifiedLicenceTier(context.Background()); got != "" {
		t.Fatalf("verifiedLicenceTier() on a forged key = %q, want \"\"", got)
	}
}
