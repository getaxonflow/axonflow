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
)

// driveLicenceTierRefusals is the write-site driver the metric label-domain
// census runs (metric_label_domain_test.go, runEveryDriver): a forged, an
// expired and a malformed key, each through license.ReadCurrentTier - the one
// verified tier read, which admission calls - so
// axonflow_license_tier_read_rejected_total ends the census with series under
// three of its five declared classes.
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
		if got := license.ReadCurrentTier(context.Background()); !got.Rejected {
			t.Fatalf("driver: a refused key read as %+v; the driver is not reaching a refusal", got)
		}
	}
}

func licenceNamingTier(priv ed25519.PrivateKey, tier string, expires time.Time) string {
	return license.SignPayloadForTest(priv, license.ServiceLicensePayload{
		Tier:      tier,
		OrgID:     "wt3709-org",
		IssuedAt:  time.Now().UTC().Format("20060102"),
		ExpiresAt: expires.Format("20060102"),
	})
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
