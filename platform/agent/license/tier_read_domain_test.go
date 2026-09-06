// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/shared/metricdomain"
)

// tierReadRejectedReasonDomain is the declared label domain for
// axonflow_license_tier_read_rejected_total{reason}: the five constants
// classifyTierRejection can return and nothing else. Its default branch is
// TierReadRejectedInvalid, so no validator message reaches the label.
//
// Declared next to the metric (this package is outside platform/agent's
// guarded-file census) and checked LIVE below with metricdomain.Check after
// the metric has been driven with every refusal class.
func tierReadRejectedReasonDomain() map[string]metricdomain.Domain {
	return map[string]metricdomain.Domain{
		"reason": metricdomain.Closed(
			"classifyTierRejection folds the validator's message onto five constants by substring, "+
				"with TierReadRejectedInvalid as the fall-through; the message itself never reaches the label",
			TierReadRejectedSignature, TierReadRejectedExpired, TierReadRejectedTier,
			TierReadRejectedMalformed, TierReadRejectedInvalid),
	}
}

// TestTierReadRejectedReasonLabelStaysInsideItsDeclaredDomain drives every
// refusal shape the validators produce, then asks metricdomain.Check whether
// any series escaped the declared set. Anti-vacuity: at least four distinct
// classes must have been observed, or the check ran over an empty vec.
func TestTierReadRejectedReasonLabelStaysInsideItsDeclaredDomain(t *testing.T) {
	priv := testTierKeypair(t)
	ctx := context.Background()
	now := time.Now()
	future := now.AddDate(0, 0, 30).Format("20060102")
	genuine := signTierPayload(t, priv, ServiceLicensePayload{Tier: string(TierEnterprise), ExpiresAt: future})

	observed := map[string]bool{}
	for _, key := range []string{
		forgeSignature(genuine),
		signTierPayload(t, priv, ServiceLicensePayload{Tier: string(TierEnterprise), ExpiresAt: now.AddDate(0, 0, -30).Format("20060102")}),
		signTierPayload(t, priv, ServiceLicensePayload{Tier: "Platinum", ExpiresAt: future}),
		"hunter2",
		"AXON-V2-legacy",
		"AXON-not-a-key",
		signTierPayload(t, priv, ServiceLicensePayload{Tier: string(TierEnterprise), ExpiresAt: "not-a-date"}),
	} {
		got := readTier(ctx, key, now)
		if !got.Rejected {
			t.Fatalf("fixture %.20q was not rejected; the drive is not exercising the label", key)
		}
		observed[got.ReasonClass] = true
	}
	if len(observed) < 4 {
		t.Fatalf("only %d distinct reason classes observed (%v); the domain check below would be over too little", len(observed), observed)
	}

	if problems := metricdomain.Check("axonflow_license_tier_read_rejected_total", tierReadRejected, tierReadRejectedReasonDomain()); len(problems) != 0 {
		t.Fatalf("a reason label escaped the declared domain:\n%v", problems)
	}
}
