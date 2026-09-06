// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// This file is deliberately identical apart from its build constraint between
// `platform/agent/license/tier_read_test.go` and `ee/platform/agent/license/tier_read_test.go`:
// the platform copy serves both build tags and carries no constraint; the ee
// copy sits in an enterprise-only package and must carry `//go:build
// enterprise`. The shipped enterprise image overlays the ee copy onto the
// platform one (platform/agent/Dockerfile, EDITION=enterprise), and
// tests/regression-test-required/license_pair_byte_identity_test.sh holds the two
// identical after stripping that one line.

package license

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// This file pins the verified tier read (#3709 row 1) under BOTH build tags:
// the file has no build constraint, and the two validators it drives differ
// in how they report a refusal (the enterprise one returns an error, the
// community one a Valid Community result with a Message), so every case below
// is exercised against both shapes by the two CI legs.
//
// Keys are signed by a keypair generated per test and installed with
// OverridePublicKeysForTest, because two of the cases - an expired date and a
// tier this build does not issue - are keys the repo's own keygen REFUSES to
// mint (validityDays must be positive; the tier is validated). The valid-key
// case minted by the repo's tooling itself lives in
// tier_read_enterprise_test.go, where the keygen compiles.

// testTierKeypair installs a fresh Ed25519 keypair as BOTH tier public keys
// for the duration of the test and returns the private key to sign with.
func testTierKeypair(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	t.Cleanup(OverridePublicKeysForTest(pub, pub))
	return priv
}

// signTierPayload fills the fields every issued licence carries and signs
// through the package's own test seam, so this file holds no copy of the wire
// encoding.
func signTierPayload(t *testing.T, priv ed25519.PrivateKey, payload ServiceLicensePayload) string {
	t.Helper()
	if payload.OrgID == "" {
		payload.OrgID = "tier-read-test"
	}
	if payload.IssuedAt == "" {
		payload.IssuedAt = time.Now().UTC().Format("20060102")
	}
	return SignPayloadForTest(priv, payload)
}

// forgeSignature is ForgeSignatureForTest, named for what the row measured.
func forgeSignature(key string) string { return ForgeSignatureForTest(key) }

func rejectedCount(t *testing.T, class string) float64 {
	t.Helper()
	return testutil.ToFloat64(tierReadRejected.WithLabelValues(class))
}

// TestReadCurrentTierUnhappyPathsResolveToCommunity is the row's own list:
// absent key, forged signature, expired key, wrong tier string. Each is its
// own named case, each must resolve to Community, and each refusal must be
// COUNTED under the class a fleet reader would look for - a refusal that only
// changes the tier is indistinguishable from "no key" at the metrics endpoint.
func TestReadCurrentTierUnhappyPathsResolveToCommunity(t *testing.T) {
	priv := testTierKeypair(t)
	ctx := context.Background()
	now := time.Now()
	future := now.AddDate(0, 0, 30).Format("20060102")

	genuine := signTierPayload(t, priv, ServiceLicensePayload{Tier: string(TierEnterprise), ExpiresAt: future})

	cases := []struct {
		name       string
		key        string
		keyPresent bool
		wantClass  string // "" means not rejected
	}{
		{"absent key", "", false, ""},
		{"forged signature NOTASIG! naming tier Enterprise", forgeSignature(genuine), true, TierReadRejectedSignature},
		{"expired key, well signed", signTierPayload(t, priv, ServiceLicensePayload{
			Tier: string(TierEnterprise), ExpiresAt: now.AddDate(0, 0, -30).Format("20060102"),
		}), true, TierReadRejectedExpired},
		{"expired key inside the 7-day grace window", signTierPayload(t, priv, ServiceLicensePayload{
			Tier: string(TierEnterprise), ExpiresAt: now.AddDate(0, 0, -2).Format("20060102"),
		}), true, TierReadRejectedExpired},
		{"wrong tier string, well signed", signTierPayload(t, priv, ServiceLicensePayload{
			Tier: "Platinum", ExpiresAt: future,
		}), true, TierReadRejectedTier},
		{"tampered payload under a genuine signature", func() string {
			// Re-encode the payload with the tier swapped; the signature no
			// longer covers it.
			dot := strings.LastIndex(genuine, ".")
			raw, _ := base64.RawURLEncoding.DecodeString(genuine[5:dot])
			raw = bytes.Replace(raw, []byte(`"tier":"Enterprise"`), []byte(`"tier":"Plus"`), 1)
			return "AXON-" + base64.RawURLEncoding.EncodeToString(raw) + genuine[dot:]
		}(), true, TierReadRejectedSignature},
		{"not an AXON key at all", "hunter2", true, TierReadRejectedMalformed},
		{"AXON prefix with no signature separator", "AXON-not-a-key", true, TierReadRejectedMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := map[string]float64{}
			for _, c := range []string{TierReadRejectedSignature, TierReadRejectedExpired, TierReadRejectedTier, TierReadRejectedMalformed, TierReadRejectedInvalid} {
				before[c] = rejectedCount(t, c)
			}

			got := readTier(ctx, tc.key, now)

			if got.Tier != TierCommunity {
				t.Fatalf("readTier() = %q, want Community", got.Tier)
			}
			if got.KeyPresent != tc.keyPresent {
				t.Errorf("KeyPresent = %v, want %v", got.KeyPresent, tc.keyPresent)
			}
			if tc.wantClass == "" {
				if got.Rejected {
					t.Fatalf("an absent key was reported as a REJECTED key (%q); the two must stay distinguishable", got.Reason)
				}
				return
			}
			if !got.Rejected {
				t.Fatalf("a %s resolved to Community without being marked Rejected; nothing downstream can tell it from no key", tc.name)
			}
			if got.ReasonClass != tc.wantClass {
				t.Errorf("ReasonClass = %q (reason %q), want %q", got.ReasonClass, got.Reason, tc.wantClass)
			}
			if got.Reason == "" {
				t.Error("a rejection carried no reason; the log line would say nothing")
			}
			if delta := rejectedCount(t, tc.wantClass) - before[tc.wantClass]; delta != 1 {
				t.Errorf("axonflow_license_tier_read_rejected_total{reason=%q} moved by %v, want 1", tc.wantClass, delta)
			}
		})
	}
}

// TestReadCurrentTierValidKeyResolvesToItsTier is the control: without it,
// every case above also passes for a read that returns Community
// unconditionally.
func TestReadCurrentTierValidKeyResolvesToItsTier(t *testing.T) {
	priv := testTierKeypair(t)
	ctx := context.Background()
	now := time.Now()
	future := now.AddDate(0, 0, 30).Format("20060102")

	for _, tier := range []Tier{TierEvaluation, TierProfessional, TierEnterprise, TierEnterprisePlus} {
		t.Run(string(tier), func(t *testing.T) {
			key := signTierPayload(t, priv, ServiceLicensePayload{Tier: string(tier), ExpiresAt: future})
			got := readTier(ctx, key, now)
			if got.Rejected {
				t.Fatalf("a valid %s key was REJECTED: %s", tier, got.Reason)
			}
			if got.Tier != tier {
				t.Fatalf("readTier() = %q, want %q", got.Tier, tier)
			}
			if !got.KeyPresent {
				t.Error("KeyPresent = false for a present key")
			}
		})
	}

	// The same key, read through the exported entry point, so the env read
	// and the clock are covered too.
	key := signTierPayload(t, priv, ServiceLicensePayload{Tier: string(TierEvaluation), ExpiresAt: future})
	t.Setenv("AXONFLOW_LICENSE_KEY", key)
	if got := ReadCurrentTier(ctx); got.Tier != TierEvaluation || got.Rejected {
		t.Fatalf("ReadCurrentTier() = %+v, want Evaluation and not rejected", got)
	}
	if got := GetCurrentTier(ctx); got != TierEvaluation {
		t.Fatalf("GetCurrentTier() = %q, want Evaluation; it must be the same read", got)
	}
}

// TestExpiryIsComparedAgainstTheClockPassedIn pins the expiry check as a
// property of the clock rather than of the key: the same key is entitled the
// day before it expires and Community the day after. Deleting the
// now.After(ExpiresAt) branch leaves the day-after case reporting Enterprise.
func TestExpiryIsComparedAgainstTheClockPassedIn(t *testing.T) {
	priv := testTierKeypair(t)
	ctx := context.Background()
	expiry := time.Date(2030, 6, 15, 0, 0, 0, 0, time.UTC)
	key := signTierPayload(t, priv, ServiceLicensePayload{Tier: string(TierEnterprise), ExpiresAt: expiry.Format("20060102")})

	if got := readTier(ctx, key, expiry.AddDate(0, 0, -1)); got.Tier != TierEnterprise || got.Rejected {
		t.Fatalf("the day before expiry: %+v, want Enterprise", got)
	}
	after := readTier(ctx, key, expiry.Add(24*time.Hour+time.Second))
	if after.Tier != TierCommunity || !after.Rejected || after.ReasonClass != TierReadRejectedExpired {
		t.Fatalf("the day after expiry: %+v, want Community, rejected as expired", after)
	}
}

// TestARefusalIsLoggedOncePerReason: the log line is what an operator greps
// for, and a per-request caller holding a bad key must not fill the log with
// it. One line per distinct reason for the life of the process.
func TestARefusalIsLoggedOncePerReason(t *testing.T) {
	priv := testTierKeypair(t)
	ctx := context.Background()
	now := time.Now()
	key := forgeSignature(signTierPayload(t, priv, ServiceLicensePayload{
		Tier: string(TierEnterprise), ExpiresAt: now.AddDate(0, 0, 30).Format("20060102"),
	}))

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// The reason text for a forged signature is stable across calls, so the
	// dedupe key is the same each time. Clear it first so this test does not
	// depend on which other test ran before it.
	loggedTierRejections.Range(func(k, _ any) bool { loggedTierRejections.Delete(k); return true })

	for i := 0; i < 3; i++ {
		if got := readTier(ctx, key, now); got.ReasonClass != TierReadRejectedSignature {
			t.Fatalf("call %d: %+v", i, got)
		}
	}
	lines := strings.Count(buf.String(), "verified tier read REFUSED it")
	if lines != 1 {
		t.Fatalf("three refusals for one reason produced %d log lines, want exactly 1:\n%s", lines, buf.String())
	}
	if !strings.Contains(buf.String(), "reason=signature") {
		t.Errorf("the log line does not name the reason class:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), key[5:25]) {
		t.Errorf("the log line leaks the licence key material:\n%s", buf.String())
	}
}

// TestClassifyTierRejectionIsClosedAndOrdered pins the label set and the
// precedence that keeps "invalid license signature" out of the invalid bucket.
func TestClassifyTierRejectionIsClosedAndOrdered(t *testing.T) {
	cases := map[string]string{
		"invalid license signature":                                          TierReadRejectedSignature,
		"invalid signature length: expected 64 bytes, got 8":                 TierReadRejectedSignature,
		"invalid signature encoding":                                         TierReadRejectedMalformed,
		"license expired on 2026-01-01":                                      TierReadRejectedExpired,
		"LICENSE_EXPIRED License expired on 2026-01-01 (grace period ended)": TierReadRejectedExpired,
		"unknown license tier":                                               TierReadRejectedTier,
		"invalid license tier: Platinum":                                     TierReadRejectedTier,
		"invalid license key prefix":                                         TierReadRejectedMalformed,
		"invalid license format":                                             TierReadRejectedMalformed,
		"V1 license format (AXON-TIER-ORG-...) is no longer supported":       TierReadRejectedMalformed,
		"invalid payload encoding":                                           TierReadRejectedMalformed,
		"invalid payload JSON":                                               TierReadRejectedMalformed,
		"V2 license format no longer supported":                              TierReadRejectedMalformed,
		"license validation failed: aud mismatch":                            TierReadRejectedInvalid,
		"": TierReadRejectedInvalid,
	}
	for reason, want := range cases {
		if got := classifyTierRejection(reason); got != want {
			t.Errorf("classifyTierRejection(%q) = %q, want %q", reason, got, want)
		}
	}
}
