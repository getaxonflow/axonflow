// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// BenchmarkReadCurrentTierWithAKey measures the per-call cost of the verified
// tier read when a key IS present.
//
// IT EXISTS TO JUSTIFY A MEMO, and the number is only interesting on the
// COMMUNITY build. The enterprise ValidateLicense consults a TTL cache
// (validation.go, getCachedValidation); the community one does not - it goes
// straight to validateEd25519License - so on a community binary holding an
// Evaluation key, which is the ordinary Evaluation deployment, every call is a
// fresh base64 decode, JSON unmarshal and Ed25519 verify.
//
// Measured 2026-09-08 on an M4 Pro: ~29.5 us/op. #3593 put the tier read on
// the authentication path of every governed request (twice: once for the
// service principal, once for the human principal), so without a memo that is
// ~59 us of pure repetition per request on exactly the tier whose ceilings
// bite. platform/agent/license/admission memoises it for
// admission.DefaultTierMemoTTL; this benchmark is what says how much that
// saves, and it will say so again if the community validator ever grows a
// cache of its own and the memo becomes redundant.
func BenchmarkReadCurrentTierWithAKey(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	restore := OverridePublicKeysForTest(pub, pub)
	defer restore()
	raw, _ := json.Marshal(ServiceLicensePayload{
		Tier: string(TierEvaluation), OrgID: "bench",
		ExpiresAt: time.Now().AddDate(0, 0, 30).Format("20060102")})
	p := base64.RawURLEncoding.EncodeToString(raw)
	key := "AXON-" + p + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(p)))
	ctx := context.Background()
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := readTier(ctx, key, now); got.Tier != TierEvaluation {
			b.Fatalf("tier=%v rejected=%v %s", got.Tier, got.Rejected, got.Reason)
		}
	}
}
