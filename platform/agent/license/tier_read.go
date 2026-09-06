// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// This file is deliberately identical apart from its build constraint between
// `platform/agent/license/tier_read.go` and `ee/platform/agent/license/tier_read.go`:
// the platform copy serves both build tags and carries no constraint; the ee
// copy sits in an enterprise-only package and must carry `//go:build
// enterprise`. The shipped enterprise image overlays the ee copy onto the
// platform one (platform/agent/Dockerfile, EDITION=enterprise), and
// tests/regression-test-required/license_pair_byte_identity_test.sh holds the two
// identical after stripping that one line.

package license

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// This file is the ONE verified read of the deployment's licence tier, shared
// by both build tags (#3709 row 1).
//
// GetCurrentTier existed twice - license.go (community) and tier_support.go
// (enterprise) - with byte-identical bodies, and both threw away the REASON a
// key was refused: a forged signature, an expired date and a malformed prefix
// all collapsed into TierCommunity with nothing logged and nothing counted.
// That is why the connector ceiling in platform/shared/policy grew its own
// unverified payload parser instead of calling this: the verified read gave
// it no way to say what it had seen.
//
// ReadCurrentTier is the same decision GetCurrentTier has always made, with
// the outcome made observable. Every rejection is counted on
// axonflow_license_tier_read_rejected_total{reason} and logged once per
// distinct reason for the life of the process, so a deployment that holds a
// key it believes grants Enterprise and is in fact running Community can be
// found from a metrics scrape or a log grep rather than from a customer
// noticing a truncated connector list.
//
// # WHAT "VERIFIED" MEANS HERE, BY CALL SITE
//
//   - the Ed25519 signature is checked by ValidateLicense ->
//     validateEd25519License -> verifyEd25519Signature against the embedded
//     tier public key (license.go in the community build, validation.go in
//     the enterprise build);
//   - the expiry is compared HERE against time.Now(), exactly as
//     GetCurrentTier did. The enterprise validator reports Valid=true inside a
//     7-day grace window; this read has always treated any past ExpiresAt as
//     Community and still does - grace is a boot-time courtesy in run.go, not
//     an entitlement.

// TierRead is the outcome of one verified read of AXONFLOW_LICENSE_KEY.
type TierRead struct {
	// Tier is the tier the deployment is entitled to. TierCommunity whenever
	// no key is present or the key did not verify.
	Tier Tier
	// KeyPresent reports whether AXONFLOW_LICENSE_KEY was non-empty.
	KeyPresent bool
	// Rejected reports that a key was present and did NOT yield its tier.
	// It is the observable the connector ceiling and the fleet dashboards
	// read; Tier alone cannot distinguish "no key" from "forged key".
	Rejected bool
	// Reason is the validator's own statement of why, for the log line.
	// Empty when not Rejected.
	Reason string
	// ReasonClass is Reason folded onto the bounded label set below, for the
	// metric. Empty when not Rejected.
	ReasonClass string
}

// The bounded set of rejection classes. These are metric label values, so the
// set is closed on purpose: a validator message that matches none of the
// substrings below lands on TierReadRejectedInvalid rather than minting a
// label per message.
const (
	// TierReadRejectedSignature: the payload does not carry a valid Ed25519
	// signature for its tier (wrong key, wrong length, tampered payload).
	TierReadRejectedSignature = "signature"
	// TierReadRejectedExpired: the signature verified and the licence is past
	// its expiry date.
	TierReadRejectedExpired = "expired"
	// TierReadRejectedTier: the payload names a tier this build does not
	// issue.
	TierReadRejectedTier = "unknown_tier"
	// TierReadRejectedMalformed: not an AXON- Ed25519 key at all (a V1/V2
	// key, a bad prefix, undecodable base64 or JSON).
	TierReadRejectedMalformed = "malformed"
	// TierReadRejectedInvalid: the validator refused it for a reason outside
	// the classes above (an audience mismatch, for example).
	TierReadRejectedInvalid = "invalid"
)

var tierReadRejected = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_license_tier_read_rejected_total",
	Help: "Verified licence tier reads that found AXONFLOW_LICENSE_KEY set and refused it, by reason. " +
		"A non-zero series means this process holds a key that grants nothing and is running on the Community tier.",
}, []string{"reason"})

// loggedTierRejections records which (class, reason) pairs have been logged so
// a per-request caller with a bad key produces one line, not one per call.
// The map is bounded at one entry per distinct reason: the validators' reasons
// embed only the tier string and byte counts, never key material, and
// AXONFLOW_LICENSE_KEY is process-scoped.
var loggedTierRejections sync.Map

// TierReadRejectedCollectorForTest exposes the refusal counter to
// platform/agent's metric label-domain census, which measures membership of
// its driven set by DRIVING a write site and counting series. Intended for use
// in tests only.
func TierReadRejectedCollectorForTest() prometheus.Collector { return tierReadRejected }

// ReadCurrentTier is the verified read of the deployment's licence tier from
// AXONFLOW_LICENSE_KEY: signature checked, expiry compared, outcome observable.
//
// It is what GetCurrentTier returns the Tier of, and the only thing a package
// that needs "which tier is this deployment entitled to" should call.
func ReadCurrentTier(ctx context.Context) TierRead {
	return readTier(ctx, os.Getenv("AXONFLOW_LICENSE_KEY"), time.Now())
}

// readTier is ReadCurrentTier with the key and the clock as parameters, so the
// expiry comparison HERE can be exercised without waiting for a licence to
// expire. The clock is honoured by this function's own comparison only: both
// validators read time.Now() internally (the enterprise one refuses a key more
// than 7 days past expiry as LICENSE_EXPIRED before this function sees it), so
// a test that passes a `now` earlier than the wall clock must use a key that
// has not expired on the wall clock either.
func readTier(ctx context.Context, key string, now time.Time) TierRead {
	if key == "" {
		return TierRead{Tier: TierCommunity}
	}

	result, err := ValidateLicense(ctx, key)
	switch {
	case err != nil:
		// The enterprise validator reports refusals as errors.
		return rejectTierRead(err.Error())
	case result == nil:
		return rejectTierRead("validator returned no result")
	case !result.Valid:
		return rejectTierRead(strings.TrimSpace(result.Error + " " + result.Message))
	case result.Tier == TierCommunity:
		// The community validator reports refusals as a Valid Community
		// result whose Message names the cause (communityFallback). A key
		// that VERIFIES never resolves to TierCommunity - both validators
		// admit only the four issued tiers - so with a key present this is a
		// refusal, not an entitlement.
		return rejectTierRead(result.Message)
	case now.After(result.ExpiresAt):
		return rejectTierRead("license expired on " + result.ExpiresAt.Format("2006-01-02"))
	}
	return TierRead{Tier: result.Tier, KeyPresent: true}
}

// rejectTierRead builds the Community outcome for a present-but-refused key,
// counts it and logs it once per distinct reason.
func rejectTierRead(reason string) TierRead {
	if reason == "" {
		reason = "license refused without a stated reason"
	}
	class := classifyTierRejection(reason)
	tierReadRejected.WithLabelValues(class).Inc()
	if _, seen := loggedTierRejections.LoadOrStore(class+"|"+reason, struct{}{}); !seen {
		log.Printf("[license] AXONFLOW_LICENSE_KEY is set but the verified tier read REFUSED it (reason=%s): %s. "+
			"This process is running on the Community tier; every tier-gated limit applies at its Community value.",
			class, reason)
	}
	return TierRead{
		Tier:        TierCommunity,
		KeyPresent:  true,
		Rejected:    true,
		Reason:      reason,
		ReasonClass: class,
	}
}

// classifyTierRejection folds a validator message onto the closed label set.
// Order matters: "invalid license signature" must land on signature, not on
// invalid; a V1-format refusal that happens to spell "AXON-TIER-ORG" must
// land on malformed, not on unknown_tier.
func classifyTierRejection(reason string) string {
	r := strings.ToLower(reason)
	switch {
	// "invalid signature encoding" is a base64 failure on the signature
	// SEGMENT - the key is malformed, no signature was ever checked - so it
	// is tested before the signature class it would otherwise match.
	case strings.Contains(r, "signature encoding"):
		return TierReadRejectedMalformed
	case strings.Contains(r, "signature"):
		return TierReadRejectedSignature
	case strings.Contains(r, "expired"):
		return TierReadRejectedExpired
	// Malformed is tested BEFORE unknown_tier: the V1-format refusal reads
	// "V1 license format (AXON-TIER-ORG-...) is no longer supported", and a
	// key that is not an Ed25519 key at all has no tier to be unknown.
	case strings.Contains(r, "prefix"),
		strings.Contains(r, "format"),
		strings.Contains(r, "encoding"),
		strings.Contains(r, "json"),
		strings.Contains(r, "no longer supported"):
		return TierReadRejectedMalformed
	case strings.Contains(r, "tier"):
		return TierReadRejectedTier
	default:
		return TierReadRejectedInvalid
	}
}
