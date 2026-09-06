// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"

	"axonflow/platform/agent/license"
	sharedpolicy "axonflow/platform/shared/policy"
)

// The agent hands its VERIFIED licence read down to platform/shared/policy
// (#3709 row 1).
//
// platform/shared/policy decides the custom-policy connector ceiling and needs
// to know which tier the deployment's licence key grants. It must not learn
// that by reading the key: the parser it used to carry took the payload's
// `tier` on trust, and under the community and community-saas postures - where
// run.go skips license.ValidateWithRetry - nothing else had checked the
// signature or the expiry either. license.GetCurrentTier is the read that
// does both (ReadCurrentTier in platform/agent/license/tier_read.go: Ed25519
// signature via ValidateLicense, ExpiresAt compared against the clock, every
// refusal counted on axonflow_license_tier_read_rejected_total and logged).
//
// # WHY init AND NOT A LINE IN Run
//
// Registration is a property of the binary, not of a boot sequence: any
// process that links package agent holds a licence read and must resolve the
// ceiling through it, including the test binary. An init keeps it that way -
// there is no ordering to get wrong between the licence block, the evaluator's
// construction and UpdateConfig, and no second boot path that can forget it.
// The unregistered default in platform/shared/policy fails closed to Community
// and says so on a log line and a counter, so a binary that does NOT link this
// package is loud rather than silently truncated.
//
// The registration is pinned end to end rather than by reading this file:
// license_tier_source_test.go drives the ceiling through the REAL validator
// with a forged, an expired, an absent and a valid key, and
// runtime-e2e/3713_connector_entitlement boots the shipped binary with a real
// keygen-minted licence and a forgery of it. Delete this init and the valid-key
// cases in both report Community.
func init() {
	sharedpolicy.SetLicenseTierSource(verifiedLicenceTier)
}

// verifiedLicenceTier is the registered source: the tier the licence key
// verifiably grants, or "" when it grants nothing. It is a named function
// rather than a closure so a test can compare what is registered.
func verifiedLicenceTier(ctx context.Context) string {
	tier := license.GetCurrentTier(ctx)
	if tier == license.TierCommunity {
		return ""
	}
	return string(tier)
}
