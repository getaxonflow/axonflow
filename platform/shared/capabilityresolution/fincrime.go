// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capabilityresolution

const (
	// FinCrimeModuleID is the stable commercial grant. Packaging can grant the
	// whole module without collapsing its separately classified artifacts.
	FinCrimeModuleID = "fincrime"

	// FinCrimeProtocolCapabilityID is the Community-visible semantic seam. It
	// does not activate either Enterprise artifact below.
	FinCrimeProtocolCapabilityID = "fincrime.protocol"
	// FinCrimePolicyPackCapabilityID is the versioned Enterprise typed-policy
	// artifact and activation boundary.
	FinCrimePolicyPackCapabilityID = "fincrime.policy_pack"
	// FinCrimeRiskScoringCapabilityID is the Enterprise scorer and Agent fact
	// producer. Typed policy remains the only verdict authority.
	FinCrimeRiskScoringCapabilityID = "fincrime.risk_scoring"

	// FinCrimeScoreRequestsLimitID is the durable tenant usage dimension for an
	// admitted scoring invocation. A plan-specific value is not part of this
	// vocabulary.
	FinCrimeScoreRequestsLimitID = "fincrime.score_requests"
)
