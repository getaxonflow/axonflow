//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "axonflow/platform/decision/contract"

// applyAnchoredCapabilityRefusal returns the reasons untouched. Naming and
// counting the capability gap behind a refusal is enterprise_implementation,
// physically absent from this build (ADR-066 Decision 5), as
// applyPEPCapabilityRefusal's is; the refusal itself is the engine's and
// reaches the caller either way. One signature for both builds keeps one call
// site per plane rather than a build-tagged branch at the caller.
func applyAnchoredCapabilityRefusal(_ string, _ pepHandshakeResolution, _ []contract.Obligation, reasons []string) []string {
	return reasons
}
