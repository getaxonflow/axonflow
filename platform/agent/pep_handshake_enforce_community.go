//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// The COMMUNITY half of the ADR-065 capability handshake split (#3704).
//
// A Community build reads, validates, binds and COUNTS a handshake exactly as
// an Enterprise build does - all of that is enterprise_protocol and ships here.
// What it does not do is DECIDE on the strength of one, which is
// enterprise_implementation and is physically absent from this build (ADR-066
// Decision 5).
//
// This is not a weaker safety posture. A mandatory obligation the enforcement
// point declares it cannot discharge is refused unsupported_obligation on EVERY
// edition wherever the engine composes it against the admitted profile
// (contract composeSet), and wherever /api/v1/decide or the gateway pre-check
// attaches a checksum validator's field_redact (attachValidatorRedactions).
// What this build leaves out is enterprise_implementation: this handler-level
// refusal over the legacy obligation slice (applyPEPCapabilityRefusal, below),
// naming and counting the enforcement point's capability gap
// (applyAnchoredCapabilityRefusal), and applyMCPRedactionRefusal, the only
// refusal of a validator's masking on the MCP passes. On this build those
// passes hand the masked content over, and an enforcement point that declared
// it cannot substitute it still fails closed at its own seam.

// applyPEPCapabilityRefusal returns the verdict untouched.
//
// The signature is identical to the Enterprise arm's so that handleDecide has
// ONE call site rather than a build-tagged branch at the caller. A branch at
// the caller is how the two arms drift: the community one stops being called at
// all, and the counter it shares goes quiet for a reason nobody can see.
func applyPEPCapabilityRefusal(
	_ string,
	_ pepHandshakeResolution,
	verdict string,
	reasons []string,
	obligations []DecisionObligation,
) (string, []string, []DecisionObligation, bool) {
	return verdict, reasons, obligations, false
}
