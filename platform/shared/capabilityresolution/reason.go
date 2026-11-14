// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package capabilityresolution defines the stable refusal vocabulary shared by
// capability metadata and the runtime resolvers that will enforce it.
//
// This package deliberately contains no entitlement or quota implementation.
// A registry entry can state which reasons a capability promises without
// turning descriptive registry data into authorization truth.
package capabilityresolution

// Reason is a stable, machine-readable reason why a capability was not
// admitted. Reasons describe one failed leg of the effective-access
// intersection; they are not customer-facing prose.
type Reason string

const (
	// ReasonEditionRequired means the deployment edition cannot carry or run
	// the capability. A plan, grant or caller claim cannot satisfy this leg.
	ReasonEditionRequired Reason = "edition_required"
	// ReasonCapabilityNotGranted means the deployment can run the capability,
	// but the server-established tenant or self-hosted licence grant does not.
	ReasonCapabilityNotGranted Reason = "capability_not_granted"
	// ReasonQuotaExhausted means the authoritative durable usage limit refused
	// another operation.
	ReasonQuotaExhausted Reason = "quota_exhausted"
	// ReasonDependencyUnreachable means the authority needed to resolve a
	// bounded capability could not be reached. It is distinct from a positive
	// grant denial and must not be treated as one.
	ReasonDependencyUnreachable Reason = "dependency_unreachable"
)

var reasons = []Reason{
	ReasonEditionRequired,
	ReasonCapabilityNotGranted,
	ReasonQuotaExhausted,
	ReasonDependencyUnreachable,
}

var validReasons = func() map[Reason]bool {
	out := make(map[Reason]bool, len(reasons))
	for _, reason := range reasons {
		out[reason] = true
	}
	return out
}()

// Reasons returns the complete vocabulary in stable order.
func Reasons() []Reason { return append([]Reason(nil), reasons...) }

// Valid reports whether reason belongs to the closed vocabulary.
func Valid(reason Reason) bool { return validReasons[reason] }
