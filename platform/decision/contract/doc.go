// Package contract defines the canonical, versioned authorization contract for
// the ADR-065 policy decision plane: the normalized request a Policy Decision
// Point evaluates, the four-valued authorization outcome it returns, the
// operational decision a Policy Enforcement Point acts on, the typed
// obligations attached to a permit, and the audience-scoped explain trace.
//
// # Why a separate package from the evaluator
//
// ADR-065 replaces two independently evolved policy paths (static policy in the
// agent, dynamic policy in the orchestrator) whose divergence is a divergence of
// contracts, not of algorithms: different request structs, different action
// mappings, different result shapes, different failure postures. Replacing the
// evaluator without first fixing one contract would preserve the drift. Every
// type in this package is therefore defined once, validated against a committed
// JSON Schema, and canonically encodable, so that a decision made on one plane
// is byte-identical to the same decision made on another.
//
// # The three invariants this package exists to make structural
//
// First, unknown is not false. Every policy-visible attribute is a tagged value
// carrying one of three states: known, absent (the authoritative source
// established that an optional attribute has no value), or unknown (AxonFlow
// could not establish the value, with a named reason). A bare Go zero value can
// never be mistaken for a resolved attribute, because Attribute.State is
// mandatory and an Attribute with an empty state fails validation. See
// tristate.go.
//
// Second, provenance is part of the type. Caller-supplied argument data and
// directory-derived identity data are both JSON, and once they are in the same
// map no reviewer can tell by reading a policy which one is authoritative.
// Attribute.Source records the class, namespaces separate the two lexically, and
// AuthorityRule rejects at authoring time any condition in which untrusted input
// establishes authority rather than merely bounding it. See provenance.go.
//
// Third, the wire contract and the internal model are different objects.
// AuthZEN 1.0 carries a boolean decision; the internal lattice is four-valued.
// The adapter in authzen.go collapses the lattice at the edge and never lets the
// boolean leak inward. Unknown envelope keys, unknown profile fields and
// unknown obligations fail closed rather than being ignored.
//
// # Edition
//
// This package is community-visible, mirroring the visibility of the policy
// engine it replaces (platform/shared/policy carries no enterprise build
// constraint). It defines the approval requirement type and its composition
// shape because the community engine already emits require_approval and must be
// able to express a challenge; it does not implement approval discharge,
// directory resolution, or decision-proof signing, which are tracked separately.
package contract
