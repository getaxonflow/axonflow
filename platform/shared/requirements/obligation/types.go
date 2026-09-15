// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
)

// THERE IS NO VOCABULARY IN THIS FILE. The obligation types, families,
// parameter keys, disclosure order, delivery guarantees and assurance levels
// are platform/decision/contract's, and this package names them through that
// import. What is declared here is what only the stateful planner knows: WHEN
// an instruction is discharged (Phase), WHETHER the policy that attached it
// applied (Applicability), and what happens when discharge fails
// (FailureBehavior). None of these takes part in composition.

// Phase is when an obligation is discharged relative to the governed action.
type Phase string

const (
	// PhaseRequest is discharged on the request, before execution.
	PhaseRequest Phase = "request"
	// PhaseResponse is discharged on the response, after execution but before
	// the response is released to the caller.
	PhaseResponse Phase = "response"
	// PhaseOutOfBand is discharged after execution and does not gate the
	// release of anything - audit and notification. These are the obligations
	// that need a DURABLE DELIVERY contract rather than completion evidence,
	// because nothing is waiting on them.
	PhaseOutOfBand Phase = "out_of_band"
)

// AllPhases lists the declared phases in a stable order.
func AllPhases() []Phase { return []Phase{PhaseRequest, PhaseResponse, PhaseOutOfBand} }

// GatesRelease reports whether an obligation in this phase must be complete
// before anything is handed onward.
//
// Both request and response phases gate a release: a request-phase redaction
// gates the call to the connector, a response-phase filter gates the bytes
// returned to the caller. Only out-of-band obligations release nothing, and
// they are exactly the ones that carry a delivery guarantee instead.
func (p Phase) GatesRelease() bool { return p == PhaseRequest || p == PhaseResponse }

// Valid reports whether p is a declared phase.
func (p Phase) Valid() bool {
	switch p {
	case PhaseRequest, PhaseResponse, PhaseOutOfBand:
		return true
	}
	return false
}

// Applicability is the tri-state that closes the source proposal's
// obligations-INDET fail-open.
//
// It is deliberately NOT a bool with a separate error. A bool forces every
// reader to decide what a false-with-error means, and the source proposal's
// answer - "not applicable, carry on" - is the bug. Here `Unknown` is a value
// the planner must handle, and the planner's handling of it for a mandatory
// obligation is Deny.
//
// It is about the requirement policy's CONDITION, not about the instruction,
// which is why it lives on the planner's wrapper and not on the canonical
// obligation: by the time the PDP composes, its conditions are resolved.
type Applicability string

const (
	// Applicable - the requirement policy's condition matched.
	Applicable Applicability = "applicable"
	// NotApplicable - the authoritative source established that the condition
	// does not match. This is a POSITIVE finding, not a failure to look.
	NotApplicable Applicability = "not_applicable"
	// Unknown - AxonFlow could not establish whether the obligation applies:
	// resolution failure, staleness, schema mismatch, unevaluable condition.
	// For a mandatory obligation this denies.
	Unknown Applicability = "unknown"
)

// Valid reports whether a is one of the three states.
func (a Applicability) Valid() bool {
	switch a {
	case Applicable, NotApplicable, Unknown:
		return true
	}
	return false
}

// FailureBehavior is what happens when discharging the obligation fails.
type FailureBehavior string

const (
	// FailClosed - a discharge failure denies.
	FailClosed FailureBehavior = "deny"
	// FailRecorded - a discharge failure is recorded and execution continues.
	// Only legal on advisory obligations; Schema.Validate enforces that.
	FailRecorded FailureBehavior = "record"
)

// Obligation is one candidate instruction the planner is asked about: the
// canonical instruction, exactly as the PDP would compose it, plus the two
// facts only the requirement policy's evaluation knows.
//
// The canonical half is EMBEDDED, not translated. A planner obligation IS a
// contract obligation with a phase and an applicability attached, so there is
// no second parameter model to keep in step and nothing to convert before the
// algebra runs. Type, target, params, mandatory, source policy and schema
// version all read through the embedding.
type Obligation struct {
	contract.Obligation

	// Phase is the phase this instance is discharged in. It must be one the
	// registered schema declares; Registry.ValidateObligation checks that.
	Phase Phase

	// Applicability is the tri-state from the requirement policy's condition.
	Applicability Applicability
	// ApplicabilityReason is the DECLARED class of unknown-ness when
	// Applicability is Unknown, spelled with the same vocabulary the attribute
	// plane uses for an attribute it could not establish. Required in that
	// state, refused in the others.
	ApplicabilityReason contract.UnknownReason
	// ApplicabilityDetail is the operator-audience expansion (which attribute,
	// which bound). Free text; it names paths and policies, never values.
	ApplicabilityDetail string
}

// Validate checks the instance-level invariants that hold regardless of
// schema. Schema-level checks live in Registry.Validate.
//
// The canonical half is validated by the canonical validator ONLY when the
// obligation is applicable: a NotApplicable or Unknown obligation carries no
// parameters and possibly no target, because there was nothing to
// parameterise, and the contract's own validator would refuse a disclosure
// transform with no target. Its type must still be a registered one, because
// an obligation of a type nobody declared cannot be planned in any state.
func (o Obligation) Validate() error {
	if o.Type == "" {
		return fmt.Errorf("obligation: type is required")
	}
	if _, err := contract.FamilyOf(o.Type); err != nil {
		return fmt.Errorf("obligation: %w", err)
	}
	if o.SchemaVersion <= 0 {
		return fmt.Errorf("obligation %s: schema_version must be >= 1 (0 is not 'latest')", o.Type)
	}
	if !o.Phase.Valid() {
		return fmt.Errorf("obligation %s: phase must be one of %v, got %q (there is no default)", o.Type, AllPhases(), o.Phase)
	}
	if !o.Applicability.Valid() {
		return fmt.Errorf("obligation %s: applicability must be one of %q/%q/%q, got %q",
			o.Type, Applicable, NotApplicable, Unknown, o.Applicability)
	}
	switch o.Applicability {
	case Unknown:
		if !validUnknownReason(o.ApplicabilityReason) {
			return fmt.Errorf("obligation %s: applicability %q requires a declared reason, one of %v; got %q",
				o.Type, Unknown, contract.AllUnknownReasons(), o.ApplicabilityReason)
		}
	default:
		if o.ApplicabilityReason != "" {
			return fmt.Errorf("obligation %s: applicability %q must not carry an unknown-reason (%q)", o.Type, o.Applicability, o.ApplicabilityReason)
		}
	}
	if o.Applicability == Applicable {
		if err := o.Obligation.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validUnknownReason(r contract.UnknownReason) bool {
	for _, known := range contract.AllUnknownReasons() {
		if r == known {
			return true
		}
	}
	return false
}

// Capability returns the exact capability this obligation demands of a PEP.
func (o Obligation) Capability() contract.Capability { return o.CapabilityOf() }

// sortedUnique returns a sorted, duplicate-free copy of in.
func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
