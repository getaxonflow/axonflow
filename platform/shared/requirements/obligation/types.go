// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"fmt"
	"sort"
	"strings"
)

// Family partitions obligation types by the ONE composition algebra that
// governs them. ADR-065's obligation table has seven rows and this enum has
// seven values; TestEveryFamilyHasExactlyOneAlgebra pins the correspondence.
//
// FamilyPhaseOrdering is the one family whose domain is the whole plan rather
// than a partition of it: no obligation TYPE belongs to it, because phase
// ordering composes the dependency edges declared by every other obligation.
// It is still a Family rather than a loose helper so that the "one algebra per
// family, selected by family alone" rule has no exception to argue about.
type Family string

const (
	// FamilyDisclosure covers field and response disclosure transforms.
	FamilyDisclosure Family = "disclosure"
	// FamilyApproval covers human approval challenges.
	FamilyApproval Family = "approval"
	// FamilyRouting covers destination and route-property restrictions.
	FamilyRouting Family = "routing"
	// FamilyStepUp covers step-up authentication requirements.
	FamilyStepUp Family = "step_up"
	// FamilyBudget covers budget and quota reservations.
	FamilyBudget Family = "budget"
	// FamilyAuditNotification covers immutable audit and notification.
	FamilyAuditNotification Family = "audit_notification"
	// FamilyPhaseOrdering covers request/response phase dependency ordering.
	// No obligation type declares it; see the type comment.
	FamilyPhaseOrdering Family = "phase_ordering"
)

// AllFamilies is the closed set, in a stable order for tests and traces.
var AllFamilies = []Family{
	FamilyDisclosure,
	FamilyApproval,
	FamilyRouting,
	FamilyStepUp,
	FamilyBudget,
	FamilyAuditNotification,
	FamilyPhaseOrdering,
}

// Type is a registered obligation type. ADR-065 names nine initial types.
type Type string

const (
	// TypeApprovalChallenge holds execution until an approval requirement is
	// discharged. Enterprise enforcement lives in
	// platform/shared/requirements/approval.
	TypeApprovalChallenge Type = "approval_challenge"
	// TypeFieldRedaction transforms named request fields before execution.
	TypeFieldRedaction Type = "field_redaction"
	// TypeSchemaConstrainedTransform applies a declared, schema-validated
	// transform to named fields.
	TypeSchemaConstrainedTransform Type = "schema_constrained_transform"
	// TypeRouteRestriction constrains where a call may be sent.
	TypeRouteRestriction Type = "route_restriction"
	// TypeImmutableAudit requires a tamper-evident audit record.
	TypeImmutableAudit Type = "immutable_audit"
	// TypeNotification requires a notification to be delivered.
	TypeNotification Type = "notification"
	// TypeQuotaReservation requires an atomic budget/quota reservation.
	TypeQuotaReservation Type = "quota_reservation"
	// TypeStepUpAuthentication requires a higher authentication assurance.
	TypeStepUpAuthentication Type = "step_up_authentication"
	// TypeResponseFiltering transforms named response fields before release.
	TypeResponseFiltering Type = "response_filtering"
)

// Enforcement says whether an obligation binds the decision.
//
// The asymmetry is the whole point and it runs both ways: a failed MANDATORY
// obligation denies, and an ADVISORY obligation can never satisfy a mandatory
// requirement nor turn a permit into a deny. Everything that reads this enum
// must branch on it explicitly; there is no "default to mandatory" fallback,
// because a zero-valued Enforcement is a construction defect and Validate
// rejects it rather than guessing in either direction.
type Enforcement string

const (
	// Mandatory obligations bind: unknown, unsupported, conflicting or failed
	// mandatory obligations deny.
	Mandatory Enforcement = "mandatory"
	// Advisory obligations are audit, warning or tuning evidence. They cannot
	// deny and cannot satisfy a mandatory requirement.
	Advisory Enforcement = "advisory"
)

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

// GatesRelease reports whether an obligation in this phase must be complete
// before anything is handed onward.
//
// Both request and response phases gate a release: a request-phase redaction
// gates the call to the connector, a response-phase filter gates the bytes
// returned to the caller. Only out-of-band obligations release nothing, and
// they are exactly the ones that carry a delivery guarantee instead.
func (p Phase) GatesRelease() bool { return p == PhaseRequest || p == PhaseResponse }

// Applicability is the tri-state that closes the source proposal's
// obligations-INDET fail-open.
//
// It is deliberately NOT a bool with a separate error. A bool forces every
// reader to decide what a false-with-error means, and the source proposal's
// answer - "not applicable, carry on" - is the bug. Here `Unknown` is a value
// the planner must handle, and the planner's handling of it for a mandatory
// obligation is Deny.
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

// DeliveryGuarantee is the durability contract for an out-of-band obligation.
type DeliveryGuarantee string

const (
	// DeliveryNone - best effort, no retry, no durable queue.
	DeliveryNone DeliveryGuarantee = "none"
	// DeliveryAtLeastOnceDurable - persisted before acknowledgement and
	// retried until acknowledged.
	DeliveryAtLeastOnceDurable DeliveryGuarantee = "at_least_once_durable"
)

// Rank orders delivery guarantees so the audit/notification algebra can take
// "the strongest required delivery guarantee". This is an ordering WITHIN one
// family over one property, which is exactly what ADR-065 asks for; it is not
// a cross-family severity rank.
func (d DeliveryGuarantee) Rank() int {
	switch d {
	case DeliveryAtLeastOnceDurable:
		return 1
	case DeliveryNone:
		return 0
	}
	return -1
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

// Capability is one obligation type at one exact schema version, as advertised
// by a PEP.
//
// The version is part of the identity, not metadata: a PEP that supports
// field_redaction v1 does not support field_redaction v2, and ADR-065 requires
// the coordinator to prove "the PEP advertises the exact capability and
// version" before permit. Comparable, so it is usable as a map key.
type Capability struct {
	Type    Type
	Version int
}

func (c Capability) String() string { return fmt.Sprintf("%s@v%d", c.Type, c.Version) }

// Obligation is one planned instruction attached to one decision.
//
// Params is family-typed rather than a free map so that composition cannot be
// asked to merge two things it has no algebra for. A nil Params on an
// applicable obligation is a construction defect, not an empty parameter set.
type Obligation struct {
	// Type and Version identify the schema. Both are required; version 0 is
	// not "latest", it is invalid.
	Type    Type
	Version int

	// Enforcement is mandatory or advisory. No default.
	Enforcement Enforcement

	// Applicability is the tri-state from the requirement policy's condition.
	Applicability Applicability
	// ApplicabilityReason is the named cause when Applicability is Unknown
	// (resolution_failed, stale_attribute, schema_mismatch, unevaluable_condition,
	// ...). It is carried into the deny reason and the audit trace so an
	// operator sees WHY the deny happened, which the source proposal's silent
	// drop never produced.
	ApplicabilityReason string

	// SourcePolicyID attributes the obligation to the requirement policy that
	// produced it. Free-form, carried into the trace.
	SourcePolicyID string

	// Params carries the family-typed parameters.
	Params Params
}

// Validate checks the instance-level invariants that hold regardless of
// schema. Schema-level checks live in Registry.Validate.
func (o Obligation) Validate() error {
	if o.Type == "" {
		return fmt.Errorf("obligation: type is required")
	}
	if o.Version <= 0 {
		return fmt.Errorf("obligation %s: version must be >= 1 (0 is not 'latest')", o.Type)
	}
	switch o.Enforcement {
	case Mandatory, Advisory:
	default:
		return fmt.Errorf("obligation %s: enforcement must be %q or %q, got %q (there is no default)",
			o.Type, Mandatory, Advisory, o.Enforcement)
	}
	if !o.Applicability.Valid() {
		return fmt.Errorf("obligation %s: applicability must be one of %q/%q/%q, got %q",
			o.Type, Applicable, NotApplicable, Unknown, o.Applicability)
	}
	if o.Applicability == Unknown && o.ApplicabilityReason == "" {
		return fmt.Errorf("obligation %s: applicability %q requires a named reason", o.Type, Unknown)
	}
	// An applicable obligation must carry parameters. A NotApplicable or
	// Unknown one need not: there was nothing to parameterise, or the
	// condition that would have parameterised it could not be evaluated.
	if o.Applicability == Applicable && o.Params == nil {
		return fmt.Errorf("obligation %s: applicable obligation has nil params", o.Type)
	}
	return nil
}

// Capability returns the exact capability this obligation demands of a PEP.
func (o Obligation) Capability() Capability {
	return Capability{Type: o.Type, Version: o.Version}
}

// Params is the family-typed parameter payload of an obligation.
//
// Family() must agree with the registered schema's family; Registry.Validate
// rejects a mismatch rather than trusting either side. Canonical() renders a
// stable, sorted string used for deduplication and for the obligations digest
// that the decision proof binds - two obligations that differ in any parameter
// must differ in Canonical(), or the proof would bind fewer facts than it
// claims.
type Params interface {
	Family() Family
	Canonical() string
	Validate() error
}

// --- helpers shared by the concrete Params types -------------------------

// sortedUnique returns a sorted, duplicate-free copy of in. Used everywhere a
// collection reaches a digest, because ADR-065 requires collections to be
// "normalized, sorted, and duplicate-free before hashing".
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

// intersect returns the sorted intersection of a and b. A nil slice means
// "unconstrained" to every caller in this package, so the caller - not this
// helper - decides what to do with it; intersect itself treats nil as the
// empty set and callers must not pass nil where unconstrained is meant.
func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(a))
	for _, s := range a {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range b {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return sortedUnique(out)
}

// canonicalKV renders a map as `k=v` pairs joined by `;`, sorted by key. Keys
// and values are rendered verbatim; a key or value containing `;` or `=` would
// be ambiguous, so Validate on each Params type rejects those characters
// rather than escaping them. Ambiguity in a digest input is a collision.
func canonicalKV(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ";")
}

// rejectSeparators refuses map keys/values that would make canonicalKV
// ambiguous. Named separately so the error message can say which field.
func rejectSeparators(what string, m map[string]string) error {
	for k, v := range m {
		if strings.ContainsAny(k, ";=") {
			return fmt.Errorf("%s: key %q contains a canonical separator (';' or '=')", what, k)
		}
		if strings.ContainsAny(v, ";") {
			return fmt.Errorf("%s: value of %q contains a canonical separator (';')", what, k)
		}
	}
	return nil
}
