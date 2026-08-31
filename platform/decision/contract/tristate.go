package contract

import (
	"fmt"
	"sort"
	"time"
)

// AttrState is the tagged state of a policy-visible attribute.
//
// ADR-065 "Explicit tri-state compilation model": native Rego undefined
// behaviour is not AxonFlow's third truth value. The Policy Information Point
// resolves every attribute a policy can reference into exactly one of these
// states before evaluation, so a missing reference can never be interpreted as
// a constraint that did not apply.
type AttrState string

const (
	// StateKnown means the authoritative source returned a value.
	StateKnown AttrState = "known"
	// StateAbsent means the authoritative source successfully established that
	// an optional attribute has no value. Absence is a fact, not a failure.
	StateAbsent AttrState = "absent"
	// StateUnknown means AxonFlow could not establish the value. It always
	// carries a reason.
	StateUnknown AttrState = "unknown"
)

// UnknownReason names why an attribute could not be established. The set is
// closed so that a reason code cannot be invented at a call site and then be
// invisible to the corpus that has to cover every one of them.
type UnknownReason string

const (
	// ReasonNotSupplied is the state of an attribute a policy references that
	// the Policy Information Point never produced at all. This is the reason
	// that must never reach Rego as a bare undefined reference.
	ReasonNotSupplied UnknownReason = "attribute_not_supplied"
	// ReasonResolutionFailed is a resolver, directory or connector failure.
	ReasonResolutionFailed UnknownReason = "resolution_failed"
	// ReasonStale is a value outside the action's declared freshness bound.
	ReasonStale UnknownReason = "stale"
	// ReasonSchemaMismatch is a value whose type does not match the declared
	// attribute schema.
	ReasonSchemaMismatch UnknownReason = "schema_mismatch"
	// ReasonClosureUnavailable is a group or resource graph closure the
	// resolver could not compute at all, for example because the directory or
	// the connector did not answer.
	//
	// It is deliberately DISTINCT from ReasonClosureTruncated even though both
	// are unknown and both propagate identically through the combining rule.
	// The two send an operator to different places: an unavailable closure
	// means go and look at the provider, a truncated one means go and look at
	// the depth and size bounds against a directory that has outgrown them.
	// Collapsing them costs nothing at evaluation time and costs the whole
	// triage during an incident.
	ReasonClosureUnavailable UnknownReason = "closure_unavailable"
	// ReasonClosureTruncated is a group or resource graph closure that hit a
	// depth or size bound mid-walk. A partial closure may be missing the very
	// group or ancestor a constraint is scoped to, so it is never evaluated
	// against.
	ReasonClosureTruncated UnknownReason = "closure_truncated"
	// ReasonMalformedValue is a syntactically present but unusable value, for
	// example a number field carrying a non-numeric JSON value.
	ReasonMalformedValue UnknownReason = "malformed_value"
	// ReasonRequiredAbsent is an attribute the authoritative source reported
	// as having no value, where the attribute schema declares it required.
	//
	// It is distinct from StateAbsent reaching a policy that declared the
	// attribute optional, which is an ordinary NO_MATCH. ADR-065 permits known
	// absence to produce NO_MATCH only where the schema marks the attribute
	// optional and the policy explicitly handles absence; everywhere else the
	// absence of something the schema says must exist is a data defect, and a
	// data defect is not evidence that a constraint does not apply.
	ReasonRequiredAbsent UnknownReason = "required_attribute_absent"
)

// AllUnknownReasons returns every declared reason in a stable order. The
// tri-state corpus enumerates this so that adding a reason without a corpus
// family fails the corpus completeness test rather than going uncovered.
func AllUnknownReasons() []UnknownReason {
	return []UnknownReason{
		ReasonNotSupplied,
		ReasonResolutionFailed,
		ReasonStale,
		ReasonSchemaMismatch,
		ReasonClosureUnavailable,
		ReasonClosureTruncated,
		ReasonMalformedValue,
		ReasonRequiredAbsent,
	}
}

// Attribute is one tagged, provenance-carrying, versioned policy-visible value.
//
// The zero Attribute is invalid on purpose: State is mandatory, so a struct
// that was never populated cannot be mistaken for a resolved attribute.
type Attribute struct {
	State AttrState `json:"state"`
	// Value is set only when State is known.
	Value any `json:"value,omitempty"`
	// Source is the provenance class that produced this value.
	Source Provenance `json:"source"`
	// SourceVersion is the version of the producing source: the directory
	// snapshot a group closure was resolved against, the resource epoch an
	// attribute was fetched at, the registry version an action was read from.
	//
	// It is part of the decision binding. Together with Snapshot.IdentityEpoch,
	// which versions the realm REGISTRY rather than the data it describes, it
	// is what stops a decision replaying clean against membership that has
	// since changed: the two move independently, and binding only one of them
	// leaves the other's staleness invisible.
	SourceVersion int64 `json:"source_version"`
	// ObservedAt is when the value was read from its source.
	ObservedAt time.Time `json:"observed_at"`
	// MaxAgeSeconds is the action's declared freshness bound. Zero means no
	// bound is declared for this attribute.
	MaxAgeSeconds int64 `json:"max_age_seconds,omitempty"`
	// Reason is set only when State is unknown.
	Reason UnknownReason `json:"reason,omitempty"`
}

// Known builds a resolved attribute.
func Known(value any, src Provenance, version int64, observedAt time.Time) Attribute {
	return Attribute{State: StateKnown, Value: value, Source: src, SourceVersion: version, ObservedAt: observedAt}
}

// Absent builds an authoritatively empty attribute.
func Absent(src Provenance, version int64, observedAt time.Time) Attribute {
	return Attribute{State: StateAbsent, Source: src, SourceVersion: version, ObservedAt: observedAt}
}

// Unknown builds an unresolvable attribute with a named reason.
func Unknown(reason UnknownReason, src Provenance, version int64, observedAt time.Time) Attribute {
	return Attribute{State: StateUnknown, Reason: reason, Source: src, SourceVersion: version, ObservedAt: observedAt}
}

// Validate rejects any attribute whose state and payload disagree.
func (a Attribute) Validate(path string) error {
	if err := a.Source.Validate(); err != nil {
		return fmt.Errorf("attribute %q: %w", path, err)
	}
	switch a.State {
	case StateKnown:
		if a.Value == nil {
			return fmt.Errorf("attribute %q: state known with no value", path)
		}
		if a.Reason != "" {
			return fmt.Errorf("attribute %q: state known must not carry reason %q", path, a.Reason)
		}
	case StateAbsent:
		if a.Value != nil {
			return fmt.Errorf("attribute %q: state absent must not carry a value", path)
		}
		if a.Reason != "" {
			return fmt.Errorf("attribute %q: state absent must not carry reason %q", path, a.Reason)
		}
	case StateUnknown:
		if a.Value != nil {
			return fmt.Errorf("attribute %q: state unknown must not carry a value", path)
		}
		if a.Reason == "" {
			return fmt.Errorf("attribute %q: state unknown requires a reason", path)
		}
		if !validUnknownReason(a.Reason) {
			return fmt.Errorf("attribute %q: unknown reason %q is not a declared reason code", path, a.Reason)
		}
	case "":
		return fmt.Errorf("attribute %q: state is required", path)
	default:
		return fmt.Errorf("attribute %q: state %q is not a declared state", path, a.State)
	}
	if a.MaxAgeSeconds < 0 {
		return fmt.Errorf("attribute %q: max_age_seconds must not be negative", path)
	}
	return nil
}

func validUnknownReason(r UnknownReason) bool {
	for _, known := range AllUnknownReasons() {
		if known == r {
			return true
		}
	}
	return false
}

// AtFreshness applies the declared freshness bound, returning the attribute the
// PDP must actually see at evaluation time.
//
// ADR-065: "An attribute outside its freshness bound is unknown." Applying it
// here rather than at every call site is what stops a last-known-good value
// from being used past its bound by whichever caller forgot to check. Absent
// and already-unknown attributes pass through: absence does not go stale, and
// an unknown attribute keeps its original, more specific reason.
func (a Attribute) AtFreshness(now time.Time) Attribute {
	if a.State != StateKnown || a.MaxAgeSeconds <= 0 {
		return a
	}
	if a.ObservedAt.IsZero() {
		// A known value with a declared bound and no observation time cannot
		// be shown to be inside its bound, so it is not.
		out := a
		out.State = StateUnknown
		out.Value = nil
		out.Reason = ReasonStale
		return out
	}
	// A value observed AFTER the evaluation instant cannot be shown to be
	// inside its bound either: the subtraction is negative and would pass every
	// comparison, so a clock ahead of the evaluator would make a value
	// permanently fresh. It is the same un-establishable condition as a missing
	// observation time, and gets the same answer.
	if a.ObservedAt.After(now) || now.Sub(a.ObservedAt) > time.Duration(a.MaxAgeSeconds)*time.Second {
		out := a
		out.State = StateUnknown
		out.Value = nil
		out.Reason = ReasonStale
		return out
	}
	return a
}

// AttributeSet is the complete, flat, namespace-keyed surface a policy may
// read. Keys are dotted paths whose first segment is a declared namespace, for
// example "principal.id", "resource.project.classification", "args.amount_cents".
//
// It is flat rather than nested so that the set of paths a bundle references
// can be enumerated statically, which is what makes the tri-state corpus
// generator able to produce a missing, absent, stale, malformed and
// resolver-failed variant for every referenced attribute.
type AttributeSet map[string]Attribute

// Paths returns the attribute paths in sorted order.
func (s AttributeSet) Paths() []string {
	out := make([]string, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Validate checks every attribute and every path.
func (s AttributeSet) Validate() error {
	for _, p := range s.Paths() {
		if err := ValidateAttributePath(p); err != nil {
			return err
		}
		if err := s[p].Validate(p); err != nil {
			return err
		}
		if err := NamespaceOf(p).ValidateProvenance(p, s[p].Source); err != nil {
			return err
		}
	}
	return nil
}

// AtFreshness returns a copy of the set with the freshness bound applied to
// every attribute.
func (s AttributeSet) AtFreshness(now time.Time) AttributeSet {
	out := make(AttributeSet, len(s))
	for p, a := range s {
		out[p] = a.AtFreshness(now)
	}
	return out
}

// Lookup returns the attribute at path, or an unknown attribute with reason
// attribute_not_supplied when the Policy Information Point produced nothing.
//
// This is the single place a policy-visible read can miss, and it is why a
// miss is a tagged unknown rather than a Go zero value or a Rego undefined.
func (s AttributeSet) Lookup(path string) Attribute {
	if a, ok := s[path]; ok {
		return a
	}
	return Attribute{
		State:  StateUnknown,
		Source: NamespaceOf(path).DefaultProvenance(),
		Reason: ReasonNotSupplied,
	}
}
