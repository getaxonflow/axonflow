// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

// THE DECISION-NAMING HELPERS: how every seam that names an anchored decision
// names what decided it (PRD v11 §1.13, §1.14), so the wire and the audit row
// agree on every plane and in every process.

import (
	"fmt"
	"strings"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// ApprovalRequiredReason is how a plane with no approval hold answers the
// engine's challenge (PRD v11 §1.13): the reason code first, then the plane,
// so a caller can tell a missing approval from a policy refusal. It is one
// sentence for every such plane, because the ruling is one rule.
func ApprovalRequiredReason(scope legacycompile.EnforcementScope) string {
	return fmt.Sprintf("%s: the policy engine requires an approval, and the %s plane has no approval hold, so it is refused rather than held (PRD v11 §1.13)",
		contract.ReasonApprovalRequired, scope)
}

// UnknownConstraints is what an unknown_constraint refusal could not evaluate,
// the binding constraint first (#4227). The binding constraint is the one the
// combining rule names in the trace; the rest follow in Determining's canonical
// order, which sorts by policy id, the order the rule picks the smallest id
// from, so with no trace the first is still the binding one. Every other
// decision names none: Unknown is kept in diagnostics even when a determinate
// policy decided, and then that policy is what decided it.
func UnknownConstraints(dec *contract.Decision) []contract.UnknownPolicy {
	if dec.Reason != contract.ReasonUnknownConstraint {
		return nil
	}
	binding := ""
	if dec.Trace != nil {
		binding = dec.Trace.BindingPolicy
	}
	var first, rest []contract.UnknownPolicy
	for _, u := range dec.Determining.Unknown {
		switch {
		case u.Authority != contract.AuthorityConstraint:
		case u.PolicyID == binding && len(first) == 0:
			first = append(first, u)
		default:
			rest = append(rest, u)
		}
	}
	return append(first, rest...)
}

// DecidingPolicies is what an anchored decision names as having decided it, in
// order: on an indeterminate deny the constraints it could not evaluate,
// binding first, then what matched (PRD v11 §1.14). Every seam that names a
// decision's policies reads it, so the wire and the audit row agree.
func DecidingPolicies(dec *contract.Decision) []string {
	return append(unknownConstraintIDs(UnknownConstraints(dec)), EvaluatedPolicies(dec.Determining)...)
}

func unknownConstraintIDs(unknown []contract.UnknownPolicy) []string {
	out := make([]string, 0, len(unknown))
	for _, u := range unknown {
		out = append(out, u.PolicyID)
	}
	return out
}

// BlockingConstraint is the constraint a refusal names as blocking: the first
// that matched, else the binding constraint an unknown_constraint refusal
// could not evaluate; empty when no constraint decided.
func BlockingConstraint(d contract.Determining, unknown []contract.UnknownPolicy) string {
	if len(d.MatchedConstraints) > 0 {
		return d.MatchedConstraints[0]
	}
	if len(unknown) > 0 {
		return unknown[0].PolicyID
	}
	return ""
}

// UnknownConstraintReasons names each constraint an unknown_constraint refusal
// could not evaluate: whose it is, the version it was published at, why, and
// the attributes it could not establish (PRD v11 §1.14), as
// "<id> (<source>[, version]) could not be evaluated: <why>", the why naming the
// attributes.
func UnknownConstraintReasons(act *activation.Activation, unknown []contract.UnknownPolicy) []string {
	out := make([]string, 0, len(unknown))
	for _, u := range unknown {
		p, _ := act.Identity(u.PolicyID)
		out = append(out, UnknownConstraintReason(p, u))
	}
	return out
}

// UnknownConstraintReason is one constraint's reason. An id the activation did
// not activate carries no source, so it is named by its identifier alone.
func UnknownConstraintReason(p activation.PolicyIdentity, u contract.UnknownPolicy) string {
	named := p.ID
	switch {
	case p.Source == activation.SourceOrganization && p.Version > 0:
		named += fmt.Sprintf(" (%s, document version %d)", p.Source, p.Version)
	case p.Source == activation.SourcePack && p.Version > 0:
		named += fmt.Sprintf(" (%s, version %d)", p.Source, p.Version)
	case p.Source != "":
		named += fmt.Sprintf(" (%s)", p.Source)
	}
	attributes := "an attribute it reads"
	if len(u.Paths) > 0 {
		attributes = strings.Join(u.Paths, ", ")
	}
	return fmt.Sprintf("%s could not be evaluated: %s", named, fmt.Sprintf(UnknownReasonPhrase(u.Reason), attributes))
}

// UnknownReasonPhrase says why a policy could not be evaluated, as a format
// taking the attributes it could not establish, worded to read for one
// attribute or several. A value not supplied is not always the caller's: a
// detector signal is supplied by the detector pass, so the words name no
// supplier. A constraint unknown for several causes is reported under the
// engine's first cause, with every attribute it could not establish.
// TestEveryUnknownReasonHasItsOwnPhrase holds it to the declared reasons.
func UnknownReasonPhrase(r contract.UnknownReason) string {
	switch r {
	case contract.ReasonNotSupplied:
		return "no value was supplied for %s"
	case contract.ReasonResolutionFailed:
		return "%s could not be resolved"
	case contract.ReasonStale:
		return "%s could not be read within the freshness bound"
	case contract.ReasonSchemaMismatch:
		return "%s did not match the declared type"
	case contract.ReasonClosureUnavailable:
		return "the group or resource closure behind %s could not be computed"
	case contract.ReasonClosureTruncated:
		return "the group or resource closure behind %s hit its depth or size bound"
	case contract.ReasonMalformedValue:
		return "%s carried an unusable value"
	case contract.ReasonRequiredAbsent:
		return "no value was supplied for %s, which the document requires"
	}
	return "%s could not be established"
}

// EvaluatedPolicies lists the policies that MATCHED, the blocking
// constraint first - the contract evaluated_policies already carries.
func EvaluatedPolicies(d contract.Determining) []string {
	out := []string{}
	for _, set := range [][]string{d.MatchedConstraints, d.MatchedRequirement, d.MatchedInspections, d.MatchedPermissions} {
		out = append(out, set...)
	}
	return out
}
