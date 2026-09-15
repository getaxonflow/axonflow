// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// PolicyReplacement says what carries a policy on the organization root in
// place of a shipped control.
type PolicyReplacement string

const (
	// ReplacementOverride is a recorded detection override's replacement
	// (#4045): the organization re-actioned the control's category. It is
	// shipped on the wire (see SourceShipped), because it has no published
	// version and the bundle digest identifies it.
	ReplacementOverride PolicyReplacement = "override"
	// ReplacementSystemControl is the replacement the organization's document
	// names in its system_controls (PRD v11 §1.5), at the document's version.
	ReplacementSystemControl PolicyReplacement = "system_control"
)

// PolicyEffect is one policy of an activation as the engine enforces it on the
// activation's scope, or one shipped control the organization's document
// disabled there.
type PolicyEffect struct {
	PolicyID string
	// Name is the policy's display name, empty when it declares none.
	Name string
	// Source and Version are what Identity names the policy by on the wire and
	// on the audit row. A disabled control is shipped, at no version.
	Source  PolicySource
	Version int
	// Control is the shipped control this policy is or replaces
	// (legacycompile.CorpusControlOf), and empty for a policy that is neither:
	// an organization's own policy, a pack's, or a baseline permission.
	Control string
	// Replacement is what carries the policy in place of Control, and empty
	// for a policy that replaces nothing.
	Replacement PolicyReplacement
	// Action is the legacy action the policy enforces
	// (legacycompile.LegacyActionOf), and empty for a policy whose shape no
	// legacy action has, which Authority then names. For a disabled control it
	// is the action the control enforced before it was disabled.
	Action    legacycompile.LegacyAction
	Authority contract.Authority
	// Disabled is true for a shipped control the organization's document
	// disabled on this scope. The engine does not carry it.
	Disabled bool
	// Category and Severity are the shipped detector census's for a policy that
	// reads a censused detector, and otherwise what the policy's own obligation
	// records. Both are empty when neither says, as for a pattern control that
	// blocks.
	Category string
	Severity string
}

// PolicyEffects lists every policy this activation enforces on its scope, and
// every shipped control the organization's document disabled there, sorted by
// policy id. It is what a summary of the active bundle reads: whose each policy
// is, what it enforces, and what it replaces.
//
// An Activation is per scope, so a plane that evaluates two phases has one list
// per phase.
func (a *Activation) PolicyEffects() []PolicyEffect {
	if a == nil {
		return nil
	}
	out := make([]PolicyEffect, 0, len(a.policies)+len(a.disabled))
	for id, p := range a.policies {
		identity, _ := a.Identity(id)
		e := a.effectOf(p)
		e.Name, e.Source, e.Version = identity.Name, identity.Source, identity.Version
		out = append(out, e)
	}
	for _, p := range a.disabled {
		e := a.effectOf(p)
		e.Name, e.Source, e.Disabled = p.Name, SourceShipped, true
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PolicyID < out[j].PolicyID })
	return out
}

// effectOf reads what one policy enforces and which shipped control it is or
// replaces. Identity's fields are the caller's to set.
func (a *Activation) effectOf(p pdp.Policy) PolicyEffect {
	e := PolicyEffect{PolicyID: p.ID, Authority: p.Authority}
	shipped := p.ID
	switch {
	case strings.HasPrefix(p.ID, OverridePolicyIDPrefix):
		shipped, e.Replacement = strings.TrimPrefix(p.ID, OverridePolicyIDPrefix), ReplacementOverride
	case strings.HasPrefix(p.ID, OrganizationControlPolicyIDPrefix):
		shipped, e.Replacement = strings.TrimPrefix(p.ID, OrganizationControlPolicyIDPrefix), ReplacementSystemControl
	}
	if control, _, isCorpus := legacycompile.CorpusControlOf(shipped); isCorpus {
		e.Control = control
	}
	e.Action, e.Category, e.Severity, _ = legacycompile.LegacyActionOf(p)
	if _, fact, censused := censusFactFor(p, a.census); censused {
		e.Category, e.Severity = fact.category, fact.severity
	}
	return e
}
