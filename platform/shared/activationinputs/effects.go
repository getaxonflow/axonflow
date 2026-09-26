// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs

import (
	"context"
	"strings"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
)

// EffectsFunc is what a report that states which controls are in force for an
// organization is handed: the policies the organization's activation enforces
// on one scope (activation.PolicyEffects), and the shipped controls its
// document disabled there. The orchestrator supplies it from its typed
// authoring workspace (ActiveEffects), so a compliance report reads what is
// active exactly as GET /api/v1/typed-policies/active/summary counts it, and
// never the legacy policy tables (#4249).
type EffectsFunc func(ctx context.Context, orgID string, plane legacycompile.Plane, phase legacycompile.Phase) ([]activation.PolicyEffect, error)

// ActiveEffects activates what is in force on one organization for the scope
// its inputs name and returns what that activation enforces there, with the
// scope. It is the one activation a report of "what is active" reads:
// ActiveSummary counts the same activation (activeActivation), so a count and
// a listing cannot disagree. inputs, active and enforcesConstructBoundary are
// as ActiveSummary documents them.
func ActiveEffects(ctx context.Context, inputs func(context.Context) (activation.Inputs, error), active *authoring.Artifact, enforcesConstructBoundary bool) (legacycompile.EnforcementScope, []activation.PolicyEffect, error) {
	act, in, err := activeActivation(ctx, inputs, active, enforcesConstructBoundary)
	if err != nil {
		return legacycompile.EnforcementScope{}, nil, err
	}
	return scopeOf(in), act.PolicyEffects(), nil
}

// activeActivation is the one activation ActiveEffects and ActiveSummary read:
// the organization's inputs for one scope, with the active artifact and the
// edition gate the enforcing seam applies.
func activeActivation(ctx context.Context, inputs func(context.Context) (activation.Inputs, error), active *authoring.Artifact, enforcesConstructBoundary bool) (*activation.Activation, activation.Inputs, error) {
	if inputs == nil {
		return nil, activation.Inputs{}, ErrNoInputs
	}
	in, err := inputs(ctx)
	if err != nil {
		return nil, activation.Inputs{}, err
	}
	in.Organization = active
	in.RefuseConstructsOutsideEdition = enforcesConstructBoundary
	act, err := activate(ctx, in)
	if err != nil {
		return nil, activation.Inputs{}, err
	}
	return act, in, nil
}

// scopeOf is the enforcement scope an activation's inputs name.
func scopeOf(in activation.Inputs) legacycompile.EnforcementScope {
	return legacycompile.EnforcementScope{Plane: legacycompile.Plane(in.Plane), Phase: in.Phase}
}

// Tier values a report states for a policy. They are the same strings as the
// legacy policy tiers, platform/agent.TierSystem, TierTenant and
// TierOrganization (policy_categories.go), the sibling vocabulary: a rename in
// either must move the other.
const (
	TierSystem       = "system"
	TierTenant       = "tenant"
	TierOrganization = "organization"
)

// TierOf is the tier a report states for a policy in force. A shipped control
// states the tier the shipped detector census records for it (PolicyEffect.Tier:
// `system` or `tenant`, registry.CensusRow.Tier), and `system` for a shipped
// control the census does not list or tiers with any other value (an
// unrecognised census value is never printed). Every other policy - the organization's
// own, a pack's - is `organization`. The census tier reaches the effect the way
// its category and severity do, so a report prints no tier the census does not
// record (#4249).
func TierOf(e activation.PolicyEffect) string {
	if e.Source != activation.SourceShipped {
		return TierOrganization
	}
	// Allow-listed: a census value that is neither tier is not printed verbatim
	// into a report; it reads as a shipped control with no census row does.
	switch t := strings.ToLower(strings.TrimSpace(e.Tier)); t {
	case TierSystem, TierTenant:
		return t
	}
	return TierSystem
}

// Scope values a report states for whose a policy is.
const (
	ScopeDeployment   = "deployment"
	ScopeOrganization = "organization"
)

// ScopeOf is whose a policy in force is, the one derivation of the Source split
// a report states beside TierOf: a shipped control is the deployment's, and
// every other policy - the organization's own, a pack's - is the
// organization's.
func ScopeOf(e activation.PolicyEffect) string {
	if e.Source == activation.SourceShipped {
		return ScopeDeployment
	}
	return ScopeOrganization
}

// ControlKey is the identity a report counts a policy in force by: the shipped
// control it IS or REPLACES (activation.PolicyEffect.Control), or, for a policy
// with no control (the organization's own, a pack's, a baseline permission),
// its policy id.
//
// A COUNT ACROSS SCOPES MUST KEY ON THIS, NEVER ON THE POLICY ID. A shipped
// control that resolves a different action per scope ships as one policy per
// action (legacycompile.CorpusVariantIDFor: control + ":" + action), so the same
// control carries a different policy id on each scope - sys_pii_pan is
// ...:warn on proxy_request and ...:redact on orchestrator_response - and a
// union by policy id counts it once per scope (#4249, #4401's slot run).
func ControlKey(e activation.PolicyEffect) string {
	if e.Control != "" {
		return e.Control
	}
	return e.PolicyID
}
