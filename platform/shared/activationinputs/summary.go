// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs

import (
	"context"
	"errors"
	"fmt"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
)

// Summary is how many policies an organization's activation enforces on one
// scope, and whose each is (#4152). It is what GET
// /api/v1/typed-policies/active/summary answers on the orchestrator and on the
// portal, and what the portal dashboard's Total Policies tile shows.
type Summary struct {
	// Scope is the enforcement scope counted. An activation is per scope, and a
	// sum across scopes would count a policy once for every scope it binds on,
	// so the summary counts one scope and names it.
	Scope string `json:"scope"`
	// Shipped is what the platform ships: the system controls the scope binds,
	// the baseline permissions the organization's document does not carry, and,
	// while no document is active, the organization template's controls.
	Shipped int `json:"shipped"`
	// Organization is the organization's own: every policy of its published
	// document, the shipped controls that document re-actions, and the
	// replacements its recorded detection overrides carry
	// (activation.CountEffects says why an override counts here).
	Organization int `json:"organization"`
	// Pack is how many policies the deployment's installed policy packs carry
	// on the scope. It is nil when PacksCounted is false: unknown, not zero.
	Pack *int `json:"pack"`
	// PacksCounted says whether the activation counted carried the
	// deployment's installed policy packs.
	PacksCounted bool `json:"packs_counted"`
	// Disabled is how many policies of the shipped controls the organization's
	// document disabled on the scope; one control can bind several policies.
	// The engine does not carry them, so Total does not count them.
	Disabled int `json:"disabled"`
	// Total is Shipped + Organization, plus Pack when packs are counted.
	Total int `json:"total"`
}

// ErrNoInputs is ActiveSummary's refusal on a surface that builds no
// activation inputs, because it has no deployment vocabulary to build them
// from.
var ErrNoInputs = errors.New("activationinputs: this surface builds no activation inputs, so what is active cannot be counted")

// activate is ActiveSummary's call out, a variable so a test can observe what is
// asked of it.
var activate = activation.Activate

// ActiveSummary activates what is in force on one organization and counts it.
// inputs are the organization's activation inputs for one scope (Builder.Source,
// the same ones its typed-authoring workspace dry-runs with), and active is the
// artifact active on the organization root, nil when nothing is active: the
// organization root is then the implicit baseline, as it is at the agent's
// enforcing seam.
//
// THE EDITION BOUNDARY IS GATED AS THE ENFORCING SEAM GATES IT. A workspace's
// dry-run inputs refuse a construct outside the edition unconditionally,
// because there the refusal is a sentence an author reads. A summary reports
// what is enforced, and the agent refuses such a document only where
// authoringedition's EnforcesConstructBoundary says it may. A summary that
// refused wherever the dry run does would fail on a deployment in a declared
// licence transition while the agent is still enforcing, so this is the one
// input the summary does not take from the workspace.
//
// enforcesConstructBoundary is that answer, and the CALLER asks it:
// authoringedition.Resolve(ctx).EnforcesConstructBoundary(), the question the
// seam asks. Resolving an edition belongs to the deployed process whose licence
// it reads (authoringedition's deployment guard, #3956), and this package runs
// in more than one.
//
// THE INSTALLED POLICY PACKS ARE COUNTED ONLY WHEN THE INPUTS CARRY THEM. The
// agent alone loads a deployment's packs (platform/agent/policy_packs.go): the
// Enterprise agent image is the only one that carries the pack files, and the
// agent's service is the only one given AXONFLOW_POLICY_PACKS. Builder carries
// none, so on both routes Pack is nil and PacksCounted false.
func ActiveSummary(ctx context.Context, inputs func(context.Context) (activation.Inputs, error), active *authoring.Artifact, enforcesConstructBoundary bool) (Summary, error) {
	if inputs == nil {
		return Summary{}, ErrNoInputs
	}
	in, err := inputs(ctx)
	if err != nil {
		return Summary{}, err
	}
	in.Organization = active
	in.RefuseConstructsOutsideEdition = enforcesConstructBoundary
	act, err := activate(ctx, in)
	if err != nil {
		return Summary{}, err
	}
	counts, err := activation.CountEffects(act.PolicyEffects())
	if err != nil {
		return Summary{}, err
	}
	scope := legacycompile.EnforcementScope{Plane: legacycompile.Plane(in.Plane), Phase: in.Phase}
	s := Summary{
		Scope:        scope.String(),
		Shipped:      counts.Shipped,
		Organization: counts.Organization,
		Disabled:     counts.Disabled,
		Total:        counts.Shipped + counts.Organization,
	}
	if len(in.Packs) > 0 {
		pack := counts.Pack
		s.Pack, s.PacksCounted, s.Total = &pack, true, counts.Total()
	} else if counts.Pack != 0 {
		return Summary{}, fmt.Errorf("activationinputs: %d pack policies are active on %s with no installed pack in the inputs", counts.Pack, scope)
	}
	return s, nil
}
