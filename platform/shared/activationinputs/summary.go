// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs

import (
	"context"
	"errors"
	"fmt"
	"slices"

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
	// document that binds on the scope (NotBoundHere lists the rest), the
	// shipped controls that document re-actions, and the
	// replacements its recorded detection overrides carry
	// (activation.CountEffects says why an override counts here).
	Organization int `json:"organization"`
	// Pack is how many policies the deployment's installed policy packs carry
	// on the scope. It is nil when PacksCounted is false: unknown, not zero.
	Pack *int `json:"pack"`
	// PacksCounted says whether the activation counted carried the
	// deployment's installed policy packs.
	PacksCounted bool `json:"packs_counted"`
	// PacksUncountedReason says why the packs were not counted, one of the
	// PacksUncounted* values, and is omitted when they were. Only the agent
	// loads a deployment's packs, so a summary served elsewhere counts them by
	// reading the agent's (AgentSummaryPath); this names why that read failed.
	PacksUncountedReason string `json:"packs_uncounted_reason,omitempty"`
	// Disabled is how many policies of the shipped controls the organization's
	// document disabled on the scope; one control can bind several policies.
	// The engine does not carry them, so Total does not count them.
	Disabled int `json:"disabled"`
	// Total is Shipped + Organization, plus Pack when packs are counted.
	Total int `json:"total"`
	// NotBoundHere names the organization's controls left out of this scope, so
	// neither counted nor enforced here, in the document's order: those whose
	// binds_on does not name it (#4371), and those that read a registry
	// detector this scope does not run (#4249 row 5674230432), which
	// DetectorNotRunHere names again with the detector. Omitted when there are
	// none, which is every summary of a document that scopes nothing and reads
	// no detector, so such a summary is byte-identical to what it was.
	NotBoundHere []string `json:"not_bound_here,omitempty"`
	// DetectorNotRunHere names, per control, the registry detector this scope
	// does not run and the planes that do. Every id here is also in
	// NotBoundHere, which is the one list an operator reads for "what is not
	// enforced here"; this one answers "why, and where it is". Omitted when
	// there are none.
	DetectorNotRunHere []DetectorNotRun `json:"detector_not_run_here,omitempty"`
}

// DetectorNotRun is one control left off this scope because the scope does not
// run a registry detector it reads (#4249 row 5674230432).
type DetectorNotRun struct {
	ID       string   `json:"id"`
	Detector string   `json:"detector"`
	RunsOn   []string `json:"runs_on"`
}

// The reasons a summary served away from the agent could not count the
// installed policy packs (Summary.PacksUncountedReason).
const (
	// PacksUncountedAgentUnreachable: the agent's summary could not be reached.
	PacksUncountedAgentUnreachable = "agent_unreachable"
	// PacksUncountedAgentRefused: the agent answered, but not with a summary
	// (a non-2xx status).
	PacksUncountedAgentRefused = "agent_refused"
	// PacksUncountedAgentAnswerUnreadable: the agent answered 2xx with a body
	// that is not a summary of the scope asked for.
	PacksUncountedAgentAnswerUnreadable = "agent_answer_unreadable"
)

// AgentSummaryPath is the agent's summary of what it enforces on the decide
// scope, installed policy packs included: GET, the internal-service
// credential (serviceauth.ServiceIDHeader and ServiceTokenHeader), and the
// organization in X-Org-ID. The internal-service security scheme, not the
// path, is what makes it internal. It is deliberately NOT under
// /api/v1/typed-policies, which the agent forwards whole to the orchestrator
// (platform/agent/proxy.go): there it would either shadow the tenant summary
// route with a 401, or send the orchestrator's read back to the orchestrator,
// which would count no packs and say nothing.
const AgentSummaryPath = "/api/v1/policy-packs/summary"

// ErrNoInputs is ActiveSummary's refusal on a surface that builds no
// activation inputs, because it has no deployment vocabulary to build them
// from.
var ErrNoInputs = errors.New("activationinputs: this surface builds no activation inputs, so what is active cannot be counted")

// activate is ActiveSummary's call out, a variable so a test can observe what is
// asked of it.
var activate = activation.Activate

// ActiveSummary activates what is in force on one organization and counts it:
// the same activation ActiveEffects lists (activeActivation), so the counts a
// summary states are the counts of the effects a report reads.
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
// none, so this count leaves Pack nil and PacksCounted false; the orchestrator's
// and the portal's routes then read the agent's own count (WithAgentPacks,
// AgentSummaryPath), which is the activation the agent enforces.
func ActiveSummary(ctx context.Context, inputs func(context.Context) (activation.Inputs, error), active *authoring.Artifact, enforcesConstructBoundary bool) (Summary, error) {
	act, in, err := activeActivation(ctx, inputs, active, enforcesConstructBoundary)
	if err != nil {
		return Summary{}, err
	}
	return SummaryOf(act, scopeOf(in), len(in.Packs) > 0)
}

// SummaryOf counts an activation's policies on scope. packsCounted says the
// activation was built with the deployment's installed packs, so its pack
// count is the deployment's: true on the agent, which loads them (even when it
// loads none, which is then a counted zero), and true elsewhere only when the
// inputs carried them. An uncounted summary whose activation nonetheless holds
// pack policies is refused rather than answered with a pack count it says it
// did not take.
func SummaryOf(act *activation.Activation, scope legacycompile.EnforcementScope, packsCounted bool) (Summary, error) {
	counts, err := activation.CountEffects(act.PolicyEffects())
	if err != nil {
		return Summary{}, err
	}
	s := Summary{
		Scope:        scope.String(),
		Shipped:      counts.Shipped,
		Organization: counts.Organization,
		Disabled:     counts.Disabled,
		Total:        counts.Shipped + counts.Organization,
		NotBoundHere: slices.Clone(act.ScopeUnboundControls),
	}
	for _, c := range act.DetectorUnboundControls {
		s.NotBoundHere = append(s.NotBoundHere, c.ID)
		s.DetectorNotRunHere = append(s.DetectorNotRunHere, DetectorNotRun{ID: c.ID, Detector: c.Detector, RunsOn: slices.Clone(c.Planes)})
	}
	if packsCounted {
		pack := counts.Pack
		s.Pack, s.PacksCounted, s.Total = &pack, true, counts.Total()
	} else if counts.Pack != 0 {
		return Summary{}, fmt.Errorf("activationinputs: %d pack policies are active on %s with no installed pack in the inputs", counts.Pack, scope)
	}
	return s, nil
}
