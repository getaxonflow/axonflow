// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs_test

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/registry"
	"axonflow/platform/shared/activationinputs"
)

// The summary's counts ARE the counts of the effects ActiveEffects lists for
// the same activation, on every scope a report reads, so the dashboard's Total
// Policies tile and a compliance report cannot disagree (#4249). The posture
// carries a recorded override, so the organization's count is not zero and the
// equality is not the trivial one.
func TestTheSummaryCountsTheEffectsActiveEffectsLists(t *testing.T) {
	ctx := context.Background()
	b := deploymentBuilder(t)
	b.Posture = func(context.Context, string) (legacycompile.CategoryActions, error) {
		return legacycompile.CategoryActions{"pii-us": legacycompile.ActionRedact}, nil
	}
	sawOrganization := false
	for _, sc := range []struct {
		plane legacycompile.Plane
		phase legacycompile.Phase
	}{
		{legacycompile.PlaneDecide, ""},
		{legacycompile.PlaneProxyRequest, ""},
		{legacycompile.PlaneOrchestratorResponse, ""},
		{legacycompile.PlaneMCP, legacycompile.PhaseRequest},
		{legacycompile.PlaneMCP, legacycompile.PhaseResponse},
	} {
		inputs := b.Source(sc.plane, sc.phase)
		summary, err := activationinputs.ActiveSummary(ctx, inputs, nil, false)
		if err != nil {
			t.Fatalf("%s/%s summary: %v", sc.plane, sc.phase, err)
		}
		scope, effects, err := activationinputs.ActiveEffects(ctx, inputs, nil, false)
		if err != nil {
			t.Fatalf("%s/%s effects: %v", sc.plane, sc.phase, err)
		}
		counts, err := activation.CountEffects(effects)
		if err != nil {
			t.Fatal(err)
		}
		if scope.String() != summary.Scope {
			t.Errorf("the effects are for %q, the summary for %q", scope, summary.Scope)
		}
		if summary.Shipped != counts.Shipped || summary.Organization != counts.Organization || summary.Disabled != counts.Disabled || summary.Total != counts.Shipped+counts.Organization {
			t.Errorf("%s: summary %+v; the effects count %+v", summary.Scope, summary, counts)
		}
		if counts.Shipped == 0 {
			t.Errorf("PREMISE: %s lists no shipped policy, so the equality proves nothing", summary.Scope)
		}
		sawOrganization = sawOrganization || counts.Organization > 0
	}
	if !sawOrganization {
		t.Fatal("PREMISE: the recorded override counted as the organization's on no scope, so the organization arm is untested")
	}
}

// ActiveEffects refuses as ActiveSummary does: no inputs is ErrNoInputs, and
// an inputs error is returned, never an empty listing.
func TestActiveEffectsRefusesWithoutInputsAndReturnsTheirError(t *testing.T) {
	ctx := context.Background()
	if _, effects, err := activationinputs.ActiveEffects(ctx, nil, nil, false); !errors.Is(err, activationinputs.ErrNoInputs) || effects != nil {
		t.Fatalf("no inputs listed %d effects with error %v; want ErrNoInputs", len(effects), err)
	}
	b := deploymentBuilder(t)
	unreadable := errors.New("planted: the recorded posture could not be read")
	b.Posture = func(context.Context, string) (legacycompile.CategoryActions, error) { return nil, unreadable }
	if _, effects, err := activationinputs.ActiveEffects(ctx, b.Source(legacycompile.PlaneDecide, ""), nil, false); !errors.Is(err, unreadable) || effects != nil {
		t.Fatalf("an unreadable posture listed %d effects with error %v; want it returned", len(effects), err)
	}
}

// The tier a report states, one arm each: a shipped control states the tier
// its census row records, `system` when the census does not list it; every
// other source is the organization's.
func TestTierOfStatesTheCensusTierOfAShippedControl(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    activation.PolicyEffect
		want string
	}{
		{"shipped, census tenant", activation.PolicyEffect{Source: activation.SourceShipped, Tier: "tenant"}, activationinputs.TierTenant},
		{"shipped, census system", activation.PolicyEffect{Source: activation.SourceShipped, Tier: "system"}, activationinputs.TierSystem},
		{"shipped, not in the census", activation.PolicyEffect{Source: activation.SourceShipped}, activationinputs.TierSystem},
		{"shipped, census tier spelled loosely", activation.PolicyEffect{Source: activation.SourceShipped, Tier: " Tenant "}, activationinputs.TierTenant},
		{"shipped, an unrecognised census tier is never printed", activation.PolicyEffect{Source: activation.SourceShipped, Tier: "platinum"}, activationinputs.TierSystem},
		{"the organization's own", activation.PolicyEffect{Source: activation.SourceOrganization, Tier: "tenant"}, activationinputs.TierOrganization},
		{"a pack's", activation.PolicyEffect{Source: activation.SourcePack}, activationinputs.TierOrganization},
	} {
		if got := activationinputs.TierOf(tc.e); got != tc.want {
			t.Errorf("%s: TierOf = %q; want %q", tc.name, got, tc.want)
		}
	}
}

// censusTenantRows is how many rows the shipped detector census tiers
// `tenant` at this tree. If the census changes, this is where it is learned.
const censusTenantRows = 31

// The census tier reaches a report END TO END: through the real census, a real
// activation and ActiveEffects, every shipped control the census tiers
// `tenant` reads `tenant`, and every one it tiers `system` reads `system`, on
// the proxy request plane the US securities inventory lists. The census's own
// tenant count is pinned beside it.
func TestTheCensusTierReachesTheReportThroughActiveEffects(t *testing.T) {
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	wantTier := map[string]string{}
	tenant := 0
	for _, r := range rows {
		wantTier[legacycompile.CorpusPolicyIDFor("static_policies", r.PolicyID)] = r.Tier
		if r.Tier == "tenant" {
			tenant++
		}
	}
	if tenant != censusTenantRows {
		t.Fatalf("the census tiers %d rows tenant; this tree pins %d", tenant, censusTenantRows)
	}
	evalExec := legacycompile.CorpusPolicyIDFor("static_policies", "sys_dangerous_eval_exec")
	if wantTier[evalExec] != "tenant" {
		t.Fatalf("PREMISE: the census tiers sys_dangerous_eval_exec %q, not tenant", wantTier[evalExec])
	}

	b := deploymentBuilder(t)
	_, effects, err := activationinputs.ActiveEffects(context.Background(), b.Source(legacycompile.PlaneProxyRequest, legacycompile.PhaseRequest), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	sawEvalExec := false
	for _, e := range effects {
		want, censused := wantTier[e.Control]
		if e.Source != activation.SourceShipped || !censused {
			continue
		}
		if got := activationinputs.TierOf(e); got != want {
			t.Errorf("%s: TierOf = %q; the census tiers it %q", e.Control, got, want)
		}
		seen[want]++
		sawEvalExec = sawEvalExec || e.Control == evalExec
	}
	if !sawEvalExec || seen["tenant"] == 0 || seen["system"] == 0 {
		t.Fatalf("PREMISE: proxy_request lists sys_dangerous_eval_exec=%v, %d tenant-tier and %d system-tier controls; each arm needs one", sawEvalExec, seen["tenant"], seen["system"])
	}
}

// ScopeOf is the one derivation of whose a policy is, one arm per source.
func TestScopeOfIsTheDeploymentsForAShippedControlOnly(t *testing.T) {
	for _, tc := range []struct {
		source activation.PolicySource
		want   string
	}{
		{activation.SourceShipped, activationinputs.ScopeDeployment},
		{activation.SourceOrganization, activationinputs.ScopeOrganization},
		{activation.SourcePack, activationinputs.ScopeOrganization},
	} {
		if got := activationinputs.ScopeOf(activation.PolicyEffect{Source: tc.source}); got != tc.want {
			t.Errorf("ScopeOf(%s) = %q; want %q", tc.source, got, tc.want)
		}
	}
}

// ControlKey is the control a policy is or replaces, so a shipped control's
// per-scope variant policies share one key; a policy with no control keys on
// its own id, so the organization's own policies stay distinct.
func TestControlKeyCollapsesAControlsVariantsOnly(t *testing.T) {
	const c = "corpus:static_policies:sys__pii__pan"
	warn := activation.PolicyEffect{PolicyID: c + ":warn", Control: c}
	redact := activation.PolicyEffect{PolicyID: c + ":redact", Control: c}
	if activationinputs.ControlKey(warn) != activationinputs.ControlKey(redact) {
		t.Fatalf("a control's per-scope variants key differently: %q vs %q", activationinputs.ControlKey(warn), activationinputs.ControlKey(redact))
	}
	own1 := activation.PolicyEffect{PolicyID: "org.one", Source: activation.SourceOrganization}
	own2 := activation.PolicyEffect{PolicyID: "org.two", Source: activation.SourceOrganization}
	if activationinputs.ControlKey(own1) == activationinputs.ControlKey(own2) || activationinputs.ControlKey(own1) != "org.one" {
		t.Fatalf("the organization's own policies must key on their ids: %q, %q", activationinputs.ControlKey(own1), activationinputs.ControlKey(own2))
	}
}
