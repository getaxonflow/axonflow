// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/policypack"
)

// WHOSE EACH POLICY IS, COUNTED (#4152), over real activations on decide. Every
// expectation comes from the fixture: the published pack, the scope's
// restriction, the census, a pack's own activation record. None comes from a
// second reading of PolicyEffects.

func mustCount(t *testing.T, act *activation.Activation) activation.EffectCounts {
	t.Helper()
	c, err := activation.CountEffects(act.PolicyEffects())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// publishedCounts publishes the baseline permission pack as the organization's
// document in a fresh world, with controls as its system_controls section, and
// counts its activation on decide under the recorded overrides assigned.
func publishedCounts(t *testing.T, controls []authoring.SystemControlEntry, assigned legacycompile.CategoryActions) activation.EffectCounts {
	t.Helper()
	w := newWorld(t)
	art := w.publishDocument(t, baselinePack(t, w), 1, "", controls)
	return mustCount(t, w.mustActivateScope(t, decideScope, func(in *activation.Inputs) {
		withOverrides(compositionFrom(t, nil), assigned)(in)
		in.Organization = art
	}))
}

// Under the implicit baseline nothing is the organization's: the baseline
// permissions and every system control the scope binds are shipped.
func TestCountEffectsCountsNothingAsTheOrganizationsUnderTheImplicitBaseline(t *testing.T) {
	w := newWorld(t)
	act := w.mustActivateScope(t, decideScope, nil)
	if !act.ImplicitBaseline {
		t.Fatal("PREMISE: nothing is published, yet the activation is not the implicit baseline")
	}
	c := mustCount(t, act)
	if c.Organization != 0 || c.Pack != 0 || c.Disabled != 0 {
		t.Fatalf("counts %+v under the implicit baseline; want every policy shipped", c)
	}
	floor := len(baselinePack(t, w).Policies) + len(restrictionOf(t, decideScope).Policies)
	if c.Shipped < floor || c.Total() != c.Shipped {
		t.Fatalf("counts %+v; want at least the %d baseline permissions and system controls, all shipped", c, floor)
	}
}

// A published document's every policy is the organization's, and what stays
// shipped is exactly the system controls the scope binds: the document carries
// every baseline permission, so none is composed beside it.
func TestCountEffectsCountsEveryPublishedPolicyAsTheOrganizations(t *testing.T) {
	c := publishedCounts(t, nil, nil)
	if want := len(baselinePack(t, newWorld(t)).Policies); c.Organization != want {
		t.Fatalf("organization = %d; the published document carries %d policies", c.Organization, want)
	}
	if want := len(restrictionOf(t, decideScope).Policies); c.Shipped != want {
		t.Fatalf("shipped = %d; decide binds %d system controls", c.Shipped, want)
	}
	if c.Pack != 0 || c.Disabled != 0 {
		t.Fatalf("counts %+v; nothing is installed or disabled", c)
	}
}

// A replacement is counted once, in place of the control it displaces. The
// document's re-action of one security-sqli control and a recorded override of
// the category move exactly those policies from shipped to the organization,
// and the total stays where it was. The override's replacement is shipped on
// the wire and the organization's in the count (CountEffects).
func TestCountEffectsCountsAReplacementOnceInPlaceOfTheControlItDisplaces(t *testing.T) {
	decide := restrictionOf(t, decideScope)
	sqli := controlsOfCategory(t, decide, "security-sqli")
	if len(sqli) < 2 {
		t.Fatal("PREMISE: decide binds fewer than two security-sqli controls, so a document's replacement and an override's cannot both be counted")
	}
	control := controlOf(t, sqli[0].ID)
	byDocument := len(policiesOfControl(decide, control))
	byOverride := 0
	for _, p := range sqli {
		if controlOf(t, p.ID) != control {
			byOverride++
		}
	}
	if byDocument == 0 || byOverride == 0 {
		t.Fatalf("PREMISE: the document replaces %d policy(ies) and the override %d; each must replace one", byDocument, byOverride)
	}

	plain := publishedCounts(t, nil, nil)
	replaced := publishedCounts(t,
		[]authoring.SystemControlEntry{{Control: control, Action: legacycompile.ActionBlock}},
		legacycompile.CategoryActions{"security-sqli": legacycompile.ActionLog})
	if replaced.Total() != plain.Total() {
		t.Fatalf("total %d with the replacements, %d without; a replacement displaces its control one for one", replaced.Total(), plain.Total())
	}
	moved := byDocument + byOverride
	if replaced.Organization != plain.Organization+moved || replaced.Shipped != plain.Shipped-moved || replaced.Disabled != 0 {
		t.Fatalf("counts %+v with the replacements, %+v without; want %d moved from shipped to the organization", replaced, plain, moved)
	}
}

// A recorded override is the organization's with nothing published as well:
// under the implicit baseline, the organization's count is exactly the
// controls the override re-actions.
func TestCountEffectsCountsARecordedOverrideAsTheOrganizationsWithNothingPublished(t *testing.T) {
	sqli := controlsOfCategory(t, restrictionOf(t, decideScope), "security-sqli")
	if len(sqli) == 0 {
		t.Fatal("PREMISE: decide binds no security-sqli control")
	}
	w := newWorld(t)
	comp := compositionFrom(t, nil)
	plain := mustCount(t, w.mustActivateScope(t, decideScope, withOverrides(comp, nil)))
	overridden := mustCount(t, w.mustActivateScope(t, decideScope,
		withOverrides(comp, legacycompile.CategoryActions{"security-sqli": legacycompile.ActionLog})))
	if plain.Organization != 0 || overridden.Organization != len(sqli) || overridden.Total() != plain.Total() {
		t.Fatalf("counts %+v overridden, %+v not; want the %d security-sqli control(s) the organization's and the total unmoved", overridden, plain, len(sqli))
	}
}

// A control the document disables is not enforced, so it leaves shipped and
// the total and is counted only as disabled.
func TestCountEffectsCountsADisabledControlOutsideTheTotal(t *testing.T) {
	decide := restrictionOf(t, decideScope)
	var target string
	for _, p := range decide.Policies {
		if _, _, ok := legacycompile.CorpusControlOf(p.ID); ok && p.Authority == contract.AuthorityConstraint {
			target = p.ID
			break
		}
	}
	if target == "" {
		t.Fatal("PREMISE: decide binds no shipped constraint")
	}
	control := controlOf(t, target)
	ids := policiesOfControl(decide, control)
	off := false
	plain := publishedCounts(t, nil, nil)
	disabled := publishedCounts(t, []authoring.SystemControlEntry{{Control: control, Enabled: &off}}, nil)
	if disabled.Disabled != len(ids) || disabled.Total() != plain.Total()-len(ids) ||
		disabled.Shipped != plain.Shipped-len(ids) || disabled.Organization != plain.Organization {
		t.Fatalf("counts %+v with %s disabled, %+v without; want its %d policy(ies) moved from shipped to disabled", disabled, control, plain, len(ids))
	}
}

// An installed pack's policies are the pack's: they add to the total beside
// what is shipped, and displace nothing.
func TestCountEffectsCountsAnInstalledPacksPoliciesAsThePacks(t *testing.T) {
	w := newWorld(t)
	installed, err := activation.InstallPacks(w.snap, []*policypack.Pack{loadPack(t, testPackSource("testpack"))})
	if err != nil {
		t.Fatal(err)
	}
	without := mustCount(t, w.activate(t))
	act := w.activateWith(t, installed)
	composed := 0
	for _, p := range act.Packs {
		composed += p.Policies
	}
	if composed == 0 {
		t.Fatal("PREMISE: the pack composes nothing on decide")
	}
	c := mustCount(t, act)
	if c.Pack != composed || c.Shipped != without.Shipped || c.Organization != 0 || c.Total() != without.Total()+composed {
		t.Fatalf("counts %+v with the pack, %+v without; want the pack's %d policy(ies) added as the pack's", c, without, composed)
	}
}

// A source no count names is refused by name, beside a known one that counts.
func TestCountEffectsRefusesASourceNoCountNames(t *testing.T) {
	known := []activation.PolicyEffect{{PolicyID: "p.known", Source: activation.SourceShipped}}
	if c, err := activation.CountEffects(known); err != nil || c.Shipped != 1 || c.Total() != 1 {
		t.Fatalf("a shipped policy counts as %+v, %v; want one shipped", c, err)
	}
	_, err := activation.CountEffects(append(known, activation.PolicyEffect{PolicyID: "p.unknown", Source: "vendor"}))
	if err == nil || !strings.Contains(err.Error(), `"vendor"`) || !strings.Contains(err.Error(), "p.unknown") {
		t.Fatalf("an unknown source counts with error %v; want a refusal naming the policy and the source", err)
	}
}
