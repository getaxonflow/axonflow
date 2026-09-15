// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"sort"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// effectsByID indexes an activation's policy effects, and refuses an unsorted
// list or a second entry under one id.
func effectsByID(t *testing.T, act *activation.Activation) map[string]activation.PolicyEffect {
	t.Helper()
	effects := act.PolicyEffects()
	if !sort.SliceIsSorted(effects, func(i, j int) bool { return effects[i].PolicyID < effects[j].PolicyID }) {
		t.Fatal("PolicyEffects is not sorted by policy id")
	}
	out := make(map[string]activation.PolicyEffect, len(effects))
	for _, e := range effects {
		if _, twice := out[e.PolicyID]; twice {
			t.Fatalf("PolicyEffects lists %s twice", e.PolicyID)
		}
		out[e.PolicyID] = e
	}
	return out
}

// On decide, with the baseline pack published as the organization's document:
// every entry agrees with Identity; every shipped control the scope binds is
// listed as the control it is, enforcing the action its shape reads as, with the
// census's category and severity; and every published policy is the
// organization's, at version 1, naming no shipped control.
func TestPolicyEffectsNamesEveryActivatedPolicyAsIdentityDoes(t *testing.T) {
	w := overrideWorld(t)
	act := w.mustActivateScope(t, decideScope, nil)
	effects := effectsByID(t, act)

	for id, e := range effects {
		identity, ok := act.Identity(id)
		if !ok {
			t.Fatalf("%s is listed and the engine did not activate it", id)
		}
		if e.Name != identity.Name || e.Source != identity.Source || e.Version != identity.Version {
			t.Fatalf("%s is listed as %q %s v%d; Identity names it %q %s v%d", id, e.Name, e.Source, e.Version, identity.Name, identity.Source, identity.Version)
		}
		if e.Disabled || e.Replacement != "" {
			t.Fatalf("%s is listed disabled=%v replacement=%q, and nothing is disabled or replaced", id, e.Disabled, e.Replacement)
		}
	}

	restricted := restrictionOf(t, decideScope)
	if len(restricted.Policies) == 0 {
		t.Fatal("PREMISE: decide binds no shipped control")
	}
	censused := 0
	for _, p := range restricted.Policies {
		e, listed := effects[p.ID]
		if !listed {
			t.Fatalf("the shipped control %s is active on decide and not listed", p.ID)
		}
		if e.Source != activation.SourceShipped || e.Version != 0 || e.Control != controlOf(t, p.ID) || e.Authority != p.Authority {
			t.Fatalf("%s is listed as %+v; want the shipped control %s, at no version, as a %s", p.ID, e, controlOf(t, p.ID), p.Authority)
		}
		if want, _, _, _ := legacycompile.LegacyActionOf(p); e.Action != want {
			t.Fatalf("%s is listed enforcing %q; its shape reads as %q", p.ID, e.Action, want)
		}
		if row, ok := censusRowFor(t, p); ok {
			censused++
			if e.Category != row.Category || e.Severity != row.Severity {
				t.Fatalf("%s is listed %q/%q; the census says %q/%q", p.ID, e.Category, e.Severity, row.Category, row.Severity)
			}
		}
	}
	if censused == 0 {
		t.Fatal("PREMISE: no shipped control on decide reads a censused detector, so the census columns are unproved")
	}

	for _, p := range baselinePack(t, w).Policies {
		e, listed := effects[p.ID]
		if !listed {
			t.Fatalf("the published policy %s is not listed", p.ID)
		}
		want, _, _, _ := legacycompile.LegacyActionOf(p)
		if e.Source != activation.SourceOrganization || e.Version != 1 || e.Authority != p.Authority || e.Action != want || e.Control != "" {
			t.Fatalf("the published policy %s is listed as %+v; want the organization's, at version 1, naming no shipped control", p.ID, e)
		}
	}
}

// PRD v11 §1.5: a control the document disables is not carried by the engine,
// and the list still names it, as shipped and disabled, with the action it
// enforced before.
func TestPolicyEffectsListsADisabledControlAsShippedAndDisabled(t *testing.T) {
	w := newWorld(t)
	decide := restrictionOf(t, decideScope)
	var target pdp.Policy
	for _, p := range decide.Policies {
		if _, _, ok := legacycompile.CorpusControlOf(p.ID); ok && p.Authority == contract.AuthorityConstraint {
			target = p
			break
		}
	}
	if target.ID == "" {
		t.Fatal("PREMISE: decide binds no shipped constraint")
	}
	control := controlOf(t, target.ID)
	off := false
	art := w.publishDocument(t, baselinePack(t, w), 1, "", []authoring.SystemControlEntry{{Control: control, Enabled: &off}})
	act := w.mustActivateScope(t, decideScope, func(in *activation.Inputs) { in.Organization = art })
	effects := effectsByID(t, act)

	ids := policiesOfControl(decide, control)
	for _, id := range ids {
		e, listed := effects[id]
		if !listed {
			t.Fatalf("%s is disabled by the document and not listed", id)
		}
		if _, active := act.Policy(id); active {
			t.Fatalf("%s is listed disabled and the engine carries it", id)
		}
		if !e.Disabled || e.Source != activation.SourceShipped || e.Version != 0 || e.Control != control || e.Replacement != "" || e.Name == "" {
			t.Fatalf("%s is listed as %+v; want the shipped control %s, disabled, at no version, by its name", id, e, control)
		}
	}
	if e := effects[target.ID]; e.Action != legacycompile.ActionBlock || e.Authority != contract.AuthorityConstraint {
		t.Fatalf("the disabled constraint %s is listed enforcing %q as a %s; want block as a constraint", target.ID, e.Action, e.Authority)
	}
	disabled := 0
	for _, e := range effects {
		if e.Disabled {
			disabled++
		}
	}
	if disabled != len(ids) {
		t.Fatalf("%d entries are disabled; the document disabled %d policy(ies) of %s", disabled, len(ids), control)
	}
}

// A shipped control the document re-actions is listed as the organization's
// replacement, at the document's version; one a recorded detection override
// re-actions is listed as the override's replacement, shipped on the wire
// (identity.go, PRD v11 item 14); and the displaced shipped control is not
// listed beside either.
func TestPolicyEffectsNamesWhatReplacesAShippedControl(t *testing.T) {
	w := newWorld(t)
	decide := restrictionOf(t, decideScope)
	sqli := controlsOfCategory(t, decide, "security-sqli")
	if len(sqli) < 2 {
		t.Fatal("PREMISE: decide binds fewer than two security-sqli controls, so a document's replacement and an override's cannot both be observed")
	}
	target := sqli[0]
	control := controlOf(t, target.ID)
	art := w.publishDocument(t, baselinePack(t, w), 1, "", []authoring.SystemControlEntry{{Control: control, Action: legacycompile.ActionBlock}})
	act := w.mustActivateScope(t, decideScope, func(in *activation.Inputs) {
		withOverrides(compositionFrom(t, nil), legacycompile.CategoryActions{"security-sqli": legacycompile.ActionLog})(in)
		in.Organization = art
	})
	effects := effectsByID(t, act)

	byDocument, listed := effects[activation.OrganizationControlPolicyIDPrefix+target.ID]
	if !listed {
		t.Fatalf("the document's replacement of %s is not listed", target.ID)
	}
	if byDocument.Replacement != activation.ReplacementSystemControl || byDocument.Source != activation.SourceOrganization || byDocument.Version != 1 ||
		byDocument.Control != control || byDocument.Action != legacycompile.ActionBlock || byDocument.Category != "security-sqli" || byDocument.Name != target.Name {
		t.Fatalf("the document's replacement is listed as %+v; want the organization's system_control replacement of %s, at version 1, enforcing block", byDocument, control)
	}
	if _, still := effects[target.ID]; still {
		t.Fatalf("the displaced shipped control %s is listed beside the document's replacement", target.ID)
	}

	overridden := 0
	for _, other := range sqli[1:] {
		if controlOf(t, other.ID) == control {
			continue
		}
		e, listed := effects[activation.OverridePolicyIDPrefix+other.ID]
		if !listed {
			t.Fatalf("the recorded override's replacement of %s is not listed", other.ID)
		}
		overridden++
		if e.Replacement != activation.ReplacementOverride || e.Source != activation.SourceShipped || e.Version != 0 ||
			e.Control != controlOf(t, other.ID) || e.Action != legacycompile.ActionLog || e.Category != "security-sqli" {
			t.Fatalf("the override's replacement of %s is listed as %+v; want a shipped override replacement, at no version, enforcing log", other.ID, e)
		}
		if _, still := effects[other.ID]; still {
			t.Fatalf("the displaced shipped control %s is listed beside the override's replacement", other.ID)
		}
	}
	if overridden == 0 {
		t.Fatal("PREMISE: the recorded override replaced no control the document leaves alone")
	}
}
