// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// policiesOfControl are a restriction's policies of one control, sorted.
func policiesOfControl(restricted *pdp.Document, control string) []string {
	var ids []string
	for _, p := range restricted.Policies {
		if c, _, ok := legacycompile.CorpusControlOf(p.ID); ok && c == control {
			ids = append(ids, p.ID)
		}
	}
	slices.Sort(ids)
	return ids
}

func restrictionOf(t *testing.T, scope legacycompile.EnforcementScope) *pdp.Document {
	t.Helper()
	restricted, _, err := activation.RestrictToScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	return restricted
}

func baselinePack(t *testing.T, w *world) *pdp.Document {
	t.Helper()
	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	return pack
}

// PRD v11 §1.5: a control the document disables leaves the scope's restriction,
// the activation says so, and a request it denied is no longer denied by it.
// That the fold runs on every plane, one that passes no recorded override
// included, is TestASystemControlFoldsOnEveryScope's.
func TestADisabledSystemControlLeavesTheShippedControlOut(t *testing.T) {
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
	withoutEntry := w.publishDocument(t, baselinePack(t, w), 1, "", nil)
	withEntry := w.publishDocument(t, baselinePack(t, w), 2, withoutEntry.Digest(), []authoring.SystemControlEntry{{Control: control, Enabled: &off}})
	signal := signalOf(t, target)

	before := w.mustActivateScope(t, decideScope, func(in *activation.Inputs) { in.Organization = withoutEntry })
	if d := decideFired(t, before, signal); d.State != contract.StateDeny || !slices.Contains(d.Determining.MatchedConstraints, target.ID) {
		t.Fatalf("CONTROL: with no system control, %s fired decides %s %s %+v; want DENY by %s", signal, d.State, d.Reason, d.Determining, target.ID)
	}

	act := w.mustActivateScope(t, decideScope, func(in *activation.Inputs) { in.Organization = withEntry })
	want := []activation.SystemControlEffect{{Control: control, Disabled: true, Policies: policiesOfControl(decide, control)}}
	if !reflect.DeepEqual(act.SystemControls, want) {
		t.Fatalf("decide reports %+v; want %+v", act.SystemControls, want)
	}
	for _, id := range want[0].Policies {
		if _, ok := act.Policy(id); ok {
			t.Fatalf("%s is disabled by the document and still active on decide", id)
		}
	}
	if !strings.Contains(act.Restriction, "the organization's document controls the shipped set") {
		t.Fatalf("decide's restriction reads %q; want the document's control in it", act.Restriction)
	}
	d := decideFired(t, act, signal)
	for _, id := range d.Determining.MatchedConstraints {
		if c, _, ok := legacycompile.CorpusControlOf(id); ok && c == control {
			t.Fatalf("with %s disabled, %s fired is still decided by %s: %s %+v", control, signal, id, d.State, d.Determining)
		}
	}
}

// PRD v11 §1.5: per-policy control takes precedence over the recorded category
// posture on the same control. A control the document re-actions returns on the
// organization root as the organization's own policy, named by the shipped
// control; the recorded category posture still reaches every control the
// document does not name.
func TestAReactionedSystemControlBeatsTheRecordedCategoryPosture(t *testing.T) {
	w := newWorld(t)
	decide := restrictionOf(t, decideScope)
	sqli := controlsOfCategory(t, decide, "security-sqli")
	if len(sqli) < 2 {
		t.Fatal("PREMISE: decide binds fewer than two security-sqli controls, so the category posture's reach beside the document's is not observable")
	}
	target := sqli[0]
	control := controlOf(t, target.ID)
	art := w.publishDocument(t, baselinePack(t, w), 1, "", []authoring.SystemControlEntry{{Control: control, Action: legacycompile.ActionBlock}})
	act := w.mustActivateScope(t, decideScope, func(in *activation.Inputs) {
		withOverrides(compositionFrom(t, nil), legacycompile.CategoryActions{"security-sqli": legacycompile.ActionLog})(in)
		in.Organization = art
	})

	replacement := activation.OrganizationControlPolicyIDPrefix + target.ID
	r, ok := act.Policy(replacement)
	if !ok || r.Root != pdp.RootOrganization || r.Authority != contract.AuthorityConstraint || r.Name != target.Name ||
		!reflect.DeepEqual(r.Where, target.Where) || !reflect.DeepEqual(r.Actions, target.Actions) {
		t.Fatalf("the document's replacement of %s is %+v (present %v); want an organization-root constraint named %q over the same condition and actions", target.ID, r, ok, target.Name)
	}
	if _, overridden := act.Policy(activation.OverridePolicyIDPrefix + target.ID); overridden {
		t.Fatalf("the recorded category posture also replaced %s, which the document controls", target.ID)
	}
	for _, other := range sqli[1:] {
		if controlOf(t, other.ID) == control {
			continue
		}
		if _, reached := act.Policy(activation.OverridePolicyIDPrefix + other.ID); !reached {
			t.Fatalf("the recorded security-sqli=log no longer reaches %s, which the document does not name", other.ID)
		}
	}
	if id, _ := act.Identity(replacement); id.Source != activation.SourceOrganization || id.Version != 1 || id.Name != target.Name {
		t.Fatalf("the replacement is named %+v; want the organization's, at version 1, named %q", id, target.Name)
	}
	if want := []activation.SystemControlEffect{{Control: control, Action: legacycompile.ActionBlock, Policies: policiesOfControl(decide, control)}}; !reflect.DeepEqual(act.SystemControls, want) {
		t.Fatalf("decide reports %+v; want %+v", act.SystemControls, want)
	}
	if d := decideFired(t, act, signalOf(t, target)); d.State != contract.StateDeny || !slices.Contains(d.Determining.MatchedConstraints, replacement) {
		t.Fatalf("under the document's block the request decides %s %s %+v; want DENY by %s", d.State, d.Reason, d.Determining, replacement)
	}
}
