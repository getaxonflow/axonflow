// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/policypack"
)

// PRD v11 §1.14 (#4127): every policy a decision names is named by its own
// display name, by whose it is, and - for an organization's own policy or an
// installed pack's - by the version it was published at. A shipped control
// carries no version: the bundle digest a decision already names identifies
// it. An identifier is never presented as a name.
func TestEveryActivatedPolicyIsNamedByWhoseItIsAndThePublishedVersion(t *testing.T) {
	w := newWorld(t)
	installed, err := activation.InstallPacks(w.snap, []*policypack.Pack{loadPack(t, testPackSource("testpack"))})
	if err != nil {
		t.Fatal(err)
	}
	identity := func(t *testing.T, act *activation.Activation, id string) activation.PolicyIdentity {
		t.Helper()
		p, ok := act.Identity(id)
		if !ok {
			t.Fatalf("%s is not activated, so it has no identity", id)
		}
		return p
	}
	activated := func(t *testing.T, act *activation.Activation, id string) pdp.Policy {
		t.Helper()
		p, ok := act.Policy(id)
		if !ok {
			t.Fatalf("%s is not activated", id)
		}
		return p
	}

	implicit := w.activateWith(t, installed)
	if !implicit.ImplicitBaseline || implicit.DocumentVersion != 0 {
		t.Fatalf("implicit baseline %v, document version %d; want the implicit baseline, which has no document version", implicit.ImplicitBaseline, implicit.DocumentVersion)
	}

	t.Run("a shipped control is named, and has no version", func(t *testing.T) {
		template, err := activation.OrganizationTemplateForScope(implicit.Scope)
		if err != nil {
			t.Fatal(err)
		}
		shipped, err := pdp.SystemCorpusDocument()
		if err != nil {
			t.Fatal(err)
		}
		var system *pdp.Policy
		for i := range shipped.Policies {
			if _, ok := implicit.Policy(shipped.Policies[i].ID); ok {
				system = &shipped.Policies[i]
				break
			}
		}
		if len(template.Policies) == 0 || system == nil {
			t.Fatalf("decide activates %d template controls and system control %v; both arms need one", len(template.Policies), system)
		}
		for _, p := range []pdp.Policy{template.Policies[0], *system} {
			want := activation.PolicyIdentity{ID: p.ID, Name: p.Name, Source: activation.SourceShipped}
			if got := identity(t, implicit, p.ID); p.Name == "" || got != want {
				t.Errorf("%s: identity %+v; want %+v, named by the corpus", p.ID, got, want)
			}
		}
	})

	t.Run("a pack's control is the pack's, at the pack's version", func(t *testing.T) {
		want := activation.PolicyIdentity{ID: packBlockID, Name: activated(t, implicit, packBlockID).Name, Source: activation.SourcePack, Version: 1}
		if got := identity(t, implicit, packBlockID); got != want {
			t.Errorf("identity %+v; want %+v", got, want)
		}
	})

	t.Run("an id the engine did not activate is named by its identifier alone", func(t *testing.T) {
		if got, ok := implicit.Identity("no.such.policy"); ok || got != (activation.PolicyIdentity{ID: "no.such.policy"}) {
			t.Errorf("identity %+v, %v; want the bare identifier and false", got, ok)
		}
	})

	t.Run("the organization's own policies are its, at each version it publishes", func(t *testing.T) {
		doc, err := authoringcatalog.BaselinePermissionPack(w.snap)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Policies) < 2 {
			t.Fatalf("the baseline pack carries %d policies; a named and an unnamed one are needed", len(doc.Policies))
		}
		named, unnamed := doc.Policies[0].ID, doc.Policies[1].ID
		doc.Policies[0].Name = "Chat completions for everyone"
		first := w.publish(t, doc, 1, "")
		w.promote(t, first)
		for _, version := range []int{1, 2} {
			if version == 2 {
				w.promote(t, w.publish(t, doc, 2, first.Digest()))
			}
			act := w.activateWith(t, installed)
			if act.ImplicitBaseline || act.DocumentVersion != version {
				t.Fatalf("v%d: implicit baseline %v, document version %d; want the published document at %d", version, act.ImplicitBaseline, act.DocumentVersion, version)
			}
			for id, name := range map[string]string{named: "Chat completions for everyone", unnamed: ""} {
				want := activation.PolicyIdentity{ID: id, Name: name, Source: activation.SourceOrganization, Version: version}
				if got := identity(t, act, id); got != want {
					t.Errorf("v%d %s: identity %+v; want %+v", version, id, got, want)
				}
			}
			if got := identity(t, act, packBlockID); got.Source != activation.SourcePack || got.Version != 1 {
				t.Errorf("v%d: the pack's control is named %+v beside a published document; want the pack's, at version 1", version, got)
			}
		}
	})

	t.Run("a recorded override's replacement is named by the shipped control it replaces", func(t *testing.T) {
		// #4211: the replacement is that control enforced with the recorded
		// action (#4045), and an override-driven block must not reach the
		// audit view unnamed.
		restricted, _, err := activation.RestrictToScope(decideScope)
		if err != nil {
			t.Fatal(err)
		}
		sqli := controlsOfCategory(t, restricted, "security-sqli")
		if len(sqli) == 0 {
			t.Fatal("PREMISE: decide binds no security-sqli control, so an override on it replaces nothing here")
		}
		act := w.mustActivateScope(t, decideScope, withOverrides(compositionFrom(t, nil),
			legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock}))
		for _, shipped := range sqli {
			id := activation.OverridePolicyIDPrefix + shipped.ID
			want := activation.PolicyIdentity{ID: id, Name: shipped.Name, Source: activation.SourceShipped}
			if got := identity(t, act, id); shipped.Name == "" || got != want {
				t.Errorf("%s: identity %+v; want %+v, named by the control it replaces", id, got, want)
			}
		}
	})

	t.Run("an action is named by the vocabulary's label for it", func(t *testing.T) {
		label := implicit.Snapshot.Catalog.ActionLabels["Action::"+authoringcatalog.ActionToolCall].DisplayName
		if label == "" {
			t.Fatal("the deployment vocabulary labels no tool.call; the arm would be vacuous")
		}
		if got := implicit.ActionName(authoringcatalog.ActionToolCall); got != label {
			t.Errorf("ActionName(tool.call) = %q; want the vocabulary's label %q", got, label)
		}
		if got := implicit.ActionName("no.such.action"); got != "" {
			t.Errorf("ActionName of an unregistered action = %q; want none", got)
		}
	})
}
