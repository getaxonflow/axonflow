// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"errors"
	"slices"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// THE BACKSTOP (#4259): a forced-category policy missing from, or edited in,
// the restriction the engine would enforce is refused by name; the same
// restriction folded by nothing passes; and a scope that forces nothing is
// never judged, whatever it leaves out.
func TestTheForcedControlBackstopRefusesAMissingForcedControl(t *testing.T) {
	cowork := legacycompile.MustScopeFor(legacycompile.PlaneCoworkIngest, legacycompile.PhaseResponse)
	restricted, _, err := RestrictToScope(cowork)
	if err != nil {
		t.Fatal(err)
	}
	if len(restricted.Policies) == 0 {
		t.Fatal("PREMISE: cowork_ingest keeps no shipped policy")
	}
	if err := refuseForcedControlMissing(cowork, restricted, restricted); err != nil {
		t.Fatalf("the unfolded restriction is refused: %v", err)
	}

	missing := &pdp.Document{Root: restricted.Root, Version: restricted.Version, Policies: slices.Clone(restricted.Policies[1:])}
	var refusal *pdp.ActivationRefusal
	if err := refuseForcedControlMissing(cowork, restricted, missing); !errors.As(err, &refusal) || refusal.Code != RefusalForcedControlMissing {
		t.Fatalf("a restriction missing %s answered %v, want %s", restricted.Policies[0].ID, err, RefusalForcedControlMissing)
	}

	edited := &pdp.Document{Root: restricted.Root, Version: restricted.Version, Policies: slices.Clone(restricted.Policies)}
	edited.Policies[0].Where = pdp.Not(pdp.True())
	if err := refuseForcedControlMissing(cowork, restricted, edited); !errors.As(err, &refusal) || refusal.Code != RefusalForcedControlMissing {
		t.Fatalf("a restriction that edits %s answered %v, want %s", restricted.Policies[0].ID, err, RefusalForcedControlMissing)
	}

	decide := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	onDecide, _, err := RestrictToScope(decide)
	if err != nil {
		t.Fatal(err)
	}
	empty := &pdp.Document{Root: onDecide.Root, Version: onDecide.Version}
	if err := refuseForcedControlMissing(decide, onDecide, empty); err != nil {
		t.Fatalf("decide forces nothing and was judged: %v", err)
	}
}

// ONE ANSWER TO "IS THIS CONTROL FORCED HERE" (#4259). Publication warns from
// authoring.SystemControlForcedScopes; activation keeps from the fold's own
// per-policy reading. For every shipped control, the scopes the warning names
// are exactly the scopes on which a disable of it is kept as Forced. And the
// warning's text is true only while every forcing scope is cowork_ingest
// forcing redact, so that is held here too.
func TestThePublishWarningNamesExactlyTheScopesTheFoldKeeps(t *testing.T) {
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	controls := map[string]bool{}
	for _, p := range corpus.Policies {
		if c, _, ok := legacycompile.CorpusControlOf(p.ID); ok {
			controls[c] = true
		}
	}
	off := false
	kept := map[string][]string{}
	for _, s := range legacycompile.AllScopes() {
		spec := legacycompile.MustSpecFor(s.Plane)
		if spec.ForcedAction != "" && (s.Plane != legacycompile.PlaneCoworkIngest || spec.ForcedAction != legacycompile.ActionRedact) {
			t.Fatalf("%s forces %s; the publish warning's text says only the cowork ingest plane forces redact", s, spec.ForcedAction)
		}
		restricted, _, err := RestrictToScope(s)
		if err != nil {
			t.Fatalf("restricting %s: %v", s, err)
		}
		for c := range controls {
			fold, err := foldSystemControls(s, restricted, []authoring.SystemControlEntry{{Control: c, Enabled: &off}})
			if err != nil {
				t.Fatalf("%s on %s: %v", c, s, err)
			}
			if len(fold.effects) == 1 && len(fold.effects[0].Forced) > 0 {
				kept[c] = append(kept[c], s.String())
			}
		}
	}
	if len(kept) == 0 {
		t.Fatal("PREMISE: no shipped control is kept as forced on any scope, so the agreement is vacuous")
	}
	for c := range controls {
		want := kept[c]
		slices.Sort(want)
		got, err := authoring.SystemControlForcedScopes(c)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: publication warns of %v, the fold keeps it on %v", c, got, want)
		}
	}
}
