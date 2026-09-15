// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// Publication refuses these (authoring.validateSystemControls), so an artifact
// can only carry them by reaching activation some other way. The fold refuses
// them again rather than folding what the document cannot mean.
func TestFoldSystemControlsRefusesWhatPublicationWould(t *testing.T) {
	scope := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	restricted, _ := restrictionAndCensus(t, scope)
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	var static, dynamic string
	for _, p := range corpus.Policies {
		control, _, ok := legacycompile.CorpusControlOf(p.ID)
		switch {
		case !ok:
		case authoring.DynamicSystemControl(control) && dynamic == "":
			dynamic = control
		case !authoring.DynamicSystemControl(control) && static == "":
			static = control
		}
	}
	if static == "" || dynamic == "" {
		t.Fatalf("PREMISE: the corpus carries a static control (%q) and a dynamic one (%q)", static, dynamic)
	}
	off := false
	for _, tc := range []struct {
		name    string
		entries []authoring.SystemControlEntry
		naming  string
	}{
		{"a control named twice", []authoring.SystemControlEntry{{Control: static, Enabled: &off}, {Control: static, Action: legacycompile.ActionBlock}}, "twice"},
		{"a dynamic control re-actioned", []authoring.SystemControlEntry{{Control: dynamic, Action: legacycompile.ActionWarn}}, "disable but not re-action"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := foldSystemControls(scope, restricted, tc.entries); err == nil || !strings.Contains(err.Error(), tc.naming) {
				t.Fatalf("folded with err %v; want a refusal naming %q", err, tc.naming)
			}
		})
	}

	t.Run("no entry changes nothing", func(t *testing.T) {
		fold, err := foldSystemControls(scope, restricted, nil)
		if err != nil || fold.system != restricted || fold.reason != "" || fold.effects != nil || fold.replacements != nil {
			t.Fatalf("an empty section folded to %+v (err %v); want the restriction unchanged and no reason", fold, err)
		}
	})
}

// A control the scope does not bind is reported as binding nowhere there: the
// entry is the organization's on every plane, and a plane it does not reach says
// so rather than dropping it from the report.
func TestASystemControlTheScopeDoesNotBindIsReportedAsBindingNowhere(t *testing.T) {
	scope := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	restricted, _ := restrictionAndCensus(t, scope)
	bound := map[string]bool{}
	for _, p := range restricted.Policies {
		if control, _, ok := legacycompile.CorpusControlOf(p.ID); ok {
			bound[control] = true
		}
	}
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	var elsewhere string
	for _, p := range corpus.Policies {
		if control, _, ok := legacycompile.CorpusControlOf(p.ID); ok && !bound[control] {
			elsewhere = control
			break
		}
	}
	if elsewhere == "" {
		t.Fatal("PREMISE: every shipped control binds on decide, so a control that binds nowhere here cannot be named")
	}
	off := false
	fold, err := foldSystemControls(scope, restricted, []authoring.SystemControlEntry{{Control: elsewhere, Enabled: &off}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fold.effects) != 1 || fold.effects[0].Control != elsewhere || len(fold.effects[0].Policies) != 0 ||
		!strings.Contains(fold.reason, elsewhere+" disabled binds nowhere on "+scope.String()) || len(fold.system.Policies) != len(restricted.Policies) {
		t.Fatalf("a control decide does not bind folded to effects %+v, reason %q, %d of %d policies kept; want it reported as binding nowhere and nothing left out",
			fold.effects, fold.reason, len(fold.system.Policies), len(restricted.Policies))
	}
}

// PER-POLICY CONTROL IS NOT BEHIND PassesOrgOverrides (PRD v11 §1.5). On every
// scope a disabled control leaves the restriction, and on a plane that passes no
// recorded override it still displaces what it names there: Activate calls
// this fold unconditionally, so the claim is decided here.
func TestASystemControlFoldsOnEveryScope(t *testing.T) {
	var control string
	var quiet legacycompile.EnforcementScope
	for _, s := range legacycompile.AllScopes() {
		spec, err := legacycompile.SpecFor(s.Plane)
		if err != nil || spec.PassesOrgOverrides {
			continue
		}
		restricted, _, err := RestrictToScope(s)
		if err != nil {
			t.Fatalf("restricting %s: %v", s, err)
		}
		for _, p := range restricted.Policies {
			if c, _, ok := legacycompile.CorpusControlOf(p.ID); ok {
				control, quiet = c, s
				break
			}
		}
		if control != "" {
			break
		}
	}
	if control == "" {
		t.Fatal("PREMISE: no plane that passes no recorded override binds a shipped control, so the claim is not observable")
	}
	off := false
	entries := []authoring.SystemControlEntry{{Control: control, Enabled: &off}}
	displacedOnQuiet := false
	for _, s := range legacycompile.AllScopes() {
		restricted, _, err := RestrictToScope(s)
		if err != nil {
			t.Fatalf("restricting %s: %v", s, err)
		}
		fold, err := foldSystemControls(s, restricted, entries)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		for _, p := range fold.system.Policies {
			if c, _, ok := legacycompile.CorpusControlOf(p.ID); ok && c == control {
				t.Fatalf("%s is disabled by the document and still in %s's restriction", p.ID, s)
			}
		}
		if s == quiet && len(fold.effects) == 1 && len(fold.effects[0].Policies) > 0 {
			displacedOnQuiet = true
		}
	}
	if !displacedOnQuiet {
		t.Fatalf("the fold displaced nothing on %s, the plane that passes no recorded override", quiet)
	}
}
