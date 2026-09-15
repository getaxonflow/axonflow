// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"slices"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// TestEveryScopeThatRedactsTheEvaluatedContentNamesItsPhase holds the two
// halves of the content target together (#4046). The shipped corpus targets
// the evaluated content, legacycompile.DefaultContentTarget, once for every
// scope; each scope says which phase that content is. So every declared scope
// whose restriction binds a field_redact on it must name a content phase the
// scope evaluates - a scope that could not would have no content to tell a
// caller to mask. The population is every declared scope's own restriction.
func TestEveryScopeThatRedactsTheEvaluatedContentNamesItsPhase(t *testing.T) {
	judged := 0
	for _, scope := range legacycompile.AllScopes() {
		doc, _, err := activation.RestrictToScope(scope)
		if err != nil {
			// A scope whose restriction cannot be derived is restriction.go's
			// subject; it binds nothing an engine could enforce.
			continue
		}
		redacts := false
		for _, p := range doc.Policies {
			for _, o := range p.Obligations {
				if o.Type == contract.ObFieldRedact && o.Target == legacycompile.DefaultContentTarget {
					redacts = true
				}
			}
		}
		if !redacts {
			continue
		}
		judged++
		if ph := scope.ContentPhase(); ph == "" || !slices.Contains(scope.Phases(), ph) {
			t.Errorf("%s binds a redaction of the evaluated content and names content phase %q, which is not one of the phases it evaluates %v",
				scope, ph, scope.Phases())
		}
	}
	if judged == 0 {
		t.Fatal("no declared scope binds a redaction of the evaluated content, so this test judged nothing; the shipped corpus's static redactions target it")
	}

	// CONTROLS: the two scopes with an enforcing seam today.
	for scope, want := range map[legacycompile.EnforcementScope]legacycompile.Phase{
		legacycompile.MustScopeFor(legacycompile.PlaneDecide, ""):                       legacycompile.PhaseRequest,
		legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse): legacycompile.PhaseResponse,
	} {
		if got := scope.ContentPhase(); got != want {
			t.Errorf("%s names content phase %q; want %q", scope, got, want)
		}
	}
}
