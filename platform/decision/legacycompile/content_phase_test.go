// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"slices"
	"testing"
)

// TestContentPhaseIsAPhaseTheScopeEvaluates pins EnforcementScope.ContentPhase
// over every declared scope: it is one of the phases the scope evaluates, and
// it is empty only for a plane that evaluates no legacy phase at all, which has
// no content a static redaction could target.
func TestContentPhaseIsAPhaseTheScopeEvaluates(t *testing.T) {
	scopes := AllScopes()
	if len(scopes) == 0 {
		t.Fatal("no scope is declared, so this test judged nothing")
	}
	for _, s := range scopes {
		ph := s.ContentPhase()
		if ph == "" {
			if len(s.Phases()) != 0 {
				t.Errorf("%s evaluates %v and names no content phase", s, s.Phases())
			}
			continue
		}
		if !slices.Contains(s.Phases(), ph) {
			t.Errorf("%s names content phase %q, which is not one of the phases it evaluates %v", s, ph, s.Phases())
		}
	}
}
