// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"sort"
	"testing"
)

// TestEveryEnforcingScopeSaysWhatAChallengeBecomes holds the approval-handling
// declaration to scopeActions' scopes in both directions: a scope an enforcing
// seam decides on with no handling would let an approval requirement bind there
// with nobody having said whether it is held, and a handling for a scope no
// seam decides on states a fact about nothing.
func TestEveryEnforcingScopeSaysWhatAChallengeBecomes(t *testing.T) {
	var missing, stale []string
	for s := range scopeActions {
		h, ok := scopeApprovalHandling[s]
		if !ok {
			missing = append(missing, s)
			continue
		}
		if h.String() == "unknown" {
			t.Errorf("%s has approval handling %d, which is none of the declared values", s, h)
		}
	}
	for s := range scopeApprovalHandling {
		if _, ok := scopeActions[s]; !ok {
			stale = append(stale, s)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	for _, s := range missing {
		t.Errorf("enforcing scope %s says nothing about what an approval challenge becomes there; add it to scopeApprovalHandling", s)
	}
	for _, s := range stale {
		t.Errorf("scopeApprovalHandling names %s, which no enforcing seam decides on", s)
	}

	var holding []string
	for _, s := range HoldingScopes() {
		holding = append(holding, s.String())
	}
	if len(holding) == 0 {
		t.Fatal("no scope holds a challenge; the workflow control plane's step gate does")
	}
	t.Logf("holding scopes: %v", holding)
}
