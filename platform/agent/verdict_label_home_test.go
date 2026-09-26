// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/pep"
)

// TestTheVerdictLabelsAreOneSetOnTheWireAndOnTheCounter pins the decision
// verdicts to their one home, anchoredenforcer (#4249 row 5666277893), from the
// two packages that spell them outside it:
//
//   - the agent's VerdictAllow, VerdictDeny and VerdictNeedsApproval
//     (decision_handler.go), which re-export the home's and are held equal here
//     by value, so the re-export is pinned rather than assumed;
//   - pep.VerdictAllow, pep.VerdictDeny and pep.VerdictNeedsApproval
//     (platform/shared/pep/pep.go:156-158), which keep their own literals because
//     pep is a client library that gateway adapters import, and importing the
//     home would pull the enforcer and prometheus into every one of them.
//
// And the home to the wire: the strings a PEP and a metric query match.
func TestTheVerdictLabelsAreOneSetOnTheWireAndOnTheCounter(t *testing.T) {
	for _, c := range []struct{ name, home, agent, pep, wire string }{
		{"allow", anchoredenforcer.VerdictAllow, VerdictAllow, pep.VerdictAllow, "allow"},
		{"deny", anchoredenforcer.VerdictDeny, VerdictDeny, pep.VerdictDeny, "deny"},
		{"needs_approval", anchoredenforcer.VerdictNeedsApproval, VerdictNeedsApproval, pep.VerdictNeedsApproval, "needs_approval"},
	} {
		if c.home != c.wire {
			t.Errorf("%s: anchoredenforcer spells it %q, the wire %q", c.name, c.home, c.wire)
		}
		if c.agent != c.home {
			t.Errorf("%s: the agent re-exports %q, the home is %q", c.name, c.agent, c.home)
		}
		if c.pep != c.home {
			t.Errorf("%s: pep (platform/shared/pep/pep.go:156-158) spells it %q, the home %q", c.name, c.pep, c.home)
		}
	}
	if anchoredenforcer.VerdictUnavailable != "unavailable" {
		t.Errorf("the counter's unavailable label is %q, want \"unavailable\"", anchoredenforcer.VerdictUnavailable)
	}
}
