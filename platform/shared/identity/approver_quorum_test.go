// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"testing"
)

// TestApproverQuorumSeparatesUnreachableFromUnderQuorum covers AXC-263.
//
// Two terminal outcomes that a single reason code would conflate, and they need
// different remedies:
//
//	ESCALATION_UNREACHABLE  nobody can answer, ever. The pool names realms that
//	                        cannot be asked a question, or every member is the
//	                        requester. Fix the pool.
//	QUORUM_UNREACHABLE      some can answer, fewer than the clause requires.
//	                        Fix the quorum, or widen the pool.
//
// The approval plane consumes this rather than counting for itself, so that one
// vocabulary reaches the audit surface. A count returned across the package
// boundary loses the reason and the detail, and the caller then reconstructs
// both from an integer.
func TestApproverQuorumSeparatesUnreachableFromUnderQuorum(t *testing.T) {
	MarkConformanceCase("AXC-263")

	reg := fixtureRegistry(t)
	twoHumans := ApproverPool{Name: "support-leads", Members: []PrincipalID{approverRaj, approverSam}}
	noneAnswerable := ApproverPool{Name: "sre", Members: []PrincipalID{approverAutomation}}

	t.Run("quorum reachable", func(t *testing.T) {
		eligible, adm := ApproverQuorumReachable(reg, fixtureOrg, twoHumans, ActorChain{fixtureAlice}, 2)
		if !adm.State.IsAdmitted() {
			t.Fatalf("two answerable members did not satisfy a quorum of two: %s", adm)
		}
		if len(eligible) != 2 {
			t.Fatalf("eligible set is %v", eligible)
		}
	})

	t.Run("fewer answerable than the quorum", func(t *testing.T) {
		_, adm := ApproverQuorumReachable(reg, fixtureOrg, twoHumans, ActorChain{fixtureAlice}, 3)
		assertDeny(t, adm, ReasonQuorumUnreachable)
		if !strings.Contains(adm.Detail, "quorum of 3") || !strings.Contains(adm.Detail, "2 member(s)") {
			t.Fatalf("the refusal does not carry both numbers, so an operator has to go and count: %s", adm)
		}
	})

	t.Run("nobody answerable is the other code", func(t *testing.T) {
		_, adm := ApproverQuorumReachable(reg, fixtureOrg, noneAnswerable, ActorChain{fixtureAlice}, 1)
		assertDeny(t, adm, ReasonEscalationUnreachable)
		if adm.Reason == ReasonQuorumUnreachable {
			t.Fatalf("an unanswerable pool was reported as an under-quorum one")
		}
	})

	t.Run("self-exclusion can take a pool under quorum", func(t *testing.T) {
		// Raj is in the requesting chain, so one answerable member remains and
		// a quorum of two is unreachable. The reason is QUORUM_UNREACHABLE and
		// not ESCALATION_UNREACHABLE, because somebody CAN answer.
		_, adm := ApproverQuorumReachable(reg, fixtureOrg, twoHumans, ActorChain{approverRaj}, 2)
		assertDeny(t, adm, ReasonQuorumUnreachable)
	})

	t.Run("self-exclusion emptying the pool is the unreachable code", func(t *testing.T) {
		_, adm := ApproverQuorumReachable(reg, fixtureOrg, twoHumans, ActorChain{approverRaj, approverSam}, 1)
		assertDeny(t, adm, ReasonEscalationUnreachable)
		if !strings.Contains(adm.Detail, "actor chain") {
			t.Fatalf("a pool emptied by exclusion is not distinguishable from an unanswerable one: %s", adm)
		}
	})

	t.Run("a non-positive quorum is refused, never trivially satisfied", func(t *testing.T) {
		for _, quorum := range []int{0, -1} {
			_, adm := ApproverQuorumReachable(reg, fixtureOrg, twoHumans, ActorChain{fixtureAlice}, quorum)
			assertDeny(t, adm, ReasonQuorumUnreachable)
			if adm.State.IsAdmitted() {
				t.Fatalf("quorum %d was treated as satisfied; a mis-serialised zero would silently disable the gate", quorum)
			}
		}
	})

	t.Run("an unresolvable registry is indeterminate, never a denial", func(t *testing.T) {
		// A directory blip terminating live approvals is a worse failure than a
		// slow one, and it is the kind that only shows up under load. The
		// approval plane leaves the clause pending on this.
		_, adm := ApproverQuorumReachable(nil, fixtureOrg, twoHumans, ActorChain{fixtureAlice}, 2)
		assertIndeterminate(t, adm, ReasonUnknownRealm)
	})

	// The two codes are distinct strings, which is what the approval plane
	// keys its verdicts on. A refactor collapsing them would make the two
	// remedies indistinguishable in the audit trail.
	if ReasonQuorumUnreachable == ReasonEscalationUnreachable {
		t.Fatalf("the two terminal approval reasons have collapsed to one string")
	}
}

// TestUnanswerablePoolIsNeverMaskedByAMalformedQuorum covers AXC-271.
//
// R3 found the ordering wrong. The quorum guard ran first, so an unanswerable
// pool with a mis-serialised quorum of zero reported QUORUM_UNREACHABLE, whose
// contract says some members CAN answer. The operator was handed the wrong
// remedy for the wrong problem, which is the one property the two codes exist
// to preserve.
func TestUnanswerablePoolIsNeverMaskedByAMalformedQuorum(t *testing.T) {
	MarkConformanceCase("AXC-271")

	reg := fixtureRegistry(t)
	unanswerable := ApproverPool{Name: "sre", Members: []PrincipalID{approverAutomation}}
	answerable := ApproverPool{Name: "support-leads", Members: []PrincipalID{approverRaj, approverSam}}

	// At a WELL-FORMED quorum, an unanswerable pool reports the pool's code.
	// That is the remedy the operator needs: the pool names realms that cannot
	// be asked a question.
	for _, quorum := range []int{1, 5} {
		_, adm := ApproverQuorumReachable(reg, fixtureOrg, unanswerable, ActorChain{fixtureAlice}, quorum)
		assertDeny(t, adm, ReasonEscalationUnreachable)
	}

	// At a MALFORMED quorum, the clause defect is reported, because it is
	// permanent and terminal whatever the pool turns out to be. Round two of
	// the review found the previous arrangement, which routed this through the
	// pool result, made a permanent configuration fault read as transient when
	// the pool could not be resolved, and an approval plane that retries on
	// Indeterminate would retry a clause that can never succeed.
	//
	// The pool's own outcome is DISCLOSED alongside rather than dropped, so
	// neither fault hides the other. That is the property both review rounds
	// were circling: two faults, two sentences, no adjudication between them.
	for _, quorum := range []int{0, -1} {
		_, adm := ApproverQuorumReachable(reg, fixtureOrg, unanswerable, ActorChain{fixtureAlice}, quorum)
		assertDeny(t, adm, ReasonQuorumUnreachable)
		if !strings.Contains(adm.Detail, string(ReasonEscalationUnreachable)) {
			t.Fatalf("the clause defect masked the pool defect instead of disclosing it: %s", adm)
		}

		_, adm = ApproverQuorumReachable(reg, fixtureOrg, answerable, ActorChain{fixtureAlice}, quorum)
		assertDeny(t, adm, ReasonQuorumUnreachable)
		if !strings.Contains(adm.Detail, "answerable by") {
			t.Fatalf("the refusal does not record that the pool itself is fine: %s", adm)
		}
	}

	// And the case that made the ordering matter: a permanent clause defect
	// must stay DETERMINATE even when the pool cannot be resolved at all. A
	// transient-looking refusal here is a clause an approval plane retries
	// forever.
	_, adm := ApproverQuorumReachable(nil, fixtureOrg, answerable, ActorChain{fixtureAlice}, 0)
	assertDeny(t, adm, ReasonQuorumUnreachable)
	if adm.State == AdmissionIndeterminate {
		t.Fatalf("a permanent clause defect was reported as transient: %s", adm)
	}
}
