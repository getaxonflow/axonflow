// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 approver quorum reachability (EX-46), consumed by the approval plane
// (#3551).
//
// InteractiveMembers answers "can anybody here answer at all". A clause also
// needs "can ENOUGH of them answer", and the two need different reason codes
// because they need different remedies: nobody can answer means the pool names
// the wrong realms or every member is the requester, while not enough can
// answer means shrink the quorum or widen the pool.
//
// The arithmetic lives here rather than in the approval plane so that one
// vocabulary reaches the audit surface. A count returned across a package
// boundary loses the reason and the detail, and the caller then has to
// reconstruct both from a number.
package identity

import (
	"fmt"
	"strings"
)

// ApproverQuorumReachable reports whether an approval clause can be satisfied
// at all, given the realms its pool members resolve in and the chain that must
// be excluded.
//
// Outcomes, and the remedy each one implies:
//
//	Accept                          quorum is reachable. The eligible set is
//	                                returned. If members were dropped as unable
//	                                to answer, the detail names them, so a
//	                                shrunken pool is visible rather than silent.
//	Deny(ESCALATION_UNREACHABLE)    nobody can answer, ever. Either every member
//	                                is in a realm that cannot be asked a
//	                                question, or every member is in the
//	                                requesting chain. The detail says which.
//	Deny(QUORUM_UNREACHABLE)        some can answer but fewer than the clause
//	                                requires. Terminal, and a different fix.
//	Indeterminate(UNKNOWN_REALM)    the realms could not be resolved at all.
//	                                NOT a denial: a directory blip terminating
//	                                live approvals is a worse failure than a
//	                                slow one, and it is the kind that only shows
//	                                up under load.
//
// A non-positive quorum is refused rather than treated as trivially satisfied.
// A clause requiring nobody is not an approval, and reading it as satisfied is
// the shape in which a mis-serialised zero silently disables an approval gate.
func ApproverQuorumReachable(
	reg *RealmRegistry, orgID string, pool ApproverPool, chain ActorChain, quorum int,
) ([]PrincipalID, Admission) {
	eligible, adm := EligibleApprovers(reg, orgID, pool, chain)

	// A NON-POSITIVE QUORUM IS A PERMANENT CLAUSE DEFECT, so it is terminal
	// whatever the pool turns out to be, and it is reported even when the pool
	// could not be resolved. Routing it through the pool result instead makes a
	// configuration fault read as transient, and an approval plane that retries
	// on Indeterminate then retries a clause that can never succeed.
	//
	// The pool's own outcome is DISCLOSED alongside rather than dropped. The
	// earlier arrangement reported only the quorum, and its reason code claims
	// some members can answer, which sent an operator to adjust a number on a
	// pool nobody could answer. Two faults, two sentences, no adjudication
	// between them.
	if quorum <= 0 {
		detail := fmt.Sprintf(
			"approver pool %q is required by a clause with quorum %d; a clause requiring nobody is not an approval and is never treated as satisfied",
			pool.Name, quorum)
		if adm.State.IsAdmitted() {
			detail += fmt.Sprintf(" (the pool itself is answerable by %d member(s))", len(eligible))
		} else {
			detail += fmt.Sprintf(" (and separately, the pool is not usable: %s)", adm)
		}
		return nil, DenyAdmission(ReasonQuorumUnreachable, detail)
	}

	if !adm.State.IsAdmitted() {
		// Passes through unchanged: ESCALATION_UNREACHABLE when nobody can
		// answer, Indeterminate when the realms could not be resolved. Both
		// already carry the detail that distinguishes the remedies.
		return nil, adm
	}

	if len(eligible) < quorum {
		names := make([]string, len(eligible))
		for i, m := range eligible {
			names[i] = m.String()
		}
		return nil, DenyAdmission(ReasonQuorumUnreachable, fmt.Sprintf(
			"approver pool %q requires a quorum of %d and %d member(s) can answer (%s); widen the pool or lower the quorum",
			pool.Name, quorum, len(eligible), strings.Join(names, ", ")))
	}

	return eligible, adm
}
