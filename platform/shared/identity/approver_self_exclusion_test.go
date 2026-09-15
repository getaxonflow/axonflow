// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"testing"
)

// The #3878 suite: an approver pool's self-exclusion compared a RENDERED
// principal, so a requester could remain eligible to approve their own
// escalation.
//
// Everything here is driven through EligibleApprovers and
// ApproverQuorumReachable rather than asserted about ContainsSubject directly.
// The defect was never in the membership helper on its own - `hop == p` is
// correct code for a comparable struct - it was in what that helper is asked
// to decide, and only the pool path shows that.

// selfExclusionRegistry returns a registry with the workspace realm plus a
// SECOND interactive realm, so "the same subject id in another realm" has
// somewhere to live.
//
// It has to be a second INTERACTIVE realm. The fixture's other realm, gcp-iam,
// is non-interactive, so a member there is dropped by InteractiveMembers before
// self-exclusion ever runs - and a test built on it would report "not excluded"
// for a reason that has nothing to do with the realm axis.
func selfExclusionRegistry(t *testing.T) *RealmRegistry {
	t.Helper()
	reg := fixtureRegistry(t)
	second := workspaceRealm()
	second.RealmID = realmWorkspaceTwo
	second.CanonicalIssuer = issuerWorkspaceTwo
	if err := reg.Register(second); err != nil {
		t.Fatalf("registering the second interactive realm: %v", err)
	}
	return reg
}

const (
	realmWorkspaceTwo   RealmID = "workspace-2"
	issuerWorkspaceTwo          = "https://idp2.acme.example"
	selfExclusionPoolNm         = "support-leads"
)

// TestSelfExclusionIsBySubjectRatherThanByClassification is the #3878 probe,
// promoted from a probe to an assertion.
//
// The two sides of this comparison get their principal type from different
// places: the chain's from the request's token, the pool member's from
// configuration that ValidateApproverPool's own comment describes as "a pool
// assembled from several directories". Two sources for one subject is exactly
// where two classifications diverge, and while the comparison included the
// type, `Agent::workspace:raj` in the chain did not match `User::workspace:raj`
// in the pool.
//
// THE NEGATIVE CONTROLS ARE THE HALF THAT MAKES IT AN ASSERTION. A widening
// that excluded everybody would satisfy the positive case and take every
// approval flow down with it, so a different subject and the same subject in a
// different realm are both required to SURVIVE. Realm is part of an identity;
// only the classification axis is folded.
func TestSelfExclusionIsBySubjectRatherThanByClassification(t *testing.T) {
	MarkConformanceCase("AXC-299")

	reg := selfExclusionRegistry(t)
	sameSubjectOtherRealm := MustParsePrincipalID("User::workspace-2:raj")
	pool := ApproverPool{
		Name:    selfExclusionPoolNm,
		Members: []PrincipalID{approverRaj, approverSam, sameSubjectOtherRealm},
	}

	// PRECONDITION, so every exclusion below is attributable to the chain and
	// not to the pool. Without it a fixture that dropped raj for an unrelated
	// reason would read as the property under test.
	base, adm := EligibleApprovers(reg, fixtureOrg, pool, ActorChain{approverTess})
	if !adm.State.IsAdmitted() {
		t.Fatalf("the baseline pool was refused: %s", adm)
	}
	if len(base) != 3 {
		t.Fatalf("the baseline eligible set is %v; all three members must be answerable before anything is excluded", base)
	}

	// THE DEFECT. raj raises the request as an Agent; the pool names raj as a
	// User. One subject, two classifications, two sources.
	rajAsAgent := MustParsePrincipalID("Agent::workspace:raj")
	if rajAsAgent == approverRaj {
		t.Fatal("the two spellings are the same value, so this test could not fail")
	}
	eligible, adm := EligibleApprovers(reg, fixtureOrg, pool, ActorChain{rajAsAgent})
	if !adm.State.IsAdmitted() {
		t.Fatalf("a pool with two remaining approvers was refused: %s", adm)
	}
	for _, m := range eligible {
		if m == approverRaj {
			t.Fatalf("%s raised the request and %s remained eligible to approve it; "+
				"the principal type classifies a subject rather than identifying one, so this is one person",
				rajAsAgent, approverRaj)
		}
	}

	// THE NEGATIVE CONTROLS, named individually rather than by a count, so a
	// widening that struck out the wrong member cannot pass on arithmetic.
	got := map[PrincipalID]bool{}
	for _, m := range eligible {
		got[m] = true
	}
	if !got[approverSam] {
		t.Errorf("a different subject was excluded; self-exclusion must strike out the requester and nobody else")
	}
	if !got[sameSubjectOtherRealm] {
		t.Errorf("%s was excluded by a chain hop in realm %q; two subjects with the same id in different realms are different principals, and the realm is never folded",
			sameSubjectOtherRealm, realmWorkspace)
	}
	if len(eligible) != 2 {
		t.Fatalf("eligible approvers are %v, want exactly sam and the other-realm raj", eligible)
	}

	// THE DIAGNOSTIC. A member struck out under a type the chain does not use
	// looks, in a one-sided log line, like a member who was never in the chain
	// - which is the one question an operator asks when a pool comes back
	// smaller than the configuration says.
	if !strings.Contains(adm.Detail, approverRaj.String()) {
		t.Errorf("the admission does not name the excluded member: %s", adm)
	}
	if !strings.Contains(adm.Detail, rajAsAgent.String()) {
		t.Errorf("the admission does not name the chain hop that matched, so the exclusion is unexplainable: %s", adm)
	}

	// AND THE EXACT SPELLING IS STILL EXCLUDED. This leg passed before the
	// correction too; it is here so that a mutant reverting ContainsSubject to
	// `hop == p` reds the leg above while this one stays green, which is what
	// makes the failure name the type axis rather than self-exclusion at large.
	eligible, _ = EligibleApprovers(reg, fixtureOrg, pool, ActorChain{approverRaj})
	for _, m := range eligible {
		if m == approverRaj {
			t.Fatalf("an exactly-spelled chain hop no longer excludes its own pool member")
		}
	}
}

// TestWideningSelfExclusionCanMakeAQuorumUnreachable states the cost of the
// #3878 correction as an assertion rather than as a caveat.
//
// Every other instance of this class makes a control STRICTER and the failure
// mode is somebody told no. This one strikes MORE members out of the approver
// pool, so a deployment whose quorum is exactly its answerable pool size goes
// from reachable to QUORUM_UNREACHABLE the moment a requester's classification
// differs from the pool's. That is a request-time path with somebody waiting,
// and it belongs in the suite where it is visible rather than in a release note
// where it is discovered.
//
// THE TWO REFUSALS ARE NOT THE SAME REFUSAL, and telling them apart is the
// whole point of the second half. ESCALATION_UNREACHABLE means nobody can
// answer - the pool was empty anyway - and QUORUM_UNREACHABLE means some can
// and there are too few. A test that accepted either could not distinguish
// "excluded correctly" from "the pool collapsed", which is the failure this
// assertion exists to make visible.
func TestWideningSelfExclusionCanMakeAQuorumUnreachable(t *testing.T) {
	reg := selfExclusionRegistry(t)
	pool := ApproverPool{
		Name:    selfExclusionPoolNm,
		Members: []PrincipalID{approverRaj, approverSam},
	}
	rajAsAgent := MustParsePrincipalID("Agent::workspace:raj")

	// REACHABLE, with the requester in a realm of their own and nobody struck
	// out. This is the shape of the deployment the correction does NOT affect,
	// and it is asserted first so the refusal below is attributable to the
	// exclusion rather than to the pool being too small to start with.
	eligible, adm := ApproverQuorumReachable(reg, fixtureOrg, pool, ActorChain{approverTess}, 2)
	if !adm.State.IsAdmitted() {
		t.Fatalf("a two-member pool with a quorum of two and an unrelated requester was refused: %s", adm)
	}
	if len(eligible) != 2 {
		t.Fatalf("eligible is %v, want both members", eligible)
	}

	// NO LONGER REACHABLE. Before the correction raj was not recognised in the
	// chain, both members counted, and this returned Accept.
	eligible, adm = ApproverQuorumReachable(reg, fixtureOrg, pool, ActorChain{rajAsAgent}, 2)
	if adm.State.IsAdmitted() {
		t.Fatalf("quorum 2 was reported reachable with eligible %v; the requester was counted as one of their own approvers", eligible)
	}
	assertDeny(t, adm, ReasonQuorumUnreachable)
	if !strings.Contains(adm.Detail, approverSam.String()) {
		t.Errorf("the refusal does not name who CAN answer, so an operator cannot tell a shrunken pool from an empty one: %s", adm)
	}
	if strings.Contains(string(adm.Reason), string(ReasonEscalationUnreachable)) {
		t.Errorf("a pool with one answerable member was reported as unanswerable: %s", adm)
	}

	// AND THE SAME DEPLOYMENT AT QUORUM 1 IS UNAFFECTED. Without this the
	// assertion above is satisfied by a correction that took every quorum down,
	// which is the outage this whole test exists to bound rather than to cause.
	eligible, adm = ApproverQuorumReachable(reg, fixtureOrg, pool, ActorChain{rajAsAgent}, 1)
	if !adm.State.IsAdmitted() {
		t.Fatalf("quorum 1 became unreachable with one answerable member left: %s", adm)
	}
	if len(eligible) != 1 || eligible[0] != approverSam {
		t.Fatalf("eligible is %v, want exactly sam", eligible)
	}

	// THE OTHER REFUSAL, so the two reason codes are pinned apart on inputs
	// that differ only in whether anybody survives.
	soloPool := ApproverPool{Name: selfExclusionPoolNm, Members: []PrincipalID{approverRaj}}
	_, adm = ApproverQuorumReachable(reg, fixtureOrg, soloPool, ActorChain{rajAsAgent}, 1)
	assertDeny(t, adm, ReasonEscalationUnreachable)
}

// TestOnePersonCannotBeTwoApproversOfAQuorum is the finding hostile review made
// against the exclusion fix above, and it is the harder half of the same class.
//
// Self-exclusion decides WHO IS eligible. This decides HOW MANY, and nothing
// deduplicated the eligible set - so a pool naming one person under two
// classifications offered TWO approvers, and ApproverQuorumReachable compares
// len(eligible) against the clause's quorum. A two-person rule was satisfiable
// by one person listed twice.
//
// The reachable shape is the same one that made the exclusion hole reachable:
// a pool assembled from several directories, each asserting its own
// classification for a subject both of them hold. Fixing the exclusion and not
// this would have closed "the requester approves themselves" while leaving
// "one person IS the quorum" open on the same pool.
func TestOnePersonCannotBeTwoApproversOfAQuorum(t *testing.T) {
	reg := selfExclusionRegistry(t)
	rajAsUser := approverRaj
	rajAsAgent := MustParsePrincipalID("Agent::workspace:raj")

	// PRECONDITION: two DIFFERENT people satisfy a quorum of two, so the
	// refusal below is attributable to the collapse and not to the arithmetic.
	twoPeople := ApproverPool{Name: selfExclusionPoolNm, Members: []PrincipalID{rajAsUser, approverSam}}
	if eligible, adm := ApproverQuorumReachable(reg, fixtureOrg, twoPeople, ActorChain{approverTess}, 2); !adm.State.IsAdmitted() {
		t.Fatalf("two different people did not satisfy a quorum of two (%v): %s", eligible, adm)
	}

	onePersonTwice := ApproverPool{Name: selfExclusionPoolNm, Members: []PrincipalID{rajAsUser, rajAsAgent}}
	eligible, adm := ApproverQuorumReachable(reg, fixtureOrg, onePersonTwice, ActorChain{approverTess}, 2)
	if adm.State.IsAdmitted() {
		t.Fatalf("a quorum of two was reported reachable by a pool naming one person twice; eligible = %v", eligible)
	}
	assertDeny(t, adm, ReasonQuorumUnreachable)

	// AND THE ONE PERSON IS STILL AN APPROVER, counted once. Without this,
	// a change that dropped both spellings would satisfy the assertion above
	// and would take an answerable pool down to nobody.
	eligible, adm = ApproverQuorumReachable(reg, fixtureOrg, onePersonTwice, ActorChain{approverTess}, 1)
	if !adm.State.IsAdmitted() {
		t.Fatalf("a quorum of one became unreachable for a pool that names one answerable person: %s", adm)
	}
	if len(eligible) != 1 {
		t.Fatalf("eligible is %v, want exactly one entry for one person", eligible)
	}
	if !eligible[0].SameSubject(rajAsUser) {
		t.Fatalf("the surviving entry is %s, which is not raj", eligible[0])
	}
	// THE COLLAPSE IS DISCLOSED, so a pool that comes back smaller than the
	// configuration is explainable rather than investigable.
	if !strings.Contains(adm.Detail, "already eligible") {
		t.Errorf("the admission does not disclose the collapse: %s", adm)
	}

	// A DIFFERENT SUBJECT IN ANOTHER REALM IS NOT COLLAPSED, which is the
	// negative control that stops this being a fold of everything.
	acrossRealms := ApproverPool{Name: selfExclusionPoolNm, Members: []PrincipalID{
		rajAsUser, MustParsePrincipalID("User::workspace-2:raj")}}
	eligible, adm = ApproverQuorumReachable(reg, fixtureOrg, acrossRealms, ActorChain{approverTess}, 2)
	if !adm.State.IsAdmitted() {
		t.Fatalf("two subjects with the same id in different realms were collapsed into one: %s", adm)
	}
	if len(eligible) != 2 {
		t.Fatalf("eligible is %v, want both realms' raj", eligible)
	}
}

// TestSubjectKeyIsTheRealmQualifiedSubjectAndNothingElse pins the axes
// SameSubject folds and the axes it must not.
//
// The zero case is the one worth stating: this package documents the zero
// PrincipalID as never matching anything, and an identity comparison that made
// two absent values equal would be reading "no identity" as an identity two
// requests share - the EX-47 shape, an undetermined fact read as a determinate
// one.
func TestSubjectKeyIsTheRealmQualifiedSubjectAndNothingElse(t *testing.T) {
	user := MustParsePrincipalID("User::workspace:raj")
	agent := MustParsePrincipalID("Agent::workspace:raj")
	otherRealm := MustParsePrincipalID("User::workspace-2:raj")
	otherSubject := MustParsePrincipalID("User::workspace:sam")
	upperSubject := MustParsePrincipalID("User::workspace:RAJ")

	if !user.SameSubject(agent) || !agent.SameSubject(user) {
		t.Errorf("%s and %s are one subject classified two ways", user, agent)
	}
	if user.SameSubject(otherRealm) {
		t.Errorf("%s and %s are different principals; the realm is what makes a collision impossible rather than unlikely", user, otherRealm)
	}
	if user.SameSubject(otherSubject) {
		t.Errorf("%s and %s are different subjects", user, otherSubject)
	}
	// NOT case-folded, and the difference from contract.CanonicalLocal is
	// deliberate: that folds an email because the roles store resolves one
	// case-insensitively, and Subject here is a realm's own opaque identifier -
	// an Okta id, a SPIFFE id - for which nothing establishes that.
	if user.SameSubject(upperSubject) {
		t.Errorf("%s and %s were folded together; a realm's subject id is opaque and case-sensitive", user, upperSubject)
	}

	var zero PrincipalID
	if zero.SameSubject(zero) {
		t.Error("two zero principals matched; the zero value is not a principal and never matches anything")
	}
	if zero.SameSubject(user) || user.SameSubject(zero) {
		t.Error("the zero principal matched a real one")
	}
	if _, ok := zero.SubjectKey(); ok {
		t.Error("the zero principal reported a subject key")
	}
	if _, ok := (PrincipalID{Type: SubjectUser, Subject: "raj"}).SubjectKey(); ok {
		t.Error("a principal with no realm reported a subject key; an unqualified subject is never completed with a default realm")
	}
	if _, ok := (PrincipalID{Realm: realmWorkspace, Type: SubjectUser}).SubjectKey(); ok {
		t.Error("a principal with no subject reported a subject key")
	}
}

// TestAdmitChainTreatsOneSubjectUnderTwoTypesAsARepeat covers the twin site.
//
// AdmitChain's fourth check is "no principal repeats", and it keyed its seen
// map on the comparable struct - which includes the type - so
// [User::workspace:raj, Agent::workspace:raj] was admitted as two principals.
// A principal is a subject; that chain revisits raj.
//
// contract.Request.Validate runs the same rule one module over, keyed on
// ID.String(), and had the identical hole. Both are corrected together, and
// TestTheActorChainCycleCheckIsBySubjectRatherThanByRenderedForm in that
// package is this assertion's twin.
func TestAdmitChainTreatsOneSubjectUnderTwoTypesAsARepeat(t *testing.T) {
	reg := fixtureRegistry(t)
	rajUser := MustParsePrincipalID("User::workspace:raj")
	rajAgent := MustParsePrincipalID("Agent::workspace:raj")

	// PRECONDITION: a chain of two DIFFERENT subjects in the same realm is
	// admitted, so the refusal below is attributable to the repeat and not to
	// the realm's delegation policy or to the depth bound.
	if adm := AdmitChain(reg, fixtureOrg, ActorChain{rajUser, MustParsePrincipalID("Agent::workspace:sam")}, 4); !adm.State.IsAdmitted() {
		t.Fatalf("a two-subject chain was refused, so this test could not attribute the refusal below: %s", adm)
	}

	adm := AdmitChain(reg, fixtureOrg, ActorChain{rajUser, rajAgent}, 4)
	if adm.State.IsAdmitted() {
		t.Fatalf("the chain %s was admitted; one subject delegating to itself is a repeat whatever type each hop declares", ActorChain{rajUser, rajAgent})
	}
	// THE REASON, not merely the refusal. A chain refused for the wrong reason
	// sends an operator to the delegation policy for a defect in the chain.
	if adm.Reason != ReasonChainCycle {
		t.Fatalf("the repeat was refused as %s, want %s: %s", adm.Reason, ReasonChainCycle, adm)
	}
	// The exactly-spelled repeat was refused before this correction too, and is
	// asserted alongside so a mutant that reverts the key reds the case above
	// while this one stays green.
	if adm := AdmitChain(reg, fixtureOrg, ActorChain{rajUser, rajUser}, 4); adm.Reason != ReasonChainCycle {
		t.Fatalf("an exactly-repeated hop is no longer a cycle: %s", adm)
	}
}
