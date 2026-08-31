// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"testing"
)

var (
	// Human approvers, in the interactive realm.
	approverRaj  = MustParsePrincipalID("User::workspace:raj")
	approverSam  = MustParsePrincipalID("User::workspace:sam")
	approverTess = MustParsePrincipalID("User::workspace:tess")
	// A service-account pool member, in the non-interactive realm. This is the
	// EX-46 member: service accounts land in approver groups for automation
	// reasons all the time.
	approverAutomation = MustNewGroupID(realmCloudIAM, "sre-automation")
)

// TestApproverPoolValidationRefusesNonInteractiveRealms covers AXC-260 (EX-46).
//
// The source case is an author submitting a ceiling that escalates to a pool in
// the cloud-IAM realm. It is rejected AT SAVE with POOL_NOT_INTERACTIVE, so it
// never becomes a live escalation. Without the check the escalation is issued,
// the eligible count is inflated by members that cannot answer, and it parks
// until on_timeout because nothing there can respond.
//
// The refusal names EVERY offending member rather than the first. An author
// fixing them one at a time learns about the next only on the next save, and a
// pool assembled from several directories usually has all of its
// non-interactive members from one of them.
func TestApproverPoolValidationRefusesNonInteractiveRealms(t *testing.T) {
	MarkConformanceCase("AXC-260")

	reg := fixtureRegistry(t)

	err := ValidateApproverPool(reg, fixtureOrg, ApproverPool{
		Name:    "sre-escalation",
		Members: []PrincipalID{approverAutomation},
	})
	if err == nil {
		t.Fatalf("a pool in a non-interactive realm was accepted at authoring time")
	}
	if !strings.Contains(err.Error(), string(ReasonPoolNotInteractive)) {
		t.Fatalf("the refusal does not carry POOL_NOT_INTERACTIVE: %v", err)
	}

	// A pool in the interactive realm is accepted, so the refusal is about the
	// realm's declaration and not about pools in general.
	if err := ValidateApproverPool(reg, fixtureOrg, ApproverPool{
		Name:    "support-leads",
		Members: []PrincipalID{approverRaj, approverSam},
	}); err != nil {
		t.Fatalf("a pool of human approvers was refused: %v", err)
	}

	// Every offending member is named, in one error.
	secondAutomation := MustNewGroupID(realmCloudIAM, "batch-runners")
	mixed := ApproverPool{
		Name:    "mixed",
		Members: []PrincipalID{approverRaj, approverAutomation, secondAutomation},
	}
	err = ValidateApproverPool(reg, fixtureOrg, mixed)
	if err == nil {
		t.Fatalf("a pool with two non-interactive members was accepted")
	}
	for _, member := range []PrincipalID{approverAutomation, secondAutomation} {
		if !strings.Contains(err.Error(), member.String()) {
			t.Fatalf("the refusal does not name %s: %v", member, err)
		}
	}

	// A member in an UNDECLARED realm is refused too. Treating the lookup miss
	// as "assume it can answer" would be EX-47 reached through the authoring
	// path rather than through a credential.
	undeclared := MustNewGroupID("acquired-co", "approvers")
	err = ValidateApproverPool(reg, fixtureOrg, ApproverPool{Name: "acquired", Members: []PrincipalID{undeclared}})
	if err == nil {
		t.Fatalf("a pool in an undeclared realm was accepted")
	}
	if !strings.Contains(err.Error(), string(ReasonUnknownRealm)) {
		t.Fatalf("the refusal does not carry UNKNOWN_REALM: %v", err)
	}

	// A disabled realm gets its own reason, and an empty pool is refused
	// because it can never reach quorum.
	disabledReg := fixtureRegistry(t)
	disabled := workspaceRealm()
	disabled.Enabled = false
	disabled.Version = 2
	if regErr := disabledReg.Register(disabled); regErr != nil {
		t.Fatalf("register: %v", regErr)
	}
	err = ValidateApproverPool(disabledReg, fixtureOrg, ApproverPool{Name: "p", Members: []PrincipalID{approverRaj}})
	if err == nil || !strings.Contains(err.Error(), string(ReasonRealmDisabled)) {
		t.Fatalf("a pool in a disabled realm produced %v", err)
	}
	if err := ValidateApproverPool(reg, fixtureOrg, ApproverPool{Name: "empty"}); err == nil {
		t.Fatalf("an empty pool was accepted")
	}
}

// TestInteractiveMembersCollapsesAnUnanswerablePool covers AXC-261 (EX-46).
//
// This is the runtime half. It is NOT redundant with the authoring check, and
// the two reasons it is not are both ordinary operations: a realm can be
// reconfigured from interactive to non-interactive after a policy referencing
// it was saved, and a policy can arrive through an import path that never ran
// the authoring check.
//
// Eligibility is counted over the interactive members only. That is the
// mechanism the source case turns on: counting raw membership inflates the
// eligible count, the escalation is issued, and it parks until timeout.
func TestInteractiveMembersCollapsesAnUnanswerablePool(t *testing.T) {
	MarkConformanceCase("AXC-261")

	reg := fixtureRegistry(t)

	eligible, adm := InteractiveMembers(reg, fixtureOrg, ApproverPool{
		Name:    "sre-escalation",
		Members: []PrincipalID{approverAutomation},
	})
	assertDeny(t, adm, ReasonEscalationUnreachable)
	if len(eligible) != 0 {
		t.Fatalf("an unanswerable pool produced eligible members %v", eligible)
	}

	// A mixed pool keeps only the members that can answer, and says so. The
	// count is what an escalation's quorum is taken over, so a silent
	// shrinkage would be a quorum an operator cannot reconcile with the pool
	// they wrote.
	eligible, adm = InteractiveMembers(reg, fixtureOrg, ApproverPool{
		Name:    "mixed",
		Members: []PrincipalID{approverRaj, approverAutomation, approverSam},
	})
	if !adm.State.IsAdmitted() {
		t.Fatalf("a pool with two human members was refused: %s", adm)
	}
	if len(eligible) != 2 {
		t.Fatalf("eligible members are %v, want the two human approvers", eligible)
	}
	for _, m := range eligible {
		if m.Realm != realmWorkspace {
			t.Fatalf("a member from a non-interactive realm survived: %s", m)
		}
	}
	if !strings.Contains(adm.Detail, approverAutomation.String()) {
		t.Fatalf("the dropped member is not named in the detail: %s", adm)
	}

	// The same fact, re-checked after a reconfiguration. This is the scenario
	// the authoring check cannot cover.
	reconfigured := fixtureRegistry(t)
	nonInteractive := workspaceRealm()
	nonInteractive.Interactive = InteractiveNonInteractive
	nonInteractive.Version = 2
	if err := reconfigured.Register(nonInteractive); err != nil {
		t.Fatalf("register: %v", err)
	}
	pool := ApproverPool{Name: "support-leads", Members: []PrincipalID{approverRaj, approverSam}}
	if err := ValidateApproverPool(reg, fixtureOrg, pool); err != nil {
		t.Fatalf("the pool must be valid against the ORIGINAL registry: %v", err)
	}
	_, adm = InteractiveMembers(reconfigured, fixtureOrg, pool)
	assertDeny(t, adm, ReasonEscalationUnreachable)

	// A nil registry is Indeterminate rather than a refusal: nothing about the
	// pool was found wanting.
	_, adm = InteractiveMembers(nil, fixtureOrg, pool)
	assertIndeterminate(t, adm, ReasonUnknownRealm)
	_, adm = InteractiveMembers(reg, "", pool)
	assertDeny(t, adm, ReasonOrgBindingMismatch)
}

// TestEligibleApproversExcludeTheWholeChain covers AXC-262.
//
// Separation of duties is about the REQUEST, not about which hop happens to be
// named as the requester. An agent acting for alice cannot approve alice's
// request and neither can alice, because both are in the chain. Excluding only
// the root would let the delegating agent approve the request it made.
//
// The second property is diagnostic and is why the interactive filter runs
// first: a pool emptied by self-exclusion and a pool emptied by an unanswerable
// realm need different remedies, and the caller can only tell them apart if the
// unanswerable case is reported before the exclusion happens.
func TestEligibleApproversExcludeTheWholeChain(t *testing.T) {
	MarkConformanceCase("AXC-262")

	reg := fixtureRegistry(t)
	pool := ApproverPool{
		Name:    "support-leads",
		Members: []PrincipalID{approverRaj, approverSam, approverTess},
	}

	// Raj is the middle hop of the chain, not its root. He is still excluded.
	chain := ActorChain{approverRaj, fixtureAgentA}
	eligible, adm := EligibleApprovers(reg, fixtureOrg, pool, chain)
	if !adm.State.IsAdmitted() {
		t.Fatalf("a pool with two remaining approvers was refused: %s", adm)
	}
	for _, m := range eligible {
		if chain.Contains(m) {
			t.Fatalf("%s is in the requesting chain and remained eligible", m)
		}
	}
	if len(eligible) != 2 {
		t.Fatalf("eligible approvers are %v, want sam and tess", eligible)
	}

	// The root is excluded too, which is the case that would pass even with a
	// root-only implementation, so it is asserted alongside the middle-hop one
	// rather than instead of it.
	rootChain := ActorChain{approverSam}
	eligible, _ = EligibleApprovers(reg, fixtureOrg, pool, rootChain)
	for _, m := range eligible {
		if m == approverSam {
			t.Fatalf("the chain root remained eligible")
		}
	}

	// A pool emptied by exclusion is ESCALATION_UNREACHABLE with a detail that
	// names the chain, so it reads differently from the unanswerable-realm
	// refusal even though both carry the same reason code.
	wholePool := ActorChain{approverRaj, approverSam, approverTess}
	_, adm = EligibleApprovers(reg, fixtureOrg, pool, wholePool)
	assertDeny(t, adm, ReasonEscalationUnreachable)
	if !strings.Contains(adm.Detail, "actor chain") {
		t.Fatalf("the exclusion refusal does not distinguish itself from an unanswerable pool: %s", adm)
	}

	unanswerable := ApproverPool{Name: "sre", Members: []PrincipalID{approverAutomation}}
	_, adm = EligibleApprovers(reg, fixtureOrg, unanswerable, ActorChain{fixtureAlice})
	assertDeny(t, adm, ReasonEscalationUnreachable)
	if strings.Contains(adm.Detail, "actor chain") {
		t.Fatalf("an unanswerable pool was reported as a self-exclusion: %s", adm)
	}
	if !strings.Contains(adm.Detail, "interactive realm") {
		t.Fatalf("the unanswerable refusal does not name the cause: %s", adm)
	}
}

// TestPoolAdmissionsNameNoPrincipal covers AXC-270.
//
// R3 found that these admissions carried an arbitrary pool member as their
// Principal. The field then reads as "the principal this admission is about"
// while holding one that self-exclusion may have just removed from the
// returned set, and a consumer attributing an audit record from it names the
// wrong person.
//
// The admission is about a SET. The zero principal matches nothing and is the
// honest value.
func TestPoolAdmissionsNameNoPrincipal(t *testing.T) {
	MarkConformanceCase("AXC-270")

	reg := fixtureRegistry(t)
	pool := ApproverPool{Name: "support-leads", Members: []PrincipalID{approverRaj, approverSam, approverTess}}

	_, adm := InteractiveMembers(reg, fixtureOrg, pool)
	if !adm.State.IsAdmitted() {
		t.Fatalf("an answerable pool was refused: %s", adm)
	}
	if !adm.Principal.IsZero() {
		t.Fatalf("a pool admission names principal %s; the admission is about the set, not a subject", adm.Principal)
	}

	// The case that made it wrong rather than merely odd: with raj excluded,
	// the returned set does not contain him, so an admission naming him would
	// name someone the caller was told is not eligible.
	chain := ActorChain{approverRaj}
	eligible, adm := EligibleApprovers(reg, fixtureOrg, pool, chain)
	if !adm.Principal.IsZero() {
		t.Fatalf("a pool admission names principal %s after self-exclusion", adm.Principal)
	}
	for _, m := range eligible {
		if m == approverRaj {
			t.Fatalf("the excluded member is still in the eligible set")
		}
	}
	if !strings.Contains(adm.Detail, approverRaj.String()) {
		t.Fatalf("the exclusion is not disclosed in the detail: %s", adm)
	}

	_, adm = ApproverQuorumReachable(reg, fixtureOrg, pool, chain, 2)
	if !adm.State.IsAdmitted() || !adm.Principal.IsZero() {
		t.Fatalf("quorum admission is %s with principal %s", adm.State, adm.Principal)
	}
}
