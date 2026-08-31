// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"fmt"
	"math/rand"
	"testing"
)

// TestAddingAnActorHopCannotWidenAuthority covers AXC-230 (EX-27).
//
// ADR-065 acceptance gate 6 states the property: adding an actor cannot widen
// authority. It is a PROPERTY, not a case, so it is tested as one: over random
// chains and random additional hops, the longer chain's effective authority
// must be a subset of the shorter one's.
//
// The generator draws capabilities from a small alphabet on purpose. A large
// alphabet makes almost every intersection empty, and a test in which the
// answer is nearly always the empty set passes just as readily against a
// broken implementation. With four capabilities and short chains, non-empty
// intersections are the common case, so the subset assertion is doing work on
// most iterations rather than on a handful.
func TestAddingAnActorHopCannotWidenAuthority(t *testing.T) {
	MarkConformanceCase("AXC-230")

	alphabet := []string{"read", "write", "refund", "export"}
	rng := rand.New(rand.NewSource(20260830))

	randomAuthority := func() Authority {
		var caps []string
		for _, c := range alphabet {
			if rng.Intn(2) == 0 {
				caps = append(caps, c)
			}
		}
		return NewAuthority(caps...)
	}

	nonEmptyResults := 0
	const iterations = 2000

	for i := 0; i < iterations; i++ {
		chainLen := 1 + rng.Intn(3)
		chain := make([]Authority, chainLen)
		for j := range chain {
			chain[j] = randomAuthority()
		}
		extra := randomAuthority()

		before := MeetAll(chain)
		after := MeetAll(append(append([]Authority(nil), chain...), extra))

		if !after.Subset(before) {
			t.Fatalf("iteration %d: adding a hop widened authority.\n  chain: %v\n  extra: %s\n  before: %s\n  after: %s",
				i, chain, extra, before, after)
		}
		if after.Len() > before.Len() {
			t.Fatalf("iteration %d: adding a hop grew the capability count %d -> %d", i, before.Len(), after.Len())
		}
		if before.Len() > 0 {
			nonEmptyResults++
		}
	}

	// Anti-vacuity: derive the floor from a second measurement rather than
	// picking a number that the observed run happens to clear. Each capability
	// survives a hop with probability 1/2, so over chains of length 1 to 3 the
	// expected fraction of iterations with a non-empty meet is well above a
	// third. A generator that produced empty authorities almost always would
	// still satisfy the subset assertion on every iteration while proving
	// nothing, and this is what catches that.
	minimumNonEmpty := iterations / 3
	if nonEmptyResults < minimumNonEmpty {
		t.Fatalf("only %d of %d iterations produced a non-empty authority before the extra hop (floor %d); "+
			"the subset assertion is passing on empty sets and proving nothing",
			nonEmptyResults, iterations, minimumNonEmpty)
	}
}

// TestConfusedDeputyMeetAcrossHeterogeneousRealms covers AXC-231 (EX-27).
//
// The source case: alice may spend up to $5,000 and agent-A holds a
// principal-scoped grant up to $50,000. Union across the chain grants $30,000
// to a principal entitled to $5,000, and every policy involved looks correct in
// isolation. The chain is heterogeneous, alice in the human realm and agent-A
// in the cloud-IAM one, which the source calls the normal case rather than an
// edge one.
//
// Capabilities stand in for the spend ceilings here because this package models
// authority as a capability set and leaves numeric ceilings to the policy
// plane. The structural property under test is the same one: the meet, not the
// union.
func TestConfusedDeputyMeetAcrossHeterogeneousRealms(t *testing.T) {
	MarkConformanceCase("AXC-231")

	reg := fixtureRegistry(t)
	chain := ActorChain{fixtureAlice, fixtureAgentA}

	// The chain itself is admissible: cross-realm delegation is ordinary.
	assertAdmitted(t, AdmitChain(reg, fixtureOrg, chain, 3), fixtureAlice)

	aliceAuthority := NewAuthority("refund.small", "read")
	agentAuthority := NewAuthority("refund.small", "refund.large", "read")

	effective := MeetAll([]Authority{aliceAuthority, agentAuthority})

	if effective.Contains("refund.large") {
		t.Fatalf("the agent's wider grant lifted its principal's limit: %s", effective)
	}
	if !effective.Contains("refund.small") {
		t.Fatalf("a capability both hops hold was lost: %s", effective)
	}
	if !effective.Equal(NewAuthority("read", "refund.small")) {
		t.Fatalf("effective authority is %s, want the intersection {read,refund.small}", effective)
	}

	// The mutant this kills: a union. Stated explicitly so the assertion above
	// cannot be satisfied by an implementation that happens to agree on this
	// input.
	union := NewAuthority(append(aliceAuthority.Capabilities(), agentAuthority.Capabilities()...)...)
	if effective.Equal(union) {
		t.Fatalf("effective authority equals the union of the hops; the meet is not being taken")
	}

	// Order does not change the result. A meet is commutative, and a chain
	// evaluated root-first must agree with the same hops evaluated in any
	// order, or the answer would depend on ingestion direction.
	reversed := MeetAll([]Authority{agentAuthority, aliceAuthority})
	if !reversed.Equal(effective) {
		t.Fatalf("the meet is order dependent: %s versus %s", effective, reversed)
	}
}

// TestEmptyChainAuthorizesNothing covers AXC-232.
//
// Intersection's identity element is the universal set, so the natural fold
// over zero hops permits everything. That is the mistake this guards, and it
// is guarded twice because either guard alone leaves a path: MeetAll returns
// the empty authority for an empty input, and AdmitChain refuses an empty
// chain before a fold is ever reached.
func TestEmptyChainAuthorizesNothing(t *testing.T) {
	MarkConformanceCase("AXC-232")

	if got := MeetAll(nil); !got.IsEmpty() {
		t.Fatalf("MeetAll over no hops returned %s; the identity element of intersection is the universal set and must not be constructible here", got)
	}
	if got := MeetAll([]Authority{}); !got.IsEmpty() {
		t.Fatalf("MeetAll over an empty slice returned %s", got)
	}

	var zero Authority
	if !zero.IsEmpty() {
		t.Fatalf("the zero Authority is not empty")
	}
	if zero.Contains("anything") {
		t.Fatalf("the zero Authority contains a capability")
	}
	if !MeetAll([]Authority{NewAuthority("read"), zero}).IsEmpty() {
		t.Fatalf("meeting with the zero Authority did not empty the result")
	}

	reg := fixtureRegistry(t)
	assertDeny(t, AdmitChain(reg, fixtureOrg, ActorChain{}, 3), ReasonChainEmpty)
	assertDeny(t, AdmitChain(reg, fixtureOrg, nil, 3), ReasonChainEmpty)

	// A single-hop chain is the shortest admissible one, and MeetAll over it
	// is that hop's own authority. This is the boundary where the widening
	// property legitimately does not hold, which is why the property test
	// above starts at length one.
	single := MeetAll([]Authority{NewAuthority("read")})
	if !single.Equal(NewAuthority("read")) {
		t.Fatalf("MeetAll over one hop is %s, want that hop's own authority", single)
	}
}

// TestAdmitChainFailsClosed covers AXC-233.
func TestAdmitChainFailsClosed(t *testing.T) {
	MarkConformanceCase("AXC-233")

	reg := fixtureRegistry(t)
	undeclared := MustParsePrincipalID("User::acquired-co:00u999")

	cases := []struct {
		name     string
		chain    ActorChain
		maxDepth int
		want     AdmissionReason
	}{
		{"cycle at the ends", ActorChain{fixtureAlice, fixtureAgentA, fixtureAlice}, 5, ReasonChainCycle},
		{"cycle adjacent", ActorChain{fixtureAlice, fixtureAgentA, fixtureAgentA}, 5, ReasonChainCycle},
		{"too deep", ActorChain{fixtureAlice, fixtureAgentA, fixtureSubB}, 2, ReasonDelegationDepth},
		{"unknown realm at the root", ActorChain{undeclared}, 3, ReasonUnknownRealm},
		{"unknown realm on a later hop", ActorChain{fixtureAlice, undeclared}, 3, ReasonUnknownRealm},
		{"malformed hop", ActorChain{fixtureAlice, {}}, 3, ReasonMalformedPrincipal},
		{"a group is not an actor", ActorChain{fixtureAlice, MustNewGroupID(realmWorkspace, "security")}, 3, ReasonSubjectTypeRejected},
		{"subject type the realm does not assert", ActorChain{MustParsePrincipalID("Service::workspace:svc-1")}, 3, ReasonSubjectTypeRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertDeny(t, AdmitChain(reg, fixtureOrg, tc.chain, tc.maxDepth), tc.want)
		})
	}

	// A disabled realm anywhere in the chain refuses, with its own reason.
	disabledReg := fixtureRegistry(t)
	disabled := cloudIAMRealm()
	disabled.Enabled = false
	disabled.Version = 2
	if err := disabledReg.Register(disabled); err != nil {
		t.Fatalf("register: %v", err)
	}
	assertDeny(t, AdmitChain(disabledReg, fixtureOrg, ActorChain{fixtureAlice, fixtureAgentA}, 3), ReasonRealmDisabled)

	// A non-positive depth bound is replaced by the default rather than read
	// as unbounded. A chain longer than the default therefore still refuses.
	tooLong := ActorChain{fixtureAlice, fixtureAgentA, fixtureSubB,
		MustParsePrincipalID("Agent::gcp-iam:sub-C"), MustParsePrincipalID("Agent::gcp-iam:sub-D")}
	if len(tooLong) <= DefaultMaxDelegationDepth {
		t.Fatalf("the fixture chain must exceed the default depth to test the substitution")
	}
	assertDeny(t, AdmitChain(reg, fixtureOrg, tooLong, 0), ReasonDelegationDepth)
	assertDeny(t, AdmitChain(reg, fixtureOrg, tooLong, -1), ReasonDelegationDepth)

	// A nil registry is Indeterminate: nothing about the chain was found
	// wanting, the plane could not resolve any hop's realm.
	assertIndeterminate(t, AdmitChain(nil, fixtureOrg, ActorChain{fixtureAlice}, 3), ReasonUnknownRealm)
	assertDeny(t, AdmitChain(reg, "", ActorChain{fixtureAlice}, 3), ReasonOrgBindingMismatch)

	// The admissible chain is admitted, and its root is the principal
	// reported, so every refusal above is attributable to its one difference.
	assertAdmitted(t, AdmitChain(reg, fixtureOrg, ActorChain{fixtureAlice, fixtureAgentA}, 3), fixtureAlice)
}

// TestAdmitChainCrossRealmDelegationPolicy covers AXC-234.
//
// EX-27 makes cross-realm chains the normal case, so the check cannot be "same
// realm". It is the DELEGATOR realm's declared policy, which means a realm can
// permit its subjects to be acted for by a named set of realms and by nothing
// else. The direction matters and is asserted: permitting realm A to delegate
// to realm B says nothing about B delegating to A.
func TestAdmitChainCrossRealmDelegationPolicy(t *testing.T) {
	MarkConformanceCase("AXC-234")

	build := func(t *testing.T, workspaceDelegation DelegationPolicy, delegates []RealmID) *RealmRegistry {
		t.Helper()
		reg := NewRealmRegistry()
		w := workspaceRealm()
		w.Delegation = workspaceDelegation
		w.DelegateRealms = delegates
		if err := reg.Register(w); err != nil {
			t.Fatalf("register workspace: %v", err)
		}
		if err := reg.Register(cloudIAMRealm()); err != nil {
			t.Fatalf("register cloud-iam: %v", err)
		}
		return reg
	}

	chain := ActorChain{fixtureAlice, fixtureAgentA}

	t.Run("denied", func(t *testing.T) {
		reg := build(t, DelegationDenied, nil)
		assertDeny(t, AdmitChain(reg, fixtureOrg, chain, 3), ReasonDelegationNotPermitted)
	})

	t.Run("allow list excluding the delegate", func(t *testing.T) {
		reg := build(t, DelegationAllowList, []RealmID{"some-other-realm"})
		assertDeny(t, AdmitChain(reg, fixtureOrg, chain, 3), ReasonDelegationNotPermitted)
	})

	t.Run("allow list including the delegate", func(t *testing.T) {
		reg := build(t, DelegationAllowList, []RealmID{realmCloudIAM})
		assertAdmitted(t, AdmitChain(reg, fixtureOrg, chain, 3), fixtureAlice)
	})

	t.Run("any realm in org", func(t *testing.T) {
		reg := build(t, DelegationAnyRealmInOrg, nil)
		assertAdmitted(t, AdmitChain(reg, fixtureOrg, chain, 3), fixtureAlice)
	})

	t.Run("the policy is directional", func(t *testing.T) {
		// workspace permits cloud-iam. cloud-iam permits nobody. A chain
		// rooted in cloud-iam and delegating to workspace must therefore be
		// refused, even though the reverse chain is admitted.
		reg := NewRealmRegistry()
		w := workspaceRealm()
		w.Delegation = DelegationAllowList
		w.DelegateRealms = []RealmID{realmCloudIAM}
		if err := reg.Register(w); err != nil {
			t.Fatalf("register workspace: %v", err)
		}
		c := cloudIAMRealm()
		c.Delegation = DelegationDenied
		if err := reg.Register(c); err != nil {
			t.Fatalf("register cloud-iam: %v", err)
		}

		assertAdmitted(t, AdmitChain(reg, fixtureOrg, ActorChain{fixtureAlice, fixtureAgentA}, 3), fixtureAlice)
		assertDeny(t, AdmitChain(reg, fixtureOrg, ActorChain{fixtureAgentA, fixtureAlice}, 3), ReasonDelegationNotPermitted)
	})
}

// TestClientIsAttributionNotAuthority covers AXC-235.
//
// ADR-065 invariant 2: client_id identifies the authenticated application. It
// is attribution, not a policy-selected identity. A Client at the chain root
// would make the calling application the authority a grant is scoped to, which
// is the shape the legacy path takes when it treats an unvalidated Basic
// username as a tenant.
//
// The second half is the part that is easy to get wrong in the other direction:
// a Client is still a legitimate INTERMEDIARY. Refusing it everywhere would
// make an authenticated gateway unrepresentable in a chain, and the gateway is
// exactly the hop an audit trail needs.
func TestClientIsAttributionNotAuthority(t *testing.T) {
	MarkConformanceCase("AXC-235")

	reg := fixtureRegistry(t)

	assertDeny(t, AdmitChain(reg, fixtureOrg, ActorChain{fixtureClient}, 3), ReasonSubjectTypeRejected)
	assertDeny(t, AdmitChain(reg, fixtureOrg, ActorChain{fixtureClient, fixtureAlice}, 3), ReasonSubjectTypeRejected)

	// The workspace realm must assert Client for the intermediary case to be
	// about position rather than about the realm's accepted types.
	withClient := workspaceRealm()
	withClient.AcceptedSubjectTypes = append(withClient.AcceptedSubjectTypes, SubjectClient)
	withClient.Version = 2
	if err := reg.Register(withClient); err != nil {
		t.Fatalf("register: %v", err)
	}

	assertAdmitted(t, AdmitChain(reg, fixtureOrg, ActorChain{fixtureAlice, fixtureClient}, 3), fixtureAlice)
	assertDeny(t, AdmitChain(reg, fixtureOrg, ActorChain{fixtureClient, fixtureAlice}, 3), ReasonSubjectTypeRejected)
}

// TestActorChainFromRFC8693IsRootFirst covers AXC-236.
//
// RFC 8693 nests `act` outward from the immediate actor, so a wire chain reads
// nearest-first. This package's in-memory order is root-first. The reversal has
// to happen exactly once, at ingestion, and a test that only checked the length
// or the set membership would not notice if it happened zero times or twice.
func TestActorChainFromRFC8693IsRootFirst(t *testing.T) {
	MarkConformanceCase("AXC-236")

	// Wire order: the workload made the call on behalf of the agent, which
	// acted on behalf of alice.
	wire := []PrincipalID{fixtureSubB, fixtureAgentA, fixtureAlice}
	chain := ActorChainFromRFC8693(wire)

	root, ok := chain.Root()
	if !ok || root != fixtureAlice {
		t.Fatalf("root is %s (ok=%t), want the original subject %s", root, ok, fixtureAlice)
	}
	immediate, ok := chain.Immediate()
	if !ok || immediate != fixtureSubB {
		t.Fatalf("immediate actor is %s (ok=%t), want the nearest wire hop %s", immediate, ok, fixtureSubB)
	}
	want := ActorChain{fixtureAlice, fixtureAgentA, fixtureSubB}
	if fmt.Sprint(chain) != fmt.Sprint(want) {
		t.Fatalf("chain is %s, want %s", chain, want)
	}

	// The conversion copies. The caller's slice frequently belongs to a parsed
	// token structure that other code still reads, and reversing it in place
	// would corrupt that for every later reader.
	if fmt.Sprint(wire) != fmt.Sprint([]PrincipalID{fixtureSubB, fixtureAgentA, fixtureAlice}) {
		t.Fatalf("ActorChainFromRFC8693 mutated its input: %v", wire)
	}

	// A single-hop wire chain is unchanged, and an empty one stays empty
	// rather than becoming a one-element chain of the zero principal.
	if got := ActorChainFromRFC8693([]PrincipalID{fixtureAlice}); len(got) != 1 || got[0] != fixtureAlice {
		t.Fatalf("single-hop conversion produced %s", got)
	}
	if got := ActorChainFromRFC8693(nil); len(got) != 0 {
		t.Fatalf("empty conversion produced %s", got)
	}

	// Contains covers the whole chain, which separation of duties depends on.
	if !chain.Contains(fixtureAgentA) {
		t.Fatalf("Contains missed a middle hop")
	}
	if chain.Contains(fixtureBob) {
		t.Fatalf("Contains matched a principal that is not in the chain")
	}
}

// TestAuthoritySetSemantics pins the value type's own guarantees, which the
// property test above relies on rather than re-establishes.
func TestAuthoritySetSemantics(t *testing.T) {
	a := NewAuthority("write", "read", "read", "", "export")

	caps := a.Capabilities()
	want := []string{"export", "read", "write"}
	if fmt.Sprint(caps) != fmt.Sprint(want) {
		t.Fatalf("NewAuthority produced %v, want sorted and de-duplicated %v with the empty string dropped", caps, want)
	}

	caps[0] = "mutated"
	if a.Contains("mutated") {
		t.Fatalf("Capabilities handed out the Authority's own slice")
	}

	if !a.Contains("read") || a.Contains("refund") {
		t.Fatalf("Contains is wrong on %s", a)
	}
	if !NewAuthority("read").Subset(a) {
		t.Fatalf("Subset is wrong")
	}
	if a.Subset(NewAuthority("read")) {
		t.Fatalf("Subset reported a superset as a subset")
	}
	if !a.Equal(NewAuthority("read", "write", "export")) {
		t.Fatalf("Equal is order sensitive")
	}
	if a.Equal(NewAuthority("read", "write")) {
		t.Fatalf("Equal ignored a missing capability")
	}
}
