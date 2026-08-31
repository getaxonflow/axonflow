// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestNoGraphRealmIsAuthoritativeEmpty covers AXC-243 (EX-45).
//
// A cloud-IAM service account resolves in a realm that has no group concept at
// all. Its empty closure is a FACT about the realm, not a failure to read one,
// and it has to be usable: collapsing it into the indeterminate states makes
// every IAM-sourced service account permanently indeterminate, which is an
// outage for exactly the population that most needs autonomous operation.
//
// The state is derived from the realm's DECLARED directory source, never from
// whether any data was found. That is the whole asymmetry, and the companion
// test below is the other half of it.
func TestNoGraphRealmIsAuthoritativeEmpty(t *testing.T) {
	MarkConformanceCase("AXC-243")

	resolver := NoGraphOnlyResolver{Now: func() time.Time { return fixtureNow }}
	agent := MustParsePrincipalID("Workload::gcp-iam:spiffe://acme.example/workload/jira-bot")

	res := resolver.ResolveClosure(context.Background(), fixtureOrg, cloudIAMRealm(), agent, ClosureBounds{})

	if res.State != ClosureStateNoGraph {
		t.Fatalf("state is %s, want NO_GRAPH", res.State)
	}
	if !res.State.IsAuthoritative() {
		t.Fatalf("a realm with no group graph did not produce an authoritative result")
	}

	groups, ok := res.AuthoritativeGroups()
	if !ok {
		t.Fatalf("AuthoritativeGroups refused a no-graph result; the service account is now permanently indeterminate")
	}
	if len(groups) != 0 {
		t.Fatalf("want an empty group set, got %v", groups)
	}

	got, adm := res.MustBeAuthoritative()
	if !adm.State.IsAdmitted() {
		t.Fatalf("MustBeAuthoritative refused a no-graph result: %s", adm)
	}
	if len(got) != 0 {
		t.Fatalf("want an empty group set, got %v", got)
	}
	if res.Reason != ReasonNone {
		t.Fatalf("an authoritative result carries reason %q; nothing went wrong", res.Reason)
	}
}

// TestGraphRealmOutageIsUnreachableNotEmpty covers AXC-244.
//
// This is the direction that fails open if it is got wrong. A realm that
// DECLARES a group graph and cannot produce one must never resolve to an empty
// set, because an empty closure removes every segment-scoped grant and every
// segment-scoped ceiling, and it is indistinguishable from a legitimate
// non-member.
//
// Three routes reach it and all three are asserted, because each is a different
// place a stub could quietly return an empty set: a build with no directory
// integration wired, an explicit outage, and a snapshot that was never loaded.
func TestGraphRealmOutageIsUnreachableNotEmpty(t *testing.T) {
	MarkConformanceCase("AXC-244")

	resolver := NoGraphOnlyResolver{Now: func() time.Time { return fixtureNow }}
	res := resolver.ResolveClosure(context.Background(), fixtureOrg, workspaceRealm(), fixtureAlice, ClosureBounds{})

	if res.State != ClosureStateUnreachable {
		t.Fatalf("state is %s, want UNREACHABLE", res.State)
	}
	if res.State.IsAuthoritative() {
		t.Fatalf("an unreadable group graph produced an authoritative result")
	}
	if groups, ok := res.AuthoritativeGroups(); ok {
		t.Fatalf("AuthoritativeGroups handed out %v for an unreachable closure", groups)
	}

	got, adm := res.MustBeAuthoritative()
	assertIndeterminate(t, adm, ReasonClosureUnavailable)
	if got != nil {
		t.Fatalf("MustBeAuthoritative returned a group set alongside a refusal: %v", got)
	}

	// The two realms differ ONLY in their declared directory source, so the
	// difference in outcome is attributable to that field and to nothing else.
	// This is the pair EX-45 and the SCIM-outage rule say must not share a
	// code path.
	noGraph := workspaceRealm()
	noGraph.Directory = DirectorySourceNone
	sibling := resolver.ResolveClosure(context.Background(), fixtureOrg, noGraph, fixtureAlice, ClosureBounds{})
	if sibling.State != ClosureStateNoGraph {
		t.Fatalf("flipping only the directory source did not change the state: %s", sibling.State)
	}
	if res.State == sibling.State {
		t.Fatalf("a realm with a graph and a realm without one produced the same closure state %s", res.State)
	}
}

// TestZeroClosureResultIsNotAuthoritative covers AXC-247.
//
// The mutant is a forgotten assignment: a ClosureResult declared and returned
// without its state ever being set. If the zero ClosureState were
// authoritative, that result would read as "this subject is in no groups" and
// silently drop every group-scoped control, which is EX-47's shape reached
// through a different door.
func TestZeroClosureResultIsNotAuthoritative(t *testing.T) {
	MarkConformanceCase("AXC-247")

	var zeroState ClosureState
	if zeroState != ClosureStateUnspecified {
		t.Fatalf("the zero ClosureState is not ClosureStateUnspecified")
	}
	if zeroState.IsAuthoritative() {
		t.Fatalf("the zero ClosureState reports itself authoritative")
	}

	var zero ClosureResult
	if groups, ok := zero.AuthoritativeGroups(); ok {
		t.Fatalf("the zero ClosureResult handed out groups %v", groups)
	}
	got, adm := zero.MustBeAuthoritative()
	if adm.State != AdmissionIndeterminate {
		t.Fatalf("the zero ClosureResult produced %s, want Indeterminate", adm)
	}
	if adm.Reason == ReasonNone {
		t.Fatalf("the zero ClosureResult produced an Indeterminate with no reason code")
	}
	if got != nil {
		t.Fatalf("the zero ClosureResult returned groups alongside a refusal")
	}

	// Every non-authoritative state refuses, so a state constant added later
	// without an IsAuthoritative case fails here rather than shipping.
	for _, state := range []ClosureState{
		ClosureStateUnspecified, ClosureStateUnreachable, ClosureStateTruncated,
	} {
		if state.IsAuthoritative() {
			t.Errorf("%s reports itself authoritative", state)
		}
	}
	for _, state := range []ClosureState{ClosureStateAuthoritative, ClosureStateNoGraph} {
		if !state.IsAuthoritative() {
			t.Errorf("%s does not report itself authoritative", state)
		}
	}
}

// TestPartialGroupsIsDiagnosticsOnly pins that a truncated result keeps what it
// saw for an operator report while refusing to hand it to policy.
//
// Both halves matter. Without the retained set an operator cannot see what a
// truncated traversal reached, and without the refusal the retained set is a
// partial closure one field access away from a policy input.
func TestPartialGroupsIsDiagnosticsOnly(t *testing.T) {
	partial := []PrincipalID{
		MustNewGroupID(realmWorkspace, "support"),
		MustNewGroupID(realmWorkspace, "all-staff"),
	}
	res := NewTruncatedClosure(fixtureAlice, partial, nil, nil, 2, "bound reached", "v1", fixtureNow)

	if _, ok := res.AuthoritativeGroups(); ok {
		t.Fatalf("a truncated closure handed out an authoritative group set")
	}
	if got := res.PartialGroups(); len(got) != 2 {
		t.Fatalf("the truncated closure did not retain what it saw: %v", got)
	}
	if _, adm := res.MustBeAuthoritative(); adm.Reason != ReasonClosureTruncated {
		t.Fatalf("a truncated closure reported %s, want CLOSURE_TRUNCATED", adm)
	}

	// PartialGroups hands out a copy, so a diagnostic report cannot edit the
	// result another consumer still holds.
	got := res.PartialGroups()
	got[0] = fixtureAlice
	if res.PartialGroups()[0] == fixtureAlice {
		t.Fatalf("PartialGroups handed out the result's own slice")
	}
}

// TestAttributeFreshnessIsTriState covers AXC-256.
//
// ADR-065 requires every policy-visible attribute to carry a maximum acceptable
// age, and says an attribute outside its freshness bound is UNKNOWN. Both halves
// need the tri-state. A boolean IsFresh would have to answer something for an
// attribute with no declared bound, and either answer is wrong: true makes an
// unbounded attribute permanently usable, which is the opposite of the
// requirement, and false makes it indistinguishable from a stale one, which
// hides a configuration error behind an operational-looking symptom.
func TestAttributeFreshnessIsTriState(t *testing.T) {
	MarkConformanceCase("AXC-256")

	fresh := DirectoryAttribute{
		Name: "active", Value: "true", Provenance: ProvenanceDirectory,
		ObservedAt: fixtureNow.Add(-time.Minute), MaxAge: time.Hour,
	}
	if got := fresh.Freshness(fixtureNow); got != FreshnessFresh {
		t.Fatalf("freshness is %s, want fresh", got)
	}
	if !fresh.IsUsable(fixtureNow) {
		t.Fatalf("a fresh attribute is not usable")
	}

	stale := fresh
	stale.ObservedAt = fixtureNow.Add(-2 * time.Hour)
	if got := stale.Freshness(fixtureNow); got != FreshnessStale {
		t.Fatalf("freshness is %s, want stale", got)
	}
	if stale.IsUsable(fixtureNow) {
		t.Fatalf("a stale attribute is usable; a stale security attribute must be unknown, not its last known value")
	}

	undeclared := fresh
	undeclared.MaxAge = 0
	if got := undeclared.Freshness(fixtureNow); got != FreshnessUndeclared {
		t.Fatalf("freshness is %s, want undeclared", got)
	}
	if undeclared.IsUsable(fixtureNow) {
		t.Fatalf("an attribute with no declared maximum age is usable as a policy input")
	}

	noObservation := fresh
	noObservation.ObservedAt = time.Time{}
	if got := noObservation.Freshness(fixtureNow); got != FreshnessUndeclared {
		t.Fatalf("an attribute with no observation time reports %s", got)
	}

	// The zero value is undeclared, so a struct built without the freshness
	// fields is never a usable policy input.
	var zero DirectoryAttribute
	if zero.IsUsable(fixtureNow) {
		t.Fatalf("the zero DirectoryAttribute is usable")
	}
}

// TestClosureBoundsZeroMeansDefaultNotUnlimited pins that an unconfigured
// bound is the default rather than no bound.
//
// A zero bound read as unlimited is a request that never returns over a
// pathological directory, and it is the reading a caller gets for free by
// passing ClosureBounds{}.
func TestClosureBoundsZeroMeansDefaultNotUnlimited(t *testing.T) {
	got := ClosureBounds{}.Normalized()
	want := DefaultClosureBounds()
	if got != want {
		t.Fatalf("zero bounds normalized to %+v, want the defaults %+v", got, want)
	}

	partial := ClosureBounds{MaxDepth: 3}.Normalized()
	if partial.MaxDepth != 3 {
		t.Fatalf("a declared bound was overwritten: %+v", partial)
	}
	if partial.MaxGroups != want.MaxGroups || partial.MaxFanOut != want.MaxFanOut {
		t.Fatalf("the undeclared bounds did not take their defaults: %+v", partial)
	}

	negative := ClosureBounds{MaxDepth: -1, MaxGroups: -1, MaxFanOut: -1}.Normalized()
	if negative != want {
		t.Fatalf("negative bounds normalized to %+v, want the defaults", negative)
	}
}

// TestGroupIdentifiersAreAlwaysRealmQualified pins that a group cannot be named
// without its realm.
//
// Two directories can both have a group called "security". A policy naming the
// bare string would target whichever one resolved first, which is a realm
// collision that looks like correct behavior until the second directory is
// federated.
func TestGroupIdentifiersAreAlwaysRealmQualified(t *testing.T) {
	a := MustNewGroupID("workspace", "security")
	b := MustNewGroupID("gcp-iam", "security")

	if a == b {
		t.Fatalf("the same group name in two realms produced one identifier")
	}
	if a.Type != SubjectGroup || b.Type != SubjectGroup {
		t.Fatalf("NewGroupID did not produce Group principals")
	}
	if a.String() != "Group::workspace:security" {
		t.Fatalf("group wire form is %q", a.String())
	}
	if _, err := NewGroupID("", "security"); err == nil {
		t.Fatalf("a group was created with no realm")
	}
	if _, err := NewGroupID("workspace", ""); err == nil {
		t.Fatalf("a group was created with no name")
	}
}

// TestGroupsAttributeIsTheTriStateThePDPConsumes covers AXC-249.
//
// The PDP does not resolve closures; group membership reaches it as an ordinary
// tri-state attribute and Kleene logic does the rest with no special case. That
// only works if the producer distinguishes an authoritative empty set from an
// unresolvable one, so this conversion is the contract between the two planes
// and the place a mistake would be invisible from either side.
//
// The two-reasons assertion is the substance. Truncated and unreachable are both
// Unknown and the PDP treats them identically, which is right. They carry
// different reasons anyway, because the cost of collapsing them is paid entirely
// by whoever is triaging: one says look at the directory provider, the other says
// look at the bounds.
func TestGroupsAttributeIsTheTriStateThePDPConsumes(t *testing.T) {
	MarkConformanceCase("AXC-249")

	support := MustNewGroupID(realmWorkspace, "support")
	staff := MustNewGroupID(realmWorkspace, "all-staff")

	t.Run("authoritative with groups is known", func(t *testing.T) {
		res := NewAuthoritativeClosure(fixtureAlice, []PrincipalID{staff, support}, nil, nil, 2, "v1", fixtureNow)
		attr := res.GroupsAttribute()
		if !attr.Known {
			t.Fatalf("a completed traversal is not known")
		}
		want := []string{"Group::workspace:all-staff", "Group::workspace:support"}
		if fmt.Sprint(attr.Groups) != fmt.Sprint(want) {
			t.Fatalf("groups are %v, want the canonical ids sorted %v", attr.Groups, want)
		}
		if attr.UnknownReason != ReasonNone {
			t.Fatalf("a known attribute carries reason %q", attr.UnknownReason)
		}
	})

	t.Run("no-graph is known and empty, not absent", func(t *testing.T) {
		attr := NewNoGraphClosure(fixtureAgentA, cloudIAMRealm(), fixtureNow).GroupsAttribute()
		if !attr.Known {
			t.Fatalf("a realm with no group concept produced an unknown attribute; every cloud-IAM service account is now permanently indeterminate")
		}
		if len(attr.Groups) != 0 {
			t.Fatalf("groups are %v, want the empty set", attr.Groups)
		}
	})

	t.Run("unreachable and truncated are both unknown, with different reasons", func(t *testing.T) {
		unreachable := NewUnreachableClosure(fixtureAlice, "provider timing out", fixtureNow).GroupsAttribute()
		truncated := NewTruncatedClosure(fixtureAlice, []PrincipalID{support}, nil, nil, 1, "bound reached", "v1", fixtureNow).GroupsAttribute()

		for name, attr := range map[string]ClosureAttribute{"unreachable": unreachable, "truncated": truncated} {
			if attr.Known {
				t.Fatalf("%s produced a known attribute", name)
			}
			if len(attr.Groups) != 0 {
				t.Fatalf("%s handed out groups %v alongside an unknown state", name, attr.Groups)
			}
			if attr.UnknownReason == ReasonNone {
				t.Fatalf("%s carries no reason, which invites a consumer to read it as merely absent", name)
			}
		}
		if unreachable.UnknownReason == truncated.UnknownReason {
			t.Fatalf("an outage and a bound share the reason %q; the two need different remedies and an operator cannot tell them apart",
				unreachable.UnknownReason)
		}
		if unreachable.UnknownReason != ReasonClosureUnavailable {
			t.Fatalf("an outage reports %q", unreachable.UnknownReason)
		}
		if truncated.UnknownReason != ReasonClosureTruncated {
			t.Fatalf("a bound reports %q", truncated.UnknownReason)
		}
	})

	t.Run("the zero result is unknown with a reason, never known-empty", func(t *testing.T) {
		var zero ClosureResult
		attr := zero.GroupsAttribute()
		if attr.Known {
			t.Fatalf("an unpopulated result rendered as a known empty group set, which is the fail-open this conversion exists to prevent")
		}
		if attr.UnknownReason != ReasonClosureUnavailable {
			t.Fatalf("the zero result carries reason %q, want the conservative one", attr.UnknownReason)
		}
	})
}

// TestAZeroRealmNeverProducesAnAuthoritativeClosure covers AXC-264.
//
// R3 found this and it is the controlling failure shape reached through a door
// neither existing mechanism guarded.
//
// RealmRegistry.Lookup returns (TrustRealm{}, false) on a miss. A caller that
// ignores the boolean hands a ZERO TrustRealm to a resolver, and a zero realm's
// DirectorySource is Unspecified, whose HasGroupGraph is false. That landed in
// the no-graph branch and produced an AUTHORITATIVE EMPTY closure: EX-47
// exactly, with every segment-scoped ceiling skipped and the PDP told the
// answer was known.
//
// Neither existing mechanism reached it. Registration refusing underspecified
// realms does not, because the zero realm was never registered. Denying an
// undeclared issuer does not, because this path never consulted an issuer.
// Three doors, three guards.
//
// The test drives the ACTUAL miss, `reg.Lookup` on an undeclared realm, rather
// than a hand-built TrustRealm{}, so it exercises the exact value a real caller
// would forward.
func TestAZeroRealmNeverProducesAnAuthoritativeClosure(t *testing.T) {
	MarkConformanceCase("AXC-264")

	reg := fixtureRegistry(t)
	zeroRealm, ok := reg.Lookup(fixtureOrg, "never-declared")
	if ok {
		t.Fatalf("the fixture registry unexpectedly holds the undeclared realm")
	}
	if zeroRealm.RealmID != "" {
		t.Fatalf("a lookup miss returned a populated realm: %+v", zeroRealm)
	}

	resolver := NoGraphOnlyResolver{Now: func() time.Time { return fixtureNow }}
	res := resolver.ResolveClosure(context.Background(), fixtureOrg, zeroRealm, fixtureAlice, ClosureBounds{})

	if res.State.IsAuthoritative() {
		t.Fatalf("a zero TrustRealm produced an authoritative closure (state %s); this is EX-47 through the resolver's front door", res.State)
	}
	if groups, usable := res.AuthoritativeGroups(); usable {
		t.Fatalf("a zero TrustRealm produced a usable group set %v", groups)
	}
	if attr := res.GroupsAttribute(); attr.Known {
		t.Fatalf("a zero TrustRealm told the PDP the group set is known")
	}
	if _, adm := res.MustBeAuthoritative(); adm.State.IsAdmitted() {
		t.Fatalf("a zero TrustRealm was admitted: %s", adm)
	}

	// A DECLARED realm whose directory source was left unset is the same class
	// reached from a hand-built struct rather than from a lookup miss. It
	// cannot be registered, but it can be constructed, and a resolver must not
	// answer it either.
	underspecified := cloudIAMRealm()
	underspecified.Directory = DirectorySourceUnspecified
	under := resolver.ResolveClosure(context.Background(), fixtureOrg, underspecified, fixtureAlice, ClosureBounds{})
	if under.State.IsAuthoritative() {
		t.Fatalf("a realm with an undeclared directory source produced an authoritative closure: %s", under.State)
	}

	// A DECLARED realm that is administratively DISABLED is refused too. Every
	// other plane refuses one; round two of the review found the closure plane
	// alone answering for a realm an operator had switched off, which is worse
	// than inconsistent, because disabling a realm is how a compromised
	// directory is taken out of service.
	disabled := cloudIAMRealm()
	disabled.Enabled = false
	off := resolver.ResolveClosure(context.Background(), fixtureOrg, disabled, fixtureAgentA, ClosureBounds{})
	if off.State.IsAuthoritative() {
		t.Fatalf("a disabled realm produced an authoritative closure: %s", off.State)
	}

	// A realm declared in ANOTHER organization is refused. The graph is keyed
	// on the argument organization while the declaration comes from the
	// caller's TrustRealm, so without this one organization's declaration
	// resolves against another's directory.
	foreign := cloudIAMRealm()
	foreign.OrgID = fixtureOtherOrg
	cross := resolver.ResolveClosure(context.Background(), fixtureOrg, foreign, fixtureAgentA, ClosureBounds{})
	if cross.State.IsAuthoritative() {
		t.Fatalf("a realm from another organization produced an authoritative closure: %s", cross.State)
	}

	// An out-of-RANGE directory source is refused, not just the zero one. A
	// guard written as inequality against Unspecified admits every other value,
	// and DirectorySource(99).HasGroupGraph() is false, which is the permissive
	// default the tri-state exists to abolish.
	outOfRange := cloudIAMRealm()
	outOfRange.Directory = DirectorySource(99)
	oor := resolver.ResolveClosure(context.Background(), fixtureOrg, outOfRange, fixtureAgentA, ClosureBounds{})
	if oor.State.IsAuthoritative() {
		t.Fatalf("an out-of-range directory source produced an authoritative closure: %s", oor.State)
	}
	if err := outOfRange.Validate(); err == nil {
		t.Fatalf("a realm with an out-of-range directory source validated")
	}

	// The properly declared realm still answers authoritatively, so the guard
	// refuses only what it should. Without this the test would pass against a
	// resolver that refused everything, which would break every service account
	// instead. The subject must be IN that realm: an out-of-realm subject is
	// its own refusal, which is the next assertion.
	good := resolver.ResolveClosure(context.Background(), fixtureOrg, cloudIAMRealm(), fixtureAgentA, ClosureBounds{})
	if !good.State.IsAuthoritative() {
		t.Fatalf("a correctly declared no-graph realm stopped answering: %s", good.State)
	}
	mismatched := resolver.ResolveClosure(context.Background(), fixtureOrg, cloudIAMRealm(), fixtureAlice, ClosureBounds{})
	if mismatched.State.IsAuthoritative() {
		t.Fatalf("a subject from another realm produced an authoritative closure: %s", mismatched.State)
	}
}

// TestAuthoritativeGroupsHandsOutACopy pins the copy on the ONE closure
// accessor whose output reaches policy.
//
// R3 found that removing the copy survived the suite. The asymmetry was the
// tell: PartialGroups (diagnostics only) and Witness were both pinned, and the
// method whose result is authority was not. A consumer sorting or filtering in
// place would corrupt the retained result, and the corruption propagates into
// the PDP attribute and into any decision proof taken afterwards.
func TestAuthoritativeGroupsHandsOutACopy(t *testing.T) {
	original := []PrincipalID{
		MustNewGroupID(realmWorkspace, "aaa"),
		MustNewGroupID(realmWorkspace, "zzz"),
	}
	res := NewAuthoritativeClosure(fixtureAlice, original, nil, nil, 1, "v1", fixtureNow)

	first, ok := res.AuthoritativeGroups()
	if !ok || len(first) != 2 {
		t.Fatalf("closure refused or returned %d groups", len(first))
	}
	first[0] = MustNewGroupID(realmWorkspace, "ATTACKER-INJECTED")

	second, _ := res.AuthoritativeGroups()
	if second[0].Subject == "ATTACKER-INJECTED" {
		t.Fatalf("AuthoritativeGroups handed out the result's own slice; a caller editing it corrupts the retained closure")
	}
	if attr := res.GroupsAttribute(); attr.Groups[0] != "Group::workspace:aaa" {
		t.Fatalf("the corruption propagated into the PDP attribute: %v", attr.Groups)
	}

	// The caller's own slice must not be captured either: mutating the input
	// after construction must not change the stored result.
	original[1] = MustNewGroupID(realmWorkspace, "ALSO-INJECTED")
	third, _ := res.AuthoritativeGroups()
	for _, g := range third {
		if g.Subject == "ALSO-INJECTED" {
			t.Fatalf("the constructor captured the caller's slice")
		}
	}
}

// TestNoGraphClosureRecordsAVersionNotProse covers finding 12 from R3.
//
// Both callers of NewNoGraphClosure passed an explanatory sentence to a
// parameter named sourceVersion, so a decision proof over a no-graph realm
// recorded prose where a version belongs and left the human-readable field
// empty. The signature now takes the REALM, because the version a no-graph
// closure should carry is the realm configuration's own: there is no directory
// snapshot behind it, and the realm's declaration is the thing that could
// change and invalidate the answer.
func TestNoGraphClosureRecordsAVersionNotProse(t *testing.T) {
	realm := cloudIAMRealm()
	realm.Version = 7
	res := NewNoGraphClosure(fixtureAgentA, realm, fixtureNow)

	if res.SourceVersion != "realm/gcp-iam/v7" {
		t.Fatalf("SourceVersion is %q, want an identifier derived from the realm and its version", res.SourceVersion)
	}
	if strings.Contains(res.SourceVersion, " ") {
		t.Fatalf("SourceVersion contains prose: %q", res.SourceVersion)
	}
	if res.Detail == "" {
		t.Fatalf("the human-readable field is empty; the explanation went into the version field instead")
	}
	if !strings.Contains(res.Detail, string(realm.RealmID)) {
		t.Fatalf("the detail does not name the realm: %q", res.Detail)
	}

	// A realm-configuration change moves the recorded version, so a cached or
	// replayed answer taken against the old declaration is detectably stale.
	realm.Version = 8
	if again := NewNoGraphClosure(fixtureAgentA, realm, fixtureNow); again.SourceVersion == res.SourceVersion {
		t.Fatalf("changing the realm version did not change the recorded source version")
	}

	// Both live callers go through it, so the property holds where it matters
	// rather than only at the constructor.
	viaResolver := NoGraphOnlyResolver{Now: func() time.Time { return fixtureNow }}.
		ResolveClosure(context.Background(), fixtureOrg, cloudIAMRealm(), fixtureAgentA, ClosureBounds{})
	if !strings.HasPrefix(viaResolver.SourceVersion, "realm/") {
		t.Fatalf("the resolver records %q as the source version", viaResolver.SourceVersion)
	}
}
