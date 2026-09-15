// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import (
	"strings"
	"testing"
	"time"
)

// The #3878 class in this module: an identity compared by a RENDERED form that
// carries the principal type.
//
// #3876 fixed that inside platform/decision/authoring, where the rule was
// spelled out locally. The structural census that #3878 asked for found the
// SAME rule keyed on ID.String() here, in Request.Validate's actor-chain cycle
// check, on the live decision path. The rule now lives once, as IdentityKey.

// TestIdentityKeyDropsTheTypeForAPrincipalAndKeepsItForEverythingElse pins the
// one branch in the rule, in both directions.
//
// The branch is not a special case bolted on for principals. For KindPrincipal
// the Type field is a CLASSIFICATION of a subject - User, Service, Agent - and
// the same person arrives at two surfaces classified two ways, which is what
// made an author their own approver. For every other kind the Type names the
// entity CLASS of a distinct entity, so `JiraIssue::conn:ABC-1` and
// `JiraProject::conn:ABC-1` are two resources and folding them would be the
// same defect pointing the other way.
//
// Both directions are required. A rule that dropped the type everywhere would
// satisfy the principal half and merge the registry's catalog entries; a rule
// that kept it everywhere is the defect being fixed.
func TestIdentityKeyDropsTheTypeForAPrincipalAndKeepsItForEverythingElse(t *testing.T) {
	alice := MustParseID(KindPrincipal, "User::acme:alice@acme.example")
	aliceAsService := MustParseID(KindPrincipal, "Service::acme:alice@acme.example")
	aliceUpper := MustParseID(KindPrincipal, "User::acme:Alice@acme.example")
	aliceOtherRealm := MustParseID(KindPrincipal, "User::other:alice@acme.example")
	bob := MustParseID(KindPrincipal, "User::acme:bob@acme.example")

	if !SameEntity(alice, aliceAsService) {
		t.Errorf("%s and %s are one person described two ways; the type classifies a subject rather than identifying one", alice, aliceAsService)
	}
	if !SameEntity(alice, aliceUpper) {
		t.Errorf("%s and %s are one person to the directory, which resolves an assignment on lower(btrim(user_email))", alice, aliceUpper)
	}
	if SameEntity(alice, aliceOtherRealm) {
		t.Errorf("%s and %s were folded together; the qualifier is a realm and two realms are two directories", alice, aliceOtherRealm)
	}
	if SameEntity(alice, bob) {
		t.Errorf("%s and %s are different people", alice, bob)
	}

	// A PRINCIPAL AND A NON-PRINCIPAL NEVER COLLIDE, whatever their remaining
	// fields. Kind leads the key for exactly this reason.
	issue := MustParseID(KindResource, "JiraIssue::conn:ABC-1")
	project := MustParseID(KindResource, "JiraProject::conn:ABC-1")
	if SameEntity(issue, project) {
		t.Errorf("%s and %s are two resources that share a local segment; for a non-principal the type names the entity class", issue, project)
	}
	// And the local segment of a resource is NOT case-folded: nothing
	// establishes case-insensitivity for a connector's own identifiers, and
	// folding a field because folding another one helped is how a fix becomes a
	// defect.
	if SameEntity(issue, MustParseID(KindResource, "JiraIssue::conn:abc-1")) {
		t.Errorf("two resource identifiers differing only in case were folded together")
	}
	// The same pair of spellings on a PRINCIPAL is one person, which is what
	// makes the assertion above about the kind branch rather than about casing
	// at large.
	if !SameEntity(MustParseID(KindPrincipal, "User::conn:ABC-1"), MustParseID(KindPrincipal, "User::conn:abc-1")) {
		t.Errorf("two principals differing only in case were treated as two people")
	}

	action := MustParseID(KindAction, "Action::billing.refund")
	if SameEntity(action, MustParseID(KindAction, "Action::billing.charge")) {
		t.Errorf("two actions were folded together")
	}
	if !SameEntity(action, MustParseID(KindAction, "Action::billing.refund")) {
		t.Errorf("an action did not match itself")
	}
}

// TestTheRenderedFormIsAnIdentityKeyForEveryKindExceptAPrincipal is the
// property that makes the census's largest classification a DRIVEN claim
// instead of a read one.
//
// Twenty of the census's rows are catalog and registry lookups keyed on
// `id.String()`, classified as correct because the values are Actions, Tools
// and Resources rather than principals. That is a claim about every one of
// those sites, and asserting it site by site would be twenty readings of the
// same argument. It is one property instead:
//
//	for a NON-PRINCIPAL kind:  a.String() == b.String()  <=>  SameEntity(a, b)
//	for a PRINCIPAL:           the two disagree, and the disagreement is #3878
//
// The first line is what makes a rendered map key a correct identity key at
// those twenty sites. The second is what makes it the defect at the sites this
// change corrects. Both directions are required: a rule that folded the type
// everywhere would break the first, and the code before this change broke the
// second.
func TestTheRenderedFormIsAnIdentityKeyForEveryKindExceptAPrincipal(t *testing.T) {
	// The axes on which two identifiers of one kind can differ: the type
	// segment, the qualifier where the kind carries one, and the case of the
	// local segment. Each is a way the two answers could come apart.
	type variant struct {
		name  string
		apply func(ID) ID
	}
	variants := []variant{
		{"a different type segment", func(id ID) ID { id.Type = "Other" + id.Type; return id }},
		{"a different qualifier", func(id ID) ID {
			if id.Qualifier == "" {
				return id
			}
			id.Qualifier += "2"
			return id
		}},
		{"a different local case", func(id ID) ID { id.Local = strings.ToUpper(id.Local); return id }},
		{"a different local segment", func(id ID) ID { id.Local += "-x"; return id }},
	}

	bases := map[Kind]ID{
		KindPrincipal:    MustParseID(KindPrincipal, "User::acme:alice@acme.example"),
		KindGroup:        MustParseID(KindGroup, "Group::acme:engineering"),
		KindResource:     MustParseID(KindResource, "JiraIssue::conn:ABC-1"),
		KindAction:       MustParseID(KindAction, "Action::billing.refund"),
		KindTool:         MustParseID(KindTool, "Tool::jira.create"),
		KindOrganization: MustParseID(KindOrganization, "Organization::org_acme"),
	}

	var sawPrincipalDisagreement bool
	for kind, base := range bases {
		for _, v := range variants {
			other := v.apply(base)
			if other == base {
				// The axis does not exist for this kind (an unqualified kind
				// has no qualifier to change, an already-lowercase local has
				// no case). Skipped rather than asserted, so the loop does not
				// claim coverage it does not have.
				continue
			}
			if other.Validate() != nil {
				continue
			}
			renderedSame := base.String() == other.String()
			entitySame := SameEntity(base, other)
			if kind == KindPrincipal {
				if renderedSame != entitySame {
					sawPrincipalDisagreement = true
				}
				continue
			}
			if renderedSame != entitySame {
				t.Errorf("kind %s, %s: %q vs %q render %v and SameEntity says %v; "+
					"a catalog keyed on the rendered form would disagree with the identity rule here",
					kind, v.name, base, other, renderedSame, entitySame)
			}
		}
	}

	// THE PRINCIPAL HALF IS THE POINT, so its absence is a failure rather
	// than a silence: if the two answers never came apart for a principal,
	// the property above would be universal and #3878 would not exist.
	if !sawPrincipalDisagreement {
		t.Error("the rendered form and the identity rule agreed on every principal variant, so this test could not " +
			"distinguish the kind that must not be keyed on its rendering from the kinds that may be")
	}
}

// TestSameEntityRefusesTheZeroIdentifier pins the floor.
//
// "No identifier" is not an identity two values can share. Every current caller
// validates before reaching here - the authoring control skips a zero approver,
// Request.Validate calls ID.Validate on every hop, and the portal refuses a
// non-canonical approver - so this is a floor rather than a live branch, and it
// is asserted because a floor nobody tests is a floor that is quietly removed.
func TestSameEntityRefusesTheZeroIdentifier(t *testing.T) {
	var zero ID
	alice := MustParseID(KindPrincipal, "User::acme:alice@acme.example")

	if SameEntity(zero, zero) {
		t.Error("two zero identifiers matched; an absent identifier is not an identity two values share")
	}
	if SameEntity(zero, alice) || SameEntity(alice, zero) {
		t.Error("the zero identifier matched a real one")
	}
	if !SameEntity(alice, alice) {
		t.Error("a real identifier did not match itself, so the guard above is refusing everything")
	}
}

// TestAnIdentityKeyCannotBeForgedThroughTheLocalSegment drives the separator
// argument instead of leaving it as a comment.
//
// ID.Validate rejects \x00, newline, carriage return and tab in a local
// segment; it does NOT reject \x1e, which is the key separator. The key is
// still unforgeable because the local segment is LAST and the fields ahead of
// it draw from grammars that admit no \x1e - but "still unforgeable because"
// is an argument, and an argument about an injection is the kind that is wrong
// once.
func TestAnIdentityKeyCannotBeForgedThroughTheLocalSegment(t *testing.T) {
	// PRECONDITION: the separator really is accepted in a local segment, so
	// this test is about a reachable input rather than a hypothetical one. If
	// Validate ever starts refusing it, this fails and says so, which is the
	// right outcome - the argument above would then need rewriting.
	forged := ID{Kind: KindPrincipal, Type: "User", Qualifier: "acme", Local: "bob\x1eacme\x1eevil"}
	if err := forged.Validate(); err != nil {
		t.Fatalf("the separator is no longer accepted in a local segment, so this test's premise is stale: %v", err)
	}

	victim := MustParseID(KindPrincipal, "User::acme:bob")
	if forged.IdentityKey() == victim.IdentityKey() {
		t.Fatalf("a local segment carrying the separator forged another identity's key: %q", forged.IdentityKey())
	}
	if SameEntity(forged, victim) {
		t.Fatal("SameEntity matched a forged local segment against another subject")
	}

	// The same shape one field along: a qualifier cannot be smuggled through
	// the local segment either.
	if SameEntity(forged, ID{Kind: KindPrincipal, Type: "User", Qualifier: "acme\x1eevil", Local: "bob"}) {
		t.Fatal("a key collided across the qualifier/local boundary")
	}
}

// TestTheActorChainCycleCheckIsBySubjectRatherThanByRenderedForm is the twin of
// identity.TestAdmitChainTreatsOneSubjectUnderTwoTypesAsARepeat.
//
// Both implement "no principal repeats" over an actor chain, in two modules,
// and both keyed on a form that carries the classification: this one on
// ID.String(), the identity plane's on a comparable struct. A subject that
// appears twice is a repeat whatever type each hop declares, and the two
// implementations must not be able to disagree about that.
//
// THE ROOT CHECK IMMEDIATELY ABOVE IT IS DELIBERATELY NOT WIDENED, and the
// contrast is asserted here rather than only commented. That check asks whether
// ONE producer built ONE request consistently, so exact equality is the correct
// comparison and widening it would let a request declare a principal its own
// chain root classifies differently.
func TestTheActorChainCycleCheckIsBySubjectRatherThanByRenderedForm(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	build := func(chain ...ID) *Request {
		actors := make([]Actor, len(chain))
		for i, id := range chain {
			actors[i] = Actor{ID: id, Attributes: AttributeSet{}}
		}
		return &Request{
			RequestID:    "req_cycle",
			Organization: MustParseID(KindOrganization, "Organization::org_acme"),
			Principal:    chain[0],
			Action:       MustParseID(KindAction, "Action::a.b"),
			Resource:     MustParseID(KindResource, "Ticket::conn:T-1"),
			Context:      Context{ActorChain: actors},
			Snapshot:     Snapshot{SchemaVersion: SchemaVersion, PolicyBundle: "sha256:aa"},
			Attributes:   AttributeSet{},
			EvaluatedAt:  now,
		}
	}

	alice := MustParseID(KindPrincipal, "User::realm_ws:alice")
	aliceAsAgent := MustParseID(KindPrincipal, "Agent::realm_ws:alice")
	bot := MustParseID(KindPrincipal, "Agent::realm_ws:bot")

	// PRECONDITION: a chain of two DIFFERENT subjects validates, so every
	// refusal below is attributable to the repeat rather than to the fixture.
	if err := build(alice, bot).Validate(); err != nil {
		t.Fatalf("a two-subject chain does not validate, so nothing below is attributable: %v", err)
	}

	err := build(alice, aliceAsAgent).Validate()
	if err == nil {
		t.Fatalf("the chain [%s, %s] validated; one subject delegating to itself is a repeat whatever type each hop declares", alice, aliceAsAgent)
	}
	// THE REASON, not merely the refusal. A request refused for the wrong
	// reason sends a producer to the wrong field.
	if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("the repeat was refused as %q, which does not name the cycle rule", err)
	}
	// The exactly-repeated hop was refused before this correction too, and is
	// asserted alongside so a mutant reverting the key reds the case above
	// while this one stays green.
	if err := build(alice, alice).Validate(); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("an exactly-repeated hop is no longer a cycle: %v", err)
	}

	// THE ROOT CHECK STAYS EXACT. The chain root and the principal are two
	// writes of one value by one producer, so a differently-classified root is
	// an inconsistent request and not a second spelling of the same person.
	inconsistent := build(alice, bot)
	inconsistent.Principal = aliceAsAgent
	err = inconsistent.Validate()
	if err == nil {
		t.Fatal("a request whose principal and chain root carry different principal types was accepted; that check asks whether one producer was consistent, not who the subject is")
	}
	if !strings.Contains(err.Error(), "root first") {
		t.Fatalf("the inconsistent request was refused as %q rather than by the root check", err)
	}
}
