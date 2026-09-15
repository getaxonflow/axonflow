// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// THE #3936 REACHABILITY TRIPWIRE, IDENTITY HALF.
//
// pdp.compileScope renders a policy's scope principals into a string equality
// on principal.id, and the rendered form carries the principal TYPE. So a
// policy naming User::acme:alice does not apply to the same subject presented
// as Service::acme:alice - measured end to end against a real bundle and a real
// evaluator, where the User spelling permits and the Service and Agent
// spellings return not_applicable/no_matching_permission.
//
// That was left uncorrected on a reachability ruling: folding the type changes
// which policies apply in BOTH directions at once, and nothing today can
// present one subject under two classifications. THIS FILE IS THE HALF OF THAT
// RULING THAT IDENTITY OWNS.
//
// The mechanism that would break it is named and specific. realm_verify.go
// prefers Credential.SubjectType over the realm's ClaimMapping.SubjectType and
// bounds the choice with realm.AcceptsSubjectType. While every realm accepts
// exactly the one type its claim mapping mints, that override cannot widen: the
// only admissible value IS the default. The day a realm declares a second
// accepted type, one credential channel can mint User::realm:alice and another
// Service::realm:alice for one subject in one realm, and every principal-scoped
// policy naming that subject silently applies to one and not the other.

// realmSubjectTypeWidening returns, for each realm, the accepted subject types
// its claim mapping can never mint.
//
// It takes the realms as an argument so the control below can drive the SAME
// function over a planted realm. A check whose only input is the shipped
// declarations cannot be shown to fire.
func realmSubjectTypeWidening(realms []TrustRealm) []string {
	var out []string
	for _, r := range realms {
		var extra []string
		for _, a := range r.AcceptedSubjectTypes {
			if a != r.ClaimMapping.SubjectType {
				extra = append(extra, string(a))
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			out = append(out, fmt.Sprintf("%s mints %s and also accepts %s",
				r.RealmID, r.ClaimMapping.SubjectType, strings.Join(extra, ", ")))
		}
	}
	sort.Strings(out)
	return out
}

// shippedRealms enumerates every realm declaration THIS ARM ships, across every
// deployment shape, by CALLING the production builders.
//
// Every shape, because HasDirectory / HasRevocation / HasCAEP are read inside
// the builders and a census of one shape is a census of one deployment. The
// three flags are enumerated as a product rather than sampled, so a realm whose
// accepted types varied with a flag could not hide in the combination nobody
// drove.
//
// THE POPULATION IS EDITION-DEPENDENT AND THE FLOOR MOVES WITH IT. The OIDC
// realm is enterprise-tagged, so a community build genuinely has five realms
// and an enterprise build six. A single floor would be wrong in one arm - too
// high in community, where it would fail a correct tree, or too low in
// enterprise, where it would pass a census that had stopped reaching the OIDC
// builder. editionShippedRealms and minDistinctShippedRealms are declared per
// arm for exactly that reason.
func shippedRealms(t *testing.T) []TrustRealm {
	t.Helper()
	var out []TrustRealm
	for _, dir := range []bool{false, true} {
		for _, rev := range []bool{false, true} {
			for _, caep := range []bool{false, true} {
				dep := BuiltinRealmDeployment{HasDirectory: dir, HasRevocation: rev, HasCAEP: caep}
				out = append(out, BuiltinRealms("org_acme", dep)...)
				out = append(out, editionShippedRealms(t, dep)...)
			}
		}
	}
	return out
}

// TestEveryShippedRealmAcceptsOnlyTheTypeItMints is the tripwire.
func TestEveryShippedRealmAcceptsOnlyTheTypeItMints(t *testing.T) {
	realms := shippedRealms(t)
	// THE DENOMINATOR FIRST. An empty realm list produces an empty widening
	// list, and an empty widening list reads exactly like a clean one. The
	// product over three booleans visits each declaration eight times, so the
	// floor here is deliberately low and the DISTINCT floor below is the one
	// that says a builder was reached.
	if len(realms) < 8 {
		t.Fatalf("the census enumerated %d realm declarations; too few to be the shipped set, so nothing "+
			"below is an assertion", len(realms))
	}
	distinct := map[RealmID]bool{}
	for _, r := range realms {
		distinct[r.RealmID] = true
	}
	if len(distinct) < minDistinctShippedRealms {
		t.Fatalf("the census enumerated %d DISTINCT realms; this edition ships %d, so a builder is not "+
			"being reached", len(distinct), minDistinctShippedRealms)
	}
	t.Logf("censused %d realm declarations over %d distinct realms", len(realms), len(distinct))

	// Every declaration must also be a legal realm, or "accepts only what it
	// mints" could be satisfied by a realm that mints nothing valid.
	for _, r := range realms {
		if err := r.Validate(); err != nil {
			t.Fatalf("shipped realm %q does not validate: %v", r.RealmID, err)
		}
	}

	if bad := realmSubjectTypeWidening(realms); len(bad) > 0 {
		t.Errorf(`%d realm declaration(s) accept a subject type their claim mapping cannot mint:

  %s

#3936's RULING NO LONGER HOLDS. realm_verify.go prefers Credential.SubjectType
over ClaimMapping.SubjectType and bounds it only by AcceptsSubjectType, so a
realm accepting two types can present ONE subject under two classifications -
and pdp.compileScope compares the rendered form, type included, so a policy
naming that subject applies to one spelling and not the other.

That may well be a correct thing to want. It is not a thing that can be added
while the scope currency is still the rendered form: re-open #3936 and move
pdp.compileScope and authoring.sharesID / containsAllIDs together first.`,
			len(bad), strings.Join(bad, "\n  "))
	}
}

// TestTheSubjectTypeWideningScannerSeesAPlantedWidening is the anti-vacuity
// control.
//
// The assertion above is satisfied by a scanner that returns nothing for
// everything. The control drives the same function over a realm that accepts a
// type it cannot mint and requires the widening back, naming the realm.
//
// The planted list holds ONE widening realm and one clean one, so a pass cannot
// come from some other row.
func TestTheSubjectTypeWideningScannerSeesAPlantedWidening(t *testing.T) {
	planted := []TrustRealm{
		{
			RealmID:              "clean",
			AcceptedSubjectTypes: []SubjectType{SubjectUser},
			ClaimMapping:         ClaimMapping{SubjectType: SubjectUser},
		},
		{
			RealmID:              "widened",
			AcceptedSubjectTypes: []SubjectType{SubjectUser, SubjectService},
			ClaimMapping:         ClaimMapping{SubjectType: SubjectUser},
		},
	}
	got := realmSubjectTypeWidening(planted)
	if len(got) != 1 || !strings.HasPrefix(got[0], "widened mints User and also accepts Service") {
		t.Fatalf("the scanner returned %v for a list with exactly one widened realm; the assertion above "+
			"is passing against an instrument that cannot see a widening", got)
	}
	if len(realmSubjectTypeWidening(planted[:1])) != 0 {
		t.Fatal("the scanner reports a widening for a realm that has none; it would fire on anything")
	}
}

// TestTheOverrideThatTheRulingDependsOnIsStillBoundedByTheAcceptedSet pins the
// mechanism the tripwire is about.
//
// The tripwire watches AcceptedSubjectTypes because realm_verify.go bounds
// Credential.SubjectType by it. If that bound were removed, watching the
// accepted set would keep passing while the thing it stands for had gone - a
// guard reporting clean about a check that no longer exists.
func TestTheOverrideThatTheRulingDependsOnIsStillBoundedByTheAcceptedSet(t *testing.T) {
	realm := BuiltinRealms("org_acme", BuiltinRealmDeployment{})[0]
	if realm.ClaimMapping.SubjectType != SubjectUser {
		t.Fatalf("the first built-in realm mints %q; this test was written against a User-minting realm",
			realm.ClaimMapping.SubjectType)
	}
	if realm.AcceptsSubjectType(SubjectService) {
		t.Fatalf("realm %q accepts Service; the widening census above should already have failed", realm.RealmID)
	}
	// The positive direction: the type it DOES mint is accepted, so the check
	// is not simply refusing everything.
	if !realm.AcceptsSubjectType(SubjectUser) {
		t.Fatalf("realm %q does not accept the type its own claim mapping mints", realm.RealmID)
	}
}
