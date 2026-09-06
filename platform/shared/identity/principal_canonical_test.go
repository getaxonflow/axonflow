// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"testing"
)

// TestPrincipalIDRoundTrip covers AXC-204.
//
// The SPIFFE case is the one that decides the parsing rule. Its subject id
// contains two colons, so any implementation that splits the whole string on
// ":" corrupts it, and any implementation that rejects colons in a subject
// cannot represent a workload at all. Both failure modes are pinned here by
// asserting the exact recovered components, not merely that a round trip
// succeeded: a parser that swallowed the scheme would still round-trip if
// String re-joined the pieces the same wrong way.
func TestPrincipalIDRoundTrip(t *testing.T) {
	MarkConformanceCase("AXC-204")

	cases := []struct {
		name        string
		wire        string
		wantRealm   RealmID
		wantType    SubjectType
		wantSubject string
	}{
		{
			name:      "user",
			wire:      "User::realm_okta:00u123",
			wantRealm: "realm_okta", wantType: SubjectUser, wantSubject: "00u123",
		},
		{
			name:      "group",
			wire:      "Group::realm_okta:security",
			wantRealm: "realm_okta", wantType: SubjectGroup, wantSubject: "security",
		},
		{
			name:      "workload subject containing colons",
			wire:      "Workload::realm_spiffe:spiffe://acme.example/workload/jira-bot",
			wantRealm: "realm_spiffe", wantType: SubjectWorkload,
			wantSubject: "spiffe://acme.example/workload/jira-bot",
		},
		{
			name:      "subject containing a double colon",
			wire:      "Service::realm_x:svc::inner",
			wantRealm: "realm_x", wantType: SubjectService, wantSubject: "svc::inner",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePrincipalID(tc.wire)
			if err != nil {
				t.Fatalf("ParsePrincipalID(%q): %v", tc.wire, err)
			}
			if got.Realm != tc.wantRealm {
				t.Errorf("realm: want %q, got %q", tc.wantRealm, got.Realm)
			}
			if got.Type != tc.wantType {
				t.Errorf("type: want %q, got %q", tc.wantType, got.Type)
			}
			if got.Subject != tc.wantSubject {
				t.Errorf("subject: want %q, got %q", tc.wantSubject, got.Subject)
			}
			if rendered := got.String(); rendered != tc.wire {
				t.Errorf("String round trip: want %q, got %q", tc.wire, rendered)
			}
		})
	}
}

// TestPrincipalIDsDoNotCollideAcrossRealms covers AXC-203.
//
// It asserts three separate things because they can fail independently: value
// equality, map-key behavior, and the rendered form. A type that compared equal
// but hashed the same would still be a collision at every call site that keys a
// closure or an eligibility set by principal.
func TestPrincipalIDsDoNotCollideAcrossRealms(t *testing.T) {
	MarkConformanceCase("AXC-203")

	inOkta := MustParsePrincipalID("User::realm_okta:00u123")
	inEntra := MustParsePrincipalID("User::realm_entra:00u123")

	if inOkta == inEntra {
		t.Fatalf("principals with the same subject in two realms compared equal: %s and %s", inOkta, inEntra)
	}
	if inOkta.Subject != inEntra.Subject {
		t.Fatalf("fixture is wrong: the two principals must share a subject id to test the collision")
	}

	seen := map[PrincipalID]string{inOkta: "okta", inEntra: "entra"}
	if len(seen) != 2 {
		t.Fatalf("the two principals collapsed to one map key: %v", seen)
	}
	if seen[inOkta] == seen[inEntra] {
		t.Fatalf("the two principals resolved to the same map value")
	}
	if inOkta.String() == inEntra.String() {
		t.Fatalf("the two principals render identically: %s", inOkta)
	}

	// The same subject id in the same realm but with a different subject TYPE
	// is also a different principal: a group and a user can share a provider
	// id in directories that number their resources independently.
	asGroup := MustParsePrincipalID("Group::realm_okta:00u123")
	if asGroup == inOkta {
		t.Fatalf("a Group and a User with the same realm and subject compared equal")
	}
}

// TestParsePrincipalIDRefusesBareIdentifiers covers AXC-205.
//
// The failure this guards is not a parse error, it is a parse SUCCESS with a
// defaulted realm. EX-47 is a fail-open produced entirely by omission, and the
// front door to it is a parser that helpfully completes "security" into
// whichever realm is handy. So the assertion is that these produce an error AND
// a zero principal: an implementation that returned a best-effort principal
// alongside an error would still be usable by a caller that logs and continues.
func TestParsePrincipalIDRefusesBareIdentifiers(t *testing.T) {
	MarkConformanceCase("AXC-205")

	bare := []string{
		"security",
		"00u123",
		"alice@acme.example",
		"User:realm_okta:00u123",  // single colon, not the type separator
		"User::realm_okta",        // no subject separator
		"::realm_okta:00u123",     // empty type
		"User::realm okta:00u123", // whitespace in the realm
		"",
	}
	for _, s := range bare {
		t.Run(s, func(t *testing.T) {
			got, err := ParsePrincipalID(s)
			if err == nil {
				t.Fatalf("ParsePrincipalID(%q) succeeded and produced %s; a bare identifier must never be completed with a default realm", s, got)
			}
			if !got.IsZero() {
				t.Fatalf("ParsePrincipalID(%q) returned an error but also a usable principal %s", s, got)
			}
		})
	}

	// A string with three colons is NOT refused, and pinning that is the point.
	// "User::realm:okta:00u123" parses to realm "realm" and subject
	// "okta:00u123" under the first-colon rule. It looks like an ambiguous
	// input and is not one: the rule resolves it deterministically, and an
	// implementation that "helpfully" rejected it would reject every workload
	// principal too. Asserting the exact components is the only way to tell a
	// correct first-colon split from a lucky one.
	got, err := ParsePrincipalID("User::realm:okta:00u123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Realm != "realm" || got.Subject != "okta:00u123" {
		t.Fatalf("first-colon rule: want realm %q subject %q, got realm %q subject %q",
			"realm", "okta:00u123", got.Realm, got.Subject)
	}
}

// TestZeroPrincipalIsNeverUsable pins the zero value's behavior directly.
//
// Every enum and struct in this plane reserves its zero value for "not
// determined". A PrincipalID is the one a consumer is most likely to construct
// accidentally, by declaring a var and forgetting to assign it.
func TestZeroPrincipalIsNeverUsable(t *testing.T) {
	var zero PrincipalID

	if !zero.IsZero() {
		t.Fatalf("the zero PrincipalID does not report itself as zero")
	}
	if err := zero.Validate(); err == nil {
		t.Fatalf("the zero PrincipalID validated")
	}
	if zero == fixtureAlice {
		t.Fatalf("the zero PrincipalID compared equal to a real principal")
	}

	// A zero principal must not be admissible.
	defer func() {
		if recover() == nil {
			t.Fatalf("AcceptAdmission accepted a zero principal")
		}
	}()
	AcceptAdmission(zero)
}

// TestValidateRealmIDRejectsSeparatorsAndWhitespace pins the character set that
// makes the wire form unambiguous.
//
// The colon rule is the load-bearing one: it is what lets a subject id contain
// colons. If a realm id could contain one, ParsePrincipalID's first-colon split
// would cut in the wrong place and a workload principal would silently become a
// different principal, not an error.
func TestValidateRealmIDRejectsSeparatorsAndWhitespace(t *testing.T) {
	bad := map[string]string{
		"empty":        "",
		"colon":        "realm:okta",
		"double colon": "realm::okta",
		"space":        "realm okta",
		"tab":          "realm\tokta",
		"newline":      "realm\nokta",
		"control rune": "realm\x00okta",
		"too long":     strings.Repeat("a", maxPrincipalComponent+1),
		// Outside the decision contract's qualifier grammar (#3709 row 3).
		// Every one of these was ACCEPTED before, and every principal minted
		// under such a realm was unparseable by the PDP.
		"plus":          "acme+prod",
		"slash":         "eu/central",
		"at":            "realm@okta",
		"non-ascii":     "réalm",
		"leading dash":  "-leading",
		"leading dot":   ".leading",
		"leading under": "_leading",
	}
	for name, id := range bad {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRealmID(RealmID(id)); err == nil {
				t.Fatalf("ValidateRealmID(%q) accepted it", id)
			}
		})
	}
	for _, ok := range []string{"workspace", "gcp-iam", "realm_okta", "acme.example"} {
		if err := ValidateRealmID(RealmID(ok)); err != nil {
			t.Errorf("ValidateRealmID(%q) rejected a legitimate realm id: %v", ok, err)
		}
	}
}

// TestSubjectTypeVocabularyIsClosed pins that an unknown subject type is an
// error rather than a permissive default, and that the exported accessor hands
// out a copy.
func TestSubjectTypeVocabularyIsClosed(t *testing.T) {
	for _, unknown := range []SubjectType{"", "user", "USER", "Robot", "Principal"} {
		if unknown.IsValid() {
			t.Errorf("SubjectType(%q) reported itself valid", unknown)
		}
		if _, err := NewPrincipalID("workspace", unknown, "x"); err == nil {
			t.Errorf("NewPrincipalID accepted subject type %q", unknown)
		}
	}

	types := SubjectTypes()
	if len(types) == 0 {
		t.Fatalf("SubjectTypes returned nothing")
	}
	types[0] = "Mutated"
	if SubjectTypes()[0] == "Mutated" {
		t.Fatalf("SubjectTypes handed out the package's own slice; a consumer can edit the vocabulary")
	}
}

// TestCanonicalFormVersionIsStable pins the constant the obligation plane binds
// into decision proofs.
//
// It is not a spelling test. ADR65-C binds this value into the proof digest so
// that a change to what counts as a well-formed principal invalidates old
// proofs loudly rather than letting two spellings compare unequal in silence.
// Changing the value is therefore a deliberate, cross-plane act, and this test
// exists to make an incidental edit fail.
func TestCanonicalFormVersionIsStable(t *testing.T) {
	const want = "identity/2" // bumped by #3709 row 3: the realm-id character set narrowed
	if CanonicalFormVersion != want {
		t.Fatalf("CanonicalFormVersion changed from %q to %q. This value is DECLARED as bound into decision proofs "+
			"(proof.Binding.IdentityCanonicalFormVersion) - though as of #3709 row 3 no production writer populates that "+
			"field, which is filed - so if the change is intended, coordinate the bump rather than editing this test alone",
			want, CanonicalFormVersion)
	}
}
