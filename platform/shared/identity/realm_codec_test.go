// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fullyPopulatedRealm returns a realm in which EVERY field carries a
// distinctive non-zero value.
//
// That is load-bearing rather than tidiness. A field left at its zero value
// survives any encoder, including one that drops it entirely: it goes in as
// nothing and comes back as nothing, and the round trip reports success. The
// round-trip test below REQUIRES every field to be non-zero and fails if one
// is not, so this fixture cannot decay into one that proves less than it
// looks like it proves.
func fullyPopulatedRealm() TrustRealm {
	return TrustRealm{
		RealmID:                  "storage-fixture",
		OrgID:                    fixtureOrg,
		Kind:                     RealmKindOIDC,
		CanonicalIssuer:          "https://idp.storage.example",
		AcceptedSubjectTypes:     []SubjectType{SubjectUser, SubjectGroup},
		AcceptedCredentialTypes:  []CredentialType{CredentialBearerJWT, CredentialIDToken},
		Audiences:                []string{audienceAxonFlow, "second-audience"},
		AuthorizedPartyPolicy:    AuthorizedPartyAllowList,
		AuthorizedParties:        []string{azpGateway},
		AllowedSigningAlgorithms: []string{"RS256", "ES256"},
		ClaimMapping: ClaimMapping{
			Version:      3,
			SubjectClaim: "sub",
			SubjectType:  SubjectUser,
			AliasClaims: map[AliasKind]string{
				AliasEmail:       "email",
				AliasDisplayName: "name",
			},
		},
		MinimumAssurance:    AssuranceHigh,
		ClockSkew:           45 * time.Second,
		CredentialAgePolicy: CredentialAgeBounded,
		MaxCredentialAge:    2 * time.Hour,
		Directory:           DirectorySourceSCIM,
		Interactive:         InteractiveHuman,
		Revocation:          RevocationSourceSharedSignals,
		Delegation:          DelegationAllowList,
		DelegateRealms:      []RealmID{realmCloudIAM},
		Enabled:             true,
		Version:             7,
	}
}

// TestEveryTrustRealmFieldSurvivesTheRoundTrip is the codec's own guard.
//
// A field added to TrustRealm and forgotten in realmRecord comes back as its
// ZERO VALUE, and on this type the zero value of every tri-state field means
// "not declared" - which is EX-47, a fail-open produced entirely by omission.
// Walking the struct by reflection means the guard cannot go stale the way a
// hand-written field list would.
func TestEveryTrustRealmFieldSurvivesTheRoundTrip(t *testing.T) {
	original := fullyPopulatedRealm()

	// Anti-vacuity: the fixture must leave nothing at its zero value, or a
	// dropped field would be indistinguishable from a preserved one.
	//
	// IT RECURSES INTO NESTED STRUCTS, and an earlier version did not. The
	// walk was top-level only, so ClaimMapping counted as non-zero because
	// SOME of its subfields were set - and a subfield added to ClaimMapping
	// and forgotten in claimMappingRecord stayed at its zero value on BOTH
	// sides and compared equal. Proven with a `go test -overlay` mutant: a new
	// ClaimMapping.TenantClaim, absent from the record, PASSED. ClaimMapping
	// is where SubjectClaim lives, which is the field ADR-065 invariant 3
	// turns on ("aliases such as email never become canonical identifiers"),
	// so the blind spot was over the most load-bearing nested value in the
	// type.
	assertNoZeroFieldsDeep(t, "TrustRealm", reflect.ValueOf(original))

	encoded, err := encodeRealm(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodeRealm(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(original, decoded) {
		// Field by field, so the message names the one that was lost rather
		// than dumping two structs.
		ov, dv := reflect.ValueOf(original), reflect.ValueOf(decoded)
		for i := 0; i < ov.NumField(); i++ {
			name := ov.Type().Field(i).Name
			if !reflect.DeepEqual(ov.Field(i).Interface(), dv.Field(i).Interface()) {
				t.Errorf("TrustRealm.%s did not survive storage: stored %v, loaded %v.\nA field the codec drops comes back as its zero value, and on this type the zero value means \"not declared\" - which is the EX-47 fail-open.",
					name, ov.Field(i).Interface(), dv.Field(i).Interface())
			}
		}
		t.FailNow()
	}
}

// assertNoZeroFieldsDeep walks a struct and fails on any exported field left
// at its zero value, descending into nested structs.
//
// Maps and slices are checked for emptiness but not walked element-wise: their
// ELEMENTS are values the fixture chooses, and a codec that dropped one would
// change the length or the content, which reflect.DeepEqual sees. It is the
// STRUCT FIELDS that can be silently absent from a record type on both sides.
// assertNoZeroFieldsDeepAt descends into whatever v is, so the walk reaches
// struct fields hidden behind a pointer or a slice/map element as well as
// direct ones.
func assertNoZeroFieldsDeepAt(t *testing.T, path string, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			assertNoZeroFieldsDeepAt(t, path, v.Elem())
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			assertNoZeroFieldsDeepAt(t, fmt.Sprintf("%s[%d]", path, i), v.Index(i))
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			assertNoZeroFieldsDeepAt(t, fmt.Sprintf("%s[%v]", path, k), v.MapIndex(k))
		}
	case reflect.Struct:
		assertNoZeroFieldsDeep(t, path, v)
	}
}

func assertNoZeroFieldsDeep(t *testing.T, path string, v reflect.Value) {
	t.Helper()
	if v.Kind() != reflect.Struct || v.Type() == reflect.TypeOf(time.Time{}) {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		name := path + "." + f.Name
		if v.Field(i).IsZero() {
			t.Fatalf("%s is at its zero value in fullyPopulatedRealm, so the round trip cannot tell a preserved field from a dropped one. Give it a distinctive value.", name)
		}
		// DESCEND THROUGH POINTERS AND SLICE/MAP ELEMENTS TOO. Gating on
		// reflect.Struct alone reopens the blind spot one level down the
		// moment TrustRealm gains a *SomeStruct or a []SomeStruct field: the
		// outer value is non-zero, so the check above is satisfied, and a
		// subfield of the element stays zero on both sides of the round trip.
		// Not reachable today - every nested value is a plain struct - which
		// is exactly when it is cheap to close.
		assertNoZeroFieldsDeepAt(t, name, v.Field(i))
	}
}

// TestEveryDeclaredEnumValueIsStorable is the guard on the storage
// vocabularies.
//
// Each candidate list in realm_codec.go declares what may be stored. A value
// added to one of realm.go's enumerations and forgotten in the matching list
// produces a realm that ENCODES fine (String() renders it) and then fails to
// DECODE - so the failure lands on a replica's boot, in production, rather
// than here.
//
// It scans a wide integer range and asks each type's OWN IsValid() what is
// declared, so it cannot be fooled by the candidate list itself: the authority
// is the type, not the list under test.
func TestEveryDeclaredEnumValueIsStorable(t *testing.T) {
	const scanFrom, scanTo = -64, 256

	assurance := map[AssuranceClass]bool{}
	for _, c := range storableAssurance {
		assurance[c] = true
	}
	directory := map[DirectorySource]bool{}
	for _, c := range storableDirectory {
		directory[c] = true
	}
	interactive := map[InteractiveClass]bool{}
	for _, c := range storableInteractive {
		interactive[c] = true
	}
	revocation := map[RevocationSource]bool{}
	for _, c := range storableRevocation {
		revocation[c] = true
	}
	delegation := map[DelegationPolicy]bool{}
	for _, c := range storableDelegation {
		delegation[c] = true
	}
	authorizedParty := map[AuthorizedPartyPolicy]bool{}
	for _, c := range storableAuthorizedParty {
		authorizedParty[c] = true
	}
	credentialAge := map[CredentialAgePolicy]bool{}
	for _, c := range storableCredentialAge {
		credentialAge[c] = true
	}

	declared := 0
	for i := scanFrom; i <= scanTo; i++ {
		check := func(name string, valid, listed bool, rendered string) {
			t.Helper()
			if !valid {
				return
			}
			declared++
			if !listed {
				t.Errorf("%s(%d) (%q) is declared valid by its own IsValid() but is missing from its storage vocabulary in realm_codec.go.\nA realm carrying it would encode and then fail to DECODE, so the failure would land on a replica's boot rather than here.",
					name, i, rendered)
			}
		}
		check("AssuranceClass", AssuranceClass(i).IsValid(), assurance[AssuranceClass(i)], AssuranceClass(i).String())
		check("DirectorySource", DirectorySource(i).IsValid(), directory[DirectorySource(i)], DirectorySource(i).String())
		check("InteractiveClass", InteractiveClass(i).IsValid(), interactive[InteractiveClass(i)], InteractiveClass(i).String())
		check("RevocationSource", RevocationSource(i).IsValid(), revocation[RevocationSource(i)], RevocationSource(i).String())
		check("DelegationPolicy", DelegationPolicy(i).IsValid(), delegation[DelegationPolicy(i)], DelegationPolicy(i).String())
		check("AuthorizedPartyPolicy", AuthorizedPartyPolicy(i).IsValid(), authorizedParty[AuthorizedPartyPolicy(i)], AuthorizedPartyPolicy(i).String())
		check("CredentialAgePolicy", CredentialAgePolicy(i).IsValid(), credentialAge[CredentialAgePolicy(i)], CredentialAgePolicy(i).String())
	}
	// The scan itself must have found something. A range that missed every
	// declared value - because the constants moved, or the bounds were edited -
	// would report success having checked nothing.
	if declared == 0 {
		t.Fatal("the scan found no declared enum values at all; the range does not cover the constants and this test proves nothing")
	}

	// THE REVERSE DIRECTION. A list entry that its own type calls INVALID is
	// as bad as a missing one and was not caught: adding
	// DirectorySourceUnspecified to storableDirectory made every test pass
	// (proven with an -overlay mutant), and decodeEnum would then resolve the
	// stored string "unspecified" to the EX-47 zero value - "not declared" -
	// with only the trailing out.Validate() standing between that and a
	// registered realm. The vocabulary must contain exactly the DECLARED
	// values, in both directions.
	for name, listed := range map[string][]bool{
		"AssuranceClass":        validityOf(storableAssurance),
		"DirectorySource":       validityOf(storableDirectory),
		"InteractiveClass":      validityOf(storableInteractive),
		"RevocationSource":      validityOf(storableRevocation),
		"DelegationPolicy":      validityOf(storableDelegation),
		"AuthorizedPartyPolicy": validityOf(storableAuthorizedParty),
		"CredentialAgePolicy":   validityOf(storableCredentialAge),
	} {
		for i, ok := range listed {
			if !ok {
				t.Errorf("%s's storage vocabulary lists entry %d, which its own IsValid() rejects.\nA stored row could then decode to a value the type calls undeclared - and every one of these reserves its zero value for \"not declared\", which is the EX-47 fail-open.", name, i)
			}
		}
	}

	// And every LISTED value must render to a distinct name. Two constants
	// sharing a String() would make decodeEnum resolve both to whichever comes
	// first in the list, silently changing what a stored realm means.
	for name, rendered := range map[string][]string{
		"AssuranceClass":        renderAll(storableAssurance),
		"DirectorySource":       renderAll(storableDirectory),
		"InteractiveClass":      renderAll(storableInteractive),
		"RevocationSource":      renderAll(storableRevocation),
		"DelegationPolicy":      renderAll(storableDelegation),
		"AuthorizedPartyPolicy": renderAll(storableAuthorizedParty),
		"CredentialAgePolicy":   renderAll(storableCredentialAge),
	} {
		seen := map[string]bool{}
		for _, r := range rendered {
			if seen[r] {
				t.Errorf("%s has two storable values rendering as %q; decodeEnum would resolve both to whichever is listed first, silently changing what a stored realm means", name, r)
			}
			seen[r] = true
		}
	}
}

// validityOf asks each listed value's OWN IsValid() whether it is declared.
func validityOf[T interface{ IsValid() bool }](vs []T) []bool {
	out := make([]bool, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.IsValid())
	}
	return out
}

func renderAll[T interface{ String() string }](vs []T) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.String())
	}
	return out
}

// TestAnUnknownStoredEnumValueIsRefusedNotDefaulted. Mapping an unrecognised
// string to the zero value would manufacture "not declared" from a typo, which
// is EX-47 with extra steps: a falsy Directory reads as has_group_graph=false,
// makes an empty group closure look authoritative, and skips every
// segment-scoped ceiling.
func TestAnUnknownStoredEnumValueIsRefusedNotDefaulted(t *testing.T) {
	encoded, err := encodeRealm(fullyPopulatedRealm())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for field, bad := range map[string]string{
		"directory":               "scim ",
		"interactive":             "humans",
		"revocation":              "",
		"delegation":              "any",
		"minimum_assurance":       "highest",
		"authorized_party_policy": "allowlist",
		"credential_age_policy":   "unspecified",
	} {
		t.Run(field, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(encoded, &raw); err != nil {
				t.Fatal(err)
			}
			raw[field] = bad
			mutated, err := json.Marshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeRealm(mutated)
			if err == nil {
				t.Fatalf("a stored %s of %q decoded to %+v; an unrecognised value must be refused, not defaulted to \"not declared\"", field, bad, got)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("the refusal does not name the field: %v", err)
			}
		})
	}
}

// TestAForeignStorageFormatVersionIsRefused. During a rolling deployment an
// older binary meets rows a newer one wrote; interpreting them under the wrong
// rules is how a realm silently changes what it accepts.
func TestAForeignStorageFormatVersionIsRefused(t *testing.T) {
	encoded, err := encodeRealm(fullyPopulatedRealm())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	for _, version := range []any{"axonflow.trust-realm.v2", "", nil} {
		if version == nil {
			delete(raw, "format_version")
		} else {
			raw["format_version"] = version
		}
		mutated, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRealm(mutated); err == nil {
			t.Errorf("a realm stored under format version %v was decoded under this version's rules", version)
		}
	}
}

// TestStorageRefusesADurationItWouldTruncate. A clock skew of 1500ms stored as
// 1s is a realm that accepts a different set of credentials after a restart
// than before it, with nothing anywhere recording the change.
func TestStorageRefusesADurationItWouldTruncate(t *testing.T) {
	for name, mutate := range map[string]func(*TrustRealm){
		"clock skew": func(r *TrustRealm) { r.ClockSkew = 1500 * time.Millisecond },
		"maximum credential age": func(r *TrustRealm) {
			r.CredentialAgePolicy = CredentialAgeBounded
			r.MaxCredentialAge = 90*time.Minute + 500*time.Millisecond
		},
	} {
		t.Run(name, func(t *testing.T) {
			realm := fullyPopulatedRealm()
			mutate(&realm)
			if _, err := encodeRealm(realm); err == nil {
				t.Fatalf("a %s that is not a whole number of seconds was accepted for storage; it would be truncated and the realm would behave differently after a restart", name)
			}
		})
	}
	// The control: the same realm with whole-second durations encodes.
	if _, err := encodeRealm(fullyPopulatedRealm()); err != nil {
		t.Fatalf("the unmutated fixture was refused, so the refusals above are not evidence about truncation: %v", err)
	}
}

// TestStorageRefusesAnInvalidRealm, in both directions. Writing one produces a
// row that fails to load on every subsequent boot, with the failure surfacing
// far from the write that caused it; reading one back that no longer validates
// - because a rule tightened, or because something wrote outside this codec -
// must fail rather than register a realm with a field nobody declared.
func TestStorageRefusesAnInvalidRealm(t *testing.T) {
	invalid := fullyPopulatedRealm()
	invalid.Directory = DirectorySourceUnspecified
	if _, err := encodeRealm(invalid); err == nil {
		t.Fatal("a realm with an undeclared Directory was accepted for storage")
	}

	// Read side: a row whose Audiences went missing (an unbounded audience is
	// a token usable anywhere, which Validate refuses) must not load.
	encoded, err := encodeRealm(fullyPopulatedRealm())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	raw["audiences"] = []string{}
	mutated, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRealm(mutated); err == nil {
		t.Fatal("a stored realm with no audiences was loaded; an unbounded audience is a token usable anywhere")
	}
}

// TestTheStorageFormatVersionIsBoundToTheRecordShape ties the version constant
// to the exact set of JSON keys realmRecord writes.
//
// # Why a golden list rather than a comment asking people to remember
//
// `storageFormatVersion` only protects a rolling deployment if somebody BUMPS
// it when the shape changes, and nothing forced that: "I only added a field"
// is exactly the reasoning that skips a bump, and the encoder, the decoder and
// every other test stayed green. DisallowUnknownFields now makes the older
// binary REFUSE the newer row rather than silently drop the field - which is
// the safe direction - but it turns a forgotten bump into a fleet-wide load
// failure during the deploy rather than into a caught mistake at review time.
//
// So the shape is written down here. Changing realmRecord fails this test,
// and the failure says what to do: bump the version if the change is not
// backward-compatible, and update this list either way. That is the whole
// mechanism - a list somebody must edit deliberately, next to the constant it
// governs.
func TestTheStorageFormatVersionIsBoundToTheRecordShape(t *testing.T) {
	const boundVersion = "axonflow.trust-realm.v1"
	if storageFormatVersion != boundVersion {
		t.Fatalf("storageFormatVersion is %q but this test is written against %q.\nIf the format changed deliberately, update the golden key set below in the same commit; if it did not, the constant was edited by accident.",
			storageFormatVersion, boundVersion)
	}

	want := map[string]bool{
		"format_version": true, "realm_id": true, "org_id": true, "kind": true,
		"canonical_issuer": true, "accepted_subject_types": true,
		"accepted_credential_types": true, "audiences": true,
		"authorized_party_policy": true, "authorized_parties": true,
		"allowed_signing_algorithms": true, "claim_mapping": true,
		"minimum_assurance": true, "clock_skew_seconds": true,
		"credential_age_policy": true, "max_credential_age_seconds": true,
		"directory": true, "interactive": true, "revocation": true,
		"delegation": true, "delegate_realms": true, "enabled": true,
		"version": true,
	}

	got := map[string]bool{}
	rt := reflect.TypeOf(realmRecord{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" {
			t.Errorf("realmRecord.%s has no json tag, so its stored key is its Go field name - which renames whenever the field does", rt.Field(i).Name)
			continue
		}
		got[strings.Split(tag, ",")[0]] = true
	}

	for key := range want {
		if !got[key] {
			t.Errorf("stored key %q is no longer written by realmRecord.\nRemoving or renaming a key changes what an older binary reads. BUMP storageFormatVersion (an older binary must refuse the new shape, not misread it) and update this list.", key)
		}
	}
	for key := range got {
		if !want[key] {
			t.Errorf("realmRecord writes a new stored key %q that this test does not know about.\nA newer binary's rows now carry a key an older one will REFUSE (DisallowUnknownFields), which is a load failure across a rolling deploy rather than a silent drop. If that is intended, bump storageFormatVersion and add %q here; if the field is meant to be backward-compatible, it cannot be - there is no ignore path by design.", key, key)
		}
	}

	// The nested record is part of the shape too, and it is where the earlier
	// round-trip guard was blind.
	wantClaim := map[string]bool{"version": true, "subject_claim": true, "subject_type": true, "alias_claims": true}
	ct := reflect.TypeOf(claimMappingRecord{})
	gotClaim := map[string]bool{}
	for i := 0; i < ct.NumField(); i++ {
		gotClaim[strings.Split(ct.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	if !reflect.DeepEqual(want["claim_mapping"], true) || !reflect.DeepEqual(gotClaim, wantClaim) {
		t.Errorf("claimMappingRecord's stored keys are %v, want %v; the nested shape is part of the format and changing it needs the same version decision", gotClaim, wantClaim)
	}
}

// TestAnUnknownStoredFieldIsRefused. The format version only protects what its
// comment claims if somebody remembers to BUMP it, and "I only added a field"
// is exactly when they will not.
//
// During a rolling deploy an older binary then reads a newer row, silently
// DROPS the field it does not know, Validate (which also does not know about
// it) passes, and the realm registers with that field at its ZERO VALUE - "not
// declared", which is the EX-47 fail-open. Measured before the fix: a row
// carrying an unknown key decoded with err == nil.
func TestAnUnknownStoredFieldIsRefused(t *testing.T) {
	encoded, err := encodeRealm(fullyPopulatedRealm())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	raw["a_field_a_newer_binary_added"] = "segment-ceiling"
	mutated, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeRealm(mutated); err == nil {
		t.Fatalf("a row carrying a field this binary does not know decoded to %+v.\nAn older replica would drop it, Validate would pass, and the realm would register with that field at its zero value - which on this type means \"not declared\".", got.RealmID)
	}
	// The control: the same row WITHOUT the unknown key still decodes, so the
	// refusal above is the unknown field and not something ambient.
	if _, err := decodeRealm(encoded); err != nil {
		t.Fatalf("the unmutated row was refused, so the refusal above is not evidence about unknown fields: %v", err)
	}
}

// TestInvalidUTF8IsRefusedRatherThanRewritten. json.Marshal does not FAIL on
// invalid UTF-8 - it silently rewrites each bad byte to U+FFFD - so the realm
// the registry holds and the realm the store persists would declare different
// values with no error on any path. An issuer is matched byte-for-byte at the
// EX-47 gate, so "close enough" is not a category that exists here.
func TestInvalidUTF8IsRefusedRatherThanRewritten(t *testing.T) {
	for name, mutate := range map[string]func(*TrustRealm){
		"canonical issuer": func(r *TrustRealm) { r.CanonicalIssuer = "https://idp.\xff\xfe.example" },
		"an audience":      func(r *TrustRealm) { r.Audiences = []string{"aud-\xff"} },
		"a claim name":     func(r *TrustRealm) { r.ClaimMapping.SubjectClaim = "sub\xfe" },
		"an alias claim":   func(r *TrustRealm) { r.ClaimMapping.AliasClaims = map[AliasKind]string{AliasEmail: "mail\xff"} },
	} {
		t.Run(name, func(t *testing.T) {
			realm := fullyPopulatedRealm()
			mutate(&realm)
			if _, err := encodeRealm(realm); err == nil {
				t.Fatalf("a realm with invalid UTF-8 in its %s was encoded; JSON would replace it with U+FFFD and the stored realm would declare a different value from the one in memory", name)
			}
		})
	}
	// The control: the unmutated fixture encodes.
	if _, err := encodeRealm(fullyPopulatedRealm()); err != nil {
		t.Fatalf("the unmutated fixture was refused, so the refusals above are not evidence about UTF-8: %v", err)
	}
}

// The realm id's storage bound is pinned in realm_store_realpg_test.go, by
// inserting an id at maxPrincipalComponent into the REAL column.
//
// It used to be pinned here, by comparing maxPrincipalComponent against a
// hand-copied `const columnWidth = 512 // migrations/core/169`. That is a
// tautology over two Go constants: it cannot see the schema, so reverting the
// column to VARCHAR(255) left this file - and the whole package - green, which
// a mutant confirmed. A bound that exists in two places and is checked in
// neither against the other is the defect the widening was meant to close.
