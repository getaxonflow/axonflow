// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// #3709 row 3: a realm id is the qualifier of every principal this package
// mints, and the decision contract parses qualifiers with one grammar. This
// file pins that ValidateRealmID and contract.ValidateQualifier agree on every
// input in BOTH directions, and that the refusal happens where an operator
// meets it - at realm creation - with a message naming the rule.
//
// The principal-level sweep in principal_contract_lockstep_test.go proves the
// same property one level up (a realm the two disagree on would surface there
// as an UNDECLARED divergence). This file is the realm-only statement of it,
// so the guard does not depend on the cross product happening to contain the
// realm that drifts.

// realmGrammarCorpus is every realm shape the two rules have ever disagreed on,
// plus the ones they always agreed on, plus the length boundary. Both sides of
// every row are asserted, and the corpus must contain both outcomes.
var realmGrammarCorpus = []struct {
	realm string
	why   string
}{
	// Accepted by both.
	{"security", "a plain word"},
	{"acme-prod", "an interior dash"},
	{"eu.central_1", "dots and underscores"},
	{"r-1", "short"},
	{"A1", "upper case and a digit"},
	{"0realm", "a leading digit is a legal qualifier start"},
	{"axonflow-minted", "a built-in realm id"},
	{"oidc", "a built-in realm id"},
	{strings.Repeat("a", maxPrincipalComponent), "exactly at identity's length bound"},

	// Refused by both since #3709 row 3; identity accepted every one before.
	{"acme+prod", "the row's own example: '+' is printable and colon-free"},
	{"eu/central", "a path separator"},
	{"realm@okta", "an '@'"},
	{"réalm", "non-ASCII, printable"},
	{"-leading", "a leading dash"},
	{"_leading", "a leading underscore"},
	{".leading", "a leading dot"},
	{"realm okta", "an interior space"},
	{"realm\tokta", "a tab"},
	{"realm\x00okta", "a NUL"},
	{"realm:okta", "the wire-form separator"},
	{"", "empty"},
	{"00u​1", "a zero-width space, printable to unicode.IsPrint's complement"},
}

// TestRealmIDGrammarIsTheContractQualifierGrammarInBothDirections asserts, for
// every row, ValidateRealmID accepts <=> contract.ValidateQualifier accepts,
// with the single declared exception of identity's length bound - which is
// asserted separately below rather than folded into the corpus, so the
// exception cannot widen.
func TestRealmIDGrammarIsTheContractQualifierGrammarInBothDirections(t *testing.T) {
	accepted, refused := 0, 0
	for _, row := range realmGrammarCorpus {
		identityErr := ValidateRealmID(RealmID(row.realm))
		contractErr := contract.ValidateQualifier(row.realm)
		switch {
		case identityErr == nil && contractErr == nil:
			accepted++
		case identityErr != nil && contractErr != nil:
			refused++
		case identityErr == nil:
			t.Errorf("identity ACCEPTS realm %q (%s) and contract REFUSES it (%v): the dangerous direction - "+
				"every principal minted under this realm is unparseable by the PDP", row.realm, row.why, contractErr)
		default:
			t.Errorf("contract ACCEPTS qualifier %q (%s) and identity REFUSES it (%v): a realm the PDP would "+
				"evaluate that no proof can bind", row.realm, row.why, identityErr)
		}
	}
	// ANTI-VACUITY: both outcomes must be present, or the loop compared nothing.
	if accepted < 5 || refused < 5 {
		t.Fatalf("corpus produced %d agreements-to-accept and %d agreements-to-refuse; a one-sided corpus is not a comparison", accepted, refused)
	}
}

// TestTheOnlyDeclaredRealmDivergenceIsTheLengthBound: identity caps a realm at
// maxPrincipalComponent and contract has no bound. That is the one remaining
// disagreement, in the SAFE direction (identity refuses what contract would
// accept), and it is pinned here so a second one cannot hide beside it.
func TestTheOnlyDeclaredRealmDivergenceIsTheLengthBound(t *testing.T) {
	long := strings.Repeat("a", maxPrincipalComponent+1)
	if err := contract.ValidateQualifier(long); err != nil {
		t.Fatalf("contract now refuses a %d-byte qualifier (%v); the component-length class in the lockstep "+
			"sweep and this exception are both stale - reconcile them", len(long), err)
	}
	if err := ValidateRealmID(RealmID(long)); err == nil {
		t.Fatalf("identity accepted a %d-byte realm id; the length bound is gone", len(long))
	}
}

// TestARealmOutsideTheGrammarIsRefusedAtCreation is the operator-facing
// assertion: the refusal happens where a realm is created, and the message
// names the rule the operator broke, so the fix is legible from the error.
func TestARealmOutsideTheGrammarIsRefusedAtCreation(t *testing.T) {
	realm := workspaceRealm()
	realm.RealmID = "acme+prod"

	err := realm.Validate()
	if err == nil {
		t.Fatal("TrustRealm.Validate accepted realm id acme+prod; every principal minted under it would be unparseable by the PDP")
	}
	for _, want := range []string{"acme+prod", "qualifier", "[A-Za-z0-9][A-Za-z0-9_.-]*", "':'"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so an operator cannot tell which rule they broke:\n%v", want, err)
		}
	}

	reg := NewRealmRegistry()
	if err := reg.Register(realm); err == nil {
		t.Fatal("RealmRegistry.Register accepted realm id acme+prod")
	}
	if _, err := NewPrincipalID("acme+prod", SubjectUser, "00u1"); err == nil {
		t.Fatal("NewPrincipalID minted a principal under realm acme+prod")
	}

	// The control: the same realm with a legal id is accepted on all three
	// surfaces, so the refusals above are the grammar and not the fixture.
	realm.RealmID = "acme-prod"
	if err := realm.Validate(); err != nil {
		t.Fatalf("the control realm acme-prod was refused: %v", err)
	}
	if err := reg.Register(realm); err != nil {
		t.Fatalf("the control realm acme-prod could not be registered: %v", err)
	}
	if _, err := NewPrincipalID("acme-prod", SubjectUser, "00u1"); err != nil {
		t.Fatalf("the control principal under acme-prod was refused: %v", err)
	}
}

// TestBuiltInRealmIDsAreInsideTheGrammar: the narrowing must not refuse a
// realm this package itself registers at boot.
func TestBuiltInRealmIDsAreInsideTheGrammar(t *testing.T) {
	for _, id := range []RealmID{
		BuiltinRealmMinted, BuiltinRealmAPICredential, BuiltinRealmInternalService,
		BuiltinRealmCommunity, BuiltinRealmTrustedHeader, BuiltinRealmOIDC,
	} {
		if err := ValidateRealmID(id); err != nil {
			t.Errorf("built-in realm %q is outside the qualifier grammar: %v", id, err)
		}
	}
}
