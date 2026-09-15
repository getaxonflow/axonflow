// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"strings"
	"testing"
)

// The built-in trust realms (#3550): what each declares, and the source that
// registers them once per organization.

func TestBuiltinRealmsValidate(t *testing.T) {
	for _, dep := range []BuiltinRealmDeployment{
		{},
		{HasDirectory: true, HasRevocation: true},
		{HasDirectory: true, HasRevocation: true, HasCAEP: true},
	} {
		realms := BuiltinRealms(fixtureOrg, dep)
		if len(realms) == 0 {
			t.Fatalf("no built-in realms for %+v", dep)
		}
		seenID := map[RealmID]bool{}
		seenIssuer := map[string]bool{}
		for _, r := range realms {
			if err := r.Validate(); err != nil {
				t.Fatalf("built-in realm %q (%+v) is invalid: %v", r.RealmID, dep, err)
			}
			if seenID[r.RealmID] {
				t.Fatalf("duplicate built-in realm id %q", r.RealmID)
			}
			seenID[r.RealmID] = true
			if seenIssuer[r.CanonicalIssuer] {
				t.Fatalf("two built-in realms claim issuer %q; the registry refuses that", r.CanonicalIssuer)
			}
			seenIssuer[r.CanonicalIssuer] = true
			if r.OrgID != fixtureOrg {
				t.Fatalf("built-in realm %q carries org %q", r.RealmID, r.OrgID)
			}
		}
	}
}

// TestBuiltinDirectoryAndRevocationArePositiveDeclarations: the two deployment
// booleans decide facts that EX-45 turns on, so they must actually move.
func TestBuiltinDirectoryAndRevocationArePositiveDeclarations(t *testing.T) {
	bare := realmByID(t, BuiltinRealms(fixtureOrg, BuiltinRealmDeployment{}), BuiltinRealmMinted)
	if bare.Directory != DirectorySourceNone {
		t.Fatalf("a deployment with no directory declared %s", bare.Directory)
	}
	if bare.Revocation != RevocationSourceNone {
		t.Fatalf("a deployment with no deny-list declared %s", bare.Revocation)
	}
	if bare.HasGroupGraph() {
		t.Fatalf("a no-directory realm reports a group graph")
	}

	wired := realmByID(t, BuiltinRealms(fixtureOrg, BuiltinRealmDeployment{HasDirectory: true, HasRevocation: true}), BuiltinRealmMinted)
	if wired.Directory != DirectorySourceSCIM {
		t.Fatalf("a deployment WITH a directory declared %s", wired.Directory)
	}
	if wired.Revocation != RevocationSourceLocalStore {
		t.Fatalf("a deployment WITH a deny-list declared %s", wired.Revocation)
	}
}

// TestBuiltinAPICredentialAssertsAClientNotAUser is ADR-065 invariant 2: a
// client credential authenticates an application, and a Client principal is
// attribution rather than authority.
func TestBuiltinAPICredentialAssertsAClientNotAUser(t *testing.T) {
	realms := BuiltinRealms(fixtureOrg, BuiltinRealmDeployment{})
	api := realmByID(t, realms, BuiltinRealmAPICredential)
	if api.ClaimMapping.SubjectType != SubjectClient {
		t.Fatalf("the api-credential realm asserts %s", api.ClaimMapping.SubjectType)
	}
	if api.AcceptsSubjectType(SubjectUser) {
		t.Fatalf("the api-credential realm accepts a User subject; an API key is not a person")
	}
	svc := realmByID(t, realms, BuiltinRealmInternalService)
	if svc.ClaimMapping.SubjectType != SubjectService {
		t.Fatalf("the internal-service realm asserts %s", svc.ClaimMapping.SubjectType)
	}
	if api.Interactive.CanAnswer() || svc.Interactive.CanAnswer() {
		t.Fatalf("a non-human realm reports that it can answer an approval (EX-46)")
	}
}

// TestBuiltinTrustedHeaderCannotClaimHighAssurance: TrustRealm.Validate caps a
// trusted-header realm at AssuranceLow, and the community realm is declared as
// one precisely so it inherits that ceiling.
func TestBuiltinTrustedHeaderCannotClaimHighAssurance(t *testing.T) {
	realms := BuiltinRealms(fixtureOrg, BuiltinRealmDeployment{})
	for _, id := range []RealmID{BuiltinRealmTrustedHeader, BuiltinRealmCommunity} {
		r := realmByID(t, realms, id)
		if r.Kind != RealmKindTrustedHeader {
			t.Fatalf("realm %q kind = %s", id, r.Kind)
		}
		if r.MinimumAssurance > AssuranceLow {
			t.Fatalf("realm %q declares assurance %s above the trusted-header ceiling", id, r.MinimumAssurance)
		}
		r.MinimumAssurance = AssuranceHigh
		if err := r.Validate(); err == nil {
			t.Fatalf("realm %q accepted an assurance above the trusted-header ceiling", id)
		}
	}
}

// TestVerificationNoneIsNotSpelledNone: TrustRealm.Validate refuses the literal
// "none" case-insensitively because in a JWT header it means an unsigned
// token, and "this deployment requires no credential" is a different fact.
func TestVerificationNoneIsNotSpelledNone(t *testing.T) {
	if strings.EqualFold(VerificationCommunityUnauthenticated, "none") {
		t.Fatalf("the community verification method is spelled %q, which Validate refuses", VerificationCommunityUnauthenticated)
	}
	for _, v := range []string{VerificationAPICredential, VerificationHMACInternalService, VerificationUpstreamAsserted, VerificationCommunityUnauthenticated} {
		if strings.TrimSpace(v) == "" {
			t.Fatalf("an empty verification method")
		}
	}
}

func realmByID(t *testing.T, realms []TrustRealm, id RealmID) TrustRealm {
	t.Helper()
	for _, r := range realms {
		if r.RealmID == id {
			return r
		}
	}
	t.Fatalf("no built-in realm %q", id)
	return TrustRealm{}
}

// TestBuiltinRealmSourceMemoizesAFailure: the remedy for an invalid built-in
// realm is a fixed build, not a validation spent on every request forever, and
// a partially registered organization must not read as a successful one.
func TestBuiltinRealmSourceMemoizesAFailure(t *testing.T) {
	reg := NewRealmRegistry()
	src, err := NewBuiltinRealmSource(reg, BuiltinRealmDeployment{})
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	// Claim the minted realm's issuer for a DIFFERENT realm first, so the
	// built-in registration collides and fails.
	blocker := workspaceRealm()
	blocker.RealmID = "blocker"
	blocker.CanonicalIssuer = UserTokenIssuer
	if regErr := reg.Register(blocker); regErr != nil {
		t.Fatalf("register blocker: %v", regErr)
	}

	first := src.EnsureRealms(context.Background(), fixtureOrg)
	if first == nil {
		t.Fatalf("a colliding built-in registration was reported as success")
	}
	// THE DECISIVE STEP. Remove the obstacle. A source that memoized its
	// failure still reports it; a source that retries would now SUCCEED, and
	// nothing else in this test could tell the two apart - an epoch check
	// cannot, because a retry that fails again also leaves the epoch alone.
	reg.Remove(fixtureOrg, "blocker")
	second := src.EnsureRealms(context.Background(), fixtureOrg)
	if second == nil {
		t.Fatalf("the failure was not memoized: the source retried once the obstacle was removed, so an invalid built-in realm would cost a validation on every request forever")
	}
	if second.Error() != first.Error() {
		t.Fatalf("the memoized failure changed between calls: %v then %v", first, second)
	}
}
