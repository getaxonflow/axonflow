// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"testing"
)

// THE CREDENTIAL PRINCIPAL (ADR-065 invariant 2 as amended 2026-09-11 (third)).
// A request that carries no user identity is evaluated for its authenticated
// client credential, and ONLY such a request: the door takes credential paths
// and nothing that asserts a user.
func TestAdmitCredentialSubjectAdmitsTheCredentialAndNothingThatAssertsAUser(t *testing.T) {
	ctx := context.Background()
	a, _ := admitterFixture(t, BuiltinRealmDeployment{})

	for name, c := range map[string]struct {
		in   CredentialPrincipal
		want PrincipalID
	}{
		"a community-mode caller": {
			CommunityPrincipal(fixtureOrg, "local-dev-org", fixtureNow),
			PrincipalID{Realm: BuiltinRealmCommunity, Type: SubjectClient, Subject: "local-dev-org"},
		},
		"a licence / API-credential caller": {
			APICredentialPrincipal(fixtureOrg, "client-7", VerificationAPICredential, true, fixtureNow),
			PrincipalID{Realm: BuiltinRealmAPICredential, Type: SubjectClient, Subject: "client-7"},
		},
		"an internal-service hop": {
			InternalServicePrincipal(fixtureOrg, "orchestrator", true, fixtureNow),
			PrincipalID{Realm: BuiltinRealmInternalService, Type: SubjectService, Subject: "orchestrator"},
		},
	} {
		t.Run(name+" is admitted as the credential principal", func(t *testing.T) {
			chain, adm := a.AdmitCredentialSubject(ctx, c.in, DefaultMaxDelegationDepth)
			if !adm.State.IsAdmitted() {
				t.Fatalf("refused: %s", adm)
			}
			if root, ok := chain.Root(); !ok || root != c.want || adm.Principal != c.want {
				t.Fatalf("admitted %v (chain %v), want %v", adm.Principal, chain, c.want)
			}
			// CONTROL: the same credential through the user door is still refused
			// on the unamended invariant, so the admission above is the door's
			// and not a relaxed AdmitChain.
			if c.want.Type == SubjectClient {
				if _, adm := a.AdmitDecisionSubject(ctx, c.in, DefaultMaxDelegationDepth); adm.State != AdmissionDeny || adm.Reason != ReasonSubjectTypeRejected {
					t.Fatalf("CONTROL: AdmitDecisionSubject now answers %s %s for a client credential; the invariant moved, not the door", adm.State, adm.Reason)
				}
			}
		})
	}

	// ADMISSION IS FOR THE ABSENCE OF A USER IDENTITY, NEVER FOR A BAD ONE. Both
	// a verified and a failed token are user assertions, and the door refuses
	// them before verifying anything.
	for name, in := range map[string]CredentialPrincipal{
		"a verified per-user token":                 HS256Principal(fixtureOrg, mintedClaims(), true, ""),
		"a per-user token that failed verification": HS256Principal(fixtureOrg, mintedClaims(), false, ""),
	} {
		t.Run(name+" is refused at the credential door", func(t *testing.T) {
			chain, adm := a.AdmitCredentialSubject(ctx, in, DefaultMaxDelegationDepth)
			if adm.State != AdmissionDeny || adm.Reason != ReasonSubjectTypeRejected || chain != nil {
				t.Fatalf("got %s %s chain %v; want a Deny for %s and no chain", adm.State, adm.Reason, chain, ReasonSubjectTypeRejected)
			}
		})
	}

	t.Run("a credential the legacy path rejected is not admitted", func(t *testing.T) {
		_, adm := a.AdmitCredentialSubject(ctx, APICredentialPrincipal(fixtureOrg, "client-7", VerificationAPICredential, false, fixtureNow), DefaultMaxDelegationDepth)
		if adm.State.IsAdmitted() {
			t.Fatalf("a rejected client credential was admitted as %v", adm.Principal)
		}
	})

	t.Run("a nil admitter is Indeterminate", func(t *testing.T) {
		var nilAdmitter *SubjectAdmitter
		if _, adm := nilAdmitter.AdmitCredentialSubject(ctx, CommunityPrincipal(fixtureOrg, "c", fixtureNow), 0); adm.State != AdmissionIndeterminate {
			t.Fatalf("a nil admitter produced state %s", adm.State)
		}
	})

}
