// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"testing"
)

// TestAdmitDecisionSubjectAdmitsAVerifiedUserAndRefusesAClientRoot: the user
// door admits the subject an enforcing decision plane evaluates for (#3895
// PR-A2), driven through the SAME CredentialPrincipal builders the agent's
// authentication paths use.
func TestAdmitDecisionSubjectAdmitsAVerifiedUserAndRefusesAClientRoot(t *testing.T) {
	ctx := context.Background()
	a, _ := admitterFixture(t, BuiltinRealmDeployment{})

	t.Run("a verified per-user token is admitted as the root, keyed on its sub claim", func(t *testing.T) {
		chain, adm := a.AdmitDecisionSubject(ctx, HS256Principal(fixtureOrg, mintedClaims(), true, ""), DefaultMaxDelegationDepth)
		if !adm.State.IsAdmitted() {
			t.Fatalf("a verified minted token was refused: %s", adm)
		}
		want := PrincipalID{Realm: BuiltinRealmMinted, Type: SubjectUser, Subject: "user-1138"}
		if root, ok := chain.Root(); !ok || root != want || adm.Principal != want {
			t.Fatalf("admitted %v (chain %v), want %v", adm.Principal, chain, want)
		}
	})

	t.Run("an internal-service hop is admitted as a Service", func(t *testing.T) {
		chain, adm := a.AdmitDecisionSubject(ctx, InternalServicePrincipal(fixtureOrg, "orchestrator", true, fixtureNow), DefaultMaxDelegationDepth)
		if !adm.State.IsAdmitted() {
			t.Fatalf("an internal-service credential was refused: %s", adm)
		}
		want := PrincipalID{Realm: BuiltinRealmInternalService, Type: SubjectService, Subject: "orchestrator"}
		if root, _ := chain.Root(); root != want {
			t.Fatalf("admitted %v, want %v", root, want)
		}
	})

	// ADR-065 INVARIANT 2, REACHED THROUGH AdmitChain: both client-credential
	// paths authenticate a Client, and a Client is never the root authority.
	for name, in := range map[string]CredentialPrincipal{
		"a community-mode caller":           CommunityPrincipal(fixtureOrg, "local-dev-org", fixtureNow),
		"a licence / API-credential caller": APICredentialPrincipal(fixtureOrg, "client-7", VerificationAPICredential, true, fixtureNow),
	} {
		t.Run(name+" is refused SUBJECT_TYPE_REJECTED", func(t *testing.T) {
			chain, adm := a.AdmitDecisionSubject(ctx, in, DefaultMaxDelegationDepth)
			if adm.State != AdmissionDeny || adm.Reason != ReasonSubjectTypeRejected {
				t.Fatalf("got state %s reason %s (%s), want a Deny for %s", adm.State, adm.Reason, adm.Detail, ReasonSubjectTypeRejected)
			}
			if chain != nil {
				t.Fatalf("a refused admission handed back a chain: %v", chain)
			}
		})
	}

	t.Run("no authenticated organization is Indeterminate, never a subject", func(t *testing.T) {
		_, adm := a.AdmitDecisionSubject(ctx, HS256Principal("", mintedClaims(), true, ""), DefaultMaxDelegationDepth)
		if adm.State != AdmissionIndeterminate {
			t.Fatalf("got state %s (%s), want Indeterminate", adm.State, adm.Detail)
		}
	})

	t.Run("a nil admitter is Indeterminate", func(t *testing.T) {
		var nilAdmitter *SubjectAdmitter
		if _, adm := nilAdmitter.AdmitDecisionSubject(ctx, HS256Principal(fixtureOrg, mintedClaims(), true, ""), 0); adm.State != AdmissionIndeterminate {
			t.Fatalf("a nil admitter produced state %s", adm.State)
		}
	})
}
