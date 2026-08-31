// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"testing"
	"time"
)

// The ADR-065 identity-plane fixtures.
//
// They mirror the source specification's own fixture set so a conformance case
// can be read against its source case without a translation step: one realm
// with a human group graph that can answer a question, and one non-human realm
// with neither. Every case in the corpus that names an EX number resolves its
// principals here.
const (
	fixtureOrg      = "org_acme"
	fixtureOtherOrg = "org_other"

	// realmWorkspace is the human directory: it has a group graph and its
	// subjects can be asked a question.
	realmWorkspace RealmID = "workspace"
	// realmCloudIAM is the non-human realm: no group graph, non-interactive.
	// It is the EX-45 and EX-46 realm.
	realmCloudIAM RealmID = "gcp-iam"

	issuerWorkspace = "https://idp.acme.example"
	issuerCloudIAM  = "https://iam.gcp.example"
	// issuerAcquired is EX-47's issuer: a directory that arrived with an
	// acquisition and has no realm declared.
	issuerAcquired = "https://idp.acquired-co.example"

	audienceAxonFlow = "axonflow"
	azpGateway       = "prod-gateway"
)

// fixtureNow is a fixed instant so every time-sensitive assertion is
// deterministic. Tests that need a different instant offset from this one.
var fixtureNow = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

// workspaceRealm returns the human realm declaration.
func workspaceRealm() TrustRealm {
	return TrustRealm{
		RealmID:                  realmWorkspace,
		OrgID:                    fixtureOrg,
		Kind:                     RealmKindOIDC,
		CanonicalIssuer:          issuerWorkspace,
		AcceptedSubjectTypes:     []SubjectType{SubjectUser, SubjectGroup, SubjectAgent},
		AcceptedCredentialTypes:  []CredentialType{CredentialBearerJWT, CredentialIDToken},
		Audiences:                []string{audienceAxonFlow},
		AuthorizedPartyPolicy:    AuthorizedPartyNotChecked,
		AllowedSigningAlgorithms: []string{"RS256"},
		ClaimMapping: ClaimMapping{
			Version:      1,
			SubjectClaim: "sub",
			SubjectType:  SubjectUser,
			AliasClaims:  map[AliasKind]string{AliasEmail: "email", AliasDisplayName: "name"},
		},
		MinimumAssurance:    AssuranceSubstantial,
		ClockSkew:           30 * time.Second,
		CredentialAgePolicy: CredentialAgeUnbounded,
		Directory:           DirectorySourceSCIM,
		Interactive:         InteractiveHuman,
		Revocation:          RevocationSourceNone,
		Delegation:          DelegationAnyRealmInOrg,
		Enabled:             true,
		Version:             1,
	}
}

// cloudIAMRealm returns the non-human realm declaration: no group graph, not
// interactive. EX-45 and EX-46 both turn on these two fields.
func cloudIAMRealm() TrustRealm {
	return TrustRealm{
		RealmID:                  realmCloudIAM,
		OrgID:                    fixtureOrg,
		Kind:                     RealmKindSPIFFE,
		CanonicalIssuer:          issuerCloudIAM,
		AcceptedSubjectTypes:     []SubjectType{SubjectService, SubjectWorkload, SubjectAgent, SubjectGroup},
		AcceptedCredentialTypes:  []CredentialType{CredentialSVID, CredentialBearerJWT},
		Audiences:                []string{audienceAxonFlow},
		AuthorizedPartyPolicy:    AuthorizedPartyNotChecked,
		AllowedSigningAlgorithms: []string{"RS256", "ES256"},
		ClaimMapping: ClaimMapping{
			Version:      1,
			SubjectClaim: "sub",
			SubjectType:  SubjectWorkload,
		},
		MinimumAssurance:    AssuranceLow,
		ClockSkew:           30 * time.Second,
		CredentialAgePolicy: CredentialAgeUnbounded,
		Directory:           DirectorySourceNone,
		Interactive:         InteractiveNonInteractive,
		Revocation:          RevocationSourceNone,
		Delegation:          DelegationAnyRealmInOrg,
		Enabled:             true,
		Version:             1,
	}
}

// fixtureRegistry returns a registry holding both fixture realms in fixtureOrg.
func fixtureRegistry(t *testing.T) *RealmRegistry {
	t.Helper()
	reg := NewRealmRegistry()
	if err := reg.Register(workspaceRealm()); err != nil {
		t.Fatalf("registering the workspace realm: %v", err)
	}
	if err := reg.Register(cloudIAMRealm()); err != nil {
		t.Fatalf("registering the cloud-IAM realm: %v", err)
	}
	return reg
}

// workspaceCredential returns a credential that the workspace realm admits.
// Tests mutate one field to isolate the check under test, which keeps every
// negative case one deliberate step away from a known-good positive.
func workspaceCredential() Credential {
	return Credential{
		Issuer:            issuerWorkspace,
		Type:              CredentialBearerJWT,
		Algorithm:         "RS256",
		SignatureVerified: true,
		Audiences:         []string{audienceAxonFlow},
		Subject:           "00u123",
		Assurance:         AssuranceSubstantial,
		IssuedAt:          fixtureNow.Add(-time.Minute),
		ExpiresAt:         fixtureNow.Add(time.Hour),
		Aliases:           map[AliasKind]string{AliasEmail: "alice@acme.example"},
	}
}

// cloudIAMCredential returns a credential the non-human realm admits.
func cloudIAMCredential() Credential {
	return Credential{
		Issuer:            issuerCloudIAM,
		Type:              CredentialSVID,
		Algorithm:         "ES256",
		SignatureVerified: true,
		Audiences:         []string{audienceAxonFlow},
		Subject:           "spiffe://acme.example/workload/jira-bot",
		Assurance:         AssuranceLow,
		IssuedAt:          fixtureNow.Add(-time.Minute),
		ExpiresAt:         fixtureNow.Add(time.Hour),
	}
}

// Fixture principals. alice and agentA are the EX-27 chain; agentA resolves in
// a different realm from alice, which the source case calls the normal case.
var (
	fixtureAlice  = MustParsePrincipalID("User::workspace:00u123")
	fixtureBob    = MustParsePrincipalID("User::workspace:00u456")
	fixtureAgentA = MustParsePrincipalID("Agent::gcp-iam:agent-7")
	fixtureSubB   = MustParsePrincipalID("Agent::gcp-iam:sub-B")
	fixtureClient = MustParsePrincipalID("Client::workspace:prod-gateway")
)

// assertDeny fails unless adm is a Deny carrying want.
func assertDeny(t *testing.T, adm Admission, want AdmissionReason) {
	t.Helper()
	if adm.State != AdmissionDeny {
		t.Fatalf("want Deny(%s), got %s", want, adm)
	}
	if adm.Reason != want {
		t.Fatalf("want reason %s, got %s", want, adm)
	}
}

// assertIndeterminate fails unless adm is Indeterminate carrying want.
func assertIndeterminate(t *testing.T, adm Admission, want AdmissionReason) {
	t.Helper()
	if adm.State != AdmissionIndeterminate {
		t.Fatalf("want Indeterminate(%s), got %s", want, adm)
	}
	if adm.Reason != want {
		t.Fatalf("want reason %s, got %s", want, adm)
	}
}

// assertAdmitted fails unless adm admitted want.
func assertAdmitted(t *testing.T, adm Admission, want PrincipalID) {
	t.Helper()
	if !adm.State.IsAdmitted() {
		t.Fatalf("want ACCEPT(%s), got %s", want, adm)
	}
	if adm.Principal != want {
		t.Fatalf("want principal %s, got %s", want, adm.Principal)
	}
}
