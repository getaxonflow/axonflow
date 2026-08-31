// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// agentCredential returns a credential the cloud-IAM realm admits as an Agent,
// which is the second hop of the EX-27 chain.
func agentCredential() Credential {
	c := cloudIAMCredential()
	c.Subject = "agent-7"
	c.SubjectType = SubjectAgent
	return c
}

// TestVerifyChainFailsClosedOnAnyHop covers AXC-237.
//
// The #3556 criterion is that cycles, excessive depth, wrong audience, expiry
// and REVOKED HOPS all fail closed. Those are two different kinds of fact:
// audience, expiry and revocation are per-credential, cycles and depth are
// per-chain. VerifyChain is the one place they compose, and this test drives
// one of each through it so the composition is exercised rather than assumed.
func TestVerifyChainFailsClosedOnAnyHop(t *testing.T) {
	MarkConformanceCase("AXC-237")

	reg := fixtureRegistry(t)
	good := func() []Credential { return []Credential{workspaceCredential(), agentCredential()} }

	// The unmutated chain is admitted, so every refusal below is attributable
	// to its one change.
	chain, subjects, adm := VerifyChain(reg, fixtureOrg, good(), 3, fixtureNow, nil)
	assertAdmitted(t, adm, fixtureAlice)
	if len(chain) != 2 || chain[0] != fixtureAlice || chain[1] != fixtureAgentA {
		t.Fatalf("chain is %s, want root-first [alice, agent-A]", chain)
	}
	if len(subjects) != 2 {
		t.Fatalf("want a verified subject per hop, got %d", len(subjects))
	}
	if subjects[0].Realm.RealmID != realmWorkspace || subjects[1].Realm.RealmID != realmCloudIAM {
		t.Fatalf("each hop must be verified in ITS OWN realm; got %q and %q",
			subjects[0].Realm.RealmID, subjects[1].Realm.RealmID)
	}

	cases := []struct {
		name   string
		mutate func([]Credential) []Credential
		want   AdmissionReason
	}{
		{"wrong audience on the root", func(c []Credential) []Credential {
			c[0].Audiences = []string{"someone-else"}
			return c
		}, ReasonAudienceRejected},
		{"wrong audience on a later hop", func(c []Credential) []Credential {
			c[1].Audiences = []string{"someone-else"}
			return c
		}, ReasonAudienceRejected},
		{"expired later hop", func(c []Credential) []Credential {
			c[1].ExpiresAt = fixtureNow.Add(-time.Hour)
			return c
		}, ReasonCredentialExpired},
		{"undeclared issuer on a later hop", func(c []Credential) []Credential {
			c[1].Issuer = issuerAcquired
			return c
		}, ReasonUnknownRealm},
		{"cycle", func(c []Credential) []Credential {
			return append(c, workspaceCredential())
		}, ReasonChainCycle},
		{"empty", func([]Credential) []Credential { return nil }, ReasonChainEmpty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotChain, gotSubjects, gotAdm := VerifyChain(reg, fixtureOrg, tc.mutate(good()), 3, fixtureNow, nil)
			assertDeny(t, gotAdm, tc.want)
			if gotChain != nil || gotSubjects != nil {
				t.Fatalf("a refused chain returned %d hop(s) and %d subject(s); a partially verified chain must not be reachable",
					len(gotChain), len(gotSubjects))
			}
		})
	}

	// Depth is a chain-level fact and refuses even though every credential is
	// individually fine.
	_, _, adm = VerifyChain(reg, fixtureOrg, good(), 1, fixtureNow, nil)
	assertDeny(t, adm, ReasonDelegationDepth)

	// A refusal names WHICH hop, which matters when several hops share a realm
	// and the reason code alone cannot tell them apart.
	creds := good()
	creds[1].Audiences = []string{"someone-else"}
	_, _, adm = VerifyChain(reg, fixtureOrg, creds, 3, fixtureNow, nil)
	if !strings.Contains(adm.Detail, "hop 1 of 2") {
		t.Fatalf("the refusal does not name the offending hop: %s", adm)
	}
}

// TestVerifyChainRevokedHopFailsClosed is the revoked-hop half of the same
// criterion, separated because it needs a revocation-declaring realm.
//
// The ordering assertion is the substance. Per-hop credential facts are
// established BEFORE any chain-level check, so a chain containing both a
// revoked hop and a cycle reports the revocation. The alternative order reports
// the cycle, an operator fixes the cycle, and the revoked credential is still
// there to be accepted on the next attempt.
func TestVerifyChainRevokedHopFailsClosed(t *testing.T) {
	reg := NewRealmRegistry()
	w := workspaceRealm()
	w.Revocation = RevocationSourceLocalStore
	if err := reg.Register(w); err != nil {
		t.Fatalf("register workspace: %v", err)
	}
	if err := reg.Register(cloudIAMRealm()); err != nil {
		t.Fatalf("register cloud-iam: %v", err)
	}

	rootCred := workspaceCredential()
	rootCred.RevocationKey = "jti-root"

	revoked := &stubRealmRevocations{revoked: true}
	_, _, adm := VerifyChain(reg, fixtureOrg, []Credential{rootCred, agentCredential()}, 3, fixtureNow, revoked)
	assertDeny(t, adm, ReasonCredentialRevoked)

	live := &stubRealmRevocations{}
	_, _, adm = VerifyChain(reg, fixtureOrg, []Credential{rootCred, agentCredential()}, 3, fixtureNow, live)
	assertAdmitted(t, adm, fixtureAlice)

	// A revocation outage is Indeterminate, not a denial and not a pass.
	down := &stubRealmRevocations{err: errors.New("store unreachable")}
	_, _, adm = VerifyChain(reg, fixtureOrg, []Credential{rootCred, agentCredential()}, 3, fixtureNow, down)
	assertIndeterminate(t, adm, ReasonRevocationUnavailable)

	// Both wrong at once: the credential fact wins over the chain fact. If this
	// ever reports CHAIN_CYCLE, the composition has been reordered and a
	// revoked credential can hide behind a chain defect the operator will fix.
	cyclic := []Credential{rootCred, agentCredential(), rootCred}
	_, _, adm = VerifyChain(reg, fixtureOrg, cyclic, 5, fixtureNow, revoked)
	assertDeny(t, adm, ReasonCredentialRevoked)
}

// TestEveryPrincipalKindHasAnExecutableFixture covers AXC-238.
//
// The #3556 criterion asks for executable authentication and delegation
// fixtures for machine, agent, service and human principals. A criterion like
// that is easy to satisfy on paper and easy to leave half-done: the four kinds
// are usually represented in negative tests, where a principal appears only to
// be rejected, and a rejection proves nothing about whether the kind can be
// authenticated at all.
//
// So every kind here is driven through a real admission AND through a
// delegation chain, and the Client case asserts the one kind that is
// deliberately admissible only as an intermediary.
func TestEveryPrincipalKindHasAnExecutableFixture(t *testing.T) {
	MarkConformanceCase("AXC-238")

	reg := fixtureRegistry(t)
	// The workspace realm must assert Client for the intermediary case, and
	// the cloud-IAM realm already asserts Service, Workload and Agent.
	withClient := workspaceRealm()
	withClient.AcceptedSubjectTypes = append(withClient.AcceptedSubjectTypes, SubjectClient)
	withClient.Version = 2
	if err := reg.Register(withClient); err != nil {
		t.Fatalf("register: %v", err)
	}

	kinds := []struct {
		name    string
		cred    Credential
		want    PrincipalID
		asRoot  bool
		comment string
	}{
		{
			name: "human", cred: workspaceCredential(), want: fixtureAlice, asRoot: true,
			comment: "a user authenticated by an OIDC realm",
		},
		{
			name: "agent", cred: agentCredential(),
			want: MustParsePrincipalID("Agent::gcp-iam:agent-7"), asRoot: true,
			comment: "an AxonFlow-registered autonomous agent",
		},
		{
			name: "machine workload", cred: cloudIAMCredential(),
			want: MustParsePrincipalID("Workload::gcp-iam:spiffe://acme.example/workload/jira-bot"), asRoot: true,
			comment: "a SPIFFE-attested workload, subject id containing colons",
		},
		{
			name: "service account", cred: func() Credential {
				c := cloudIAMCredential()
				c.Subject = "svc-reconciler"
				c.SubjectType = SubjectService
				return c
			}(),
			want: MustParsePrincipalID("Service::gcp-iam:svc-reconciler"), asRoot: true,
			comment: "a directory service account",
		},
		{
			name: "client credential", cred: func() Credential {
				c := workspaceCredential()
				c.Subject = "prod-gateway"
				c.SubjectType = SubjectClient
				return c
			}(),
			want: fixtureClient, asRoot: false,
			comment: "attribution only: authenticates, but is never the authority",
		},
	}

	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			// Authentication fixture: the kind resolves to a canonical
			// principal of the expected type.
			got := VerifyCredential(reg, fixtureOrg, k.cred, fixtureNow, nil)
			assertAdmitted(t, got.Admission, k.want)
			if got.Admission.Principal.Type != k.want.Type {
				t.Fatalf("%s admitted as subject type %q, want %q", k.comment, got.Admission.Principal.Type, k.want.Type)
			}

			// Delegation fixture: the kind is usable in a chain, at the
			// position its semantics allow.
			if k.asRoot {
				adm := AdmitChain(reg, fixtureOrg, ActorChain{k.want, fixtureSubB}, 3)
				assertAdmitted(t, adm, k.want)
				return
			}
			// A Client is admissible only as an intermediary. Both directions
			// are asserted, because a test that only checked the refusal would
			// pass against an implementation that refused Clients everywhere
			// and made an authenticated gateway unrepresentable in a chain.
			assertAdmitted(t, AdmitChain(reg, fixtureOrg, ActorChain{fixtureAlice, k.want}, 3), fixtureAlice)
			assertDeny(t, AdmitChain(reg, fixtureOrg, ActorChain{k.want, fixtureAlice}, 3), ReasonSubjectTypeRejected)
		})
	}
}

// TestVerifyChainBoundsWorkBeforeVerifyingCredentials covers AXC-273.
//
// R3 measured this: 5,000 presented credentials against a depth bound of 4 made
// 5,000 revocation-oracle round trips before the bound refused. AdmitChain's own
// documentation says the bound exists because "an unbounded chain is an
// unbounded number of hops each of which the realm layer has to trust", and
// applying it only after the per-hop loop turned a correctness bound into
// something that no longer bounds work at all.
//
// It does not weaken the credentials-first ordering, which is about which
// refusal a chain of ADMISSIBLE LENGTH reports. A chain longer than the bound is
// refused whatever its credentials say.
func TestVerifyChainBoundsWorkBeforeVerifyingCredentials(t *testing.T) {
	MarkConformanceCase("AXC-273")

	reg := NewRealmRegistry()
	w := workspaceRealm()
	w.Revocation = RevocationSourceLocalStore
	if err := reg.Register(w); err != nil {
		t.Fatalf("register: %v", err)
	}

	const presented = 500
	creds := make([]Credential, presented)
	for i := range creds {
		c := workspaceCredential()
		c.Subject = fmt.Sprintf("00u%04d", i)
		c.RevocationKey = fmt.Sprintf("jti-%04d", i)
		creds[i] = c
	}

	oracle := &stubRealmRevocations{}
	_, _, adm := VerifyChain(reg, fixtureOrg, creds, 4, fixtureNow, oracle)

	assertDeny(t, adm, ReasonDelegationDepth)
	if oracle.calls != 0 {
		t.Fatalf("the revocation source was consulted %d time(s) for a chain the depth bound refuses; "+
			"the bound stops being a work limiter and an unauthenticated caller can amplify against it", oracle.calls)
	}
	if !strings.Contains(adm.Detail, "before any credential was verified") {
		t.Fatalf("the refusal does not record that no credential work was done: %s", adm)
	}

	// A chain WITHIN the bound still verifies every hop, so the early bound has
	// not turned into a blanket short-circuit.
	within := []Credential{workspaceCredential(), func() Credential {
		c := workspaceCredential()
		c.Subject = "00u456"
		c.RevocationKey = "jti-b"
		return c
	}()}
	within[0].RevocationKey = "jti-a"
	oracle.calls = 0
	_, _, adm = VerifyChain(reg, fixtureOrg, within, 4, fixtureNow, oracle)
	assertAdmitted(t, adm, fixtureAlice)
	if oracle.calls != 2 {
		t.Fatalf("an admissible chain made %d revocation checks, want one per hop", oracle.calls)
	}

	// A non-positive bound takes the default rather than becoming unbounded,
	// so the work limit cannot be switched off by omission.
	oracle.calls = 0
	tooLong := creds[:DefaultMaxDelegationDepth+1]
	_, _, adm = VerifyChain(reg, fixtureOrg, tooLong, 0, fixtureNow, oracle)
	assertDeny(t, adm, ReasonDelegationDepth)
	if oracle.calls != 0 {
		t.Fatalf("a zero bound did work before refusing: %d call(s)", oracle.calls)
	}
}
