// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// stubRealmRevocations is a RevocationOracle whose answer and error are set per
// test. A hand-rolled fake rather than a mocking library, matching the
// package's existing convention.
type stubRealmRevocations struct {
	revoked bool
	err     error
	calls   int
}

func (s *stubRealmRevocations) IsRevoked(string, RealmID, string) (bool, error) {
	s.calls++
	return s.revoked, s.err
}

// TestVerifyCredentialDeniesUndeclaredIssuer covers AXC-200 (EX-47).
//
// The credential here is fully valid in every way EXCEPT that its issuer has no
// declared realm: correct signature, accepted algorithm, right audience, in
// date, sufficient assurance. That is the point of the case. "Validly signed"
// is not "declared", and a directory that arrived with an acquisition is the
// ordinary way an undeclared issuer shows up with real credentials behind it.
//
// The mutant this test is written to kill is a falsy realm default: an
// implementation that, on a lookup miss, proceeds with a zero-valued
// TrustRealm. That realm reports HasGroupGraph false, so the closure is
// authoritatively empty, so every segment-scoped ceiling is skipped, and the
// request is PERMITTED with no error anywhere. Asserting only "not admitted"
// would not catch it, because such an implementation admits. So the assertions
// are on the exact reason code and on the principal being absent.
func TestVerifyCredentialDeniesUndeclaredIssuer(t *testing.T) {
	MarkConformanceCase("AXC-200")

	reg := fixtureRegistry(t)
	cred := workspaceCredential()
	cred.Issuer = issuerAcquired

	got := VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil)

	assertDeny(t, got.Admission, ReasonUnknownRealm)
	if !got.Admission.Principal.IsZero() {
		t.Fatalf("a denied credential produced a principal: %s", got.Admission.Principal)
	}
	if got.Realm.RealmID != "" {
		t.Fatalf("a denied credential produced a realm: %q", got.Realm.RealmID)
	}
	if !strings.Contains(got.Admission.Detail, issuerAcquired) {
		t.Fatalf("the refusal does not name the undeclared issuer: %s", got.Admission)
	}

	// The identical credential from the DECLARED issuer is admitted, so the
	// refusal above is attributable to the issuer alone.
	ok := VerifyCredential(reg, fixtureOrg, workspaceCredential(), fixtureNow, nil)
	assertAdmitted(t, ok.Admission, fixtureAlice)

	// A realm that exists but is disabled is REALM_DISABLED, not
	// UNKNOWN_REALM. The two need different remedies and an operator who
	// cannot tell them apart will go looking for a declaration that is
	// already there.
	disabled := workspaceRealm()
	disabled.Enabled = false
	disabled.Version = 2
	if err := reg.Register(disabled); err != nil {
		t.Fatalf("register: %v", err)
	}
	assertDeny(t, VerifyCredential(reg, fixtureOrg, workspaceCredential(), fixtureNow, nil).Admission, ReasonRealmDisabled)
}

// TestOrgBindingRefusesWrongButNonEmptyOrgClaim covers AXC-210.
//
// This is the #3488 acceptance criterion, and the specific wording matters: the
// claim is REFUSED, not silently narrowed to an organization-only evaluation.
//
// The behavior being replaced is the one that made #3488 hard to see. Segment
// resolution keyed on the subject organization from the claim; a wrong but
// non-empty organization returned zero directory rows; and zero rows is a
// SUCCESSFUL EMPTY resolution, indistinguishable from a genuine non-member. So
// a verified member of a targeted segment was evaluated organization-only, with
// no refusal, no audit row, and a metric that looked normal.
//
// The test therefore asserts more than "not admitted". It asserts that the
// outcome is a Deny with ORG_BINDING_MISMATCH and NOT an admitted subject with
// an empty closure, because the second is exactly what the defect produced and
// it is a state a weaker assertion would accept.
func TestOrgBindingRefusesWrongButNonEmptyOrgClaim(t *testing.T) {
	MarkConformanceCase("AXC-210")

	reg := fixtureRegistry(t)
	cred := workspaceCredential()
	cred.HasAssertedOrg = true
	cred.AssertedOrgID = fixtureOtherOrg

	got := VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil)

	assertDeny(t, got.Admission, ReasonOrgBindingMismatch)
	if got.Admission.State.IsAdmitted() {
		t.Fatalf("a credential asserting another organization was admitted")
	}
	if !got.Admission.Principal.IsZero() {
		t.Fatalf("a refused organization binding still produced a principal %s; "+
			"an admitted subject with an empty closure is the exact #3488 outcome this refuses", got.Admission.Principal)
	}
	if !strings.Contains(got.Admission.Detail, fixtureOtherOrg) {
		t.Fatalf("the refusal does not name the asserted organization: %s", got.Admission)
	}

	// A credential asserting the CORRECT organization is admitted, so the
	// refusal is about disagreement and not about carrying the claim at all.
	agreeing := workspaceCredential()
	agreeing.HasAssertedOrg = true
	agreeing.AssertedOrgID = fixtureOrg
	assertAdmitted(t, VerifyCredential(reg, fixtureOrg, agreeing, fixtureNow, nil).Admission, fixtureAlice)

	// And the realm itself is only reachable from its own organization, which
	// is the first of the two mechanisms: even without the claim check, a
	// credential cannot be verified under an organization whose registry does
	// not declare its issuer.
	assertDeny(t, VerifyCredential(reg, fixtureOtherOrg, workspaceCredential(), fixtureNow, nil).Admission, ReasonUnknownRealm)
}

// TestOrgBindingAcceptsAbsentOrgClaim covers AXC-211.
func TestOrgBindingAcceptsAbsentOrgClaim(t *testing.T) {
	MarkConformanceCase("AXC-211")

	reg := fixtureRegistry(t)
	cred := workspaceCredential()
	if cred.HasAssertedOrg {
		t.Fatalf("the fixture credential must not assert an organization for this case")
	}

	got := VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil)
	assertAdmitted(t, got.Admission, fixtureAlice)
	if got.Admission.Principal.Realm != realmWorkspace {
		t.Fatalf("the admitted principal is not realm-qualified to the verifying realm: %s", got.Admission.Principal)
	}
}

// TestOrgBindingDistinguishesEmptyClaimFromAbsentClaim covers AXC-212.
//
// A single string field cannot represent both "carries no organization claim"
// and "carries an empty one", and collapsing them picks one of two wrong
// answers: treat absent as empty and every ordinary credential is refused;
// treat empty as absent and a credential asserting the empty organization is
// admitted as though it had asserted nothing. HasAssertedOrg exists to keep
// them apart, and this test is what stops the field being dropped as
// redundant.
func TestOrgBindingDistinguishesEmptyClaimFromAbsentClaim(t *testing.T) {
	MarkConformanceCase("AXC-212")

	reg := fixtureRegistry(t)

	absent := workspaceCredential()
	absent.HasAssertedOrg = false
	absent.AssertedOrgID = ""
	assertAdmitted(t, VerifyCredential(reg, fixtureOrg, absent, fixtureNow, nil).Admission, fixtureAlice)

	empty := workspaceCredential()
	empty.HasAssertedOrg = true
	empty.AssertedOrgID = ""
	assertDeny(t, VerifyCredential(reg, fixtureOrg, empty, fixtureNow, nil).Admission, ReasonOrgBindingMismatch)
}

// TestVerifyCredentialRefusesWithoutAuthenticatedOrg covers AXC-213.
func TestVerifyCredentialRefusesWithoutAuthenticatedOrg(t *testing.T) {
	MarkConformanceCase("AXC-213")

	reg := fixtureRegistry(t)
	for _, org := range []string{"", "   "} {
		got := VerifyCredential(reg, org, workspaceCredential(), fixtureNow, nil)
		assertDeny(t, got.Admission, ReasonOrgBindingMismatch)
	}

	// A nil registry is Indeterminate rather than Deny: nothing about the
	// credential was found wanting, the plane simply could not answer.
	assertIndeterminate(t, VerifyCredential(nil, fixtureOrg, workspaceCredential(), fixtureNow, nil).Admission, ReasonUnknownRealm)
}

// TestVerifyCredentialRefusesUnverifiedSignature covers AXC-224.
func TestVerifyCredentialRefusesUnverifiedSignature(t *testing.T) {
	MarkConformanceCase("AXC-224")

	reg := fixtureRegistry(t)

	cred := workspaceCredential()
	cred.SignatureVerified = false
	assertDeny(t, VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil).Admission, ReasonSignatureNotVerified)

	// The zero Credential is the accidental version of the same thing: every
	// field unset, including the flag. It must refuse, and it must refuse on
	// the signature rather than reaching the issuer lookup with an empty
	// issuer string.
	assertDeny(t, VerifyCredential(reg, fixtureOrg, Credential{}, fixtureNow, nil).Admission, ReasonSignatureNotVerified)
}

// TestVerifyCredentialRejectsRealmPolicyViolations covers AXC-220.
//
// Every case starts from the admitted fixture credential and changes exactly
// one thing, so a reason code can only come from the field under test.
func TestVerifyCredentialRejectsRealmPolicyViolations(t *testing.T) {
	MarkConformanceCase("AXC-220")

	reg := fixtureRegistry(t)

	// The workspace realm pins an authorized party for the azp cases.
	pinned := workspaceRealm()
	pinned.AuthorizedPartyPolicy = AuthorizedPartyAllowList
	pinned.AuthorizedParties = []string{azpGateway}
	pinned.Version = 2
	if err := reg.Register(pinned); err != nil {
		t.Fatalf("register: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Credential)
		want   AdmissionReason
	}{
		{"unsupported algorithm", func(c *Credential) { c.Algorithm = "HS256" }, ReasonUnsupportedAlgorithm},
		{"algorithm none", func(c *Credential) { c.Algorithm = "none" }, ReasonUnsupportedAlgorithm},
		{"algorithm case folded", func(c *Credential) { c.Algorithm = "rs256" }, ReasonUnsupportedAlgorithm},
		{"unsupported credential type", func(c *Credential) { c.Type = CredentialSVID }, ReasonUnsupportedCredentialType},
		{"empty credential type", func(c *Credential) { c.Type = "" }, ReasonUnsupportedCredentialType},
		{"wrong audience", func(c *Credential) { c.Audiences = []string{"someone-else"} }, ReasonAudienceRejected},
		{"no audience", func(c *Credential) { c.Audiences = nil }, ReasonAudienceRejected},
		{"empty audience string", func(c *Credential) { c.Audiences = []string{""} }, ReasonAudienceRejected},
		{"wrong azp", func(c *Credential) { c.AuthorizedParty = "other-client" }, ReasonAuthorizedPartyRejected},
		{"absent azp against a pinning realm", func(c *Credential) { c.AuthorizedParty = "" }, ReasonAuthorizedPartyRejected},
		{"subject type the realm does not assert", func(c *Credential) { c.SubjectType = SubjectWorkload }, ReasonSubjectTypeRejected},
		{"unknown subject type", func(c *Credential) { c.SubjectType = "Robot" }, ReasonSubjectTypeRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred := workspaceCredential()
			cred.AuthorizedParty = azpGateway
			tc.mutate(&cred)
			assertDeny(t, VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil).Admission, tc.want)
		})
	}

	// The unmutated credential with the correct azp is admitted, so every
	// refusal above is attributable to its one change.
	good := workspaceCredential()
	good.AuthorizedParty = azpGateway
	assertAdmitted(t, VerifyCredential(reg, fixtureOrg, good, fixtureNow, nil).Admission, fixtureAlice)

	// A realm that does NOT pin azp ignores the credential's azp entirely,
	// including a populated one. Otherwise adding an azp to a token would
	// start failing against realms that never asked for it.
	unpinned := fixtureRegistry(t)
	withAzp := workspaceCredential()
	withAzp.AuthorizedParty = "any-client-at-all"
	assertAdmitted(t, VerifyCredential(unpinned, fixtureOrg, withAzp, fixtureNow, nil).Admission, fixtureAlice)
}

// TestVerifyCredentialTimeChecks covers AXC-221.
//
// The two cases worth naming are the ones where an absent claim could be read
// as permission. A credential with no expiry is not a credential that never
// expires, and a realm that bounds credential age cannot apply that bound to a
// credential carrying no issuance time, so both refuse rather than skip.
func TestVerifyCredentialTimeChecks(t *testing.T) {
	MarkConformanceCase("AXC-221")

	reg := fixtureRegistry(t)
	aged := workspaceRealm()
	aged.CredentialAgePolicy = CredentialAgeBounded
	aged.MaxCredentialAge = time.Hour
	aged.Version = 2
	if err := reg.Register(aged); err != nil {
		t.Fatalf("register: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Credential)
		want   AdmissionReason
	}{
		{"expired", func(c *Credential) { c.ExpiresAt = fixtureNow.Add(-time.Hour) }, ReasonCredentialExpired},
		{"no expiry at all", func(c *Credential) { c.ExpiresAt = time.Time{} }, ReasonCredentialExpired},
		{"not yet valid", func(c *Credential) { c.NotBefore = fixtureNow.Add(time.Hour) }, ReasonCredentialNotYetValid},
		{"issued in the future", func(c *Credential) { c.IssuedAt = fixtureNow.Add(time.Hour) }, ReasonCredentialNotYetValid},
		{"older than the realm bound", func(c *Credential) { c.IssuedAt = fixtureNow.Add(-2 * time.Hour) }, ReasonCredentialTooOld},
		{"no issuance time under an age bound", func(c *Credential) { c.IssuedAt = time.Time{} }, ReasonCredentialTooOld},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred := workspaceCredential()
			tc.mutate(&cred)
			assertDeny(t, VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil).Admission, tc.want)
		})
	}

	// Skew is applied outward in both directions, so a clock wrong by less
	// than the declared tolerance does not deny. The fixture realm declares
	// 30s; these sit 10s outside the window and inside the tolerance.
	justExpired := workspaceCredential()
	justExpired.ExpiresAt = fixtureNow.Add(-10 * time.Second)
	assertAdmitted(t, VerifyCredential(reg, fixtureOrg, justExpired, fixtureNow, nil).Admission, fixtureAlice)

	justEarly := workspaceCredential()
	justEarly.NotBefore = fixtureNow.Add(10 * time.Second)
	assertAdmitted(t, VerifyCredential(reg, fixtureOrg, justEarly, fixtureNow, nil).Admission, fixtureAlice)

	// And a credential outside the window by MORE than the tolerance denies,
	// so the tolerance is a bound rather than an amnesty.
	wellExpired := workspaceCredential()
	wellExpired.ExpiresAt = fixtureNow.Add(-31 * time.Second)
	assertDeny(t, VerifyCredential(reg, fixtureOrg, wellExpired, fixtureNow, nil).Admission, ReasonCredentialExpired)

	// A realm with no age bound admits an old-but-unexpired credential, so the
	// age refusals above come from the bound and not from age alone.
	noBound := fixtureRegistry(t)
	old := workspaceCredential()
	old.IssuedAt = fixtureNow.Add(-30 * 24 * time.Hour)
	assertAdmitted(t, VerifyCredential(noBound, fixtureOrg, old, fixtureNow, nil).Admission, fixtureAlice)
}

// TestVerifyCredentialAssurance covers AXC-222.
func TestVerifyCredentialAssurance(t *testing.T) {
	MarkConformanceCase("AXC-222")

	reg := fixtureRegistry(t)

	low := workspaceCredential()
	low.Assurance = AssuranceLow
	assertDeny(t, VerifyCredential(reg, fixtureOrg, low, fixtureNow, nil).Admission, ReasonAssuranceInsufficient)

	// The zero value is the one that matters: a credential attesting NOTHING
	// must not satisfy a floor. AssuranceUnspecified ranks below every
	// declared class precisely so that this is true without a special case.
	none := workspaceCredential()
	none.Assurance = AssuranceUnspecified
	assertDeny(t, VerifyCredential(reg, fixtureOrg, none, fixtureNow, nil).Admission, ReasonAssuranceInsufficient)

	// Higher than the floor is admitted, and the class is carried forward so a
	// specific action can require more than the realm's minimum.
	high := workspaceCredential()
	high.Assurance = AssuranceHigh
	got := VerifyCredential(reg, fixtureOrg, high, fixtureNow, nil)
	assertAdmitted(t, got.Admission, fixtureAlice)
	if got.Assurance != AssuranceHigh {
		t.Fatalf("the admitted subject's assurance was not carried forward: %s", got.Assurance)
	}

	// The non-human realm's floor is Low, so the same credential shape that
	// fails against the workspace realm passes there. The floor is per realm,
	// not global.
	assertAdmitted(t, VerifyCredential(reg, fixtureOrg, cloudIAMCredential(), fixtureNow, nil).Admission,
		MustParsePrincipalID("Workload::gcp-iam:spiffe://acme.example/workload/jira-bot"))
}

// TestVerifyCredentialRevocation covers AXC-223.
//
// The ordering assertion is the substance. Revocation is the only check that
// can return Indeterminate, so it runs LAST. If it ran earlier, a credential
// that is BOTH wrong-audience and unverifiable-for-revocation would report
// REVOCATION_UNAVAILABLE, an operator would chase a revocation outage, and the
// actual defect, a misconfigured client sending the wrong audience, would stay
// invisible for as long as the outage lasted.
func TestVerifyCredentialRevocation(t *testing.T) {
	MarkConformanceCase("AXC-223")

	reg := NewRealmRegistry()
	realm := workspaceRealm()
	realm.Revocation = RevocationSourceLocalStore
	if err := reg.Register(realm); err != nil {
		t.Fatalf("register: %v", err)
	}

	withKey := func() Credential {
		c := workspaceCredential()
		c.RevocationKey = "jti-1"
		return c
	}

	t.Run("revoked denies", func(t *testing.T) {
		oracle := &stubRealmRevocations{revoked: true}
		assertDeny(t, VerifyCredential(reg, fixtureOrg, withKey(), fixtureNow, oracle).Admission, ReasonCredentialRevoked)
	})

	t.Run("oracle error is indeterminate", func(t *testing.T) {
		oracle := &stubRealmRevocations{err: errors.New("store unreachable")}
		assertIndeterminate(t, VerifyCredential(reg, fixtureOrg, withKey(), fixtureNow, oracle).Admission, ReasonRevocationUnavailable)
	})

	t.Run("missing oracle is indeterminate, never a pass", func(t *testing.T) {
		assertIndeterminate(t, VerifyCredential(reg, fixtureOrg, withKey(), fixtureNow, nil).Admission, ReasonRevocationUnavailable)
	})

	t.Run("no revocation key is indeterminate", func(t *testing.T) {
		oracle := &stubRealmRevocations{}
		assertIndeterminate(t, VerifyCredential(reg, fixtureOrg, workspaceCredential(), fixtureNow, oracle).Admission, ReasonRevocationUnavailable)
	})

	t.Run("not revoked admits", func(t *testing.T) {
		oracle := &stubRealmRevocations{}
		assertAdmitted(t, VerifyCredential(reg, fixtureOrg, withKey(), fixtureNow, oracle).Admission, fixtureAlice)
	})

	t.Run("a determinate refusal wins over a revocation outage", func(t *testing.T) {
		oracle := &stubRealmRevocations{err: errors.New("store unreachable")}
		cred := withKey()
		cred.Audiences = []string{"someone-else"}
		got := VerifyCredential(reg, fixtureOrg, cred, fixtureNow, oracle)
		assertDeny(t, got.Admission, ReasonAudienceRejected)
		if oracle.calls != 0 {
			t.Fatalf("the revocation source was consulted for a credential already refused on its audience (%d call(s)); "+
				"an outage would then mask the real defect", oracle.calls)
		}
	})

	t.Run("a realm declaring no revocation source never reports an outage", func(t *testing.T) {
		none := fixtureRegistry(t)
		assertAdmitted(t, VerifyCredential(none, fixtureOrg, workspaceCredential(), fixtureNow, nil).Admission, fixtureAlice)
	})
}

// TestSubjectMissingIsNotFilledFromAnAlias covers AXC-225.
//
// The credential here carries an email and no subject. The failure being
// prevented is the natural one: falling back to the email because it is right
// there and non-empty. That fallback is how an email becomes an identifier, and
// two directories asserting the same address then become one subject.
func TestSubjectMissingIsNotFilledFromAnAlias(t *testing.T) {
	MarkConformanceCase("AXC-225")

	reg := fixtureRegistry(t)

	for _, subject := range []string{"", "   "} {
		cred := workspaceCredential()
		cred.Subject = subject
		cred.Aliases = map[AliasKind]string{AliasEmail: "alice@acme.example"}

		got := VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil)
		assertDeny(t, got.Admission, ReasonSubjectMissing)
		if !got.Admission.Principal.IsZero() {
			t.Fatalf("a credential with no subject produced principal %s", got.Admission.Principal)
		}
		if strings.Contains(got.Admission.Principal.Subject, "@") {
			t.Fatalf("the email was used as the canonical subject")
		}
	}

	// An admitted credential records its aliases WITH provenance, bound to the
	// canonical principal. The direction is what matters: the alias names the
	// principal, and no map from an alias back to a principal exists.
	got := VerifyCredential(reg, fixtureOrg, workspaceCredential(), fixtureNow, nil)
	assertAdmitted(t, got.Admission, fixtureAlice)
	if len(got.Aliases) != 1 {
		t.Fatalf("want exactly the one declared alias, got %d: %v", len(got.Aliases), got.Aliases)
	}
	alias := got.Aliases[0]
	if alias.Kind != AliasEmail || alias.Value != "alice@acme.example" {
		t.Fatalf("unexpected alias: %+v", alias)
	}
	if alias.Principal != fixtureAlice {
		t.Fatalf("the alias is bound to %s rather than the canonical principal", alias.Principal)
	}
	if alias.Provenance != ProvenanceAuthentication {
		t.Fatalf("the alias carries provenance %q rather than authentication", alias.Provenance)
	}
	if alias.SourceVersion == "" {
		t.Fatalf("the alias carries no source version, so a stale binding would be undetectable")
	}

	// An alias the realm never mapped is NOT carried. Carrying it would let a
	// credential introduce an attribute the operator did not ask AxonFlow to
	// hold, and an uninvited attribute is an uninvited policy input.
	extra := workspaceCredential()
	extra.Aliases = map[AliasKind]string{
		AliasEmail:              "alice@acme.example",
		AliasConnectorAccountID: "acct-999",
	}
	withExtra := VerifyCredential(reg, fixtureOrg, extra, fixtureNow, nil)
	for _, a := range withExtra.Aliases {
		if a.Kind == AliasConnectorAccountID {
			t.Fatalf("an alias the realm never mapped was carried: %+v", a)
		}
	}
}

// TestInconsistentOrgAssertionIsRefused covers AXC-272.
//
// R3 found that HasAssertedOrg was a falsy default that SKIPPED the #3488
// check, which is the opposite of every other flag in Credential. The doc
// claimed "every field that could carry a permissive meaning has a zero value
// that is refused": SignatureVerified false refuses, HasAssertedOrg false
// skipped, and AssertedOrgID was then read by nothing.
//
// The consequence is exactly the historical defect, reinstated by an adapter
// that populates the string and forgets the companion bool. No later check
// could see it, because after the skip the field is never read again.
//
// The flag cannot simply be deleted in favour of a non-empty string: it is what
// separates "carries no organization claim" from "carries an empty one", which
// AXC-212 pins. So the two are required to AGREE instead.
func TestInconsistentOrgAssertionIsRefused(t *testing.T) {
	MarkConformanceCase("AXC-272")

	reg := fixtureRegistry(t)

	forgotten := workspaceCredential()
	forgotten.AssertedOrgID = "org-attacker"
	forgotten.HasAssertedOrg = false

	got := VerifyCredential(reg, fixtureOrg, forgotten, fixtureNow, nil)
	assertDeny(t, got.Admission, ReasonOrgBindingMismatch)
	if got.Admission.State.IsAdmitted() {
		t.Fatalf("a credential carrying a wrong organization with the flag unset was admitted; this is #3488 reinstated by an adapter bug")
	}
	if !strings.Contains(got.Admission.Detail, "org-attacker") {
		t.Fatalf("the refusal does not name the inconsistent value: %s", got.Admission)
	}

	// Setting the flag on the same value gives the ordinary mismatch refusal,
	// so the new check is about the inconsistency and not about the value.
	forgotten.HasAssertedOrg = true
	assertDeny(t, VerifyCredential(reg, fixtureOrg, forgotten, fixtureNow, nil).Admission, ReasonOrgBindingMismatch)

	// And the two consistent shapes still behave as AXC-211 and AXC-212 pin
	// them, so the check has not made an ordinary credential unusable.
	absent := workspaceCredential()
	assertAdmitted(t, VerifyCredential(reg, fixtureOrg, absent, fixtureNow, nil).Admission, fixtureAlice)

	agreeing := workspaceCredential()
	agreeing.HasAssertedOrg = true
	agreeing.AssertedOrgID = fixtureOrg
	assertAdmitted(t, VerifyCredential(reg, fixtureOrg, agreeing, fixtureNow, nil).Admission, fixtureAlice)
}

// TestAnOrderedEnumIsCheckedForMembershipBeforeItIsCompared covers AXC-279.
//
// AssuranceClass is the only ORDERED enum in this plane, and ordering is what
// makes it different from the other eight. The realm's minimum is validated at
// registration; the credential's class is not, and it is compared with `<`, so
// an out-of-range value satisfies every floor by ordinary integer comparison.
// AssuranceClass(99) passed a realm requiring high assurance.
//
// The zero value was carefully arranged to rank BELOW every declared class, so
// a credential attesting nothing fails every floor. That arrangement says
// nothing whatever about the other end of the range, and only one end was ever
// looked at.
//
// The general rule, which is why this test is written as a sweep over both ends
// rather than as one case: a membership check on a value used only for EQUALITY
// can be deferred to whoever writes it, because an unrecognized value simply
// matches nothing. A value used for ORDERING cannot, because the comparison
// itself is what turns an unrecognized value into a permissive answer.
func TestAnOrderedEnumIsCheckedForMembershipBeforeItIsCompared(t *testing.T) {
	MarkConformanceCase("AXC-279")

	reg := fixtureRegistry(t)
	if workspaceRealm().MinimumAssurance != AssuranceSubstantial {
		t.Fatalf("the fixture realm must declare a mid-range floor for this test to exercise both ends")
	}

	// Above the declared range: the end nobody looked at.
	for _, above := range []AssuranceClass{AssuranceHigh + 1, 99, 1 << 30} {
		cred := workspaceCredential()
		cred.Assurance = above
		got := VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil)
		if got.Admission.State.IsAdmitted() {
			t.Fatalf("assurance %d satisfied a realm requiring %s by ordinary comparison", int(above), AssuranceSubstantial)
		}
		assertDeny(t, got.Admission, ReasonAssuranceInsufficient)
	}

	// Below it, which already worked and must keep working: a credential
	// attesting nothing fails every floor.
	below := workspaceCredential()
	below.Assurance = AssuranceUnspecified
	assertDeny(t, VerifyCredential(reg, fixtureOrg, below, fixtureNow, nil).Admission, ReasonAssuranceInsufficient)

	// Negative, which an int-backed enum can hold and which would sort below
	// the zero value rather than above the top.
	negative := workspaceCredential()
	negative.Assurance = AssuranceClass(-1)
	assertDeny(t, VerifyCredential(reg, fixtureOrg, negative, fixtureNow, nil).Admission, ReasonAssuranceInsufficient)

	// Every DECLARED class at or above the floor is still admitted, so the
	// membership check refuses only what it should. Without this the test would
	// pass against an implementation that refused every credential.
	for _, ok := range []AssuranceClass{AssuranceSubstantial, AssuranceHigh} {
		cred := workspaceCredential()
		cred.Assurance = ok
		assertAdmitted(t, VerifyCredential(reg, fixtureOrg, cred, fixtureNow, nil).Admission, fixtureAlice)
	}

	// And the ordering itself is intact: the declared classes rank in the
	// documented direction. A membership check that also broke the order would
	// pass every assertion above.
	if !(AssuranceUnspecified < AssuranceLow && AssuranceLow < AssuranceSubstantial && AssuranceSubstantial < AssuranceHigh) {
		t.Fatalf("the assurance ordering is not monotonic")
	}
}
