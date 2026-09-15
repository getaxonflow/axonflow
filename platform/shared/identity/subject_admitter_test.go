// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Subject admission (ADR-065 invariant 2; PRD v11 §1.6): a credential is
// verified against its organization's trust realms and the subject it names is
// admitted, or refused with a reason. These tests drive a real SubjectAdmitter
// over the built-in realms, through the same CredentialPrincipal builders the
// agent's authentication paths use.

// --- test doubles ---

// failingRealmSource reports an outage.
type failingRealmSource struct{ err error }

func (s failingRealmSource) EnsureRealms(context.Context, string) error { return s.err }

// countingRealmSource records how many times it was asked.
type countingRealmSource struct {
	inner RealmSource
	calls int
}

func (s *countingRealmSource) EnsureRealms(ctx context.Context, orgID string) error {
	s.calls++
	return s.inner.EnsureRealms(ctx, orgID)
}

// staticRevocations answers from a fixed set of revoked keys.
type staticRevocations struct {
	revoked map[string]bool
	err     error
}

func (s staticRevocations) IsRevoked(_ string, _ RealmID, key string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.revoked[key], nil
}

// admitterFixture builds a subject admitter over the built-in realms, on the
// fixture clock.
func admitterFixture(t *testing.T, dep BuiltinRealmDeployment, opts ...SubjectAdmitterOption) (*SubjectAdmitter, *RealmRegistry) {
	t.Helper()
	reg := NewRealmRegistry()
	src, err := NewBuiltinRealmSource(reg, dep)
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	opts = append([]SubjectAdmitterOption{WithAdmitterClock(func() time.Time { return fixtureNow })}, opts...)
	a, err := NewSubjectAdmitter(reg, src, opts...)
	if err != nil {
		t.Fatalf("NewSubjectAdmitter: %v", err)
	}
	return a, reg
}

// admitUser admits in through the user door, AdmitDecisionSubject.
func admitUser(a *SubjectAdmitter, in CredentialPrincipal) Admission {
	_, adm := a.AdmitDecisionSubject(context.Background(), in, DefaultMaxDelegationDepth)
	return adm
}

// admitClient admits in through the credential door, AdmitCredentialSubject.
func admitClient(a *SubjectAdmitter, in CredentialPrincipal) Admission {
	_, adm := a.AdmitCredentialSubject(context.Background(), in, DefaultMaxDelegationDepth)
	return adm
}

// mintedClaims builds a well-formed AxonFlow-minted HS256 claim set: the happy
// path every unhappy case below is one field away from.
func mintedClaims() map[string]any {
	return map[string]any{
		"iss":    UserTokenIssuer,
		"sub":    "user-1138",
		"email":  "dev@corp.example",
		"jti":    "jti-1",
		"org_id": fixtureOrg,
		"iat":    float64(fixtureNow.Add(-time.Minute).Unix()),
		"exp":    float64(fixtureNow.Add(time.Hour).Unix()),
	}
}

// --- the subject ---

// TestTheSubjectComesFromTheClaimMapping is ADR-065 invariant 3 at the
// admission boundary: the canonical subject is the claim the REALM named, and
// an email is not substituted for it.
func TestTheSubjectComesFromTheClaimMapping(t *testing.T) {
	a, _ := admitterFixture(t, BuiltinRealmDeployment{})
	claims := mintedClaims()
	delete(claims, "sub")

	adm := admitUser(a, HS256Principal(fixtureOrg, claims, true, ""))
	if adm.Reason != ReasonSubjectMissing {
		t.Fatalf("a token with no subject claim: reason = %s, want %s", adm.Reason, ReasonSubjectMissing)
	}
	if strings.Contains(adm.Detail, "dev@corp.example") {
		t.Fatalf("the refusal detail leaked the email that was NOT substituted for the subject")
	}
}

// TestATrustedHeaderNeedsASubjectNotAnAlias: an upstream asserting only an
// address has asserted an alias, not an identity.
func TestATrustedHeaderNeedsASubjectNotAnAlias(t *testing.T) {
	a, _ := admitterFixture(t, BuiltinRealmDeployment{})

	t.Run("email only is SUBJECT_MISSING", func(t *testing.T) {
		adm := admitUser(a, TrustedHeaderPrincipal(fixtureOrg, "", "dev@corp.example", true, fixtureNow))
		if adm.Reason != ReasonSubjectMissing {
			t.Fatalf("reason = %s, want %s", adm.Reason, ReasonSubjectMissing)
		}
	})

	t.Run("a stable user id is admitted, with the email as an alias", func(t *testing.T) {
		in := TrustedHeaderPrincipal(fixtureOrg, "u-42", "dev@corp.example", true, fixtureNow)
		adm := admitUser(a, in)
		if !adm.State.IsAdmitted() {
			t.Fatalf("admission = %s %s (%s)", adm.State, adm.Reason, adm.Detail)
		}
		if adm.Principal.Subject != "u-42" {
			t.Fatalf("canonical subject = %q, want the asserted user id", adm.Principal.Subject)
		}
		// The email reaches verification as an alias of the credential, never
		// as its subject.
		prep := a.prepareCredential(context.Background(), in)
		if prep.refusal != nil {
			t.Fatalf("preparation refused: %s", *prep.refusal)
		}
		if prep.cred.Subject != "u-42" || prep.cred.Aliases[AliasEmail] != "dev@corp.example" {
			t.Fatalf("completed credential = subject %q aliases %v, want subject u-42 with the email as an alias",
				prep.cred.Subject, prep.cred.Aliases)
		}
	})

	t.Run("nothing asserted at all is not admitted", func(t *testing.T) {
		if adm := admitUser(a, TrustedHeaderPrincipal(fixtureOrg, "", "", false, fixtureNow)); adm.State.IsAdmitted() {
			t.Fatalf("an empty header assertion was admitted")
		}
	})
}

// --- the realm ---

// TestAnUndeclaredIssuerIsUnknownRealm is EX-47: a validly signed token whose
// issuer no realm declares is refused UNKNOWN_REALM, and the refusal's detail
// names the issuer, which is what an operator needs to declare the realm or
// reject the token.
func TestAnUndeclaredIssuerIsUnknownRealm(t *testing.T) {
	for name, iss := range map[string]any{
		"an issuer no realm declares": issuerAcquired,
		"no issuer claim at all":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			a, _ := admitterFixture(t, BuiltinRealmDeployment{})
			claims := mintedClaims()
			if iss == nil {
				delete(claims, "iss")
			} else {
				claims["iss"] = iss
			}
			adm := admitUser(a, HS256Principal(fixtureOrg, claims, true, ""))
			if adm.State != AdmissionDeny || adm.Reason != ReasonUnknownRealm {
				t.Fatalf("admission = %s %s, want a Deny for %s", adm.State, adm.Reason, ReasonUnknownRealm)
			}
			if iss != nil && !strings.Contains(adm.Detail, issuerAcquired) {
				t.Fatalf("the refusal detail does not name the undeclared issuer: %q", adm.Detail)
			}
		})
	}
}

// TestAWrongOrgClaimIsRefused is #3488 / #3556: the org claim is bound to the
// credential that authenticated, and a disagreement is refused rather than
// narrowed to an organization-only evaluation.
//
// The three refused cases are the three shapes an org claim can take, and the
// last two are the ones a happy-path-only test misses.
func TestAWrongOrgClaimIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(map[string]any)
		wantReason AdmissionReason
		wantAdmit  bool
	}{
		{name: "an org claim naming another organization", mutate: func(c map[string]any) { c["org_id"] = fixtureOtherOrg }, wantReason: ReasonOrgBindingMismatch},
		{name: "an org claim present but empty", mutate: func(c map[string]any) { c["org_id"] = "" }, wantReason: ReasonOrgBindingMismatch},
		{name: "an org claim delivered as a number, which is not a string this plane can key on", mutate: func(c map[string]any) { c["org_id"] = float64(42) }, wantReason: ReasonOrgBindingMismatch},
		{name: "NO org claim at all is bound by construction and admitted", mutate: func(c map[string]any) { delete(c, "org_id") }, wantAdmit: true},
		{name: "the matching org claim is admitted", mutate: func(c map[string]any) { c["org_id"] = fixtureOrg }, wantAdmit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := admitterFixture(t, BuiltinRealmDeployment{})
			claims := mintedClaims()
			tc.mutate(claims)
			adm := admitUser(a, HS256Principal(fixtureOrg, claims, true, ""))
			if tc.wantAdmit {
				if !adm.State.IsAdmitted() {
					t.Fatalf("admission = %s %s (%s)", adm.State, adm.Reason, adm.Detail)
				}
				return
			}
			if adm.State.IsAdmitted() || adm.Reason != tc.wantReason {
				t.Fatalf("admission = %s %s, want a refusal for %s", adm.State, adm.Reason, tc.wantReason)
			}
		})
	}
}

// TestMalformedAudienceIsRefusedNotDefaulted: a malformed aud must not fall
// back to the deployment audience, which would admit it.
func TestMalformedAudienceIsRefusedNotDefaulted(t *testing.T) {
	a, _ := admitterFixture(t, BuiltinRealmDeployment{})
	claims := mintedClaims()
	claims["aud"] = 7
	if adm := admitUser(a, HS256Principal(fixtureOrg, claims, true, "")); adm.Reason != ReasonAudienceRejected {
		t.Fatalf("reason = %s, want %s", adm.Reason, ReasonAudienceRejected)
	}
}

// --- revocation ---

// TestAnUnrevocableTokenIsIndeterminate: a realm that declares a revocation
// source and a credential that carries no revocation key cannot be checked,
// and "cannot be checked" is not "not revoked".
func TestAnUnrevocableTokenIsIndeterminate(t *testing.T) {
	a, _ := admitterFixture(t, BuiltinRealmDeployment{HasRevocation: true}, WithAdmitterRevocations(staticRevocations{}))
	claims := mintedClaims()
	delete(claims, "jti")
	adm := admitUser(a, HS256Principal(fixtureOrg, claims, true, ""))
	if adm.State != AdmissionIndeterminate || adm.Reason != ReasonRevocationUnavailable {
		t.Fatalf("admission = %s %s, want Indeterminate %s", adm.State, adm.Reason, ReasonRevocationUnavailable)
	}
}

// TestARevocationOutageIsIndeterminateNotClear pins the direction: an oracle
// that errors must never read as "not revoked".
func TestARevocationOutageIsIndeterminateNotClear(t *testing.T) {
	a, _ := admitterFixture(t, BuiltinRealmDeployment{HasRevocation: true},
		WithAdmitterRevocations(staticRevocations{err: errors.New("deny-list unreachable")}))
	if adm := admitUser(a, HS256Principal(fixtureOrg, mintedClaims(), true, "")); adm.State != AdmissionIndeterminate {
		t.Fatalf("a revocation outage produced %s, want INDETERMINATE", adm.State)
	}
}

// --- what admission never does ---

// TestAPathRejectionIsNeverAdmitted is the one-direction invariant: admission
// has no route by which a credential the path rejected becomes an admitted
// subject, and the refusal says the signature did not verify.
func TestAPathRejectionIsNeverAdmitted(t *testing.T) {
	a, _ := admitterFixture(t, BuiltinRealmDeployment{})
	// A claim set that would otherwise pass every realm check.
	adm := admitUser(a, HS256Principal(fixtureOrg, mintedClaims(), false, ""))
	if adm.State.IsAdmitted() {
		t.Fatalf("a credential the path rejected was ADMITTED as %v", adm.Principal)
	}
	if adm.Reason != ReasonSignatureNotVerified {
		t.Fatalf("reason = %s, want %s", adm.Reason, ReasonSignatureNotVerified)
	}
}

// TestAMalformedCredentialPrincipalIsIndeterminate: a CredentialPrincipal the
// call site built wrongly is a defect of that code, not a fact about the
// caller's credential, so admission answers Indeterminate
// IDENTITY_INTERNAL_ERROR - the enforcing plane fails closed - rather than a
// Deny that would name a token that is fine.
func TestAMalformedCredentialPrincipalIsIndeterminate(t *testing.T) {
	base := func() CredentialPrincipal { return HS256Principal(fixtureOrg, mintedClaims(), true, "") }
	for _, tc := range []struct {
		name   string
		mutate func(*CredentialPrincipal)
		// detail is the guard's own wording. Asserting it, and not only the
		// reason, is what makes each case pass through its own guard: without
		// the organization guard, an empty organization still ends
		// Indeterminate IDENTITY_INTERNAL_ERROR further down the pipeline.
		detail string
	}{
		{"an undeclared path", func(in *CredentialPrincipal) { in.Path = CredentialPath("smtp") }, "is not one of the declared paths"},
		{"a path decision left at its zero value", func(in *CredentialPrincipal) { in.Decision = PathVerdictUnspecified }, "is not one of the declared decisions"},
		{"an out-of-range path decision", func(in *CredentialPrincipal) { in.Decision = PathVerdict(99) }, "is not one of the declared decisions"},
		{"no authenticated organization", func(in *CredentialPrincipal) { in.AuthenticatedOrgID = " " }, "passed no authenticated organization"},
		{"a nil claim set", func(in *CredentialPrincipal) { in.Claims = nil }, "presented no claim set"},
		{"a caller-supplied canonical subject", func(in *CredentialPrincipal) { in.Credential.Subject = "smuggled" }, "supplied a canonical subject"},
		{"an unverifiable reason outside the allow-list", func(in *CredentialPrincipal) {
			in.Decision = PathVerdictRejected
			in.UnverifiableReason = ReasonUnknownRealm
		}, "is not one of the reasons a path may report"},
		{"an unverifiable reason on an ACCEPTED credential", func(in *CredentialPrincipal) {
			in.UnverifiableReason = ReasonKeyMaterialUnavailable
		}, "a path that could not reach a verdict did not accept the credential"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := admitterFixture(t, BuiltinRealmDeployment{})
			in := base()
			tc.mutate(&in)
			if adm := admitUser(a, in); adm.State != AdmissionIndeterminate || adm.Reason != ReasonIdentityInternalError || !strings.Contains(adm.Detail, tc.detail) {
				t.Fatalf("admission = %s %s (%s), want Indeterminate %s naming %q", adm.State, adm.Reason, adm.Detail, ReasonIdentityInternalError, tc.detail)
			}
		})
	}
}

// TestAnUnverifiableReasonShortCircuits: a path that could not reach a verdict
// is reported as the outage it was, never run through realm verification to
// come back as an unverified signature, which is the wording for a forgery.
func TestAnUnverifiableReasonShortCircuits(t *testing.T) {
	for _, reason := range []AdmissionReason{ReasonKeyMaterialUnavailable, ReasonRevocationUnavailable} {
		t.Run(string(reason), func(t *testing.T) {
			a, _ := admitterFixture(t, BuiltinRealmDeployment{})
			adm := admitUser(a, OIDCPrincipal(fixtureOrg, nil, false, reason))
			if adm.State != AdmissionIndeterminate || adm.Reason != reason {
				t.Fatalf("admission = %s %s, want Indeterminate %s", adm.State, adm.Reason, reason)
			}
		})
	}
}

// --- realm-source outages ---

// TestARealmOutageIsIndeterminateNotUnknownRealm: a realm source that cannot
// answer must not present as an organization with no realms, which would send
// an operator to declare a realm that already exists.
func TestARealmOutageIsIndeterminateNotUnknownRealm(t *testing.T) {
	a, err := NewSubjectAdmitter(NewRealmRegistry(), failingRealmSource{err: errors.New("realm store unreachable")},
		WithAdmitterClock(func() time.Time { return fixtureNow }))
	if err != nil {
		t.Fatalf("NewSubjectAdmitter: %v", err)
	}
	adm := admitUser(a, HS256Principal(fixtureOrg, mintedClaims(), true, ""))
	if adm.State != AdmissionIndeterminate {
		t.Fatalf("state = %s, want INDETERMINATE", adm.State)
	}
	if adm.Reason == ReasonUnknownRealm {
		t.Fatalf("a realm-source outage was reported as UNKNOWN_REALM")
	}
}

// TestARealmSourceFailureDoesNotRefuseADeclaredIssuer: a realm source is a
// CHAIN. The built-ins register once and never fail again; the tenant OIDC
// source reads a database row and can fail for reasons that have nothing to do
// with the credential in hand. One unreadable sso_configurations row must not
// refuse the client credential, the internal-service hop and the HS256 token,
// none of which involves OIDC.
func TestARealmSourceFailureDoesNotRefuseADeclaredIssuer(t *testing.T) {
	reg := NewRealmRegistry()
	builtins, err := NewBuiltinRealmSource(reg, BuiltinRealmDeployment{},
		failingRealmSource{err: errors.New("the tenant OIDC row will not parse")})
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	a, err := NewSubjectAdmitter(reg, builtins, WithAdmitterClock(func() time.Time { return fixtureNow }))
	if err != nil {
		t.Fatalf("NewSubjectAdmitter: %v", err)
	}

	// The built-in minted realm IS registered (the extras run after them), so
	// this credential's issuer resolves even though the chain reported a
	// failure.
	if adm := admitUser(a, HS256Principal(fixtureOrg, mintedClaims(), true, "")); !adm.State.IsAdmitted() {
		t.Fatalf("a credential whose realm IS declared was refused because another source in the chain failed: %s %s (%s)",
			adm.State, adm.Reason, adm.Detail)
	}

	// The control: a credential whose issuer does NOT resolve stays
	// Indeterminate, because a failed source and an undeclared issuer cannot
	// be told apart.
	claims := mintedClaims()
	claims["iss"] = issuerAcquired
	miss := admitUser(a, HS256Principal(fixtureOrg, claims, true, ""))
	if miss.State != AdmissionIndeterminate {
		t.Fatalf("an undeclared issuer under a failed realm source: state = %s, want INDETERMINATE", miss.State)
	}
	if miss.Reason == ReasonUnknownRealm {
		t.Fatalf("a realm-source outage was reported as UNKNOWN_REALM")
	}
}

// TestBuiltinRealmsAreRegisteredOnce pins the memoization: the version-must-
// advance rule in the registry means a second registration of the same
// built-ins would fail, so the source must not attempt one.
func TestBuiltinRealmsAreRegisteredOnce(t *testing.T) {
	reg := NewRealmRegistry()
	inner, err := NewBuiltinRealmSource(reg, BuiltinRealmDeployment{})
	if err != nil {
		t.Fatalf("NewBuiltinRealmSource: %v", err)
	}
	src := &countingRealmSource{inner: inner}
	a, err := NewSubjectAdmitter(reg, src, WithAdmitterClock(func() time.Time { return fixtureNow }))
	if err != nil {
		t.Fatalf("NewSubjectAdmitter: %v", err)
	}

	for i := 0; i < 3; i++ {
		if adm := admitUser(a, HS256Principal(fixtureOrg, mintedClaims(), true, "")); !adm.State.IsAdmitted() {
			t.Fatalf("call %d: %s %s (%s)", i, adm.State, adm.Reason, adm.Detail)
		}
	}
	if src.calls != 3 {
		t.Fatalf("the realm source was consulted %d times, want once per request", src.calls)
	}
	epoch := reg.Epoch()
	if _, ok := reg.Lookup(fixtureOrg, BuiltinRealmMinted); !ok {
		t.Fatalf("the minted realm was not registered")
	}
	// A fourth request must not mutate the registry.
	admitUser(a, HS256Principal(fixtureOrg, mintedClaims(), true, ""))
	if reg.Epoch() != epoch {
		t.Fatalf("the registry epoch advanced on a repeat request: realms are being re-registered")
	}
}

// TestBuiltinRealmsAreOrgScoped: one organization's built-ins never answer for
// another's.
func TestBuiltinRealmsAreOrgScoped(t *testing.T) {
	a, reg := admitterFixture(t, BuiltinRealmDeployment{})
	admitUser(a, HS256Principal(fixtureOrg, mintedClaims(), true, ""))
	if _, ok := reg.LookupByIssuer(fixtureOtherOrg, UserTokenIssuer); ok {
		t.Fatalf("one organization's built-in realm resolved for another")
	}
}

// --- the live-verification window ---

// TestLiveVerifiedCredentialsExpire: an API credential has no expiry of its
// own, and the synthesized window can only ever NARROW what is admissible.
func TestLiveVerifiedCredentialsExpire(t *testing.T) {
	verifiedAt := fixtureNow.Add(-2 * LiveVerificationWindow)
	a, _ := admitterFixture(t, BuiltinRealmDeployment{})

	stale := admitClient(a, APICredentialPrincipal(fixtureOrg, "client-1", VerificationAPICredential, true, verifiedAt))
	if stale.Reason != ReasonCredentialExpired {
		t.Fatalf("a verification two windows old: reason = %s, want %s", stale.Reason, ReasonCredentialExpired)
	}
	fresh := admitClient(a, APICredentialPrincipal(fixtureOrg, "client-1", VerificationAPICredential, true, fixtureNow))
	if !fresh.State.IsAdmitted() {
		t.Fatalf("a fresh verification was refused: %s %s", fresh.Reason, fresh.Detail)
	}
	if fresh.Principal.Type != SubjectClient {
		t.Fatalf("an API credential produced a %s principal", fresh.Principal.Type)
	}
}
