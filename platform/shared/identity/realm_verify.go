// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 realm verification and organization binding (#3556).
//
// # WHAT THIS LAYER DOES AND DOES NOT DO
//
// It does NOT verify a signature. Signature verification, JWKS handling, and
// SSRF protection stay with the existing validators (hs256_validator.go,
// oidc_verifier.go). This layer takes an ALREADY cryptographically verified
// credential and applies realm policy to it: is this issuer declared, is this
// organization the one that authenticated, is this credential class, algorithm,
// audience, authorized party, age, and assurance acceptable to the realm, and
// what canonical principal do its claims map to.
//
// The split matters because EX-47's whole point is that those are different
// questions. A validly signed token is not a declared one.
//
// # ORDER IS PART OF THE CONTRACT
//
// The checks below run in a fixed order and the order is load-bearing twice:
//
//   - Realm lookup is FIRST, so realm(p) is never undefined for any later
//     step. Every later check reads realm configuration; running any of them
//     before the lookup would mean reading a zero-valued TrustRealm.
//   - Revocation is LAST, because it is the only check that can return
//     Indeterminate. Running it earlier would let a revocation-source outage
//     mask a determinate refusal, turning a clear "wrong audience" into an
//     ambiguous "cannot tell", and an operator would chase the outage instead
//     of the misconfigured client.
package identity

import (
	"fmt"
	"strings"
	"time"
)

// Credential is a cryptographically verified credential, decomposed into the
// facts realm policy is expressed over.
//
// Every field that could carry a permissive meaning has a zero value that is
// refused: SignatureVerified false is a refusal, an empty Audiences set cannot
// intersect a realm's non-empty audience list, AssuranceUnspecified is below
// every declared minimum, and a zero ExpiresAt is treated as "declares no
// expiry" rather than "never expires".
type Credential struct {
	// Issuer is the credential's issuer, exactly as presented. It is matched
	// against a realm's canonical issuer by exact string equality: no
	// normalization, no trailing-slash tolerance, no case folding. An issuer
	// that does not match exactly is an issuer AxonFlow was not told about.
	Issuer string
	// Type is the credential class.
	Type CredentialType
	// Algorithm is the signing algorithm the verifier actually used.
	Algorithm string
	// SignatureVerified records that the signature was checked and passed.
	SignatureVerified bool
	// Audiences is the credential's audience set.
	Audiences []string
	// AuthorizedParty is the credential's azp, empty if it carries none.
	AuthorizedParty string
	// Subject is the value of the realm's declared subject claim.
	Subject string
	// SubjectType optionally overrides the realm's default subject type, for
	// realms that assert more than one kind. Empty means use the realm's
	// claim-mapping default.
	SubjectType SubjectType
	// AssertedOrgID is an organization the credential claims to be about.
	AssertedOrgID string
	// HasAssertedOrg distinguishes "carries no organization claim" from
	// "carries an empty one". They are different facts and only one of them is
	// a malformed credential, so a bare string cannot represent both.
	HasAssertedOrg bool
	// Assurance is the authentication assurance the issuer attests.
	Assurance AssuranceClass
	// IssuedAt, NotBefore and ExpiresAt are the credential's time claims. A
	// zero value means the claim is absent.
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	// Aliases carries non-canonical identifiers the credential asserted. They
	// are recorded with provenance and never become identifiers.
	Aliases map[AliasKind]string
	// RevocationKey is the value a revocation source is keyed on (a jti, a
	// serial, a session id). Empty when the realm declares no revocation
	// source; required otherwise.
	RevocationKey string
}

// RevocationOracle answers whether a credential has been revoked.
//
// A nil oracle where the realm declares a revocation source is an outage, not
// a pass: VerifyCredential returns Indeterminate(REVOCATION_UNAVAILABLE). That
// is the one place in this file where "not configured" cannot be read as "not
// applicable", because the realm itself declared that it has a source.
type RevocationOracle interface {
	// IsRevoked reports whether the credential identified by key, in the given
	// realm, has been revoked. An error means the source could not be
	// consulted; it must not be reported as "not revoked".
	IsRevoked(orgID string, realm RealmID, key string) (bool, error)
}

// VerifiedSubject is the full outcome of realm verification.
type VerifiedSubject struct {
	// Admission is the outcome. Read Admission.State.IsAdmitted, never the
	// other fields, to decide whether to proceed.
	Admission Admission
	// Realm is the realm that accepted the credential. Zero unless admitted.
	Realm TrustRealm
	// Assurance is the credential's assurance class, carried forward so a
	// policy can require more than the realm's floor for a specific action.
	Assurance AssuranceClass
	// Aliases are the non-canonical identifiers the credential asserted, bound
	// to the canonical principal with authentication provenance.
	Aliases []Alias
	// IdentityEpoch is the registry epoch at verification time. A cached
	// closure or a decision proof carrying a different epoch is stale.
	IdentityEpoch int64
}

// VerifyCredential applies realm policy to a verified credential and produces
// a canonical principal, or refuses.
//
// authenticatedOrgID is the organization the CREDENTIAL ITSELF authenticated
// as, established upstream by the client credential. It is never a value read
// out of the credential being verified here, and never a caller-supplied
// header. Everything below is scoped to it.
//
// THE ORG-BINDING CRITERION (#3488, transferred to #3556)
//
// The prior behavior is the defect this function exists to remove. Segment
// resolution was keyed on the subject organization taken from a token claim,
// with nothing binding that claim to the authenticated organization. A
// wrong-but-non-empty org claim returned zero directory rows, which the
// resolver correctly reported as a SUCCESSFUL EMPTY resolution, so a verified
// member of a targeted segment was evaluated org-only: no refusal, no audit
// row, and a metric indistinguishable from a genuine non-member.
//
// Two mechanisms close it here, and the second is not redundant:
//
//  1. The realm lookup uses authenticatedOrgID. A realm declared in another
//     organization is UNKNOWN_REALM here, so a credential cannot reach even
//     the first policy check under an organization it did not authenticate as.
//  2. An asserted organization that DISAGREES with the authenticated one is
//     Deny(ORG_BINDING_MISMATCH). It is not ignored and it is not silently
//     narrowed to an org-only evaluation. Ignoring it would leave exactly the
//     observable outcome #3488 describes; the caller asked for something it is
//     not entitled to and must be told so.
//
// A credential carrying NO organization claim is fine: it is bound to the
// authenticated organization by construction, because that is the only
// organization its realm was looked up in.
func VerifyCredential(
	reg *RealmRegistry,
	authenticatedOrgID string,
	cred Credential,
	now time.Time,
	revocations RevocationOracle,
) VerifiedSubject {
	if reg == nil {
		return VerifiedSubject{Admission: IndeterminateAdmission(
			ReasonUnknownRealm, "no realm registry is configured, so no issuer can be resolved")}
	}
	if strings.TrimSpace(authenticatedOrgID) == "" {
		return VerifiedSubject{Admission: DenyAdmission(
			ReasonOrgBindingMismatch, "the request carries no authenticated organization to bind the subject to")}
	}
	if !cred.SignatureVerified {
		return VerifiedSubject{Admission: DenyAdmission(
			ReasonSignatureNotVerified, "the credential reached realm verification without a verified signature")}
	}

	// 1. Realm lookup, under the AUTHENTICATED organization. EX-47.
	// The realm and the epoch are read under ONE lock. Two separate reads leave
	// a window in which a concurrent Register stamps the NEW epoch onto a
	// subject verified against the OLD configuration, so a decision proof that
	// should be detectably stale reads as current. That is the one thing the
	// epoch exists to prevent, and it is the direction that fails silently.
	realm, epoch, ok := reg.lookupByIssuerAtEpoch(authenticatedOrgID, cred.Issuer)
	if !ok {
		return VerifiedSubject{Admission: DenyAdmission(ReasonUnknownRealm, fmt.Sprintf(
			"issuer %q has no declared trust realm in this organization; a validly signed credential is not a declared one",
			cred.Issuer))}
	}

	if !realm.Enabled {
		return VerifiedSubject{Admission: DenyAdmission(ReasonRealmDisabled, fmt.Sprintf(
			"realm %q is declared but administratively disabled", realm.RealmID))}
	}

	// 2. Organization binding. See the doc comment above.
	if realm.OrgID != authenticatedOrgID {
		// Defense in depth: the org-scoped lookup should make this
		// unreachable. If it ever fires, the registry index and the stored
		// realm disagree, and continuing would evaluate one organization's
		// subject under another's configuration.
		return VerifiedSubject{Admission: DenyAdmission(ReasonOrgBindingMismatch, fmt.Sprintf(
			"realm %q is declared in a different organization than the credential authenticated as", realm.RealmID))}
	}
	if !cred.HasAssertedOrg && cred.AssertedOrgID != "" {
		// Internally inconsistent, and inconsistent in the one direction that
		// matters: the flag is what gates the #3488 check, so an adapter that
		// populates AssertedOrgID and forgets the companion bool silently
		// reinstates the historical defect, and no later check can see it. The
		// flag is not redundant with a non-empty string (it is what separates
		// "carries no organization claim" from "carries an empty one"), so the
		// two cannot be collapsed; they can only be required to agree.
		return VerifiedSubject{Admission: DenyAdmission(ReasonOrgBindingMismatch, fmt.Sprintf(
			"the credential carries organization %q but is not marked as asserting one; the organization binding cannot be evaluated from an inconsistent credential",
			cred.AssertedOrgID))}
	}
	if cred.HasAssertedOrg && cred.AssertedOrgID != authenticatedOrgID {
		return VerifiedSubject{Admission: DenyAdmission(ReasonOrgBindingMismatch, fmt.Sprintf(
			"the credential asserts organization %q but authenticated as another; the assertion is refused, not narrowed to an organization-only evaluation",
			cred.AssertedOrgID))}
	}

	// 3. Credential class and algorithm.
	if !realm.AcceptsCredentialType(cred.Type) {
		return VerifiedSubject{Admission: DenyAdmission(ReasonUnsupportedCredentialType, fmt.Sprintf(
			"realm %q does not accept credential type %q", realm.RealmID, cred.Type))}
	}
	if !containsExact(realm.AllowedSigningAlgorithms, cred.Algorithm) {
		return VerifiedSubject{Admission: DenyAdmission(ReasonUnsupportedAlgorithm, fmt.Sprintf(
			"realm %q does not allow signing algorithm %q", realm.RealmID, cred.Algorithm))}
	}

	// 4. Audience, then authorized party. They answer different questions:
	// aud says who the credential is FOR, azp says which client obtained it.
	if !intersects(realm.Audiences, cred.Audiences) {
		return VerifiedSubject{Admission: DenyAdmission(ReasonAudienceRejected, fmt.Sprintf(
			"realm %q accepts none of the credential's audiences", realm.RealmID))}
	}
	if realm.AuthorizedPartyPolicy == AuthorizedPartyAllowList &&
		!containsExact(realm.AuthorizedParties, cred.AuthorizedParty) {
		// An empty azp lands here too, and must: a realm that pins azp is
		// pinning which client may present the credential, and a credential
		// with no azp does not satisfy that pin.
		return VerifiedSubject{Admission: DenyAdmission(ReasonAuthorizedPartyRejected, fmt.Sprintf(
			"realm %q pins its authorized parties and the credential's azp is not among them", realm.RealmID))}
	}

	// 5. Time. Skew is applied outward in both directions, so a clock that is
	// slightly wrong in either direction does not deny.
	if adm, refused := checkCredentialTime(realm, cred, now); refused {
		return VerifiedSubject{Admission: adm}
	}

	// 6. Assurance.
	// ASSURANCE IS THE ONE ORDERED ENUM IN THIS PLANE, so membership has to be
	// checked BEFORE the comparison and not only at realm registration.
	//
	// The realm's minimum is validated when the realm is registered. The
	// CREDENTIAL's class is not, and it is compared with `<`, so an
	// out-of-range value satisfies every floor by ordinary integer comparison:
	// AssuranceClass(99) passes a realm requiring high assurance. The zero
	// value was carefully arranged to rank below every declared class and that
	// arrangement says nothing at all about the other end of the range.
	//
	// A membership check on a value used only for equality can be deferred to
	// its writer. A value used for ORDERING cannot: the comparison itself is
	// what turns an unrecognized value into a permissive answer, and it does it
	// silently.
	if !cred.Assurance.IsValid() {
		return VerifiedSubject{Admission: DenyAdmission(ReasonAssuranceInsufficient, fmt.Sprintf(
			"the credential attests assurance %s, which is not a declared class; an unrecognized class would satisfy every realm minimum by ordinary comparison",
			cred.Assurance))}
	}
	if cred.Assurance < realm.MinimumAssurance {
		return VerifiedSubject{Admission: DenyAdmission(ReasonAssuranceInsufficient, fmt.Sprintf(
			"realm %q requires assurance %s and the credential attests %s",
			realm.RealmID, realm.MinimumAssurance, cred.Assurance))}
	}

	// 7. Subject type, then the canonical subject.
	subjectType := cred.SubjectType
	if subjectType == "" {
		subjectType = realm.ClaimMapping.SubjectType
	}
	if !realm.AcceptsSubjectType(subjectType) {
		return VerifiedSubject{Admission: DenyAdmission(ReasonSubjectTypeRejected, fmt.Sprintf(
			"realm %q does not assert subject type %q", realm.RealmID, subjectType))}
	}
	if strings.TrimSpace(cred.Subject) == "" {
		return VerifiedSubject{Admission: DenyAdmission(ReasonSubjectMissing, fmt.Sprintf(
			"the credential carries no value for realm %q's declared subject claim %q; an alias is never substituted for it",
			realm.RealmID, realm.ClaimMapping.SubjectClaim))}
	}
	principal, err := NewPrincipalID(realm.RealmID, subjectType, cred.Subject)
	if err != nil {
		return VerifiedSubject{Admission: DenyAdmission(ReasonMalformedPrincipal, fmt.Sprintf(
			"realm %q's subject claim did not produce a canonical principal: %v", realm.RealmID, err))}
	}

	// 8. Revocation, last, so an outage cannot mask a determinate refusal.
	if realm.Revocation != RevocationSourceNone {
		if revocations == nil {
			return VerifiedSubject{Admission: IndeterminateAdmission(ReasonRevocationUnavailable, fmt.Sprintf(
				"realm %q declares revocation source %s and no oracle is wired", realm.RealmID, realm.Revocation))}
		}
		if strings.TrimSpace(cred.RevocationKey) == "" {
			return VerifiedSubject{Admission: IndeterminateAdmission(ReasonRevocationUnavailable, fmt.Sprintf(
				"realm %q declares revocation source %s and the credential carries no revocation key, so it cannot be checked",
				realm.RealmID, realm.Revocation))}
		}
		revoked, revErr := revocations.IsRevoked(authenticatedOrgID, realm.RealmID, cred.RevocationKey)
		if revErr != nil {
			return VerifiedSubject{Admission: IndeterminateAdmission(ReasonRevocationUnavailable, fmt.Sprintf(
				"realm %q's revocation source could not be consulted", realm.RealmID))}
		}
		if revoked {
			return VerifiedSubject{Admission: DenyAdmission(ReasonCredentialRevoked, fmt.Sprintf(
				"the credential is revoked in realm %q", realm.RealmID))}
		}
	}

	return VerifiedSubject{
		Admission:     AcceptAdmission(principal),
		Realm:         realm,
		Assurance:     cred.Assurance,
		Aliases:       buildAliases(principal, realm, cred),
		IdentityEpoch: epoch,
	}
}

// checkCredentialTime applies the realm's clock skew to the credential's time
// claims. It returns (admission, true) when the credential is refused.
func checkCredentialTime(realm TrustRealm, cred Credential, now time.Time) (Admission, bool) {
	skew := realm.ClockSkew

	if cred.ExpiresAt.IsZero() {
		return DenyAdmission(ReasonCredentialExpired, fmt.Sprintf(
			"the credential declares no expiry; realm %q requires one, because a credential that never expires cannot be aged out",
			realm.RealmID)), true
	}
	if now.After(cred.ExpiresAt.Add(skew)) {
		return DenyAdmission(ReasonCredentialExpired, "the credential expired"), true
	}
	if !cred.NotBefore.IsZero() && now.Before(cred.NotBefore.Add(-skew)) {
		return DenyAdmission(ReasonCredentialNotYetValid, "the credential is not yet valid"), true
	}
	if !cred.IssuedAt.IsZero() && now.Before(cred.IssuedAt.Add(-skew)) {
		return DenyAdmission(ReasonCredentialNotYetValid, "the credential is issued in the future"), true
	}
	if realm.CredentialAgePolicy == CredentialAgeBounded {
		if cred.IssuedAt.IsZero() {
			// The realm bounds age and the credential does not say when it was
			// issued. Accepting it would apply no bound at all, which is the
			// opposite of what the operator configured.
			return DenyAdmission(ReasonCredentialTooOld, fmt.Sprintf(
				"realm %q bounds credential age at %s and the credential carries no issuance time",
				realm.RealmID, realm.MaxCredentialAge)), true
		}
		if now.After(cred.IssuedAt.Add(realm.MaxCredentialAge).Add(skew)) {
			return DenyAdmission(ReasonCredentialTooOld, fmt.Sprintf(
				"the credential is older than realm %q's maximum age of %s", realm.RealmID, realm.MaxCredentialAge)), true
		}
	}
	return Admission{}, false
}

// buildAliases records the credential's non-canonical identifiers against the
// canonical principal, with authentication provenance and the realm's
// claim-mapping version as the source version.
//
// Only alias kinds the REALM declared a claim for are recorded. A credential
// asserting an alias the realm never mapped is asserting something the
// operator did not ask AxonFlow to carry, and carrying it anyway is how an
// undeclared claim becomes a policy input.
func buildAliases(principal PrincipalID, realm TrustRealm, cred Credential) []Alias {
	if len(cred.Aliases) == 0 || len(realm.ClaimMapping.AliasClaims) == 0 {
		return nil
	}
	sourceVersion := fmt.Sprintf("claim_mapping/%d", realm.ClaimMapping.Version)
	var out []Alias
	// Iterate the alias vocabulary rather than either map, so the output order
	// is deterministic regardless of Go's map iteration order. A
	// nondeterministic alias order would make decision proofs over the same
	// credential differ between calls.
	for _, kind := range aliasKindOrder {
		if _, declared := realm.ClaimMapping.AliasClaims[kind]; !declared {
			continue
		}
		value, present := cred.Aliases[kind]
		if !present || value == "" {
			continue
		}
		out = append(out, Alias{
			Principal:     principal,
			Kind:          kind,
			Value:         value,
			Provenance:    ProvenanceAuthentication,
			SourceVersion: sourceVersion,
		})
	}
	return out
}

// aliasKindOrder fixes the emission order of aliases.
var aliasKindOrder = []AliasKind{
	AliasEmail, AliasUsername, AliasDisplayName, AliasSCIMExternalID,
	AliasTokenSubject, AliasSPIFFEID, AliasConnectorAccountID,
}

// containsExact reports whether want appears in set by exact string equality.
// Exact, not case-folded: JWT algorithm names, audiences, and azp values are
// case-sensitive, and folding them would widen every allow-list in this file.
func containsExact(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

// intersects reports whether the two sets share at least one exact member. An
// empty presented set never intersects, which is the correct direction: a
// credential with no audience does not satisfy a realm that declares one.
func intersects(accepted, presented []string) bool {
	if len(accepted) == 0 || len(presented) == 0 {
		return false
	}
	for _, p := range presented {
		if containsExact(accepted, p) {
			return true
		}
	}
	return false
}
