// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Per-path credential builders (#3550).
//
// Each builder turns what ONE authentication path already established into
// the Credential shape realm verification is expressed over. They do no
// verification of their own: by the time a builder runs, the path has already
// decided, and the builder's whole job is to describe that decision faithfully
// enough for subject admission to verify the credential against the
// organization's trust realms.
//
// # WHAT NONE OF THEM DO
//
// None of them sets Credential.Subject. The canonical subject is taken from
// the realm's ClaimMapping by the admitter (SubjectAdmitter.completeCredential),
// for every one of the four paths, including the two that carry no JWT. A
// builder that could set a subject directly is the route by which "the mapped
// claim was absent, so we used the email instead" gets reintroduced one path
// at a time - so admission refuses a CredentialPrincipal that carries one.
package identity

import (
	"encoding/json"
	"time"
)

// Pseudo-claim keys for the credentials that carry no JWT. They are the keys a
// built-in realm's ClaimMapping names, so an operator reading the realm can
// see exactly which asserted value became the canonical subject.
const (
	claimKeyClientID  = subjectClaimClientID
	claimKeyServiceID = subjectClaimServiceID
	claimKeyUserID    = subjectClaimUserID
	claimKeyUserEmail = "x-user-email"
)

// HS256Principal builds the credential principal for a verified AxonFlow HS256
// bearer token.
//
// claims is the token's verified claim set; accepted is what the path decided.
//
// SIGNATURE VERIFICATION IS THE CALLER'S FACT, NOT THIS FUNCTION'S. It is set
// from `accepted`, so a rejected token reaches realm verification with
// SignatureVerified false and is denied for exactly that reason: admission has
// no route by which an unverified credential can be admitted.
func HS256Principal(orgID string, claims map[string]any, accepted bool, unverifiable AdmissionReason) CredentialPrincipal {
	decision := PathVerdictRejected
	if accepted {
		decision = PathVerdictAccepted
	}
	if claims == nil {
		claims = map[string]any{}
	}
	assertedOrg, hasAssertedOrg := claimPresence(claims, OrgAssertionClaim)
	return CredentialPrincipal{
		Path:               CredentialPathHS256,
		AuthenticatedOrgID: orgID,
		Decision:           decision,
		Claims:             claims,
		UnverifiableReason: unverifiable,
		Credential: Credential{
			Issuer:            claimStringFromMap(claims, "iss"),
			Type:              CredentialBearerJWT,
			Algorithm:         "HS256",
			SignatureVerified: accepted,
			Audiences:         audienceClaim(claims),
			AuthorizedParty:   claimStringFromMap(claims, "azp"),
			AssertedOrgID:     assertedOrg,
			HasAssertedOrg:    hasAssertedOrg,
			// The built-in realms declare the lowest possible floor, so
			// attesting the lowest class is the truthful reading of a bearer
			// token that proves possession and nothing else. Raising it is an
			// operator act, not a builder's.
			Assurance: AssuranceLow,
			IssuedAt:  timeClaim(claims, "iat"),
			NotBefore: timeClaim(claims, "nbf"),
			ExpiresAt: timeClaim(claims, "exp"),
			// A realm declaring a revocation source and receiving a token with
			// no jti is INDETERMINATE, not fine. The legacy plane treats an
			// unrevocable token as unrevoked; this records the difference.
			RevocationKey: claimStringFromMap(claims, "jti"),
		},
	}
}

// OIDCPrincipal builds the credential principal for a verified OIDC token.
//
// It is UNTAGGED even though the OIDC realm declaration (oidc_realm.go) is
// enterprise-only, because ValidatedIdentityPrincipal, which calls it, compiles
// in both editions. In a community build no validator is registered, so no OIDC
// identity is ever validated and no OIDC realm is ever declared - which is the
// correct community answer, not a gap.
//
// claims is the token's verified claim set. unverifiable is non-empty only
// when the verifier could not reach a verdict at all, in practice
// ReasonKeyMaterialUnavailable from a JWKS endpoint that could not be reached
// or a cached key set past its staleness bound.
//
// AN OIDC TOKEN ASSERTS NO ORGANIZATION. The organization is the one whose SSO
// configuration was used to verify it, which is the authenticated organization
// by construction, so HasAssertedOrg stays false. A tenant IdP that emits an
// org claim is asserting something AxonFlow did not ask it to carry and does
// not read, and reading it here would create the unbound-claim binding the
// HS256 path is being fixed for.
func OIDCPrincipal(orgID string, claims map[string]any, accepted bool, unverifiable AdmissionReason) CredentialPrincipal {
	decision := PathVerdictRejected
	if accepted {
		decision = PathVerdictAccepted
	}
	if claims == nil {
		claims = map[string]any{}
	}
	return CredentialPrincipal{
		Path:               CredentialPathOIDC,
		AuthenticatedOrgID: orgID,
		Decision:           decision,
		Claims:             claims,
		UnverifiableReason: unverifiable,
		Credential: Credential{
			Issuer:            claimStringFromMap(claims, "iss"),
			Type:              CredentialBearerJWT,
			Algorithm:         "RS256",
			SignatureVerified: accepted,
			Audiences:         audienceClaim(claims),
			AuthorizedParty:   claimStringFromMap(claims, "azp"),
			HasAssertedOrg:    false,
			Assurance:         AssuranceLow,
			IssuedAt:          timeClaim(claims, "iat"),
			NotBefore:         timeClaim(claims, "nbf"),
			ExpiresAt:         timeClaim(claims, "exp"),
			// An OIDC access token carries no AxonFlow revocation key. The
			// realm declares RevocationSourceNone unless CAEP is wired, so
			// this is not consulted then; when CAEP IS wired the key is the
			// token's jti, which RFC 9068 access tokens carry.
			RevocationKey: claimStringFromMap(claims, "jti"),
		},
	}
}

// OrgAssertionClaim is the claim by which an AxonFlow-minted token asserts the
// organization it is about.
//
// It is read for PRESENCE, not for a non-empty value. "Carries no organization
// claim" and "carries an empty one" are different facts: the first is bound to
// the authenticated organization by construction, the second is a malformed
// credential, and a bare string cannot tell them apart. This is the #3488
// finding's own shape, one layer up.
const OrgAssertionClaim = "org_id"

// APICredentialPrincipal builds the credential principal for an AxonFlow-issued
// client credential: the Ed25519 license key, the bcrypt API key, or the
// community-SaaS registration secret.
//
// clientID is the credential identity (ADR-052 §5: the api_key_id for
// API-keyed callers, not the organization license id). verification names how
// the credential was checked.
//
// A client credential asserts NO organization of its own: the authenticated
// organization is derived FROM it upstream, so it is bound by construction and
// HasAssertedOrg stays false. Setting it would compare the organization
// against itself and prove nothing.
func APICredentialPrincipal(orgID, clientID, verification string, accepted bool, now time.Time) CredentialPrincipal {
	return liveVerifiedPrincipal(liveVerifiedInput{
		path:           CredentialPathAPICredential,
		orgID:          orgID,
		issuer:         IssuerAPICredential,
		credentialType: CredentialAPICredential,
		verification:   verification,
		claimKey:       claimKeyClientID,
		subject:        clientID,
		accepted:       accepted,
		now:            now,
	})
}

// InternalServicePrincipal builds the credential principal for the
// orchestrator-to-agent HMAC hop.
//
// It is the FIFTH auth entry point a census of four credential paths misses,
// and it is covered here rather than excluded: platform/agent's Authenticate()
// returns AuthKindInternalService from the same function that returns the
// other three kinds, so admission wired at that choke point sees it whether or
// not anyone remembered it. Its subject is a SERVICE, not a user and not a
// client.
func InternalServicePrincipal(orgID, serviceID string, accepted bool, now time.Time) CredentialPrincipal {
	return liveVerifiedPrincipal(liveVerifiedInput{
		path:           CredentialPathAPICredential,
		orgID:          orgID,
		issuer:         IssuerInternalService,
		credentialType: CredentialAPICredential,
		verification:   VerificationHMACInternalService,
		claimKey:       claimKeyServiceID,
		subject:        serviceID,
		accepted:       accepted,
		now:            now,
	})
}

// CommunityPrincipal builds the credential principal for community mode, where the
// deployment requires no credential at all.
//
// The caller's asserted client id becomes a Client principal at AssuranceLow.
// Community mode is not an absence of identity: it is a deployment declaring
// that it accepts an unverified assertion, which is a fact worth being able to
// name in an audit trail.
func CommunityPrincipal(orgID, clientID string, now time.Time) CredentialPrincipal {
	return liveVerifiedPrincipal(liveVerifiedInput{
		path:           CredentialPathAPICredential,
		orgID:          orgID,
		issuer:         IssuerCommunity,
		credentialType: CredentialTrustedHeader,
		verification:   VerificationCommunityUnauthenticated,
		claimKey:       claimKeyClientID,
		subject:        clientID,
		// Community mode never rejects: that IS its posture.
		accepted: true,
		now:      now,
	})
}

// TrustedHeaderPrincipal builds the credential principal for an upstream-asserted
// identity header, honored only under the #2896 trust gate.
//
// userID and userEmail are the values that SURVIVED the gate - a gated-off
// deployment passes the empty strings it actually used, not the values the
// caller sent, because what is admitted must be what the platform acted on.
//
// The email is presented as an ALIAS. It is not, and cannot become, the
// canonical subject: a deployment whose upstream asserts only an address gets
// SUBJECT_MISSING, which is the honest statement that it has attribution and
// not identity.
func TrustedHeaderPrincipal(orgID, userID, userEmail string, accepted bool, now time.Time) CredentialPrincipal {
	in := liveVerifiedPrincipal(liveVerifiedInput{
		path:           CredentialPathTrustedHeader,
		orgID:          orgID,
		issuer:         IssuerTrustedHeader,
		credentialType: CredentialTrustedHeader,
		verification:   VerificationUpstreamAsserted,
		claimKey:       claimKeyUserID,
		subject:        userID,
		accepted:       accepted,
		now:            now,
	})
	if userEmail != "" {
		in.Claims[claimKeyUserEmail] = userEmail
	}
	return in
}

// liveVerifiedInput carries the fields the three non-JWT builders share.
type liveVerifiedInput struct {
	path           CredentialPath
	orgID          string
	issuer         string
	credentialType CredentialType
	verification   string
	claimKey       string
	subject        string
	accepted       bool
	now            time.Time
}

// liveVerifiedPrincipal builds the credential principal for a credential that is
// re-verified from scratch on every request and therefore has no expiry of its
// own.
//
// The synthesized validity window (LiveVerificationWindow) is the truthful
// encoding of that: the credential was checked at `now`, and the check is
// asserted for the next minute and no longer.
//
// TWO THINGS IT DOES AND ONE IT DOES NOT. It satisfies TrustRealm's "a
// credential that never expires cannot be aged out" invariant without
// weakening it, and it bounds how long a verification RESULT may be carried by
// a caller that passes a non-current instant. It does NOT bound anything for
// the ordinary caller, who passes time.Now(): the window is minted from the
// same clock the verifier compares against microseconds later, so that check
// is vacuous by construction there. It can never widen: the only outcome it
// can change is a refusal for an old verification.
func liveVerifiedPrincipal(in liveVerifiedInput) CredentialPrincipal {
	decision := PathVerdictRejected
	if in.accepted {
		decision = PathVerdictAccepted
	}
	now := in.now
	if now.IsZero() {
		now = time.Now()
	}
	claims := map[string]any{}
	if in.subject != "" {
		claims[in.claimKey] = in.subject
	}
	return CredentialPrincipal{
		Path:               in.path,
		AuthenticatedOrgID: in.orgID,
		Decision:           decision,
		Claims:             claims,
		Credential: Credential{
			Issuer:            in.issuer,
			Type:              in.credentialType,
			Algorithm:         in.verification,
			SignatureVerified: in.accepted,
			Audiences:         []string{AudienceDeployment},
			// No organization is asserted: the authenticated organization was
			// derived from this credential upstream.
			HasAssertedOrg: false,
			Assurance:      AssuranceLow,
			IssuedAt:       now,
			ExpiresAt:      now.Add(LiveVerificationWindow),
		},
	}
}

// --- claim readers ---
//
// They are deliberately strict about types. A claim delivered in a shape the
// reader does not recognize reads as ABSENT, never as a coerced value: two
// different JSON shapes producing the same principal is how a subject becomes
// ambiguous, and a coerced expiry is how a token outlives its own claim.

// claimPresence returns a string claim's value and whether the claim was
// PRESENT at all. A present-but-empty claim returns ("", true), which is the
// distinction Credential.HasAssertedOrg exists to carry.
//
// A present claim of a non-string type returns ("", true): it is present, and
// its value is not one this plane can key on. Reporting it as absent would let
// an org_id delivered as a number bypass the binding check entirely, which is
// the exact fail-open direction.
func claimPresence(claims map[string]any, name string) (string, bool) {
	raw, ok := claims[name]
	if !ok {
		return "", false
	}
	s, _ := raw.(string)
	return s, true
}

// audienceClaim reads the JWT `aud` claim, which RFC 7519 allows to be either
// a single string or an array of strings.
//
// An ABSENT audience yields the deployment's own audience, because a
// symmetric-key token is usable only against the holder of the key. A PRESENT
// audience is returned verbatim and must satisfy the realm's list - so a token
// minted for somewhere else is refused rather than silently re-audienced.
func audienceClaim(claims map[string]any) []string {
	raw, ok := claims["aud"]
	if !ok {
		return []string{AudienceDeployment}
	}
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, isStr := item.(string); isStr {
				out = append(out, s)
			}
		}
		return out
	default:
		// Present in a shape that is not an audience. Returning the
		// deployment's audience here would treat a malformed claim as an
		// absent one and admit it; an empty set intersects nothing and is
		// refused.
		return nil
	}
}

// timeClaim reads a NumericDate claim. Absent, non-numeric, or unparseable
// yields the zero time, which every caller in this package treats as "the
// claim is absent" - and which, for `exp`, TrustRealm verification treats as a
// refusal rather than as "never expires".
func timeClaim(claims map[string]any, name string) time.Time {
	raw, ok := claims[name]
	if !ok {
		return time.Time{}
	}
	switch v := raw.(type) {
	case float64:
		return unixSeconds(v)
	case int64:
		return time.Unix(v, 0).UTC()
	case int:
		return time.Unix(int64(v), 0).UTC()
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return time.Time{}
		}
		return unixSeconds(f)
	default:
		return time.Time{}
	}
}

// unixSeconds converts a possibly-fractional NumericDate to a time, preserving
// sub-second precision rather than truncating it (a truncated `exp` would
// expire a credential up to a second early, and a truncated `nbf` would admit
// one up to a second early).
func unixSeconds(f float64) time.Time {
	sec := int64(f)
	nsec := int64((f - float64(sec)) * float64(time.Second))
	return time.Unix(sec, nsec).UTC()
}
