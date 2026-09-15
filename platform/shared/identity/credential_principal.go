// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import "fmt"

// CredentialPath names which credential path presented the credential. It is a
// closed vocabulary: an unrecognized path is a call-site defect, and admission
// refuses to evaluate one (validateCredentialPrincipal).
type CredentialPath string

const (
	// CredentialPathHS256 is the AxonFlow HS256 bearer-JWT path: the agent's
	// validateUserToken and the fleet plane's Path A validator.
	CredentialPathHS256 CredentialPath = "hs256"
	// CredentialPathOIDC is the IdP-issued OIDC path: the fleet plane's Path B
	// verifier and the customer-portal interactive SSO login.
	CredentialPathOIDC CredentialPath = "oidc"
	// CredentialPathAPICredential is an AxonFlow-issued client credential: the
	// Ed25519 license key, the bcrypt API key, the community-SaaS
	// registration secret, and the internal-service HMAC token.
	CredentialPathAPICredential CredentialPath = "api_credential"
	// CredentialPathTrustedHeader is an upstream-asserted identity header
	// (X-User-Email / X-User-ID) honored only under the #2896 trust gate.
	CredentialPathTrustedHeader CredentialPath = "trusted_header"
)

var credentialPaths = []CredentialPath{
	CredentialPathHS256, CredentialPathOIDC, CredentialPathAPICredential, CredentialPathTrustedHeader,
}

// IsValid reports whether p is a declared path.
func (p CredentialPath) IsValid() bool {
	for _, known := range credentialPaths {
		if p == known {
			return true
		}
	}
	return false
}

// PathVerdict is what the credential path decided before admission ran.
//
// A tri-state rather than a bool, and validated by membership, because the
// zero value of a bool is "rejected", and a caller that forgot to set it would
// present every credential as one the path rejected. The zero value here is
// refused instead.
type PathVerdict int

const (
	// PathVerdictUnspecified is the zero value and is refused.
	PathVerdictUnspecified PathVerdict = iota
	// PathVerdictAccepted means the path authenticated the caller.
	PathVerdictAccepted
	// PathVerdictRejected means the path refused the caller.
	PathVerdictRejected
)

// IsValid reports whether d is one of the declared decisions.
func (d PathVerdict) IsValid() bool {
	switch d {
	case PathVerdictAccepted, PathVerdictRejected:
		return true
	default:
		return false
	}
}

// String renders the decision.
func (d PathVerdict) String() string {
	switch d {
	case PathVerdictAccepted:
		return "accepted"
	case PathVerdictRejected:
		return "rejected"
	case PathVerdictUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("PathVerdict(%d)", int(d))
	}
}

// CredentialPrincipal is one authenticated request's credential, decomposed into
// what the identity plane needs to admit the principal it names (PRD v11 §1.6).
type CredentialPrincipal struct {
	// Path names the credential path.
	Path CredentialPath
	// AuthenticatedOrgID is the organization the CREDENTIAL authenticated as,
	// established upstream. Never a claim out of the credential under
	// verification and never a caller-supplied header.
	AuthenticatedOrgID string
	// Decision is what the path decided.
	Decision PathVerdict
	// Credential is the realm-verification input. When Claims is non-nil
	// admission OVERWRITES Subject and Aliases from the realm's claim mapping
	// (see Claims); every other field is the caller's.
	Credential Credential
	// Claims is the verified claim set for claim-bearing credentials (HS256,
	// OIDC), nil for the others.
	//
	// When it is non-nil, the realm's ClaimMapping - not the caller - decides
	// which claim is the canonical subject and which are aliases. A caller
	// cannot pre-set Credential.Subject and have it honored, because that is
	// exactly the route by which "the configured subject claim was absent, so
	// we used the email" gets reintroduced one builder at a time. ADR-065
	// invariant 3 is enforced here, not asked for.
	Claims map[string]any
	// UnverifiableReason records that the path could not REACH a verdict
	// about this credential, and names why. Empty for every ordinary
	// accept and every ordinary reject.
	//
	// It exists so that "your IdP is unreachable" does not reach the operator
	// as "this credential's signature did not verify". Without it, a JWKS
	// outage reads as SIGNATURE_NOT_VERIFIED, which is the wording for a
	// forgery and sends an operator to the wrong investigation.
	//
	// It is tightly constrained and can only ever make admission MORE
	// conservative: unverifiableReasons is a two-element allow-list, the
	// outcome it produces is always Indeterminate, and Indeterminate is never
	// an admission. A value outside the allow-list, or one paired with an
	// accepted decision, is a call-site defect and refuses to evaluate.
	UnverifiableReason AdmissionReason
}

// unverifiableReasons is the closed set a path may report as "could not reach
// a verdict". Both are Indeterminate outcomes in the identity plane's own
// vocabulary, and neither is a Deny - a path that DID reach a verdict reports
// it through Decision, not here.
var unverifiableReasons = map[AdmissionReason]bool{
	ReasonKeyMaterialUnavailable: true,
	ReasonRevocationUnavailable:  true,
}
