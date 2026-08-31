// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 trust realms and the organization-scoped realm registry (#3556).
//
// A trust realm is configuration, not an issuer string. It declares which
// credentials this organization accepts from one identity source, what those
// credentials are allowed to assert, whether the source carries a group graph,
// and whether anything in it can answer a question.
//
// # WHY THE REGISTRY REFUSES UNDERSPECIFIED REALMS
//
// Every tri-state field here reserves its zero value for "not declared", and
// Register REFUSES a realm that leaves one at its zero value. That is stronger
// than checking for the zero value at each read site, and it is deliberate:
// EX-47 is a fail-open produced entirely by omission, where realm(p) is
// undefined and a falsy default reads as has_group_graph = false, making an
// empty group closure look authoritative and skipping every segment-scoped
// ceiling. Two mechanisms close it, and both are needed:
//
//  1. An issuer with no declared realm is Deny(UNKNOWN_REALM) before any
//     policy loads, so realm(p) is never undefined downstream. Lookup returns
//     (TrustRealm{}, false) and every caller in this package treats the miss
//     as a refusal, never as a realm with default settings.
//  2. A realm that IS declared cannot hold a falsy default for any fact a
//     downstream decision keys on, because it could not have been registered.
//     So there is no reachable state in which the value read is a zero value
//     that happens to mean something permissive.
//
// The second is what makes the first sufficient. Without it, an operator could
// declare a realm, leave DirectorySource unset, and reconstruct EX-47 through
// the front door.
package identity

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// RealmKind classifies the identity source behind a realm. It is descriptive:
// it drives diagnostics and operator tooling, never an authorization shortcut.
type RealmKind string

const (
	// RealmKindOIDC is an OIDC issuer with a JWKS.
	RealmKindOIDC RealmKind = "oidc"
	// RealmKindSPIFFE is a SPIFFE trust domain.
	RealmKindSPIFFE RealmKind = "spiffe"
	// RealmKindAxonFlowMinted is the AxonFlow per-user token minting path.
	RealmKindAxonFlowMinted RealmKind = "axonflow_minted"
	// RealmKindAPICredential is a client credential issued by AxonFlow.
	RealmKindAPICredential RealmKind = "api_credential"
	// RealmKindTrustedHeader is a deployment-declared upstream that asserts
	// identity in a header. Attribution-grade at best; a realm of this kind
	// cannot declare an assurance above AssuranceLow (enforced in Validate).
	RealmKindTrustedHeader RealmKind = "trusted_header"
)

var realmKinds = []RealmKind{
	RealmKindOIDC, RealmKindSPIFFE, RealmKindAxonFlowMinted,
	RealmKindAPICredential, RealmKindTrustedHeader,
}

// IsValid reports whether k is a known realm kind.
func (k RealmKind) IsValid() bool {
	for _, known := range realmKinds {
		if k == known {
			return true
		}
	}
	return false
}

// CredentialType is the class of credential a realm accepts.
type CredentialType string

const (
	// CredentialBearerJWT is a signed bearer JWT.
	CredentialBearerJWT CredentialType = "bearer_jwt"
	// CredentialIDToken is an OIDC ID token from an interactive login.
	CredentialIDToken CredentialType = "id_token"
	// CredentialSVID is a SPIFFE verifiable identity document.
	CredentialSVID CredentialType = "svid"
	// CredentialAPICredential is an AxonFlow-issued client credential.
	CredentialAPICredential CredentialType = "api_credential"
	// CredentialTrustedHeader is an upstream-asserted identity header.
	CredentialTrustedHeader CredentialType = "trusted_header"
)

var credentialTypes = []CredentialType{
	CredentialBearerJWT, CredentialIDToken, CredentialSVID,
	CredentialAPICredential, CredentialTrustedHeader,
}

// IsValid reports whether c is a known credential type.
func (c CredentialType) IsValid() bool {
	for _, known := range credentialTypes {
		if c == known {
			return true
		}
	}
	return false
}

// AssuranceClass ranks how strongly a credential authenticated its subject.
//
// The zero value is Unspecified and ranks BELOW every declared class, so a
// credential that failed to carry an assurance never satisfies a realm
// minimum. A realm may not declare Unspecified as its minimum (Validate
// refuses), so the comparison can never degenerate into "anything passes".
type AssuranceClass int

const (
	// AssuranceUnspecified is the zero value: no assurance was established.
	AssuranceUnspecified AssuranceClass = iota
	// AssuranceLow is a single factor, or an assertion from an upstream that
	// AxonFlow does not itself verify.
	AssuranceLow
	// AssuranceSubstantial is a verified credential from a managed directory.
	AssuranceSubstantial
	// AssuranceHigh is multi-factor or hardware-backed authentication.
	AssuranceHigh
)

// IsValid reports whether a is one of the declared classes. See
// DirectorySource.IsValid for why this is membership and not inequality: an
// AssuranceClass above the declared range would otherwise satisfy every realm
// minimum by ordinary integer comparison.
func (a AssuranceClass) IsValid() bool {
	switch a {
	case AssuranceLow, AssuranceSubstantial, AssuranceHigh:
		return true
	default:
		return false
	}
}

// String renders the assurance class.
func (a AssuranceClass) String() string {
	switch a {
	case AssuranceLow:
		return "low"
	case AssuranceSubstantial:
		return "substantial"
	case AssuranceHigh:
		return "high"
	case AssuranceUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("AssuranceClass(%d)", int(a))
	}
}

// DirectorySource declares whether a realm carries a group graph, and where it
// comes from.
//
// This is the field EX-45 and EX-47 both turn on. DirectorySourceNone is a
// POSITIVE declaration that this realm has no group concept, which is what
// makes an empty closure from it authoritative rather than an outage. It is
// never inferred from a query returning zero rows, and it is never the value a
// missing configuration produces, because DirectorySourceUnspecified is
// refused at registration.
type DirectorySource int

const (
	// DirectorySourceUnspecified is the zero value and cannot be registered.
	DirectorySourceUnspecified DirectorySource = iota
	// DirectorySourceNone declares that this realm has no group graph at all.
	// Cloud IAM service-account realms are the ordinary case. A closure over
	// such a realm is authoritatively empty.
	DirectorySourceNone
	// DirectorySourceSCIM declares a SCIM-provisioned directory.
	DirectorySourceSCIM
	// DirectorySourceExternalGraph declares a non-SCIM directory normalized
	// through the same DirectoryEntity and DirectoryEdge contract.
	DirectorySourceExternalGraph
)

// HasGroupGraph reports whether closures over this source can be non-empty.
// Unspecified answers false, but no registered realm can hold it: this method
// exists for values read from unvalidated structs in tests and adapters.
func (d DirectorySource) HasGroupGraph() bool {
	return d == DirectorySourceSCIM || d == DirectorySourceExternalGraph
}

// IsValid reports whether d is one of the declared sources.
//
// EVERY TRI-STATE IN THIS PLANE IS VALIDATED BY MEMBERSHIP, NOT BY INEQUALITY
// AGAINST ITS ZERO VALUE, and the difference is not stylistic. A check of the
// form `if d == DirectorySourceUnspecified { refuse }` admits every OTHER
// out-of-range value, and DirectorySource(99) then reaches HasGroupGraph, which
// answers false, which is the permissive default the tri-state was introduced
// to abolish. One enum value over the top of the range reinstates it.
//
// The threat is the same one the tri-states were added for: a mis-serialised
// value, a second directory adapter, or a newer producer writing an enum this
// build does not know. Membership refuses all three; inequality refuses one.
func (d DirectorySource) IsValid() bool {
	switch d {
	case DirectorySourceNone, DirectorySourceSCIM, DirectorySourceExternalGraph:
		return true
	case DirectorySourceUnspecified:
		return false
	default:
		return false
	}
}

// String renders the directory source.
func (d DirectorySource) String() string {
	switch d {
	case DirectorySourceNone:
		return "none"
	case DirectorySourceSCIM:
		return "scim"
	case DirectorySourceExternalGraph:
		return "external_graph"
	case DirectorySourceUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("DirectorySource(%d)", int(d))
	}
}

// InteractiveClass declares whether a subject in this realm can be asked a
// question. It is EX-46's field.
//
// A service-account realm lands in approver pools for automation reasons all
// the time. Without this declaration those members inflate the eligible count,
// an escalation is issued, and it parks until timeout because nothing there
// can answer. Declaring it on the REALM keeps the engine out of the business
// of deciding which subjects are people.
type InteractiveClass int

const (
	// InteractiveUnspecified is the zero value and cannot be registered.
	InteractiveUnspecified InteractiveClass = iota
	// InteractiveHuman declares that subjects here can be prompted.
	InteractiveHuman
	// InteractiveNonInteractive declares that they cannot.
	InteractiveNonInteractive
)

// CanAnswer reports whether an approval request to a subject in this realm can
// be answered. Unspecified answers false; see InteractiveClass.
func (i InteractiveClass) CanAnswer() bool { return i == InteractiveHuman }

// IsValid reports whether i is one of the declared classes. See
// DirectorySource.IsValid for why this is membership and not inequality.
func (i InteractiveClass) IsValid() bool {
	switch i {
	case InteractiveHuman, InteractiveNonInteractive:
		return true
	default:
		return false
	}
}

// String renders the interactive class.
func (i InteractiveClass) String() string {
	switch i {
	case InteractiveHuman:
		return "human"
	case InteractiveNonInteractive:
		return "non_interactive"
	case InteractiveUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("InteractiveClass(%d)", int(i))
	}
}

// RevocationSource declares how a realm's credentials are revoked.
type RevocationSource int

const (
	// RevocationSourceUnspecified is the zero value and cannot be registered.
	RevocationSourceUnspecified RevocationSource = iota
	// RevocationSourceNone is a POSITIVE declaration that this realm has no
	// revocation channel. It is not the same as forgetting to configure one:
	// a realm declaring None never yields REVOCATION_UNAVAILABLE, because
	// there was never a source to be unavailable.
	RevocationSourceNone
	// RevocationSourceLocalStore is an AxonFlow-held revocation list.
	RevocationSourceLocalStore
	// RevocationSourceSharedSignals is an OpenID Shared Signals / CAEP
	// receiver, with polling and TTL fallback.
	RevocationSourceSharedSignals
)

// IsValid reports whether r is one of the declared sources. See
// DirectorySource.IsValid for why this is membership and not inequality.
func (r RevocationSource) IsValid() bool {
	switch r {
	case RevocationSourceNone, RevocationSourceLocalStore, RevocationSourceSharedSignals:
		return true
	default:
		return false
	}
}

// String renders the revocation source.
func (r RevocationSource) String() string {
	switch r {
	case RevocationSourceNone:
		return "none"
	case RevocationSourceLocalStore:
		return "local_store"
	case RevocationSourceSharedSignals:
		return "shared_signals"
	case RevocationSourceUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("RevocationSource(%d)", int(r))
	}
}

// DelegationPolicy declares which realms may act as an intermediary for a
// subject asserted by this realm.
//
// EX-27 makes chains spanning realms the normal case, not an edge one, so this
// cannot default to "deny everything" without breaking ordinary delegation;
// and it must not default to "allow anything", which would let an acquisition's
// directory interpose itself in a chain rooted in the corporate one. So it is
// a tri-state that must be declared.
type DelegationPolicy int

const (
	// DelegationUnspecified is the zero value and cannot be registered.
	DelegationUnspecified DelegationPolicy = iota
	// DelegationDenied means no realm may act on behalf of subjects here.
	DelegationDenied
	// DelegationAllowList means only the realms in DelegateRealms may.
	DelegationAllowList
	// DelegationAnyRealmInOrg means any realm registered in the same
	// organization may. Still bounded by the organization, never global.
	DelegationAnyRealmInOrg
)

// IsValid reports whether d is one of the declared policies. See
// DirectorySource.IsValid for why this is membership and not inequality.
func (d DelegationPolicy) IsValid() bool {
	switch d {
	case DelegationDenied, DelegationAllowList, DelegationAnyRealmInOrg:
		return true
	default:
		return false
	}
}

// String renders the delegation policy.
func (d DelegationPolicy) String() string {
	switch d {
	case DelegationDenied:
		return "denied"
	case DelegationAllowList:
		return "allow_list"
	case DelegationAnyRealmInOrg:
		return "any_realm_in_org"
	case DelegationUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("DelegationPolicy(%d)", int(d))
	}
}

// AuthorizedPartyPolicy declares whether a realm checks the credential's
// authorized party (azp).
//
// It is a tri-state and not an empty slice, because "we did not configure azp"
// and "this realm deliberately does not pin azp" are different facts with the
// same falsy representation. Many realms legitimately do not pin it: their
// credentials carry no azp at all. But a realm that MEANT to pin it and shipped
// with an empty list accepts a token minted for one client and replayed by
// another, and nothing about the configuration says which of the two happened.
type AuthorizedPartyPolicy int

const (
	// AuthorizedPartyUnspecified is the zero value and cannot be registered.
	AuthorizedPartyUnspecified AuthorizedPartyPolicy = iota
	// AuthorizedPartyNotChecked declares that this realm does not pin azp.
	AuthorizedPartyNotChecked
	// AuthorizedPartyAllowList declares that only the listed parties are
	// accepted, and that a credential carrying no azp is refused.
	AuthorizedPartyAllowList
)

// IsValid reports whether p is one of the declared policies. See
// DirectorySource.IsValid for why this is membership and not inequality.
func (p AuthorizedPartyPolicy) IsValid() bool {
	switch p {
	case AuthorizedPartyNotChecked, AuthorizedPartyAllowList:
		return true
	default:
		return false
	}
}

// String renders the authorized-party policy.
func (p AuthorizedPartyPolicy) String() string {
	switch p {
	case AuthorizedPartyNotChecked:
		return "not_checked"
	case AuthorizedPartyAllowList:
		return "allow_list"
	case AuthorizedPartyUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("AuthorizedPartyPolicy(%d)", int(p))
	}
}

// CredentialAgePolicy declares whether a realm bounds how old an unexpired
// credential may be.
//
// Same reasoning as AuthorizedPartyPolicy, and the same falsy trap: a zero
// MaxCredentialAge means unbounded, which is indistinguishable from an operator
// who intended a bound and left the field at its zero value. The bound is a
// real control (it is what stops a long-lived token minted years ago still
// working), so its absence has to be a declaration.
type CredentialAgePolicy int

const (
	// CredentialAgeUnspecified is the zero value and cannot be registered.
	CredentialAgeUnspecified CredentialAgePolicy = iota
	// CredentialAgeUnbounded declares that only the credential's own expiry
	// applies.
	CredentialAgeUnbounded
	// CredentialAgeBounded declares that MaxCredentialAge applies, and a
	// credential carrying no issuance time is refused because the bound cannot
	// be applied to it.
	CredentialAgeBounded
)

// IsValid reports whether p is one of the declared policies. See
// DirectorySource.IsValid for why this is membership and not inequality.
func (p CredentialAgePolicy) IsValid() bool {
	switch p {
	case CredentialAgeUnbounded, CredentialAgeBounded:
		return true
	default:
		return false
	}
}

// String renders the credential-age policy.
func (p CredentialAgePolicy) String() string {
	switch p {
	case CredentialAgeUnbounded:
		return "unbounded"
	case CredentialAgeBounded:
		return "bounded"
	case CredentialAgeUnspecified:
		return "unspecified"
	default:
		return fmt.Sprintf("CredentialAgePolicy(%d)", int(p))
	}
}

// ClaimMapping declares how a realm's credential claims become a canonical
// principal. The mapping is versioned so a change to it is observable, and it
// names the SUBJECT claim explicitly so no code path can fall back to an email
// when the configured claim is absent.
type ClaimMapping struct {
	// Version identifies this mapping. Bumping it changes the identity epoch.
	Version int
	// SubjectClaim is the claim carrying the realm's immutable subject id.
	// Required. It is never defaulted to "email".
	SubjectClaim string
	// SubjectType is the canonical kind a credential from this realm asserts
	// when the credential does not carry one of its own.
	SubjectType SubjectType
	// AliasClaims maps alias kinds to the claims that carry them. Aliases are
	// recorded with provenance and never become identifiers.
	AliasClaims map[AliasKind]string
}

// TrustRealm is one organization-scoped identity source.
//
// It is a value type and is copied out of the registry on lookup, so a caller
// cannot mutate registered configuration by holding a pointer. Slices and maps
// inside it are deep-copied by the registry for the same reason.
type TrustRealm struct {
	// RealmID is the realm's canonical identifier within its organization.
	RealmID RealmID
	// OrgID is the owning organization. It is the RLS boundary (ADR-052 and
	// ADR-053) and a realm never spans organizations.
	OrgID string
	// Kind classifies the identity source.
	Kind RealmKind
	// CanonicalIssuer is the exact issuer string credentials must carry. It is
	// the registry's secondary lookup key, and it is unique per organization.
	CanonicalIssuer string
	// AcceptedSubjectTypes bounds what this realm may assert. Required and
	// non-empty.
	AcceptedSubjectTypes []SubjectType
	// AcceptedCredentialTypes bounds the credential classes. Required and
	// non-empty.
	AcceptedCredentialTypes []CredentialType
	// Audiences is the set of accepted `aud` values. Required and non-empty:
	// an unbounded audience is a token usable anywhere.
	Audiences []string
	// AuthorizedPartyPolicy declares whether azp is checked at all. Required.
	AuthorizedPartyPolicy AuthorizedPartyPolicy
	// AuthorizedParties is the allow-list consulted under
	// AuthorizedPartyAllowList. Required non-empty in that case, refused
	// otherwise.
	AuthorizedParties []string
	// AllowedSigningAlgorithms is the algorithm allow-list. Required and
	// non-empty; "none" is refused by Validate.
	AllowedSigningAlgorithms []string
	// ClaimMapping declares how claims become a canonical principal.
	ClaimMapping ClaimMapping
	// MinimumAssurance is the lowest acceptable assurance class. Required.
	MinimumAssurance AssuranceClass
	// ClockSkew is the tolerance applied to time claims. Required, bounded by
	// maxRealmClockSkew.
	ClockSkew time.Duration
	// CredentialAgePolicy declares whether MaxCredentialAge applies. Required.
	CredentialAgePolicy CredentialAgePolicy
	// MaxCredentialAge bounds how old an unexpired credential may be. Required
	// positive under CredentialAgeBounded, refused otherwise.
	MaxCredentialAge time.Duration
	// Directory declares the group graph. Required, and the field EX-45 and
	// EX-47 turn on.
	Directory DirectorySource
	// Interactive declares whether subjects here can answer a question.
	// Required, and EX-46's field.
	Interactive InteractiveClass
	// Revocation declares the revocation channel. Required.
	Revocation RevocationSource
	// Delegation declares which realms may act on behalf of subjects here.
	// Required.
	Delegation DelegationPolicy
	// DelegateRealms is the allow-list consulted when Delegation is
	// DelegationAllowList. Required non-empty in that case, refused otherwise.
	DelegateRealms []RealmID
	// Enabled is the administrative on/off switch. A disabled realm is
	// REALM_DISABLED, which is distinct from UNKNOWN_REALM because the
	// remedies differ.
	Enabled bool
	// Version is the realm's configuration version. It contributes to the
	// identity epoch, so a change to a realm invalidates cached closures and
	// decision proofs bound to the old epoch.
	Version int64
}

// maxRealmClockSkew bounds the skew an operator may declare. Five minutes is
// the widely used ceiling; beyond it, an expired credential stays usable for
// long enough that expiry stops being a control.
const maxRealmClockSkew = 5 * time.Minute

// HasGroupGraph reports whether closures over this realm can be non-empty.
func (r TrustRealm) HasGroupGraph() bool { return r.Directory.HasGroupGraph() }

// CanAnswerApprovals reports whether subjects in this realm can answer an
// escalation. EX-46.
func (r TrustRealm) CanAnswerApprovals() bool { return r.Interactive.CanAnswer() }

// AcceptsSubjectType reports whether this realm may assert t.
func (r TrustRealm) AcceptsSubjectType(t SubjectType) bool {
	for _, allowed := range r.AcceptedSubjectTypes {
		if allowed == t {
			return true
		}
	}
	return false
}

// AcceptsCredentialType reports whether this realm accepts credential class c.
func (r TrustRealm) AcceptsCredentialType(c CredentialType) bool {
	for _, allowed := range r.AcceptedCredentialTypes {
		if allowed == c {
			return true
		}
	}
	return false
}

// PermitsDelegateRealm reports whether a hop asserted by delegate may act on
// behalf of a subject asserted by this realm.
func (r TrustRealm) PermitsDelegateRealm(delegate RealmID) bool {
	switch r.Delegation {
	case DelegationAnyRealmInOrg:
		return true
	case DelegationAllowList:
		for _, allowed := range r.DelegateRealms {
			if allowed == delegate {
				return true
			}
		}
		return false
	case DelegationDenied, DelegationUnspecified:
		return false
	default:
		// An unrecognized policy value is not a permit. A new policy constant
		// added without updating this switch fails closed.
		return false
	}
}

// Validate checks a realm's internal consistency. Register calls it, so an
// invalid realm never enters the registry; it is exported so an admin API can
// reject a bad configuration at the edge with the same rules.
//
// Every tri-state field is checked for its zero value here. That check is the
// second half of the EX-47 fix: see the file doc.
func (r TrustRealm) Validate() error {
	if err := ValidateRealmID(r.RealmID); err != nil {
		return err
	}
	if strings.TrimSpace(r.OrgID) == "" {
		return fmt.Errorf("identity: realm %q has no org_id; a realm never spans organizations", r.RealmID)
	}
	if !r.Kind.IsValid() {
		return fmt.Errorf("identity: realm %q has unknown kind %q (known: %v)", r.RealmID, r.Kind, realmKinds)
	}
	if strings.TrimSpace(r.CanonicalIssuer) == "" {
		return fmt.Errorf("identity: realm %q has no canonical issuer", r.RealmID)
	}
	if len(r.AcceptedSubjectTypes) == 0 {
		return fmt.Errorf("identity: realm %q accepts no subject types", r.RealmID)
	}
	for _, t := range r.AcceptedSubjectTypes {
		if !t.IsValid() {
			return fmt.Errorf("identity: realm %q accepts unknown subject type %q", r.RealmID, t)
		}
	}
	if len(r.AcceptedCredentialTypes) == 0 {
		return fmt.Errorf("identity: realm %q accepts no credential types", r.RealmID)
	}
	for _, c := range r.AcceptedCredentialTypes {
		if !c.IsValid() {
			return fmt.Errorf("identity: realm %q accepts unknown credential type %q", r.RealmID, c)
		}
	}
	if len(r.Audiences) == 0 {
		return fmt.Errorf("identity: realm %q declares no audiences; an unbounded audience is a credential usable anywhere", r.RealmID)
	}
	for _, aud := range r.Audiences {
		if strings.TrimSpace(aud) == "" {
			return fmt.Errorf("identity: realm %q declares an empty audience", r.RealmID)
		}
	}
	if !r.AuthorizedPartyPolicy.IsValid() {
		return fmt.Errorf(
			"identity: realm %q declares authorized-party policy %s; declare AuthorizedPartyNotChecked to state that it does not check azp",
			r.RealmID, r.AuthorizedPartyPolicy)
	}
	if r.AuthorizedPartyPolicy == AuthorizedPartyAllowList && len(r.AuthorizedParties) == 0 {
		return fmt.Errorf("identity: realm %q pins its authorized parties with an empty list; declare AuthorizedPartyNotChecked instead", r.RealmID)
	}
	if r.AuthorizedPartyPolicy != AuthorizedPartyAllowList && len(r.AuthorizedParties) > 0 {
		return fmt.Errorf("identity: realm %q lists authorized parties under policy %s, which does not consult them", r.RealmID, r.AuthorizedPartyPolicy)
	}
	for _, azp := range r.AuthorizedParties {
		if strings.TrimSpace(azp) == "" {
			return fmt.Errorf("identity: realm %q declares an empty authorized party", r.RealmID)
		}
	}
	if len(r.AllowedSigningAlgorithms) == 0 {
		return fmt.Errorf("identity: realm %q declares no signing algorithms", r.RealmID)
	}
	for _, alg := range r.AllowedSigningAlgorithms {
		trimmed := strings.TrimSpace(alg)
		if trimmed == "" {
			return fmt.Errorf("identity: realm %q declares an empty signing algorithm", r.RealmID)
		}
		if strings.EqualFold(trimmed, "none") {
			return fmt.Errorf("identity: realm %q allows the %q algorithm, which is an unsigned credential", r.RealmID, alg)
		}
	}
	if r.ClaimMapping.Version <= 0 {
		return fmt.Errorf("identity: realm %q has no claim-mapping version", r.RealmID)
	}
	if strings.TrimSpace(r.ClaimMapping.SubjectClaim) == "" {
		return fmt.Errorf("identity: realm %q declares no subject claim; it is never defaulted to an alias claim such as email", r.RealmID)
	}
	if !r.ClaimMapping.SubjectType.IsValid() {
		return fmt.Errorf("identity: realm %q claim mapping asserts unknown subject type %q", r.RealmID, r.ClaimMapping.SubjectType)
	}
	if !r.AcceptsSubjectType(r.ClaimMapping.SubjectType) {
		return fmt.Errorf("identity: realm %q claim mapping asserts subject type %q, which the realm does not accept", r.RealmID, r.ClaimMapping.SubjectType)
	}
	for kind, claim := range r.ClaimMapping.AliasClaims {
		if strings.TrimSpace(claim) == "" {
			return fmt.Errorf("identity: realm %q maps alias %q to an empty claim", r.RealmID, kind)
		}
		if claim == r.ClaimMapping.SubjectClaim {
			// The configuration route to "an email is an identifier". Without
			// this check an operator can point SubjectClaim at the same claim
			// they mapped as AliasEmail, and every downstream invariant about
			// aliases never being keys is satisfied while the canonical
			// subject IS the email. ADR-065 invariant 3 has to be enforced
			// here, because no code path downstream can tell the difference.
			return fmt.Errorf(
				"identity: realm %q uses claim %q as both its canonical subject and its %q alias; an alias is never an identifier",
				r.RealmID, claim, kind)
		}
	}
	if !r.MinimumAssurance.IsValid() {
		return fmt.Errorf("identity: realm %q declares minimum assurance %s, which is not a declared class", r.RealmID, r.MinimumAssurance)
	}
	if r.Kind == RealmKindTrustedHeader && r.MinimumAssurance > AssuranceLow {
		return fmt.Errorf(
			"identity: realm %q is a trusted-header realm declaring assurance %s; AxonFlow does not verify the upstream's authentication, so it cannot attest more than %s",
			r.RealmID, r.MinimumAssurance, AssuranceLow)
	}
	if r.ClockSkew < 0 {
		return fmt.Errorf("identity: realm %q declares a negative clock skew", r.RealmID)
	}
	if r.ClockSkew > maxRealmClockSkew {
		return fmt.Errorf("identity: realm %q declares clock skew %s, above the %s ceiling", r.RealmID, r.ClockSkew, maxRealmClockSkew)
	}
	if !r.CredentialAgePolicy.IsValid() {
		return fmt.Errorf(
			"identity: realm %q declares credential-age policy %s; declare CredentialAgeUnbounded to state that it does not bound age",
			r.RealmID, r.CredentialAgePolicy)
	}
	if r.CredentialAgePolicy == CredentialAgeBounded && r.MaxCredentialAge <= 0 {
		return fmt.Errorf("identity: realm %q declares a bounded credential age of %s; the bound must be positive", r.RealmID, r.MaxCredentialAge)
	}
	if r.CredentialAgePolicy != CredentialAgeBounded && r.MaxCredentialAge != 0 {
		return fmt.Errorf("identity: realm %q sets a maximum credential age under policy %s, which does not apply it", r.RealmID, r.CredentialAgePolicy)
	}
	if !r.Directory.IsValid() {
		return fmt.Errorf(
			"identity: realm %q declares directory source %s; an undeclared or unrecognized source reads as 'no group graph' and would make an empty closure look authoritative (EX-47)",
			r.RealmID, r.Directory)
	}
	if !r.Interactive.IsValid() {
		return fmt.Errorf("identity: realm %q declares interactivity %s, which is not a declared class", r.RealmID, r.Interactive)
	}
	if !r.Revocation.IsValid() {
		return fmt.Errorf("identity: realm %q declares revocation source %s; declare RevocationSourceNone to state that it has none", r.RealmID, r.Revocation)
	}
	if !r.Delegation.IsValid() {
		return fmt.Errorf("identity: realm %q declares delegation policy %s, which is not a declared policy", r.RealmID, r.Delegation)
	}
	if r.Delegation == DelegationAllowList && len(r.DelegateRealms) == 0 {
		return fmt.Errorf("identity: realm %q declares an allow-list delegation policy with an empty list; declare DelegationDenied instead", r.RealmID)
	}
	if r.Delegation != DelegationAllowList && len(r.DelegateRealms) > 0 {
		return fmt.Errorf("identity: realm %q lists delegate realms under policy %s, which does not consult them", r.RealmID, r.Delegation)
	}
	for _, d := range r.DelegateRealms {
		if err := ValidateRealmID(d); err != nil {
			return fmt.Errorf("identity: realm %q lists an invalid delegate realm: %w", r.RealmID, err)
		}
	}
	if r.Version <= 0 {
		return fmt.Errorf("identity: realm %q has no configuration version", r.RealmID)
	}
	return nil
}

// clone returns a deep copy so registry state cannot be mutated through a
// slice or map header handed to a caller.
func (r TrustRealm) clone() TrustRealm {
	out := r
	out.AcceptedSubjectTypes = append([]SubjectType(nil), r.AcceptedSubjectTypes...)
	out.AcceptedCredentialTypes = append([]CredentialType(nil), r.AcceptedCredentialTypes...)
	out.Audiences = append([]string(nil), r.Audiences...)
	out.AuthorizedParties = append([]string(nil), r.AuthorizedParties...)
	out.AllowedSigningAlgorithms = append([]string(nil), r.AllowedSigningAlgorithms...)
	out.DelegateRealms = append([]RealmID(nil), r.DelegateRealms...)
	if r.ClaimMapping.AliasClaims != nil {
		aliases := make(map[AliasKind]string, len(r.ClaimMapping.AliasClaims))
		for k, v := range r.ClaimMapping.AliasClaims {
			aliases[k] = v
		}
		out.ClaimMapping.AliasClaims = aliases
	}
	return out
}

// RealmRegistry holds the trust realms of one or more organizations.
//
// Lookups are always org-scoped. There is no method that finds a realm without
// an organization, because a realm id or an issuer string is only unique
// within an organization: two customers can legitimately both federate the
// same public IdP, and a cross-org lookup would let one customer's declaration
// answer for the other.
//
// This first implementation is in-memory. ADR-065 Phase 1 persists realms, and
// that migration is deliberately not in this change: the registry's contract
// is what the rest of the plane compiles against, and it does not change when
// the backing store does.
type RealmRegistry struct {
	mu sync.RWMutex
	// byID is keyed (orgID, realmID).
	byID map[realmKey]TrustRealm
	// byIssuer is keyed (orgID, canonicalIssuer). It is the EX-47 lookup: the
	// credential presents an issuer, and a miss here is UNKNOWN_REALM.
	byIssuer map[realmKey]RealmID
	// epoch increments on every mutation. It is the identity epoch a decision
	// proof binds, so a realm change invalidates proofs rather than silently
	// changing what a principal means.
	epoch int64
}

// realmKey is the org-scoped composite key. A struct rather than a joined
// string so no separator can be smuggled through an org id.
type realmKey struct {
	org   string
	value string
}

// NewRealmRegistry builds an empty registry.
func NewRealmRegistry() *RealmRegistry {
	return &RealmRegistry{
		byID:     make(map[realmKey]TrustRealm),
		byIssuer: make(map[realmKey]RealmID),
		epoch:    1,
	}
}

// Register validates and stores a realm, replacing any realm with the same
// (org, realm id). It refuses a realm whose canonical issuer is already claimed
// by a DIFFERENT realm in the same organization: an issuer that resolves to two
// realms has no determinate answer, and picking one would be arbitrary.
func (reg *RealmRegistry) Register(realm TrustRealm) error {
	if err := realm.Validate(); err != nil {
		return err
	}
	stored := realm.clone()

	reg.mu.Lock()
	defer reg.mu.Unlock()

	issuerK := realmKey{org: stored.OrgID, value: stored.CanonicalIssuer}
	if existing, ok := reg.byIssuer[issuerK]; ok && existing != stored.RealmID {
		return fmt.Errorf(
			"identity: issuer %q in org %q is already declared by realm %q; an issuer resolving to two realms has no determinate answer",
			stored.CanonicalIssuer, stored.OrgID, existing)
	}

	idK := realmKey{org: stored.OrgID, value: string(stored.RealmID)}
	if prior, ok := reg.byID[idK]; ok && stored.Version <= prior.Version {
		// Version must ADVANCE on a re-registration, because it is not just a
		// label: a no-graph closure derives its recorded source version from
		// it, so two materially different declarations sharing a version
		// produce closures that are indistinguishable in a decision proof and
		// in replay. Without this the field documents nothing and the
		// staleness it is supposed to make detectable is not.
		return fmt.Errorf(
			"identity: realm %q is already registered at version %d and this registration carries version %d; a re-registration must advance the version",
			stored.RealmID, prior.Version, stored.Version)
	}
	if prior, ok := reg.byID[idK]; ok && prior.CanonicalIssuer != stored.CanonicalIssuer {
		// Re-registering under a new issuer: drop the stale issuer index entry
		// so the old issuer stops resolving. Leaving it would keep a
		// withdrawn issuer admissible, which is EX-47 in reverse.
		delete(reg.byIssuer, realmKey{org: prior.OrgID, value: prior.CanonicalIssuer})
	}

	reg.byID[idK] = stored
	reg.byIssuer[issuerK] = stored.RealmID
	reg.epoch++
	return nil
}

// Remove deletes a realm and its issuer index entry. A removed realm is
// UNKNOWN_REALM again, not a realm with default settings.
func (reg *RealmRegistry) Remove(orgID string, id RealmID) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	idK := realmKey{org: orgID, value: string(id)}
	prior, ok := reg.byID[idK]
	if !ok {
		return
	}
	delete(reg.byID, idK)
	delete(reg.byIssuer, realmKey{org: prior.OrgID, value: prior.CanonicalIssuer})
	reg.epoch++
}

// Lookup returns the realm declared for (orgID, id).
//
// The second return value is the whole contract: false means NO realm, and
// every caller in this package turns that into Deny(UNKNOWN_REALM). The
// returned TrustRealm on a miss is the zero value, and callers must not read
// it. That is why HasGroupGraph, CanAnswerApprovals and PermitsDelegateRealm
// all answer conservatively on a zero realm: a caller that ignores ok gets a
// refusal, not a permit.
func (reg *RealmRegistry) Lookup(orgID string, id RealmID) (TrustRealm, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	realm, ok := reg.byID[realmKey{org: orgID, value: string(id)}]
	if !ok {
		return TrustRealm{}, false
	}
	return realm.clone(), true
}

// lookupByIssuerAtEpoch resolves an issuer AND reads the identity epoch under a
// single lock, so the two cannot disagree. See VerifyCredential for why.
func (reg *RealmRegistry) lookupByIssuerAtEpoch(orgID, issuer string) (TrustRealm, int64, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	id, ok := reg.byIssuer[realmKey{org: orgID, value: issuer}]
	if !ok {
		return TrustRealm{}, reg.epoch, false
	}
	realm, ok := reg.byID[realmKey{org: orgID, value: string(id)}]
	if !ok {
		return TrustRealm{}, reg.epoch, false
	}
	return realm.clone(), reg.epoch, true
}

// LookupByIssuer resolves a credential's issuer to the realm declaring it,
// within one organization. This is the EX-47 gate: a validly signed credential
// from an issuer with no declared realm misses here and is denied before any
// policy loads.
func (reg *RealmRegistry) LookupByIssuer(orgID, issuer string) (TrustRealm, bool) {
	realm, _, ok := reg.lookupByIssuerAtEpoch(orgID, issuer)
	return realm, ok
}

// Epoch returns the current identity epoch. It increments on every mutation,
// so a cached closure or a decision proof bound to an older epoch is
// detectably stale rather than silently wrong.
func (reg *RealmRegistry) Epoch() int64 {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.epoch
}

// RealmIDs lists the realms declared for one organization, sorted. Used by
// operator tooling and by the authoring-time checks; never by a hot path.
func (reg *RealmRegistry) RealmIDs(orgID string) []RealmID {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	var out []RealmID
	for k := range reg.byID {
		if k.org == orgID {
			out = append(out, RealmID(k.value))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
