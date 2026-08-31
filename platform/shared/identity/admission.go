// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 identity-plane admission outcomes and reason codes (#3550 / #3556).
//
// The identity plane runs BEFORE any policy loads. Its job is to turn a
// presented credential into a canonical, realm-qualified principal, or to
// refuse. Refusal here is not a policy denial: it means the request never
// becomes evaluable, which is why the outcome type is separate from any
// policy verdict type and why it carries its own reason vocabulary.
//
// THE ZERO VALUE IS NOT SAFE, AND THAT IS DELIBERATE.
//
// AdmissionUnspecified is the zero value of AdmissionState. It is not Accept
// and it is not a benign default: a caller that forgets to set the field, or
// reads a struct that a failed constructor returned, gets a state that no
// consumer may treat as admitted. This is the single most important property
// in this file and it exists because of the EX-47 failure shape:
//
//	A validly signed token from an issuer with no declared realm reaches
//	evaluation with realm(p) undefined. A FALSY DEFAULT then reads as
//	has_group_graph = false, which makes an empty group closure look
//	AUTHORITATIVE (EX-45's legitimate outcome), and every segment-scoped
//	ceiling is silently skipped. A fail-open produced entirely by omission.
//
// Every enum in the ADR-065 identity plane therefore reserves its zero value
// for "not determined" and never for a permissive fact. See ClosureState in
// directory.go for the same rule applied to the group graph.
package identity

import "fmt"

// AdmissionState is the tri-state outcome of identity admission.
//
// Accept and Deny are determinate. Indeterminate means the plane could not
// establish the fact it needed (a directory source is unreachable, a closure
// hit its bounds) and is NOT a permit: under ADR-065 the caller's declared
// error posture resolves it, and the ADR removes the per-tool
// "on_error: Permit" option, so in the production profile Indeterminate
// resolves to Deny. The identity plane deliberately does not resolve it
// itself, because the posture belongs to the governed surface, not to
// identity.
type AdmissionState int

const (
	// AdmissionUnspecified is the zero value. No consumer may treat it as
	// admitted. See the file doc.
	AdmissionUnspecified AdmissionState = iota
	// AdmissionAccept means a canonical principal was established.
	AdmissionAccept
	// AdmissionDeny means the request is refused before policy loads.
	AdmissionDeny
	// AdmissionIndeterminate means a required identity fact could not be
	// established. Never a permit.
	AdmissionIndeterminate
)

// String renders the state for logs, traces, and test failure messages.
func (s AdmissionState) String() string {
	switch s {
	case AdmissionAccept:
		return "ACCEPT"
	case AdmissionDeny:
		return "DENY"
	case AdmissionIndeterminate:
		return "INDETERMINATE"
	case AdmissionUnspecified:
		return "UNSPECIFIED"
	default:
		return fmt.Sprintf("AdmissionState(%d)", int(s))
	}
}

// IsAdmitted reports whether this state establishes a usable principal. It is
// the ONLY sanctioned way to ask that question: a consumer writing
// `state != AdmissionDeny` would admit both Unspecified and Indeterminate.
func (s AdmissionState) IsAdmitted() bool { return s == AdmissionAccept }

// AdmissionReason is the stable, audit-safe reason vocabulary of the identity
// plane. Reason codes are contract: they appear in decision traces, in the
// conformance corpus, and in operator tooling, so they are added rather than
// renamed.
type AdmissionReason string

const (
	// ReasonNone is the zero value. A determinate outcome always carries a
	// reason, so an outcome holding ReasonNone alongside Deny is a defect and
	// the constructors below refuse to build one.
	ReasonNone AdmissionReason = ""

	// ReasonUnknownRealm is EX-47: the credential verified cryptographically
	// but its issuer has no declared TrustRealm in this organization. Denied
	// before policy loads, symmetric with an unknown tool.
	ReasonUnknownRealm AdmissionReason = "UNKNOWN_REALM"

	// ReasonRealmDisabled means the realm exists but is administratively
	// disabled. Distinct from UNKNOWN_REALM because the remedies differ: one
	// is "declare the directory", the other is "re-enable it".
	ReasonRealmDisabled AdmissionReason = "REALM_DISABLED"

	// ReasonOrgBindingMismatch is the #3488 acceptance criterion: the subject
	// organization asserted by the credential is not the organization the
	// credential itself authenticated as. Refused, never silently narrowed to
	// an org-only evaluation.
	ReasonOrgBindingMismatch AdmissionReason = "ORG_BINDING_MISMATCH"

	// ReasonSignatureNotVerified means the presented credential was not
	// cryptographically verified before it reached the realm layer. This layer
	// applies realm POLICY to an already-verified credential; it re-checks the
	// flag because the flag's zero value is false, so a caller that forgets to
	// set it gets a refusal rather than a realm-policy pass on unverified
	// material.
	ReasonSignatureNotVerified AdmissionReason = "SIGNATURE_NOT_VERIFIED"

	// ReasonUnsupportedAlgorithm means the credential's signing algorithm is
	// not in the realm's allow-list.
	ReasonUnsupportedAlgorithm AdmissionReason = "UNSUPPORTED_ALGORITHM"

	// ReasonUnsupportedCredentialType means the realm does not accept this
	// credential class (for example a bearer JWT presented to a realm that
	// only accepts SPIFFE SVIDs).
	ReasonUnsupportedCredentialType AdmissionReason = "UNSUPPORTED_CREDENTIAL_TYPE"

	// ReasonAudienceRejected means the credential's audience set does not
	// intersect the realm's accepted audiences.
	ReasonAudienceRejected AdmissionReason = "AUDIENCE_REJECTED"

	// ReasonAuthorizedPartyRejected means the credential's authorized party
	// (azp) is not in the realm's allow-list. Distinct from AUDIENCE_REJECTED:
	// aud says who the token is FOR, azp says which client obtained it, and
	// conflating them is how a token minted for one client is replayed by
	// another.
	ReasonAuthorizedPartyRejected AdmissionReason = "AUTHORIZED_PARTY_REJECTED"

	// ReasonSubjectTypeRejected means the realm does not accept this subject
	// type (for example a human user asserted by a workload-only realm).
	ReasonSubjectTypeRejected AdmissionReason = "SUBJECT_TYPE_REJECTED"

	// ReasonCredentialExpired means the credential is outside its validity
	// window after the realm's clock skew allowance.
	ReasonCredentialExpired AdmissionReason = "CREDENTIAL_EXPIRED"

	// ReasonCredentialNotYetValid means nbf/iat is in the future beyond the
	// realm's clock skew allowance.
	ReasonCredentialNotYetValid AdmissionReason = "CREDENTIAL_NOT_YET_VALID"

	// ReasonCredentialTooOld means the credential's issuance instant is older
	// than the realm's maximum accepted age, even though it has not expired.
	ReasonCredentialTooOld AdmissionReason = "CREDENTIAL_TOO_OLD"

	// ReasonAssuranceInsufficient means the credential's authentication
	// assurance class is below what the realm requires.
	ReasonAssuranceInsufficient AdmissionReason = "ASSURANCE_INSUFFICIENT"

	// ReasonCredentialRevoked means an authoritative revocation source names
	// this credential.
	ReasonCredentialRevoked AdmissionReason = "CREDENTIAL_REVOKED"

	// ReasonRevocationUnavailable means the realm declares a revocation source
	// and that source could not be consulted. Indeterminate, not Deny: the
	// distinction is what lets an operator see a revocation outage as an
	// outage rather than as a wave of denials with no cause.
	ReasonRevocationUnavailable AdmissionReason = "REVOCATION_UNAVAILABLE"

	// ReasonSubjectMissing means the credential carries no subject identifier,
	// or carries only an alias (email, display name) where a canonical subject
	// is required.
	ReasonSubjectMissing AdmissionReason = "SUBJECT_MISSING"

	// ReasonClaimMappingFailed means the realm's claim mapping could not
	// produce a canonical principal from the presented claims. A mapping error
	// is an authorization error, never a request with missing optional data.
	ReasonClaimMappingFailed AdmissionReason = "CLAIM_MAPPING_FAILED"

	// ReasonMalformedPrincipal means a principal identifier could not be
	// parsed into its canonical (realm, type, subject) form.
	ReasonMalformedPrincipal AdmissionReason = "MALFORMED_PRINCIPAL"

	// ReasonChainCycle means the actor chain visits the same principal twice.
	ReasonChainCycle AdmissionReason = "CHAIN_CYCLE"

	// ReasonChainEmpty means an actor chain with no hops was presented where
	// one is required. An empty chain has no authority to intersect and must
	// never read as unconstrained.
	ReasonChainEmpty AdmissionReason = "CHAIN_EMPTY"

	// ReasonDelegationDepth means the chain is longer than the governed
	// surface allows.
	ReasonDelegationDepth AdmissionReason = "DELEGATION_DEPTH"

	// ReasonDelegationNotPermitted means a realm in the chain is not permitted
	// to act as an intermediary for the preceding hop.
	ReasonDelegationNotPermitted AdmissionReason = "DELEGATION_NOT_PERMITTED"

	// ReasonClosureTruncated is EX-14: the group closure hit a bound, so the
	// resolved set may be missing an ancestor a ceiling is scoped to.
	// Indeterminate, never evaluated partially.
	ReasonClosureTruncated AdmissionReason = "CLOSURE_TRUNCATED"

	// ReasonClosureUnavailable is the SCIM-outage case: the realm HAS a group
	// graph and it could not be read. Indeterminate. Distinct from a realm
	// with no graph at all, which is authoritative and carries no reason.
	ReasonClosureUnavailable AdmissionReason = "CLOSURE_UNAVAILABLE"

	// ReasonEscalationUnreachable is EX-46 at runtime: an approver pool
	// resolves in a realm that cannot be asked a question.
	ReasonEscalationUnreachable AdmissionReason = "ESCALATION_UNREACHABLE"

	// ReasonQuorumUnreachable means an approval clause cannot be satisfied by a
	// pool whose members CAN answer: either fewer of them can answer than the
	// quorum requires, or the clause declares a non-positive quorum, which is
	// not an approval at all. Both are terminal and both are fixed on the
	// clause or the pool rather than on the realms.
	//
	// The "can answer" half of that is load-bearing and is why
	// ApproverQuorumReachable examines the pool BEFORE the quorum: reported on
	// a pool where nobody can answer, this code would send an operator to
	// adjust a quorum that was never the problem.
	//
	// It is deliberately distinct from ESCALATION_UNREACHABLE,
	// because the remedies differ: this one is fixed by lowering the quorum or
	// widening the pool, the other by fixing a pool whose members can never
	// answer at all. The approval plane (#3551) keys its verdicts on these two
	// strings, so collapsing them would make the two remedies
	// indistinguishable in the audit trail.
	ReasonQuorumUnreachable AdmissionReason = "QUORUM_UNREACHABLE"

	// ReasonIdentityInternalError means an invariant inside the identity plane
	// itself did not hold. It is Indeterminate, never a permit, and it is
	// deliberately not one of the operational codes: an operator paged with
	// UNKNOWN_REALM will go and declare a realm, which cannot help when the
	// actual fault is in this package.
	ReasonIdentityInternalError AdmissionReason = "IDENTITY_INTERNAL_ERROR"

	// ReasonPoolNotInteractive is EX-46 at authoring time: a policy naming an
	// approver pool in a non-interactive realm is refused at save, before it
	// can park a live escalation until timeout.
	ReasonPoolNotInteractive AdmissionReason = "POOL_NOT_INTERACTIVE"

	// ReasonKeyMaterialUnavailable means the verifying key material could not
	// be obtained: a JWKS endpoint that is unreachable, or a cached key set
	// that has aged past the bounded staleness window. Indeterminate, never
	// Deny.
	//
	// IT IS DELIBERATELY DISTINCT FROM SIGNATURE_NOT_VERIFIED, and the
	// distinction is the whole reason the code exists. Both arrive at the same
	// place - the credential is not admitted - and an operator paged with
	// "signature not verified" goes looking for forged tokens, which is
	// exactly the wrong investigation when the actual fact is that the IdP is
	// down. Collapsing an outage into a forgery is a diagnosis that costs
	// hours; the two also have opposite urgencies, since one is an availability
	// incident and the other is an attack.
	ReasonKeyMaterialUnavailable AdmissionReason = "KEY_MATERIAL_UNAVAILABLE"
)

// Admission is the outcome of an identity-plane check.
//
// It is constructed only through Accept/Deny/Indeterminate so that a Deny or
// Indeterminate can never be built without a reason, and an Accept can never
// be built without a principal. A struct literal built elsewhere in the
// package would bypass that, which is why Verify and Admit return this type by
// value from those constructors alone.
type Admission struct {
	// State is the tri-state outcome. Never read this field directly to decide
	// whether to proceed; call State.IsAdmitted.
	State AdmissionState
	// Reason is the stable reason code. Empty only for Accept.
	Reason AdmissionReason
	// Principal is the canonical principal. Zero unless State is Accept.
	Principal PrincipalID
	// Detail is a short, audit-safe explanation. It must never echo credential
	// material, and must never echo unsanitized caller input: the only
	// caller-influenced values rendered here are already-parsed canonical
	// identifiers and issuer URLs, both bounded by realm configuration.
	Detail string
}

// AcceptAdmission builds an admitted outcome. It panics on a zero principal
// because an admitted outcome with no principal is not a state this package is
// able to represent safely, and returning one would push the check onto every
// caller.
func AcceptAdmission(p PrincipalID) Admission {
	if p.IsZero() {
		panic("identity: AcceptAdmission called with a zero PrincipalID")
	}
	return Admission{State: AdmissionAccept, Principal: p}
}

// AcceptPoolAdmission builds an admitted outcome that is about a SET rather
// than a subject: an approver pool that can be answered, for instance.
//
// Its Principal is deliberately the zero value. The alternative, naming an
// arbitrary member of the set, is worse than it looks: the field then reads as
// "the principal this admission is about" while holding one the caller may
// have just excluded, and a consumer attributing an audit record from it names
// the wrong person. The zero principal matches nothing and is safe to read.
func AcceptPoolAdmission(detail string) Admission {
	return Admission{State: AdmissionAccept, Detail: detail}
}

// DenyAdmission builds a refusal. reason must be non-empty.
func DenyAdmission(reason AdmissionReason, detail string) Admission {
	if reason == ReasonNone {
		panic("identity: DenyAdmission called with no reason code")
	}
	return Admission{State: AdmissionDeny, Reason: reason, Detail: detail}
}

// IndeterminateAdmission builds an unresolvable outcome. reason must be
// non-empty.
func IndeterminateAdmission(reason AdmissionReason, detail string) Admission {
	if reason == ReasonNone {
		panic("identity: IndeterminateAdmission called with no reason code")
	}
	return Admission{State: AdmissionIndeterminate, Reason: reason, Detail: detail}
}

// String renders the admission for traces and test failures.
func (a Admission) String() string {
	if a.State == AdmissionAccept {
		if a.Principal.IsZero() {
			// A pool admission. Rendering the zero principal here would print
			// the wire form's separators around two empty components, which
			// reads as a corrupt identifier rather than as a deliberate
			// absence.
			if a.Detail == "" {
				return "ACCEPT(no subject)"
			}
			return fmt.Sprintf("ACCEPT(no subject: %s)", a.Detail)
		}
		return fmt.Sprintf("ACCEPT(%s)", a.Principal)
	}
	if a.Detail == "" {
		return fmt.Sprintf("%s(%s)", a.State, a.Reason)
	}
	return fmt.Sprintf("%s(%s: %s)", a.State, a.Reason, a.Detail)
}
