// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SubjectAdmitter verifies a request's credential against its organization's
// trust realms and admits the subject an enforcing decision plane evaluates
// for (ADR-065 invariant 2; PRD v11 §1.6).
//
// It holds what verification needs and nothing else: the realm registry, the
// source that establishes an organization's realms in it, the revocation
// oracle consulted for realms that declare one, and a clock.
type SubjectAdmitter struct {
	registry    *RealmRegistry
	realms      RealmSource
	revocations RevocationOracle
	now         func() time.Time
}

// SubjectAdmitterOption customizes the admitter.
type SubjectAdmitterOption func(*SubjectAdmitter)

// WithAdmitterClock overrides the clock. Test seam only.
func WithAdmitterClock(now func() time.Time) SubjectAdmitterOption {
	return func(a *SubjectAdmitter) {
		if now != nil {
			a.now = now
		}
	}
}

// WithAdmitterRevocations wires the revocation oracle consulted for realms that
// declare a revocation source. Absent it, such a realm yields
// Indeterminate(REVOCATION_UNAVAILABLE) - which is correct and is why this is
// an option rather than a required argument: a deployment whose realms all
// declare RevocationSourceNone needs no oracle.
func WithAdmitterRevocations(o RevocationOracle) SubjectAdmitterOption {
	return func(a *SubjectAdmitter) { a.revocations = o }
}

// NewSubjectAdmitter builds an admitter. A nil registry leaves nothing to verify
// against, and a nil realm source declares no realm, so every credential would
// be refused UNKNOWN_REALM: both are refused here rather than at the first
// request.
func NewSubjectAdmitter(registry *RealmRegistry, realms RealmSource, opts ...SubjectAdmitterOption) (*SubjectAdmitter, error) {
	if registry == nil {
		return nil, fmt.Errorf("identity: a subject admitter requires a realm registry")
	}
	if realms == nil {
		return nil, fmt.Errorf("identity: a subject admitter requires a realm source; without one every credential is UNKNOWN_REALM")
	}
	a := &SubjectAdmitter{registry: registry, realms: realms, now: time.Now}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// RealmSource registers an organization's trust realms into the registry
// on demand. It is separate from the registry so that where realms COME from
// (built-in deployment realms today, a persisted table in a later PR) can
// change without touching the admitter.
type RealmSource interface {
	// EnsureRealms registers orgID's realms, idempotently. It must be safe to
	// call on every request. An error means the organization's realms could
	// not be established, which is an outage, not an empty realm set.
	EnsureRealms(ctx context.Context, orgID string) error
}

// AdmitDecisionSubject verifies a path's credential through this admitter's
// realms and admits it as the ROOT of a one-hop actor chain, for an enforcing
// decision plane (#3895 PR-A2).
//
// It prepares the credential (prepareCredential: input validation, realm
// establishment, credential completion from the realm's claim mapping) and
// hands it to VerifyChain, the one place per-credential verification and
// AdmitChain compose, then applies the re-declaration check. It adds no rule of
// its own. In particular ADR-065 invariant 2 - a client credential is
// attribution and cannot be the authority a request is evaluated for - is
// AdmitChain's, reached here rather than restated. A request that carries no
// user identity is admitted through AdmitCredentialSubject.
//
// On refusal the chain is nil. A Deny is a determinate refusal of THIS
// credential; an Indeterminate means the plane could not reach an answer (no
// authenticated organization, realms that could not be established, a
// credential the path could not verify) and the caller fails closed.
func (a *SubjectAdmitter) AdmitDecisionSubject(ctx context.Context, in CredentialPrincipal, maxDepth int) (ActorChain, Admission) {
	return a.admitSubject(ctx, in, maxDepth, rootNeverClient)
}

// AdmitCredentialSubject admits a request's authenticated CLIENT CREDENTIAL as
// the principal a decision is evaluated for, for a request that carries no user
// identity: every request on a deployment that can verify none (Community,
// Community-SaaS) and every request on a route that carries none (the
// OpenAI-compatible route). ADR-065 invariant 2 as amended 2026-09-11 (third);
// PRD v11 §1.6.
//
// ONLY A CREDENTIAL PATH ENTERS HERE. A user-token path - HS256, OIDC, a trusted
// identity header - is refused SUBJECT_TYPE_REJECTED before anything is
// verified: it asserts a user identity, verified or not, and that is
// AdmitDecisionSubject's to decide. Admission is for the ABSENCE of a user
// identity, never for a bad one.
//
// Everything else is AdmitDecisionSubject's pipeline: the credential is
// verified against its realm and the chain admitted, with the one difference
// that a Client may be the root. The admitted principal is that Client (or the
// Service an internal-service hop authenticates), and the caller records it as
// the subject type the decision was evaluated for.
func (a *SubjectAdmitter) AdmitCredentialSubject(ctx context.Context, in CredentialPrincipal, maxDepth int) (ActorChain, Admission) {
	if in.Path != CredentialPathAPICredential {
		return nil, DenyAdmission(ReasonSubjectTypeRejected, fmt.Sprintf(
			"the %s path asserts a user identity; the credential principal is admitted only for a request that carries none", in.Path))
	}
	return a.admitSubject(ctx, in, maxDepth, rootMayBeCredential)
}

func (a *SubjectAdmitter) admitSubject(ctx context.Context, in CredentialPrincipal, maxDepth int, root chainRoot) (ActorChain, Admission) {
	if a == nil {
		return nil, IndeterminateAdmission(ReasonIdentityInternalError,
			"no subject admitter is installed in this process, so no decision subject can be verified")
	}
	in.AuthenticatedOrgID = strings.TrimSpace(in.AuthenticatedOrgID)
	prep := a.prepareCredential(ctx, in)
	if prep.refusal != nil {
		return nil, *prep.refusal
	}
	chain, subjects, adm := verifyChain(a.registry, in.AuthenticatedOrgID, []Credential{prep.cred}, maxDepth, a.now(), a.revocations, root)
	if adm.State.IsAdmitted() && len(subjects) == 1 && prep.staleMapping(subjects[0]) {
		return nil, IndeterminateAdmission(ReasonIdentityInternalError, staleMappingDetail)
	}
	return chain, adm
}

// preparedCredential is what the verification pipeline's shared preparation
// produced: the credential to verify, or the refusal it stopped at.
type preparedCredential struct {
	cred         Credential
	mappingRealm TrustRealm
	mappingFound bool
	// refusal is non-nil when preparation stopped before verification.
	refusal *Admission
	// defect reports that the stop was a call-site input defect - the
	// call site handed over a malformed CredentialPrincipal - rather than a fact about
	// the credential.
	defect bool
}

// prepareCredential runs the steps every admission takes before
// VerifyCredential, in order. AdmitDecisionSubject and AdmitCredentialSubject
// both reach it through admitSubject, so the two doors cannot disagree about
// when a credential is verifiable at all.
func (a *SubjectAdmitter) prepareCredential(ctx context.Context, in CredentialPrincipal) preparedCredential {
	// Call-site input defects. These are a bug in the code that built the
	// CredentialPrincipal, not a fact about the caller's credential, so they
	// are IDENTITY_INTERNAL_ERROR rather than a Deny naming the credential: an
	// enforcing plane fails closed on the Indeterminate, and its log names the
	// defect rather than blaming a token that is fine.
	if defect := validateCredentialPrincipal(in); defect != "" {
		adm := IndeterminateAdmission(ReasonIdentityInternalError, defect)
		return preparedCredential{refusal: &adm, defect: true}
	}

	// Realms first. A realm source that cannot answer is an outage, and an
	// outage is Indeterminate - never an empty realm set, which would present
	// as UNKNOWN_REALM and send an operator to declare a realm that already
	// exists.
	realmCtx, cancelRealms := boundedRealmContext(ctx)
	realmErr := a.realms.EnsureRealms(realmCtx, in.AuthenticatedOrgID)
	cancelRealms()
	if realmErr != nil && !a.issuerIsDeclared(in) {
		// The realm source could not answer AND this credential's issuer does
		// not resolve, so nothing can be said about it.
		//
		// THE ISSUER CHECK IS WHAT KEEPS ONE SOURCE'S FAILURE FROM TAKING DOWN
		// THE OTHERS. A realm source is a chain: the built-ins register once
		// and never fail again, while the tenant OIDC source reads a database
		// row on a TTL and can fail for reasons that have nothing to do with
		// the credential in hand. Without this, one unreadable
		// sso_configurations row refused EVERY path for that organization
		// under enforce - the client credential, the internal-service hop and
		// the HS256 token included, none of which involves OIDC.
		//
		// It is not a fail-open: a resolved issuer means that realm's full
		// declaration is registered and VerifyCredential applies all of it. A
		// credential whose issuer is genuinely undeclared still cannot be
		// distinguished from one whose realm could not be read, which is why
		// that case stays Indeterminate rather than becoming UNKNOWN_REALM.
		adm := IndeterminateAdmission(
			ReasonIdentityInternalError,
			fmt.Sprintf("the organization's trust realms could not be established: %v", realmErr))
		return preparedCredential{refusal: &adm}
	}

	// A path that could not reach a verdict short-circuits realm
	// verification. Running it anyway would produce SIGNATURE_NOT_VERIFIED -
	// technically true, since nothing verified the signature, and the wrong
	// answer to give an operator whose IdP is down. validateCredentialPrincipal has
	// already established that this can only be an Indeterminate cause paired
	// with a path rejection, so this branch can never widen anything.
	if in.UnverifiableReason != "" {
		adm := IndeterminateAdmission(
			in.UnverifiableReason,
			fmt.Sprintf("the %s path could not obtain what it needed to verify the credential", in.Path))
		return preparedCredential{refusal: &adm}
	}

	cred, mappingRealm, mappingFound := a.completeCredential(in)
	return preparedCredential{cred: cred, mappingRealm: mappingRealm, mappingFound: mappingFound}
}

// staleMappingDetail is the refusal detail for staleMapping's condition.
const staleMappingDetail = "the realm was re-declared between reading its claim mapping and verifying against it; the subject was mapped by a declaration that is no longer live"

// staleMapping reports that the subject was admitted under a realm declaration
// other than the one its claim mapping was read from.
//
// THE CLAIM MAPPING AND THE VERIFICATION CAME FROM TWO SEPARATE LOOKUPS.
//
// completeCredential reads the realm to learn which claim is canonical;
// VerifyCredential reads it again, under its own lock, together with the
// epoch. realm_verify.go argues at length that the realm and the epoch must be
// read under ONE lock, and this pipeline reintroduces exactly that window one
// frame up: a concurrent re-registration between the two reads would extract
// the subject with the OLD mapping and then stamp the NEW epoch onto it, so a
// proof that should be detectably stale reads as current.
//
// Rather than restructure a merged API, the two are compared. A disagreement
// is Indeterminate: the subject in hand was mapped by a declaration that is no
// longer the live one, and re-deriving it would just race again.
func (p preparedCredential) staleMapping(subject VerifiedSubject) bool {
	return p.mappingFound && subject.Admission.State.IsAdmitted() &&
		(subject.Realm.Version != p.mappingRealm.Version ||
			subject.Realm.ClaimMapping.Version != p.mappingRealm.ClaimMapping.Version)
}

// validateCredentialPrincipal returns a non-empty description of a call-site input
// defect, or "".
func validateCredentialPrincipal(in CredentialPrincipal) string {
	if !in.Path.IsValid() {
		return fmt.Sprintf("credential path %q is not one of the declared paths %v", in.Path, credentialPaths)
	}
	if !in.Decision.IsValid() {
		return fmt.Sprintf("path decision %s is not one of the declared decisions; a caller that leaves it at its zero value would present a rejection it never made", in.Decision)
	}
	if strings.TrimSpace(in.AuthenticatedOrgID) == "" {
		// VerifyCredential would also refuse this, with ORG_BINDING_MISMATCH.
		// It is caught here instead because an empty authenticated org on THIS
		// side means the call site did not pass one, which is a call-site
		// wiring defect, not a property of the caller's credential - and
		// attributing it to the caller would send an operator to inspect
		// tokens that are fine.
		return "the call site passed no authenticated organization; the identity plane cannot bind a subject without one"
	}
	if in.Claims == nil {
		// Every one of the four paths presents a claim set, including the two
		// that carry no JWT (their asserted values are presented under the
		// pseudo-claim keys the built-in realms name). A nil map would make
		// completeCredential a no-op and leave the subject wherever the caller
		// put it, which is the next check.
		return "the call site presented no claim set; the canonical subject is taken from the realm's claim mapping, so there is nothing to map"
	}
	if in.Credential.Subject != "" {
		// THE CALLER MAY NOT SUPPLY A SUBJECT. completeCredential overwrites
		// it from the realm's mapping, so a supplied value is either ignored
		// (harmless but misleading) or, if the realm lookup misses, carried
		// through to a refusal that names it. Refusing it outright is what
		// keeps "an alias is never an identifier" a property of this package
		// rather than of each builder's discipline.
		return "the call site supplied a canonical subject; the subject is taken from the realm's claim mapping and never from the admitter's caller"
	}
	if in.UnverifiableReason != "" {
		if !unverifiableReasons[in.UnverifiableReason] {
			return fmt.Sprintf(
				"path reported unverifiable reason %q, which is not one of the reasons a path may report; only an Indeterminate cause may be reported this way",
				in.UnverifiableReason)
		}
		if in.Decision != PathVerdictRejected {
			// A path that could not verify a credential cannot also have
			// accepted it. Allowing the pair would let an accepted request be
			// refused as an outage that never happened.
			return fmt.Sprintf(
				"path reported unverifiable reason %q alongside decision %s; a path that could not reach a verdict did not accept the credential",
				in.UnverifiableReason, in.Decision)
		}
	}
	return ""
}

// completeCredential fills the claim-derived fields of the credential from the
// realm's claim mapping.
//
// It looks the realm up by issuer to read the mapping, and on a MISS it
// returns the credential unchanged: VerifyCredential owns the UNKNOWN_REALM
// refusal and its wording, and duplicating that decision here is how two
// spellings of the same refusal start to drift.
func (a *SubjectAdmitter) completeCredential(in CredentialPrincipal) (Credential, TrustRealm, bool) {
	cred := in.Credential
	if in.Claims == nil {
		return cred, TrustRealm{}, false
	}
	realm, ok := a.registry.LookupByIssuer(in.AuthenticatedOrgID, cred.Issuer)
	if !ok {
		return cred, TrustRealm{}, false
	}
	// The mapping is authoritative for claim-bearing credentials. A
	// caller-supplied Subject is discarded, INCLUDING when the mapped claim is
	// absent - an absent subject claim must produce SUBJECT_MISSING, never a
	// fallback to whatever the caller happened to put there.
	cred.Subject = claimStringFromMap(in.Claims, realm.ClaimMapping.SubjectClaim)
	cred.Aliases = aliasesFromClaims(in.Claims, realm.ClaimMapping.AliasClaims)
	return cred, realm, true
}

// issuerIsDeclared reports whether this credential's issuer already resolves to
// a registered realm, so a failure elsewhere in the realm-source chain does not
// have to refuse it. A credential with no claim set carries no issuer to
// resolve and is not covered.
func (a *SubjectAdmitter) issuerIsDeclared(in CredentialPrincipal) bool {
	if strings.TrimSpace(in.Credential.Issuer) == "" {
		return false
	}
	_, ok := a.registry.LookupByIssuer(in.AuthenticatedOrgID, in.Credential.Issuer)
	return ok
}

// claimStringFromMap reads a string claim. A non-string value reads as absent:
// a claim the realm named as the canonical subject, delivered as a number or
// an object, is not a subject this plane can key on, and coercing it would
// make two different JSON shapes produce the same principal.
func claimStringFromMap(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// aliasesFromClaims collects the alias values for the alias kinds the realm
// declared a claim for. Kinds the realm did not map are not collected;
// buildAliases would drop them anyway, and collecting them here would put
// undeclared claim values into a struct that is logged.
func aliasesFromClaims(claims map[string]any, aliasClaims map[AliasKind]string) map[AliasKind]string {
	if len(aliasClaims) == 0 {
		return nil
	}
	var out map[AliasKind]string
	for kind, claim := range aliasClaims {
		v := claimStringFromMap(claims, claim)
		if v == "" {
			continue
		}
		if out == nil {
			out = make(map[AliasKind]string, len(aliasClaims))
		}
		out[kind] = v
	}
	return out
}

// realmTimeout bounds how long establishing an organization's realms may
// take on the authentication path.
//
// It is a bound ON TOP OF the caller's, not a replacement for it: the derived
// context still inherits the parent's cancellation, so an already-cancelled
// caller gets an immediately-failed EnsureRealms. That is correct for the
// storage read it wraps.
//
// The bound exists because a caller with no request context at all passes
// context.Background(), which would otherwise leave the read unbounded.
const realmTimeout = 2 * time.Second

// boundedRealmContext derives the context the realm source runs under.
func boundedRealmContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(nonNilContext(ctx), realmTimeout)
}

// nonNilContext is context.Background() for a nil context.
func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
