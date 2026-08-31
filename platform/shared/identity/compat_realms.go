// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Built-in trust realms for the four legacy credential paths (#3550).
//
// # THE DECLARATION PRINCIPLE
//
// Every realm here declares WHAT THE LEGACY PATH ALREADY ENFORCES, PLUS THE
// TWO INVARIANTS TrustRealm STRUCTURALLY REQUIRES, AND NOTHING ELSE.
//
// The two structural additions are named rather than hidden, because each
// produces a divergence class of its own and an unenumerated divergence is
// indistinguishable from a defect:
//
//  1. AN EXPIRY IS REQUIRED. checkCredentialTime denies a credential with no
//     `exp`, and the agent plane's validateUserToken does not pass
//     WithExpirationRequired, so a legacy token carrying no expiry
//     authenticates today and is refused here as CREDENTIAL_EXPIRED. Both
//     production minters stamp one, so this is latent rather than live.
//  2. AN AUDIENCE IS BOUNDED. TrustRealm refuses an empty audience list ("a
//     credential usable anywhere"), while the legacy HS256 path performs no
//     `aud` check at all. The realms therefore declare AudienceDeployment and
//     the builders present it for a credential that carries no `aud` - so a
//     token without one does not diverge, and a token minted for a DIFFERENT
//     audience is refused. Neither production minter sets `aud`, so this too
//     is latent.
//
// Everything else is derived from the legacy path.
//
// That is the difference between a shadow phase that is worth reading and one
// that is not. If these realms declared an audience the platform never
// checked, or an assurance floor nobody ever attested, every single request
// would diverge and the four findings that matter would be buried under a
// hundred thousand of my own invention. So: the minimum assurance is the
// lowest declarable class, the audience is the one the legacy path already
// pins (or the deployment itself, for credentials that have no audience
// concept), delegation is denied because no legacy path delegates, and the
// directory and revocation sources are read from what the deployment actually
// wired rather than from what it ought to have.
//
// # THE FOUR DIVERGENCES THIS IS EXPECTED TO SURFACE
//
// Each of these is a REAL fact about the installed platform, not an artifact
// of the realm declarations above:
//
//  1. UNKNOWN_REALM (EX-47). The agent plane's validateUserToken parses an
//     HS256 token with no issuer constraint at all, so a token carrying no
//     `iss`, or one no realm declares, authenticates today. Here it is denied
//     before policy loads. This is the single largest expected divergence and
//     it is the whole point of the epic.
//
//  2. ORG_BINDING_MISMATCH (#3488, carried into #3556). The same function reads org_id
//     straight out of the token with nothing binding it to the credential that
//     authenticated. A wrong-but-non-empty org claim is refused here.
//
//  3. REVOCATION_UNAVAILABLE. A realm that declares a revocation source and
//     receives a credential with no revocation key cannot be checked. Legacy
//     treats a jti-less token as unrevocable-and-therefore-fine; this plane
//     calls it what it is, which is indeterminate.
//
//  4. SUBJECT_MISSING on the trusted-header path. An upstream asserting only
//     X-User-Email has asserted an ALIAS, and ADR-065 invariant 3 is that an
//     alias is never an identifier. A trusted-header deployment that wants a
//     canonical principal has to assert a stable subject (X-User-ID); one that
//     asserts only an address gets attribution, not identity.
//
// A FIFTH, WHICH IS A PROPERTY OF THE MINTERS RATHER THAN OF THESE REALMS: both
// AxonFlow token minters set `sub` to the user's email address, so the
// canonical principal on the minted realm currently IS an email, recorded
// alongside itself as an AliasEmail. TrustRealm.Validate catches a claim used
// as both subject and alias by NAME and cannot see a collision by VALUE. That
// is a minting change, not a realm one, and it is named in the PR's
// items-not-modified rather than papered over here.
package identity

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Built-in realm identifiers. They are colon-free and whitespace-free by
// construction (ValidateRealmID), and unique within an organization, which is
// the registry's scope.
const (
	// BuiltinRealmMinted is the AxonFlow per-user token minting path (Path A).
	BuiltinRealmMinted RealmID = "axonflow-minted"
	// BuiltinRealmAPICredential is the client-credential path: the Ed25519
	// license key, the bcrypt API key, and the community-SaaS registration
	// secret.
	BuiltinRealmAPICredential RealmID = "axonflow-api-credential"
	// BuiltinRealmInternalService is the orchestrator-to-agent HMAC path.
	BuiltinRealmInternalService RealmID = "axonflow-internal-service"
	// BuiltinRealmCommunity is community mode, where no credential is
	// required at all.
	BuiltinRealmCommunity RealmID = "axonflow-community"
	// BuiltinRealmTrustedHeader is the #2896 trust-gated identity-header
	// upstream.
	BuiltinRealmTrustedHeader RealmID = "axonflow-trusted-header"
	// BuiltinRealmOIDC is the tenant's configured OIDC issuer. One per
	// organization: the registry is org-scoped, so the id needs no suffix.
	BuiltinRealmOIDC RealmID = "oidc"
)

// Built-in canonical issuers. An issuer is the registry's secondary key and is
// matched by exact string equality, so these are constants rather than
// anything derived at runtime.
const (
	// IssuerAPICredential is the issuer stamped on a client-credential
	// verification. AxonFlow issued the credential and AxonFlow verified it,
	// so the deployment is the issuer.
	IssuerAPICredential = "axonflow-api-credential"
	// IssuerInternalService is the issuer for the internal-service HMAC hop.
	IssuerInternalService = "axonflow-internal-service"
	// IssuerCommunity is the issuer for community mode's unauthenticated
	// caller.
	IssuerCommunity = "axonflow-community"
	// IssuerTrustedHeader is the default issuer for the identity-header
	// upstream when the deployment does not name one.
	IssuerTrustedHeader = "axonflow-trusted-header"
)

// AudienceDeployment is the audience presented for credentials that have no
// audience of their own.
//
// A symmetric-key JWT, a client credential and a header assertion are all
// usable only against the deployment that holds the verifying material, so the
// deployment IS their audience. Declaring it explicitly keeps TrustRealm's
// "an unbounded audience is a credential usable anywhere" invariant intact
// without inventing an audience check the platform never had: a credential
// that DOES carry an audience is presented verbatim and must match.
const AudienceDeployment = "axonflow-deployment"

// Verification methods, presented as Credential.Algorithm.
//
// Credential.Algorithm is "the signing algorithm the verifier actually used",
// and three of the four legacy paths verify a credential without signing
// anything. Naming the method they DID use keeps the realm's allow-list
// meaningful: a realm that expects a license-signed client credential is not
// satisfied by an upstream's header assertion, which is precisely the
// substitution an empty or shared algorithm name would permit.
const (
	// VerificationAPICredential is an AxonFlow-issued client credential
	// verified server-side: a signed enterprise license key, a bcrypt API key,
	// or a community-SaaS registration secret.
	//
	// THE THREE ARE DELIBERATELY NOT SPLIT. Splitting them would need the
	// verifying branch to report which one matched, and Authenticate cannot:
	// the DB path dispatches internally between the organization-license and
	// the API-key lookups. A finer name that the code cannot actually
	// establish is worse than a coarser one it can, because the realm's
	// allow-list would then be enforcing a distinction nothing populates
	// correctly. The distinction that MATTERS to a realm - an AxonFlow-issued
	// credential versus an upstream assertion versus an internal HMAC hop
	// versus no credential at all - is preserved, and those four are the ones
	// with different trust properties.
	VerificationAPICredential = "api-credential"
	// VerificationHMACInternalService is the internal-service HMAC token.
	VerificationHMACInternalService = "hmac-internal-service"
	// VerificationUpstreamAsserted is an assertion AxonFlow did not verify,
	// accepted because the deployment declared the upstream trusted.
	VerificationUpstreamAsserted = "upstream-asserted"
	// VerificationCommunityUnauthenticated is community mode, where the
	// deployment declares that it requires no credential.
	//
	// It is NOT spelled "none": TrustRealm.Validate refuses that string
	// case-insensitively, because in a JWT header it means an unsigned token.
	// The two facts are different - "this deployment requires no credential"
	// is a deployment posture, "this token is unsigned" is a forgery - and
	// they must not share a spelling.
	VerificationCommunityUnauthenticated = "community-unauthenticated"
)

// Pseudo-claim names for credentials that carry no claim set. They name where
// the canonical subject came from, so a realm's ClaimMapping is readable even
// where there is no JWT.
const (
	subjectClaimSub       = "sub"
	subjectClaimClientID  = "client_id"
	subjectClaimServiceID = "service_id"
	subjectClaimUserID    = "x-user-id"
)

// LiveVerificationWindow is how long a live credential verification is
// asserted for.
//
// An API credential and a header assertion have no expiry of their own: they
// are re-verified from scratch on every request. Encoding that as "issued at
// the verification instant, valid for the next minute" is the truthful form -
// the fact being asserted really is only claimed for the instant it was
// checked - and it keeps TrustRealm's "a credential that never expires cannot
// be aged out" invariant intact without weakening it. It can only ever narrow
// what is admissible: a verification older than this window is refused.
const LiveVerificationWindow = time.Minute

// BuiltinRealmDeployment describes what the deployment ACTUALLY wired. The
// built-in realms are derived from it rather than assumed, because
// DirectorySourceNone and RevocationSourceNone are positive declarations that
// a source does not exist, and declaring one that does - or failing to declare
// one that does not - is how a closure becomes authoritatively wrong.
type BuiltinRealmDeployment struct {
	// HasDirectory reports whether this deployment resolves group membership
	// from a SCIM-synced directory. False declares DirectorySourceNone, which
	// makes an empty closure AUTHORITATIVE rather than an outage (EX-45).
	HasDirectory bool
	// HasRevocation reports whether a revocation oracle is wired for
	// AxonFlow-minted tokens. False declares RevocationSourceNone, which is a
	// positive statement that this realm has no revocation channel - not a
	// forgotten configuration.
	HasRevocation bool
	// HasCAEP reports whether an OpenID Shared Signals / CAEP receiver is
	// wired for the OIDC realm. False declares RevocationSourceNone for it,
	// which is a positive statement that an IdP-issued token has no revocation
	// channel here - true today, and the thing the CAEP receiver
	// (compat_caep.go) exists to change.
	HasCAEP bool
}

// NOTE ON A KNOB THAT IS NOT HERE. An earlier revision carried a
// TrustedHeaderIssuer field so a deployment could name its own upstream. It
// was removed rather than kept unused: TrustedHeaderLegacyAuth stamps
// IssuerTrustedHeader unconditionally, so setting the field would move the
// realm's canonical issuer away from the one the credential presents and turn
// every trusted-header request into UNKNOWN_REALM. A knob whose only reachable
// effect is to break the path it configures is worse than no knob, and naming
// the upstream is a change that has to thread through the builder.

// BuiltinRealms returns the built-in realms for one organization.
//
// They are returned rather than registered so an operator tool, a test, and
// the runtime registration path all read the same declarations.
func BuiltinRealms(orgID string, dep BuiltinRealmDeployment) []TrustRealm {
	directory := DirectorySourceNone
	if dep.HasDirectory {
		directory = DirectorySourceSCIM
	}
	revocation := RevocationSourceNone
	if dep.HasRevocation {
		revocation = RevocationSourceLocalStore
	}
	return []TrustRealm{
		{
			RealmID:                 BuiltinRealmMinted,
			OrgID:                   orgID,
			Kind:                    RealmKindAxonFlowMinted,
			CanonicalIssuer:         UserTokenIssuer,
			AcceptedSubjectTypes:    []SubjectType{SubjectUser},
			AcceptedCredentialTypes: []CredentialType{CredentialBearerJWT},
			Audiences:               []string{AudienceDeployment},
			AuthorizedPartyPolicy:   AuthorizedPartyNotChecked,
			// The legacy HS256 paths pin HS256 twice over (a keyfunc method
			// assertion plus WithValidMethods). Declaring the same single
			// algorithm adds no check they do not already make.
			AllowedSigningAlgorithms: []string{"HS256"},
			ClaimMapping: ClaimMapping{
				Version:      1,
				SubjectClaim: subjectClaimSub,
				SubjectType:  SubjectUser,
				// AliasTokenSubject is deliberately NOT mapped: it would name
				// the same "sub" claim the canonical subject is taken from,
				// and TrustRealm.Validate refuses a realm that uses one claim
				// as both. That refusal is the configuration route to "an
				// email is an identifier" being closed, and it applies just as
				// much when the duplicated claim is the harmless-looking one.
				AliasClaims: map[AliasKind]string{
					AliasEmail: "email",
				},
			},
			MinimumAssurance:    AssuranceLow,
			ClockSkew:           30 * time.Second,
			CredentialAgePolicy: CredentialAgeUnbounded,
			Directory:           directory,
			Interactive:         InteractiveHuman,
			Revocation:          revocation,
			Delegation:          DelegationDenied,
			Enabled:             true,
			Version:             1,
		},
		{
			RealmID:                  BuiltinRealmAPICredential,
			OrgID:                    orgID,
			Kind:                     RealmKindAPICredential,
			CanonicalIssuer:          IssuerAPICredential,
			AcceptedSubjectTypes:     []SubjectType{SubjectClient},
			AcceptedCredentialTypes:  []CredentialType{CredentialAPICredential},
			Audiences:                []string{AudienceDeployment},
			AuthorizedPartyPolicy:    AuthorizedPartyNotChecked,
			AllowedSigningAlgorithms: []string{VerificationAPICredential},
			ClaimMapping: ClaimMapping{
				Version:      1,
				SubjectClaim: subjectClaimClientID,
				// A client credential authenticates an APPLICATION. ADR-065
				// invariant 2: a Client principal is attribution, never the
				// authority a grant is scoped to. Asserting SubjectUser here
				// would make every API key a person.
				SubjectType: SubjectClient,
			},
			MinimumAssurance:    AssuranceLow,
			ClockSkew:           0,
			CredentialAgePolicy: CredentialAgeUnbounded,
			// A client credential has no group graph. This is the positive
			// declaration EX-45 turns on, not an omission.
			Directory: DirectorySourceNone,
			// A client cannot answer an approval (EX-46).
			Interactive: InteractiveNonInteractive,
			// A client credential is revoked by disabling the client, which is
			// checked live on every request by the credential validator
			// itself. There is no separate revocation channel to be
			// unavailable.
			Revocation: RevocationSourceNone,
			Delegation: DelegationDenied,
			Enabled:    true,
			Version:    1,
		},
		{
			RealmID:                  BuiltinRealmInternalService,
			OrgID:                    orgID,
			Kind:                     RealmKindAPICredential,
			CanonicalIssuer:          IssuerInternalService,
			AcceptedSubjectTypes:     []SubjectType{SubjectService},
			AcceptedCredentialTypes:  []CredentialType{CredentialAPICredential},
			Audiences:                []string{AudienceDeployment},
			AuthorizedPartyPolicy:    AuthorizedPartyNotChecked,
			AllowedSigningAlgorithms: []string{VerificationHMACInternalService},
			ClaimMapping: ClaimMapping{
				Version:      1,
				SubjectClaim: subjectClaimServiceID,
				SubjectType:  SubjectService,
			},
			MinimumAssurance:    AssuranceLow,
			ClockSkew:           0,
			CredentialAgePolicy: CredentialAgeUnbounded,
			Directory:           DirectorySourceNone,
			Interactive:         InteractiveNonInteractive,
			Revocation:          RevocationSourceNone,
			Delegation:          DelegationDenied,
			Enabled:             true,
			Version:             1,
		},
		{
			RealmID: BuiltinRealmCommunity,
			OrgID:   orgID,
			// Community mode accepts an identity the caller asserts and
			// AxonFlow does not verify, which is what RealmKindTrustedHeader
			// means. Declaring it as such also caps its assurance at Low
			// (TrustRealm.Validate), which is the honest ceiling.
			Kind:                     RealmKindTrustedHeader,
			CanonicalIssuer:          IssuerCommunity,
			AcceptedSubjectTypes:     []SubjectType{SubjectClient},
			AcceptedCredentialTypes:  []CredentialType{CredentialTrustedHeader},
			Audiences:                []string{AudienceDeployment},
			AuthorizedPartyPolicy:    AuthorizedPartyNotChecked,
			AllowedSigningAlgorithms: []string{VerificationCommunityUnauthenticated},
			ClaimMapping: ClaimMapping{
				Version:      1,
				SubjectClaim: subjectClaimClientID,
				SubjectType:  SubjectClient,
			},
			MinimumAssurance:    AssuranceLow,
			ClockSkew:           0,
			CredentialAgePolicy: CredentialAgeUnbounded,
			Directory:           DirectorySourceNone,
			Interactive:         InteractiveNonInteractive,
			Revocation:          RevocationSourceNone,
			Delegation:          DelegationDenied,
			Enabled:             true,
			Version:             1,
		},
		{
			RealmID:                  BuiltinRealmTrustedHeader,
			OrgID:                    orgID,
			Kind:                     RealmKindTrustedHeader,
			CanonicalIssuer:          IssuerTrustedHeader,
			AcceptedSubjectTypes:     []SubjectType{SubjectUser},
			AcceptedCredentialTypes:  []CredentialType{CredentialTrustedHeader},
			Audiences:                []string{AudienceDeployment},
			AuthorizedPartyPolicy:    AuthorizedPartyNotChecked,
			AllowedSigningAlgorithms: []string{VerificationUpstreamAsserted},
			ClaimMapping: ClaimMapping{
				Version: 1,
				// X-User-ID, not X-User-Email. The email is an alias and an
				// alias is never an identifier (ADR-065 invariant 3), so an
				// upstream that asserts only an address produces
				// SUBJECT_MISSING here. That refusal is the finding, not a
				// bug: it says the deployment has attribution and not
				// identity.
				SubjectClaim: subjectClaimUserID,
				SubjectType:  SubjectUser,
				AliasClaims: map[AliasKind]string{
					AliasEmail: "x-user-email",
				},
			},
			// TrustRealm.Validate refuses anything above Low for a
			// trusted-header realm, because AxonFlow does not verify the
			// upstream's authentication.
			MinimumAssurance:    AssuranceLow,
			ClockSkew:           0,
			CredentialAgePolicy: CredentialAgeUnbounded,
			Directory:           directory,
			Interactive:         InteractiveHuman,
			Revocation:          RevocationSourceNone,
			Delegation:          DelegationDenied,
			Enabled:             true,
			Version:             1,
		},
	}
}

// builtinRealmSource registers the built-in realms for an organization on
// first sight and remembers that it has, so the per-request call is a read on
// a sync.Map after the first request for that organization.
type builtinRealmSource struct {
	registry *RealmRegistry
	dep      BuiltinRealmDeployment
	extra    []CompatRealmSource

	mu   sync.Mutex
	done map[string]error
}

// NewBuiltinRealmSource builds the realm source that declares the four legacy
// paths' realms. Additional sources (the OIDC realm, in enterprise builds) are
// consulted after the built-ins, in order.
func NewBuiltinRealmSource(registry *RealmRegistry, dep BuiltinRealmDeployment, extra ...CompatRealmSource) (CompatRealmSource, error) {
	if registry == nil {
		return nil, fmt.Errorf("identity: builtin realm source requires a registry")
	}
	return &builtinRealmSource{
		registry: registry,
		dep:      dep,
		extra:    extra,
		done:     map[string]error{},
	}, nil
}

// EnsureRealms registers orgID's built-in realms once, then delegates to every
// extra source on EVERY call.
//
// The two halves are memoized differently on purpose. The built-ins are
// derived from deployment configuration that cannot change without a restart,
// so registering them twice would trip the registry's version-must-advance
// rule for no benefit. An extra source (the OIDC realm) reads per-tenant
// configuration that CAN change while the process runs, so it is asked every
// time and owns its own idempotency.
func (s *builtinRealmSource) EnsureRealms(ctx context.Context, orgID string) error {
	if orgID == "" {
		return fmt.Errorf("identity: cannot establish realms without an organization")
	}
	if err := s.ensureBuiltins(orgID); err != nil {
		return err
	}
	for _, ex := range s.extra {
		if ex == nil {
			continue
		}
		if err := ex.EnsureRealms(ctx, orgID); err != nil {
			return err
		}
	}
	return nil
}

// ensureBuiltins registers the built-in realms for orgID exactly once.
//
// A FAILURE IS MEMOIZED TOO, and returned on every later call. Retrying a
// registration that failed because a realm declaration is invalid would spend
// a validation on every request forever and report a different error depending
// on which realm happened to fail first; and a partially registered
// organization must not read as a successfully registered one. The remedy for
// an invalid built-in realm is a fixed build, not a retry.
func (s *builtinRealmSource) ensureBuiltins(orgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err, seen := s.done[orgID]; seen {
		return err
	}
	var firstErr error
	for _, realm := range BuiltinRealms(orgID, s.dep) {
		if err := s.registry.Register(realm); err != nil {
			firstErr = fmt.Errorf("identity: registering built-in realm %q for org %q: %w", realm.RealmID, orgID, err)
			break
		}
	}
	s.done[orgID] = firstErr
	return firstErr
}
