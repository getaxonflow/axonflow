// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// Agent-side wiring of the ADR-065 identity compatibility adapters (#3550).
//
// The adapter itself lives in platform/shared/identity. This file is only the
// deployment's half: what this process actually wired (a directory, a
// revocation store, a tenant OIDC configuration), and the translation of an
// agent AuthResult into the adapter's vocabulary.
//
// # WHERE THE ADAPTER IS CALLED, AND WHY IT IS NOT CALLED ANYWHERE ELSE
//
// Three call sites in this package, each the SINGLE function through which its
// credential path resolves an identity:
//
//	Authenticate              authenticator.go - every client credential, all
//	                          four AuthKinds including the internal-service
//	                          HMAC hop a four-adapter census would miss.
//	adaptedValidateUserToken  this file - the HS256 per-user token. NOT
//	                          ResolveUser: validateUserToken has a second
//	                          production caller (resolveAuditReadAuthority),
//	                          and a guard at one of two callers is not a
//	                          guard. An AST test pins that there is exactly
//	                          one caller.
//	authenticateMCPSession    mcp_server_handler.go - the #2896 trust-gated
//	                          identity header, on the branch where a header
//	                          actually becomes the session's identity.
//
// The fleet plane's token path is covered one layer down, inside
// sharedidentity.ResolveToken, which authenticateMCPSession calls. It is wired
// there rather than here so that every consumer of that function is covered,
// including one added after this change.

// identityCompatDeployment records what THIS process wired, as observed at
// boot. The built-in realms are derived from it, and the two booleans are
// positive declarations (DirectorySourceNone and RevocationSourceNone) rather
// than absences, so getting one wrong makes an empty closure authoritative
// when it is not.
var identityCompatDeployment sharedidentity.BuiltinRealmDeployment

// identityCompatRevocations is the deny-list the built-in minted realm is
// checked against, set only when one was successfully wired.
var identityCompatRevocations sharedidentity.RevocationChecker

// identityCompatOIDCConfigs is the tenant OIDC configuration provider, set
// only in an enterprise build with a usable database.
var identityCompatOIDCConfigs sharedidentity.OIDCConfigProvider

// identityOrgSettings is the per-organization identity settings store
// (session ADR65-I): the compatibility-mode override and the Shared Signals
// opt-in, read from identity_org_settings. Set only in an enterprise build
// with a usable database; nil means the process mode is the whole answer.
var identityOrgSettings sharedidentity.OrgIdentitySettingsSource

// identityCompatBoot is the installed bootstrap. It IS held now, because it
// finally has a reader: the CAEP push endpoint verifies a SET's issuer
// against this registry, which is the "follow-up that gives them a reader"
// #3582 named as the one that should start holding it.
//
// That reader (identity_caep.go) is enterprise-only, and CI lints this
// package without the enterprise tag, where the variable is written here and
// read nowhere; the community build genuinely has no reader, by design.
//
//nolint:unused // read by RegisterCAEPReceiver in identity_caep.go (enterprise build)
var identityCompatBoot *sharedidentity.CompatBootstrap

// noteIdentityOrgSettingsWired records that the per-organization settings
// store was constructed. Called from registerFleetValidators, for the same
// reason noteIdentityCompatWiring is: the fact comes from the constructor
// succeeding, not from configuration.
func noteIdentityOrgSettingsWired(store sharedidentity.OrgIdentitySettingsSource) {
	if store != nil {
		identityOrgSettings = store
	}
}

// noteIdentityCAEPReceivable records whether THIS process can host a Shared
// Signals receiver, which is what BuiltinRealmDeployment.HasCAEP declares.
//
// HasCAEP IS DERIVED, NOT CONSTANT, AND IT IS DERIVED FROM WHAT WAS WIRED.
// The receiver needs three collaborators - the tenant OIDC configuration
// (to name the realm's key set), the identity attribute resolver (the cache
// it invalidates) and the org settings store (the audience and the opt-in) -
// and it is registered only if all three exist. This is called at the end of
// registerFleetValidators, after the three have been constructed or not, so
// the realms derived at initIdentityCompat declare a Shared Signals channel
// exactly when RegisterCAEPReceiver will succeed in providing one. The
// per-organization half - whether a given tenant has pointed a stream at it -
// comes from the settings row (compat_oidc.go's deploymentFor).
func noteIdentityCAEPReceivable(resolverWired bool) {
	identityCompatDeployment.HasCAEP = resolverWired &&
		identityCompatOIDCConfigs != nil && identityOrgSettings != nil
}

// noteIdentityCompatWiring records a fact about this deployment for the
// built-in realm declarations. It is called from registerFleetValidators,
// which is the one function that knows whether each collaborator was actually
// constructed - asking again here would mean re-deriving an answer from
// configuration rather than from what was wired, and the two disagree exactly
// when a constructor failed.
func noteIdentityCompatWiring(revocations sharedidentity.RevocationChecker, configs sharedidentity.OIDCConfigProvider, directoryWired bool) {
	if revocations != nil {
		identityCompatRevocations = revocations
		identityCompatDeployment.HasRevocation = true
	}
	if configs != nil {
		identityCompatOIDCConfigs = configs
	}
	if directoryWired {
		identityCompatDeployment.HasDirectory = true
	}
}

// initIdentityCompat parses the configured mode, assembles the adapter and
// installs it process-wide.
//
// IT IS FATAL ON AN UNRECOGNIZED MODE. AXONFLOW_IDENTITY_COMPAT_MODE=enfore is
// an operator who believes their deployment enforces; booting anyway with the
// adapter silently off would leave them believing it. A container that refuses
// to start is the one failure an operator sees immediately.
//
// It runs unconditionally, in both DB and no-DB modes, so the mode is
// validated even on a deployment where nothing else would touch it.
func initIdentityCompat() {
	boot, err := sharedidentity.BootstrapCompatFromEnv(
		"agent", identityCompatDeployment, identityCompatExtraRealmSources, identityCompatRevocationOracle(),
		identityCompatOrgModes())
	if err != nil {
		log.Fatalf("❌ %v", err)
	}
	// Held, because it has a reader: RegisterCAEPReceiver verifies a SET's
	// issuer against this registry. #3582 deliberately discarded it while
	// nothing read it (the write-only shape #3473 removed); the endpoint is
	// the follow-up that changed that.
	identityCompatBoot = boot
}

// identityCompatOrgModes is the per-organization mode source for the adapter,
// or nil when none was wired (every community build; an enterprise build
// with no database). A nil source means the process mode is the whole
// answer, which is #3582's behaviour.
func identityCompatOrgModes() sharedidentity.CompatOrgModeSource {
	if identityOrgSettings == nil {
		return nil
	}
	return identityOrgSettings
}

// identityCompatExtraRealmSources declares the tenant OIDC realm source, when
// this build and this deployment have one.
//
// Enterprise-only by construction: the community NewOIDCRealmSource returns
// ErrEnterpriseOnly, which is SKIPPED rather than propagated - the established
// pattern for every Enterprise capability in this package
// (registerFleetValidators does the same for the validators themselves). A
// community deployment then declares no OIDC realm, which is the correct
// answer for a build that federates no IdP, not a gap.
func identityCompatExtraRealmSources(reg *sharedidentity.RealmRegistry) ([]sharedidentity.CompatRealmSource, error) {
	if identityCompatOIDCConfigs == nil {
		return nil, nil
	}
	// The per-organization Shared Signals opt-in rides on the same source:
	// the realm declares RevocationSourceSharedSignals only for a tenant
	// whose settings row opts in, on a deployment where HasCAEP says a
	// receiver is wired.
	var opts []sharedidentity.OIDCRealmSourceOption
	if identityOrgSettings != nil {
		opts = append(opts, sharedidentity.WithOIDCRealmCAEPSettings(identityOrgSettings))
	}
	src, err := sharedidentity.NewOIDCRealmSource(reg, identityCompatOIDCConfigs, identityCompatDeployment, opts...)
	switch {
	case err == nil:
		return []sharedidentity.CompatRealmSource{src}, nil
	case errors.Is(err, sharedidentity.ErrEnterpriseOnly):
		return nil, nil
	default:
		// A real construction failure. It is returned, not logged and
		// swallowed: a deployment that HAS an OIDC configuration and could not
		// build a realm source for it would otherwise silently report every
		// IdP token as UNKNOWN_REALM, which reads exactly like EX-47 and is
		// not.
		return nil, err
	}
}

// identityCompatRevocationOracle adapts the fleet plane's RevocationChecker to
// the realm registry's RevocationOracle, or returns nil when none was wired.
//
// # THE ONE THING THIS ORACLE CANNOT SEE
//
// RevocationOracle is keyed on a single opaque revocation key, so this can
// consult the per-jti rows and NOT the mass-revocation rows, which are keyed
// on (user_email, issued_before). That is a real narrowing and it is safe in
// exactly one direction: the legacy validator has ALREADY applied the full
// check, including mass revocation, before the adapter runs, so this oracle
// can only ever add a refusal to a credential legacy already cleared. It can
// never restore one legacy rejected, because a rejected credential reaches the
// adapter with SignatureVerified false and is denied before revocation is
// consulted at all.
func identityCompatRevocationOracle() sharedidentity.RevocationOracle {
	if identityCompatRevocations == nil {
		return nil
	}
	return &compatRevocationOracle{checker: identityCompatRevocations}
}

// compatRevocationLookupTimeout bounds the deny-list lookup on the
// authentication path.
const compatRevocationLookupTimeout = 2 * time.Second

type compatRevocationOracle struct {
	checker sharedidentity.RevocationChecker
}

// IsRevoked implements sharedidentity.RevocationOracle.
//
// An error propagates rather than being flattened to false: VerifyCredential
// turns it into Indeterminate(REVOCATION_UNAVAILABLE), which is the whole
// point - a deny-list that could not be consulted is not a deny-list that said
// no.
func (o *compatRevocationOracle) IsRevoked(orgID string, _ sharedidentity.RealmID, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), compatRevocationLookupTimeout)
	defer cancel()
	// Email and issuedAt are deliberately zero: see the oracle's doc for what
	// that excludes and why it is safe here.
	return o.checker.IsRevoked(ctx, orgID, key, "", time.Time{})
}

// --- translation of agent auth outcomes into the adapter's vocabulary ---

// authResultLegacyAuth builds the adapter input for a SUCCESSFUL client-
// credential authentication.
//
// All four AuthKinds are mapped, including AuthKindInternalService. That kind
// is the fifth auth entry point a "four legacy paths" census misses: it is
// produced by the same function as the other three, so wiring the adapter at
// that function covers it whether or not anyone remembered it existed.
func authResultLegacyAuth(auth *AuthResult, now time.Time) (sharedidentity.LegacyAuth, bool) {
	if auth == nil {
		return sharedidentity.LegacyAuth{}, false
	}
	if auth.OrgID == "" {
		// No authenticated organization means the identity plane has nothing
		// to scope a realm lookup to. Reporting it as an adapter defect would
		// be accurate but useless: an org-less AuthResult is a deployment
		// running without ORG_ID, not a wiring bug, and it would fire on every
		// request of such a deployment.
		return sharedidentity.LegacyAuth{}, false
	}
	var legacy sharedidentity.LegacyAuth
	switch auth.Kind {
	case AuthKindCommunity:
		legacy = sharedidentity.CommunityLegacyAuth(auth.OrgID, auth.ClientID, now)
	case AuthKindCommunitySaaS, AuthKindEnterprise:
		legacy = sharedidentity.APICredentialLegacyAuth(
			auth.OrgID, auth.ClientID, sharedidentity.VerificationAPICredential, true, "", now)
	case AuthKindInternalService:
		legacy = sharedidentity.InternalServiceLegacyAuth(auth.OrgID, auth.ClientID, true, "", now)
	default:
		return sharedidentity.LegacyAuth{}, false
	}
	// #3602: set AFTER the per-kind builder, once, so a kind added later
	// cannot forget it - the alternative, a Synthetic argument on each of the
	// three builders, is three places to forget it in.
	legacy.Synthetic = auth.Synthetic
	return legacy, true
}

// adaptedValidateUserToken is the SINGLE production entry point for the HS256
// per-user token path.
//
// # WHY THIS EXISTS RATHER THAN A GUARD IN ResolveUser
//
// The first version of this change wired the adapter into ResolveUser, on the
// argument that ResolveUser is "the function that owns the invariant". It is
// not. The function that owns it is validateUserToken, and it has TWO
// production callers: ResolveUser, and resolveAuditReadAuthority
// (audit_verification_authority.go), which uses a per-user token to decide
// TENANT-WIDE AUDIT READ. Under enforce, a token from an issuer no realm
// declares was refused on every ResolveUser route and accepted on the one
// surface where it buys read-scope elevation.
//
// validateUserToken's own signature cannot carry the authenticated
// organization (it takes the credential TENANT, which is a different
// identifier) and it has some thirty test callers, so the guard lives here
// instead, in the one function both production paths must traverse. That is
// only a guard if nothing else calls validateUserToken directly, which is not
// a matter of discipline: TestValidateUserTokenHasExactlyOneProductionCaller
// walks the package AST and fails when a second one appears.
//
// THE CONTEXT IS Background BY CHOICE. Neither caller's context is used: the
// counterfactual must be recorded even when the caller's context is already
// cancelled, or the shadow goes blind during exactly the incidents it exists
// to explain. The adapter bounds anything that touches storage itself.
func adaptedValidateUserToken(authenticatedOrgID, tokenString, expectedTenantID string, synthetic bool) (*User, error) {
	user, err := validateUserToken(tokenString, expectedTenantID)

	// Only the enterprise HS256 branch presents a credential. Community and
	// community-SaaS synthesize a fixed user from no credential at all, and
	// their CLIENT credential is already adapted in Authenticate; adapting the
	// synthetic user too would record a second counterfactual about the same
	// request, under a path whose credential does not exist.
	if isCommunityMode() || isCommunitySaasMode() {
		return user, err
	}

	// No authenticated organization means the identity plane has nothing to
	// scope a realm lookup to. Skipped for the same reason authResultLegacyAuth
	// skips it: an org-less deployment is a deployment running without ORG_ID,
	// not a wiring bug, and recording it as an adapter DEFECT would fire on
	// every request such a deployment serves.
	if strings.TrimSpace(authenticatedOrgID) == "" {
		return user, err
	}

	legacy := sharedidentity.HS256LegacyAuth(
		authenticatedOrgID,
		userTokenClaims(user, err),
		err == nil,
		compatLegacyReason(err),
		"",
	)
	// #3602: the observation-window canary tag, carried on the AuthResult
	// because this function deliberately has no *http.Request. It is a metric
	// label only and is read by nothing that decides admission.
	legacy.Synthetic = synthetic
	if ref := sharedidentity.CompatResolve(context.Background(), legacy).Refusal(); ref != nil {
		// The reason CODE only, and NAMED so it does not share a code with a
		// forged token. See compatAuthError for why: this change's own thesis,
		// applied to ErrJWKSUnavailable one layer up, is that an outage and an
		// attack must not share a wording; an identity-plane refusal and a
		// tampered signature must not share one either.
		return nil, fmt.Errorf("%s: refused by the identity plane (%s)", sharedidentity.CompatRefusalCode, ref.Reason)
	}
	return user, err
}

// userTokenClaims returns the verified claim set behind a resolved user, or
// nil when none was produced.
//
// A REJECTED token contributes no claims, deliberately. Nothing about a token
// that failed validation is verified, and feeding its claims to realm
// verification would be presenting unverified material, which is the one thing
// the adapter has no route to do (see the one-direction invariant in
// platform/shared/identity/compat.go).
func userTokenClaims(user *User, err error) map[string]any {
	if user == nil || err != nil {
		return nil
	}
	return user.TokenClaims
}

// compatLegacyReason renders an error as a counterfactual reason string.
func compatLegacyReason(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// compatAuthError renders an adapter refusal as an agent AuthError.
//
// The reason CODE is surfaced and the detail is not: the reason is a stable
// vocabulary an operator can look up, while the detail names realm
// configuration that a caller has no business reading off a 401. The detail is
// in the counterfactual record, which is where an operator looks.
func compatAuthError(ref *sharedidentity.CompatRefusal) *AuthError {
	return &AuthError{
		Code: sharedidentity.CompatRefusalCode,
		Message: "Authentication refused by the identity plane (" + string(ref.Reason) +
			"). The credential authenticated, but the organization's trust-realm configuration does not admit it.",
		HTTPStatus: http.StatusUnauthorized,
	}
}
