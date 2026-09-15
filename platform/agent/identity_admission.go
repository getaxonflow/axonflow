// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// Agent-side wiring of subject admission (ADR-065 invariant 2; PRD v11 §1.6):
// what this process wired - a directory, a revocation store, a tenant OIDC
// configuration, the per-organization identity settings - from which the
// built-in realms are derived, and the translation of an agent AuthResult into
// the credential principal an enforcing plane admits.

// identityDeployment records what THIS process wired, as observed at
// boot. The built-in realms are derived from it, and the two booleans are
// positive declarations (DirectorySourceNone and RevocationSourceNone) rather
// than absences, so getting one wrong makes an empty closure authoritative
// when it is not.
var identityDeployment sharedidentity.BuiltinRealmDeployment

// identityRevocations is the deny-list the built-in minted realm is
// checked against, set only when one was successfully wired.
var identityRevocations sharedidentity.RevocationChecker

// identityOIDCConfigs is the tenant OIDC configuration provider, set
// only in an enterprise build with a usable database.
var identityOIDCConfigs sharedidentity.OIDCConfigProvider

// identityOrgSettings is the per-organization identity settings store
// (session ADR65-I): the Shared Signals opt-in and audience, read from
// identity_org_settings. Set only in an enterprise build with a usable
// database.
var identityOrgSettings sharedidentity.OrgIdentitySettingsSource

// identityAdmission is the process's subject admission, nil until
// initIdentityPlane assembles it: the anchored enforcer admits each request's
// subject through its admitter, and RegisterCAEPReceiver verifies a SET's
// issuer against its registry.
var identityAdmission *sharedidentity.AdmissionBootstrap

// noteIdentityOrgSettingsWired records that the per-organization settings
// store was constructed. Called from registerFleetValidators, for the same
// reason noteIdentityWiring is: the fact comes from the constructor
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
// the realms derived at initIdentityPlane declare a Shared Signals channel
// exactly when RegisterCAEPReceiver will succeed in providing one. The
// per-organization half - whether a given tenant has pointed a stream at it -
// comes from the settings row (oidc_realm.go's deploymentFor).
func noteIdentityCAEPReceivable(resolverWired bool) {
	identityDeployment.HasCAEP = resolverWired &&
		identityOIDCConfigs != nil && identityOrgSettings != nil
}

// noteIdentityWiring records a fact about this deployment for the
// built-in realm declarations. It is called from registerFleetValidators,
// which is the one function that knows whether each collaborator was actually
// constructed - asking again here would mean re-deriving an answer from
// configuration rather than from what was wired, and the two disagree exactly
// when a constructor failed.
func noteIdentityWiring(revocations sharedidentity.RevocationChecker, configs sharedidentity.OIDCConfigProvider, directoryWired bool) {
	if revocations != nil {
		identityRevocations = revocations
		identityDeployment.HasRevocation = true
	}
	if configs != nil {
		identityOIDCConfigs = configs
	}
	if directoryWired {
		identityDeployment.HasDirectory = true
	}
}

// identityExtraRealmSources declares the tenant OIDC realm source, when
// this build and this deployment have one.
//
// Enterprise-only by construction: the community NewOIDCRealmSource returns
// ErrEnterpriseOnly, which is SKIPPED rather than propagated - the established
// pattern for every Enterprise capability in this package
// (registerFleetValidators does the same for the validators themselves). A
// community deployment then declares no OIDC realm, which is the correct
// answer for a build that federates no IdP, not a gap.
func identityExtraRealmSources(reg *sharedidentity.RealmRegistry) ([]sharedidentity.RealmSource, error) {
	if identityOIDCConfigs == nil {
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
	src, err := sharedidentity.NewOIDCRealmSource(reg, identityOIDCConfigs, identityDeployment, opts...)
	switch {
	case err == nil:
		return []sharedidentity.RealmSource{src}, nil
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

// identityRevocationOracle adapts the fleet plane's RevocationChecker to
// the realm registry's RevocationOracle, or returns nil when none was wired.
//
// # THE ONE THING THIS ORACLE CANNOT SEE
//
// RevocationOracle is keyed on a single opaque revocation key, so this can
// consult the per-jti rows and NOT the mass-revocation rows, which are keyed
// on (user_email, issued_before). That is a real narrowing and it is safe in
// exactly one direction: the legacy validator has ALREADY applied the full
// check, including mass revocation, before admission runs, so this oracle
// can only ever add a refusal to a credential legacy already cleared. It can
// never restore one legacy rejected, because a rejected credential reaches
// admission with SignatureVerified false and is denied before revocation is
// consulted at all.
func identityRevocationOracle() sharedidentity.RevocationOracle {
	if identityRevocations == nil {
		return nil
	}
	return &fleetRevocationOracle{checker: identityRevocations}
}

// revocationLookupTimeout bounds the deny-list lookup on the
// authentication path.
const revocationLookupTimeout = 2 * time.Second

type fleetRevocationOracle struct {
	checker sharedidentity.RevocationChecker
}

// IsRevoked implements sharedidentity.RevocationOracle.
//
// An error propagates rather than being flattened to false: VerifyCredential
// turns it into Indeterminate(REVOCATION_UNAVAILABLE), which is the whole
// point - a deny-list that could not be consulted is not a deny-list that said
// no.
func (o *fleetRevocationOracle) IsRevoked(orgID string, _ sharedidentity.RealmID, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), revocationLookupTimeout)
	defer cancel()
	// Email and issuedAt are deliberately zero: see the oracle's doc for what
	// that excludes and why it is safe here.
	return o.checker.IsRevoked(ctx, orgID, key, "", time.Time{})
}

// authResultPrincipal builds the credential principal an enforcing plane
// admits, for a SUCCESSFUL client-credential authentication.
//
// All four AuthKinds are mapped, including AuthKindInternalService. That kind
// is the fifth auth entry point a "four legacy paths" census misses: it is
// produced by the same function as the other three, so mapping every kind here
// covers it whether or not anyone remembered it existed.
func authResultPrincipal(auth *AuthResult, now time.Time) (sharedidentity.CredentialPrincipal, bool) {
	if auth == nil {
		return sharedidentity.CredentialPrincipal{}, false
	}
	if auth.OrgID == "" {
		// No authenticated organization means the identity plane has nothing
		// to scope a realm lookup to. Reporting it as a defect would
		// be accurate but useless: an org-less AuthResult is a deployment
		// running without ORG_ID, not a wiring bug, and it would fire on every
		// request of such a deployment.
		return sharedidentity.CredentialPrincipal{}, false
	}
	var legacy sharedidentity.CredentialPrincipal
	switch auth.Kind {
	case AuthKindCommunity:
		legacy = sharedidentity.CommunityPrincipal(auth.OrgID, auth.ClientID, now)
	case AuthKindCommunitySaaS, AuthKindEnterprise:
		legacy = sharedidentity.APICredentialPrincipal(
			auth.OrgID, auth.ClientID, sharedidentity.VerificationAPICredential, true, now)
	case AuthKindInternalService:
		legacy = sharedidentity.InternalServicePrincipal(auth.OrgID, auth.ClientID, true, now)
	default:
		return sharedidentity.CredentialPrincipal{}, false
	}
	return legacy, true
}

// userTokenClaims returns the verified claim set behind a resolved user, or
// nil when none was produced.
//
// A REJECTED token contributes no claims, deliberately. Nothing about a token
// that failed validation is verified, and presenting its claims for realm
// verification would be presenting unverified material.
func userTokenClaims(user *User, err error) map[string]any {
	if user == nil || err != nil {
		return nil
	}
	return user.TokenClaims
}
