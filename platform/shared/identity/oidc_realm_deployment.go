// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"database/sql"

	"axonflow/platform/shared/deploymode"
)

// The deployment half of the tenant OIDC realm (#4249): whether this
// deployment wires the enterprise OIDC realm source, and what an authoring
// vocabulary may say about the realm that source declares.
//
// # WHY THIS IS NOT A SIXTH ENTRY IN BuiltinRealms
//
// BuiltinRealms is the RUNTIME REGISTRATION list: ensureBuiltins registers
// every realm it returns, for every organization, before the OIDC source runs.
// The OIDC realm's canonical issuer is the organization's own IdP, which no
// deployment-level declaration can know, so a sixth entry would either fail
// TrustRealm.Validate (an empty canonical issuer) - and ensureBuiltins
// memoizes that failure, refusing every admission for the organization - or,
// given an issuer, collide with the real per-organization realm the OIDC
// source registers under the same id. The realm's IDENTIFIER and its two
// authoring attributes are deployment facts all the same, and that is all an
// authoring vocabulary reads, so they are declared here.
//
// # WHY THE VOCABULARY NEEDS IT AT ALL
//
// The anchored engine admits an actor only if its realm qualifier is in the
// deployment vocabulary's realm set (pdp.Registry.Admit), and publication
// refuses a scope naming a realm outside that set (REALM_NOT_DECLARED). The
// identity plane admitting an IdP token is therefore not enough: a set built
// from BuiltinRealms alone refused every OIDC-admitted user as unknown_realm
// before any policy ran, and refused every policy that named one.

// OIDCRealmSourceWiring constructs the tenant OIDC configuration provider, and
// reports whether this deployment wires the enterprise OIDC realm source over it.
//
// IT IS THE ONE PREDICATE BEHIND BuiltinRealmDeployment.HasOIDC. The agent
// builds its realm source over the provider exactly when wired is true, and the
// orchestrator and the portal's DeploymentFromDatabase take the same boolean.
// Processes that share a DEPLOYMENT_MODE therefore agree on whether the realm
// exists.
//
// PROCESSES THAT DO NOT SHARE ONE CAN DISAGREE, and one shipped configuration
// does: the marketplace template's licence-transition mode overrides
// DEPLOYMENT_MODE to community on the agent and orchestrator only, never the
// portal (deploymode.EnvLicenceTransition). There the portal declares `oidc`
// and the enforcement plane does not, so a policy naming the realm validates
// at the portal and is refused REALM_NOT_DECLARED by the orchestrator's route.
// That direction fails closed. The operator-run importer reads the mode from
// its own shell, so run with DEPLOYMENT_MODE unset it declares no `oidc` realm
// (#4249 row filed with #4347).
//
// THE PROVIDER IS THE BUILD'S; wired IS THE DEPLOYMENT'S. configs is returned
// whenever the provider builds (an enterprise build with a database; a
// community build answers ErrEnterpriseOnly, a nil database an error), because
// the agent's OIDC token verifier is built over it independently of this
// declaration. wired additionally requires that the deployment mode applies the
// enterprise schema (deploymode.AppliesEnterpriseSchema; an unset mode resolves
// to community and answers false, but an UNRECOGNISED spelling answers true, by
// deploymode.AppliesCategory's deliberate fallback, which predates this
// predicate and wireOrgIdentitySettings shares): sso_configurations is
// created by migrations/enterprise/108 only, and the Community SaaS fleet runs
// the enterprise-tagged image on the core + community-saas schema, where the
// table does not exist. Keyed on the build alone, that fleet declared the `oidc`
// realm in its vocabulary, moving a Community vocabulary nobody changed (#4249,
// R3 round 1). It is the gate wireOrgIdentitySettings applies to the same class
// of collaborator (platform/agent/mcp_identity.go).
//
// Nothing else in production calls NewDBOIDCConfigProvider; a test holds that.
func OIDCRealmSourceWiring(db *sql.DB) (configs OIDCConfigProvider, wired bool, err error) {
	configs, err = NewDBOIDCConfigProvider(db)
	if err != nil || configs == nil {
		return nil, false, err
	}
	return configs, deploymode.AppliesEnterpriseSchema(), nil
}

// oidcRealmInteractive is the interactive class the tenant OIDC realm
// declares: a person signs in at the organization's IdP.
const oidcRealmInteractive = InteractiveHuman

// oidcRealmDirectory is the directory source the tenant OIDC realm declares
// for a deployment. It is the derivation NewOIDCRealmSource's realm uses, not a
// copy of it, so the authoring attribute and the admitted realm move together.
func oidcRealmDirectory(dep BuiltinRealmDeployment) DirectorySource {
	if dep.HasDirectory {
		return DirectorySourceSCIM
	}
	return DirectorySourceNone
}

// DeclaredRealm is a realm as a deployment vocabulary sees it: its identifier
// and the two attributes an authoring catalog reads.
type DeclaredRealm struct {
	RealmID     RealmID
	Interactive InteractiveClass
	Directory   DirectorySource
}

// DeclaredOIDCRealm returns the tenant OIDC realm as the deployment vocabulary
// declares it, and false when the deployment wires no OIDC realm source.
//
// The identifier is the constant every organization's realm is registered
// under (the registry scopes it per organization), so declaring it is not a
// per-organization vocabulary. An Enterprise organization with no OIDC
// configuration can therefore name the realm in a policy; no request in that
// organization can arrive from it, so a constraint scoped to it binds nobody
// and a permit scoped to it grants nobody.
func DeclaredOIDCRealm(dep BuiltinRealmDeployment) (DeclaredRealm, bool) {
	if !dep.HasOIDC {
		return DeclaredRealm{}, false
	}
	return DeclaredRealm{
		RealmID:     BuiltinRealmOIDC,
		Interactive: oidcRealmInteractive,
		Directory:   oidcRealmDirectory(dep),
	}, true
}
