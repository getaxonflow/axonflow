// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package authoringvocabulary resolves the deployment's typed-authoring
// VOCABULARY - the snapshot authoring validation, activation, admission and the
// enforcing seam all read - and nothing about the licence (#3895).
//
// # WHY IT IS NOT IN platform/shared/authoringedition, WHERE IT STARTED
//
// It lived there until the decide-plane enforcing seam needed it. The agent
// ENFORCES an organization's active document, so it must resolve the same
// vocabulary the document was published against; it holds no licence-derived
// authoring boundary, because it authors nothing. authoringedition's #3956
// deployment guard counts every binary that imports that package as a surface
// that resolves a LICENSED edition and therefore owes AXONFLOW_LICENSE_KEY in
// every manifest - which is correct for the package's licence read, and would
// have been a false claim about the agent the moment it imported the package
// for its vocabulary. A guard reporting a surface that does not exist is a
// guard nobody believes the next time.
//
// So the two questions live in two packages: authoringedition.Resolve answers
// "what may this customer write", from the verified licence; this package
// answers "what vocabulary does this deployment author and enforce against",
// from the build, the deployment mode and the identity plane. The same split
// already put deploymode.PlaneEdition outside the licence resolver, for the same
// reason one level down.
package authoringvocabulary

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/shared/deploymode"
	"axonflow/platform/shared/identity"
)

// THE DEPLOYMENT'S AUTHORING VOCABULARY, RESOLVED ONCE (#3895).
//
// authoringcatalog cannot resolve the production vocabulary on its own: it
// lives in the decision module, and two of the three facts it needs are the
// platform's - which trust realms this deployment's identity plane mints
// principals in, and which edition of the enforcement planes this BUILD
// carries. This file supplies both, so that the resolver stays one function
// and the realm set stays the identity plane's rather than a copy.
//
// # TWO EDITIONS, AND CONFLATING THEM IS THE #3956 DEFECT ONE STEP OVER
//
// A deployment has two edition questions and they have different answers:
//
//   - WHAT MAY THIS CUSTOMER WRITE - the licensed construct set and the duty
//     rule. That is authoringedition.Resolve, from the verified licence, and it
//     is read PER PUBLICATION because a licence can lapse while the process
//     runs.
//   - WHAT CAN THIS BINARY'S PLANES DISCHARGE - which in-process enforcement
//     planes exist and which obligations each advertises. That is a property
//     of the BUILD and its deployment mode, not of the customer's licence: a
//     community binary genuinely has no approval tables, so a plane in it
//     cannot be handed an approval_challenge whatever a licence says.
//
// deploymode.PlaneEdition answers the second, and it lives THERE rather than
// in the licence resolver for a reason learned the hard way: putting it there
// made platform/agent import the licence package for a question that has
// nothing to do with licences, and the #3956 deployment guard - correctly -
// then demanded that the agent's every compose service be given
// AXONFLOW_LICENSE_KEY. The two questions are answered by two packages, which
// is what keeps them two questions.
//
// Reading the licence for the second would let an expired key silently narrow
// the capability set a plane advertises to the PDP, which turns a billing
// event into a decision change; reading the mode for the first would let
// configuration grant a construct nobody paid for. tier_limits.go states the
// standing rule the second half rests on: the deployment mode "may narrow what
// a build registers, it never grants a limit".

// EnvCatalog is the deployment's vocabulary selector, re-exported so a
// deployment guard and a refusal message cite one string.
const EnvCatalog = authoringcatalog.Env

// DeploymentRealms is the authoring view of the trust realms this deployment
// mints principals in.
//
// DERIVED FROM identity.BuiltinRealms, never listed here. Both attributes an
// authoring catalog needs come off the realm's own declaration -
// InteractiveClass.CanAnswer and DirectorySource.HasGroupGraph - so a realm
// added to the identity plane arrives here without anybody remembering to add
// it, and a realm whose directory wiring changes changes its authoring
// attributes with it. A hand-kept map would be one entry short the day the
// sixth realm lands, which is #3877's shape.
//
// THE ORGANIZATION ARGUMENT IS EMPTY, DELIBERATELY. A realm's IDENTIFIER and
// its two authoring attributes are deployment facts: BuiltinRealms fills OrgID
// on each realm and changes nothing else per organization, and the authoring
// catalog is a deployment vocabulary rather than a per-tenant one. Resolving
// it per organization would make the set of realms an author may scope to
// depend on which tenant's request built the catalog first.
func DeploymentRealms(dep identity.BuiltinRealmDeployment) map[string]authoring.RealmEntry {
	out := map[string]authoring.RealmEntry{}
	for _, r := range identity.BuiltinRealms("", dep) {
		out[string(r.RealmID)] = authoring.RealmEntry{
			Interactive:   r.Interactive.CanAnswer(),
			HasGroupGraph: r.Directory.HasGroupGraph(),
		}
	}
	return out
}

// CatalogDeployment describes what this deployment wired, for the realm
// derivation. It is identity's own input type rather than a second one: the
// realms an author may scope to must be the realms the identity plane mints,
// and the two are the same declaration read twice only if they take the same
// input.
type CatalogDeployment = identity.BuiltinRealmDeployment

// DeploymentFromDatabase derives what a process wired from the one fact the
// authoring catalog depends on: whether a SCIM-backed directory resolver can
// be built over this database.
//
// IT IS THE ORCHESTRATOR'S OWN DERIVATION, reused rather than restated -
// initSegmentPolicyGate declares HasDirectory from exactly this constructor
// succeeding, and the community build of it returns ErrEnterpriseOnly, so a
// community binary correctly declares no directory. It is cheap and does no
// I/O: it assembles a role resolver and a cache.
//
// THE OTHER TWO FIELDS ARE LEFT FALSE ON PURPOSE, and that is not an omission.
// An authoring catalog needs exactly two attributes per realm - can a person
// answer here, and does this realm have a group graph - and neither is moved
// by revocation or by CAEP: those decide RevocationSource, which the authoring
// plane does not read. A process that filled them in from a guess would be
// declaring capabilities it had not checked.
func DeploymentFromDatabase(db *sql.DB) CatalogDeployment {
	dep := CatalogDeployment{}
	if db == nil {
		return dep
	}
	if _, err := identity.NewIdentityAttributeResolver(db); err == nil {
		dep.HasDirectory = true
	}
	return dep
}

// ResolveCatalog resolves the deployment's typed-authoring vocabulary.
//
// It is the ONE call every transport makes - the community route, the
// enterprise portal, the operator-run importer - and the snapshot it returns
// is the one that must then feed authoring validation, activation, the
// admission registry an engine runs against, and the version a decision and a
// proof carry. A transport that resolved twice would hold two vocabularies
// whose digests differ, and the decision record would name one while the
// editor validated against the other.
//
// A nil snapshot with a nil error is "this deployment declares no vocabulary",
// which is the unset case every transport already answers 503 for.
func ResolveCatalog(dep CatalogDeployment) (*authoringcatalog.Snapshot, error) {
	return ResolveCatalogValue(os.Getenv(EnvCatalog), dep)
}

// ResolveCatalogValue is ResolveCatalog with the value supplied, so the four
// outcomes can be driven without a process environment.
func ResolveCatalogValue(raw string, dep CatalogDeployment) (*authoringcatalog.Snapshot, error) {
	edition, recognised := deploymode.PlaneEdition()
	if !recognised {
		return nil, fmt.Errorf(
			"this deployment's DEPLOYMENT_MODE (%q) is not a recognised mode, so which enforcement planes this build "+
				"carries cannot be established and no authoring vocabulary can be resolved against them",
			deploymode.Current())
	}
	return authoringcatalog.Resolve(raw, authoringcatalog.Deployment{
		Edition: edition,
		Realms:  DeploymentRealms(dep),
		// THE INSTANT IS THE RESOLUTION'S, not a wall-clock read inside the
		// registry: a catalog whose compatibility expiry silently read the
		// clock could not be replayed, and a decision that cannot be replayed
		// cannot be audited.
		Now: time.Now().UTC(),
	})
}
