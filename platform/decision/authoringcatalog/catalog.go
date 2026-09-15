// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package authoringcatalog resolves the deployment's typed-authoring
// vocabulary from its environment variable, as ONE snapshot.
//
// # Why it is a package rather than a function inside one transport
//
// It has THREE callers that must agree, and the number has grown once per
// surface added:
//
//   - the enterprise portal editor (#3762);
//   - the operator-run legacy importer (#3786), which validates the documents
//     it produces against the same catalog the editor would;
//   - the community typed-authoring route (#3907), which is the surface a
//     deployment with no portal writes through.
//
// Two resolutions of "which vocabulary does this deployment author against" is
// a vocabulary fork, and the symptom is an import or a CLI publication that
// validates cleanly and then fails ACTION_NOT_REGISTERED in the editor - or,
// worse, the reverse, where one surface accepts a policy another believes is
// not expressible.
//
// # Why the answer is a SNAPSHOT and not a catalog (#3895)
//
// Before #3895 this package returned an authoring catalog and nothing else,
// and the only vocabulary it knew was the conformance FIXTURE - the world the
// ADR-065 corpus is written against, with `realm_ws`, `stripe.create_refund`
// and a Jira ticket hierarchy no deployment has. A fresh install therefore had
// exactly two choices: author against a fixture, or not author at all.
//
// ADR-065's gate for a new installation is stricter than "a catalog exists":
// the SAME resolver snapshot must feed authoring validation, activation, the
// PIP/PDP and proof verification, and its version must travel through the
// request, the decision and the proof. That is a snapshot - a catalog, the
// registry it was projected from, a content digest, the version the wire
// carries and the shipped-corpus digest it is anchored to - resolved once and
// handed to every consumer, so no two of them can disagree about what a
// deployment's vocabulary is.
//
// # Why it is COMMUNITY-VISIBLE and carries no build tag
//
// The vocabulary is not an edition capability. ADR-066 classifies typed
// authoring as `community_core`, and #3906 ruled that the edition boundary is
// which CONSTRUCTS a policy may use rather than which surface resolves the
// catalog - so a community deployment resolves the same vocabulary and is
// bounded, at publication, by authoring.Profile. A build tag here would make
// the community route unable to name a single action, which is a boundary
// drawn in the wrong place and one nobody ruled.
//
// # Why it lives in the decision module
//
// The catalog type, the registry projection, the conformance registry and the
// shipped corpus are all in this module, and it is the module a community
// deployment already carries. Putting the resolver above it would make the
// decision module's own vocabulary resolvable only by something outside it.
// The one thing this module CANNOT see is the identity plane's realm
// attributes, which belong to platform/shared/identity in the platform module;
// Deployment is how a caller hands those in, and the platform-side package
// that does so is platform/shared/authoringvocabulary.
package authoringcatalog

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/conformance"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// Env names the deployment's authoring vocabulary.
//
// UNSET MEANS SourceDeployment (PRD §1.5). The typed authoring path is how
// every organization configures policy in v11 - enable, disable and re-action
// the shipped set, and author its own - so a deployment that names no
// vocabulary gets the one it actually runs, not an editor that answers 503.
// The deployment vocabulary is not a guess: it is derived from this build's
// registered actions, its identity plane's realms and the shipped detectors,
// which is exactly what an author on this deployment may reference.
//
// A value that is set and not recognised is still refused: a typo must not
// select a vocabulary or silently fall back to one. See Value.
const Env = "AXONFLOW_TYPED_AUTHORING_CATALOG"

// SourceConformance is the FIXTURE vocabulary: the conformance registry, which
// is the world the ADR-065 conformance corpus is written against.
//
// It is recognised so that the conformance corpus, the replay environment and
// the editor's own fixture-backed tests keep working, and it is marked as a
// fixture so that PRODUCTION ACTIVATION refuses it by name. A deployment can
// validate and publish against it; it cannot activate against it.
const SourceConformance = "conformance"

// SourceDeployment is the PRODUCTION vocabulary: the actions this deployment's
// decision surfaces actually recognise, the trust realms its identity plane
// mints principals in, the enforcement planes of this build, and the shipped
// inspection controls, anchored to the digest of the corpus this binary was
// built with. See deployment.go.
const SourceDeployment = "deployment"

// Sources lists the recognised values, for a refusal message.
func Sources() []string { return []string{SourceConformance, SourceDeployment} }

// Value normalises a raw Env value to the vocabulary it selects: unset or
// empty is SourceDeployment (PRD §1.5), a recognised value is itself, and
// anything else is an error naming the variable, the recognised values and
// the default, so a transport can refuse on it before it serves anything.
func Value(raw string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(raw)); v {
	case "":
		return SourceDeployment, nil
	case SourceConformance, SourceDeployment:
		return v, nil
	default:
		return "", fmt.Errorf("%s=%q is not a typed-authoring vocabulary: the recognised values are %s, and unset means %s (PRD §1.5)",
			Env, raw, strings.Join(Sources(), ", "), SourceDeployment)
	}
}

// Snapshot is ONE resolution of the deployment's vocabulary.
//
// Every field is derived from the same registry catalog in the same call, and
// the struct is what every consumer receives, so authoring validation, the
// activation refusals, the admission registry an engine runs against, and the
// version a decision and a proof carry cannot come from four reads that
// happened to agree.
type Snapshot struct {
	// Source is the recognised value that produced this snapshot.
	Source string
	// Fixture is true when the vocabulary is a test world rather than the
	// deployment's own. Production activation refuses a fixture snapshot with
	// authoring.CodeCatalogIsFixture.
	Fixture bool
	// Catalog is the authoring-time view: what an author may reference and how
	// a rejection is worded. Its Provenance carries Source, Fixture, Digest and
	// RegistryVersion so that a consumer holding only the catalog still holds
	// the identity of the snapshot it came from.
	Catalog *authoring.Catalog
	// Registry is the governance-layer catalog the authoring view was projected
	// from. It is what an engine's admission registry and a plane's enforcement
	// profile are read out of.
	Registry *registry.Catalog
	// Digest is contract.ExactDigest over the authoring view's actions, realms
	// and resource types. Two snapshots with equal digests admit and refuse the
	// same policies.
	Digest string
	// RegistryVersion is the integer the wire carries as
	// contract.Snapshot.RegistryVersion and proof.Binding.ToolRegistryVersion.
	// For the deployment vocabulary it is DeploymentCatalogVersion, which a test
	// welds to Digest: the digest cannot move without the version moving.
	RegistryVersion int64
	// CorpusDigest is the digest of the shipped system corpus this vocabulary
	// declares the detectors of, empty for a fixture.
	//
	// IT IDENTIFIES THE CORPUS THIS VOCABULARY WAS BUILT AGAINST, and it is NOT
	// the digest an engine's system bundle carries. An earlier version of this
	// comment said it was "the value an anchored engine's system bundle must
	// digest to", which is false by construction for every plane: an engine
	// activates the corpus RESTRICTED to the controls that bind on its plane, so
	// its bundle digests to something else on purpose. The two are related by
	// the restriction, not by equality, and pdp's own anchor is what checks that
	// relationship (checkSystemRestriction, one policy at a time).
	//
	// What it is FOR: telling two deployments' vocabularies apart, and saying
	// which corpus the detector set in this snapshot was derived from.
	CorpusDigest string
	// Edition is the build edition the enforcement planes were registered for.
	Edition registry.Edition
}

// PEPFor returns the enforcement profile of one in-process plane, as the
// registry declares it for this snapshot's edition, or false when the plane is
// not registered.
//
// It is read out of the SNAPSHOT'S registry rather than from the checked-in
// table directly, so that the profile a plane advertises to an engine is the
// one the same snapshot's admission registry was projected beside.
func (s *Snapshot) PEPFor(plane string) (*contract.PEPProfile, bool) {
	if s == nil || s.Registry == nil {
		return nil, false
	}
	rec, ok := s.Registry.PEP(registry.LegacyPlanePEPPrefix + plane)
	if !ok {
		return nil, false
	}
	return &contract.PEPProfile{ID: rec.ID, Capabilities: append([]contract.Capability(nil), rec.Capabilities...)}, true
}

// Deployment is what the platform module knows and this module cannot: which
// realms the identity plane mints principals in and how each behaves, and
// which edition this build is.
//
// It is REQUIRED for SourceDeployment and ignored for SourceConformance, whose
// fixture world describes its own realms. A caller that resolves the
// deployment vocabulary without describing its realms gets a refusal, not a
// catalog with no realm in it: a vocabulary whose realm set was invented here
// would let an author scope a policy to a realm no request can arrive from.
type Deployment struct {
	// Edition selects the enforcement-plane rows registered as PEPs.
	Edition registry.Edition
	// Realms are the identity plane's trust realms and their authoring
	// attributes, keyed by realm qualifier.
	Realms map[string]authoring.RealmEntry
	// Now is the instant compatibility expiry is judged against. Zero is
	// refused by the registry rather than defaulted, so a snapshot can be
	// replayed.
	Now time.Time
}

// Resolve maps the environment value onto a snapshot.
//
// Two outcomes:
//
//   - unset, empty or a recognised value: the snapshot. Unset is the
//     deployment vocabulary (PRD §1.5), so there is no "no catalog" posture
//     for a transport to answer 503 with.
//   - anything else: an error. A value nobody chose must not select a policy
//     vocabulary, and silently falling back to the default would mean a typo in
//     a deployment variable changes which policies are expressible.
func Resolve(raw string, dep Deployment) (*Snapshot, error) {
	value, err := Value(raw)
	if err != nil {
		return nil, err
	}
	switch value {
	case SourceConformance:
		reg, err := conformance.Catalog()
		if err != nil {
			return nil, fmt.Errorf("the conformance catalog could not be built: %w", err)
		}
		cat, err := authoring.NewCatalogFromRegistry(reg, ConformanceRealmAttributes())
		if err != nil {
			return nil, fmt.Errorf("the conformance registry is not usable as an authoring catalog: %w", err)
		}
		return finish(SourceConformance, true, reg, cat, "", conformanceCatalogVersion, registry.EditionCommunity)
	default:
		return resolveDeployment(dep)
	}
}

// conformanceCatalogVersion is the registry version a FIXTURE snapshot carries.
// Zero is deliberate: contract.Snapshot.Validate accepts it, and a decision
// stamped with version 0 is visibly not a decision against a deployment
// vocabulary.
const conformanceCatalogVersion int64 = 0

// finish stamps the shared fields and validates the result once.
func finish(source string, fixture bool, reg *registry.Catalog, cat *authoring.Catalog, corpusDigest string, version int64, edition registry.Edition) (*Snapshot, error) {
	digest, err := CatalogDigest(cat)
	if err != nil {
		return nil, err
	}
	cat.Provenance = authoring.CatalogProvenance{
		Source:          source,
		Fixture:         fixture,
		Digest:          digest,
		RegistryVersion: version,
	}
	s := &Snapshot{
		Source:          source,
		Fixture:         fixture,
		Catalog:         cat,
		Registry:        reg,
		Digest:          digest,
		RegistryVersion: version,
		CorpusDigest:    corpusDigest,
		Edition:         edition,
	}
	return s, nil
}

// CatalogDigest is the content identity of an authoring catalog: its actions,
// realms and resource types, and nothing else.
//
// The Provenance is EXCLUDED on purpose, and not only because it would be
// circular. The digest answers "would this catalog admit and refuse the same
// policies as that one", and the label a deployment resolved it under is not
// part of that answer.
func CatalogDigest(cat *authoring.Catalog) (string, error) {
	if cat == nil {
		return "", fmt.Errorf("authoringcatalog: cannot digest a nil catalog")
	}
	return contract.ExactDigest(catalogContent{
		Actions:       cat.Actions,
		Realms:        cat.Realms,
		ResourceTypes: cat.ResourceTypes,
	})
}

// catalogContent is the digested projection. Maps encode with sorted keys under
// contract.ExactJSON, so the digest is order-independent.
type catalogContent struct {
	Actions       map[string]pdp.ActionEntry        `json:"actions"`
	Realms        map[string]authoring.RealmEntry   `json:"realms"`
	ResourceTypes map[string]authoring.ResourceType `json:"resource_types"`
}

// ConformanceRealmAttributes describes the fixture world's realms.
//
// NewCatalogFromRegistry takes realm ATTRIBUTES from the caller rather than the
// registry on purpose - whether a realm is interactive and whether it has a
// group graph are identity-plane facts owned by platform/shared/identity, and
// restating them in the registry would make it a second authority on the
// directory - and it REFUSES a set that disagrees with the registry's trusted
// realms in either direction. So this map is held to the registry by that
// refusal, not by a reader remembering to update it.
func ConformanceRealmAttributes() map[string]authoring.RealmEntry {
	return map[string]authoring.RealmEntry{
		// The workspace realm is where people are: an approval resolving there
		// can be answered, which is what POOL_NOT_INTERACTIVE checks.
		conformance.RealmWorkspace: {Interactive: true, HasGroupGraph: true},
		// A cloud realm's subjects are service identities; nobody there answers
		// a challenge, and it carries a directory group graph.
		conformance.RealmGCP: {Interactive: false, HasGroupGraph: true},
		// A connector realm has neither: no person and no group closure, so a
		// group-scoped policy there is well formed and can never match, which
		// GROUP_SCOPE_WITHOUT_GRAPH warns about rather than refusing.
		conformance.RealmConnector: {Interactive: false, HasGroupGraph: false},
	}
}

// sortedKeys is the deterministic iteration order every derivation here uses.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
