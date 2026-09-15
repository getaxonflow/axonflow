// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package activation builds the PRODUCTION decision engine: the shipped system
// corpus, anchored to the digest this binary was built with, beside the
// organization's active typed document, against the deployment vocabulary,
// advertising the enforcement profile of the plane that will enforce it.
//
// # Why this package exists (#3895)
//
// Before it, `pdp.AnchorToShippedCorpus()` had zero non-test callers: #3967
// put the corpus in the model and built the anchor, and the only production
// construction of a `pdp.Engine` was the shadow observer's, which is
// `Unanchored(...)` by design and compiles a per-observation world with a
// blanket permission and a synthetic enforcement profile. "The corpus is in the
// model" and "the model enforces the corpus" were different facts. This is the
// construction that makes them one fact: it is what a plane runs under
// `enforce`, and it is what an activation verb dry-runs before flipping the
// active digest, so a document that cannot be enforced cannot become active.
//
// # What it refuses, by name
//
//   - a FIXTURE vocabulary (authoring.CodeCatalogIsFixture): a deployment may
//     not enforce a world no request can arrive in;
//   - a BLANKET permission (pdp.RefusalBlanketPermission): the shadow
//     harness's stand-in for the legacy substrate's missing gate, refused by
//     the anchored engine because it permits every action registered after it;
//   - a system bundle that is not the shipped corpus (the anchor), and an
//     engine with no system bundle at all;
//   - a system key that signed the organization document it activates beside
//     (RefusalSystemKeyIsOrganizationKey, #4047): the two roots are separate
//     signing authorities, and the engine's trust store is built per
//     activation so that nothing is ever authorized into the caller's;
//   - a composition key that is the system key or the organization's
//     (RefusalCompositionKeySignsAnotherRoot, #4045), and an authored policy
//     whose id takes the prefix an override's replacement carries
//     (RefusalOverridePolicyIDReserved);
//   - a plane the deployment vocabulary does not register, because an engine
//     that advertises no enforcement profile denies every mandatory obligation
//     and an engine that advertises an invented one permits what the plane
//     cannot discharge.
//
// # Community-visible, no build tag
//
// The model is `community_core` (ADR-066 driver 3). The organization document
// a Community deployment activates is bounded by authoring.Profile at
// publication; nothing here widens what may be written, so nothing here is
// Enterprise.
package activation

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// RefusalSystemKeyIsOrganizationKey is the code Activate refuses with when the
// system authority's key is the key that signed the organization document being
// activated beside it (#4047). One key under both roots makes the organization
// authority and the system authority the same authority.
const RefusalSystemKeyIsOrganizationKey = "SYSTEM_KEY_IS_AN_ORGANIZATION_KEY"

// RefusalBaselinePackUnsigned is the code Activate refuses with when no
// composition authority was supplied: every organization root composes the
// deployment's baseline permission pack beside whatever document is active
// (PRD v11 §1.4), and something must sign that root.
const RefusalBaselinePackUnsigned = "BASELINE_PACK_UNSIGNED"

// Inputs is everything a production engine is built from. Every field but
// Organization, OrganizationID, Overrides, BreakGlass and Limits is required;
// OrganizationID is required with Overrides. Composition is required always,
// because every organization root composes the baseline permission pack.
type Inputs struct {
	// Snapshot is the deployment vocabulary, resolved once
	// (authoringcatalog.Resolve with SourceDeployment).
	Snapshot *authoringcatalog.Snapshot
	// Organization is the organization's ACTIVE typed document, or nil when
	// none is active yet.
	//
	// THE ORGANIZATION ROOT IS COMPOSED, WHATEVER IS ACTIVE (PRD v11 §1.4).
	// ADR-065 denies what no permission grants, so the shipped corpus alone
	// would deny every request. The organization root is the active document
	// composed with the deployment's baseline permission pack
	// (authoringcatalog.BaselinePermissionPack): the explicit permission set
	// the deployment runs under, which an organization narrows with
	// constraints (invariant 6). A pack policy the document already carries is
	// the document's own and stands. While no document is active the root also
	// composes the organization template restricted to the scope
	// (OrganizationTemplateForScope): the shipped controls a deployment
	// instantiates per organization. A published document replaces the
	// template by digest - the organization owns its root, so a template
	// control its document omits stops deciding, and one it carries binds
	// only where the template's would (Activation.UnboundTemplateControls).
	// The root is signed by Composition: never persisted and never an
	// organization key.
	Organization *authoring.Artifact
	// Trust is where the organization artifact's signing key is READ from: the
	// store the authoring surface verifies against. This package never writes
	// to it (#4047). The engine verifies through a trust store of its own, built
	// from the system publication plus the one organization key read here.
	Trust *pdp.TrustStore
	// System is the system-root authority that signs this process's
	// restriction of the shipped corpus. Its key must not be the key that
	// signed the organization document.
	System *authoring.SystemAuthority
	// OrganizationID names the organization whose recorded overrides Overrides
	// carries, in the reason the restriction records.
	OrganizationID string
	// Overrides are the organization's recorded detection overrides as the
	// plane's legacy engine assigns them: policy category to action, the map
	// legacycompile's static compile applies. Where the plane passes them
	// (PlaneSpec.PassesOrgOverrides), each shipped control of an assigned
	// category leaves the system restriction and is carried on the organization
	// root with the assigned action (#4045; see overrides.go). Empty activates
	// the shipped actions.
	Overrides legacycompile.CategoryActions
	// Composition signs the organization root: the active document, or none,
	// less the template controls it carries that the scope does not bind,
	// composed with the baseline pack, the organization template while no
	// document is active, and the replacements Overrides carries. Its key must
	// be neither the system key nor the organization's.
	Composition *authoring.CompositionAuthority
	// Plane is the enforcement plane this engine will decide for, in the
	// registry's plane vocabulary (registry/legacy_plane_peps.tsv). It selects
	// the enforcement profile the engine advertises.
	Plane string
	// Phase names which of a two-phase plane's phases this engine decides
	// (#3564); empty for a plane that evaluates one. The two phases of one
	// plane bind different controls, so an engine is built for one of them.
	Phase legacycompile.Phase
	// Delivers is what the wire this scope answers on hands to an enforcement
	// point that DECLARES it in its capability handshake (#4046). A scope that
	// returns its decision over the Decision API passes
	// contract.DecisionWireCapabilities(); a pass that discharges inline and
	// returns no obligation to its caller passes nil. It is supplied by the
	// caller rather than looked up by plane, because it is a fact about the SEAM
	// that renders the decision: a plane with no enforcing seam delivers
	// nothing, whatever its legacy handler once answered.
	Delivers []contract.Capability
	// Profile is the deployment's authoring boundary, resolved from the SIGNED
	// licence by the caller (platform/shared/authoringedition is the one
	// resolver). It is passed in rather than resolved here because
	// platform/decision is its own module and carries no dependency on the
	// licence package - the same reason authoring.EditionFor takes a string.
	//
	// Required whenever RefuseConstructsOutsideEdition is set; a zero value is
	// refused by authoring.Profile.Validate rather than read as an edition.
	Profile authoring.Profile
	// RefuseConstructsOutsideEdition turns on the edition-construct check at
	// this activation, using Profile.
	//
	// # WHY THE CALLER DECIDES, AND WHAT EACH CALLER DECIDES
	//
	// The answer differs by DOOR, not by document, so it cannot be derived
	// here. The transports' dry run - publish, promote, rollback - sets it
	// unconditionally: refusing there costs an author one refusal at the moment
	// they are choosing what to write, which is ADR-066's chokepoint 2.
	//
	// The agent's enforcement seam sets it only when the deployment's tier is
	// ESTABLISHED AND NOT IN A LICENCE TRANSITION
	// (authoringedition.Resolution.EnforcesConstructBoundary). An activation
	// error there is not a refusal an author reads: it becomes HTTP 503 on
	// /api/v1/decide and a withheld MCP response, so refusing on a licence that
	// merely lapsed would convert an entitlement change into an outage - the
	// one LicenceTransitionMode exists to prevent, reached through the seam
	// instead of the healthcheck (#4094).
	RefuseConstructsOutsideEdition bool
	// Packs are the policy packs this deployment installed (PRD v11 §1.9),
	// instantiated for its realms (InstallPacks). Each composes on the
	// organization root beside the baseline pack, restricted to what this scope
	// evaluates (packs.go), whether or not a document is active: a pack is the
	// deployment's, and an organization's document does not remove it. A pack
	// policy the document already carries is the document's own and stands.
	Packs []InstalledPack
	// ApprovalTTL is the challenge lifetime stamped on a composed approval.
	ApprovalTTL time.Duration
	// BreakGlass is optional.
	BreakGlass pdp.BreakGlassLookup
	// Limits bound evaluation; zero means pdp.DefaultLimits.
	Limits pdp.Limits
}

// Activation is a built production engine and the identities a decision made
// by it carries.
type Activation struct {
	Engine *pdp.Engine
	// Snapshot is the vocabulary the engine admits against.
	Snapshot *authoringcatalog.Snapshot
	// Plane and PEP are the enforcement point the engine advertises.
	Plane string
	PEP   *contract.PEPProfile
	// Delivers is what this scope's wire hands to an enforcement point that
	// declares it, narrowed to what an enforcement point of this edition may
	// declare (#4046): the delivery this engine was activated with, recorded so
	// the activation states what its discharge guard counted.
	Delivers []contract.Capability
	// Scope is the plane, or the one phase of a two-phase plane, whose
	// restriction this engine activated (#3564).
	Scope legacycompile.EnforcementScope
	// Restriction says which of the shipped corpus's controls do not bind on
	// this plane, and why. It is carried rather than recomputed so an operator
	// reading "which of the platform's controls does this plane enforce" gets
	// the sentence the anchor was built from.
	Restriction string
	// Overrides is what the organization's recorded detection overrides did on
	// this scope: one entry per assigned policy category, sorted, naming the
	// shipped controls each displaced (#4045). Nil when none is recorded.
	Overrides []OverrideDisplacement
	// UnboundTemplateControls are the organization template's controls the
	// active document carries and this scope does not bind, in the document's
	// order: left out of the organization root here, as the implicit bundle
	// leaves them out of the template, because a control whose detector this
	// scope does not run would refuse every request it cannot decide. Nil when
	// there are none, and while no document is active.
	UnboundTemplateControls []string
	// SystemControls is what the active document's system_controls did on this
	// scope (PRD v11 §1.5): one entry per control it names, sorted, naming the
	// shipped policies each displaced here. Nil when it names none.
	SystemControls []SystemControlEffect
	// SystemPolicies is how many shipped controls this plane activates, of how
	// many the corpus carries. Two numbers rather than one: a restriction that
	// silently became total would otherwise read as a small number nobody could
	// compare against anything.
	SystemPolicies, ShippedPolicies int
	// SystemBundleDigest is the verified digest of the RESTRICTED corpus bundle
	// as signed by this process.
	//
	// It is deliberately NOT Snapshot.CorpusDigest and must not be compared to
	// it: this bundle is compiled from the corpus restricted to this plane, so
	// it digests to something else for every plane that restricts anything. The
	// relationship between them is the anchor's subset check, not equality.
	SystemBundleDigest string
	// OrganizationBundleDigest is the verified digest of the organization-root
	// bundle the engine activated: the composition's whenever anything was
	// composed with the authored document - the baseline pack, the organization
	// template, a recorded override's replacements (#4045) - or anything was
	// left out of it (UnboundTemplateControls), and the authored document's own
	// when it already carries the whole pack, no override applies and it binds
	// here whole.
	OrganizationBundleDigest string
	// OrganizationArtifactDigest is the authoring artifact digest that was
	// activated - the value an activation record names - empty when none.
	OrganizationArtifactDigest string
	// ImplicitBaseline reports that no organization document is active, so the
	// organization root is the deployment's baseline permission pack and the
	// organization template, composed by this process (see
	// Inputs.Organization). PolicyBundle names it by digest, as it names a
	// published document.
	ImplicitBaseline bool
	// PolicyBundle is the ONE digest a decision carries for "which policy set
	// decided this": contract.ExactDigest over [system, organization] bundle
	// digests in that order. Two roots, one identity, so a rollback of the
	// organization document moves every decision's snapshot.
	PolicyBundle string
	// Packs are the installed policy packs that bind at least one control on
	// this scope, sorted by id. A pack that binds nothing here composed nothing
	// here and is not listed. PolicyBundle already moves with them, because
	// they compose into the organization root; the wire and the audit row name
	// them by their own digest as well, so which pack decided is legible.
	Packs []PackActivation
	// DocumentVersion is the published version of the organization document
	// this engine activated, read from the artifact's signed provenance; zero
	// under the implicit baseline, which PolicyBundle names by digest instead
	// (PRD v11 §1.14).
	DocumentVersion int

	// policies indexes every policy the engine activated - the system
	// restriction and the organization document - by id, so a seam applying a
	// decision can read what a determining policy attached (see Policy).
	policies map[string]pdp.Policy
	// detectorSignals are the censused detector signal paths those policies
	// read, sorted (see DetectorSignalPaths).
	detectorSignals []string
	// origins records each organization-root policy that is not shipped - the
	// organization's own document's, or an installed pack's - with the version
	// it was published at (see Identity). A policy with no entry is shipped.
	origins map[string]policyOrigin
	// disabled are the shipped policies the organization's document disabled on
	// this scope, as the restriction held them (see PolicyEffects). The engine
	// does not carry them.
	disabled []pdp.Policy
	// census is the shipped detector census by signal path, which names the
	// category and severity of a control that reads a censused detector (see
	// PolicyEffects).
	census map[string]censusFact
}

// RequestSnapshot is the contract.Snapshot every request to this engine must
// carry. The identity and resource epochs come from the caller's identity and
// resource planes; the policy epoch is the activation sequence of the
// organization root, which the durable store advances per activation.
func (a *Activation) RequestSnapshot(identityEpoch, resourceEpoch, policyEpoch int64) contract.Snapshot {
	return contract.Snapshot{
		IdentityEpoch:   identityEpoch,
		ResourceEpoch:   resourceEpoch,
		PolicyBundle:    a.PolicyBundle,
		RegistryVersion: a.Snapshot.RegistryVersion,
		SchemaVersion:   contract.SchemaVersion,
		PolicyEpoch:     policyEpoch,
	}
}

// Activate builds the production engine.
func Activate(ctx context.Context, in Inputs) (*Activation, error) {
	if in.Snapshot == nil || in.Snapshot.Catalog == nil || in.Snapshot.Registry == nil {
		return nil, fmt.Errorf("activation: a resolved deployment vocabulary is required; nothing can be enforced against no vocabulary")
	}
	if in.Snapshot.Fixture {
		return nil, &authoring.ErrCatalogIsFixture{Source: in.Snapshot.Source}
	}
	if in.Trust == nil {
		return nil, fmt.Errorf("activation: a trust store is required; an unverified bundle cannot be activated")
	}
	if in.System == nil {
		return nil, fmt.Errorf("activation: a system-root authority is required to sign the shipped corpus for this process (authoring.NewSystemAuthority)")
	}
	if in.Composition == nil {
		return nil, &pdp.ActivationRefusal{
			Code: RefusalBaselinePackUnsigned,
			Detail: "every organization root composes the deployment's baseline permission pack beside whatever document is " +
				"active, and no composition authority was supplied to sign it (authoring.NewCompositionAuthority). The shipped " +
				"corpus is never activated alone: it permits nothing, and denying for want of a permission set is not a state " +
				"this product has",
		}
	}
	pep, ok := in.Snapshot.PEPFor(in.Plane)
	if !ok {
		return nil, fmt.Errorf("activation: plane %q is not a registered enforcement point of this %s build; an engine cannot advertise a profile the deployment never declared",
			in.Plane, in.Snapshot.Edition)
	}

	// THE ANCHOR, AND THE PLANE RESTRICTION. This is the production call site
	// the shipped-corpus anchor did not have before #3895.
	//
	// The engine activates the corpus RESTRICTED to the controls that bind on
	// this plane (see restriction.go for the measurement that forced it), and
	// the anchor verifies that restriction as a SUBSET of the corpus this
	// binary shipped: a control may be left out, never added and never edited.
	// The system authority asks the anchor the same question before it signs,
	// so it cannot sign a document the engine below would refuse.
	scope, err := legacycompile.ScopeFor(legacycompile.Plane(in.Plane), in.Phase)
	if err != nil {
		return nil, fmt.Errorf("activation: %w", err)
	}
	system, restriction, err := RestrictToScope(scope)
	if err != nil {
		return nil, err
	}
	// THE ORGANIZATION'S DOCUMENT, read here because its system_controls shape
	// the restriction below (PRD v11 §1.5). It is the artifact's signed source:
	// an Artifact is built only by Publish or LoadArtifact, both of which bind
	// the source to its signature, so nothing unverified moves the platform's
	// ceiling. The fold runs before foldOverrides, so per-policy control
	// takes precedence over the recorded category posture.
	var orgDoc *authoring.Document
	controls := systemControlFold{system: system}
	if in.Organization != nil {
		if in.Organization.Root() != pdp.RootOrganization {
			return nil, fmt.Errorf("activation: the organization artifact declares root %q; the system root is the shipped corpus and nothing else activates there", in.Organization.Root())
		}
		if orgDoc, err = in.Organization.Document(); err != nil {
			return nil, fmt.Errorf("activation: the organization artifact's source does not parse: %w", err)
		}
		if controls, err = foldSystemControls(scope, system, orgDoc.SystemControls); err != nil {
			return nil, err
		}
		if controls.reason != "" {
			system = controls.system
			restriction += "; " + controls.reason
		}
	}
	// THE ORGANIZATION'S RECORDED OVERRIDES (#4045). Where this plane's legacy
	// engine applies them, each shipped control of an assigned category leaves
	// the restriction and returns on the organization root with the assigned
	// action, composed below. The fold's reason joins the restriction's, so the
	// anchor records why this organization's ceiling is narrower than the
	// scope's.
	fold, err := foldOverrides(scope, system, in.OrganizationID, in.Overrides)
	if err != nil {
		return nil, err
	}
	if fold.reason != "" {
		system = fold.system
		restriction += "; " + fold.reason
	}
	// THE DISCHARGE GUARD (#4046), beside the restriction it reads: a shipped
	// control that binds here and carries a mandatory obligation that neither
	// this plane discharges nor its wire can hand to a declaring caller would
	// deny every request it matches as unsupported_obligation - a verdict the
	// legacy engine never gave. It is a (policy, scope, surface) fact, so it is
	// checked where the corpus meets a scope, never baked into the corpus
	// artifact.
	//
	// An override's replacement is not guarded here. It is the organization's
	// recorded choice, and a mandatory obligation it carries that a caller
	// cannot discharge is a per-decision unsupported_obligation (ADR-065
	// invariant 8), never an activation that refuses the organization.

	// THE EDITION BOUNDARY (#3592), after foldOverrides and before the
	// discharge guard. The order is deliberate: the overrides are folded
	// first, so this judges the document as it will actually be ENFORCED
	// rather than as it was written. It is off unless the caller asks - see
	// Inputs.RefuseConstructsOutsideEdition for which door asks and why.
	if err := refuseConstructsOutsideEdition(in); err != nil {
		return nil, err
	}

	surface := NewDischargeSurface(pep, in.Delivers, in.Snapshot.Edition)
	if err := refuseUndischargeable(scope, system, surface); err != nil {
		return nil, err
	}
	// THE SHIPPED TEMPLATE IS HELD TO THE SAME GUARD (#4131). The implicit bundle
	// composes the organization template restricted to this scope, and a
	// published document's copy of a template control binds only where the
	// template's does, so a template control carrying a mandatory obligation this
	// surface cannot discharge would deny every request it matches exactly as a
	// system control would. Only the SHIPPED template is judged here; what an
	// organization authors stays a per-decision unsupported_obligation.
	shippedTemplate, err := OrganizationTemplateForScope(scope)
	if err != nil {
		return nil, fmt.Errorf("activation: the organization template on %s: %w", scope, err)
	}
	if err := refuseUndischargeable(scope, shippedTemplate, surface); err != nil {
		return nil, fmt.Errorf("the organization template: %w", err)
	}
	published, err := in.System.Publish(system, restriction)
	if err != nil {
		return nil, err
	}

	// THE ENGINE'S TRUST STORE IS ITS OWN (#4047).
	//
	// This used to authorize the system key into in.Trust - the store the
	// organization's authoring surface verifies against - on every activation,
	// and every transport passed its organization workspace's own signing key
	// as the system key. A dry run therefore left the organization's key
	// authorized under the system root in the organization's own store, and the
	// route's org-root constant was the only thing between a caller and a
	// system-root publication that store would admit. Building a store per
	// activation from the system publication plus the one organization key read
	// below leaves the caller's store exactly as it was.
	trust := published.TrustStore()
	bundles := []*pdp.Bundle{published.Bundle}
	docs := []*pdp.Document{system}
	orgBundleDigest, orgArtifactDigest := "", ""
	documentVersion, origins := 0, map[string]policyOrigin{}
	var authored *authoring.AuthoredSource
	if in.Organization != nil {
		orgBundle := in.Organization.Bundle()
		orgKey, ok := in.Trust.PublicKey(pdp.RootOrganization, orgBundle.KeyID)
		if !ok {
			return nil, fmt.Errorf("%w: the organization bundle is signed by key %q, which the caller's trust store does not authorize under the %q root",
				authoring.ErrKeyNotAuthorized, orgBundle.KeyID, pdp.RootOrganization)
		}
		// ONE KEY, TWO ROOTS, IS ONE AUTHORITY. Refused by name rather than
		// tolerated, because it is exactly what both transports did: the key
		// that signs the organization's documents would be the key the engine
		// trusts for the platform's ceiling.
		if orgKey.Equal(in.System.PublicKey()) {
			return nil, &pdp.ActivationRefusal{
				Code: RefusalSystemKeyIsOrganizationKey,
				Detail: fmt.Sprintf("the system authority's key is the key %q that signed the organization document. The "+
					"system root and the organization root are separate signing authorities; mint the system key separately "+
					"(authoring.NewSystemAuthority) so that no key signs under both", orgBundle.KeyID),
			}
		}
		if err := refuseReservedOverrideIDs(&orgDoc.Policy); err != nil {
			return nil, err
		}
		authored = &authoring.AuthoredSource{Document: &orgDoc.Policy, Bundle: orgBundle, Key: orgKey}
		orgArtifactDigest = in.Organization.Digest()
		documentVersion = in.Organization.Provenance().DocumentVersion
		for _, p := range orgDoc.Policy.Policies {
			origins[p.ID] = policyOrigin{source: SourceOrganization, version: documentVersion}
		}
	}
	// THE ORGANIZATION ROOT (see Inputs.Organization): the authored document, if
	// one is active, composed with the baseline pack it does not already carry,
	// with the organization template while none is active, and with the
	// replacements a recorded override carries. One bundle, signed by the
	// composition authority once it has verified the authored bundle itself,
	// because the engine accepts one per root.
	pack, err := authoringcatalog.BaselinePermissionPack(in.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("activation: the baseline permission pack: %w", err)
	}
	additions := notCarried(pack.Policies, authored)
	schemas := slices.Clone(pack.Attributes)
	// THE INSTALLED POLICY PACKS (PRD v11 §1.9), beside the baseline pack and on
	// the same terms: implicit or published, each composes what binds here.
	var packs []PackActivation
	packSignals := map[string]bool{}
	for _, ip := range in.Packs {
		scoped, err := packForScope(scope, ip)
		if err != nil {
			return nil, err
		}
		for _, d := range ip.Pack.Source.Detectors {
			packSignals[legacycompile.DetectorSignalPath(d.ID)] = true
		}
		if len(scoped.Policies) == 0 {
			continue
		}
		// A pack control the document already carries is the document's own.
		composed := notCarried(scoped.Policies, authored)
		for _, p := range composed {
			origins[p.ID] = policyOrigin{source: SourcePack, version: ip.Pack.Source.Version}
		}
		additions = append(additions, composed...)
		schemas = append(schemas, scoped.Attributes...)
		packs = append(packs, PackActivation{
			ID: ip.Pack.Source.ID, Version: ip.Pack.Source.Version, Digest: ip.Digest,
			Policies: len(scoped.Policies), Of: len(ip.Document.Policies),
		})
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].ID < packs[j].ID })
	if authored == nil {
		additions = append(additions, shippedTemplate.Policies...)
		schemas = append(schemas, shippedTemplate.Attributes...)
	}
	additions = append(additions, fold.replacements...)
	schemas = append(schemas, fold.schemas...)
	// The document's re-actioned controls return on the organization root
	// beside the category fold's replacements. They are the organization's own
	// edit, so they are named as its, at its document version.
	for _, p := range controls.replacements {
		origins[p.ID] = policyOrigin{source: SourceOrganization, version: documentVersion}
	}
	additions = append(additions, controls.replacements...)
	schemas = append(schemas, controls.schemas...)
	// A TEMPLATE CONTROL BINDS WHERE THE TEMPLATE'S DOES. A published document
	// carries the organization template's controls, first as the draft it was
	// seeded with, and a scope that does not run one's detector would decide it
	// UNKNOWN and refuse every request, so the composition leaves each such
	// control out here exactly as the implicit bundle leaves the template's out.
	var unbound []string
	if authored != nil {
		if unbound, err = unboundTemplateControls(scope, authored.Document); err != nil {
			return nil, fmt.Errorf("activation: the organization template on %s: %w", scope, err)
		}
	}
	var orgBundle *pdp.Bundle
	switch {
	case len(additions) > 0 || len(unbound) > 0:
		compKey := in.Composition.PublicKey()
		if compKey.Equal(in.System.PublicKey()) || (authored != nil && compKey.Equal(authored.Key)) {
			return nil, &pdp.ActivationRefusal{
				Code: RefusalCompositionKeySignsAnotherRoot,
				Detail: "the composition authority's key is the system key or the key that signed the organization document. A composed " +
					"organization root is neither authored by the organization nor shipped by the release, so it has a signing authority " +
					"of its own; mint its key separately (authoring.NewCompositionAuthority)",
			}
		}
		comp, err := in.Composition.Compose(authored, unbound, additions, schemas)
		if err != nil {
			return nil, fmt.Errorf("activation: %w", err)
		}
		trust.Authorize(pdp.RootOrganization, authoring.CompositionKeyID, compKey)
		orgBundle = comp.Bundle
		docs = append(docs, comp.Document)
	case authored != nil:
		trust.Authorize(pdp.RootOrganization, authored.Bundle.KeyID, authored.Key)
		orgBundle = authored.Bundle
		docs = append(docs, authored.Document)
	}
	if orgBundle != nil {
		bundles = append(bundles, orgBundle)
	}

	registry, err := in.Snapshot.Registry.PDPRegistry()
	if err != nil {
		return nil, fmt.Errorf("activation: %w", err)
	}
	engine, err := pdp.NewEngine(ctx, pdp.EngineConfig{
		Bundles:       bundles,
		Documents:     docs,
		TrustStore:    trust,
		PayloadLeaves: payloadLeaves(in.Snapshot.Catalog),
		ApprovalTTL:   in.ApprovalTTL,
		PEP:           pep,
		BreakGlass:    in.BreakGlass,
		Registry:      registry,
		SystemCorpus:  published.Anchor,
		Limits:        in.Limits,
	})
	if err != nil {
		return nil, err
	}

	// RECOMPUTED, not advertised (#3700): NewEngine has verified every bundle
	// by now, so a failure here is a defect rather than a data condition.
	sysDigest, err := published.Bundle.VerifiedDigest()
	if err != nil {
		return nil, fmt.Errorf("activation: system bundle digest: %w", err)
	}
	if orgBundle != nil {
		orgBundleDigest, err = orgBundle.VerifiedDigest()
		if err != nil {
			return nil, fmt.Errorf("activation: organization bundle digest: %w", err)
		}
	}
	policyBundle, err := contract.ExactDigest([]string{sysDigest, orgBundleDigest})
	if err != nil {
		return nil, err
	}
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		return nil, err
	}
	policies := map[string]pdp.Policy{}
	for _, doc := range docs {
		for _, p := range doc.Policies {
			policies[p.ID] = p
		}
	}
	census, err := detectorCensusBySignalPath()
	if err != nil {
		return nil, err
	}
	var detectorSignals []string
	for _, p := range policies {
		for _, path := range p.ReferencedPaths() {
			if _, censused := census[path]; censused || packSignals[path] {
				detectorSignals = append(detectorSignals, path)
			}
		}
	}
	sort.Strings(detectorSignals)
	detectorSignals = slices.Compact(detectorSignals)
	return &Activation{
		Engine:                     engine,
		Snapshot:                   in.Snapshot,
		Plane:                      in.Plane,
		PEP:                        pep,
		Delivers:                   surface.Delivers,
		Scope:                      scope,
		Restriction:                restriction,
		Overrides:                  fold.displacements,
		UnboundTemplateControls:    unbound,
		SystemControls:             controls.effects,
		SystemPolicies:             len(system.Policies),
		ShippedPolicies:            len(shipped.Policies),
		SystemBundleDigest:         sysDigest,
		OrganizationBundleDigest:   orgBundleDigest,
		OrganizationArtifactDigest: orgArtifactDigest,
		ImplicitBaseline:           authored == nil,
		PolicyBundle:               policyBundle,
		Packs:                      packs,
		DocumentVersion:            documentVersion,
		policies:                   policies,
		detectorSignals:            detectorSignals,
		origins:                    origins,
		disabled:                   controls.disabled,
		census:                     census,
	}, nil
}

// notCarried is the pack's policies the authored document does not already
// carry. A document that published the pack itself keeps its own copy, and a
// composition refuses a second policy under one id.
func notCarried(pack []pdp.Policy, authored *authoring.AuthoredSource) []pdp.Policy {
	out := slices.Clone(pack)
	if authored == nil {
		return out
	}
	carried := make(map[string]bool, len(authored.Document.Policies))
	for _, p := range authored.Document.Policies {
		carried[p.ID] = true
	}
	return slices.DeleteFunc(out, func(p pdp.Policy) bool { return carried[p.ID] })
}

// Policy returns a policy this engine activated - from the system restriction
// or the organization document - by id. A seam applying a decision reads what a
// determining policy attached here, from the documents the engine was built
// over, rather than deriving either document a second time.
func (a *Activation) Policy(id string) (pdp.Policy, bool) {
	if a == nil {
		return pdp.Policy{}, false
	}
	p, ok := a.policies[id]
	return p, ok
}

// DetectorSignalPaths returns the censused detector signal paths the policies
// this engine activated read, sorted, as a copy. A seam that knows the content
// it evaluates is EMPTY states each as known-false, because a content detector
// over no content has a determined answer (#3564).
func (a *Activation) DetectorSignalPaths() []string {
	if a == nil {
		return nil
	}
	return slices.Clone(a.detectorSignals)
}

// payloadLeaves is the union of every registered action's payload leaves,
// sorted and deduplicated - the surface disclosure obligations expand over.
func payloadLeaves(cat *authoring.Catalog) []string {
	set := map[string]struct{}{}
	for _, a := range cat.Actions {
		for _, l := range a.PayloadLeaves {
			set[l] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Activator returns the authoring.Activator a transport installs on its API:
// a DRY activation of the candidate artifact, built exactly as the enforcing
// engine would be and then discarded. `deps` is called per activation, with its context, so that
// a snapshot, a trust store or an organization's recorded posture replaced
// under a long-lived API is the one checked against. An error from it refuses
// the activation: a dry run that cannot read what the engine would be built
// from does not guess it.
//
// The dry run is the FIRST plane's profile and the first plane only: an
// artifact that cannot be enforced on one registered plane cannot be enforced
// on another for any reason that depends on the document, because the
// document is the same and the plane changes only the advertised
// capabilities - and a capability the plane lacks is a per-decision deny
// (invariant 8), not an activation failure.
func Activator(deps func(context.Context) (Inputs, error)) authoring.Activator {
	return func(ctx context.Context, _ authoring.ActivationKind, candidate *authoring.Artifact) error {
		in, err := deps(ctx)
		if err != nil {
			return err
		}
		in.Organization = candidate
		_, err = Activate(ctx, in)
		return err
	}
}
