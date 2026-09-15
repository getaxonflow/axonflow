// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	"slices"
)

// The production activation path, driven end to end in process (#3895):
// deployment vocabulary -> baseline pack published through the REAL authoring
// API -> promoted through the REAL activator -> anchored engine -> a decision
// whose snapshot is the activation's -> a narrowed version -> a driven
// ROLLBACK -> the earlier decision again. Every negative has its positive
// control in the same test.

const (
	testRealm    = "axonflow-trusted-header"
	testAuthor   = "User::" + testRealm + ":installer"
	testApprover = "User::" + testRealm + ":reviewer"
	testCaller   = "User::" + testRealm + ":alice"
	testPlane    = "decide"
)

func realms() map[string]authoring.RealmEntry {
	return map[string]authoring.RealmEntry{
		testRealm:                 {Interactive: true, HasGroupGraph: false},
		"axonflow-api-credential": {Interactive: false, HasGroupGraph: false},
	}
}

func deployment() authoringcatalog.Deployment {
	return authoringcatalog.Deployment{
		Edition: registry.EditionCommunity, Realms: realms(),
		Now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
	}
}

func snapshot(t *testing.T) *authoringcatalog.Snapshot {
	t.Helper()
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, deployment())
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

type world struct {
	snap  *authoringcatalog.Snapshot
	trust *pdp.TrustStore
	api   *authoring.API
	// orgKeyID and orgPriv sign the organization's documents; sysPriv is the
	// system authority's key, minted separately as a transport must.
	orgKeyID string
	orgPriv  ed25519.PrivateKey
	sysPriv  ed25519.PrivateKey
	system   *authoring.SystemAuthority
	// composition signs the implicit baseline while no document is active, as
	// the agent's enforcer does with a key it mints beside the system key.
	composition *authoring.CompositionAuthority
}

const testOrgKeyID = "org-key"

func newWorld(t *testing.T) *world {
	t.Helper()
	snap := snapshot(t)
	trust := pdp.NewTrustStore()
	orgPub, orgPriv, _ := ed25519.GenerateKey(nil)
	trust.Authorize(pdp.RootOrganization, testOrgKeyID, orgPub)
	_, sysPriv, _ := ed25519.GenerateKey(nil)
	system, err := authoring.NewSystemAuthority(sysPriv)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{
		snap: snap, trust: trust,
		orgKeyID: testOrgKeyID, orgPriv: orgPriv, sysPriv: sysPriv, system: system,
		composition: compositionFrom(t, nil),
	}
	profile, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(snap.Catalog, authoring.StaticTrust(trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	// THE REAL ACTIVATOR: every promote and rollback below dry-runs the
	// anchored engine before the store flips.
	w.api = api.WithActivator(activation.Activator(func(context.Context) (activation.Inputs, error) { return w.inputs(), nil }))
	return w
}

func (w *world) inputs() activation.Inputs {
	// decide returns its decision over the Decision API, so it is built with
	// that wire's vocabulary exactly as the agent's seam and the transports'
	// dry runs build it (#4046).
	return activation.Inputs{
		Snapshot: w.snap, Trust: w.trust, System: w.system, Composition: w.composition,
		Plane: testPlane, Delivers: contract.DecisionWireCapabilities(),
	}
}

func (w *world) publish(t *testing.T, doc *pdp.Document, version int, supersedes string) *authoring.Artifact {
	t.Helper()
	return w.publishDocument(t, doc, version, supersedes, nil)
}

// publishDocument is publish with a system_controls section (PRD v11 §1.5). It is
// set on the envelope before Publish, which validates it again.
func (w *world) publishDocument(t *testing.T, doc *pdp.Document, version int, supersedes string, controls []authoring.SystemControlEntry) *authoring.Artifact {
	t.Helper()
	doc.Version = version
	meta := authoring.Metadata{
		DocumentID: authoringcatalog.BaselinePermissionPackID, Title: "baseline permissions",
		Author: contract.MustParseID(contract.KindPrincipal, testAuthor), Supersedes: supersedes,
	}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: *doc}, w.snap.Catalog)
	if err != nil {
		t.Fatalf("NewDocument: %v\n%v", err, findings)
	}
	d.SystemControls = controls
	art, findings, err := w.api.Publish(context.Background(), d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: w.orgKeyID, PrivateKey: w.orgPriv,
		Approvers: []contract.ID{contract.MustParseID(contract.KindPrincipal, testApprover)},
		Fixtures:  fixturesFor(doc), Now: time.Date(2026, 9, 10, 12, 1, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("publish v%d: %v\n%v", version, err, findings)
	}
	return art
}

// fixturesFor is the gauntlet a pack is published with: one request per
// permission the DOCUMENT carries, expecting it to MATCH its own action - so a
// narrowed pack is published with a narrowed gauntlet.
func fixturesFor(doc *pdp.Document) []authoring.Fixture {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	var out []authoring.Fixture
	for _, p := range doc.Policies {
		local := strings.TrimPrefix(p.ID, "baseline.permit.")
		out = append(out, authoring.Fixture{
			Name: "a " + local + " request",
			Attributes: contract.AttributeSet{
				"action.id":   contract.Known("Action::"+local, contract.ProvPlatform, 1, now),
				"action.tags": contract.Known([]any{"stage:" + strings.SplitN(local, ".", 2)[0]}, contract.ProvPlatform, 1, now),
				"args.query":  contract.Known("hello", contract.ProvCaller, 1, now),
			},
			Expect: map[string]pdp.Verdict{"baseline.permit." + local: pdp.VerdictMatch},
		})
	}
	return out
}

func (w *world) promote(t *testing.T, art *authoring.Artifact) {
	t.Helper()
	actor := contract.MustParseID(contract.KindPrincipal, testApprover)
	if _, err := w.api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), actor, time.Now().UTC(), "install"); err != nil {
		t.Fatalf("promote %s: %v", art.Digest(), err)
	}
}

func (w *world) activate(t *testing.T) *activation.Activation {
	t.Helper()
	return w.activateWith(t, nil)
}

// activateWith activates the organization's active document, or its implicit
// baseline while none is, beside the installed policy packs.
func (w *world) activateWith(t *testing.T, packs []activation.InstalledPack) *activation.Activation {
	t.Helper()
	in := w.inputs()
	in.Packs = packs
	if art, ok, err := w.api.Store().Active(context.Background(), pdp.RootOrganization); err != nil {
		t.Fatal(err)
	} else if ok {
		in.Organization = art
	}
	act, err := activation.Activate(context.Background(), in)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	return act
}

// cleanSignals supplies every attribute the shipped corpus and the organization
// template read, as a plane
// whose detectors all ran and none fired would: a KNOWN value at the type's
// zero, never absent. An absent signal is UNKNOWN(attribute_not_supplied) and
// the anchored engine answers ERROR for it - which is the fail-closed contract
// an enforcing plane's PIP has to meet, and the reason this helper exists in
// the test rather than a default in the engine.
func cleanSignals(t *testing.T) (shared, principal contract.AttributeSet) {
	t.Helper()
	now := time.Date(2026, 9, 10, 12, 5, 0, 0, time.UTC)
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	// The organization template's detectors too: while no document is active
	// the implicit bundle carries its controls, and a migrated database loads
	// their rows in the global scope, so they run like the shipped corpus's.
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	shared, principal = contract.AttributeSet{}, contract.AttributeSet{}
	for _, a := range append(slices.Clone(corpus.Attributes), template.Attributes...) {
		var v any
		switch a.Type {
		case pdp.TypeBoolean:
			v = false
		case pdp.TypeNumber:
			v = 0
		case pdp.TypeString:
			v = ""
		case pdp.TypeArray:
			v = []any{}
		default:
			continue
		}
		prov := contract.ProvDetector
		switch {
		case strings.HasPrefix(a.Path, "env."):
			prov = contract.ProvPlatform
		case strings.HasPrefix(a.Path, "args."):
			continue // the caller's, supplied by the request
		case strings.HasPrefix(a.Path, "principal."):
			principal[a.Path] = contract.Known(v, contract.ProvDirectory, 1, now)
			continue
		}
		shared[a.Path] = contract.Known(v, prov, 1, now)
	}
	return shared, principal
}

func request(t *testing.T, act *activation.Activation, local string) *contract.Request {
	t.Helper()
	now := time.Date(2026, 9, 10, 12, 5, 0, 0, time.UTC)
	principal := contract.MustParseID(contract.KindPrincipal, testCaller)
	shared, identity := cleanSignals(t)
	identity["principal.id"] = contract.Known(testCaller, contract.ProvAuthentication, 1, now)
	shared["action.id"] = contract.Known("Action::"+local, contract.ProvPlatform, 1, now)
	shared["action.tags"] = contract.Known([]any{"stage:" + strings.SplitN(local, ".", 2)[0]}, contract.ProvPlatform, 1, now)
	shared["args.query"] = contract.Known("hello", contract.ProvCaller, 1, now)
	return &contract.Request{
		RequestID:    "req-" + local,
		Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_1"),
		Principal:    principal,
		Action:       contract.MustParseID(contract.KindAction, "Action::"+local),
		Resource:     contract.MustParseID(contract.KindResource, "Request::self:req-"+local),
		Context:      contract.Context{ActorChain: []contract.Actor{{ID: principal, Attributes: identity}}},
		Snapshot:     act.RequestSnapshot(7, 0, 1),
		Attributes:   shared,
		EvaluatedAt:  now,
	}
}

func decide(t *testing.T, act *activation.Activation, local string) *contract.Decision {
	t.Helper()
	req := request(t, act, local)
	d, err := act.Engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide %s: %v", local, err)
	}
	// THE SNAPSHOT PROPAGATES: what the decision says it was decided against
	// is what the request carried, which is what the activation computed.
	if d.Snapshot != req.Snapshot {
		t.Fatalf("decision snapshot %+v differs from request snapshot %+v", d.Snapshot, req.Snapshot)
	}
	if d.Snapshot.PolicyBundle != act.PolicyBundle || d.Snapshot.RegistryVersion != act.Snapshot.RegistryVersion {
		t.Fatalf("decision snapshot %+v is not the activation's (bundle %s, registry %d)", d.Snapshot, act.PolicyBundle, act.Snapshot.RegistryVersion)
	}
	return d
}

func TestTheFirstAnchoredProductionEngine(t *testing.T) {
	w := newWorld(t)

	// PRD v11 §1.4: an organization that has published nothing runs the shipped
	// set. Before v11 this subtest asserted the opposite - the shipped corpus
	// alone, DENY on every action - and that state is now refused by name
	// (TestANilOrganizationWithNoCompositionAuthorityIsRefused).
	var implicit *activation.Activation
	t.Run("the shipped corpus plus the baseline pack is what a nil organization activates", func(t *testing.T) {
		implicit = w.activate(t)
		if implicit.OrganizationArtifactDigest != "" {
			t.Fatalf("no organization document is active, yet the activation names artifact %s", implicit.OrganizationArtifactDigest)
		}
		if !implicit.ImplicitBaseline || implicit.OrganizationBundleDigest == "" {
			t.Fatalf("no organization document is active and the organization root is not the implicit baseline: implicit=%v bundle=%q",
				implicit.ImplicitBaseline, implicit.OrganizationBundleDigest)
		}
		if implicit.PEP == nil || implicit.PEP.ID != registry.LegacyPlanePEPPrefix+testPlane {
			t.Fatalf("the engine advertises %+v, want the %s plane's profile", implicit.PEP, testPlane)
		}
		for _, local := range authoringcatalog.DeploymentActions() {
			if d := decide(t, implicit, local); d.State != contract.StateAllow {
				t.Fatalf("%s: state %s reason %s with no document active; want ALLOW under the implicit baseline, because denying for want of a document is not a state this product has",
					local, d.State, d.Reason)
			}
		}
	})

	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	v1 := w.publish(t, pack, 1, "")
	w.promote(t, v1)
	var first *activation.Activation

	t.Run("the baseline pack permits every stage, through the real publish and promote", func(t *testing.T) {
		first = w.activate(t)
		if first.OrganizationArtifactDigest != v1.Digest() {
			t.Fatalf("the activation names %s, the store activated %s", first.OrganizationArtifactDigest, v1.Digest())
		}
		// A PUBLISHED DOCUMENT REPLACES THE IMPLICIT BASELINE BY DIGEST, even
		// when its content is the same pack: the root is the organization's own
		// signed artifact now, so every decision names a different bundle.
		if first.ImplicitBaseline || first.PolicyBundle == implicit.PolicyBundle {
			t.Fatalf("the published pack activated and the implicit baseline did not give way: implicit=%v bundle %s (implicit was %s)",
				first.ImplicitBaseline, first.PolicyBundle, implicit.PolicyBundle)
		}
		// THE ANCHOR IS ASSERTED BY WHAT IT REFUSES, NOT BY TWO STRINGS BEING
		// NON-EMPTY. An earlier version of this compared nothing: it checked
		// that CorpusDigest and SystemBundleDigest were both non-empty - two
		// unrelated values, which are non-empty for any successful activation
		// whether it is anchored or not, and which (see below) are not even
		// supposed to be equal. It survived deleting the anchor. The real
		// assertions live in TestTheAnchorRefusesARestrictionThatIsNotOne.
		//
		// What IS worth asserting here is the relationship that holds: the
		// activation names the restriction it activated, and it activated fewer
		// controls than the corpus ships.
		if first.Restriction == "" {
			t.Fatal("the activation carries no restriction reason, so nothing records which controls this plane enforces")
		}
		if first.SystemPolicies <= 0 || first.SystemPolicies >= first.ShippedPolicies {
			t.Fatalf("the activation binds %d of %d shipped controls; a plane binding all or none is not a restriction",
				first.SystemPolicies, first.ShippedPolicies)
		}
		for _, local := range authoringcatalog.DeploymentActions() {
			if d := decide(t, first, local); d.State != contract.StateAllow {
				t.Fatalf("%s: state %s reason %s, want ALLOW under the baseline pack", local, d.State, d.Reason)
			}
		}
	})

	// v2 omits tool.call's permission. The deployment's baseline pack composes
	// beside every organization document (PRD v11 §1.4), so omitting a
	// permission narrows nothing: an organization narrows the pack with a
	// constraint (TestTheBaselinePackComposesBesideAPublishedDocument).
	narrowed, _ := authoringcatalog.BaselinePermissionPack(w.snap)
	var kept []pdp.Policy
	for _, p := range narrowed.Policies {
		if p.ID != "baseline.permit."+authoringcatalog.ActionToolCall {
			kept = append(kept, p)
		}
	}
	narrowed.Policies = kept
	v2 := w.publish(t, narrowed, 2, v1.Digest())
	w.promote(t, v2)
	var second *activation.Activation

	t.Run("a promoted document that omits a permission moves the policy bundle, and the pack still permits the action", func(t *testing.T) {
		second = w.activate(t)
		if second.PolicyBundle == first.PolicyBundle {
			t.Fatal("v2 activated but the policy bundle did not move; a rollback would be unobservable")
		}
		if d := decide(t, second, authoringcatalog.ActionToolCall); d.State != contract.StateAllow {
			t.Fatalf("tool.call under v2: %s, want ALLOW - the deployment's pack permits what a document omits, and only a constraint narrows it", d.State)
		}
		if d := decide(t, second, authoringcatalog.ActionLLMCompletion); d.State != contract.StateAllow {
			t.Fatalf("llm.completion under v2: %s, want ALLOW (the control: v2 still grants it)", d.State)
		}
	})

	t.Run("a DRIVEN rollback restores v1's decisions and v1's bundle", func(t *testing.T) {
		actor := contract.MustParseID(contract.KindPrincipal, testApprover)
		if _, err := w.api.Rollback(context.Background(), pdp.RootOrganization, v1.Digest(), actor, time.Now().UTC(), "v2 over-narrowed"); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		third := w.activate(t)
		if third.OrganizationArtifactDigest != v1.Digest() {
			t.Fatalf("after rollback the activation names %s, want %s", third.OrganizationArtifactDigest, v1.Digest())
		}
		if third.PolicyBundle != first.PolicyBundle {
			t.Fatalf("after rollback the policy bundle is %s, v1's was %s", third.PolicyBundle, first.PolicyBundle)
		}
		if d := decide(t, third, authoringcatalog.ActionToolCall); d.State != contract.StateAllow {
			t.Fatalf("tool.call after rollback: %s, want ALLOW", d.State)
		}
		history, _ := w.api.Store().History(context.Background(), pdp.RootOrganization)
		if len(history) != 3 || history[2].Kind != authoring.ActivationRollback {
			t.Fatalf("the activation history is %+v; want promote, promote, rollback", history)
		}
	})
}

func TestActivationRefusesByName(t *testing.T) {
	w := newWorld(t)

	t.Run("a fixture vocabulary", func(t *testing.T) {
		fixture, err := authoringcatalog.Resolve(authoringcatalog.SourceConformance, authoringcatalog.Deployment{})
		if err != nil {
			t.Fatal(err)
		}
		in := w.inputs()
		in.Snapshot = fixture
		_, err = activation.Activate(context.Background(), in)
		var refusal *authoring.ErrCatalogIsFixture
		if !errors.As(err, &refusal) || refusal.Code() != authoring.CodeCatalogIsFixture {
			t.Fatalf("a fixture vocabulary was activated (err=%v)", err)
		}
	})

	t.Run("a plane the deployment does not register", func(t *testing.T) {
		in := w.inputs()
		in.Plane = "cowork_ingest" // enterprise-only in the plane table; this is a community snapshot
		if _, err := activation.Activate(context.Background(), in); err == nil || !strings.Contains(err.Error(), "cowork_ingest") {
			t.Fatalf("an unregistered plane was activated (err=%v)", err)
		}
	})

	// A blanket permission that reaches the engine without passing through
	// authoring is refused by the ANCHORED ENGINE itself, by name:
	// pdp.TestAnAnchoredEngineRefusesABlanketPermissionByName drives it with a
	// hand-built, hand-signed bundle, which is the only way such a document
	// can exist - Publish refuses the shape before it compiles anything.

	t.Run("the control: the unmutated inputs activate", func(t *testing.T) {
		if _, err := activation.Activate(context.Background(), w.inputs()); err != nil {
			t.Fatalf("the control activation failed, so the refusals above prove nothing: %v", err)
		}
	})
}
