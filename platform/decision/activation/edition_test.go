// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// enterpriseArtifact returns a SIGNED organization document that spends a
// construct Community may not: a group-scoped policy (groupScopeFloor is
// Enterprise).
//
// It publishes through an API built with an ENTERPRISE profile, because that is
// the only honest way to obtain one. w.api carries the Community profile, and
// Publish refuses the construct there - correctly, that door works. The two
// real-world producers of such an artifact are the importer, whose profile
// comes from an operator FLAG (ee/platform/policy/cmd/axonflow-policy-import),
// and a direct INSERT into typed_policy_artifacts, which migrations/core/176
// grants the application role. Neither is reachable from this package, so the
// fixture stands in for both by doing what they do: producing a valid, signed
// artifact that a Community deployment then has to decide about.
//
// The realm carries no group graph, so publication also raises
// GROUP_SCOPE_WITHOUT_GRAPH. That one is SeverityWarn and does not block, which
// is what makes this fixture publishable at all.
func enterpriseArtifact(t *testing.T, w *world) *authoring.Artifact {
	t.Helper()
	doc, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Policies) == 0 {
		t.Fatal("the baseline permission pack carries no policy to scope; the fixture changed")
	}
	doc.Version = 1
	doc.Policies[0].Scope.Groups = []contract.ID{
		contract.MustParseID(contract.KindGroup, "Group::"+testRealm+":platform-admins"),
	}

	enterprise, err := authoring.ProfileFor(authoring.EditionEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(w.snap.Catalog, authoring.StaticTrust(w.trust), enterprise)
	if err != nil {
		t.Fatal(err)
	}
	meta := authoring.Metadata{
		DocumentID: authoringcatalog.BaselinePermissionPackID, Title: "baseline permissions",
		Author: contract.MustParseID(contract.KindPrincipal, testAuthor),
	}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: *doc}, w.snap.Catalog)
	if err != nil {
		t.Fatalf("NewDocument: %v\n%v", err, findings)
	}
	art, findings, err := api.Publish(context.Background(), d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: w.orgKeyID, PrivateKey: w.orgPriv,
		Approvers: []contract.ID{contract.MustParseID(contract.KindPrincipal, testApprover)},
		Fixtures:  fixturesFor(doc), Now: time.Date(2026, 9, 10, 12, 1, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("publishing the Enterprise fixture: %v\n%v", err, findings)
	}
	return art
}

// TestActivationRefusesAConstructTheEditionDoesNotCarry is ADR-066 chokepoint
// 2: the edition boundary applied where a document becomes, or stays, active.
//
// Publication already refuses the same construct, and Publish is the only
// function that produces an Artifact - so no document signed through this tree
// can miss it. That covers one door, and says nothing about a document that
// reached the store another way. This is the second door.
func TestActivationRefusesAConstructTheEditionDoesNotCarry(t *testing.T) {
	w := newWorld(t)
	art := enterpriseArtifact(t, w)

	community, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	in := w.inputs()
	in.Organization = art
	in.Profile = community
	in.RefuseConstructsOutsideEdition = true

	_, err = activation.Activate(context.Background(), in)
	if err == nil {
		t.Fatal("a Community deployment activated a group-scoped document; the construct boundary is not enforced " +
			"at activation, so an imported or directly-inserted document is enforced unchecked")
	}
	var refusal *activation.CapabilityRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("the refusal is not a *activation.CapabilityRefusal, so a transport cannot tell it from any other "+
			"activation failure without parsing a message: %T: %v", err, err)
	}
	if refusal.Code != activation.CodeCapabilityRequiresUpgrade {
		t.Errorf("code = %q, want %q", refusal.Code, activation.CodeCapabilityRequiresUpgrade)
	}
	if refusal.Edition != string(authoring.EditionCommunity) {
		t.Errorf("edition = %q, want %q - the refusal must name the edition that refused",
			refusal.Edition, authoring.EditionCommunity)
	}
	if !refusal.Findings.Has(authoring.CodeGroupScopeNotInEdition) {
		t.Errorf("the refusal carries %v, not the %s an author would have seen at publication; the two doors "+
			"must say the same sentence about the same construct",
			refusal.Findings.Codes(), authoring.CodeGroupScopeNotInEdition)
	}
}

// TestTheSameDocumentActivatesOnTheEditionThatCarriesTheConstruct is the
// positive control.
//
// Without it, a check that refused every document - a broken parse, a profile
// read as the zero value - would satisfy the assertion above, and the boundary
// would look enforced while actually refusing everything.
func TestTheSameDocumentActivatesOnTheEditionThatCarriesTheConstruct(t *testing.T) {
	w := newWorld(t)
	art := enterpriseArtifact(t, w)

	enterprise, err := authoring.ProfileFor(authoring.EditionEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	in := w.inputs()
	in.Organization = art
	in.Profile = enterprise
	in.RefuseConstructsOutsideEdition = true

	if _, err := activation.Activate(context.Background(), in); err != nil {
		t.Fatalf("an Enterprise deployment was refused its own group-scoped document: %v", err)
	}
}

// TestTheConstructCheckIsOffUnlessTheCallerAsksForIt pins the switch itself.
//
// The agent's enforcement seam leaves it off whenever the deployment's tier is
// unestablished or in a declared licence transition, because an activation
// error THERE is HTTP 503 on /api/v1/decide and a withheld MCP response rather
// than a sentence an author reads (#4094). If the check ran regardless of the
// field, that gate would be decorative and a lapsed licence would become an
// outage - the failure this shape exists to avoid.
func TestTheConstructCheckIsOffUnlessTheCallerAsksForIt(t *testing.T) {
	w := newWorld(t)
	art := enterpriseArtifact(t, w)

	community, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	in := w.inputs()
	in.Organization = art
	in.Profile = community
	in.RefuseConstructsOutsideEdition = false

	if _, err := activation.Activate(context.Background(), in); err != nil {
		t.Fatalf("the construct check ran with RefuseConstructsOutsideEdition unset, so the enforcement seam's "+
			"gate cannot suppress it: %v", err)
	}
}

// TestTheCheckRefusesAZeroProfileRatherThanReadingItAsAnEdition is the
// fail-closed half of the switch.
//
// A zero-value Profile is constructible by any caller. Read as an edition it
// would silently mean "Community constructs, duties on" for a deployment that
// never said so. The INPUT is refused instead, and not as a capability refusal:
// an operator told to upgrade would be chasing the wrong fault.
func TestTheCheckRefusesAZeroProfileRatherThanReadingItAsAnEdition(t *testing.T) {
	w := newWorld(t)
	in := w.inputs()
	in.Organization = enterpriseArtifact(t, w)
	in.RefuseConstructsOutsideEdition = true
	// in.Profile deliberately left zero.

	_, err := activation.Activate(context.Background(), in)
	if err == nil {
		t.Fatal("a zero-value Profile was accepted as an edition")
	}
	var refusal *activation.CapabilityRefusal
	if errors.As(err, &refusal) {
		t.Fatalf("a zero-value Profile was reported as a capability refusal, which tells an operator to upgrade "+
			"when the actual fault is a caller that supplied no profile: %v", err)
	}
}

// templateArtifact publishes the shipped organization template as an
// organization document through an API built for ed: the draft an organization
// is seeded with (PRD §1.4). ids, when non-nil, renames each policy - which is
// what makes the same policies the organization's OWN.
func templateArtifact(t *testing.T, w *world, ed authoring.Edition, rename func(i int, id string) string) (*authoring.Artifact, authoring.Findings, error) {
	t.Helper()
	doc, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	doc.Version = 1
	for i := range doc.Policies {
		if rename != nil {
			doc.Policies[i].ID = rename(i, doc.Policies[i].ID)
		}
	}
	profile, err := authoring.ProfileFor(ed)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(w.snap.Catalog, authoring.StaticTrust(w.trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	meta := authoring.Metadata{
		DocumentID: "organization.template-seeded", Title: "seeded from the organization template",
		Author: contract.MustParseID(contract.KindPrincipal, testAuthor),
	}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: *doc}, w.snap.Catalog)
	if err != nil {
		t.Fatalf("NewDocument: %v\n%v", err, findings)
	}
	// One fixture is enough for the gauntlet to have evidence: the destructive
	// block the K12 sentence names, matching on its detector.
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	const drop = "signal.detector.drop__table__prevention"
	target := doc.Policies[0].ID
	fixtures := []authoring.Fixture{{
		Name:       "a DROP TABLE the shipped detector flagged",
		Attributes: contract.AttributeSet{drop: contract.Known(true, contract.NamespaceOf(drop).DefaultProvenance(), 1, now)},
		Expect:     map[string]pdp.Verdict{target: pdp.VerdictMatch},
	}}
	opts := authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: w.orgKeyID, PrivateKey: w.orgPriv,
		Fixtures: fixtures, Now: now.Add(time.Minute),
	}
	if ed == authoring.EditionEnterprise {
		opts.Approvers = []contract.ID{contract.MustParseID(contract.KindPrincipal, testApprover)}
	}
	return api.Publish(context.Background(), d, opts)
}

// TestACommunityOrganizationPublishesAndActivatesTheTemplateItWasSeededWith is
// K12 end to end, through both doors: the publication a Community author makes
// and the activation a Community deployment performs with the construct check
// on. Before it, the 22 template policies were refused
// ATTRIBUTE_NAMESPACE_NOT_IN_EDITION at both, because every one reads signal.*.
func TestACommunityOrganizationPublishesAndActivatesTheTemplateItWasSeededWith(t *testing.T) {
	w := newWorld(t)
	art, findings, err := templateArtifact(t, w, authoring.EditionCommunity, nil)
	if err != nil {
		t.Fatalf("a Community author could not publish the template drafts are seeded with: %v\n%v", err, findings)
	}
	community, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	in := w.inputs()
	in.Organization = art
	in.Profile = community
	in.RefuseConstructsOutsideEdition = true
	if _, err := activation.Activate(context.Background(), in); err != nil {
		t.Fatalf("a Community deployment refused to activate the template it seeds drafts with: %v", err)
	}
}

// TestACommunityOrganizationsOwnSignalConstraintsAreRefusedAtBothDoors is the
// negative twin: the same 22 policies under the organization's own ids. The
// Community publication refuses them, and an artifact that reached the store
// another way (published here under Enterprise, standing in for the importer
// and a direct INSERT) is refused at Community activation with the same code.
func TestACommunityOrganizationsOwnSignalConstraintsAreRefusedAtBothDoors(t *testing.T) {
	w := newWorld(t)
	own := func(i int, _ string) string { return "org.own." + string(rune('a'+i)) }

	_, findings, err := templateArtifact(t, w, authoring.EditionCommunity, own)
	if err == nil {
		t.Fatal("a Community author published 22 signal readers of their own; the floor for an organization's own constraints is not enforced at publication")
	}
	if !findings.Has(authoring.CodeAttributeNamespaceNotInEdition) {
		t.Fatalf("publication refused, but not for the signal floor: %v", findings.Codes())
	}

	art, findings, err := templateArtifact(t, w, authoring.EditionEnterprise, own)
	if err != nil {
		t.Fatalf("publishing the Enterprise stand-in: %v\n%v", err, findings)
	}
	community, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	in := w.inputs()
	in.Organization = art
	in.Profile = community
	in.RefuseConstructsOutsideEdition = true
	_, err = activation.Activate(context.Background(), in)
	var refusal *activation.CapabilityRefusal
	if !errors.As(err, &refusal) || !refusal.Findings.Has(authoring.CodeAttributeNamespaceNotInEdition) {
		t.Fatalf("Community activation of the organization's own signal readers answered %v; want a CapabilityRefusal carrying %s",
			err, authoring.CodeAttributeNamespaceNotInEdition)
	}
}
