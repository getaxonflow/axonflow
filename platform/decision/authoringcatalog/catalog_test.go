// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringcatalog_test

import (
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// testRealms stands in for the identity plane's realm attributes, which live in
// the platform module and cannot be imported here. The REAL set is what
// platform/shared/authoringedition hands in; its tests pin that set. These
// three are enough to drive every rule in this package: one interactive realm
// with a graph, one without a graph, one non-interactive.
func testRealms() map[string]authoring.RealmEntry {
	return map[string]authoring.RealmEntry{
		"axonflow-minted":         {Interactive: true, HasGroupGraph: true},
		"axonflow-trusted-header": {Interactive: true, HasGroupGraph: false},
		"axonflow-api-credential": {Interactive: false, HasGroupGraph: false},
	}
}

func testDeployment() authoringcatalog.Deployment {
	return authoringcatalog.Deployment{
		Edition: registry.EditionCommunity,
		Realms:  testRealms(),
		Now:     time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
	}
}

func TestTheResolverHasThreeOutcomesAndNoFourth(t *testing.T) {
	t.Run("unset and empty are the deployment vocabulary (PRD §1.5)", func(t *testing.T) {
		for _, raw := range []string{"", "   "} {
			snap, err := authoringcatalog.Resolve(raw, testDeployment())
			if err != nil || snap == nil {
				t.Fatalf("Resolve(%q) = (%v, %v); unset must be the deployment vocabulary, not no vocabulary", raw, snap, err)
			}
			if snap.Source != authoringcatalog.SourceDeployment || snap.Fixture {
				t.Fatalf("Resolve(%q) resolved %q (fixture=%t), want the deployment vocabulary", raw, snap.Source, snap.Fixture)
			}
		}
	})
	t.Run("an unrecognised value is refused and names the recognised ones", func(t *testing.T) {
		_, err := authoringcatalog.Resolve("registry", testDeployment())
		if err == nil {
			t.Fatal("a value nobody chose must not select a vocabulary")
		}
		for _, s := range authoringcatalog.Sources() {
			if !strings.Contains(err.Error(), s) {
				t.Fatalf("the refusal does not name %q: %v", s, err)
			}
		}
	})
	t.Run("conformance is a FIXTURE and says so on the catalog", func(t *testing.T) {
		snap, err := authoringcatalog.Resolve("  CONFORMANCE ", authoringcatalog.Deployment{})
		if err != nil {
			t.Fatal(err)
		}
		if !snap.Fixture || snap.Source != authoringcatalog.SourceConformance {
			t.Fatalf("conformance must resolve as a fixture: %+v", snap)
		}
		if !snap.Catalog.Provenance.Fixture || snap.Catalog.Provenance.Source != authoringcatalog.SourceConformance {
			t.Fatalf("the catalog must carry its provenance so the activation path can refuse it: %+v", snap.Catalog.Provenance)
		}
		if snap.CorpusDigest != "" {
			t.Fatalf("a fixture is anchored to nothing; got corpus digest %q", snap.CorpusDigest)
		}
		if snap.Digest == "" || snap.Catalog.Provenance.Digest != snap.Digest {
			t.Fatalf("the snapshot and its catalog disagree about the digest: %q vs %q", snap.Digest, snap.Catalog.Provenance.Digest)
		}
	})
}

func TestTheDeploymentVocabularyIsDerivedNotListed(t *testing.T) {
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, testDeployment())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Fixture || snap.Catalog.Provenance.Fixture {
		t.Fatal("the deployment vocabulary is not a fixture")
	}
	if err := snap.Catalog.Validate(); err != nil {
		t.Fatalf("the deployment catalog is not usable as a validation authority: %v", err)
	}

	t.Run("the actions are exactly the three stages", func(t *testing.T) {
		var got []string
		for k := range snap.Catalog.Actions {
			got = append(got, strings.TrimPrefix(k, "Action::"))
		}
		sort.Strings(got)
		want := authoringcatalog.DeploymentActions()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("actions = %v, want %v", got, want)
		}
	})

	t.Run("every args path the shipped corpus reads is a declared argument, at the corpus's type", func(t *testing.T) {
		corpus, err := pdp.SystemCorpusDocument()
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, a := range corpus.Attributes {
			if !strings.HasPrefix(a.Path, "args.") {
				continue
			}
			seen++
			name := strings.TrimPrefix(a.Path, "args.")
			for key, entry := range snap.Catalog.Actions {
				got, ok := entry.Arguments[name]
				if !ok {
					t.Fatalf("%s does not declare %q, which the shipped corpus reads; admission would refuse the requests the corpus inspects", key, name)
				}
				if got != a.Type {
					t.Fatalf("%s declares %q as %s, the corpus reads it as %s", key, name, got, a.Type)
				}
			}
		}
		if seen == 0 {
			t.Fatal("the shipped corpus reads no args.* path, so this assertion checked nothing; the corpus has changed shape")
		}
		for key, entry := range snap.Catalog.Actions {
			if entry.Arguments[authoringcatalog.ArgumentQuery] != pdp.TypeString {
				t.Fatalf("%s does not declare the query argument the evaluator requires", key)
			}
			if len(entry.RequiredArguments) != 1 || entry.RequiredArguments[0] != authoringcatalog.ArgumentQuery {
				t.Fatalf("%s requires %v, want exactly [%s]", key, entry.RequiredArguments, authoringcatalog.ArgumentQuery)
			}
		}
	})

	t.Run("the payload leaves are the corpus's redaction targets and the fields it retains", func(t *testing.T) {
		corpus, _ := pdp.SystemCorpusDocument()
		tmpl, _ := pdp.SystemCorpusOrganizationTemplate()
		want := map[string]bool{}
		for _, d := range []*pdp.Document{corpus, tmpl} {
			for _, p := range d.Policies {
				for _, o := range p.Obligations {
					if o.Type == contract.ObFieldRedact && o.Target != "" {
						want[o.Target] = true
					}
				}
			}
		}
		if len(want) == 0 {
			t.Fatal("the corpus carries no redaction target; this assertion would check nothing")
		}
		// #4254: a redaction the corpus ships as a warn keeps its fields as
		// leaves, so no organization's authoring surface narrows with it.
		retained, err := pdp.SystemCorpusRetainedPayloadLeaves()
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range retained {
			want[field] = true
		}
		for key, entry := range snap.Catalog.Actions {
			got := map[string]bool{}
			for _, l := range entry.PayloadLeaves {
				got[l] = true
			}
			for w := range want {
				if !got[w] {
					t.Fatalf("%s does not declare leaf %q; a mandatory redaction targeting it would be reported unplaced and NOT applied", key, w)
				}
			}
			if len(got) != len(want) {
				t.Fatalf("%s declares %d leaves, the corpus names %d", key, len(got), len(want))
			}
		}
	})

	t.Run("the realms are the caller's plus the two this module declares, and nothing else", func(t *testing.T) {
		want := testRealms()
		for q, e := range authoringcatalog.PlatformRealmAttributes() {
			want[q] = e
		}
		if len(snap.Catalog.Realms) != len(want) {
			t.Fatalf("realms = %v, want %v", snap.Catalog.Realms, want)
		}
		for q, e := range want {
			if snap.Catalog.Realms[q] != e {
				t.Fatalf("realm %q = %+v, want %+v", q, snap.Catalog.Realms[q], e)
			}
		}
		if !snap.Registry.RealmDeclared(registry.LegacyPlaneRealm) || !snap.Registry.RealmDeclared(registry.ExternalPEPRealm) {
			t.Fatal("the registry does not declare the platform realms")
		}
	})

	t.Run("the enforcement planes are registered for the edition, and PEPFor reads them", func(t *testing.T) {
		rows, err := registry.LegacyPlanePEPs(registry.EditionCommunity)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("no community plane is declared; this assertion would check nothing")
		}
		for _, r := range rows {
			plane := strings.TrimPrefix(r.ID, registry.LegacyPlanePEPPrefix)
			pep, ok := snap.PEPFor(plane)
			if !ok {
				t.Fatalf("PEPFor(%q) = false; the plane is declared for this edition", plane)
			}
			if pep.ID != r.ID || len(pep.Capabilities) != len(r.Capabilities) {
				t.Fatalf("PEPFor(%q) = %+v, want %+v", plane, pep, r)
			}
		}
		if _, ok := snap.PEPFor("no-such-plane"); ok {
			t.Fatal("an undeclared plane must not resolve to a profile")
		}
	})

	t.Run("the shipped detectors are in the registry", func(t *testing.T) {
		want, err := registry.ShippedDetectors()
		if err != nil {
			t.Fatal(err)
		}
		if got := snap.Registry.Detectors(); len(got) != len(want) {
			t.Fatalf("%d detectors registered, the census has %d", len(got), len(want))
		}
	})

	t.Run("it is anchored to the corpus this binary shipped", func(t *testing.T) {
		want, err := pdp.SystemCorpusDigest()
		if err != nil {
			t.Fatal(err)
		}
		if snap.CorpusDigest != want {
			t.Fatalf("corpus digest %q, the binary's is %q", snap.CorpusDigest, want)
		}
		if snap.RegistryVersion != authoringcatalog.DeploymentCatalogVersion || snap.Catalog.Provenance.RegistryVersion != snap.RegistryVersion {
			t.Fatalf("registry version %d / %d, want %d", snap.RegistryVersion, snap.Catalog.Provenance.RegistryVersion, authoringcatalog.DeploymentCatalogVersion)
		}
	})

	t.Run("the digest is over content, not over the label", func(t *testing.T) {
		again, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, testDeployment())
		if err != nil {
			t.Fatal(err)
		}
		if again.Digest != snap.Digest {
			t.Fatal("two resolutions of the same deployment differ; the digest is not deterministic")
		}
		other := testDeployment()
		other.Realms["axonflow-oidc"] = authoring.RealmEntry{Interactive: true, HasGroupGraph: true}
		moved, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, other)
		if err != nil {
			t.Fatal(err)
		}
		if moved.Digest == snap.Digest {
			t.Fatal("adding a realm did not move the digest; the digest is not over the content")
		}
	})
}

func TestTheDeploymentVocabularyRefusesAnUnderdescribedDeployment(t *testing.T) {
	cases := map[string]func(*authoringcatalog.Deployment){
		"no realms":    func(d *authoringcatalog.Deployment) { d.Realms = nil },
		"no edition":   func(d *authoringcatalog.Deployment) { d.Edition = 0 },
		"zero instant": func(d *authoringcatalog.Deployment) { d.Now = time.Time{} },
		"platform realm": func(d *authoringcatalog.Deployment) {
			d.Realms[registry.LegacyPlaneRealm] = authoring.RealmEntry{Interactive: true}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dep := testDeployment()
			mutate(&dep)
			if _, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, dep); err == nil {
				t.Fatalf("%s: a deployment vocabulary was built from an underdescribed deployment", name)
			}
		})
	}
	// POSITIVE CONTROL for the four negatives above: the unmutated deployment
	// resolves, so the refusals are about the mutation and not about the base.
	if _, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, testDeployment()); err != nil {
		t.Fatalf("the control deployment does not resolve: %v", err)
	}
}

func TestTheBaselinePackIsExplicitAndValidatesAgainstItsOwnCatalog(t *testing.T) {
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, testDeployment())
	if err != nil {
		t.Fatal(err)
	}
	pack, err := authoringcatalog.BaselinePermissionPack(snap)
	if err != nil {
		t.Fatal(err)
	}
	if pack.Root != pdp.RootOrganization {
		t.Fatalf("the pack publishes under %q; a customer document is organization-root", pack.Root)
	}
	if len(pack.Policies) != len(snap.Catalog.Actions) {
		t.Fatalf("%d permissions for %d actions; the pack is one per action", len(pack.Policies), len(snap.Catalog.Actions))
	}
	for _, p := range pack.Policies {
		if p.Authority != contract.AuthorityPermission {
			t.Fatalf("%s is a %s", p.ID, p.Authority)
		}
		if p.Actions.Any || len(p.Actions.Actions) != 1 {
			t.Fatalf("%s selects %+v; a baseline names exactly one action", p.ID, p.Actions)
		}
		if pdp.IsBlanketPermission(p) {
			t.Fatalf("%s is a blanket permission; the pack exists to replace that shape", p.ID)
		}
	}
	// Through the REAL constructor, against the same snapshot's catalog: what
	// the pack claims to be publishable must be publishable.
	author := contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:installer")
	meta := authoring.Metadata{DocumentID: authoringcatalog.BaselinePermissionPackID, Title: "baseline permissions", Author: author}
	if _, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: *pack}, snap.Catalog); err != nil {
		t.Fatalf("the baseline pack does not validate against the deployment catalog: %v\n%v", err, findings)
	}

	// NEGATIVE + CONTROL: a blanket permission in the same document IS refused
	// by the same constructor, by name, so the pack's acceptance is not the
	// validator accepting everything.
	blanket := *pack
	blanket.Policies = append(append([]pdp.Policy(nil), pack.Policies...), pdp.Policy{
		ID: "blanket", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
		Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true}, Where: pdp.True(),
	})
	_, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: blanket}, snap.Catalog)
	if err == nil || !findings.Has(authoring.CodeBlanketPermission) {
		t.Fatalf("a blanket permission validated against the deployment catalog: err=%v findings=%v", err, findings.Codes())
	}

	// A fixture cannot seed a pack: the pack is the deployment's own baseline.
	fixture, _ := authoringcatalog.Resolve(authoringcatalog.SourceConformance, authoringcatalog.Deployment{})
	if _, err := authoringcatalog.BaselinePermissionPack(fixture); err == nil {
		t.Fatal("a baseline pack was derived from the conformance fixture")
	}
}

// TestActionLabelsNeverMoveTheCatalogDigest (#3789): a name is not part of
// "which policies does this catalog admit", so relabelling every action leaves
// CatalogDigest - and with it DeploymentCatalogVersion's weld - where it was.
// The deployment's three actions carry their display names and descriptions.
func TestActionLabelsNeverMoveTheCatalogDigest(t *testing.T) {
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, testDeployment())
	if err != nil {
		t.Fatal(err)
	}
	cat := snap.Catalog
	want := map[string]string{
		"Action::" + authoringcatalog.ActionLLMCompletion: "Model completion",
		"Action::" + authoringcatalog.ActionToolCall:      "Tool call",
		"Action::" + authoringcatalog.ActionAgentInvoke:   "Agent invocation",
	}
	if len(cat.ActionLabels) != len(want) {
		t.Fatalf("the deployment catalog labels %d actions, want %d: %+v", len(cat.ActionLabels), len(want), cat.ActionLabels)
	}
	for id, name := range want {
		got := cat.ActionLabels[id]
		if got.DisplayName != name || got.Description == "" {
			t.Errorf("%s is labelled %+v, want display name %q and a description", id, got, name)
		}
	}

	before, err := authoringcatalog.CatalogDigest(cat)
	if err != nil {
		t.Fatal(err)
	}
	relabelled := *cat
	relabelled.ActionLabels = map[string]authoring.ActionLabel{}
	for id := range cat.ActionLabels {
		relabelled.ActionLabels[id] = authoring.ActionLabel{DisplayName: "renamed " + id, Description: "rewritten"}
	}
	after, err := authoringcatalog.CatalogDigest(&relabelled)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("relabelling the actions moved the catalog digest %s -> %s; a name must not change which policies the catalog admits", before, after)
	}
	// THE CONTROL: the digest does see a change to what the catalog admits.
	grown := *cat
	grown.Actions = map[string]pdp.ActionEntry{}
	for id, a := range cat.Actions {
		grown.Actions[id] = a
	}
	for id, a := range grown.Actions {
		a.MaxDelegationDepth++
		grown.Actions[id] = a
		break
	}
	if moved, err := authoringcatalog.CatalogDigest(&grown); err != nil || moved == before {
		t.Fatalf("changing an action's delegation depth left the digest at %s (err %v), so the comparison above proves nothing", moved, err)
	}
}
