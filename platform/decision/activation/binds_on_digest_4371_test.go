// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/conformance"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/policypack"
	"axonflow/platform/decision/registry"
)

// THE DIGEST-EQUALITY PROOF FOR #4371: ABSENT binds_on MOVES NOTHING.
//
// #4371 adds binds_on to every typed control, and its one promise to every
// document published before it is that absent means exactly what it meant:
// every scope. The proof is the activation digests, per (edition, document,
// scope), over the enforcing scopes: the system bundle, the organization
// bundle and PolicyBundle, the digest a decision carries and the step gate
// binds. The expected values are NOT computed here. They were computed on the
// BASE tree (fcdb39625, before #4371) by this same file with
// H2_WRITE_BASE_DIGESTS=1 and committed as testdata, because a before and after
// computed in one tree compares the change with itself. The eight cowork_ingest
// rows were added when #4259 made that pass an enforcing scope: computed the
// same way on 770cf2ce6, the tree before #4259, whose other 103 rows were the
// committed ones byte for byte.
//
// THE EIGHT enterprise+packs ROWS ON decide AND mcp:request WERE RE-KEYED FOR
// #3330, which ships FinCrime pack v2 (one more control, the Engine B score
// step-up) - and the +packs world reads the LIVE ee/policy-packs, so a pack
// edit moves the rows of exactly the scopes that pack binds on. Before the
// re-key this tree was measured against the packs the base rows were computed
// with (ee/policy-packs at a4cf136d52, read from outside the repository):
// 111 of 111 rows and 78 of 78 re-activations identical, so the change moved
// no digest but the pack's own. Only those eight .tsv rows were rewritten; the
// committed base artifacts are the base's bytes and were not.
//
// This file must therefore compile on the base: it names no symbol #4371 adds.
// The scopes are written out; TestTheDigestScopesAreTheEnforcingScopes
// (binds_on_4371_test.go) holds them to legacycompile.EnforcingScopes.
//
// Every key is derived from a fixed seed and every publication from a fixed
// instant, so the digests are a function of the documents and the code alone.

const baseDigestsFile = "testdata/binds_on_4371_base_digests.tsv"

// digestScope is one enforcing scope, as plane and phase.
type digestScope struct {
	plane legacycompile.Plane
	phase legacycompile.Phase
}

// digestScopes are the ten enforcing scopes, as plane and phase. The cowork
// ingest storage pass (#4259) is the Enterprise build's alone, so a Community
// world activates the other nine (digestWorld.scopes).
var digestScopes = []digestScope{
	{legacycompile.PlaneCoworkIngest, legacycompile.PhaseResponse},
	{legacycompile.PlaneDecide, ""},
	{legacycompile.PlaneGatewayRequest, ""},
	{legacycompile.PlaneMAP, ""},
	{legacycompile.PlaneMCP, legacycompile.PhaseRequest},
	{legacycompile.PlaneMCP, legacycompile.PhaseResponse},
	{legacycompile.PlaneOpenAICompatible, ""},
	{legacycompile.PlaneOrchestratorResponse, ""},
	{legacycompile.PlaneProxyRequest, ""},
	{legacycompile.PlaneWCP, ""},
}

// derivedScope is a scope with no base-computed row, and the base scope whose
// rows it must equal.
//
// orchestrator_request is the orchestrator's two request routes, which decided
// under wcp's scope when the base was computed (#4249 row 5706695827). It reads
// the same substrate and the corpus binds it what wcp binds, so for a document
// that names no scopes every activation digest on it must equal wcp's - which
// is ruling 2's equality, asserted here at digest level rather than described.
var derivedScope = struct {
	plane legacycompile.Plane
	phase legacycompile.Phase
	from  legacycompile.EnforcementScope
}{legacycompile.PlaneOrchestratorRequest, "", legacycompile.MustScopeFor(legacycompile.PlaneWCP, "")}

func seededKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

var digestNow = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// digestWorld is a deterministic authoring world for one edition.
type digestWorld struct {
	edition registry.Edition
	snap    *authoringcatalog.Snapshot
	trust   *pdp.TrustStore
	api     *authoring.API
	system  *authoring.SystemAuthority
	comp    *authoring.CompositionAuthority
	orgPriv ed25519.PrivateKey
	// packs are the policy packs the world installs, nil for none.
	packs []activation.InstalledPack
}

func newDigestWorld(t *testing.T, edition registry.Edition) *digestWorld {
	t.Helper()
	dep := deployment()
	dep.Edition = edition
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, dep)
	if err != nil {
		t.Fatal(err)
	}
	orgPriv := seededKey(1)
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, testOrgKeyID, orgPriv.Public().(ed25519.PublicKey))
	system, err := authoring.NewSystemAuthority(seededKey(2))
	if err != nil {
		t.Fatal(err)
	}
	comp, err := authoring.NewCompositionAuthority(seededKey(3))
	if err != nil {
		t.Fatal(err)
	}
	authEdition := authoring.EditionCommunity
	if edition == registry.EditionEnterprise {
		authEdition = authoring.EditionEnterprise
	}
	profile, err := authoring.ProfileFor(authEdition)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(snap.Catalog, authoring.StaticTrust(trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	return &digestWorld{edition: edition, snap: snap, trust: trust, api: api, system: system, comp: comp, orgPriv: orgPriv}
}

// scopes are the digest scopes whose plane this world's edition registers: the
// cowork ingest storage pass is Enterprise-only (registry/legacy_plane_peps.tsv).
func (w *digestWorld) scopes() []digestScope {
	var out []digestScope
	for _, s := range digestScopes {
		if s.plane == legacycompile.PlaneCoworkIngest && w.edition != registry.EditionEnterprise {
			continue
		}
		out = append(out, s)
	}
	return out
}

// unpinned is the world publishing through a catalog that states NO version, so
// its artifacts are byte-identical to the base tree's: the catalog version the
// provenance pins (#4249 row 5706695827) is the one thing this tree adds to an
// artifact, and the pin is omitempty, so a catalog with no version writes the
// bytes the base wrote. A catalog's provenance is excluded from its content
// digest, so this changes nothing the validator reads.
func (w *digestWorld) unpinned(t *testing.T) *digestWorld {
	t.Helper()
	cat := *w.snap.Catalog
	cat.Provenance.RegistryVersion = 0
	snap := *w.snap
	snap.Catalog = &cat
	profile, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	if w.edition == registry.EditionEnterprise {
		if profile, err = authoring.ProfileFor(authoring.EditionEnterprise); err != nil {
			t.Fatal(err)
		}
	}
	api, err := authoring.NewAPI(snap.Catalog, authoring.StaticTrust(w.trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	out := *w
	out.snap = &snap
	out.api = api
	return &out
}

// publish publishes doc with fixtures, at the fixed instant.
func (w *digestWorld) publish(t *testing.T, id string, doc pdp.Document, fixtures []authoring.Fixture) *authoring.Artifact {
	t.Helper()
	art, findings, err := w.tryPublish(id, doc, fixtures)
	if err != nil {
		t.Fatalf("%s: publish: %v\n%v", id, err, findings)
	}
	return art
}

// tryPublish is publish that returns the refusal rather than failing.
func (w *digestWorld) tryPublish(id string, doc pdp.Document, fixtures []authoring.Fixture) (*authoring.Artifact, authoring.Findings, error) {
	meta := authoring.Metadata{
		DocumentID: id, Title: id,
		Author: contract.MustParseID(contract.KindPrincipal, testAuthor),
	}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: doc}, w.snap.Catalog)
	if err != nil {
		return nil, findings, err
	}
	art, pubFindings, err := w.api.Publish(context.Background(), d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: testOrgKeyID, PrivateKey: w.orgPriv,
		Approvers: []contract.ID{contract.MustParseID(contract.KindPrincipal, testApprover)},
		Fixtures:  fixtures, Now: digestNow,
	})
	return art, append(findings, pubFindings...), err
}

// activateOn activates org (nil = the implicit baseline) on one scope, beside
// the world's installed packs, if any.
func (w *digestWorld) activateOn(t *testing.T, org *authoring.Artifact, plane legacycompile.Plane, phase legacycompile.Phase) *activation.Activation {
	t.Helper()
	scope := legacycompile.MustScopeFor(plane, phase)
	act, err := activation.Activate(context.Background(), activation.Inputs{
		Snapshot: w.snap, Trust: w.trust, System: w.system, Composition: w.comp,
		Plane: string(plane), Phase: phase, Delivers: legacycompile.ScopeDeliveries(scope),
		Organization: org, Packs: w.packs,
	})
	if err != nil {
		t.Fatalf("activate on %s: %v", scope, err)
	}
	return act
}

// baselineDocument is the deployment's baseline permission pack as a
// published document: the first document a fresh install publishes.
func baselineDocument(t *testing.T, snap *authoringcatalog.Snapshot) pdp.Document {
	t.Helper()
	pack, err := authoringcatalog.BaselinePermissionPack(snap)
	if err != nil {
		t.Fatal(err)
	}
	doc := *pack
	doc.Policies = append([]pdp.Policy(nil), pack.Policies...)
	doc.Attributes = append([]pdp.AttributeSchema{}, pack.Attributes...)
	doc.Version = 1
	return doc
}

// withApprovalOnToolCall is the acme-approval document (#4249 row 5763392959): the
// baseline and an organization-wide approval requirement on tool.call, with
// no binds_on - the shape every such document published before #4371 has.
func withApprovalOnToolCall(t *testing.T, snap *authoringcatalog.Snapshot) pdp.Document {
	t.Helper()
	doc := baselineDocument(t, snap)
	doc.Policies = append(doc.Policies, pdp.Policy{
		ID: "approve.tool_calls", Authority: contract.AuthorityRequirement, Root: pdp.RootOrganization,
		Scope:   pdp.Scope{Organization: true},
		Actions: pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)}},
		Where:   pdp.True(),
		Obligations: []contract.Obligation{{
			Type: contract.ObApprovalChallenge, Mandatory: true, SourcePolicy: "approve.tool_calls", SchemaVersion: 1,
			Params: map[string]string{"quorum": "1", "eligible": "Group::" + testRealm + ":approvers"},
		}},
		Mandatory: true,
	})
	return doc
}

func approvalFixtures(doc *pdp.Document) []authoring.Fixture {
	out := fixturesFor(&pdp.Document{Policies: doc.Policies[:len(doc.Policies)-1]})
	out[len(out)-1].Expect["approve.tool_calls"] = pdp.VerdictMatch
	for i := range out[:len(out)-1] {
		out[i].Expect["approve.tool_calls"] = pdp.VerdictNoMatch
	}
	return out
}

// templateDocument is the organization template as the portal seeds a draft
// from it (authoring.ShippedOrganizationTemplateView), with the one fixture
// the template-seeded publication in edition_test.go uses.
func templateDocument(t *testing.T) (pdp.Document, []authoring.Fixture) {
	t.Helper()
	view, err := authoring.ShippedOrganizationTemplateView()
	if err != nil {
		t.Fatal(err)
	}
	var doc pdp.Document
	if err := json.Unmarshal(view.Document, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Version = 1
	const drop = "signal.detector.drop__table__prevention"
	return doc, []authoring.Fixture{{
		Name:       "a DROP TABLE the shipped detector flagged",
		Attributes: contract.AttributeSet{drop: contract.Known(true, contract.NamespaceOf(drop).DefaultProvenance(), 1, digestNow)},
		Expect:     map[string]pdp.Verdict{doc.Policies[0].ID: pdp.VerdictMatch},
	}}
}

// packsWorldLabel is the +packs world's label, and the prefix of its rows.
const packsWorldLabel = "enterprise+packs"

// shippedPacks loads every policy pack under ee/policy-packs, sorted by
// directory, beside testpack (the fixture TestGate15OffScopeIsDeletionForAPackIDCopy
// installs). present is false when the tree ships no ee/policy-packs - the
// community mirror, which strips ee/ - and then the +packs world is not built.
func shippedPacks(t *testing.T) (packs []*policypack.Pack, present bool) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "ee", "policy-packs")
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []*policypack.Pack
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		source, err := os.ReadFile(filepath.Join(root, e.Name(), "pack.json"))
		if err != nil {
			t.Fatal(err)
		}
		committed, err := os.ReadFile(filepath.Join(root, e.Name(), "document.json"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := policypack.Load(source, committed)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		out = append(out, p)
	}
	return append(out, loadPack(t, testPackSource("testpack"))), true
}

// digestDocuments are the documents the proof activates, per edition: the
// implicit baseline (no document), the baseline pack published, the
// organization template published, and - where the edition admits an
// approval requirement - the acme-approval document. The conformance corpus's
// organization document is ATTEMPTED under the deployment vocabulary too: its
// refusal is recorded as a row (refusals), so base and head must refuse it
// identically, and should it ever publish, it joins the activated set.
func digestDocuments(t *testing.T, w *digestWorld) (docs map[string]*authoring.Artifact, refusals []string) {
	t.Helper()
	base := baselineDocument(t, w.snap)
	tmpl, tmplFixtures := templateDocument(t)
	docs = map[string]*authoring.Artifact{
		"implicit": nil,
		"baseline": w.publish(t, authoringcatalog.BaselinePermissionPackID, base, fixturesFor(&base)),
		"template": w.publish(t, "organization.template-seeded", tmpl, tmplFixtures),
	}
	if w.edition == registry.EditionEnterprise {
		doc := withApprovalOnToolCall(t, w.snap)
		docs["acme-approval"] = w.publish(t, "acme-approval", doc, approvalFixtures(&doc))
	}
	for name, doc := range map[string]*pdp.Document{"conformance-organization": conformance.OrganizationDocument()} {
		art, findings, err := w.tryPublish(name, *doc, nil)
		if err == nil {
			docs[name] = art
			continue
		}
		codes := map[string]bool{}
		for _, f := range findings.Rejections() {
			codes[f.Code] = true
		}
		var list []string
		for c := range codes {
			list = append(list, c)
		}
		sort.Strings(list)
		refusals = append(refusals, fmt.Sprintf("%s/%s\trefused\t-\t%s\t-\t-", w.label(), name, strings.Join(list, ",")))
	}
	return docs, refusals
}

// label names the world in a row: its edition, and "+packs" when it installs
// policy packs.
func (w *digestWorld) label() string {
	if len(w.packs) > 0 {
		return w.edition.String() + "+packs"
	}
	return w.edition.String()
}

// digestWorlds are the worlds the proof activates in: each edition alone, and
// the Enterprise edition with every shipped pack and testpack installed - the
// composition path a pack's own policy takes.
func digestWorlds(t *testing.T) []*digestWorld {
	t.Helper()
	out := []*digestWorld{newDigestWorld(t, registry.EditionCommunity), newDigestWorld(t, registry.EditionEnterprise)}
	if packs, present := shippedPacks(t); present {
		withPacks := newDigestWorld(t, registry.EditionEnterprise)
		installed, err := activation.InstallPacks(withPacks.snap, packs)
		if err != nil {
			t.Fatal(err)
		}
		withPacks.packs = installed
		out = append(out, withPacks)
	} else {
		t.Logf("no ee/policy-packs in this tree (the community mirror): the %s world is not built, and its rows and artifacts are not compared", packsWorldLabel)
	}
	// Each world's rows are keyed by its label, so two worlds under one label
	// would compare each other's rows.
	seen := map[string]bool{}
	for _, w := range out {
		if seen[w.label()] {
			t.Fatalf("two digest worlds are labelled %q", w.label())
		}
		seen[w.label()] = true
	}
	return out
}

// builtLabels is the labels of the worlds digestWorlds built.
func builtLabels(worlds []*digestWorld) map[string]bool {
	out := map[string]bool{}
	for _, w := range worlds {
		out[w.label()] = true
	}
	return out
}

// digestRows computes every row of the proof, sorted.
func digestRows(t *testing.T) (rows []string, artifacts map[string][]byte, built map[string]bool) {
	t.Helper()
	artifacts = map[string][]byte{}
	corpus, err := pdp.SystemCorpusDigest()
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, "corpus\t-\t-\t"+corpus+"\t-\t-")
	worlds := digestWorlds(t)
	built = builtLabels(worlds)
	for _, w := range worlds {
		docs, refusals := digestDocuments(t, w)
		base, _ := digestDocuments(t, w.unpinned(t))
		rows = append(rows, refusals...)
		for name, art := range docs {
			artDigest := "-"
			if art != nil {
				// THE KEY IS THE UNPINNED ARTIFACT'S DIGEST, which is the base
				// tree's: this tree adds the catalog pin to a published
				// artifact and nothing else, so keying on the pinned digest
				// would move all 103 rows for a change no activation makes.
				// assertPinIsTheOnlyDifference proves that "and nothing else".
				unpinned := base[name]
				if unpinned == nil {
					t.Fatalf("%s/%s: no unpinned artifact to key the row on", w.label(), name)
				}
				assertPinIsTheOnlyDifference(t, w.label()+"/"+name, art, unpinned)
				artDigest = unpinned.Digest()
				// THE COMMITTED CORPUS IS THE UNPINNED BYTES, for the same
				// reason the key above is the unpinned digest: they are the
				// bytes the base tree wrote, and
				// TestAnArtifactPublishedBeforeBindsOnActivatesAsItDid
				// requires both that each committed artifact carries NO
				// catalog_version and that its digest keys a row. Marshalling
				// the PINNED artifact here wrote a corpus whose digests did
				// not match the keys written beside them, so a regeneration
				// on this tree produced a set no run could then read.
				raw, err := unpinned.MarshalJSON()
				if err != nil {
					t.Fatal(err)
				}
				artifacts[w.label()+"-"+name] = raw
			}
			for _, s := range w.scopes() {
				act := w.activateOn(t, art, s.plane, s.phase)
				rows = append(rows, strings.Join([]string{
					w.label() + "/" + name + "@" + artDigest,
					act.Scope.String(), "",
					act.SystemBundleDigest, act.OrganizationBundleDigest, act.PolicyBundle,
				}, "\t"))
			}
			// THE DERIVED SCOPE, computed independently and compared to the
			// scope it must equal: a scope the base tree does not have cannot
			// have a base-computed row, and stating its digests here would be a
			// definition rather than a proof.
			assertDerivedScopeEqualsItsBase(t, w, art, w.label()+"/"+name)
		}
	}
	sort.Strings(rows)
	return rows, artifacts, built
}

// TestAbsentBindsOnMovesNoActivationDigest is the proof. Under
// H2_WRITE_BASE_DIGESTS=1 it WRITES the expected values instead, which is only
// ever done on the base tree.
func TestAbsentBindsOnMovesNoActivationDigest(t *testing.T) {
	rows, artifacts, built := digestRows(t)
	// A row computed twice is two worlds or two documents under one key: the
	// multiset, not only the set, must match the base's.
	counts := map[string]int{}
	for _, r := range rows {
		counts[r]++
		if counts[r] == 2 {
			t.Errorf("row computed more than once: %s", r)
		}
	}
	got := strings.Join(rows, "\n") + "\n"
	if os.Getenv("H2_WRITE_BASE_DIGESTS") == "1" {
		if err := os.MkdirAll(filepath.Join("testdata", "binds_on_4371_base_artifacts"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(baseDigestsFile, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		for name, raw := range artifacts {
			if err := os.WriteFile(filepath.Join("testdata", "binds_on_4371_base_artifacts", name+".json"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Skipf("wrote %d base digest rows and %d artifacts", len(rows), len(artifacts))
	}
	raw, err := os.ReadFile(baseDigestsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := keepBuilt(t, string(raw), built)
	if got == want {
		t.Logf("%d activation digest rows identical to the base's", len(rows))
		return
	}
	wantRows := map[string]bool{}
	for _, r := range strings.Split(strings.TrimSpace(want), "\n") {
		wantRows[r] = true
	}
	moved := 0
	for _, r := range rows {
		if !wantRows[r] {
			moved++
			t.Errorf("moved from the base: %s", r)
		}
	}
	t.Fatalf("%d of %d activation digest rows differ from the base's (%d rows there)", moved, len(rows), len(wantRows))
}

// TestAnArtifactPublishedBeforeBindsOnActivatesAsItDid loads the artifacts the
// BASE tree published (their bytes, committed), re-activates each on every
// scope, and requires the base's digests: a document published before #4371
// and re-activated after it is the same policy set.
//
// WHAT IT PROVES ABOUT THE CATALOG PIN, EXACTLY (#4249 row 5706695827; the
// claim here was narrowed in master R3 round 1 on #4394, MEDIUM-1). These
// bytes were written before the pin existed. LoadArtifact re-marshals the
// provenance and re-digests it, so a pin that were not omitempty would break
// the signature on every one of them here - the fleet-wide activation refusal
// that mistake would be - and each artifact is asserted to carry NO pin, so
// zero is a value the compatibility rule really meets in the field.
//
// IT PROVES NOTHING ABOUT WHAT THE PIN MEANS. None of these artifacts carries
// a `binds_on` at all, so the alias never fires here: this test stayed GREEN
// under a plant that replaced activation's pin wiring with a constant. The
// meaning of the pin - which scopes a `wcp` control binds at 6 and at 7 - is
// proven by TestTheCatalogPinTheArtifactCarriesDecidesWhatWcpMeant
// (catalog_pin_wiring_4249_test.go), which is the cell that reds under that
// plant.
func TestAnArtifactPublishedBeforeBindsOnActivatesAsItDid(t *testing.T) {
	raw, err := os.ReadFile(baseDigestsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, r := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Split(r, "\t")
		want[f[0]+"\t"+f[1]] = strings.Join(f[3:], "\t")
	}
	checked := 0
	worlds := digestWorlds(t)
	built := builtLabels(worlds)
	// Every committed artifact is read by a world this tree builds, or named
	// as skipped: the +packs world's, where ee/policy-packs is absent.
	all, err := filepath.Glob(filepath.Join("testdata", "binds_on_4371_base_artifacts", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	read, expected, readByWorlds := 0, 0, 0
	for _, path := range all {
		name := filepath.Base(path)
		switch {
		case strings.HasPrefix(name, packsWorldLabel+"-") && !built[packsWorldLabel]:
			t.Logf("skipped %s by name: the %s world is not built in this tree", name, packsWorldLabel)
		default:
			read++
		}
	}
	for _, w := range worlds {
		entries, err := filepath.Glob(filepath.Join("testdata", "binds_on_4371_base_artifacts", w.label()+"-*.json"))
		if err != nil {
			t.Fatal(err)
		}
		readByWorlds += len(entries)
		if len(entries) == 0 {
			t.Fatalf("%s: no base artifacts committed", w.label())
		}
		for _, path := range entries {
			rawArt, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			art, err := authoring.LoadArtifact(rawArt, w.trust)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), w.label()+"-"), ".json")
			expected += len(w.scopes())
			for _, s := range w.scopes() {
				act := w.activateOn(t, art, s.plane, s.phase)
				key := w.label() + "/" + name + "@" + art.Digest() + "\t" + act.Scope.String()
				wantDigests, ok := want[key]
				if !ok {
					t.Fatalf("no base row for %s", key)
				}
				got := strings.Join([]string{act.SystemBundleDigest, act.OrganizationBundleDigest, act.PolicyBundle}, "\t")
				if got != wantDigests {
					t.Errorf("%s re-activated on %s: %s, the base activated %s", name, act.Scope, got, wantDigests)
				}
				checked++
				// THE SCOPE THE BASE DOES NOT HAVE, on the base's own bytes: a
				// document published before the pin existed carries none, so
				// the compatibility rule reads it as pre-split, and the routes'
				// plane must activate what wcp activated for it.
				if s.plane == derivedScope.from.Plane && s.phase == derivedScope.from.Phase {
					derived := w.activateOn(t, art, derivedScope.plane, derivedScope.phase)
					if g := strings.Join([]string{derived.SystemBundleDigest, derived.OrganizationBundleDigest, derived.PolicyBundle}, "\t"); g != wantDigests {
						t.Errorf("%s re-activated on %s: %s, the base activated %s on %s", name, derived.Scope, g, wantDigests, act.Scope)
					}
					if art.Provenance().CatalogVersion != 0 {
						t.Errorf("%s: a committed base artifact carries catalog_version %d; the base tree wrote none, so the field must be omitempty", name, art.Provenance().CatalogVersion)
					}
				}
			}
		}
	}
	if readByWorlds != read {
		t.Errorf("the worlds read %d committed artifacts of %d: an artifact was not read", readByWorlds, read)
	}
	if checked != expected {
		t.Errorf("%d re-activations for %d committed artifacts, want %d (each on its world's scopes): an artifact was not read", checked, read, expected)
	}
	t.Logf("%s", fmt.Sprintf("%d (artifact, scope) re-activations identical to the base's", checked))
}

// keepBuilt is the base's rows less those of a world this tree did not build,
// dropped by name: only the +packs world can be missing (the community mirror
// ships no ee/policy-packs), and its rows are the ones keyed by its label.
func keepBuilt(t *testing.T, want string, built map[string]bool) string {
	t.Helper()
	if built[packsWorldLabel] {
		return want
	}
	var kept []string
	dropped := 0
	for _, r := range strings.Split(strings.TrimSuffix(want, "\n"), "\n") {
		if strings.HasPrefix(r, packsWorldLabel+"/") {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	t.Logf("dropped the base's %d %s rows by name: that world is not built in this tree", dropped, packsWorldLabel)
	return strings.Join(kept, "\n") + "\n"
}

// assertPinIsTheOnlyDifference proves that the catalog pin is the whole of what
// this tree adds to a published artifact: the pinned artifact's bytes, with the
// pin removed, are the unpinned artifact's, and the two digests differ (so the
// pin is really there and the key above is not silently the same value).
func assertPinIsTheOnlyDifference(t *testing.T, name string, pinned, unpinned *authoring.Artifact) {
	t.Helper()
	got, err := pinned.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want, err := unpinned.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	pin := fmt.Sprintf("\"catalog_version\":%d,", authoringcatalog.DeploymentCatalogVersion)
	if !strings.Contains(string(got), pin) {
		t.Fatalf("%s: the published artifact does not carry %s; the pin is what the compatibility rule reads", name, pin)
	}
	if strings.Contains(string(want), "catalog_version") {
		t.Fatalf("%s: the unpinned artifact carries a catalog_version; it must be the base tree's bytes", name)
	}
	// The signed VIEW is compared, which is everything up to the artifact's own
	// digest: the digest and the signature over it differ by construction once
	// the pin is in the view, and that difference is what the next assertion
	// requires.
	view := func(raw []byte) string {
		v, _, ok := strings.Cut(string(raw), `,"digest":"`)
		if !ok {
			t.Fatalf("%s: the artifact JSON carries no digest member", name)
		}
		return v
	}
	if stripped := strings.Replace(view(got), pin, "", 1); stripped != view(want) {
		t.Fatalf("%s: with the pin removed the signed view is not the base tree's; this tree changes more than the pin", name)
	}
	if pinned.Digest() == unpinned.Digest() {
		t.Fatalf("%s: the pinned and unpinned artifacts digest alike; the pin is not in the digest", name)
	}
}

// assertDerivedScopeEqualsItsBase activates the derived scope and requires the
// activation digests of the scope it is derived from, computed in the same run.
// Both are computed here: if the derivation and the computation ever disagree,
// what broke is the equality ruling 2 states - the new plane binding what wcp
// binds - and this names it.
func assertDerivedScopeEqualsItsBase(t *testing.T, w *digestWorld, art *authoring.Artifact, name string) {
	t.Helper()
	got := w.activateOn(t, art, derivedScope.plane, derivedScope.phase)
	want := w.activateOn(t, art, derivedScope.from.Plane, derivedScope.from.Phase)
	for _, f := range []struct{ what, got, want string }{
		{"system bundle", got.SystemBundleDigest, want.SystemBundleDigest},
		{"organization bundle", got.OrganizationBundleDigest, want.OrganizationBundleDigest},
		{"policy bundle", got.PolicyBundle, want.PolicyBundle},
	} {
		if f.got != f.want {
			t.Errorf("%s: %s on %s is %s and on %s %s. The two scopes must activate the same policy set: %s binds what %s binds, by the same derivation (#4249 row 5706695827)",
				name, f.what, got.Scope, f.got, want.Scope, f.want, got.Scope, want.Scope)
		}
	}
}
