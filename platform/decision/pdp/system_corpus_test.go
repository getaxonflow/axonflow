// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheShippedCorpusParsesAndDigests holds the embedded artifact to the
// minimum a deployment needs from it.
func TestTheShippedCorpusParsesAndDigests(t *testing.T) {
	sys, err := SystemCorpusDocument()
	if err != nil {
		t.Fatalf("SystemCorpusDocument: %v", err)
	}
	if sys.Root != RootSystem {
		t.Fatalf("the shipped system document declares root %q", sys.Root)
	}
	if len(sys.Policies) == 0 {
		t.Fatal("the shipped system document carries no policy")
	}
	if errs := sys.Validate(); len(errs) > 0 {
		t.Fatalf("the shipped system document does not validate: %v", errs)
	}
	org, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("SystemCorpusOrganizationTemplate: %v", err)
	}
	if org.Root != RootOrganization {
		t.Fatalf("the shipped organization template declares root %q", org.Root)
	}

	d, err := SystemCorpusDigest()
	if err != nil {
		t.Fatalf("SystemCorpusDigest: %v", err)
	}
	if !strings.HasPrefix(d, "sha256:") {
		t.Errorf("the corpus digest is %q, which is not the digest form the bundle provenance carries", d)
	}

	// THE ANCHOR IS ONLY WORTH ANYTHING IF IT EQUALS WHAT A BUNDLE BUILT FROM
	// THE SAME DOCUMENT ADVERTISES. Digesting the FILE BYTES instead of the
	// document would pass every check above and refuse every real bundle,
	// which is a fail-CLOSED defect but a total one: no deployment could
	// activate its own shipped corpus.
	b, err := BuildBundle(sys)
	if err != nil {
		t.Fatalf("BuildBundle over the shipped corpus: %v", err)
	}
	if b.Provenance.SourceDigest != d {
		t.Fatalf("a bundle built from the shipped corpus advertises source digest %s and the anchor is %s; the anchor would "+
			"refuse the very corpus this binary ships", b.Provenance.SourceDigest, d)
	}
}

// TestTheSystemCorpusAnchorRefusesAnEmptyDeclaration is the fail-closed rule.
func TestTheSystemCorpusAnchorRefusesAnEmptyDeclaration(t *testing.T) {
	if err := (SystemCorpusAnchor{}).Validate(); err == nil {
		t.Fatal("an empty anchor was accepted; a missing anchor is a system root nobody is checking")
	}
	if err := (SystemCorpusAnchor{Digest: "sha256:aa", UnanchoredReason: "because"}).Validate(); err == nil {
		t.Fatal("an anchor that is both pinned and unanchored was accepted; it cannot refuse anything")
	}
	if err := Unanchored("a fixture world").Validate(); err != nil {
		t.Errorf("a declared unanchored engine was refused: %v", err)
	}
	a, err := AnchorToShippedCorpus()
	if err != nil {
		t.Fatalf("AnchorToShippedCorpus: %v", err)
	}
	if err := a.Validate(); err != nil {
		t.Errorf("the production anchor was refused: %v", err)
	}
}

// signedBundleFor builds and signs a bundle for a document, and authorizes its
// key, so the anchor is the only thing left that can refuse it.
func signedBundleFor(t *testing.T, d *Document) (*Bundle, *TrustStore) {
	t.Helper()
	b, err := BuildBundle(d)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := b.Sign("test-key", priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(d.Root, "test-key", pub)
	return b, ts
}

// TestActivationRefusesASystemBundleThisBinaryDidNotShip is the whole control,
// driven end to end through NewEngine.
//
// The POSITIVE control comes first and is not decoration: the same document,
// the same key, the same trust store, activated under the correct anchor, must
// succeed. Without it, the refusal below could be for any of a dozen reasons -
// a signature, a registry, a manifest - and the test would report a working
// guard while the guard did nothing.
func TestActivationRefusesASystemBundleThisBinaryDidNotShip(t *testing.T) {
	shipped, err := SystemCorpusDocument()
	if err != nil {
		t.Fatalf("SystemCorpusDocument: %v", err)
	}
	anchor, err := AnchorToShippedCorpus()
	if err != nil {
		t.Fatalf("AnchorToShippedCorpus: %v", err)
	}

	// Positive control: the shipped corpus activates.
	b, ts := signedBundleFor(t, shipped)
	reg := &Registry{Actions: map[string]ActionEntry{}, Realms: map[string]bool{}}
	if _, err := NewEngine(context.Background(), EngineConfig{
		Bundles: []*Bundle{b}, Documents: []*Document{shipped},
		TrustStore: ts, Registry: reg, SystemCorpus: anchor,
	}); err != nil {
		t.Fatalf("the shipped corpus did not activate under its own anchor, so the refusal below proves nothing: %v", err)
	}

	// The negative: a system document that is NOT the shipped one. It is the
	// shipped corpus with one policy removed, which is the realistic shape of
	// the attack - a ceiling quietly weakened, not a document that looks
	// obviously wrong.
	weakened := *shipped
	weakened.Policies = append([]Policy(nil), shipped.Policies[1:]...)
	wb, wts := signedBundleFor(t, &weakened)
	_, err = NewEngine(context.Background(), EngineConfig{
		Bundles: []*Bundle{wb}, Documents: []*Document{&weakened},
		TrustStore: wts, Registry: reg, SystemCorpus: anchor,
	})
	if err == nil {
		t.Fatal("a system-root bundle carrying a document this binary did not ship was activated. It was correctly signed and " +
			"its key was authorized, which is exactly why the signature is not the control here")
	}
	if !strings.Contains(err.Error(), "did not ship") && !strings.Contains(err.Error(), "refusing to activate a system-root bundle") {
		t.Errorf("the refusal is not the anchor's: %v", err)
	}

	// And the same weakened document activates when the engine DECLARES itself
	// unanchored, which is what the shadow, replay and conformance worlds do.
	if _, err := NewEngine(context.Background(), EngineConfig{
		Bundles: []*Bundle{wb}, Documents: []*Document{&weakened},
		TrustStore: wts, Registry: reg,
		SystemCorpus: Unanchored("a test world that deliberately activates a document other than the shipped corpus"),
	}); err != nil {
		t.Errorf("a declared-unanchored engine refused a non-shipped system document: %v", err)
	}
}

// TestTheAnchorDoesNotRefuseAnOrganizationBundle keeps the control scoped to
// the root it is about.
//
// An anchor that also refused organization bundles would be a control on the
// customer's own authority, which is not what it is for and would break every
// deployment that publishes one.
//
// IT ACTIVATES THE SHIPPED CORPUS ALONGSIDE, and the earlier version did not.
// That version was the configuration R3 flagged: an anchored engine with an
// organization bundle and NO system bundle, asserted as correct. It was not
// correct - it is a deployment enforcing none of the platform's own ceilings
// while every per-bundle check passes - and the test asserting it was correct
// is what would have kept that state.
func TestTheAnchorDoesNotRefuseAnOrganizationBundle(t *testing.T) {
	org, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("SystemCorpusOrganizationTemplate: %v", err)
	}
	if len(org.Policies) == 0 {
		// NOT a skip. The input is a checked-in artifact, so an empty
		// organization template is a broken artifact rather than a reason this
		// machine cannot run the check, and a skip here would be a green
		// nobody reads.
		t.Fatal("the shipped organization template carries no policy; the artifact is broken, and skipping would report that as a pass")
	}
	sys, err := SystemCorpusDocument()
	if err != nil {
		t.Fatalf("SystemCorpusDocument: %v", err)
	}
	anchor, err := AnchorToShippedCorpus()
	if err != nil {
		t.Fatalf("AnchorToShippedCorpus: %v", err)
	}
	ob, ts := signedBundleFor(t, org)
	sb, err := BuildBundle(sys)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := sb.Sign("system-key", priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ts.Authorize(RootSystem, "system-key", pub)

	if _, err := NewEngine(context.Background(), EngineConfig{
		Bundles: []*Bundle{sb, ob}, Documents: []*Document{sys, org},
		TrustStore: ts, Registry: &Registry{Actions: map[string]ActionEntry{}, Realms: map[string]bool{}}, SystemCorpus: anchor,
	}); err != nil {
		t.Fatalf("the anchor refused an ORGANIZATION-root bundle activated beside the shipped corpus: %v", err)
	}
}

// TestAnAnchoredEngineWithNoSystemBundleIsRefused is the absence check.
//
// A per-bundle check cannot see a document that is not there. Without this, a
// deployment that simply omits the system bundle passes every check, enforces
// zero platform ceilings, and is indistinguishable from one that activated the
// corpus correctly.
func TestAnAnchoredEngineWithNoSystemBundleIsRefused(t *testing.T) {
	org, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("SystemCorpusOrganizationTemplate: %v", err)
	}
	anchor, err := AnchorToShippedCorpus()
	if err != nil {
		t.Fatalf("AnchorToShippedCorpus: %v", err)
	}
	ob, ts := signedBundleFor(t, org)
	reg := &Registry{Actions: map[string]ActionEntry{}, Realms: map[string]bool{}}

	_, err = NewEngine(context.Background(), EngineConfig{
		Bundles: []*Bundle{ob}, Documents: []*Document{org},
		TrustStore: ts, Registry: reg, SystemCorpus: anchor,
	})
	if err == nil {
		t.Fatal("an engine anchored to the shipped corpus activated with no system-root bundle at all; it enforces none of " +
			"the platform's own ceilings and every per-bundle check passed while it did")
	}
	if !strings.Contains(err.Error(), "activates no system-root bundle") {
		t.Errorf("the refusal is not the absence check's: %v", err)
	}

	// The CONTROL: the identical configuration under a DECLARED unanchored
	// engine is accepted, because that is what the shadow, replay and
	// conformance worlds do. Without it this test would pass on an engine that
	// refused everything.
	if _, err := NewEngine(context.Background(), EngineConfig{
		Bundles: []*Bundle{ob}, Documents: []*Document{org},
		TrustStore: ts, Registry: reg,
		SystemCorpus: Unanchored("a fixture world that activates no system document"),
	}); err != nil {
		t.Errorf("a declared-unanchored engine with no system bundle was refused: %v", err)
	}
}

// TestTheShapeEqualityCitationResolves resolves the citation this package
// makes about where its private mirror of the artifact's shape is held equal.
//
// `shippedCorpusFile` is a hand-maintained mirror of `legacycompile.Corpus`,
// and this package deliberately does not import that one - the decision core
// must not depend on the migration tool that produced the artifact. That
// treatment always carries the same hazard, so the comment names the test that
// closes it. An earlier version named a test that had never been written.
func TestTheShapeEqualityCitationResolves(t *testing.T) {
	path, symbol, ok := strings.Cut(shapeEqualityTest, "::")
	if !ok {
		t.Fatalf("the shape-equality citation %q is not in path::Symbol form", shapeEqualityTest)
	}
	root := repoRootFromPDP(t)
	b, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatalf("this package cites %s as the test holding its private shape equal to legacycompile.Corpus, and that file "+
			"cannot be read: %v", path, err)
	}
	if !strings.Contains(string(b), "func "+symbol+"(") {
		t.Errorf("this package cites %s in %s, and that file declares no such test. Nothing then holds shippedCorpusFile "+
			"equal to legacycompile.Corpus, and a field added to one and not the other makes the artifact unparseable here "+
			"or silently truncated there", symbol, path)
	}
}

// TestTheOrganizationTemplateIsNotSharedBetweenCallers drives the aliasing.
//
// The template's documented use is "a deployment instantiates it per
// organization", so extending it is the expected shape of use - and
// organization bundles are not anchored, so nothing downstream would notice a
// caller that extended the shared copy. The system document is deliberately
// NOT copied and this asserts that difference too, so the asymmetry is a
// decision rather than an oversight.
func TestTheOrganizationTemplateIsNotSharedBetweenCallers(t *testing.T) {
	first, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("SystemCorpusOrganizationTemplate: %v", err)
	}
	before := len(first.Policies)
	if before == 0 {
		t.Fatal("the shipped organization template carries no policy; this check would compare nothing")
	}
	first.Policies = append(first.Policies, first.Policies[0])
	if len(first.Policies) > 0 {
		first.Policies[0].ID = "mutated-by-a-caller"
	}

	second, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("SystemCorpusOrganizationTemplate: %v", err)
	}
	if len(second.Policies) != before {
		t.Errorf("a caller that appended to the template changed what a later caller sees: %d then %d", before, len(second.Policies))
	}
	if second.Policies[0].ID == "mutated-by-a-caller" {
		t.Error("a caller that wrote through the template's policy slice changed what a later caller sees")
	}

	// THE SLICES INSIDE A POLICY, WHICH IS WHERE THE FIRST VERSION OF THIS
	// TEST STOPPED LOOKING. Copying the policy slice protects the ID a test
	// happens to poke and leaves obligations, break-glass roles, scope groups
	// and the condition tree shared. R3 drove exactly that: an obligation
	// written through the returned template was visible to the next caller.
	obligated := -1
	for i, p := range first.Policies {
		if len(p.Obligations) > 0 {
			obligated = i
			break
		}
	}
	if obligated < 0 {
		t.Fatal("no policy in the shipped organization template carries an obligation; the aliasing check below would compare nothing")
	}
	first.Policies[obligated].Obligations[0].SourcePolicy = "mutated-through-an-obligation"
	if first.Policies[obligated].Where.Operands != nil {
		first.Policies[obligated].Where.Operands[0].Path = "mutated-through-a-condition"
	}
	third, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("SystemCorpusOrganizationTemplate: %v", err)
	}
	if third.Policies[obligated].Obligations[0].SourcePolicy == "mutated-through-an-obligation" {
		t.Error("a caller that wrote through a returned policy's OBLIGATION changed what a later caller sees; the copy is one " +
			"level deep and a policy owns several slices below that level")
	}
	if ops := third.Policies[obligated].Where.Operands; len(ops) > 0 && ops[0].Path == "mutated-through-a-condition" {
		t.Error("a caller that wrote through a returned policy's CONDITION TREE changed what a later caller sees")
	}

	// The system document is the OTHER answer, and it is protected by the
	// digest rather than by a copy: a mutation there cannot become a ceiling
	// because the anchor compares against the digest computed from the
	// embedded bytes at load, which no caller can reach.
	sys, err := SystemCorpusDocument()
	if err != nil {
		t.Fatalf("SystemCorpusDocument: %v", err)
	}
	pinned, err := SystemCorpusDigest()
	if err != nil {
		t.Fatalf("SystemCorpusDigest: %v", err)
	}
	// DRIVEN THROUGH THE REAL REFUSAL, because the obvious assertion cannot
	// fail. `SystemCorpusDigest` returns a field set once inside `once.Do`, so
	// comparing it before and after a mutation tests memoisation and not the
	// claim - which is that a mutated document cannot become the ceiling. That
	// claim is only true if ACTIVATION refuses it, so activation is what runs.
	held := sys.Policies
	sys.Policies = append([]Policy(nil), held[1:]...)
	mutated := *sys
	sys.Policies = held

	b, ts := signedBundleFor(t, &mutated)
	anchor, err := AnchorToShippedCorpus()
	if err != nil {
		t.Fatalf("AnchorToShippedCorpus: %v", err)
	}
	if _, err := NewEngine(context.Background(), EngineConfig{
		Bundles: []*Bundle{b}, Documents: []*Document{&mutated},
		TrustStore: ts, Registry: &Registry{Actions: map[string]ActionEntry{}, Realms: map[string]bool{}},
		SystemCorpus: anchor,
	}); err == nil {
		t.Error("a system document with a policy removed was activated under the shipped-corpus anchor; the memoised digest is " +
			"only worth something if activation refuses what does not match it")
	}
	if after, err := SystemCorpusDigest(); err != nil || after != pinned {
		t.Errorf("the anchor digest moved (%s -> %s, err=%v); it is memoised at load precisely so a caller cannot move it",
			pinned, after, err)
	}
}

// TestCheckSystemPublicationBindsTheDocumentToTheBundle is the pair the anchor
// alone cannot see, on either anchor.
//
// Under a restriction, checkSystemBundle accepts any bundle that is not the
// whole corpus and leaves the verdict to the document, so a valid restriction
// handed over beside a bundle compiled from a DIFFERENT valid restriction passes
// both anchor checks. Under the whole corpus it is the other way round: the
// subset check does not run and the bundle check judges only the bundle, so the
// shipped corpus's own bundle beside any other document passes both. In each
// case only the binding refuses the pair. The method is exported, so "the
// caller built the bundle from the document" is not something it may assume.
func TestCheckSystemPublicationBindsTheDocumentToTheBundle(t *testing.T) {
	shipped, err := SystemCorpusDocument()
	if err != nil {
		t.Fatalf("SystemCorpusDocument: %v", err)
	}
	if len(shipped.Policies) < 2 {
		t.Fatalf("the shipped corpus carries %d policy(ies); two different restrictions need at least two", len(shipped.Policies))
	}
	restrictTo := func(p Policy) *Document {
		d := *shipped
		d.Policies = []Policy{p}
		return &d
	}
	signed, other := restrictTo(shipped.Policies[0]), restrictTo(shipped.Policies[1])
	refusedByTheBinding := func(t *testing.T, err error, b *Bundle, pair string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s was answered nil; the anchor judged one of a pair that nothing tied to the other", pair)
		}
		if !strings.Contains(err.Error(), "the two must be the same policy set") || !strings.Contains(err.Error(), b.Provenance.SourceDigest) {
			t.Fatalf("%s was refused, but not by the binding of the document to the bundle's source digest %s: %v",
				pair, b.Provenance.SourceDigest, err)
		}
	}

	t.Run("restriction anchor", func(t *testing.T) {
		anchor, err := AnchorToShippedCorpusRestriction("test: two different one-control restrictions of the shipped corpus")
		if err != nil {
			t.Fatal(err)
		}
		b, err := BuildBundle(signed)
		if err != nil {
			t.Fatalf("BuildBundle over a one-control restriction: %v", err)
		}
		// CONTROLS, so the refusal below can only be about the pairing: the
		// matched pair is a publication the anchor accepts, and the other
		// document is a restriction the anchor accepts on its own.
		if err := anchor.CheckSystemPublication(signed, b); err != nil {
			t.Fatalf("the matched pair was refused, so this test cannot tell the binding from any other refusal: %v", err)
		}
		if err := anchor.CheckSystemRestrictionForTest(other); err != nil {
			t.Fatalf("the other document is not a valid restriction on its own, so the pair below is refused for that: %v", err)
		}
		refusedByTheBinding(t, anchor.CheckSystemPublication(other, b), b,
			"a valid restriction beside a bundle compiled from a different one")
	})

	t.Run("whole-corpus anchor", func(t *testing.T) {
		anchor, err := AnchorToShippedCorpus()
		if err != nil {
			t.Fatal(err)
		}
		b, err := BuildBundle(shipped)
		if err != nil {
			t.Fatalf("BuildBundle over the shipped corpus: %v", err)
		}
		// CONTROL: the shipped corpus and its own bundle are the publication
		// the whole-corpus anchor exists to accept.
		if err := anchor.CheckSystemPublication(shipped, b); err != nil {
			t.Fatalf("the shipped corpus and its own bundle were refused, so this test cannot tell the binding from any other refusal: %v", err)
		}
		refusedByTheBinding(t, anchor.CheckSystemPublication(other, b), b,
			"the shipped corpus's own bundle beside a different document")
	})

	// A BUNDLE THAT NAMES NO SOURCE. Under a restriction the anchor accepts any
	// bundle that is not the whole corpus, and an empty source digest is not the
	// whole corpus, so only the binding can refuse it. The document is the one
	// the bundle was really built from, so nothing but the missing provenance is
	// wrong with the pair.
	t.Run("bundle with no source digest", func(t *testing.T) {
		anchor, err := AnchorToShippedCorpusRestriction("test: a bundle whose provenance names no source")
		if err != nil {
			t.Fatal(err)
		}
		built, err := BuildBundle(signed)
		if err != nil {
			t.Fatalf("BuildBundle over a one-control restriction: %v", err)
		}
		if err := anchor.CheckSystemPublication(signed, built); err != nil {
			t.Fatalf("the pair with its provenance intact was refused, so this test cannot tell the missing digest from any other refusal: %v", err)
		}
		bare := *built
		bare.Provenance.SourceDigest = ""
		err = anchor.CheckSystemPublication(signed, &bare)
		if err == nil {
			t.Fatal("a bundle carrying no source digest was answered nil beside the document it was built from; a bundle that names no source vouches for no document")
		}
		if !strings.Contains(err.Error(), "carries no source digest") {
			t.Fatalf("a bundle carrying no source digest was refused, but not as one: %v", err)
		}
	})
}
