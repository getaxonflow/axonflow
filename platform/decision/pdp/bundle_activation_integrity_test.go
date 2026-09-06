package pdp

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// The two checks in TrustStore.Verify that nothing exercised.
//
// Found by proving the ADR-065 gate 19 threat model's citations (#3690): the
// method that catches "this row cites a test that survives a mutant of its own
// control" also catches "no test anywhere sees this control", and these two are
// the second kind. Before this file, deleting either check left
// TestSignatureBindsTheBytesTheCompilerReads and the whole conformance corpus -
// AXC-009 included - green.
//
// Existing coverage around Verify was: unsigned, signed, module edited after
// signing, wrong key, wrong root. Every one of those is caught by the SIGNATURE.
// The two below cannot be, and that is exactly why they were missed:
//
//   - the advertised digest is NOT in the signed view (view() is Root, Module,
//     Manifest, Provenance), so a wrong digest over genuine content carries a
//     perfectly valid signature; and
//   - provenance IS signed, but the check compares it against THIS EVALUATOR's
//     helper module and compiler, and both sides of that comparison are genuine
//     - a signature cannot make it.

// bundleFixtureFor builds and signs a minimal valid bundle plus the trust store
// that accepts it, so each test below starts from something that verifies.
func bundleFixtureFor(t *testing.T) (*Bundle, *TrustStore) {
	t.Helper()
	doc := &Document{
		Root: RootSystem, Version: 1,
		Attributes: []AttributeSchema{{Path: "principal.groups", Type: TypeArray}},
		Policies: []Policy{{
			ID: "C1", Authority: contract.AuthorityConstraint, Root: RootSystem,
			Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true},
			Where: Member("principal.groups", "Group::realm_ws:eng"),
		}},
	}
	b, err := BuildBundle(doc)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	if err := b.Sign("k", priv); err != nil {
		t.Fatalf("signing: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(RootSystem, "k", pub)
	return b, ts
}

// TestAnAdvertisedDigestThatDoesNotDescribeTheContentIsRefused.
//
// A bundle is "built, signed, activated by digest and rolled back by digest",
// so the digest is the handle the whole control plane keys on - and it is the
// one field of a Bundle that no signature covers. The recomputation in Verify
// is therefore the ONLY thing making the advertised digest mean anything, and
// until this test it was unguarded: an edit deleting it would have shipped
// green.
//
// The positive control is not decoration here. Without it a Verify that refused
// every bundle would pass the assertion above it, and this test would report a
// control that had been replaced by a brick.
func TestAnAdvertisedDigestThatDoesNotDescribeTheContentIsRefused(t *testing.T) {
	b, ts := bundleFixtureFor(t)

	if err := ts.Verify(b); err != nil {
		t.Fatalf("the untouched bundle must verify, or the refusal below proves nothing: %v", err)
	}

	// The content is GENUINE and the signature is GENUINE. Only the advertised
	// digest is wrong - which is possible precisely because it is outside
	// view(). This is what an activation record would then pin, and what a
	// decision proof's PolicyBundleDigest would carry.
	mislabelled := *b
	mislabelled.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	err := ts.Verify(&mislabelled)
	if err == nil {
		t.Fatal("a bundle advertising a digest that does not describe its content verified.\n" +
			"Activation and rollback key on that digest, so nothing downstream - including a decision " +
			"proof's PolicyBundleDigest - would describe the policy that actually evaluated.")
	}
	if !strings.Contains(err.Error(), "advertised digest") {
		t.Fatalf("the refusal must name the mismatch so an operator knows which half is wrong, got: %v", err)
	}

	// And the same bundle with its CORRECT digest is still accepted, so the
	// check discriminates rather than refusing everything.
	if err := ts.Verify(b); err != nil {
		t.Fatalf("the correctly labelled bundle must still verify: %v", err)
	}
}

// TestABundleValidatedAgainstAnotherEvaluatorIsRefused.
//
// Provenance is inside the signed view, so tampering with it breaks the
// signature and the existing tests catch that. What they cannot catch, and what
// this covers, is the case where NOTHING is tampered with: a bundle that was
// genuinely compiled and genuinely signed, against a different helper module,
// compiler or schema than the binary now loading it. Both sides are authentic,
// so only an explicit comparison refuses it - "a bundle validated against a
// different helper module has not been validated at all".
//
// ONE MUTANT PER FIELD, because the three are three independent checks: a test
// that changed all three at once would pass with two of the comparisons deleted.
func TestABundleValidatedAgainstAnotherEvaluatorIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*BundleProvenance){
		"helper module":    func(p *BundleProvenance) { p.HelperDigest = "sha256:another-helper-module" },
		"compiler version": func(p *BundleProvenance) { p.CompilerVersion = CompilerVersion + "-next" },
		"schema version":   func(p *BundleProvenance) { p.SchemaVersion = contract.SchemaVersion + "-next" },
	} {
		t.Run(name, func(t *testing.T) {
			b, ts := bundleFixtureFor(t)
			if err := ts.Verify(b); err != nil {
				t.Fatalf("the untouched bundle must verify: %v", err)
			}

			// Re-signed after the change, so this is a bundle that is entirely
			// authentic and simply belongs to another evaluator - not a forgery.
			// Signing after the mutation is what makes the signature unable to
			// be the thing that rejects it.
			other := *b
			mutate(&other.Provenance)
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("generating a key: %v", err)
			}
			if err := other.Sign("k2", priv); err != nil {
				t.Fatalf("re-signing: %v", err)
			}
			// The digest is recomputed too, so the digest check cannot be what
			// rejects it either. Only the provenance comparison is left.
			d, err := contract.ExactDigest(other.view())
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			other.Digest = d
			ts.Authorize(RootSystem, "k2", pub)

			if err := ts.Verify(&other); err == nil {
				t.Fatalf("a bundle validated against another evaluator's %s was accepted; "+
					"it would then evaluate under helpers and a compiler it was never checked against", name)
			}
		})
	}

	// The positive control for the whole table: a bundle whose provenance
	// matches THIS evaluator verifies. Without it, three refusals prove only
	// that something refuses.
	b, ts := bundleFixtureFor(t)
	if err := ts.Verify(b); err != nil {
		t.Fatalf("a bundle built by this evaluator must verify: %v", err)
	}
}
