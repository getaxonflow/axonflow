package pdp

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestSignatureBindsTheBytesTheCompilerReads is the ARTIFACT-level pin.
//
// The encoder-level pin in the contract package proves the exact encoder does
// not normalize. This proves the consequence that matters: a module edited into
// a Unicode-equivalent form after signing does not verify, and does not evaluate
// the same way either. Without it, reverting the exact encoder to a normalizing
// one leaves this package green while reintroducing a signature bypass.
func TestSignatureBindsTheBytesTheCompilerReads(t *testing.T) {
	// Built from explicit code points: two literals a reader cannot tell apart
	// are two literals a WRITER cannot tell apart, and the test would then
	// compare a bundle with itself.
	precomposed := "Group::realm_ws:s" + string(rune(0x00E9)) + "curit"
	decomposed := "Group::realm_ws:s" + string(rune(0x0065)) + string(rune(0x0301)) + "curit"
	if precomposed == decomposed {
		t.Fatal("the two group identifiers are byte-identical, so this test asserts nothing")
	}

	doc := func(group string) *Document {
		return &Document{
			Root: RootSystem, Version: 1,
			Attributes: []AttributeSchema{{Path: "principal.groups", Type: TypeArray}},
			Policies: []Policy{{
				ID: "C1", Authority: contract.AuthorityConstraint, Root: RootSystem,
				Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true},
				Where: Member("principal.groups", group),
			}},
		}
	}
	original, err := BuildBundle(doc(precomposed))
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	variant, err := BuildBundle(doc(decomposed))
	if err != nil {
		t.Fatalf("building the variant: %v", err)
	}
	if original.Module == variant.Module {
		t.Fatal("the two compiled modules are byte-identical, so there is nothing to substitute")
	}
	if original.Digest == variant.Digest {
		t.Error("two byte-different modules produced one bundle digest; activation by digest cannot distinguish them")
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	if err := original.Sign("k", priv); err != nil {
		t.Fatalf("signing: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(RootSystem, "k", pub)
	if err := ts.Verify(original); err != nil {
		t.Fatalf("the untouched bundle does not verify, so the substitution below proves nothing: %v", err)
	}

	// The substitution an adversary with write access performs: keep the
	// signature and the advertised digest, swap the module for one that is
	// Unicode-equivalent and compiles differently.
	tampered := *original
	tampered.Module = variant.Module
	if err := ts.Verify(&tampered); err == nil {
		t.Fatal("a module rewritten into a Unicode-equivalent form kept its signature; " +
			"an edit at rest could flip a constraint while the bundle still verified")
	}

	// And the substitution really does change the program, so the refusal is
	// protecting something rather than being pedantic about bytes.
	rtA, err := NewRuntime(context.Background(), original, DefaultLimits())
	if err != nil {
		t.Fatalf("preparing the original: %v", err)
	}
	rtB, err := NewRuntime(context.Background(), variant, DefaultLimits())
	if err != nil {
		t.Fatalf("preparing the variant: %v", err)
	}
	attrs := contract.AttributeSet{
		"principal.groups": contract.Known([]any{precomposed}, contract.ProvDirectory, 1, contract.Attribute{}.ObservedAt),
	}
	a, err := rtA.Eval(context.Background(), attrs)
	if err != nil {
		t.Fatalf("evaluating the original: %v", err)
	}
	b, err := rtB.Eval(context.Background(), attrs)
	if err != nil {
		t.Fatalf("evaluating the variant: %v", err)
	}
	if a.Outcomes["C1"].Verdict == b.Outcomes["C1"].Verdict {
		t.Errorf("both modules returned %s for the same input, so the substitution would have been harmless; "+
			"the fixture no longer demonstrates the bypass", a.Outcomes["C1"].Verdict)
	}
	if a.Outcomes["C1"].Verdict != VerdictMatch {
		t.Errorf("the original module did not match its own group literal: %s", a.Outcomes["C1"].Verdict)
	}

	// A module carrying an invalid byte cannot be signed at all, so the
	// signature never covers something the encoder had to approximate.
	invalid := *original
	invalid.Module = original.Module + "\n# \xff\n"
	if err := invalid.Sign("k", priv); err == nil {
		t.Error("a module containing an invalid UTF-8 byte was signed")
	} else if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("signing failed for the wrong reason: %v", err)
	}
}
