// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring_test

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestTheSystemAuthoritySignsTheShippedCorpusAndNothingElse is the system half
// of #3884's authority: the one signer of system-root policy signs the corpus
// this binary shipped, or a restriction of it that says why, and refuses
// anything a deployment edited - before a signature exists.
func TestTheSystemAuthoritySignsTheShippedCorpusAndNothingElse(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	system, err := authoring.NewSystemAuthority(priv)
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := pdp.SystemCorpusDigest()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the whole shipped corpus signs and verifies under the publication's own trust", func(t *testing.T) {
		pub, err := system.Publish(shipped, "")
		if err != nil {
			t.Fatalf("the shipped corpus was refused: %v", err)
		}
		if pub.Anchor.Digest != digest || pub.Anchor.RestrictionReason != "" {
			t.Fatalf("the anchor is %+v; want the whole-corpus anchor on %s", pub.Anchor, digest)
		}
		if pub.Bundle.Provenance.SourceDigest != digest || pub.Bundle.KeyID != authoring.SystemKeyID {
			t.Fatalf("the bundle's source digest is %s under key %q; want %s under %q",
				pub.Bundle.Provenance.SourceDigest, pub.Bundle.KeyID, digest, authoring.SystemKeyID)
		}
		trust := pub.TrustStore()
		if err := trust.Verify(pub.Bundle); err != nil {
			t.Fatalf("the publication does not verify under its own trust store: %v", err)
		}
		// A NEW STORE EVERY CALL, and only the system root: #4047 was an
		// authorization written into a store somebody else holds.
		if trust == pub.TrustStore() {
			t.Fatal("TrustStore handed the same store out twice, so one caller adding a key would change what the next verifies against")
		}
		if _, ok := trust.PublicKey(pdp.RootOrganization, authoring.SystemKeyID); ok {
			t.Fatal("the publication's trust store authorizes the system key under the organization root")
		}
	})

	restricted, reason, err := activation.RestrictToPlane("decide")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a restriction signs under its stated reason", func(t *testing.T) {
		pub, err := system.Publish(restricted, reason)
		if err != nil {
			t.Fatalf("the derived restriction was refused: %v", err)
		}
		if pub.Anchor.RestrictionReason != reason || pub.Anchor.Digest != digest {
			t.Fatalf("the anchor is %+v; want a restriction of %s carrying the plane's reason", pub.Anchor, digest)
		}
	})

	// THE WHOLE-CORPUS REFUSAL IS checkSystemBundle's OWN SENTENCE, the one an
	// anchored engine refuses the same bundle with - which is what makes "the
	// signer refuses what the engine refuses" a fact rather than an agreement.
	const bundleRefusal = "this binary shipped the system corpus digesting to"

	t.Run("a restriction presented as the whole corpus is refused", func(t *testing.T) {
		_, err := system.Publish(restricted, "")
		refusedAsNotShipped(t, err, "", bundleRefusal)
	})

	t.Run("an edited control is refused, whole or restricted", func(t *testing.T) {
		_, err := system.Publish(withOneConditionInverted(t, shipped), "")
		refusedAsNotShipped(t, err, "", bundleRefusal)
		_, err = system.Publish(withOneConditionInverted(t, restricted), reason)
		refusedAsNotShipped(t, err, pdp.RefusalNotARestriction, "")
	})

	t.Run("an organization-root document is refused before anything is built", func(t *testing.T) {
		doc := *shipped
		doc.Root = pdp.RootOrganization
		_, err := system.Publish(&doc, "")
		refusedAsNotShipped(t, err, "", "the shipped corpus is the \"system\" document")
	})

	t.Run("no key, no authority", func(t *testing.T) {
		if _, err := authoring.NewSystemAuthority(nil); err == nil {
			t.Fatal("a system authority was built with no signing key")
		}
		if _, err := system.Publish(nil, ""); err == nil {
			t.Fatal("the system authority published a nil document")
		}
	})
}

// refusedAsNotShipped asserts the authority's code, and then WHICH anchor rule
// refused: a typed pdp code where the anchor function returns one (the subset
// check), otherwise the anchor function's own sentence (the bundle check).
func refusedAsNotShipped(t *testing.T, err error, anchorCode, anchorSentence string) {
	t.Helper()
	var refusal *authoring.ErrSystemContentNotShipped
	if !errors.As(err, &refusal) || refusal.Code() != authoring.CodeSystemContentNotShipped {
		t.Fatalf("got %v; want the system authority's %s refusal", err, authoring.CodeSystemContentNotShipped)
	}
	if anchorCode != "" {
		var anchor *pdp.ActivationRefusal
		if !errors.As(err, &anchor) || anchor.Code != anchorCode {
			t.Fatalf("the system authority refused, but the anchor's rule is %v; want %s", err, anchorCode)
		}
	}
	if anchorSentence != "" && !strings.Contains(err.Error(), anchorSentence) {
		t.Fatalf("the system authority refused with %v; want the anchor's %q", err, anchorSentence)
	}
}

// withOneConditionInverted returns a copy of d whose first single-comparison
// boolean constraint binds when its detector does NOT fire: the same
// identifier with the opposite meaning, still schema-valid and compilable, so
// only the content rule can refuse it. d itself is not modified - the shipped
// document is the memoised one.
func withOneConditionInverted(t *testing.T, d *pdp.Document) *pdp.Document {
	t.Helper()
	out := *d
	out.Policies = append([]pdp.Policy(nil), d.Policies...)
	for i := range out.Policies {
		p := &out.Policies[i]
		if p.Authority != contract.AuthorityConstraint || p.Where.Kind != pdp.CondCompare {
			continue
		}
		if lit, ok := p.Where.Literal.(bool); ok && lit {
			p.Where = pdp.Compare(p.Where.Path, p.Where.Op, false)
			return &out
		}
	}
	t.Fatal("no single-comparison boolean constraint to invert, so this case would prove nothing")
	return nil
}
