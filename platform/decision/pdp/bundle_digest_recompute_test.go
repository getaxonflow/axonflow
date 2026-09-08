// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// mislabelledBundle returns a bundle whose content is genuine, whose signature
// is genuine, and whose advertised digest describes something else.
//
// That combination is the whole point of #3700 and it is not a contrived one:
// Digest is excluded from view(), so the signature cannot cover it. A verifier
// that only checked the signature would accept this bundle.
func mislabelledBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := b.Sign("k1", priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	b.Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	return b
}

func TestVerifiedDigestRefusesABundleWhoseDigestDoesNotDescribeIt(t *testing.T) {
	good, err := BuildBundle(testDoc())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	content, err := good.ContentDigest()
	if err != nil {
		t.Fatalf("ContentDigest: %v", err)
	}
	if content != good.Digest {
		t.Fatalf("a freshly built bundle disagrees with its own content: advertised %s, content %s", good.Digest, content)
	}
	verified, err := good.VerifiedDigest()
	if err != nil {
		t.Fatalf("VerifiedDigest on a genuine bundle: %v", err)
	}
	if verified != content {
		t.Fatalf("VerifiedDigest returned %s, ContentDigest %s", verified, content)
	}

	bad := mislabelledBundle(t)
	if _, err := bad.VerifiedDigest(); err == nil {
		t.Fatal("VerifiedDigest accepted a bundle whose advertised digest does not describe its content")
	} else if !strings.Contains(err.Error(), "does not match content digest") {
		t.Fatalf("the refusal does not name the mismatch: %v", err)
	}

	// ContentDigest must still ANSWER for the mislabelled bundle - it is "what
	// this hashes to", not "what this claims". A ContentDigest that refused
	// would leave a caller with no way to report the true value.
	if got, err := bad.ContentDigest(); err != nil {
		t.Fatalf("ContentDigest on a mislabelled bundle: %v", err)
	} else if got == bad.Digest {
		t.Fatal("ContentDigest returned the advertised value")
	}

	// THE SAME ERROR AS Verify. #3700's ruling is that a mismatch is refused
	// "with the same error TrustStore.Verify uses", so a caller matching on
	// the text cannot need to know which site produced it.
	ts := NewTrustStore()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed := mislabelledBundle(t)
	if err := signed.Sign("k1", priv); err != nil {
		t.Fatal(err)
	}
	ts.Authorize(signed.Root, "k1", pub)
	verifyErr := ts.Verify(signed)
	if verifyErr == nil {
		t.Fatal("Verify accepted a mislabelled bundle")
	}
	_, digestErr := signed.VerifiedDigest()
	if digestErr == nil {
		t.Fatal("VerifiedDigest accepted a mislabelled bundle")
	}
	if verifyErr.Error() != digestErr.Error() {
		t.Fatalf("the two refusals differ:\n  Verify:         %v\n  VerifiedDigest: %v", verifyErr, digestErr)
	}

	if _, err := (*Bundle)(nil).ContentDigest(); err == nil {
		t.Error("ContentDigest on a nil bundle returned no error")
	}
	if _, err := (*Bundle)(nil).VerifiedDigest(); err == nil {
		t.Error("VerifiedDigest on a nil bundle returned no error")
	}
}
