package conformance

import (
	"testing"

	"axonflow/platform/decision/pdp"
)

// The pinned bundle digests of the two merged conformance documents.
//
// They exist so that a compiler or encoder change that moves digests fails
// HERE, loudly, on an unchanged corpus. Before these pins, whether a change of
// the regoLiteral class moved digests could only be established empirically,
// by building the same corpus under both trees and comparing bytes; a pin
// turns that archaeology into a red test.
//
// If this test fails and the corpus was NOT edited, the compiler's output
// changed for unchanged input. That is a compatibility event for every stored
// artifact digest and every activation history entry that names one, and the
// pin update must say so in review. If the corpus WAS edited deliberately,
// update the pin in the same commit as the edit.
const (
	pinnedSystemBundleDigest       = "sha256:dff5063380cea338ed604a53fbdf17dbaa3cd9564e6d6df4f33fd5059c828c84"
	pinnedOrganizationBundleDigest = "sha256:fafe6c63da63897b2af1afcb0f597e3fcb35a72f35dc1f4fa3f97a678eebf329"
)

func TestConformanceBundleDigestsArePinned(t *testing.T) {
	rows := []struct {
		name string
		doc  *pdp.Document
		want string
	}{
		{"system", SystemDocument(), pinnedSystemBundleDigest},
		{"organization", OrganizationDocument(), pinnedOrganizationBundleDigest},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			b, err := pdp.BuildBundle(tc.doc)
			if err != nil {
				t.Fatalf("building the %s conformance bundle: %v", tc.name, err)
			}
			if b.Digest != tc.want {
				t.Errorf("the %s conformance document builds to\n  %s\nand the pin is\n  %s\n"+
					"If the corpus was not edited, the compiler's output moved for unchanged input, "+
					"which is a compatibility event for every stored artifact digest; the pin update must say so in review.",
					tc.name, b.Digest, tc.want)
			}
		})
	}
}
