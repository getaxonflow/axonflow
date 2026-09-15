// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringvocabulary_test

import (
	"testing"
	"time"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/shared/authoringvocabulary"
)

// weldedDigest is the content digest of the deployment vocabulary resolved for
// weldDeployment below.
//
// IT IS A PIN, and the thing it pins is not the digest for its own sake: it is
// the WELD between the vocabulary's content and the integer that identifies it
// on the wire. See the test.
const weldedDigest = "sha256:19d7d2e7d60ba0d8f4ff4c53cd38f21db6a863a2b9b7fdee29ee7c3e3e678d4d"

// weldDeployment is a FIXED deployment description, so the digest below is a
// function of the vocabulary alone.
//
// The realm set is deployment-derived, so a digest pinned against "whatever
// this machine resolves" would move with the machine and pin nothing. Fixing
// the input is what makes the pin a statement about the CATALOG.
func weldDeployment() authoringvocabulary.CatalogDeployment {
	return authoringvocabulary.CatalogDeployment{HasDirectory: true, HasRevocation: false, HasCAEP: false}
}

// TestTheDeploymentCatalogVersionIsWeldedToItsDigest is the mechanism behind
// authoringcatalog.DeploymentCatalogVersion's claim that it "is not a number
// somebody remembers to bump; it is a number the digest makes them bump"
// (#3895).
//
// # THE FAILURE IT EXISTS TO PREVENT
//
// contract.Snapshot.RegistryVersion travels on every request, into every
// decision, and into a decision proof's binding. Its whole job is to answer
// "which vocabulary was this decided against". If the vocabulary's CONTENT
// changes - an action registered, an argument's type corrected, a realm's
// attributes moved - and the integer does not, then two materially different
// vocabularies are both called version N. A decision recorded under N is then
// not reproducible, and replay would verify against the wrong catalog while
// reporting success. That is a silent failure in the one field that exists to
// make it impossible.
//
// So the digest is pinned. Changing what the vocabulary contains fails this
// test, and the only way to make it pass is to update the pin AND the version
// together - which is the review moment where somebody asks whether the change
// was intended.
//
// # WHY THIS IS NOT MERELY A CHANGE-DETECTOR
//
// A bare "the digest is X" pin would fail for a reformatting that changed
// nothing. This pins the digest of the CONTENT projection - actions, realms and
// resource types - which is what decides whether two catalogs admit and refuse
// the same policies. contract.ExactDigest over that projection is exactly the
// question a caller asks when it compares two deployments' vocabularies.
func TestTheDeploymentCatalogVersionIsWeldedToItsDigest(t *testing.T) {
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, weldDeployment())
	if err != nil || snap == nil {
		t.Fatalf("the deployment vocabulary must resolve: %v", err)
	}

	if snap.RegistryVersion != authoringcatalog.DeploymentCatalogVersion {
		t.Fatalf("the snapshot carries registry version %d and the constant is %d",
			snap.RegistryVersion, authoringcatalog.DeploymentCatalogVersion)
	}

	if weldedDigest == "sha256:PIN_ME" {
		t.Fatalf("this pin has never been set. The deployment vocabulary currently digests to:\n\n    %s\n\n"+
			"Set weldedDigest to that value. If you are seeing this because you CHANGED the vocabulary, bump "+
			"authoringcatalog.DeploymentCatalogVersion in the same commit: a decision recorded under the old "+
			"version must never be reproducible against a different vocabulary wearing the same number.",
			snap.Digest)
	}
	if snap.Digest != weldedDigest {
		t.Fatalf("THE DEPLOYMENT VOCABULARY'S CONTENT CHANGED.\n"+
			"  digest now: %s\n"+
			"  pinned:     %s\n"+
			"  version:    %d\n\n"+
			"The vocabulary's actions, realms or resource types are not what they were. That is allowed - it is "+
			"not allowed to happen QUIETLY, because contract.Snapshot.RegistryVersion travels into every decision "+
			"and every proof binding as the answer to \"which vocabulary decided this\".\n\n"+
			"Update weldedDigest AND bump authoringcatalog.DeploymentCatalogVersion, in this commit, together.",
			snap.Digest, weldedDigest, snap.RegistryVersion)
	}

	// THE PIN IS OVER CONTENT, and this is what says so: the same content
	// resolved twice is the same digest, and a changed realm set is not.
	again, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, weldDeployment())
	if err != nil {
		t.Fatal(err)
	}
	if again.Digest != snap.Digest {
		t.Fatal("two resolutions of one deployment produced two digests; the digest is not a function of the content")
	}
	moved := weldDeployment()
	moved.HasDirectory = false
	other, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, moved)
	if err != nil {
		t.Fatal(err)
	}
	if other.Digest == snap.Digest {
		t.Fatal("a deployment with no directory resolved to the SAME digest as one with a directory; the realm " +
			"attributes are not reaching the digest, so this pin would not notice them changing")
	}
}

// TestTheWeldedPinIsNotStaleAgainstAnUnrelatedInput guards the pin itself: it
// must be a statement about the vocabulary, not about the clock.
func TestTheWeldedPinIsNotStaleAgainstAnUnrelatedInput(t *testing.T) {
	first, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, weldDeployment())
	if err != nil {
		t.Fatal(err)
	}
	// Resolved a second time a notional day later. The registry's evaluation
	// instant is read per resolution (time.Now), and if it reached the digest
	// the pin above would fail for everybody tomorrow.
	time.Sleep(2 * time.Millisecond)
	second, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, weldDeployment())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("the vocabulary digest moved between two resolutions in the same process (%s -> %s); something "+
			"time-varying is reaching it, and the pin would be unmaintainable", first.Digest, second.Digest)
	}
}
