// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringvocabulary_test

import (
	"testing"
	"time"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/shared/authoringvocabulary"
)

// weldedCommunityDigest and weldedEnterpriseDigest are the content digests of
// the deployment vocabulary resolved for weldDeployment below, under each
// plane edition (deploymode.PlaneEdition: a Community-category deployment mode
// and an Enterprise one).
//
// THEY ARE PINS, and the thing they pin is not the digest for its own sake: it
// is the WELD between the vocabulary's content and the integer that identifies
// it on the wire. See the test.
//
// BOTH EDITIONS, because the vocabulary is edition-dependent (#4371's
// editionScopes: an action states only the scopes whose plane the edition
// registers). Until #4259 the weld resolved under the test process's own
// DEPLOYMENT_MODE, which is unset in CI and resolves Community, so an
// Enterprise-only change - #4259's cowork_ingest scope - moved the Enterprise
// vocabulary with the version unmoved and the weld green (#4249 row filed by
// S1, found by S3's design).
const (
	weldedCommunityDigest  = "sha256:8c8262fe1b433110cc2f75333eff560f530eb8674071d5591c547fa9dfe228c2"
	weldedEnterpriseDigest = "sha256:e8466d4ef51c3ea1f71ac9d9f0ce6506545071cc104a9f89268e35ed1a7dd66d"
)

// weldHistory is every pair of digests the weld has pinned, with the version
// they were pinned under, oldest first: exactly one entry per version,
// contiguous from 2 (the first version the weld pinned) to
// DeploymentCatalogVersion, and no two entries with the same pair: a version
// advances when EITHER edition's content does. The last entry is the welded
// pair.
//
// Versions 2-4 were welded under one edition only, the one the test process
// resolved; their Enterprise digest was never pinned, so it is recorded empty
// and not compared. Version 5 is recorded with both, measured on 7ec34a15c6
// (both editions resolved one digest there).
//
// IT IS WHAT MAKES THE VERSION HALF OF THE WELD FAIL. Comparing the snapshot's
// version with the constant it was built from cannot fail, so a pin moved
// without a bump used to pass. Now a new digest must arrive as a new entry at
// the next version, and that version must be the constant.
//
// WHAT NO TEST IN ONE TREE CAN SEE: rewriting the last entry's digests AND
// the welded digests in place, both to the new content, at the same version. The
// history then describes itself consistently. A test run on a tree proves that
// tree agrees with itself, not that it agrees with the tree before it, so this
// edit is caught only where a pin is carried from the base - the base-computed
// digest constants beside this test - and by the reviewer reading the diff, in
// which a recorded digest changes. That edit is the review moment this file
// exists to force.
var weldHistory = []struct {
	community, enterprise string
	version               int64
}{
	{"sha256:19d7d2e7d60ba0d8f4ff4c53cd38f21db6a863a2b9b7fdee29ee7c3e3e678d4d", "", 2},
	// #4249: the `oidc` realm declared when the deployment wires the OIDC
	// source; the fixture below gained HasOIDC to see it.
	{"sha256:12d0f2159045823aa8d690480ade5556590263108a5f98ecc4e3a307e1a444f7", "", 3},
	// #4249 row 5670275054: args.context.step__name and args.context.tool__name
	// declared for an organization's document to read, so the deployment
	// vocabulary's content moves again.
	{"sha256:05e6ed5d5f6754075f33c087eb1a81287d66351375a9f375e5692ad667f73374", "", 4},
	// #4371: each action states the enforcement scopes that present it
	// (pdp.ActionEntry.Planes), the scopes a control may name in binds_on.
	{"sha256:c0a92aee66424f8ad8e32f7e131ee5e6ad29e1510ff7d850f7e3bca3e7f235b3", "sha256:c0a92aee66424f8ad8e32f7e131ee5e6ad29e1510ff7d850f7e3bca3e7f235b3", 5},
	// #4259: the Enterprise plane set gains cowork_ingest, which presents
	// llm.completion and tool.call; the Community vocabulary is unchanged.
	{"sha256:c0a92aee66424f8ad8e32f7e131ee5e6ad29e1510ff7d850f7e3bca3e7f235b3", "sha256:6136eedf266b0d548a562fe88b7d3f0c229789e8195a5baadae7060a8491562e", 6},
	// #4249 row 5706695827: the orchestrator's two request routes are their own
	// enforcement scope, orchestrator_request, so llm.completion and agent.invoke
	// each state one scope more. Unlike 6 this is edition-independent, so BOTH
	// welded digests move; the version is also what a published document pins and
	// what the pre-split compatibility rule compares against
	// (legacycompile.RouteSeamSplitCatalogVersion).
	{"sha256:8c8262fe1b433110cc2f75333eff560f530eb8674071d5591c547fa9dfe228c2", "sha256:e8466d4ef51c3ea1f71ac9d9f0ce6506545071cc104a9f89268e35ed1a7dd66d", 7},
}

// weldModes are the deployment modes the weld resolves under, one per plane
// edition, whatever the test process's own DEPLOYMENT_MODE.
var weldModes = []struct{ edition, mode string }{{"community", "community"}, {"enterprise", "in-vpc-enterprise"}}

// resolveWeld resolves weldDeployment under mode.
func resolveWeld(t *testing.T, mode string) *authoringcatalog.Snapshot {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", mode)
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, weldDeployment())
	if err != nil || snap == nil {
		t.Fatalf("the deployment vocabulary must resolve under DEPLOYMENT_MODE=%s: %v", mode, err)
	}
	return snap
}

// weldDeployment is a FIXED deployment description, so the digest below is a
// function of the vocabulary alone.
//
// The realm set is deployment-derived, so a digest pinned against "whatever
// this machine resolves" would move with the machine and pin nothing. Fixing
// the input is what makes the pin a statement about the CATALOG.
func weldDeployment() authoringvocabulary.CatalogDeployment {
	return authoringvocabulary.CatalogDeployment{HasDirectory: true, HasRevocation: false, HasCAEP: false, HasOIDC: true}
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
	welded := map[string]string{"community": weldedCommunityDigest, "enterprise": weldedEnterpriseDigest}
	last := weldHistory[len(weldHistory)-1]
	recorded := map[string]string{"community": last.community, "enterprise": last.enterprise}
	var snap *authoringcatalog.Snapshot
	for _, m := range weldModes {
		got := resolveWeld(t, m.mode)
		if got.RegistryVersion != authoringcatalog.DeploymentCatalogVersion {
			t.Fatalf("%s: the snapshot carries registry version %d and the constant is %d",
				m.edition, got.RegistryVersion, authoringcatalog.DeploymentCatalogVersion)
		}
		if got.Digest != welded[m.edition] {
			t.Fatalf("THE %s DEPLOYMENT VOCABULARY'S CONTENT CHANGED.\n"+
				"  digest now: %s\n"+
				"  pinned:     %s\n"+
				"  version:    %d\n\n"+
				"The vocabulary's actions, realms or resource types are not what they were. That is allowed - it is "+
				"not allowed to happen QUIETLY, because contract.Snapshot.RegistryVersion travels into every decision "+
				"and every proof binding as the answer to \"which vocabulary decided this\".\n\n"+
				"Record the new pair in weldHistory, update the welded digests AND bump "+
				"authoringcatalog.DeploymentCatalogVersion, in this commit, together.",
				m.edition, got.Digest, welded[m.edition], got.RegistryVersion)
		}
		// THE VERSION MOVED WITH THE DIGEST: recorded, and the constant the
		// wire carries.
		if recorded[m.edition] != welded[m.edition] {
			t.Fatalf("the welded %s digest %s is not the one weldHistory's last entry records (%s); record it against the version it ships under",
				m.edition, welded[m.edition], recorded[m.edition])
		}
		if m.edition == "community" {
			snap = got
		}
	}
	if last.version != authoringcatalog.DeploymentCatalogVersion {
		t.Fatalf("the welded digests are recorded at version %d and authoringcatalog.DeploymentCatalogVersion is %d. "+
			"Two different vocabularies must never wear the same number: bump the constant with the digest.",
			last.version, authoringcatalog.DeploymentCatalogVersion)
	}
	if weldHistory[0].version != 2 {
		t.Fatalf("weldHistory starts at version %d; the weld first pinned version 2", weldHistory[0].version)
	}
	seen := map[string]bool{}
	for i, h := range weldHistory {
		// Both directions: a pair recorded twice is either a version bumped
		// with content nobody changed, or one content wearing two numbers.
		pair := h.community + "|" + h.enterprise
		if seen[pair] {
			t.Fatalf("weldHistory records the pair %s twice; a version advances only when some edition's content does", pair)
		}
		seen[pair] = true
		if i > 0 && h.version != weldHistory[i-1].version+1 {
			t.Fatalf("weldHistory records version %d after %d; a content change is exactly the next version, one entry each", h.version, weldHistory[i-1].version)
		}
	}

	// THE PIN IS OVER CONTENT, and this is what says so: the same content
	// resolved twice is the same digest, and a changed realm set is not. Read
	// under the Community mode, as snap was.
	t.Setenv("DEPLOYMENT_MODE", "community")
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
	// And the realm set itself (#4249): the fixture must SEE the `oidc` realm,
	// or the pin says nothing about whether it is declared.
	noOIDC := weldDeployment()
	noOIDC.HasOIDC = false
	withoutRealm, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, noOIDC)
	if err != nil {
		t.Fatal(err)
	}
	if withoutRealm.Digest == snap.Digest {
		t.Fatal("the fixture with and without the OIDC source resolved to the SAME digest; either the fixture does not " +
			"wire the OIDC source or the realm set is not reaching the digest, and either way this pin cannot see it")
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
