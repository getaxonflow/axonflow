// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// A replica that started BEFORE another process authorized its signing key
// must still be able to serve the organization.
//
// Every read path re-verifies against the trust store the process holds, so a
// key authorized afterwards - by a second portal replica, by the orchestrator's
// community route, or by one `axonflow-policy-import -write` run - is not in
// it. The consequence is not a missing row: authoring.LoadArtifact returns an
// ERROR, which the store reports as "a stored artifact did not verify on load"
// and the portal answers as 500. The organization's own policy history becomes
// unreadable on that replica while another replica serves it fine.
//
// WHAT THE EXISTING COVERAGE DOES NOT REACH.
// TestASecondProcessReadsWhatTheFirstPublished_RealPG builds its second store
// AFTER the publish, so its LoadTrust already contains the key - the ordering
// that works. This is the ordering the durable store exists for and the one
// nothing exercised: the reader was constructed FIRST.
func TestAReplicaVerifiesAKeyAuthorizedAfterItStarted_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	const root = pdp.RootOrganization

	// --- Replica A opens first, exactly as a portal workspace does ----------
	storeA, trustA, keyIDA, err := OpenForSigning(ctx, h.appRoleDB, root, orgA, "replica-a", h.pub, "replica-a")
	if err != nil {
		t.Fatalf("replica A could not open its durable store: %v", err)
	}

	// A publishes one artifact of its own, signed as A, so the assertions
	// below cannot pass vacuously on an empty root.
	hA := *h
	hA.keyID = keyIDA
	artA := hA.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := storeA.PutArtifact(ctx, root, artA); err != nil {
		t.Fatal(err)
	}

	// --- Replica B starts LATER with a key of its own ----------------------
	//
	// Each process signs as itself and records the public half; that is the
	// whole design of the signing chain, and it is what makes A's snapshot
	// stale the moment B authorizes.
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	storeB, _, keyIDB, err := OpenForSigning(ctx, h.appRoleDB, root, orgA, "replica-b", pubB, "replica-b")
	if err != nil {
		t.Fatalf("replica B could not open its durable store: %v", err)
	}
	hB := *h
	hB.keyID, hB.pub, hB.priv = keyIDB, pubB, privB
	artB := hB.publish(t, 2, time.Unix(1_700_000_200, 0).UTC())
	if err := storeB.PutArtifact(ctx, root, artB); err != nil {
		t.Fatal(err)
	}

	// PRECONDITIONS, asserted rather than assumed. Without these a green run
	// could mean "B never used its own key" or "A already knew it", either of
	// which would make the whole test vacuous.
	if artB.KeyID() != keyIDB {
		t.Fatalf("replica B's artifact is signed by %q, want %q", artB.KeyID(), keyIDB)
	}
	if keyIDA == keyIDB {
		t.Fatalf("both replicas derived the same key identifier %q; the ordering under test cannot arise", keyIDA)
	}
	if _, known := trustA.Current().PublicKey(root, keyIDB); known {
		t.Fatalf("replica A already carries %q, so this test is not exercising the ordering it exists for", keyIDB)
	}

	// --- Replica A, still running, must still serve the organization -------

	t.Run("the artifact listing does not become an error", func(t *testing.T) {
		list, err := storeA.ListArtifacts(ctx, root, 0)
		if err != nil {
			t.Fatalf("ListArtifacts on the replica that started first: %v\n\n"+
				"This is the portal answering 500 \"the artifact list is unavailable\". Another process "+
				"authorized a key and published; this replica verified against the set it loaded at open "+
				"and failed the WHOLE listing rather than the one row.", err)
		}
		if len(list) != 2 {
			t.Fatalf("ListArtifacts returned %d artifacts, want 2 (one from each replica)", len(list))
		}
	})

	t.Run("the other replica's artifact is retrievable by digest", func(t *testing.T) {
		got, found, err := storeA.GetArtifact(ctx, root, artB.Digest())
		if err != nil {
			t.Fatalf("GetArtifact for the other replica's digest: %v", err)
		}
		if !found || got.Digest() != artB.Digest() {
			t.Fatalf("GetArtifact: found=%t", found)
		}
	})

	// PROMOTE, because the listing and the fetch are only two of the three
	// surfaces the snapshot broke. Promote re-verifies through the same read
	// path, so a replica that could not verify B's key could not activate B's
	// version either.
	//
	// THE ASSERTION IS NARROW ON PURPOSE. Activation carries several other
	// rules - the actor must not be the author, the version must advance, the
	// parent must be the active digest - and each has its own test in this
	// package. What A changes is whether Promote can get PAST VERIFICATION, so
	// that is what is asserted: it must not fail as an unauthorized key. An
	// assertion that tolerated any error would pass on a store that still
	// could not verify anything.
	t.Run("promote gets past verification for the other replica's artifact", func(t *testing.T) {
		plane, err := authoring.NewStoreWithBackend(trustA, mustEnterpriseProfile(t), storeA)
		if err != nil {
			t.Fatal(err)
		}
		// THE ACTOR IS AN APPROVER OF THE VERSION, and the author is not the
		// actor - the two rules activation applies besides verification. The
		// harness publishes with alice as author and bob as the sole approver,
		// so bob is the one principal who can activate this version. Naming
		// anyone else would leave the assertion below satisfied by an approver
		// refusal rather than by an activation, which is a weaker claim than
		// this test can make.
		actor := contract.MustParseID(contract.KindPrincipal, "User::portal:bob@example.com")
		act, perr := plane.Promote(ctx, root, artB.Digest(), actor, time.Unix(1_700_000_300, 0).UTC(), "multi-replica activation")
		if errors.Is(perr, authoring.ErrKeyNotAuthorized) {
			t.Fatalf("Promote refused the other replica's artifact as an unauthorized key: %v\n\n"+
				"Verification is the surface this fix is about; whatever else activation decides, it must "+
				"not decide that a key another replica authorized does not exist.", perr)
		}
		if perr != nil {
			t.Fatalf("Promote did not complete: %v", perr)
		}
		if act == nil || act.Digest != artB.Digest() {
			t.Fatalf("the activation names %v, want the other replica's digest %s", act, artB.Digest())
		}
		// AND IT IS ACTUALLY ACTIVE - an activation record that nothing reads
		// back would be a weaker claim than the one this test exists to make.
		active, found, aerr := plane.Active(ctx, root)
		if aerr != nil || !found || active.Digest() != artB.Digest() {
			t.Fatalf("after promoting the other replica's artifact the active digest is found=%t err=%v", found, aerr)
		}
	})

	// THE POSITIVE CONTROL. Without it, a store broken for some unrelated
	// reason would satisfy the assertions above by failing them wrongly.
	t.Run("its own artifact still verifies, so the reader is not simply broken", func(t *testing.T) {
		got, found, err := storeA.GetArtifact(ctx, root, artA.Digest())
		if err != nil || !found || got.Digest() != artA.Digest() {
			t.Fatalf("the replica cannot read its OWN artifact: found=%t err=%v", found, err)
		}
	})
}
