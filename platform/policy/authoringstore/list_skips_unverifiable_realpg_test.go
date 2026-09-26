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
	"axonflow/platform/decision/pdp"
)

// ONE ARTIFACT THAT DOES NOT VERIFY IS NAMED, NOT THE LIST (#4283 item 3). The
// durable listing failed with the first artifact that did not load; it now
// returns the ones that did and names the rest in *authoring.ArtifactsSkipped.
func TestAListNamesAnArtifactThatDoesNotVerifyAndListsTheRest_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)

	good := h.publish(t, 2, time.Unix(1_700_000_200, 0).UTC())

	// v1 is signed by a key this store's trust does not hold, so it does not
	// verify when the listing loads it.
	origPriv, origKeyID := h.priv, h.keyID
	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h.priv, h.keyID = otherPriv, KeyIDFor("test", orgA, otherPub)
	bad := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	h.priv, h.keyID = origPriv, origKeyID

	for _, a := range []*authoring.Artifact{good, bad} {
		if err := s.PutArtifact(ctx, pdp.RootOrganization, a); err != nil {
			t.Fatal(err)
		}
	}

	list, err := s.ListArtifacts(ctx, pdp.RootOrganization, 0)
	if len(list) != 1 || list[0].Digest() != good.Digest() {
		t.Fatalf("the listing returned %d artifact(s); want exactly the one that verifies (%s)", len(list), good.Digest())
	}
	var skipped *authoring.ArtifactsSkipped
	if !errors.As(err, &skipped) {
		t.Fatalf("the listing returned %v; want *authoring.ArtifactsSkipped naming the artifact that does not verify", err)
	}
	if len(skipped.Skipped) != 1 || skipped.Skipped[0].Digest != bad.Digest() || skipped.Skipped[0].Reason != "artifact_unverifiable" {
		t.Fatalf("skipped = %+v; want %s as artifact_unverifiable", skipped.Skipped, bad.Digest())
	}
	if !errors.Is(skipped.Skipped[0].Err, ErrArtifactUnverifiable) {
		t.Fatalf("the skipped artifact's own error lost its sentinel: %v", skipped.Skipped[0].Err)
	}
}
