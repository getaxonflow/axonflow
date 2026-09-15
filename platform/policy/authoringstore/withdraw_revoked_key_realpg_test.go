// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// A DOCUMENT WHOSE SIGNING KEY WAS REVOKED CAN STILL BE WITHDRAWN (#4299).
//
// This backend re-verifies an artifact on every load, so after a revocation the
// active document no longer loads - and the anchored enforcer then fails closed
// on every decision of that organization. Withdrawing it is the exit, and the
// actor rule must still hold on the way out. The in-process store cannot show
// either: it never re-verifies. So these run against real Postgres.

var (
	revokedAuthor   = contract.MustParseID(contract.KindPrincipal, "User::portal:alice@example.com")
	revokedApprover = contract.MustParseID(contract.KindPrincipal, "User::portal:bob@example.com")
)

// revokedKeyStore admits and promotes one document signed by the harness key,
// revokes that key, and returns an authoring store built from the trust loaded
// AFTER the revocation, the durable backend beneath it, and the document.
func revokedKeyStore(t *testing.T) (*authoring.Store, *Store, *authoring.Artifact) {
	t.Helper()
	h := setup(t)
	ctx := context.Background()
	root := pdp.RootOrganization
	keys := h.storeFor(t, orgA)
	if err := keys.AuthorizeKey(ctx, root, h.keyID, h.pub, "test"); err != nil {
		t.Fatal(err)
	}
	trust, err := keys.LoadTrust(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	durable, err := New(h.appRoleDB, orgA, authoring.StaticTrust(trust))
	if err != nil {
		t.Fatal(err)
	}
	st, err := authoring.NewStoreWithBackend(authoring.StaticTrust(trust), mustEnterpriseProfile(t), durable)
	if err != nil {
		t.Fatal(err)
	}
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := st.Admit(ctx, art); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Promote(ctx, root, art.Digest(), revokedApprover, time.Unix(1_700_000_200, 0).UTC(), "rollout"); err != nil {
		t.Fatal(err)
	}
	if err := keys.RevokeKey(ctx, root, h.keyID, "compromise drill"); err != nil {
		t.Fatal(err)
	}
	after, err := keys.LoadTrust(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	durableAfter, err := New(h.appRoleDB, orgA, authoring.StaticTrust(after))
	if err != nil {
		t.Fatal(err)
	}
	// THE PREMISE, asserted rather than assumed: after the revocation the active
	// document really does not load. Without it both tests would pass on a store
	// that never re-verified, and prove nothing.
	if _, _, err := durableAfter.GetArtifact(ctx, root, art.Digest()); !errors.Is(err, ErrArtifactUnverifiable) {
		t.Fatalf("premise: the revoked-key document loaded, or failed otherwise (%v); want ErrArtifactUnverifiable", err)
	}
	stAfter, err := authoring.NewStoreWithBackend(authoring.StaticTrust(after), mustEnterpriseProfile(t), durableAfter)
	if err != nil {
		t.Fatal(err)
	}
	return stAfter, durableAfter, art
}

// The escape B closed, reopened: the approver withdraws a document whose
// signing key was revoked, and nothing is active afterwards.
func TestARevokedKeyDocumentIsWithdrawnByTheApprover_RealPG(t *testing.T) {
	st, durable, art := revokedKeyStore(t)
	ctx := context.Background()
	root := pdp.RootOrganization
	if active, err := durable.ActiveDigest(ctx, root); err != nil || active != art.Digest() {
		t.Fatalf("before the withdrawal the active digest is %q (%v); want %s", active, err, art.Digest())
	}
	if _, err := st.Withdraw(ctx, root, revokedApprover, time.Unix(1_700_000_300, 0).UTC(), "the signing key was revoked"); err != nil {
		t.Fatalf("the approver could not withdraw a document whose signing key was revoked: %v", err)
	}
	if active, err := durable.ActiveDigest(ctx, root); err != nil || active != "" {
		t.Fatalf("after the withdrawal the active digest is %q (%v); want nothing active", active, err)
	}
}

// No revoked key buys the author a bypass: on that same document the author's
// withdrawal is still refused - by the ACTOR RULE, read from the admission
// record, not by the artifact's failure to load.
func TestTheAuthorCannotWithdrawARevokedKeyDocument_RealPG(t *testing.T) {
	st, durable, art := revokedKeyStore(t)
	ctx := context.Background()
	root := pdp.RootOrganization
	_, err := st.Withdraw(ctx, root, revokedAuthor, time.Unix(1_700_000_300, 0).UTC(), "the author withdraws alone")
	if err == nil || !strings.Contains(err.Error(), "separation of author and approver duties") {
		t.Fatalf("the author's withdrawal of a revoked-key document answered %v; want the actor rule", err)
	}
	if errors.Is(err, ErrArtifactUnverifiable) {
		t.Fatalf("the refusal is the artifact's failure to load (%v), not the actor rule", err)
	}
	if active, err := durable.ActiveDigest(ctx, root); err != nil || active != art.Digest() {
		t.Fatalf("a refused withdrawal changed what is active: %q (%v)", active, err)
	}
}
