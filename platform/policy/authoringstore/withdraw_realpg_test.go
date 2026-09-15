// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// WITHDRAWAL ON REAL POSTGRES (PRD v11 §1.15). The durable ActiveTip reads a
// withdrawal as nothing active while its sequence still advances the policy
// epoch; the compare-and-set keeps reading the RAW tip, so an append that still
// believes nothing was ever activated is refused as raced; and a promotion
// chains onto the withdrawal, which the audit trail records in the same
// transaction.
func TestAWithdrawalIsReadAsNothingActiveAndTheChainContinues_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	org := pdp.RootOrganization
	s := h.storeFor(t, orgA)
	art := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := s.PutArtifact(ctx, org, art); err != nil {
		t.Fatal(err)
	}
	template, err := pdp.SystemCorpusOrganizationTemplateDigest()
	if err != nil {
		t.Fatal(err)
	}
	bob := contract.MustParseID(contract.KindPrincipal, "User::portal:bob@example.com")
	promote := authoring.Activation{
		Kind: authoring.ActivationPromote, Root: org, Digest: art.Digest(),
		DocumentID: art.Provenance().DocumentID, DocumentVersion: 1,
		Actor: bob, At: time.Unix(1_700_000_300, 0).UTC(),
	}
	if err := s.AppendActivation(ctx, org, promote, ""); err != nil {
		t.Fatal(err)
	}
	withdraw := authoring.Activation{
		Kind: authoring.ActivationWithdraw, Root: org, Digest: template, PreviousDigest: art.Digest(),
		DocumentID: pdp.SystemCorpusOrganizationTemplateID, DocumentVersion: 1,
		Actor: bob, At: time.Unix(1_700_000_400, 0).UTC(), Reason: "back to the shipped set",
	}
	if err := s.AppendActivation(ctx, org, withdraw, art.Digest()); err != nil {
		t.Fatalf("appending a withdrawal was refused: %v", err)
	}

	if digest, seq, err := s.ActiveTip(ctx, org); err != nil || digest != "" || seq != 2 {
		t.Fatalf("ActiveTip after a withdrawal = (%q, %d, %v); want nothing active at sequence 2", digest, seq, err)
	}
	if digest, err := s.ActiveDigest(ctx, org); err != nil || digest != "" {
		t.Fatalf("ActiveDigest after a withdrawal = %q (%v); want nothing active", digest, err)
	}

	// THE RAW TIP: an append that still believes nothing was ever activated is
	// raced, because the ledger's tip is the withdrawal and not empty.
	stale := promote
	if err := s.AppendActivation(ctx, org, stale, ""); !errors.Is(err, authoring.ErrActivationRaced) {
		t.Fatalf("an append expecting an empty ledger after a withdrawal returned %v; it must be ErrActivationRaced", err)
	}
	again := promote
	again.PreviousDigest, again.At = template, time.Unix(1_700_000_500, 0).UTC()
	if err := s.AppendActivation(ctx, org, again, template); err != nil {
		t.Fatalf("a promotion chained onto the withdrawal was refused: %v", err)
	}
	if digest, seq, err := s.ActiveTip(ctx, org); err != nil || digest != art.Digest() || seq != 3 {
		t.Fatalf("ActiveTip after the promotion = (%q, %d, %v); want %s at sequence 3", digest, seq, err, art.Digest())
	}

	history, err := s.Activations(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 3 || history[1].Kind != authoring.ActivationWithdraw || history[1].Reason != "back to the shipped set" ||
		history[2].PreviousDigest != template {
		t.Fatalf("history %+v; want promote, the withdrawal with its reason, and a promotion chained onto it", history)
	}
	trail, err := s.AuditTrail(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	var withdrawals int
	for _, e := range trail {
		if e.Action == authoring.AuditWithdraw {
			withdrawals++
			if e.Digest != template || e.PreviousDigest != art.Digest() || e.Reason != "back to the shipped set" {
				t.Fatalf("the withdrawal's audit row is %+v; want the template's digest, withdrawing %s, with its reason", e, art.Digest())
			}
		}
	}
	if withdrawals != 1 {
		t.Fatalf("the audit trail holds %d withdraw rows; the append must record exactly one", withdrawals)
	}
}
