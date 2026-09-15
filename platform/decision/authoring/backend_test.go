// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"testing"
	"time"

	"axonflow/platform/decision/pdp"
)

// The Backend seam, tested through the in-process implementation.
//
// The DURABLE implementation is platform/policy/authoringstore and is
// tested against a real Postgres there. What is tested HERE is the contract
// both must satisfy, and in particular the two properties a durable store
// cannot be trusted to reinvent: that the active digest is DERIVED from the
// activation history rather than stored beside it, and that an append refuses
// when the tip has moved.

func memStore(t *testing.T) (*Store, *Artifact, *Store) {
	t.Helper()
	art, trust, _ := mustPublish(t)
	s, err := NewStore(StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	// A SECOND store over the SAME backend models a second replica. Two
	// processes sharing a database is the whole reason expectPrev exists, and
	// a test using one store could not tell a compare-and-set from a mutex.
	backend := s.backend
	other, err := NewStoreWithBackend(StaticTrust(trust), mustProfile(t, EditionEnterprise), backend)
	if err != nil {
		t.Fatal(err)
	}
	return s, art, other
}

func TestNewStoreDefaultsToTheInProcessBackend(t *testing.T) {
	_, trust, _ := mustPublish(t)
	s, err := NewStore(StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	if s.backend == nil {
		t.Fatal("a store built without a backend has none, so every operation would nil-panic")
	}
	if _, err := NewStoreWithBackend(nil, mustProfile(t, EditionEnterprise), NewMemoryBackend()); err == nil {
		t.Fatal("a store was built with no trust store; an artifact that nothing verified is not an artifact")
	}
}

func TestTheActiveDigestIsDerivedFromTheActivationHistory(t *testing.T) {
	ctx := context.Background()
	s, art, _ := memStore(t)
	if err := s.Admit(ctx, art); err != nil {
		t.Fatal(err)
	}

	// Nothing activated: no active digest, and no history. The two must agree,
	// because they are the same fact read two ways.
	if _, ok, err := s.Active(ctx, art.Root()); err != nil || ok {
		t.Fatalf("Active before any promotion: ok=%t err=%v", ok, err)
	}
	h, err := s.History(ctx, art.Root())
	if err != nil || len(h) != 0 {
		t.Fatalf("History before any promotion: %d entries, err=%v", len(h), err)
	}

	if _, err := s.Promote(ctx, art.Root(), art.Digest(), pid(t, principalBob), timeFixture(), "rollout"); err != nil {
		t.Fatal(err)
	}
	active, ok, err := s.Active(ctx, art.Root())
	if err != nil || !ok || active.Digest() != art.Digest() {
		t.Fatalf("after promotion Active = %v ok=%t err=%v", active, ok, err)
	}
	h, err = s.History(ctx, art.Root())
	if err != nil || len(h) != 1 || h[0].Digest != art.Digest() {
		t.Fatalf("after promotion History = %+v err=%v", h, err)
	}
	// THE DERIVATION, ASSERTED. The last history entry IS the active digest;
	// a backend keeping a separate pointer would pass the two checks above and
	// fail this one the first time the two drifted.
	tip, err := s.backend.ActiveDigest(ctx, art.Root())
	if err != nil || tip != h[len(h)-1].Digest {
		t.Fatalf("ActiveDigest = %q and the last activation names %q", tip, h[len(h)-1].Digest)
	}
}

// TestAppendActivationRefusesWhenTheTipMoved is the compare-and-set.
//
// Two stores over one backend model two replicas. Both read the same tip; one
// appends; the other's append must be refused with ErrActivationRaced rather
// than silently overwriting the first replica's activation.
func TestAppendActivationRefusesWhenTheTipMoved(t *testing.T) {
	ctx := context.Background()
	s, art, other := memStore(t)
	if err := s.Admit(ctx, art); err != nil {
		t.Fatal(err)
	}

	// Both replicas observe an empty root.
	tipA, err := s.backend.ActiveDigest(ctx, art.Root())
	if err != nil {
		t.Fatal(err)
	}
	tipB, err := other.backend.ActiveDigest(ctx, art.Root())
	if err != nil {
		t.Fatal(err)
	}
	if tipA != "" || tipB != "" {
		t.Fatalf("both replicas should see an empty root, got %q and %q", tipA, tipB)
	}

	act := Activation{
		Kind: ActivationPromote, Root: art.Root(), Digest: art.Digest(),
		DocumentID: art.Provenance().DocumentID, DocumentVersion: art.Provenance().DocumentVersion,
		Actor: pid(t, principalBob), At: timeFixture(),
	}
	if err := s.backend.AppendActivation(ctx, art.Root(), act, tipA); err != nil {
		t.Fatalf("the first replica's append must succeed: %v", err)
	}
	err = other.backend.AppendActivation(ctx, art.Root(), act, tipB)
	if !errors.Is(err, ErrActivationRaced) {
		t.Fatalf("the second replica's append returned %v; it must be ErrActivationRaced, or two replicas can each promote over the same parent and both believe they won", err)
	}

	// NEGATIVE CONTROL: the same append with the CORRECT tip succeeds, so the
	// refusal above is about the stale parent and not about the append path
	// being broken.
	second := act
	second.PreviousDigest = art.Digest()
	if err := other.backend.AppendActivation(ctx, art.Root(), second, art.Digest()); err != nil {
		t.Fatalf("an append with the current tip was refused, so the race assertion proves nothing: %v", err)
	}
}

func TestBySourceDigestIsStableAcrossRepublication(t *testing.T) {
	ctx := context.Background()
	trust, priv := systemTrust(t)
	s, err := NewStore(StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	d := baseDocument(t)
	cat := baseCatalog(t)

	opts := publishOptions(t, priv)
	first, _, err := Publish(ctx, d, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	// The SAME document at a LATER instant. An artifact digest covers the
	// publication timestamp, so this is a different artifact carrying an
	// identical document - which is exactly the state an idempotent importer
	// has to recognise.
	opts.Now = opts.Now.Add(time.Hour)
	second, _, err := Publish(ctx, d, cat, opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() == second.Digest() {
		t.Fatal("republishing at a later instant produced the same artifact digest; this test's premise is wrong")
	}
	if first.Provenance().SourceDigest != second.Provenance().SourceDigest {
		t.Fatal("the source digest moved with the timestamp, so it is not the stable key it is used as")
	}

	if err := s.Admit(ctx, first); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.BySourceDigest(ctx, first.Root(), second.Provenance().SourceDigest)
	if err != nil || !ok {
		t.Fatalf("the second publication's source digest did not resolve to the first artifact: ok=%t err=%v", ok, err)
	}
	if got.Digest() != first.Digest() {
		t.Fatalf("BySourceDigest returned %s, want the admitted %s", got.Digest(), first.Digest())
	}

	if _, ok, err := s.BySourceDigest(ctx, first.Root(), ""); err != nil || ok {
		t.Fatalf("an empty source digest resolved to something: ok=%t err=%v", ok, err)
	}
	if _, ok, err := s.BySourceDigest(ctx, first.Root(), "sha256:nothing"); err != nil || ok {
		t.Fatalf("an unknown source digest resolved to something: ok=%t err=%v", ok, err)
	}
}

func TestCountAndListReportWhatTheStoreHolds(t *testing.T) {
	ctx := context.Background()
	s, art, _ := memStore(t)

	if n, err := s.Count(ctx, art.Root()); err != nil || n != 0 {
		t.Fatalf("an empty store counts %d (err %v)", n, err)
	}
	if err := s.Admit(ctx, art); err != nil {
		t.Fatal(err)
	}
	// Re-admitting the SAME artifact is idempotent, so the count does not move.
	if err := s.Admit(ctx, art); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Count(ctx, art.Root()); err != nil || n != 1 {
		t.Fatalf("after admitting one artifact twice the store counts %d (err %v)", n, err)
	}

	list, err := s.List(ctx, art.Root(), 0)
	if err != nil || len(list) != 1 || list[0].Digest() != art.Digest() {
		t.Fatalf("List = %+v err=%v", list, err)
	}
	if capped, err := s.List(ctx, art.Root(), 1); err != nil || len(capped) != 1 {
		t.Fatalf("a limit of 1 returned %d (err %v)", len(capped), err)
	}
}

// TestListIsOrderedByVersionDescending pins the ORDER, not merely the
// membership. Map iteration is randomised, so an unsorted implementation would
// present an operator a different list on every request while passing any
// assertion about which artifacts are in it.
func TestListIsOrderedByVersionDescending(t *testing.T) {
	ctx := context.Background()
	trust, priv := systemTrust(t)
	s, err := NewStore(StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	cat := baseCatalog(t)
	for v := 1; v <= 4; v++ {
		d := documentWith(t, cat, func(m *Metadata, doc *pdp.Document) { doc.Version = v })
		art, _, err := Publish(ctx, d, cat, publishOptions(t, priv))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Admit(ctx, art); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List(ctx, pdp.RootSystem, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 4 {
		t.Fatalf("expected 4 artifacts, got %d", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Provenance().DocumentVersion < list[i].Provenance().DocumentVersion {
			t.Fatalf("version %d preceded version %d; the listing must be newest first",
				list[i-1].Provenance().DocumentVersion, list[i].Provenance().DocumentVersion)
		}
	}
	if list[0].Provenance().DocumentVersion != 4 {
		t.Fatalf("the newest listed version is %d, want 4", list[0].Provenance().DocumentVersion)
	}
}
