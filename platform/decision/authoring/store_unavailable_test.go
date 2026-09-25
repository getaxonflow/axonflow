// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"axonflow/platform/decision/pdp"
)

// A STORE FAILURE IS MARKED, A REFUSAL IS NOT (#4283, #4249 row 5666781792).
// Every backend call a Store makes returns its error as ErrStoreUnavailable,
// beside the cause, so the routes can answer an outage 503 rather than as a
// refusal of the caller's action; a lost activation race and the store's own
// refusals stay unmarked.

var errPlantedBackend = errors.New("pq: connection refused (planted-4283-backend)")

// failingEveryBackend fails every call with err.
type failingEveryBackend struct{ err error }

func (b failingEveryBackend) PutArtifact(context.Context, pdp.Root, *Artifact) error { return b.err }
func (b failingEveryBackend) GetArtifact(context.Context, pdp.Root, string) (*Artifact, bool, error) {
	return nil, false, b.err
}
func (b failingEveryBackend) ArtifactBySourceDigest(context.Context, pdp.Root, string) (*Artifact, bool, error) {
	return nil, false, b.err
}
func (b failingEveryBackend) CountArtifacts(context.Context, pdp.Root) (int, error) { return 0, b.err }
func (b failingEveryBackend) ListArtifacts(context.Context, pdp.Root, int) ([]*Artifact, error) {
	return nil, b.err
}
func (b failingEveryBackend) ActiveDigest(context.Context, pdp.Root) (string, error) {
	return "", b.err
}
func (b failingEveryBackend) AppendActivation(context.Context, pdp.Root, Activation, string) error {
	return b.err
}
func (b failingEveryBackend) Activations(context.Context, pdp.Root) ([]Activation, error) {
	return nil, b.err
}
func (b failingEveryBackend) AuditTrail(context.Context, pdp.Root) ([]AuditEntry, error) {
	return nil, b.err
}

func TestEveryStoreCallMarksABackendFailure(t *testing.T) {
	trust, _ := organizationTrust(t)
	store, err := NewStoreWithBackend(StaticTrust(trust), mustProfile(t, EditionEnterprise), failingEveryBackend{err: errPlantedBackend})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	root := pdp.RootOrganization
	actor := pid(t, "User::axonflow-minted:approver@acme.example")
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

	calls := map[string]func() error{
		"Get":            func() error { _, _, err := store.Get(ctx, root, "sha256:x"); return err },
		"BySourceDigest": func() error { _, _, err := store.BySourceDigest(ctx, root, "sha256:y"); return err },
		"Count":          func() error { _, err := store.Count(ctx, root); return err },
		"List":           func() error { _, err := store.List(ctx, root, 10); return err },
		"Active":         func() error { _, _, err := store.Active(ctx, root); return err },
		"History":        func() error { _, err := store.History(ctx, root); return err },
		"AuditTrail":     func() error { _, err := store.AuditTrail(ctx, root); return err },
		"Promote":        func() error { _, err := store.Promote(ctx, root, "sha256:x", actor, now, "go live"); return err },
		"Rollback":       func() error { _, err := store.Rollback(ctx, root, "sha256:x", actor, now, "back out"); return err },
		"Withdraw":       func() error { _, err := store.Withdraw(ctx, root, actor, now, "drill"); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			if !errors.Is(err, ErrStoreUnavailable) {
				t.Fatalf("%s returned %v; want it marked ErrStoreUnavailable", name, err)
			}
			if !errors.Is(err, errPlantedBackend) {
				t.Fatalf("%s returned %v; want the backend's cause kept beside the mark", name, err)
			}
		})
	}
}

func TestStoreFailureLeavesARaceAndARefusalUnmarked(t *testing.T) {
	raced := fmt.Errorf("%w: another replica first", ErrActivationRaced)
	if got := storeFailure(raced); errors.Is(got, ErrStoreUnavailable) || !errors.Is(got, ErrActivationRaced) {
		t.Fatalf("storeFailure(race) = %v; a lost race is a refusal, not an outage", got)
	}
	if storeFailure(nil) != nil {
		t.Fatal("storeFailure(nil) is not nil")
	}
	once := storeFailure(errPlantedBackend)
	if twice := storeFailure(once); twice != once {
		t.Fatalf("an error already marked was wrapped again: %v", twice)
	}

	// The store's own refusal on a healthy backend is not marked: a digest the
	// store answered for and does not hold.
	trust, _ := organizationTrust(t)
	store, err := NewStoreWithBackend(StaticTrust(trust), mustProfile(t, EditionEnterprise), NewMemoryBackend())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Promote(context.Background(), pdp.RootOrganization, "sha256:never-admitted",
		pid(t, "User::axonflow-minted:approver@acme.example"), time.Now(), "go live")
	if err == nil || errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("promoting a digest the store does not hold returned %v; want the store's refusal, unmarked", err)
	}
}

// A listing's skipped report is not an outage (#4283 item 3): the store passes
// it through unmarked, beside the artifacts that loaded.
func TestAListingsSkippedReportIsNotMarkedAnOutage(t *testing.T) {
	skipped := &ArtifactsSkipped{Skipped: []SkippedArtifact{{Digest: "sha256:x", Reason: "artifact_unverifiable"}}}
	got := storeFailure(skipped)
	var back *ArtifactsSkipped
	if errors.Is(got, ErrStoreUnavailable) || !errors.As(got, &back) || back != skipped {
		t.Fatalf("storeFailure(skipped) = %v; want it unchanged", got)
	}
}
