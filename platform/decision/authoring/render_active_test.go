// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/decision/pdp"
)

// failingActiveBackend is the in-process backend whose active-digest read
// fails, as a durable store's does when its database cannot be reached.
type failingActiveBackend struct {
	Backend
	err error
}

func (b failingActiveBackend) ActiveDigest(context.Context, pdp.Root) (string, error) {
	return "", b.err
}

// RENDER TELLS "NOTHING ACTIVE" FROM "THE STORE COULD NOT BE READ" (#4255). The
// typed-authoring route answers the first 404 and the second 503, and it can do
// that only if Render returns them as different errors: the sentinel for a root
// the store holds nothing active on, and the store's own error, wrapped, for a
// read that failed.
func TestRenderTellsNothingActiveFromAStoreThatCouldNotBeRead(t *testing.T) {
	trust, _ := organizationTrust(t)
	build := func(t *testing.T, b Backend) *API {
		t.Helper()
		api, err := NewAPIWithBackend(baseCatalog(t), StaticTrust(trust), mustProfile(t, EditionEnterprise), b)
		if err != nil {
			t.Fatal(err)
		}
		return api
	}

	t.Run("a root with nothing active is ErrNothingActive", func(t *testing.T) {
		_, err := build(t, NewMemoryBackend()).Render(context.Background(), pdp.RootOrganization)
		if !errors.Is(err, ErrNothingActive) {
			t.Fatalf("Render on a root with nothing active returned %v; want ErrNothingActive", err)
		}
	})

	t.Run("a store that could not be read is its own error, never ErrNothingActive", func(t *testing.T) {
		storeErr := errors.New("the database could not be reached")
		api := build(t, failingActiveBackend{Backend: NewMemoryBackend(), err: storeErr})
		_, err := api.Render(context.Background(), pdp.RootOrganization)
		if !errors.Is(err, storeErr) {
			t.Fatalf("Render returned %v; want the store's own error, wrapped", err)
		}
		if errors.Is(err, ErrNothingActive) {
			t.Fatalf("Render reported a failed read as nothing active: %v", err)
		}
	})
}
