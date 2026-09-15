// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/decision/pdp"
)

// failingGetBackend is the in-process backend whose artifact read fails, as a
// durable store's does when its database cannot be reached.
type failingGetBackend struct {
	Backend
	err error
}

func (b failingGetBackend) GetArtifact(context.Context, pdp.Root, string) (*Artifact, bool, error) {
	return nil, false, b.err
}

// RENDERDIGEST AND DIFF TELL THE STORE APART (#4271). The portal's
// artifact-source route answers a digest the store does not hold 404 and a
// store it could not read as a store refusal, and its diff route answers a
// candidate's own error 422 and an unreadable active document as a store
// refusal. It can do that only if these return different errors.
func TestRenderDigestAndDiffTellTheStoreApart(t *testing.T) {
	trust, _ := organizationTrust(t)
	build := func(t *testing.T, b Backend) *API {
		t.Helper()
		api, err := NewAPIWithBackend(baseCatalog(t), StaticTrust(trust), mustProfile(t, EditionEnterprise), b)
		if err != nil {
			t.Fatal(err)
		}
		return api
	}
	storeErr := errors.New("the database could not be reached (planted-4271)")

	t.Run("a digest the store does not hold is ErrNotAdmitted", func(t *testing.T) {
		_, err := build(t, NewMemoryBackend()).RenderDigest(context.Background(), pdp.RootOrganization, "sha256:planted-4271-absent")
		if !errors.Is(err, ErrNotAdmitted) {
			t.Fatalf("RenderDigest on a digest the store does not hold returned %v; want ErrNotAdmitted", err)
		}
	})

	t.Run("a store that could not be read is its own error, never ErrNotAdmitted", func(t *testing.T) {
		_, err := build(t, failingGetBackend{Backend: NewMemoryBackend(), err: storeErr}).RenderDigest(context.Background(), pdp.RootOrganization, "sha256:planted-4271-absent")
		if !errors.Is(err, storeErr) {
			t.Fatalf("RenderDigest returned %v; want the store's own error, wrapped", err)
		}
		if errors.Is(err, ErrNotAdmitted) {
			t.Fatalf("RenderDigest reported a failed read as not admitted: %v", err)
		}
	})

	t.Run("an unreadable active document is ErrActiveUnavailable, carrying the store's error", func(t *testing.T) {
		candidate := &Document{Policy: pdp.Document{Root: pdp.RootOrganization}}
		_, err := build(t, failingActiveBackend{Backend: NewMemoryBackend(), err: storeErr}).Diff(context.Background(), candidate)
		if !errors.Is(err, ErrActiveUnavailable) || !errors.Is(err, storeErr) {
			t.Fatalf("Diff returned %v; want ErrActiveUnavailable wrapping the store's own error", err)
		}
	})

	t.Run("the candidate's own error is not ErrActiveUnavailable", func(t *testing.T) {
		_, err := build(t, NewMemoryBackend()).Diff(context.Background(), nil)
		if err == nil || errors.Is(err, ErrActiveUnavailable) {
			t.Fatalf("Diff of a nil candidate returned %v; want an error that is not ErrActiveUnavailable", err)
		}
	})
}
