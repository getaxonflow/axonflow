// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"strings"
	"testing"

	"axonflow/platform/decision/pdp"
)

// THE ARTIFACT-LOAD BLOCKS, PINNED (#4249 row 5666782153). Five sites load an
// artifact and refuse when it is missing: promote's candidate and its active
// document, rollback's target, withdraw's fallback for an active digest with
// no admission record, and the API's activator. Each is driven to both of its
// failures here, a store failure and a missing artifact, and its exact error
// text and ErrStoreUnavailable marking are pinned, so the change that gives
// them one helper shows in this file's diff exactly which answer moved.

var errPinnedLoadBackend = errors.New("pq: connection reset (planted-artifact-load)")

// pinLoadBackend wraps a real backend. A non-empty active makes ActiveDigest
// answer it, whatever the ledger says; a digest in failGet makes GetArtifact
// fail for it.
type pinLoadBackend struct {
	Backend
	active  string
	failGet map[string]bool
}

func (b pinLoadBackend) ActiveDigest(ctx context.Context, root pdp.Root) (string, error) {
	if b.active != "" {
		return b.active, nil
	}
	return b.Backend.ActiveDigest(ctx, root)
}

func (b pinLoadBackend) GetArtifact(ctx context.Context, root pdp.Root, digest string) (*Artifact, bool, error) {
	if b.failGet[digest] {
		return nil, false, errPinnedLoadBackend
	}
	return b.Backend.GetArtifact(ctx, root, digest)
}

const (
	pinLoadUnknown = "sha256:never-admitted"
	pinLoadGhost   = "sha256:active-but-not-stored"
)

func TestTheArtifactLoadSitesAnswerAsPinned(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	bob := pid(t, principalBob)
	at := timeFixture()
	passActivator := func(context.Context, ActivationKind, *Artifact) error { return nil }

	// withBackend returns a published API whose store reads through wrap.
	withBackend := func(t *testing.T, wrap func(Backend) Backend) (*API, *Artifact) {
		t.Helper()
		api, art := publishedAPI(t, false)
		api.store.backend = wrap(api.store.backend)
		return api, art
	}
	unwrapped := func(b Backend) Backend { return b }

	for _, c := range []struct {
		name       string
		run        func(t *testing.T) error
		want       string
		storeError bool
	}{
		{"promote's candidate, missing", func(t *testing.T) error {
			api, _ := withBackend(t, unwrapped)
			_, err := api.Store().Promote(ctx, org, pinLoadUnknown, bob, at, "rollout")
			return err
		}, `authoring: digest sha256:never-admitted is not admitted under root "organization"; a digest is activated only after it has been verified`, false},
		{"promote's candidate, store failure", func(t *testing.T) error {
			api, _ := withBackend(t, func(b Backend) Backend {
				return pinLoadBackend{Backend: b, failGet: map[string]bool{pinLoadUnknown: true}}
			})
			_, err := api.Store().Promote(ctx, org, pinLoadUnknown, bob, at, "rollout")
			return err
		}, "authoring: the typed-authoring store could not be read or written: pq: connection reset (planted-artifact-load)", true},
		{"promote's active document, missing", func(t *testing.T) error {
			api, art := withBackend(t, func(b Backend) Backend { return pinLoadBackend{Backend: b, active: pinLoadGhost} })
			_, err := api.Store().Promote(ctx, org, art.Digest(), bob, at, "rollout")
			return err
		}, `authoring: the typed-authoring store could not be read or written: authoring: the store's ledger and its artifacts disagree: the active digest sha256:active-but-not-stored for root "organization" is not in the store`, true},
		{"promote's active document, store failure", func(t *testing.T) error {
			api, art := withBackend(t, func(b Backend) Backend {
				return pinLoadBackend{Backend: b, active: pinLoadGhost, failGet: map[string]bool{pinLoadGhost: true}}
			})
			_, err := api.Store().Promote(ctx, org, art.Digest(), bob, at, "rollout")
			return err
		}, "authoring: the typed-authoring store could not be read or written: pq: connection reset (planted-artifact-load)", true},
		{"rollback's target, missing", func(t *testing.T) error {
			api, _ := withBackend(t, unwrapped)
			_, err := api.Store().Rollback(ctx, org, pinLoadUnknown, bob, at, "restore")
			return err
		}, `authoring: digest sha256:never-admitted is not admitted under root "organization"; a digest is activated only after it has been verified`, false},
		{"rollback's target, store failure", func(t *testing.T) error {
			api, _ := withBackend(t, func(b Backend) Backend {
				return pinLoadBackend{Backend: b, failGet: map[string]bool{pinLoadUnknown: true}}
			})
			_, err := api.Store().Rollback(ctx, org, pinLoadUnknown, bob, at, "restore")
			return err
		}, "authoring: the typed-authoring store could not be read or written: pq: connection reset (planted-artifact-load)", true},
		{"withdraw's fallback, missing", func(t *testing.T) error {
			api, _ := withBackend(t, func(b Backend) Backend { return pinLoadBackend{Backend: b, active: pinLoadGhost} })
			_, err := api.Store().Withdraw(ctx, org, bob, at, "drill")
			return err
		}, `authoring: the typed-authoring store could not be read or written: authoring: the store's ledger and its artifacts disagree: the active digest sha256:active-but-not-stored for root "organization" is not in the store`, true},
		{"withdraw's fallback, store failure", func(t *testing.T) error {
			api, _ := withBackend(t, func(b Backend) Backend {
				return pinLoadBackend{Backend: b, active: pinLoadGhost, failGet: map[string]bool{pinLoadGhost: true}}
			})
			_, err := api.Store().Withdraw(ctx, org, bob, at, "drill")
			return err
		}, "authoring: the typed-authoring store could not be read or written: pq: connection reset (planted-artifact-load)", true},
		{"the activator's candidate on promote, missing", func(t *testing.T) error {
			api, _ := withBackend(t, unwrapped)
			_, err := api.WithActivator(passActivator).Promote(ctx, org, pinLoadUnknown, bob, at, "rollout")
			return err
		}, `authoring: digest sha256:never-admitted is not admitted under root "organization"; a digest is activated only after it has been verified`, false},
		{"the activator's candidate on rollback, missing", func(t *testing.T) error {
			api, _ := withBackend(t, unwrapped)
			_, err := api.WithActivator(passActivator).Rollback(ctx, org, pinLoadUnknown, bob, at, "restore")
			return err
		}, `authoring: digest sha256:never-admitted is not admitted under root "organization"; a digest is activated only after it has been verified`, false},
		{"the activator's candidate, store failure", func(t *testing.T) error {
			api, _ := withBackend(t, func(b Backend) Backend {
				return pinLoadBackend{Backend: b, failGet: map[string]bool{pinLoadUnknown: true}}
			})
			_, err := api.WithActivator(passActivator).Promote(ctx, org, pinLoadUnknown, bob, at, "rollout")
			return err
		}, "authoring: the typed-authoring store could not be read or written: pq: connection reset (planted-artifact-load)", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(t)
			if err == nil {
				t.Fatal("the load site answered no error")
			}
			if err.Error() != c.want {
				t.Errorf("error text:\n got  %s\n want %s", err.Error(), c.want)
			}
			if got := errors.Is(err, ErrStoreUnavailable); got != c.storeError {
				t.Errorf("marked ErrStoreUnavailable = %v, want %v", got, c.storeError)
			}
			if c.storeError && strings.Contains(c.want, "planted-artifact-load") && !errors.Is(err, errPinnedLoadBackend) {
				t.Errorf("the store failure does not carry its cause: %v", err)
			}
		})
	}
}
