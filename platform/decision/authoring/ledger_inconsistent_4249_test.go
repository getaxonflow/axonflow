// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/decision/pdp"
)

// A LOST ACTIVE DOCUMENT IS ErrLedgerInconsistent AND STILL ErrStoreUnavailable
// (#4249 row 5797853828). The ledger names an active digest the store does not
// hold: every reader keeps answering it as the store's failure (the second
// sentinel), and a route can now tell an operator that a retry will not heal
// it (the first). A backend that FAILED is an outage and is not marked
// inconsistent; a candidate the caller named that is missing is the caller's
// refusal and carries neither mark.
func TestALostActiveDocumentIsLedgerInconsistentAndStillTheStores(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	bob := pid(t, principalBob)
	at := timeFixture()

	withBackend := func(t *testing.T, wrap func(Backend) Backend) (*API, *Artifact) {
		t.Helper()
		api, art := publishedAPI(t, false)
		api.store.backend = wrap(api.store.backend)
		return api, art
	}
	ghost := func(b Backend) Backend { return pinLoadBackend{Backend: b, active: pinLoadGhost} }
	ghostFails := func(b Backend) Backend {
		return pinLoadBackend{Backend: b, active: pinLoadGhost, failGet: map[string]bool{pinLoadGhost: true}}
	}

	for _, c := range []struct {
		name            string
		run             func(t *testing.T) error
		store, inconsis bool
	}{
		{"Active, the ledger's digest is not stored", func(t *testing.T) error {
			api, _ := withBackend(t, ghost)
			_, _, err := api.Store().Active(ctx, org)
			return err
		}, true, true},
		{"promote's active document, not stored", func(t *testing.T) error {
			api, art := withBackend(t, ghost)
			_, err := api.Store().Promote(ctx, org, art.Digest(), bob, at, "rollout")
			return err
		}, true, true},
		{"withdraw's fallback, not stored", func(t *testing.T) error {
			api, _ := withBackend(t, ghost)
			_, err := api.Store().Withdraw(ctx, org, bob, at, "drill")
			return err
		}, true, true},
		{"CONTROL: Active, the backend failed reading the ledger's digest", func(t *testing.T) error {
			api, _ := withBackend(t, ghostFails)
			_, _, err := api.Store().Active(ctx, org)
			return err
		}, true, false},
		{"CONTROL: promote's candidate, not admitted", func(t *testing.T) error {
			api, _ := withBackend(t, func(b Backend) Backend { return b })
			_, err := api.Store().Promote(ctx, org, pinLoadUnknown, bob, at, "rollout")
			return err
		}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(t)
			if err == nil {
				t.Fatal("no error")
			}
			if got := errors.Is(err, ErrStoreUnavailable); got != c.store {
				t.Errorf("errors.Is(err, ErrStoreUnavailable) = %t, want %t: %v", got, c.store, err)
			}
			if got := errors.Is(err, ErrLedgerInconsistent); got != c.inconsis {
				t.Errorf("errors.Is(err, ErrLedgerInconsistent) = %t, want %t: %v", got, c.inconsis, err)
			}
		})
	}
}
