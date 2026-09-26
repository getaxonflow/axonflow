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

// A READ OF THE ACTIVE DOCUMENT IS NEVER "NOTHING ACTIVE" WHEN THE STORE HAS
// LOST IT (#4249 row 5797853828). The ledger names an active digest the store
// does not hold: Active, and Render and Diff through it, answer the store's
// failure, never an absence, because every reader of "nothing active" (the
// active document, the compliance effects, a diff against the baseline)
// would otherwise report the organization's own controls as absent.
func TestAReadOfTheActiveDocumentTheStoreLostIsTheStoresFailure(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	api, art := publishedAPI(t, false)
	api.store.backend = pinLoadBackend{Backend: api.store.backend, active: pinLoadGhost}

	t.Run("Active", func(t *testing.T) {
		got, found, err := api.Store().Active(ctx, org)
		if !errors.Is(err, ErrStoreUnavailable) || got != nil || found {
			t.Fatalf("Active answered (%v, %v, %v); want the store's failure", got, found, err)
		}
		if !strings.Contains(err.Error(), "the active digest "+pinLoadGhost) {
			t.Fatalf("the failure does not name the missing digest: %v", err)
		}
	})
	t.Run("Render", func(t *testing.T) {
		_, err := api.Render(ctx, org)
		if !errors.Is(err, ErrStoreUnavailable) || errors.Is(err, ErrNothingActive) {
			t.Fatalf("Render answered %v; want the store's failure, never ErrNothingActive", err)
		}
	})
	t.Run("Diff", func(t *testing.T) {
		doc, err := art.Document()
		if err != nil {
			t.Fatal(err)
		}
		_, err = api.Diff(ctx, doc)
		if !errors.Is(err, ErrActiveUnavailable) || !errors.Is(err, ErrStoreUnavailable) {
			t.Fatalf("Diff answered %v; want ErrActiveUnavailable marked as the store's failure", err)
		}
	})
	t.Run("control: nothing active is still nothing active", func(t *testing.T) {
		fresh, _ := publishedAPI(t, false)
		if got, found, err := fresh.Store().Active(ctx, org); err != nil || found || got != nil {
			t.Fatalf("an organization with nothing active answered (%v, %v, %v)", got, found, err)
		}
		if _, err := fresh.Render(ctx, org); !errors.Is(err, ErrNothingActive) {
			t.Fatalf("Render with nothing active answered %v; want ErrNothingActive", err)
		}
	})
}
