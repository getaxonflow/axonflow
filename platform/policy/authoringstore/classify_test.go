// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"errors"
	"fmt"
	"testing"

	"axonflow/platform/decision/authoring"
)

// The classification's order is the rule it exists to hold in one place: an
// error the Store marked ErrStoreUnavailable still carries its cause, so an
// outage-marked key-not-loaded is a key-not-loaded, and so on. Each case is
// built the way the Store builds it: "%w: %w" with the mark first.
func TestClassifyStoreFailure(t *testing.T) {
	marked := func(cause error) error { return fmt.Errorf("%w: %w", authoring.ErrStoreUnavailable, cause) }
	for _, c := range []struct {
		name string
		err  error
		want StoreFailure
	}{
		{"a backend error", marked(errors.New("pq: connection reset")), StoreOutage},
		{"an unmarked error", errors.New("dial tcp: refused"), StoreOutage},
		{"a key not loaded, marked as the store's", marked(fmt.Errorf("reading: %w", ErrSigningKeyNotLoaded)), StoreKeyNotLoaded},
		{"an artifact that does not verify, marked", marked(fmt.Errorf("loading: %w", ErrArtifactUnverifiable)), StoreUnverifiable},
		{"a lost active document, marked", marked(fmt.Errorf("%w: the active digest sha256:x is not in the store", authoring.ErrLedgerInconsistent)), StoreLedgerInconsistent},
		// THE ORDER, ASSERTED ONCE (master R3 round 1 on #4439, MEDIUM-1):
		// an error carrying BOTH marks is a key that is not loaded, the
		// retryable answer, on every reader of this rule.
		{"both marks: key not loaded wins over unverifiable", marked(fmt.Errorf("%w; and %w", ErrArtifactUnverifiable, ErrSigningKeyNotLoaded)), StoreKeyNotLoaded},
		// And the other two pairs of the three specific arms (master R3 round
		// 2 on #4439, LOW-6): with the three reversed, every other cell in the
		// tree stayed green. Each pair is written with the LOSER first, so a
		// switch that took the first mark it met would fail.
		{"both marks: key not loaded wins over ledger inconsistent", marked(fmt.Errorf("%w; and %w", authoring.ErrLedgerInconsistent, ErrSigningKeyNotLoaded)), StoreKeyNotLoaded},
		{"both marks: unverifiable wins over ledger inconsistent", marked(fmt.Errorf("%w; and %w", authoring.ErrLedgerInconsistent, ErrArtifactUnverifiable)), StoreUnverifiable},
		{"all three marks: key not loaded wins", marked(fmt.Errorf("%w; %w; and %w", authoring.ErrLedgerInconsistent, ErrArtifactUnverifiable, ErrSigningKeyNotLoaded)), StoreKeyNotLoaded},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyStoreFailure(c.err); got != c.want {
				t.Errorf("ClassifyStoreFailure(%v) = %s, want %s", c.err, got, c.want)
			}
		})
	}
}
