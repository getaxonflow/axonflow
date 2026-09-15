// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"sync"
	"testing"

	"axonflow/platform/decision/pdp"
)

// The concurrency this type introduces, exercised rather than assumed.
//
// refreshingTrust is read on every artifact load and written by a reload, from
// whatever goroutines are serving requests. Running -race over tests that never
// touch it concurrently would prove nothing, so this drives readers and
// reloaders at the same time.

// TestConcurrentReloadsAreCoalescedByTheInFlightGuard tests the GUARD, not the
// floor - and the distinction is the whole test.
//
// AN EARLIER VERSION OF THIS TEST MEASURED THE WRONG THING. Its loader returned
// instantly, so the first reloader stamped lastReload before any peer reached
// the check and the FLOOR did the coalescing. Deleting `r.reloading` from the
// guard left it passing at -cpu=1 - a mutant that removes the mechanism the
// test is named for must not survive it.
//
// The fix is to make the window real: the first loader BLOCKS until every other
// reloader has been through the guard and returned. While it blocks, lastReload
// is still zero, so the floor cannot be what refuses them - only the in-flight
// guard can.
func TestConcurrentReloadsAreCoalescedByTheInFlightGuard(t *testing.T) {
	const peers = 32

	var mu sync.Mutex
	loads := 0

	entered := make(chan struct{}) // closed once the first loader is inside
	release := make(chan struct{}) // closed once every peer has been refused

	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(func(context.Context) (*pdp.TrustStore, error) {
		mu.Lock()
		loads++
		first := loads == 1
		mu.Unlock()
		if first {
			close(entered)
			<-release
		}
		// A FRESH store every time, never a mutation of a published one.
		return pdp.NewTrustStore(), nil
	})

	var winner sync.WaitGroup
	winner.Add(1)
	go func() {
		defer winner.Done()
		if changed, err := r.reload(context.Background()); !changed || err != nil {
			t.Errorf("the first reload should have succeeded: changed=%t err=%v", changed, err)
		}
	}()

	<-entered // the loader is now inside and holding

	var refused sync.WaitGroup
	results := make([]bool, peers)
	for i := 0; i < peers; i++ {
		refused.Add(1)
		go func(i int) {
			defer refused.Done()
			changed, err := r.reload(context.Background())
			if err != nil {
				t.Errorf("peer %d got an error from a coalesced reload: %v", i, err)
			}
			results[i] = changed
		}(i)
	}
	refused.Wait()

	close(release)
	winner.Wait()

	// EVERY peer must have been refused by the in-flight guard. The floor
	// cannot account for this: lastReload was still zero throughout, because
	// the winner had not returned.
	for i, changed := range results {
		if changed {
			t.Fatalf("peer %d performed a second reload while one was in flight", i)
		}
	}
	mu.Lock()
	got := loads
	mu.Unlock()
	if got != 1 {
		t.Fatalf("%d peers arriving during one in-flight reload produced %d loader calls, want exactly 1", peers, got)
	}
}

// TestConcurrentReadsDuringAReloadAreRaceFree is the -race half: readers and a
// writer on the same object at the same time.
func TestConcurrentReadsDuringAReloadAreRaceFree(t *testing.T) {
	const readers = 32

	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(func(context.Context) (*pdp.TrustStore, error) { return pdp.NewTrustStore(), nil })

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				if got := r.Current(); got == nil {
					// Contractual: authoring.TrustSource must never hand back
					// nil, or a caller reports every artifact as unsigned.
					t.Error("Current() returned nil")
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, _ = r.reload(context.Background())
	}()

	close(start)
	wg.Wait()
}

// TestAReaderKeepsAConsistentStoreAcrossAReload is the pointer-swap property.
//
// The assertion is that the store a reader ALREADY HOLDS does not gain the
// reload's keys - not merely that the variable still points where it did, which
// no implementation could break. A reload that authorized into the live store
// instead of publishing a fresh one would fail exactly this.
func TestAReaderKeepsAConsistentStoreAcrossAReload(t *testing.T) {
	const keyID = "key-added-by-the-reload"
	pub := make([]byte, 32)

	first := pdp.NewTrustStore()
	second := pdp.NewTrustStore()
	second.Authorize(pdp.RootOrganization, keyID, pub)

	r := newRefreshingTrust(first)
	r.bind(func(context.Context) (*pdp.TrustStore, error) { return second, nil })

	held := r.Current()
	if _, ok := held.PublicKey(pdp.RootOrganization, keyID); ok {
		t.Fatal("the starting store already carries the key the reload adds; this test would assert nothing")
	}

	if changed, err := r.reload(context.Background()); !changed || err != nil {
		t.Fatalf("reload: changed=%t err=%v", changed, err)
	}

	// The source now serves the new keys...
	if _, ok := r.Current().PublicKey(pdp.RootOrganization, keyID); !ok {
		t.Fatal("after a successful reload the source does not serve the reloaded keys")
	}
	// ...and the store a reader was already holding does NOT.
	if _, ok := held.PublicKey(pdp.RootOrganization, keyID); ok {
		t.Fatal("the reload mutated the store a reader was already holding, instead of publishing a fresh one")
	}
}
