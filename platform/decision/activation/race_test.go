// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"runtime"
	"sync"
	"testing"

	"axonflow/platform/decision/activation"
)

// TestConcurrentActivationsDoNotRaceTheTrustStore is the regression for the
// race R3 reproduced (#3895).
//
// # WHY IT IS A REAL SHAPE AND NOT A CONTRIVED ONE
//
// Activate used to authorize the deployment's system-corpus key on the CALLER's
// trust store, and a transport holds ONE store per organization that every
// concurrent request for that organization shares - the orchestrator's
// typed-authoring handler releases its map mutex before it uses the workspace.
// So two activations for one organization, or an activation racing a
// publication's artifact verification, both reached TrustStore concurrently.
//
// Before the store took a mutex this reported a write/write race under -race,
// and in production it is `fatal error: concurrent map writes`, which is an
// unrecoverable abort of the whole process rather than of the request.
//
// Activate no longer writes the caller's store at all (#4047; see
// TestActivateWritesNothingIntoTheCallersTrustStore), so the write half of that
// race is gone. The test stays because concurrent activations still READ the
// shared store while publications verify against it, and because the mutex it
// proved necessary is still what makes a trust store safe to share.
//
// RUN IT WITH -race FOR IT TO MEAN ANYTHING. Without the detector it only
// asserts that nothing panicked, which a racy map usually manages.
func TestConcurrentActivationsDoNotRaceTheTrustStore(t *testing.T) {
	// AT GOMAXPROCS=1 THIS TEST PROVES NOTHING, and saying so is the point.
	//
	// R3 measured it: with every lock deleted, this passed under `-race -cpu=1`.
	// The detector reports a race only when two goroutines actually interleave
	// on the access, and on a single processor the loop below runs to
	// completion before the scheduler switches. A green run at -cpu=1 is
	// therefore a statement about the scheduler, not about the locks - which is
	// exactly the "an invariant that cannot fail for a class is not evidence
	// about that class" shape.
	//
	// SO IT SKIPS, LOUDLY, AND THE SKIP CARRIES ITS OWN REASON. A pass at
	// -cpu=1 would be the false negative - the run that says "no race" having
	// been incapable of observing one - and that is what the skip refuses to
	// emit. The skip is not a silent hole either: the suite runs at -cpu=1 in
	// one CI lane and at the default CPUs in the race lane, so this test has a
	// lane where it is meaningful, and the -cpu=1 lane reports it as SKIP with
	// the sentence below rather than as a green assertion about the locks.
	//
	// (An earlier version of this comment said the test FAILS here. It does
	// not, and never did - the next line is a t.Skipf. Failing would red the
	// -cpu=1 lane for every run over a condition that lane cannot satisfy.)
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skipf("GOMAXPROCS=%d: the race detector cannot observe an interleaving on one processor, so this "+
			"test would pass with every lock deleted. Run it with -cpu>=2 (and -race) for it to mean anything.",
			runtime.GOMAXPROCS(0))
	}

	w := newWorld(t)
	in := w.inputs()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				if _, err := activation.Activate(context.Background(), in); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a concurrent activation failed: %v", err)
	}
}
