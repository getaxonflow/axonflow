// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// readerPacedWriter couples a concurrent writer to a concurrent reader's
// PROGRESS rather than to the clock (#3648).
//
// The shape it replaces: a writer goroutine issues N writes as fast as the
// store takes them while a reader loops over Load; afterwards the test requires
// "at least K loads happened during the writes" so the window was sampled.
// That floor is a claim about the relative speed of two goroutines, and on a
// loaded CI runner the writes finished before the third load returned
// (run 33623146131 attempt 1: 12 writes, 2 loads, case FAILED on its own floor
// while the invariant under test had held on every load). Locally the same
// code passed 50 of 50, because a laptop's Load is faster.
//
// With the pacer the writer waits, after each write, until the reader has
// COMPLETED a load that finished after the write started. Every write is then
// sampled by at least one load on any machine; the goroutines still overlap
// (the load that releases the writer began before or during the write, which
// is the interleaving the invariant is about); and the count floor becomes a
// structural property the test can assert without betting on speed.
type readerPacedWriter struct {
	loads atomic.Int64
}

// recordLoad is called by the reader after each completed load.
func (p *readerPacedWriter) recordLoad() { p.loads.Add(1) }

// loadsCompleted returns the number of loads completed so far; the writer
// takes it as a mark BEFORE issuing a write.
func (p *readerPacedWriter) loadsCompleted() int64 { return p.loads.Load() }

// awaitLoadAfter blocks until more loads have completed than `mark`, i.e.
// until at least one load finished after the caller took the mark, or until
// ctx ends.
func (p *readerPacedWriter) awaitLoadAfter(ctx context.Context, mark int64) error {
	for p.loads.Load() <= mark {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Microsecond):
		}
	}
	return nil
}

// TestReaderPacedWriterSamplesEveryWriteWhateverTheRelativeSpeed is the
// deterministic regression test for #3648's cause. It runs the free-running
// arrangement and the paced arrangement against the SAME slow reader and fast
// writer and asserts that the first under-samples (the flake) and the second
// cannot. The speeds are four orders of magnitude apart (a ~100 ns write
// against a 2 ms load), so the first arm's outcome does not depend on the
// scheduler: twelve writes complete in microseconds and no load can finish
// inside them.
func TestReaderPacedWriterSamplesEveryWriteWhateverTheRelativeSpeed(t *testing.T) {
	const writes = 12
	const loadCost = 2 * time.Millisecond

	// The "store": a counter the writer bumps and the reader observes slowly.
	var written atomic.Int64
	slowLoad := func() int64 {
		time.Sleep(loadCost)
		return written.Load()
	}

	t.Run("free-running: the writer outruns the reader and the window is not sampled", func(t *testing.T) {
		written.Store(0)
		done := make(chan struct{})
		go func() {
			for i := 0; i < writes; i++ {
				written.Add(1)
			}
			close(done)
		}()
		reads := 0
	loop:
		for {
			slowLoad()
			reads++
			select {
			case <-done:
				break loop
			default:
			}
		}
		// reads counts the loads issued before the writer was seen finished;
		// the first load alone outlives every write.
		if reads >= writes {
			t.Fatalf("the free-running arrangement sampled %d load(s) against %d writes; the defect this test pins (a slow reader sees a finished writer) did not reproduce, so the paced arm below proves nothing by comparison", reads, writes)
		}
		t.Logf("free-running: %d load(s) against %d writes - the run-33623146131 shape (2 against 12)", reads, writes)
	})

	t.Run("paced: at least one completed load per write, on any machine", func(t *testing.T) {
		written.Store(0)
		var pacer readerPacedWriter
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			for i := 0; i < writes; i++ {
				mark := pacer.loadsCompleted()
				written.Add(1)
				if err := pacer.awaitLoadAfter(ctx, mark); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		reads := 0
		var seen []int64
	loop:
		for {
			seen = append(seen, slowLoad())
			reads++
			pacer.recordLoad()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("paced writer: %v", err)
				}
				break loop
			default:
			}
		}
		if reads < writes {
			t.Fatalf("the paced arrangement sampled %d load(s) against %d writes; the pacer let a write go unsampled", reads, writes)
		}
		// Every write was observed: the sequence of observed counts must
		// reach `writes` and never decrease (a monotonic counter read once per
		// write cannot skip a value the pacer waited on).
		for i := 1; i < len(seen); i++ {
			if seen[i] < seen[i-1] {
				t.Fatalf("observed counts went backwards: %v", seen)
			}
		}
		if last := seen[len(seen)-1]; last != writes {
			t.Fatalf("the last load observed %d writes, want %d", last, writes)
		}
		t.Logf("paced: %d load(s) against %d writes", reads, writes)
	})
}
