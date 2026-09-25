// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"errors"
	"testing"
)

// A PLANE'S FACT SOURCE IS BUILT ONCE PER PROCESS, AND A BUILD ERROR IS STICKY
// (#4249 row 5674229604). That was the contract of the three once/value/error
// triples lazyFactSource replaced: the first use builds, every later use reads
// what the first built - its value or its error - and only a reset (tests)
// builds again. The builds are pure today, so this pins the contract, not a
// performance claim.
func TestALazyFactSourceBuildsOnceAndKeepsItsError(t *testing.T) {
	t.Run("built once, whatever the number of uses", func(t *testing.T) {
		builds := 0
		src := lazyFactSource[int]{build: func() (int, error) { builds++; return builds * 10, nil }}
		for i := 0; i < 3; i++ {
			if v, err := src.get(); err != nil || v != 10 {
				t.Fatalf("use %d answered (%d, %v); want the first build's (10, nil)", i+1, v, err)
			}
		}
		if builds != 1 {
			t.Fatalf("the source was built %d times over three uses; want 1", builds)
		}
	})
	t.Run("a build error is kept, not retried", func(t *testing.T) {
		builds := 0
		planted := errors.New("planted build failure")
		src := lazyFactSource[int]{build: func() (int, error) { builds++; return 0, planted }}
		for i := 0; i < 3; i++ {
			if _, err := src.get(); !errors.Is(err, planted) {
				t.Fatalf("use %d answered %v; want the first build's error", i+1, err)
			}
		}
		if builds != 1 {
			t.Fatalf("a failed build was retried: %d builds over three uses; want 1", builds)
		}
	})
	t.Run("reset builds again", func(t *testing.T) {
		builds := 0
		src := lazyFactSource[int]{build: func() (int, error) { builds++; return builds, nil }}
		first, _ := src.get()
		src.reset()
		second, _ := src.get()
		if first != 1 || second != 2 || builds != 2 {
			t.Fatalf("after reset: first %d, second %d, builds %d; want 1, 2, 2", first, second, builds)
		}
	})
	t.Run("a builder replaced before the first use is the one used", func(t *testing.T) {
		prev := newWCPFactProducer
		t.Cleanup(func() { newWCPFactProducer = prev; wcpFactSource.reset() })
		wcpFactSource.reset()
		replaced := errors.New("the replaced builder ran")
		newWCPFactProducer = func() (*dynamicFactProducer, error) { return nil, replaced }
		if _, err := wcpFactSource.get(); !errors.Is(err, replaced) {
			t.Fatalf("the plane's source answered %v; want the builder installed before its first use", err)
		}
	})
}
