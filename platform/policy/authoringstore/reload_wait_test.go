// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"axonflow/platform/decision/pdp"
)

// A DEFERRED RELOAD IS WAITED FOR, AND THE ANSWER IS DEFINITIVE (#4272). A read
// that landed inside another read's reload floor answered 503 key_not_loaded,
// so under several concurrent readers a retry loop could end on key_not_loaded
// for an artifact that will never verify. The read now waits, bounded by
// reloadFloor, for the trust that reload produces and classifies against it.

// floorInForce returns a refreshing trust whose last reload completed just
// now, so every read of an unknown key is deferred by the floor, with load as
// its loader.
func floorInForce(load func(context.Context) (*pdp.TrustStore, error)) *refreshingTrust {
	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(load)
	r.lastReload = time.Now()
	return r
}

func unknownKeyArtifact(t *testing.T) (string, ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := KeyIDFor("test", "org-4272", pub)
	_, stored := artifactFor(t, keyID, priv, 1)
	return keyID, pub, stored
}

func TestConcurrentReadersInsideTheFloorAnswerDefinitively(t *testing.T) {
	_, _, stored := unknownKeyArtifact(t)
	var loads atomic.Int32
	r := floorInForce(func(context.Context) (*pdp.TrustStore, error) {
		loads.Add(1)
		return pdp.NewTrustStore(), nil // the key is not authorized anywhere
	})
	s := &Store{trust: r}

	const readers = 6
	var wg sync.WaitGroup
	errs := make([]error, readers)
	start := time.Now()
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.loadVerified(context.Background(), stored, time.Now())
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		failure := loadFailure(pdp.RootOrganization, err)
		if errors.Is(failure, ErrSigningKeyNotLoaded) {
			t.Fatalf("reader %d answered key_not_loaded inside the floor; want the definitive answer after the reload: %v", i, failure)
		}
		if !errors.Is(failure, ErrArtifactUnverifiable) {
			t.Fatalf("reader %d: %v; want ErrArtifactUnverifiable (the key is authorized nowhere)", i, failure)
		}
	}
	if n := loads.Load(); n != 1 {
		t.Errorf("%d reloads for %d concurrent readers; want 1", n, readers)
	}
	if took := time.Since(start); took > reloadFloor+time.Second {
		t.Errorf("the readers took %v; the wait is bounded by the floor (%v)", took, reloadFloor)
	}
}

func TestAKeyAnotherReplicaAuthorizedLoadsAfterTheWait(t *testing.T) {
	keyID, pub, stored := unknownKeyArtifact(t)
	r := floorInForce(func(context.Context) (*pdp.TrustStore, error) {
		ts := pdp.NewTrustStore()
		ts.Authorize(pdp.RootOrganization, keyID, pub)
		return ts, nil
	})
	if _, err := (&Store{trust: r}).loadVerified(context.Background(), stored, time.Now()); err != nil {
		t.Fatalf("an artifact whose key the next reload authorizes did not load: %v", err)
	}
}

func TestAReloadThatFailsAfterTheWaitIsTheStoresFailure(t *testing.T) {
	_, _, stored := unknownKeyArtifact(t)
	r := floorInForce(func(context.Context) (*pdp.TrustStore, error) {
		return nil, errors.New("dial tcp: connection refused")
	})
	_, err := (&Store{trust: r}).loadVerified(context.Background(), stored, time.Now())
	failure := loadFailure(pdp.RootOrganization, err)
	if !errors.Is(failure, errKeyReloadFailed) || errors.Is(failure, ErrArtifactUnverifiable) || errors.Is(failure, ErrSigningKeyNotLoaded) {
		t.Fatalf("a failed re-read after the wait is %v; want the storage failure (503 storage_unavailable)", failure)
	}
}

func TestAReloadSlowerThanTheFloorStillAnswersKeyNotLoaded(t *testing.T) {
	_, _, stored := unknownKeyArtifact(t)
	release := make(chan struct{})
	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(func(context.Context) (*pdp.TrustStore, error) {
		<-release
		return pdp.NewTrustStore(), nil
	})
	// A reload is in flight and will not finish within the floor.
	go func() { _, _ = r.reload(context.Background()) }()
	for {
		r.mu.RLock()
		inFlight := r.reloading
		r.mu.RUnlock()
		if inFlight {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer close(release)
	start := time.Now()
	_, err := (&Store{trust: r}).loadVerified(context.Background(), stored, time.Now())
	if failure := loadFailure(pdp.RootOrganization, err); !errors.Is(failure, ErrSigningKeyNotLoaded) {
		t.Fatalf("a wait that timed out is %v; want ErrSigningKeyNotLoaded (503 key_not_loaded)", failure)
	}
	if took := time.Since(start); took < reloadFloor-200*time.Millisecond || took > reloadFloor+time.Second {
		t.Errorf("the wait took %v; want about the floor (%v)", took, reloadFloor)
	}
}

// A call that began before a reload which has since completed takes that
// reload's answer without waiting again: a listing of many artifacts signed by
// one unknown key waits once, not once per artifact.
func TestACallWaitsOnceNotOncePerArtifact(t *testing.T) {
	_, _, stored := unknownKeyArtifact(t)
	r := floorInForce(func(context.Context) (*pdp.TrustStore, error) { return pdp.NewTrustStore(), nil })
	s := &Store{trust: r}
	since := time.Now()
	start := time.Now()
	for i := 0; i < 5; i++ {
		_, err := s.loadVerified(context.Background(), stored, since)
		if err == nil {
			t.Fatal("an artifact with an unknown key loaded")
		}
		// AND EACH IS DEFINITIVE, not just non-nil (master R3 round 1 on
		// #4398, LOW). The reload here completes and does not authorize the
		// key, so every one of the five must be the terminal refusal; a
		// key_not_loaded among them would mean a read paid the wait and still
		// came back "ask again", which is what #4272 exists to stop.
		if f := loadFailure(pdp.RootOrganization, err); !errors.Is(f, ErrArtifactUnverifiable) || errors.Is(f, ErrSigningKeyNotLoaded) {
			t.Fatalf("load %d answered %v; want the terminal ErrArtifactUnverifiable", i+1, f)
		}
	}
	if took := time.Since(start); took > reloadFloor+time.Second {
		t.Fatalf("five loads in one call took %v; the wait must be paid once (about %v)", took, reloadFloor)
	}
}
