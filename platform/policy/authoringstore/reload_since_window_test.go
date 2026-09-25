// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"axonflow/platform/decision/pdp"
)

// A READ THAT JOINS A RELOAD IN FLIGHT AND SEES IT SETTLE answers
// definitively - never key_not_loaded (master R3 round 1 on #4398, adopted as
// a cell; deterministic, the loader blocks until the test releases it).
//
// IT DOES NOT take about the settle delay any more, and the header said so
// until master R3 round 2 (NEW-1) pointed out that its own body already
// contradicted it. Under the START rule this read does not take the joined
// reload's answer - that reload read its keys before the read arrived - so it
// falls through to a fresh one and pays the bound reloadWaiting documents.
func TestAReadThatJoinsASettlingReloadIsAnsweredDefinitively(t *testing.T) {
	_, _, stored := unknownKeyArtifact(t)
	release := make(chan struct{})
	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(func(context.Context) (*pdp.TrustStore, error) { <-release; return pdp.NewTrustStore(), nil })
	go func() { _, _ = r.reload(context.Background()) }()
	for {
		r.mu.RLock()
		in := r.reloading
		r.mu.RUnlock()
		if in {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	go func() { time.Sleep(300 * time.Millisecond); close(release) }()
	start := time.Now()
	_, err := (&Store{trust: r}).loadVerified(context.Background(), stored, time.Now())
	f := loadFailure(pdp.RootOrganization, err)
	if !errors.Is(f, ErrArtifactUnverifiable) || errors.Is(f, ErrSigningKeyNotLoaded) {
		t.Fatalf("joined reader got %v; want unverifiable", f)
	}
	// THE BOUND, NOT ~300ms. Before the since rule keyed on the reload's
	// START, this read took the in-flight reload's answer as soon as it
	// settled (~300ms). It must not: that reload read its keys before this
	// read began (the MEDIUM this file's second cell pins). So the join falls
	// through to the floored branch and a FRESH reload - the bound
	// reloadWaiting documents, "a reload it joins, one floor, plus one floor
	// for a fresh reload it then runs or joins", which is three legs and not
	// two (master R3 round 2, NEW-1: a measurement caught 4.20s against a
	// stated 4s). What must not change is that the answer is definitive
	// rather than key_not_loaded.
	if took := time.Since(start); took > 3*reloadFloor+time.Second {
		t.Fatalf("joined reader took %v; want at most a joined reload, one floor and one more floor for the fresh reload, plus slack", took)
	}
}

// A RELOAD THAT READ ITS KEYS BEFORE THE READ BEGAN IS NOT THE READ'S ANSWER
// (master R3 round 1 on #4398, the MEDIUM). Keyed on the reload's COMPLETION,
// a read joining a reload already in flight took that reload's result - which
// had read the key set before the read arrived - so a key another replica
// authorized in between was reported TERMINAL (500 unverifiable) where main
// answered a retriable 503. Keyed on the reload's START, such a join falls
// through to the floored branch and a fresh reload.
//
// R3 plant D (the since window): a reload that STARTED and read its keys BEFORE
// the read began, but COMPLETED after it, is taken as the read's answer. If
// the key was authorized between that reload's key read and the read's start,
// the read answers unverifiable (500, terminal to a client) although a fresh
// reload would admit it. This asserts the answer is NEVER "unverifiable" for a
// key the source authorizes at the time the read began.
func TestAReloadThatReadItsKeysBeforeTheReadBeganIsNotTheReadsAnswer(t *testing.T) {
	keyID, pub, stored := unknownKeyArtifact(t)
	var mu sync.Mutex
	authorized := false // "the database": is the key authorized?
	release := make(chan struct{})
	r := newRefreshingTrust(pdp.NewTrustStore())
	r.bind(func(context.Context) (*pdp.TrustStore, error) {
		mu.Lock()
		snap := authorized // the key set is READ here, at the start
		mu.Unlock()
		<-release // ... and the reload completes later
		ts := pdp.NewTrustStore()
		if snap {
			ts.Authorize(pdp.RootOrganization, keyID, pub)
		}
		return ts, nil
	})
	go func() { _, _ = r.reload(context.Background()) }()
	for {
		r.mu.RLock()
		in := r.reloading
		r.mu.RUnlock()
		if in {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	mu.Lock()
	authorized = true // another replica authorizes the key now
	mu.Unlock()
	time.Sleep(10 * time.Millisecond)
	since := time.Now() // the read begins AFTER the authorization
	go func() { time.Sleep(100 * time.Millisecond); close(release) }()
	_, err := (&Store{trust: r}).loadVerified(context.Background(), stored, since)
	if err == nil {
		return // 200: the key was admitted
	}
	f := loadFailure(pdp.RootOrganization, err)
	if errors.Is(f, ErrArtifactUnverifiable) {
		t.Fatalf("a key authorized BEFORE the read began was answered unverifiable (terminal 500): %v", f)
	}
	t.Logf("non-terminal refusal: %v", f)
}
