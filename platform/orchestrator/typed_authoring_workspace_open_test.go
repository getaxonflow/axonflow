// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
)

// THE DURABLE OPEN RUNS OUTSIDE THE HANDLER'S LOCK, ONE PER ORGANIZATION, AND
// THE CAP APPLIES ONLY TO A WORKSPACE THAT WILL BE CACHED (#4283 items 5, 6).

// gatedOpen is an openForSigning stub: it counts opens per organization,
// blocks an organization's open until released, and fails it or builds a store
// over a sqlmock database.
type gatedOpen struct {
	mu      sync.Mutex
	opens   map[string]int
	keys    map[string][]ed25519.PublicKey
	gate    map[string]chan struct{}
	entered map[string]chan struct{}
	fail    map[string]bool
	db      *sql.DB
}

func newGatedOpen(t *testing.T) *gatedOpen {
	t.Helper()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &gatedOpen{opens: map[string]int{}, keys: map[string][]ed25519.PublicKey{}, gate: map[string]chan struct{}{},
		entered: map[string]chan struct{}{}, fail: map[string]bool{}, db: db}
}

func (g *gatedOpen) open(_ context.Context, _ *sql.DB, _ pdp.Root, orgID, _ string, pub ed25519.PublicKey, _ string) (*authoringstore.Store, authoring.TrustSource, string, error) {
	g.mu.Lock()
	g.opens[orgID]++
	g.keys[orgID] = append(g.keys[orgID], pub)
	gate, entered, fail := g.gate[orgID], g.entered[orgID], g.fail[orgID]
	delete(g.entered, orgID) // signalled once, by the first open
	g.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if gate != nil {
		<-gate
	}
	if fail {
		return nil, nil, "", errors.New(plantedStoreError)
	}
	trust := authoring.StaticTrust(pdp.NewTrustStore())
	store, err := authoringstore.New(g.db, orgID, trust)
	return store, trust, "", err
}

func (g *gatedOpen) count(org string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.opens[org]
}

func installGatedOpen(t *testing.T, h *TypedAuthoringRouteHandler, g *gatedOpen) {
	t.Helper()
	h.db = g.db
	h.openForSigning = g.open
}

func TestConcurrentRequestsForOneOrganizationRunOneOpen(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	g := newGatedOpen(t)
	entered := make(chan struct{})
	g.gate["org-a"], g.entered["org-a"] = make(chan struct{}), entered
	installGatedOpen(t, h, g)

	const n = 8
	results := make(chan *typedAuthoringWorkspace, n)
	for i := 0; i < n; i++ {
		go func() {
			ws, err := h.workspaceFor(context.Background(), "org-a")
			if err != nil {
				t.Errorf("workspaceFor: %v", err)
			}
			results <- ws
		}()
	}
	<-entered
	time.Sleep(100 * time.Millisecond) // let the other seven reach the in-flight build
	if got := g.count("org-a"); got != 1 {
		t.Fatalf("%d opens in flight for one organization; want 1", got)
	}

	// ANOTHER ORGANIZATION IS NOT HELD BEHIND IT: the open no longer runs under
	// the handler's lock.
	other := make(chan error, 1)
	go func() { _, err := h.workspaceFor(context.Background(), "org-b"); other <- err }()
	select {
	case err := <-other:
		if err != nil {
			t.Fatalf("org-b: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("org-b waited behind org-a's open: the durable open still runs under the handler's lock")
	}

	close(g.gate["org-a"])
	var first *typedAuthoringWorkspace
	for i := 0; i < n; i++ {
		ws := <-results
		if first == nil {
			first = ws
		} else if ws != first {
			t.Fatal("concurrent requests for one organization got different workspaces")
		}
	}
	if got := g.count("org-a"); got != 1 {
		t.Fatalf("%d opens for one organization's concurrent requests; want 1", got)
	}
}

func TestAtTheCapAnOutageEvictsNothingAndIsAnsweredAsTheOutage(t *testing.T) {
	for _, full := range []bool{false, true} {
		name := "every cached workspace empty"
		if full {
			name = "every cached workspace holding artifacts"
		}
		t.Run(name, func(t *testing.T) {
			h := newRouteHandler(t, authoring.EditionCommunity)
			g := newGatedOpen(t)
			installGatedOpen(t, h, g)
			var cached []string
			for i := 0; i < maxTypedAuthoringWorkspaces; i++ {
				org := fmt.Sprintf("org-full-%02d", i)
				ws, err := h.workspaceFor(context.Background(), org)
				if err != nil {
					t.Fatal(err)
				}
				if full {
					ws.digests["sha256:held"] = struct{}{}
				}
				cached = append(cached, org)
			}
			g.fail["org-down"] = true
			ws, err := h.workspaceFor(context.Background(), "org-down")
			if err != nil {
				t.Fatalf("a request at the cap during an outage was refused %v; want the degraded workspace (answered 503)", err)
			}
			if !ws.degraded {
				t.Fatal("the workspace built over a failed open is not degraded")
			}
			h.mu.Lock()
			for _, org := range cached {
				if _, ok := h.workspaces[org]; !ok {
					t.Errorf("%s was evicted for a workspace that is never cached", org)
				}
			}
			_, installed := h.workspaces["org-down"]
			h.mu.Unlock()
			if installed {
				t.Fatal("a degraded workspace was cached")
			}

			// Through a write route: the outage's answer, never 429.
			headers := map[string]string{"X-Org-ID": "org-down", "X-User-ID": testUser}
			rr := call(t, routerFor(h), http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), headers)
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d body %s; want 503 storage_unavailable", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestADegradedRetryReusesItsSigningKey(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	g := newGatedOpen(t)
	g.fail["org-a"] = true
	installGatedOpen(t, h, g)
	for i := 0; i < 3; i++ {
		if _, err := h.workspaceFor(context.Background(), "org-a"); err != nil {
			t.Fatal(err)
		}
	}
	g.mu.Lock()
	keys := g.keys["org-a"]
	g.mu.Unlock()
	if len(keys) != 3 {
		t.Fatalf("%d opens; want 3", len(keys))
	}
	for i := 1; i < len(keys); i++ {
		if !keys[i].Equal(keys[0]) {
			t.Fatal("a degraded retry minted a new signing key; each attempt could leave a typed_policy_signing_keys row")
		}
	}
	// Once the store is back, the workspace is cached and the kept key released.
	g.mu.Lock()
	g.fail["org-a"] = false
	g.mu.Unlock()
	ws, err := h.workspaceFor(context.Background(), "org-a")
	if err != nil || ws.degraded {
		t.Fatalf("after the store came back: degraded=%v err=%v", ws != nil && ws.degraded, err)
	}
	h.mu.Lock()
	_, kept := h.degradedKeys["org-a"]
	h.mu.Unlock()
	if kept {
		t.Fatal("the retry key was kept after a healthy build was installed")
	}
}

// A BUILD THAT PANICS MUST NOT WEDGE THE ORGANIZATION (master R3 round 1 on
// #4397, MEDIUM-2; probe F).
//
// The guard entry and the `done` channel used to be released on the normal
// return only. net/http recovers a handler panic and the process lives on, so
// `h.building[orgID]` stayed set with `done` never closed, and every later
// request for that organization waited at <-ctx.Done(): one with no deadline
// waited forever, and the organization was unreachable until a restart.
func TestABuildThatPanicsDoesNotWedgeTheOrganization(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	g := newGatedOpen(t)
	installGatedOpen(t, h, g)
	panicOnce := true
	base := h.openForSigning
	h.openForSigning = func(ctx context.Context, db *sql.DB, root pdp.Root, orgID, name string, pub ed25519.PublicKey, s string) (*authoringstore.Store, authoring.TrustSource, string, error) {
		if panicOnce {
			panicOnce = false
			panic("the store open panicked")
		}
		return base(ctx, db, root, orgID, name, pub, s)
	}

	// The request that panics: recovered here as net/http recovers a handler's.
	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("the planted panic did not propagate out of workspaceFor; the cell proves nothing")
			}
		}()
		_, _ = h.workspaceFor(context.Background(), "org-a")
	}()

	// THE NEXT REQUEST BUILDS. It is given a deadline only so a wedged guard
	// fails this cell in seconds instead of hanging the package.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ws, err := h.workspaceFor(ctx, "org-a")
	if err != nil {
		t.Fatalf("the request after a panicking build was refused %v; want a workspace (opens=%d)", err, g.count("org-a"))
	}
	if ws == nil {
		t.Fatal("the request after a panicking build got no workspace and no error")
	}
	// One RECORDED open: the panicking call never reaches the recorder (it
	// panics before it), so this counts the rebuild alone. What it proves is
	// that a rebuild happened at all - a wedged guard yields zero.
	if got := g.count("org-a"); got != 1 {
		t.Errorf("%d recorded opens for org-a; want 1 (the rebuild after the panic)", got)
	}
	// AND THE GUARD IS GONE, not merely unused: a third request builds from
	// the cache rather than waiting on a stale entry.
	if _, err := h.workspaceFor(ctx, "org-a"); err != nil {
		t.Errorf("a third request was refused %v", err)
	}
}

// THE FIRST CALLER'S DISCONNECT DOES NOT DEGRADE THE WAITERS' BUILD (master R3
// round 1 on #4397, LOW-4). Every waiter takes the shared build's result, so a
// build running on the first caller's context would be cancelled under them
// all when that one request went away.
func TestASharedBuildSurvivesTheFirstCallersDisconnect(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	g := newGatedOpen(t)
	gate, entered := make(chan struct{}), make(chan struct{})
	g.gate["org-a"], g.entered["org-a"] = gate, entered
	installGatedOpen(t, h, g)

	// THE STUB OPEN OBSERVES CANCELLATION, which is the whole point: a stub
	// that ignored ctx would pass this cell with the build still running on
	// the first caller's context, which is the defect. It reports the context
	// error the real open would.
	base := h.openForSigning
	h.openForSigning = func(ctx context.Context, db *sql.DB, root pdp.Root, orgID, name string, pub ed25519.PublicKey, str string) (*authoringstore.Store, authoring.TrustSource, string, error) {
		type result struct {
			st  *authoringstore.Store
			ts  authoring.TrustSource
			s   string
			err error
		}
		done := make(chan result, 1)
		go func() {
			st, ts, str2, err := base(ctx, db, root, orgID, name, pub, str)
			done <- result{st, ts, str2, err}
		}()
		select {
		case r := <-done:
			return r.st, r.ts, r.s, r.err
		case <-ctx.Done():
			return nil, nil, "", ctx.Err()
		}
	}

	// The first caller's request is cancelled while its open is in flight.
	first, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := h.workspaceFor(first, "org-a")
		firstDone <- err
	}()
	<-entered

	type waited struct {
		ws  *typedAuthoringWorkspace
		err error
	}
	waiter := make(chan waited, 1)
	go func() {
		ws, err := h.workspaceFor(context.Background(), "org-a")
		waiter <- waited{ws, err}
	}()
	time.Sleep(100 * time.Millisecond) // let the waiter reach the in-flight build
	cancelFirst()
	// The cancellation is given time to be OBSERVED before the open is allowed
	// to finish: otherwise the open's completion races it and the cell passes
	// whichever context the build ran on.
	time.Sleep(150 * time.Millisecond)
	close(gate)

	select {
	case got := <-waiter:
		if got.err != nil {
			t.Fatalf("the waiter was refused %v after the first caller disconnected; the shared build must not carry that context", got.err)
		}
		// A CANCELLED OPEN DOES NOT FAIL THE BUILD - it DEGRADES it (the
		// store could not be opened, so writes are refused and the workspace
		// is not cached). That is the harm here, and it is what this asserts:
		// an error check alone passes while every waiter gets a degraded
		// workspace because one request went away.
		if got.ws == nil {
			t.Fatal("the waiter got no workspace and no error")
		}
		if got.ws.degraded {
			t.Fatal("the waiter got a DEGRADED workspace: the shared build ran on the first caller's context and was cancelled with it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter never finished after the first caller disconnected")
	}
	<-firstDone // whatever the disconnected caller got is its own business
	if got := g.count("org-a"); got != 1 {
		t.Errorf("%d opens for org-a; want 1 shared build", got)
	}
}

// A PANIC INSIDE THE LOCKED INSTALL WINDOW MUST NOT BLOCK EVERY ORGANIZATION
// (master R3 round 2 on #4397, LOW-8; probe K).
//
// MEDIUM-2's fix releases the guard entry in a deferred publish that RE-TAKES
// h.mu. A panic raised while the install section held that lock would run the
// deferred publish on the same goroutine, which would block for ever on a
// non-reentrant mutex - the lock held, every organization's request queued
// behind it, and the request never reaching net/http's recover to turn into a
// 500. The install section has its own `defer Unlock` for exactly this.
func TestAPanicInsideTheInstallWindowDoesNotBlockEveryOrganization(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	g := newGatedOpen(t)
	installGatedOpen(t, h, g)
	panicOnce := true
	h.afterInstallLocked = func() {
		if panicOnce {
			panicOnce = false
			panic("the install window panicked")
		}
	}

	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("the planted panic did not propagate; the cell proves nothing")
			}
		}()
		_, _ = h.workspaceFor(context.Background(), "org-a")
	}()

	// ANOTHER ORGANIZATION IS SERVED. If the lock were still held this would
	// wait out its context rather than build.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := h.workspaceFor(ctx, "org-b"); err != nil {
		t.Fatalf("org-b was refused %v after org-a panicked inside the install window: the handler's lock is held", err)
	}
	// And the organization that panicked builds on its next request.
	if _, err := h.workspaceFor(ctx, "org-a"); err != nil {
		t.Errorf("org-a was refused %v on the request after its panic", err)
	}
}

// THE WAITER OF A PANICKED ROUND GETS A REFUSAL, NEVER A NIL WORKSPACE (master
// R3 round 2 on #4397; probe J). A waiter that was handed a nil workspace with
// a nil error would dereference it.
func TestTheWaiterOfAPanickedBuildIsRefusedRatherThanHandedNothing(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	g := newGatedOpen(t)
	entered := make(chan struct{})
	g.gate["org-a"], g.entered["org-a"] = make(chan struct{}), entered
	installGatedOpen(t, h, g)
	base := h.openForSigning
	h.openForSigning = func(ctx context.Context, db *sql.DB, root pdp.Root, orgID, name string, pub ed25519.PublicKey, s string) (*authoringstore.Store, authoring.TrustSource, string, error) {
		_, _, _, _ = base(ctx, db, root, orgID, name, pub, s)
		panic("the store open panicked after the waiter joined")
	}

	waiter := make(chan struct {
		ws  *typedAuthoringWorkspace
		err error
	}, 1)
	go func() {
		defer func() { _ = recover() }()
		_, _ = h.workspaceFor(context.Background(), "org-a")
	}()
	<-entered
	go func() {
		ws, err := h.workspaceFor(context.Background(), "org-a")
		waiter <- struct {
			ws  *typedAuthoringWorkspace
			err error
		}{ws, err}
	}()
	time.Sleep(100 * time.Millisecond) // let the waiter reach the in-flight build
	close(g.gate["org-a"])

	select {
	case got := <-waiter:
		if got.err == nil {
			t.Fatalf("the waiter of a panicked build was handed ws=%v with NO error; it would dereference it", got.ws)
		}
		if got.ws != nil {
			t.Errorf("the waiter got both a workspace and an error %v", got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter of a panicked build never finished")
	}
}
