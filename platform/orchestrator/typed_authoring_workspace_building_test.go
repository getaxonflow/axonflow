// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
)

// A REQUEST THAT STOPS WAITING FOR ITS ORGANIZATION'S BUILD IS 503
// workspace_building (#4283, master's ruling on (7)). It was answered as a
// build that failed (503 workspace_unavailable here, 500 on the portal), which
// a retry cannot fix; a build still running is exactly what a retry fixes. The
// log names the step the build was on, so an operator can still see when that
// step was the store.
func TestARequestThatStopsWaitingForABuildIsWorkspaceBuilding(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	g := newGatedOpen(t)
	entered := make(chan struct{})
	g.gate["org-a"], g.entered["org-a"] = make(chan struct{}), entered
	installGatedOpen(t, h, g)

	builder := make(chan error, 1)
	go func() { _, err := h.workspaceFor(context.Background(), "org-a"); builder <- err }()
	<-entered

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	rr := httptest.NewRecorder()
	if _, ok := h.requireWorkspace(ctx, rr, "org-a"); ok {
		t.Fatal("a request that stopped waiting was handed a workspace")
	}
	body := decodeBody(t, rr)
	if rr.Code != http.StatusServiceUnavailable || body["reason"] != "workspace_building" {
		t.Fatalf("status %d body %v; want 503 workspace_building", rr.Code, body)
	}
	if strings.Contains(rr.Body.String(), "durable") || strings.Contains(rr.Body.String(), "deadline") {
		t.Fatalf("the cause reached the body: %s", rr.Body.String())
	}
	// POSITIVE: the log names the step in flight and the waiter's own cause.
	if !strings.Contains(logs.String(), "the build was opening the durable store") || !strings.Contains(logs.String(), "context deadline exceeded") {
		t.Fatalf("the log does not name the step in flight and the cause: %q", logs.String())
	}

	close(g.gate["org-a"])
	if err := <-builder; err != nil {
		t.Fatalf("the build itself: %v", err)
	}
	// CONTROL: once the build is in, the next request is served.
	rr = httptest.NewRecorder()
	if _, ok := h.requireWorkspace(context.Background(), rr, "org-a"); !ok {
		t.Fatalf("the built workspace was refused: %d %s", rr.Code, rr.Body.String())
	}
}

// A BUILD THAT FAILED IS 500 workspace_unavailable, THROUGH AN INPUT
// PRODUCTION CAN REACH (#4283, master R3 round 1 on #4439, MEDIUM-2). The
// 503 -> 500 change covers four reachable causes: a key that could not be
// generated, the plane, an activation authority, and a build that panicked.
// The only other cell for the 500 drives buildWorkspace's "no vocabulary"
// guard, which no production input reaches, so it proves nothing about them.
// This cell drives the panicked build: the durable open panics while one
// request waits on it, and the waiter is answered 500.
//
// THE ASYMMETRY, STATED: this 500 is a WAITER's answer only. The request that
// started the build panics out to net/http, which recovers the handler and
// writes no body; only a request waiting on that build is answered, from
// errTypedWorkspaceBuildDidNotComplete.
func TestAWaiterOnAPanickedBuildIsAnswered500WorkspaceUnavailable(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	g := newGatedOpen(t)
	entered := make(chan struct{})
	g.gate["org-a"], g.entered["org-a"] = make(chan struct{}), entered
	installGatedOpen(t, h, g)
	base := h.openForSigning
	var once sync.Once
	h.openForSigning = func(ctx context.Context, db *sql.DB, root pdp.Root, orgID, name string, pub ed25519.PublicKey, s string) (*authoringstore.Store, authoring.TrustSource, string, error) {
		store, trust, id, err := base(ctx, db, root, orgID, name, pub, s)
		panicked := false
		once.Do(func() { panicked = true })
		if panicked {
			panic("the store open panicked (planted, #4439 MEDIUM-2)")
		}
		return store, trust, id, err
	}

	go func() {
		defer func() { _ = recover() }() // as net/http recovers the handler that started the build
		_, _ = h.workspaceFor(context.Background(), "org-a")
	}()
	<-entered
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rr := httptest.NewRecorder()
		h.requireWorkspace(context.Background(), rr, "org-a")
		answered <- rr
	}()
	time.Sleep(100 * time.Millisecond) // let the waiter reach the in-flight build
	close(g.gate["org-a"])

	select {
	case rr := <-answered:
		body := decodeBody(t, rr)
		if rr.Code != http.StatusInternalServerError || body["reason"] != "workspace_unavailable" {
			t.Fatalf("status %d body %v; want 500 workspace_unavailable (a build that failed; a retry will not fix it)", rr.Code, body)
		}
		if strings.Contains(rr.Body.String(), "panicked") || strings.Contains(rr.Body.String(), "did not complete") {
			t.Fatalf("the cause reached the body: %s", rr.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter of a panicked build was never answered")
	}
}
