// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// #4249 row 5681489141: the classification the breaker's exemption rests on,
// the readiness probe, and the additive /health member.

func resetReach(t *testing.T, service string) {
	t.Helper()
	flag := upstreamReachedFlag(service)
	prev := flag.Load()
	flag.Store(false)
	t.Cleanup(func() { flag.Store(prev) })
}

func closedPortURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "http://" + addr
}

func TestIsDialFailure_ClassifiesRealTransportErrors(t *testing.T) {
	client := &http.Client{Timeout: 2 * time.Second}

	_, refused := client.Get(closedPortURL(t) + "/health")
	if refused == nil {
		t.Fatal("PREMISE: a GET to a closed port succeeded")
	}
	// Wrapped the way forwardToOrchestrator wraps it.
	wrapped := fmt.Errorf("orchestrator connection failed: %w", refused)

	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	}))
	defer hang.Close()
	_, hungUp := client.Get(hang.URL)
	if hungUp == nil {
		t.Fatal("PREMISE: a hang-up after connect was answered")
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"connection refused", refused, true},
		{"connection refused, wrapped with %w", wrapped, true},
		{"no such host", &net.DNSError{Err: "no such host", Name: "orchestrator.invalid", IsNotFound: true}, true},
		{"hang-up after connect", hungUp, false},
		{"io.EOF", io.EOF, false},
		{"connection refused, wrapped with %v (the pre-fix wrap)", fmt.Errorf("orchestrator connection failed: %v", refused), false},
		{"nil", nil, false},
		{"plain error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := isDialFailure(tc.err); got != tc.want {
			t.Errorf("%s: isDialFailure = %v, want %v (%v)", tc.name, got, tc.want, tc.err)
		}
	}
}

func TestUpstreamErrorCountsAgainstClient(t *testing.T) {
	// The subject is the orchestrator: the exemption is its alone, because it
	// is the one upstream something marks reached (the forward, its proxy, the
	// readiness probe) and the one /health reports (master R3 round 1).
	const svc = upstreamOrchestrator
	resetReach(t, svc)
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	read := &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}

	if upstreamErrorCountsAgainstClient(svc, dial) {
		t.Error("a dial failure before the upstream was ever reached counts against the client")
	}
	if !upstreamErrorCountsAgainstClient(svc, read) {
		t.Error("a read failure before reach does not count: only a dial failure is exempt")
	}
	markUpstreamReached(svc)
	if !upstreamErrorCountsAgainstClient(svc, dial) {
		t.Error("a dial failure after the upstream was reached does not count: the exemption outlived the boot window")
	}

	// ANY OTHER UPSTREAM KEEPS THE BASE BEHAVIOUR. The customer portal is
	// served by the same createReverseProxy and is probed by nothing, so an
	// exemption there would never end.
	const other = "portal"
	resetReach(t, other)
	if !upstreamErrorCountsAgainstClient(other, dial) {
		t.Error("a dial failure to an upstream that is not the orchestrator is exempt; nothing would ever mark it reached")
	}
}

func TestUpstreamReadinessProbe_MarksReachedOnAnyAnswerAndNotBefore(t *testing.T) {
	prevInterval := upstreamProbeInterval
	upstreamProbeInterval = 20 * time.Millisecond
	t.Cleanup(func() { upstreamProbeInterval = prevInterval })

	// Nothing listening: the probe keeps the upstream unreached.
	const down = "upstream-4249-probe-down"
	resetReach(t, down)
	startUpstreamReadinessProbe(down, closedPortURL(t))
	time.Sleep(300 * time.Millisecond)
	if upstreamReached(down) {
		t.Fatal("the probe marked an upstream reached that never answered")
	}
	// Its failed attempts are not the client's either: a refused connection to
	// the orchestrator is still exempt while the probe has not seen an answer
	// (master's condition on the probe). Read on the orchestrator's own flag,
	// because the exemption is scoped to it.
	resetReach(t, upstreamOrchestrator)
	if upstreamErrorCountsAgainstClient(upstreamOrchestrator, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}) {
		t.Fatal("after the probe's failed attempts, a refused connection counts against the client")
	}
	if got := fmt.Sprint(upstreamHealthFor(down)); got != "unreached" {
		t.Fatalf("health for a never-answering upstream = %q, want unreached", got)
	}
	// Stop that probe: its loop ends once the upstream reads as reached.
	markUpstreamReached(down)

	// A 503 is an answer: the upstream is listening.
	const up = "upstream-4249-probe-up"
	resetReach(t, up)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("the probe asked for %q, want /health", r.URL.Path)
		}
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	startUpstreamReadinessProbe(up, srv.URL+"/")
	deadline := time.Now().Add(3 * time.Second)
	for !upstreamReached(up) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !upstreamReached(up) {
		t.Fatal("the probe did not mark an answering upstream reached within 3s")
	}
	if !upstreamErrorCountsAgainstClient(up, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}) {
		t.Fatal("after the probe's first answer, a refused connection is still exempt")
	}
	time.Sleep(100 * time.Millisecond)
	if n := hits.Load(); n != 1 {
		t.Errorf("the probe asked %d times; it stops at the first answer", n)
	}
}

// (b) is ADDITIVE: the member reports the orchestrator's reach, and neither
// `status` nor the HTTP code reads it (the compose files start the orchestrator
// only once the agent is healthy, so gating on it would deadlock a fresh
// install).
func TestHealth_UpstreamMemberIsAdditive(t *testing.T) {
	resetReach(t, upstreamOrchestrator)
	prevReady := appReady.Load()
	appReady.Store(true)
	t.Cleanup(func() { appReady.Store(prevReady) })

	read := func() (int, map[string]interface{}) {
		rr := httptest.NewRecorder()
		readinessAwareHealthHandler(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
		var body map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("/health is not JSON: %v", err)
		}
		return rr.Code, body
	}
	code, body := read()
	if code != http.StatusOK || body["status"] != "healthy" {
		t.Fatalf("an unreached orchestrator changed the agent's health: %d %v", code, body["status"])
	}
	if got := body["upstream"]; fmt.Sprint(got) != "map[orchestrator:unreached]" {
		t.Errorf("upstream = %v, want orchestrator unreached", got)
	}
	markUpstreamReached(upstreamOrchestrator)
	code, body = read()
	if code != http.StatusOK || body["status"] != "healthy" {
		t.Fatalf("/health after reach: %d %v", code, body["status"])
	}
	if got := body["upstream"]; fmt.Sprint(got) != "map[orchestrator:reached]" {
		t.Errorf("upstream = %v, want orchestrator reached", got)
	}
}
