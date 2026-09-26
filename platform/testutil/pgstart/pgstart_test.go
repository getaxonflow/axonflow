// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pgstart

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

// fakeClock advances only when the Waiter sleeps, so a window is measured in
// polls rather than wall time.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time        { return c.t }
func (c *fakeClock) sleep(d time.Duration) { c.t = c.t.Add(d) }

// fakeAttempt is a container whose port publishes after publishAfter polls
// (never when negative), and which stops running after stopAfter state reads
// (never when negative).
type fakeAttempt struct {
	name         string
	publishAfter int
	stopAfter    int
	polls        int
	stateReads   int
	exitCode     int
	oom          bool
	removed      bool
	// stateErr makes every state read fail: a container removed under the
	// wait, or a daemon that cannot answer.
	stateErr bool
}

func (f *fakeAttempt) Name() string { return f.name }

func (f *fakeAttempt) Endpoint() (string, error) {
	f.polls++
	if f.publishAfter >= 0 && f.polls > f.publishAfter {
		return "postgres://" + f.name, nil
	}
	return "", errors.New("docker port: exit status 1")
}

func (f *fakeAttempt) State() (State, error) {
	f.stateReads++
	if f.stateErr {
		return State{}, errors.New("docker inspect: No such object: " + f.name)
	}
	if f.stopAfter >= 0 && f.stateReads > f.stopAfter {
		return State{Running: false, Status: "exited", ExitCode: f.exitCode, OOMKilled: f.oom}, nil
	}
	return State{Running: true, Status: "running"}, nil
}

func (f *fakeAttempt) Logs(n int) string { return fmt.Sprintf("%s: last log line", f.name) }
func (f *fakeAttempt) Remove()           { f.removed = true }

// harness starts the fakes in order and records how many were started.
type harness struct {
	fakes   []*fakeAttempt
	started int
	clock   *fakeClock
}

func (h *harness) start() (Attempt, error) {
	if h.started >= len(h.fakes) {
		return nil, errors.New("no more fakes")
	}
	f := h.fakes[h.started]
	h.started++
	return f, nil
}

func (h *harness) waiter(window time.Duration) Waiter {
	return Waiter{Window: window, Now: h.clock.now, Sleep: h.clock.sleep, Poll: time.Second}
}

func newHarness(fakes ...*fakeAttempt) *harness {
	return &harness{fakes: fakes, clock: &fakeClock{t: time.Unix(0, 0)}}
}

func alwaysReady(string) error { return nil }

func TestAPortThatPublishesInsideTheWindowIsOneAttempt(t *testing.T) {
	slow := &fakeAttempt{name: "slow", publishAfter: 45, stopAfter: -1}
	h := newHarness(slow)
	dsn, a, err := h.waiter(90*time.Second).Start(h.start, alwaysReady)
	if err != nil || dsn != "postgres://slow" || a != Attempt(slow) {
		t.Fatalf("got (%q, %v, %v); want slow's DSN after 45 polls, one attempt", dsn, a, err)
	}
	if h.started != 1 || slow.removed {
		t.Fatalf("started %d, removed %v; want one attempt, kept", h.started, slow.removed)
	}
}

// A container that is not running is not waited on: the poll stops at once and
// a fresh container is tried.
func TestADeadContainerIsNotWaitedOnAndIsRetriedOnce(t *testing.T) {
	dead := &fakeAttempt{name: "dead", publishAfter: -1, stopAfter: 0, exitCode: 137, oom: true}
	fresh := &fakeAttempt{name: "fresh", publishAfter: 0, stopAfter: -1}
	h := newHarness(dead, fresh)
	dsn, _, err := h.waiter(90*time.Second).Start(h.start, alwaysReady)
	if err != nil || dsn != "postgres://fresh" {
		t.Fatalf("got (%q, %v); want the fresh container's DSN", dsn, err)
	}
	if dead.polls != 1 {
		t.Fatalf("the dead container was polled %d times; want once: it is not waited on", dead.polls)
	}
	if !dead.removed || h.started != 2 {
		t.Fatalf("dead removed %v, started %d; want the dead one removed and one retry", dead.removed, h.started)
	}
}

// Two attempts whose port never publishes fail naming BOTH: the container, the
// wait, the state, exit code, OOM flag and the last log lines.
func TestTwoExhaustedWindowsFailNamingBothAttempts(t *testing.T) {
	first := &fakeAttempt{name: "first", publishAfter: -1, stopAfter: -1}
	second := &fakeAttempt{name: "second", publishAfter: -1, stopAfter: -1}
	h := newHarness(first, second)
	_, _, err := h.waiter(30*time.Second).Start(h.start, alwaysReady)
	if err == nil {
		t.Fatal("two exhausted windows succeeded")
	}
	msg := err.Error()
	for _, want := range []string{
		"attempt 1: container first", "attempt 2: container second", "the port was never published",
		"status=running running=true exit_code=0 oom_killed=false", "first: last log line", "second: last log line",
		"window 30s", WaitEnv,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the failure does not name %q:\n%s", want, msg)
		}
	}
	if h.started != 2 || !first.removed || !second.removed {
		t.Fatalf("started %d, removed %v/%v; want exactly one retry and both removed", h.started, first.removed, second.removed)
	}
	// The window bounds the wait: 30 one-second polls, give or take the last.
	if first.polls < 30 || first.polls > 32 {
		t.Fatalf("the first attempt was polled %d times in a 30s window of 1s polls", first.polls)
	}
}

// A server that answers with its own error (a bad password, a missing
// database) is a real defect: it fails at once, with the server's text, and is
// never retried.
func TestAServerThatAnswersWithAnErrorFailsAtOnceAndIsNotRetried(t *testing.T) {
	up := &fakeAttempt{name: "up", publishAfter: 0, stopAfter: -1}
	spare := &fakeAttempt{name: "spare", publishAfter: 0, stopAfter: -1}
	h := newHarness(up, spare)
	pings := 0
	authFailure := func(string) error {
		pings++
		return &pq.Error{Code: "28P01", Message: `password authentication failed for user "postgres"`}
	}
	_, _, err := h.waiter(90*time.Second).Start(h.start, authFailure)
	if err == nil || !strings.Contains(err.Error(), "password authentication failed") || !strings.Contains(err.Error(), "the server answered with an error") {
		t.Fatalf("err = %v; want the server's own text, answered with an error", err)
	}
	if pings != 1 || h.started != 1 {
		t.Fatalf("pinged %d times, started %d; want one ping and no retry", pings, h.started)
	}
}

// Not answering yet (refused, or the server's own "starting up") is waited on.
func TestAServerNotAnsweringYetIsWaitedOn(t *testing.T) {
	up := &fakeAttempt{name: "up", publishAfter: 0, stopAfter: -1}
	h := newHarness(up)
	pings := 0
	warming := func(string) error {
		pings++
		switch {
		case pings < 3:
			return errors.New("dial tcp 127.0.0.1:5432: connect: connection refused")
		case pings < 5:
			return &pq.Error{Code: "57P03", Message: "the database system is starting up"}
		}
		return nil
	}
	if _, _, err := h.waiter(90*time.Second).Start(h.start, warming); err != nil || pings != 5 || h.started != 1 {
		t.Fatalf("err %v after %d pings and %d starts; want ready on the fifth ping, one attempt", err, pings, h.started)
	}
}

// A container that published its port and keeps running but never answers is
// not retried: a fresh one would meet the same thing.
func TestAPublishedPortThatNeverAnswersIsNotRetried(t *testing.T) {
	up := &fakeAttempt{name: "up", publishAfter: 0, stopAfter: -1}
	spare := &fakeAttempt{name: "spare", publishAfter: 0, stopAfter: -1}
	h := newHarness(up, spare)
	silent := func(string) error { return errors.New("read: connection reset by peer") }
	_, _, err := h.waiter(30*time.Second).Start(h.start, silent)
	if err == nil || !strings.Contains(err.Error(), "the server never answered on its published port") || h.started != 1 {
		t.Fatalf("err %v, started %d; want one attempt failing as never answered", err, h.started)
	}
}

// A start that already waited the window itself (a library wait strategy) is
// not waited on a second time, and is retried as a port never published.
func TestAStartThatAlreadyWaitedIsRetriedWithoutASecondWindow(t *testing.T) {
	waited := &waitedAttempt{fakeAttempt{name: "waited", publishAfter: -1, stopAfter: -1}}
	fresh := &fakeAttempt{name: "fresh", publishAfter: 0, stopAfter: -1}
	h := newHarness()
	started := 0
	start := func() (Attempt, error) {
		started++
		if started == 1 {
			return waited, nil
		}
		return fresh, nil
	}
	dsn, _, err := h.waiter(90*time.Second).Start(start, alwaysReady)
	if err != nil || dsn != "postgres://fresh" || waited.polls != 1 {
		t.Fatalf("got (%q, %v) after %d polls; want the fresh DSN and one poll of the waited attempt", dsn, err, waited.polls)
	}
}

type waitedAttempt struct{ fakeAttempt }

func (w *waitedAttempt) Endpoint() (string, error) {
	w.polls++
	return "", fmt.Errorf("%w: context deadline exceeded", ErrWaited)
}

func TestTheWindowDefaultsTo90sAndIsNeverBelow30s(t *testing.T) {
	for _, c := range []struct {
		env    string
		want   time.Duration
		logged bool
	}{
		{"", DefaultWait, false},
		{"10s", MinWait, true},
		{"30s", 30 * time.Second, false},
		{"2m", 2 * time.Minute, false},
	} {
		t.Setenv(WaitEnv, c.env)
		var logs []string
		got, err := Window(func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
		if err != nil || got != c.want || (len(logs) > 0) != c.logged {
			t.Errorf("%s=%q: got %s (err %v, logs %v); want %s, logged %v", WaitEnv, c.env, got, err, logs, c.want, c.logged)
		}
	}
	if DefaultWait != 90*time.Second || MinWait != 30*time.Second {
		t.Fatalf("default %s, floor %s; want 90s and 30s (master's ruling)", DefaultWait, MinWait)
	}
	t.Setenv(WaitEnv, "ninety")
	if _, err := Window(nil); err == nil || !strings.Contains(err.Error(), WaitEnv) {
		t.Fatalf("a malformed %s was accepted: %v", WaitEnv, err)
	}
}

// The port wait and the answer wait share ONE window (#4435 round 1 P2): a port
// that publishes late leaves the answer only the rest of it.
func TestThePortAndTheAnswerShareOneWindow(t *testing.T) {
	late := &fakeAttempt{name: "late", publishAfter: 20, stopAfter: -1}
	h := newHarness(late)
	pings := 0
	silent := func(string) error { pings++; return errors.New("connection refused") }
	_, _, err := h.waiter(30*time.Second).Start(h.start, silent)
	if err == nil || !strings.Contains(err.Error(), "the server never answered on its published port") {
		t.Fatalf("err = %v; want never answered", err)
	}
	if late.polls+pings > 32 {
		t.Fatalf("%d port polls + %d pings in a 30s window of 1s polls; the two phases ran two windows", late.polls, pings)
	}
}

// A start that itself waits (a library wait strategy) spends the same window:
// the answer phase gets only what is left of it (#4435 round 1 F2).
func TestAStartThatWaitsSpendsTheSameWindow(t *testing.T) {
	up := &fakeAttempt{name: "up", publishAfter: 0, stopAfter: -1}
	h := newHarness()
	start := func() (Attempt, error) {
		h.clock.sleep(25 * time.Second) // the library's own wait
		return up, nil
	}
	pings := 0
	silent := func(string) error { pings++; return errors.New("connection refused") }
	if _, _, err := h.waiter(30*time.Second).Start(start, silent); err == nil {
		t.Fatal("a server that never answered was ready")
	}
	if pings > 7 {
		t.Fatalf("%d pings after a start that took 25s of a 30s window; want at most the 5s left", pings)
	}
}

// A retry is a FRESH container: one that came back under the first attempt's
// name is refused rather than waited on as if it were new.
func TestARetryThatReusesTheContainerNameIsRefused(t *testing.T) {
	dead := &fakeAttempt{name: "same", publishAfter: -1, stopAfter: 0}
	again := &fakeAttempt{name: "same", publishAfter: 0, stopAfter: -1}
	h := newHarness(dead, again)
	_, _, err := h.waiter(30*time.Second).Start(h.start, alwaysReady)
	if err == nil || !strings.Contains(err.Error(), "reused the first attempt's container name same") {
		t.Fatalf("err = %v; want the reused name refused", err)
	}
	if !again.removed {
		t.Fatal("the reused-name container was not removed")
	}
}

// A container whose state cannot be read (removed under the wait) is NOT taken
// for stopped: it costs a full window, then the retry, and the report says its
// state was unreadable (#4435 round 2 L1; the package doc's third statement).
func TestAContainerWhoseStateCannotBeReadCostsAFullWindow(t *testing.T) {
	gone := &fakeAttempt{name: "gone", publishAfter: -1, stopAfter: -1, stateErr: true}
	fresh := &fakeAttempt{name: "fresh", publishAfter: 0, stopAfter: -1}
	var logs []string
	h := newHarness(gone, fresh)
	w := h.waiter(30 * time.Second)
	w.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	dsn, _, err := w.Start(h.start, alwaysReady)
	if err != nil || dsn != "postgres://fresh" {
		t.Fatalf("got (%q, %v); want the fresh container after the retry", dsn, err)
	}
	if gone.polls < 30 {
		t.Fatalf("the unreadable container was polled %d times; want the full 30s window of 1s polls", gone.polls)
	}
	joinedLogs := strings.Join(logs, "\n")
	if !strings.Contains(joinedLogs, "state unreadable: docker inspect: No such object: gone") || !strings.Contains(joinedLogs, "the port was never published") {
		t.Fatalf("the retry's report does not say the state was unreadable:\n%s", joinedLogs)
	}
}
