// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package pgstart is the one wait-and-retry rule the Real-PG test helpers start
// a throwaway Postgres container under (#4249 rows 5771426373, 5796048780).
//
// Two helpers start those containers: approletest's startPostgresContainer (the
// docker CLI) and testutil.StartPostgres (testcontainers). Both used to give a
// container a fixed 30 seconds, or none, to publish its port. On a daemon other
// lanes' boards are also starting containers on, that fixed window was short,
// and whichever Real-PG test started its container in a busy moment went red;
// alone it passed. The tests were never the variable, so the rule lives here and
// no test body changes.
//
// The rule:
//   - ONE window per attempt covers publishing the port and the first answer.
//     It is AXONFLOW_TEST_PG_START_WAIT (a Go duration), default 90s, never
//     below 30s.
//   - Every failed poll also reads the container's state. A container that is
//     not running is not waited on: waiting longer on a dead container only
//     delays the same red.
//   - ONE retry, with a fresh container carrying the same labels, and only when
//     the container is not running or the window ran out with the port never
//     published. A server that answers with a database or authentication error
//     is a real defect: it fails at once, with the server's text, and is never
//     retried.
//   - A double failure names BOTH attempts: the container, how long it was
//     waited on, its state, exit code and OOM flag, and its last log lines.
//
// Bounds and reads, stated so nobody has to derive them:
//   - An attempt's window runs from when it BEGAN starting the container, so
//     an attempt takes at most max(start, window) plus a poll, where start is
//     the time start() itself took. For approletest start is `docker run`; for
//     testutil it is the image pull and create PLUS the library wait, which
//     may use the whole window. A helper call is at most two such attempts:
//     two windows plus EACH attempt's start overrun, not only the retry's.
//   - The window is read on EVERY helper call, not once per process: a
//     t.Setenv between two calls changes the second call's window.
//   - A container removed under the wait makes every state read fail, so it
//     is not seen as stopped: it costs a full window, then the retry, and the
//     report says its state was unreadable. Safe, only slower.
package pgstart

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lib/pq"
)

// WaitEnv names the start window, a Go duration (for example "2m").
const WaitEnv = "AXONFLOW_TEST_PG_START_WAIT"

const (
	// DefaultWait is the window when WaitEnv is unset.
	DefaultWait = 90 * time.Second
	// MinWait is the floor: a smaller WaitEnv is raised to it.
	MinWait = 30 * time.Second
	// LogLines is how many of a failed container's last log lines are reported.
	LogLines = 20
)

// Window returns the start window WaitEnv sets, DefaultWait when it is unset,
// raised to MinWait (and logged) when it is smaller. A value that is not a
// duration is an error, so a typo never silently means the default.
func Window(logf func(format string, args ...any)) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(WaitEnv))
	if raw == "" {
		return DefaultWait, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a Go duration (for example 2m): %v", WaitEnv, raw, err)
	}
	if d < MinWait {
		if logf != nil {
			logf("pgstart: %s=%s is below the %s floor; waiting %s", WaitEnv, d, MinWait, MinWait)
		}
		return MinWait, nil
	}
	return d, nil
}

// State is what the daemon says about a container.
type State struct {
	Running   bool
	Status    string
	ExitCode  int
	OOMKilled bool
}

func (s State) String() string {
	return fmt.Sprintf("status=%s running=%v exit_code=%d oom_killed=%v", s.Status, s.Running, s.ExitCode, s.OOMKilled)
}

// Attempt is one started container.
type Attempt interface {
	// Name identifies the container in a report.
	Name() string
	// Endpoint is the DSN once the daemon has published the port, or an
	// error while it has not.
	Endpoint() (string, error)
	// State reads the container's state from the daemon.
	State() (State, error)
	// Logs returns the container's last n log lines.
	Logs(n int) string
	// Remove removes the container and its anonymous volume.
	Remove()
}

// ErrWaited is what an Attempt's Endpoint wraps when starting the container
// already waited the window itself (a library wait strategy) and gave up: the
// Waiter does not wait a second window on it, and treats it as a port never
// published.
var ErrWaited = errors.New("the start's own wait for the published port ran out")

// Ready is one readiness probe against a DSN. nil means the server answered.
type Ready func(dsn string) error

// Transient reports whether a readiness error means "not answering yet"
// rather than "answered with an error". A server that answers is a pq.Error;
// the one it answers while it is still starting (57P03, cannot_connect_now) is
// transient, and every other is the server's own refusal (a bad password, a
// missing database, a missing role): a real defect.
func Transient(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == "57P03"
	}
	return true
}

// Waiter runs the rule. Now, Sleep and Poll are injectable so the rule is
// testable without a daemon; the zero value uses the wall clock and polls
// every 250ms.
type Waiter struct {
	Window time.Duration
	Now    func() time.Time
	Sleep  func(time.Duration)
	Poll   time.Duration
	Logf   func(format string, args ...any)
}

func (w Waiter) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w Waiter) sleep() {
	d := w.Poll
	if d <= 0 {
		d = 250 * time.Millisecond
	}
	if w.Sleep != nil {
		w.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (w Waiter) logf(format string, args ...any) {
	if w.Logf != nil {
		w.Logf(format, args...)
	}
}

// Outcome is how one attempt ended.
type Outcome struct {
	// DSN is set when the attempt is ready.
	DSN string
	// Retryable is true when a fresh container may be tried: this one is not
	// running, or its port was never published within the window.
	Retryable bool
	// Err is the failure; nil when ready.
	Err error
	// Report describes a failed attempt: container, wait, state, logs.
	Report string
}

// Wait waits on one started container under the rule, and removes it when it
// fails. The window runs from now.
func (w Waiter) Wait(a Attempt, ready Ready) Outcome {
	return w.waitSince(w.now(), a, ready)
}

// waitSince is Wait with the window running from start: Start passes the
// moment it began starting the container, so a start that itself waits (a
// library wait strategy) spends the same window, and an attempt never takes
// longer than one window plus a poll.
func (w Waiter) waitSince(start time.Time, a Attempt, ready Ready) Outcome {
	deadline := start.Add(w.Window)
	fail := func(retryable bool, phase string, cause error) Outcome {
		st, stErr := a.State()
		state := st.String()
		if stErr != nil {
			state = "unreadable: " + stErr.Error()
		}
		report := fmt.Sprintf("container %s, waited %s (window %s), %s, last error: %v; state %s; last %d log lines:\n%s",
			a.Name(), w.now().Sub(start).Round(time.Millisecond), w.Window, phase, cause, state, LogLines, strings.TrimRight(a.Logs(LogLines), "\n"))
		a.Remove()
		return Outcome{Retryable: retryable, Err: fmt.Errorf("%s: %v", phase, cause), Report: report}
	}
	notRunning := func() bool {
		st, err := a.State()
		return err == nil && !st.Running
	}

	var dsn string
	for {
		ep, err := a.Endpoint()
		if err == nil {
			dsn = ep
			break
		}
		if notRunning() {
			return fail(true, "the container stopped before its port was published", err)
		}
		if errors.Is(err, ErrWaited) || !w.now().Before(deadline) {
			return fail(true, "the port was never published", err)
		}
		w.sleep()
	}
	for {
		err := ready(dsn)
		if err == nil {
			return Outcome{DSN: dsn}
		}
		if !Transient(err) {
			return fail(false, "the server answered with an error", err)
		}
		if notRunning() {
			return fail(true, "the container stopped before it answered", err)
		}
		if !w.now().Before(deadline) {
			return fail(false, "the server never answered on its published port", err)
		}
		w.sleep()
	}
}

// Start starts a container with start and waits on it, retrying ONCE with a
// fresh container when the first attempt's outcome is retryable. It returns the
// ready DSN and the attempt that holds it; the caller removes that one. A
// failure names every attempt.
//
// Each attempt takes at most max(start, window) plus a poll, the window
// running from when it began starting the container (see the package doc for
// what start is per helper). A retry that reused the first attempt's container
// name is refused: it would be the same container, not a fresh one.
func (w Waiter) Start(start func() (Attempt, error), ready Ready) (string, Attempt, error) {
	var reports []string
	var firstName string
	for n := 1; n <= 2; n++ {
		began := w.now()
		a, err := start()
		if err != nil {
			reports = append(reports, fmt.Sprintf("attempt %d: the container could not be started: %v", n, err))
			return "", nil, joined(reports)
		}
		if n == 1 {
			firstName = a.Name()
		} else if a.Name() == firstName {
			a.Remove()
			reports = append(reports, fmt.Sprintf("attempt %d: the retry reused the first attempt's container name %s, so it is not a fresh container", n, firstName))
			return "", nil, joined(reports)
		}
		out := w.waitSince(began, a, ready)
		if out.Err == nil {
			if n > 1 {
				w.logf("pgstart: attempt %d is ready after attempt 1 failed:\n%s", n, reports[0])
			}
			return out.DSN, a, nil
		}
		reports = append(reports, fmt.Sprintf("attempt %d: %s", n, out.Report))
		if !out.Retryable {
			return "", nil, joined(reports)
		}
		w.logf("pgstart: retrying with a fresh container:\n%s", reports[len(reports)-1])
	}
	return "", nil, joined(reports)
}

func joined(reports []string) error {
	return fmt.Errorf("a throwaway Postgres container did not become ready (%s, default %s, floor %s):\n%s",
		WaitEnv, DefaultWait, MinWait, strings.Join(reports, "\n"))
}
