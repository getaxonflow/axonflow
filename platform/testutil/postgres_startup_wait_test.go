// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package testutil

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go/exec"
)

// deadlineTarget is a wait.StrategyTarget that records the ABSOLUTE deadline
// each phase runs under: Logs answers the ready line twice after a measurable
// delay, and MappedPort records its deadline and cancels the wait, so the cell
// never waits a real window. The delay is what separates one shared deadline
// (both phases end at the same instant) from one deadline each (the port
// phase's would end the delay later).
type deadlineTarget struct {
	cancel       context.CancelFunc
	logDeadline  time.Time
	portDeadline time.Time
}

// logPhaseDelay is how long the log phase takes in the cell.
const logPhaseDelay = 200 * time.Millisecond

func (d *deadlineTarget) Host(context.Context) (string, error) { return "localhost", nil }
func (d *deadlineTarget) Inspect(context.Context) (*container.InspectResponse, error) {
	return nil, errors.New("not inspected in this cell")
}
func (d *deadlineTarget) Ports(context.Context) (network.PortMap, error) { return nil, nil }
func (d *deadlineTarget) MappedPort(ctx context.Context, _ string) (network.Port, error) {
	d.portDeadline, _ = ctx.Deadline()
	d.cancel()
	return network.Port{}, errors.New("stopped by the cell")
}
func (d *deadlineTarget) Logs(ctx context.Context) (io.ReadCloser, error) {
	d.logDeadline, _ = ctx.Deadline()
	time.Sleep(logPhaseDelay)
	line := "database system is ready to accept connections\n"
	return io.NopCloser(strings.NewReader(line + line)), nil
}
func (d *deadlineTarget) Exec(context.Context, []string, ...exec.ProcessOption) (int, io.Reader, error) {
	return 0, nil, errors.New("not exec'd in this cell")
}
func (d *deadlineTarget) State(context.Context) (*container.State, error) {
	return &container.State{Running: true, Status: "running"}, nil
}
func (d *deadlineTarget) CopyFileFromContainer(context.Context, string) (io.ReadCloser, error) {
	return nil, errors.New("not copied in this cell")
}

// The library wait runs under the WHOLE window above the library's 60s default
// (#4435 round 1 F1: a window of 90s or 2m ran every child under 60s), and both
// phases share ONE deadline (round 2 FIX-1): the port phase ends at the same
// instant as the log phase, t0+window, not a window after it starts.
func TestTheStartupWaitRunsUnderTheWholeWindow(t *testing.T) {
	const slack = 50 * time.Millisecond
	for _, window := range []time.Duration{30 * time.Second, 90 * time.Second, 2 * time.Minute} {
		ctx, cancel := context.WithCancel(context.Background())
		target := &deadlineTarget{cancel: cancel}
		t0 := time.Now()
		_ = startupWait(window).WaitUntilReady(ctx, target)
		cancel()
		want := t0.Add(window)
		if target.logDeadline.IsZero() || target.portDeadline.IsZero() {
			t.Fatalf("window %s: a phase ran with no deadline (log %v, port %v)", window, target.logDeadline, target.portDeadline)
		}
		if d := target.logDeadline.Sub(want); d < 0 || d > slack {
			t.Errorf("window %s: the log phase's deadline is %s from t0+window; want t0+window", window, d)
		}
		if !target.portDeadline.Equal(target.logDeadline) {
			t.Errorf("window %s: the port phase's deadline is %s after the log phase's; want one shared deadline", window, target.portDeadline.Sub(target.logDeadline))
		}
	}
}
