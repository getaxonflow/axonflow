// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logutil "axonflow/platform/shared/logger"
)

// AN UPSTREAM THE AGENT HAS NOT YET REACHED IS NOT AN ERROR THE CLIENT CAUSED
// (#4249 row 5681489141, fix shape (a)).
//
// On a fresh install the agent serves before the orchestrator listens (13.8s
// measured on compose). Every governed request it forwarded in that window
// failed to connect, and each failure was recorded against the CLIENT's
// circuit: after ten the circuit opened and refused that client's governed
// requests with 503 for five minutes after the orchestrator was up. It is
// #4280's rule (a response a governance plane withheld is not an error the
// client caused), one step further out: a connection that was never
// established asked nothing of the upstream.
//
// So a DIAL failure is not recorded while the upstream has never answered.
// The first HTTP response of any status from it, from a forwarded request or
// from the one-shot readiness probe (startUpstreamReadinessProbe), marks it
// reached for the life of the process, and from then on every failure counts
// as before: an orchestrator that goes away mid-life still opens circuits.
// The request itself is refused as before (500 on the forward, 502 on the
// proxy); only the circuit's count changes.
//
// The breaker is an Enterprise feature (the community build's RecordError is
// a no-op), so on Community this changes nothing observable but /health.

// upstreamOrchestrator is the service name the orchestrator is tracked under,
// shared by forwardToOrchestrator and the orchestrator reverse proxy.
const upstreamOrchestrator = "orchestrator"

var upstreamReach sync.Map // service name -> *atomic.Bool

func upstreamReachedFlag(service string) *atomic.Bool {
	v, _ := upstreamReach.LoadOrStore(service, new(atomic.Bool))
	return v.(*atomic.Bool)
}

// markUpstreamReached records that service answered once.
func markUpstreamReached(service string) {
	if !upstreamReachedFlag(service).Swap(true) {
		log.Printf("[Upstream] %s reached: its failures now count against the client's circuit", logutil.Sanitize(service))
	}
}

// upstreamReached reports whether service has answered at least once.
func upstreamReached(service string) bool {
	return upstreamReachedFlag(service).Load()
}

// isDialFailure reports whether err is a failure to establish the connection
// (connection refused, no such host, a dial timeout), as opposed to a failure
// after the upstream accepted it.
func isDialFailure(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}

// upstreamErrorCountsAgainstClient reports whether a transport error from
// service is recorded against the client's circuit.
//
// THE EXEMPTION IS THE ORCHESTRATOR'S ALONE (master R3 round 1 on this PR).
// It rests on something marking the upstream reached: the forward, the
// orchestrator proxy, or the one-shot readiness probe. The agent probes only
// the orchestrator and /health reports only the orchestrator, so for any other
// upstream - the customer portal, which createReverseProxy also serves - the
// flag would never be set and a dial failure would be exempt for the life of
// the process, which is a wider exemption than the row asks for and one no
// signal would ever end. Every other service keeps the base behaviour.
func upstreamErrorCountsAgainstClient(service string, err error) bool {
	if service != upstreamOrchestrator {
		return true
	}
	if upstreamReached(service) {
		return true
	}
	return !isDialFailure(err)
}

// upstreamHealth is the /health `upstream` member (#4249 row 5681489141, (b)):
// whether the orchestrator has answered since this process started. It is
// ADDITIVE: `status` and the HTTP code do not read it, because the compose
// files start the orchestrator only once the agent is healthy, so gating the
// agent's health on the orchestrator would deadlock a fresh install.
func upstreamHealth() map[string]string {
	return map[string]string{upstreamOrchestrator: upstreamHealthFor(upstreamOrchestrator)}
}

// upstreamHealthFor is one upstream's /health state.
func upstreamHealthFor(service string) string {
	if upstreamReached(service) {
		return "reached"
	}
	return "unreached"
}

// upstreamProbeInterval and upstreamProbeTimeout bound the readiness probe.
var (
	upstreamProbeInterval = time.Second
	upstreamProbeTimeout  = 2 * time.Second
)

// startUpstreamReadinessProbe polls baseURL's /health until the first HTTP
// response of any status, marks service reached, and stops. It never runs
// again in the process's life, so it costs one request a second only while
// the upstream has never answered.
func startUpstreamReadinessProbe(service, baseURL string) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" || upstreamReached(service) {
		return
	}
	client := &http.Client{Timeout: upstreamProbeTimeout}
	interval := upstreamProbeInterval
	go func() {
		// The loop also ends when a forwarded request marks the upstream
		// reached first.
		for !upstreamReached(service) {
			resp, err := client.Get(baseURL + "/health")
			if err == nil {
				_ = resp.Body.Close()
				markUpstreamReached(service)
				return
			}
			time.Sleep(interval)
		}
	}()
}
