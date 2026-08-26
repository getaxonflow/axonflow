// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package queue

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

// hitlEnqueueTotal counts every enqueue attempt through the chokepoint,
// classified by outcome.
//
// WHY A COUNTER IS PART OF THE FIX, not decoration. #3509's defining property
// was that the failure was INVISIBLE: fincrime_seam.go:186 logged the enqueue
// error and let the verdict stand, so a deployment could hold callers for
// months with an empty review queue and nothing on any dashboard said so. The
// WCP plane had the same shape one file over - wcp_policy_adapter.go's
// createHITLApproval logged and returned uuid.Nil. A refusal that only exists
// in stdout is a refusal nobody operates on.
//
// NAME. #3514 (in flight, branch ws-hitl-3509-enqueue) introduces
// `axonflow_hitl_policy_enqueue_total{plane,outcome}` in package
// platform/agent for the policy-authored step-up plane. This is the same
// PATTERN with a distinct name on purpose: platform/orchestrator imports
// platform/agent, so both collectors can end up linked into one binary, and
// two registrations of the same metric name would panic at init. Converging
// the two names once #3514 lands is tracked as a checklist row on #3408.
var hitlEnqueueTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_hitl_enqueue_total",
		Help: "HITL approval-queue enqueue attempts through the shared chokepoint, by plane and outcome (created|reused|cap_reached|tier_disabled|error).",
	},
	[]string{"plane", "outcome"},
)

// hitlMirrorResolveTotal counts WCP step-gate mirror resolutions by outcome
// (#3408). "not_pending" is the benign case - no adapter was wired when the
// gate fired, or the mirror was already terminal - and it is COUNTED rather
// than logged so an operator can tell "this deployment writes no mirrors" from
// "this deployment's mirrors are failing to resolve", which is precisely the
// distinction that was unavailable while the phantom row existed.
var hitlMirrorResolveTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_hitl_mirror_resolve_total",
		Help: "WCP step-gate HITL mirror resolutions, by outcome (approved|rejected|not_pending|no_org|error).",
	},
	[]string{"outcome"},
)

// RecordMirrorResolve is the exported hook the orchestrator's resolver calls.
func RecordMirrorResolve(outcome string) {
	if outcome == "" {
		outcome = string(OutcomeError)
	}
	hitlMirrorResolveTotal.WithLabelValues(outcome).Inc()
}

func init() {
	// prometheus.Register rather than MustRegister: this package is linked
	// into the agent binary, the orchestrator binary AND every test binary
	// that touches either, and a duplicate registration must not take a
	// process down over a counter. AlreadyRegisteredError is the only
	// tolerable failure - anything else is a real wiring problem and is
	// logged rather than swallowed.
	register("axonflow_hitl_enqueue_total", hitlEnqueueTotal)
	register("axonflow_hitl_mirror_resolve_total", hitlMirrorResolveTotal)
}

func register(name string, c prometheus.Collector) {
	if err := prometheus.Register(c); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			log.Printf("[HITL] WARN: could not register %s: %v", name, err)
		}
	}
}

// recordEnqueue increments the counter. An empty outcome (a code path that
// returned without classifying itself) is recorded as "error" rather than
// dropped: a silent gap in this counter is the very thing it exists to stop.
func recordEnqueue(plane string, outcome Outcome) {
	if outcome == "" {
		outcome = OutcomeError
	}
	hitlEnqueueTotal.WithLabelValues(plane, string(outcome)).Inc()
}
