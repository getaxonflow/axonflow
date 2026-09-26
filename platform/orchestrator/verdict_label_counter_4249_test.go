// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// TestTheOrchestratorCounterSitesCountUnderTheWireLabels drives five counter
// sites in four of the orchestrator's six counting files that record through
// the home constants (#4249 row 5666277893; the response seam and the step
// action admission are covered by the guard and the label census only) and
// reads the series back by the WIRE label, as a dashboard
// would: a constant that drifted from its spelling would count under a series
// no query names, and this fails.
func TestTheOrchestratorCounterSitesCountUnderTheWireLabels(t *testing.T) {
	read := func(scope legacycompile.EnforcementScope, verdict, reason string) float64 {
		return promtestutil.ToFloat64(anchoredenforcer.Decisions.WithLabelValues(scope.String(), anchoredenforcer.EngineAnchored, verdict, reason))
	}
	for _, c := range []struct {
		name            string
		scope           legacycompile.EnforcementScope
		verdict, reason string
		drive           func()
	}{
		{"route_request_enforcing_seam.go routeRequestUnavailable", orchestratorRequestSeamScope, "unavailable", anchoredenforcer.CauseNotWired,
			func() { routeRequestUnavailable(anchoredenforcer.CauseNotWired) }},
		{"wcp_enforcing_seam.go stepGateUnavailable", wcpSeamScope, "unavailable", anchoredenforcer.CauseNotWired,
			func() { stepGateUnavailable(anchoredenforcer.CauseNotWired) }},
		{"wcp_enforcing_seam.go stepGateSegmentResolutionFailed", wcpSeamScope, "unavailable", anchoredenforcer.CauseEvaluation,
			func() { stepGateSegmentResolutionFailed() }},
		{"map_enforcing_seam.go mapStepUnavailable", mapSeamScope, "unavailable", anchoredenforcer.CauseNotWired,
			func() { mapStepUnavailable(anchoredenforcer.CauseNotWired) }},
		{"step_request_body_cap.go recordStepBodyRefused", wcpSeamScope, "deny", workflow_control.RequestTooLarge,
			func() { recordStepBodyRefused(wcpSeamScope) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := read(c.scope, c.verdict, c.reason)
			c.drive()
			if got := read(c.scope, c.verdict, c.reason) - before; got != 1 {
				t.Fatalf("the series {%s, %s} moved by %v, want 1", c.verdict, c.reason, got)
			}
		})
	}
}
