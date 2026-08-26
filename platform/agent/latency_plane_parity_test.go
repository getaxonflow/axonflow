// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	sharedaudit "axonflow/platform/shared/audit"
)

// TestLatencyProviderPlaneMatchesAgentConstant pins the one string that decides
// which rows the portal's Avg Latency tile refuses to average (#3424).
//
// sharedaudit.LatencyEnforcementPredicate excludes plane='llm' because that
// plane's response_time_ms is a PROVIDER round trip, not an enforcement
// duration -- measured live, three such rows among 53 moved the tile from 5ms
// to 724ms. The predicate cannot import this package (the dependency runs the
// other way), so it carries its own copy of the literal. If PlaneLLM is ever
// renamed and the copy is not, the exclusion silently stops matching and the
// provider round trips quietly rejoin the enforcement average with nothing
// failing anywhere.
func TestLatencyProviderPlaneMatchesAgentConstant(t *testing.T) {
	if sharedaudit.LatencyProviderPlane != PlaneLLM {
		t.Fatalf("sharedaudit.LatencyProviderPlane = %q but agent.PlaneLLM = %q.\n"+
			"The Avg Latency tile excludes rows by the FIRST string and the writer stamps them "+
			"with the SECOND, so they must be identical or the exclusion is a no-op.",
			sharedaudit.LatencyProviderPlane, PlaneLLM)
	}
}
