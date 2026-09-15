// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// The agent half of the /health cross-plane parity contract (#3901 §3).
// platform/orchestrator/health_parity_test.go is the other half. The two cannot
// be one test: platform/orchestrator imports platform/agent, so no test here
// can reach the orchestrator's handler. Both CALL their handler rather than
// reading its source.

package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/shared/heartbeat"
)

func driveAgentHealth(t *testing.T) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	readinessAwareHealthHandler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health returned %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("GET /health returned Content-Type %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET /health did not return decodable JSON: %v\nbody: %s", err, rec.Body.String())
	}
	return body
}

// TestAgentHealthCarriesEveryCrossPlaneMember.
//
// IT DRIVES readinessAwareHealthHandler AND NOT healthHandler, and that
// distinction is the whole reason this test can be trusted: healthHandler
// (run.go) is a stale duplicate registered on NO route, and a previous change
// asserted against it and reported a member as present while a live agent
// returned null for it. The handler under test here is the one run.go registers.
func TestAgentHealthCarriesEveryCrossPlaneMember(t *testing.T) {
	body := driveAgentHealth(t)

	// ANTI-VACUITY, and it is about the CONTRACT LIST rather than the body.
	//
	// R3 killed the previous version of this block: it compared the body's
	// member count against the contract list's length, which can only be true
	// in cases where the missing-member loop below also reports. It turned an
	// Error into a Fatal and asserted nothing of its own, under a comment
	// claiming it measured "what the body demonstrably carries" - which it did
	// not; it measured the length of a list in another package.
	//
	// The real vacuity risk is the OTHER side: an empty contract list makes the
	// loop below iterate zero times and pass against any body at all, including
	// `{}`. That is what this guards.
	contract := heartbeat.HealthMembersBothPlanesMustCarry()
	if len(contract) < 5 {
		t.Fatalf("the cross-plane /health contract names only %d member(s). The loop below iterates "+
			"over it, so a short or empty list passes against ANY response body - including one that "+
			"carries nothing at all.", len(contract))
	}

	var missing []string
	for _, m := range contract {
		if _, ok := body[m]; !ok {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("GET /health on the AGENT omits %v, which the orchestrator's /health carries. "+
			"A client that probes whichever port it can reach must get the same answer (#3901 §3).",
			missing)
	}
}
