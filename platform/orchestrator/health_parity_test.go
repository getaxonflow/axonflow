// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// The orchestrator half of the /health cross-plane parity contract (#3901 §3).
// platform/agent/health_parity_test.go is the other half. Neither reads source:
// each CALLS its plane's handler and reads the JSON that came back.

package orchestrator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/shared/heartbeat"
)

// driveOrchestratorHealth calls the registered /health handler and returns the
// decoded body. It is a real request through a real ResponseWriter, so a
// handler that wrote nothing, wrote non-JSON, or panicked fails here rather
// than being read as agreement.
func driveOrchestratorHealth(t *testing.T) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	healthHandler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health returned %d, want 200; nothing below is evidence about the body", rec.Code)
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

// TestOrchestratorHealthCarriesEveryCrossPlaneMember is the driven half of the
// rule this handler's own comment has stated since #3660.
func TestOrchestratorHealthCarriesEveryCrossPlaneMember(t *testing.T) {
	body := driveOrchestratorHealth(t)

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
		t.Errorf("GET /health on the ORCHESTRATOR omits %v. This handler's own comment states the rule "+
			"it breaks - \"a client that probes whichever port it can reach must get the same "+
			"answer\" - and the agent's /health carries these. #3901 §3.", missing)
	}
}

// TestOrchestratorHealthTierIsTheLicenceVocabulary pins WHICH `tier` this is.
//
// `tier` names two unrelated vocabularies across this API (#3901 §4): the
// licence tier, and the policy SCOPE tier that GET /api/v1/policies?tier= takes.
// A developer arriving from /health will reach for the wrong one, so the value
// here is asserted to be from the licence set rather than merely non-empty.
func TestOrchestratorHealthTierIsTheLicenceVocabulary(t *testing.T) {
	body := driveOrchestratorHealth(t)
	tier, ok := body["tier"].(string)
	if !ok {
		t.Fatalf("GET /health `tier` is %T, not a string", body["tier"])
	}
	licenceTiers := map[string]bool{
		"starting": true, "community": true, "evaluation": true,
		"professional": true, "enterprise": true,
	}
	scopeTiers := map[string]bool{"system": true, "organization": true, "tenant": true}
	if scopeTiers[tier] {
		t.Fatalf("GET /health reported tier=%q, which is a POLICY SCOPE tier. /health must report the "+
			"LICENCE tier; the two vocabularies share a name and nothing else (#3901 §4).", tier)
	}
	if !licenceTiers[tier] {
		t.Errorf("GET /health reported tier=%q, which is in neither the licence vocabulary %v nor the "+
			"scope vocabulary. A tier a client cannot interpret is worse than an absent one.",
			tier, licenceTiers)
	}
}
