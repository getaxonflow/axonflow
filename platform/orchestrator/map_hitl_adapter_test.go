// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/license"
)

// mockPolicyEngineForHITL implements the dynamicPolicyEngine interface for CheckPolicy tests.
type mockPolicyEngineForHITL struct {
	result *PolicyEvaluationResult
}

func (m *mockPolicyEngineForHITL) EvaluateDynamicPolicies(_ context.Context, _ OrchestratorRequest) *PolicyEvaluationResult {
	return m.result
}

func (m *mockPolicyEngineForHITL) ListActivePolicies() []DynamicPolicy {
	return nil
}

func (m *mockPolicyEngineForHITL) ListActivePoliciesForTenant(_ string, _ []string) []DynamicPolicy {
	return nil
}

func (m *mockPolicyEngineForHITL) ListActivePoliciesForOrgInEverySegment(_ string) []DynamicPolicy {
	return nil
}

func (m *mockPolicyEngineForHITL) IsHealthy() bool {
	return true
}

func TestMapStepApproveHandler_CommunityNoLicense(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	origTier := tierChecker
	tierChecker = nil // no license — community + no eval = rejected
	defer func() { tierChecker = origTier }()

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/approve", mapStepApproveHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/approve", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for community mode without license, got %d", w.Code)
	}
}

func TestMapStepRejectHandler_CommunityNoLicense(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	origTier := tierChecker
	tierChecker = nil
	defer func() { tierChecker = origTier }()

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/reject", mapStepRejectHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/reject",
		strings.NewReader(`{"reason":"test rejection"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for community mode without license, got %d", w.Code)
	}
}

// TestMapStepApproveHandler_CommunityWithEvalLicenseBypassesTierCheck asserts
// that community mode + Evaluation license passes the tier check (matching
// WCP's /approve behavior). The handler then falls through to the workflow
// control plane lookup, which finds no workflow for the plan and answers 404
// (#4249 row 5774060413 retired the in-memory pause that answered 503 here) -
// that's fine; what we're pinning here is that the tier gate no longer 403s on
// Evaluation callers.
//
// R3 round 2: the mock now carries the TIER, not just hitlEnabled. It used to
// set `hitlEnabled: true` alone and leave `tier` at its zero value, so the
// fixture asserted "a checker that says HITL is on" rather than "an Evaluation
// licence" - the exact conflation this release separates. Since the
// 2026-08-26 decision Evaluation is NOT entitled to create approvals while it
// IS entitled to resolve them, so a fixture that cannot tell the two apart
// cannot pin either. With the tier set, this test now fails if the resolve
// gate is ever collapsed back onto the creation entitlement.
func TestMapStepApproveHandler_CommunityWithEvalLicenseBypassesTierCheck(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	origTier := tierChecker
	origEnabled := hitlEnabled
	tierChecker = &mockLicenseCheckerForSim{tier: license.TierEvaluation, hitlEnabled: false}
	hitlEnabled = false // the flag is a no-op since #4382; set to show it changes nothing
	defer func() {
		tierChecker = origTier
		hitlEnabled = origEnabled
	}()

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/approve", mapStepApproveHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/approve", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Not 403 — that would mean the tier gate rejected Evaluation.
	if w.Code == http.StatusForbidden {
		t.Errorf("community + eval license should bypass tier gate, got 403: %s", w.Body.String())
	}
	// Expect 404: the tier gate passed and no workflow backs the plan.
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 no paused execution, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMapStepRejectHandler_ResponseFormat(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/reject", mapStepRejectHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/reject",
		strings.NewReader(`{"reason":"compliance violation"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["error"] == nil {
		t.Error("expected error field in response")
	}
}

// A MAP approve or reject that no workflow control plane workflow backs answers
// 404 "No paused execution found for this plan", whatever AXONFLOW_HITL_ENABLED
// says (#4249 row 5774060413). The in-memory pause that used to answer here
// (503 while its engine was unwired, otherwise a scan of a process-local store
// nothing has written since #4382) is retired: the workflow control plane is
// the one place a multi-agent step is held.
func TestAMAPApproveOrRejectNoWorkflowBacksAnswersNotFound(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)
	origEnabled := hitlEnabled
	t.Cleanup(func() { hitlEnabled = origEnabled })

	for _, tc := range []struct {
		verb    string
		handler http.HandlerFunc
		body    string
	}{
		{"approve", mapStepApproveHandler, ""},
		{"reject", mapStepRejectHandler, `{"reason":"not needed"}`},
	} {
		for _, enabled := range []bool{false, true} {
			hitlEnabled = enabled
			r := mux.NewRouter()
			r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/"+tc.verb, tc.handler).Methods("POST")
			req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/"+tc.verb, strings.NewReader(tc.body))
			req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			var resp map[string]interface{}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if w.Code != http.StatusNotFound || resp["error"] != "No paused execution found for this plan" {
				t.Errorf("%s with AXONFLOW_HITL_ENABLED=%v = %d %s, want 404 \"No paused execution found for this plan\"", tc.verb, enabled, w.Code, w.Body.String())
			}
		}
	}
}
