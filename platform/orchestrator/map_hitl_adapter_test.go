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

	"github.com/google/uuid"
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
// WCP's /approve behavior). The handler then falls through to the HITL
// availability check, which returns 503 because hitlEnabled is false in
// these tests — that's fine; what we're pinning here is that the tier gate
// no longer 403s on Evaluation callers.
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
	hitlEnabled = false // ensure we stop at the HITL-enabled check, not the tier check
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
	// Expect 503 because hitlEnabled is false — tier gate already passed by here.
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 HITL-disabled, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMapStepApproveHandler_HITLDisabled(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	origEnabled := hitlEnabled
	origEngine := hitlWorkflowEngine
	defer func() {
		hitlEnabled = origEnabled
		hitlWorkflowEngine = origEngine
	}()
	hitlEnabled = false
	hitlWorkflowEngine = nil

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/approve", mapStepApproveHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/approve", nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when HITL disabled, got %d", w.Code)
	}
}

func TestMapStepApproveHandler_NoPausedExecution(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	origEnabled := hitlEnabled
	origEngine := hitlWorkflowEngine
	defer func() {
		hitlEnabled = origEnabled
		hitlWorkflowEngine = origEngine
	}()
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/approve", mapStepApproveHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/approve", nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no paused execution, got %d", w.Code)
	}
}

func TestMAPHITLApprovalAdapter_CreateApproval(t *testing.T) {
	adapter := &MAPHITLApprovalAdapter{}

	resp, err := adapter.CreateApproval(nil, &HITLApprovalRequest{
		StepName:   "analyze",
		PolicyName: "high-risk-check",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "pending" {
		t.Errorf("expected status pending, got %s", resp.Status)
	}
	if resp.ApprovalID.String() == "" {
		t.Error("expected non-empty approval ID")
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

func TestMAPHITLApprovalAdapter_GetApproval_NotFound(t *testing.T) {
	adapter := &MAPHITLApprovalAdapter{}
	randomID := uuid.New()

	_, err := adapter.GetApproval(nil, randomID)
	if err == nil {
		t.Error("expected error for nonexistent approval")
	}
}

func TestMAPHITLApprovalAdapter_GetApproval_Found(t *testing.T) {
	adapter := &MAPHITLApprovalAdapter{}

	// Create an approval first
	resp, err := adapter.CreateApproval(nil, &HITLApprovalRequest{
		StepName:   "analyze",
		PolicyName: "high-risk",
	})
	if err != nil {
		t.Fatalf("CreateApproval error: %v", err)
	}

	// Store a matching execution in the execution store
	executionStoreMutex.Lock()
	executionStore[hitlStoreKey("org-approval", resp.ApprovalID.String())] = &HITLWorkflowExecution{
		ApprovalID:     resp.ApprovalID,
		ApprovalStatus: "pending",
	}
	executionStoreMutex.Unlock()

	defer func() {
		executionStoreMutex.Lock()
		delete(executionStore, hitlStoreKey("org-approval", resp.ApprovalID.String()))
		executionStoreMutex.Unlock()
	}()

	// Now retrieve it
	// #3067: the store scan is bound to the caller's org scope, carried on
	// the context by the approve/reject handlers.
	got, err := adapter.GetApproval(WithHITLScope(context.Background(), "org-approval"), resp.ApprovalID)
	if err != nil {
		t.Fatalf("GetApproval error: %v", err)
	}
	if got.ApprovalID != resp.ApprovalID {
		t.Errorf("ApprovalID = %v, want %v", got.ApprovalID, resp.ApprovalID)
	}
	if got.Status != "pending" {
		t.Errorf("Status = %v, want pending", got.Status)
	}
}

func TestMapStepRejectHandler_HITLDisabled(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	origEnabled := hitlEnabled
	origEngine := hitlWorkflowEngine
	defer func() {
		hitlEnabled = origEnabled
		hitlWorkflowEngine = origEngine
	}()
	hitlEnabled = false
	hitlWorkflowEngine = nil

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/reject", mapStepRejectHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/reject",
		strings.NewReader(`{"reason":"not needed"}`))
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when HITL disabled, got %d", w.Code)
	}
}

func TestMapStepRejectHandler_NoPausedExecution(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)

	origEnabled := hitlEnabled
	origEngine := hitlWorkflowEngine
	defer func() {
		hitlEnabled = origEnabled
		hitlWorkflowEngine = origEngine
	}()
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/reject", mapStepRejectHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/reject",
		strings.NewReader(`{"reason":"test"}`))
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no paused execution, got %d", w.Code)
	}
}
