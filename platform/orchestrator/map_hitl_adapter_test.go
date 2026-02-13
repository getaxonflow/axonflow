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

func (m *mockPolicyEngineForHITL) IsHealthy() bool {
	return true
}

func TestMapStepApproveHandler_CommunityMode(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/approve", mapStepApproveHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/approve", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for community mode, got %d", w.Code)
	}
}

func TestMapStepRejectHandler_CommunityMode(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/reject", mapStepRejectHandler).Methods("POST")

	req := httptest.NewRequest("POST", "/api/v1/plans/plan-123/steps/step-1/reject",
		strings.NewReader(`{"reason":"test rejection"}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for community mode, got %d", w.Code)
	}
}

func TestMapStepApproveHandler_HITLDisabled(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

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
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when HITL disabled, got %d", w.Code)
	}
}

func TestMapStepApproveHandler_NoPausedExecution(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

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

func TestMAPHITLPolicyChecker_NilEngine(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()
	dynamicPolicyEngine = nil

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(nil, WorkflowStep{Name: "test"}, &WorkflowExecution{})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil result when engine is nil")
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
	executionStore[resp.ApprovalID.String()] = &HITLWorkflowExecution{
		ApprovalID:     resp.ApprovalID,
		ApprovalStatus: "pending",
	}
	executionStoreMutex.Unlock()

	defer func() {
		executionStoreMutex.Lock()
		delete(executionStore, resp.ApprovalID.String())
		executionStoreMutex.Unlock()
	}()

	// Now retrieve it
	got, err := adapter.GetApproval(nil, resp.ApprovalID)
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
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when HITL disabled, got %d", w.Code)
	}
}

func TestMapStepRejectHandler_NoPausedExecution(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

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
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no paused execution, got %d", w.Code)
	}
}

// TestMAPHITLPolicyChecker_AllowedResult tests that an allowed policy result
// returns nil (no policy intervention needed).
func TestMAPHITLPolicyChecker_AllowedResult(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()

	dynamicPolicyEngine = &mockPolicyEngineForHITL{
		result: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{"safe-content"},
			RiskScore:       0.1,
		},
	}

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(
		context.Background(),
		WorkflowStep{Name: "analyze", Type: "llm-call", Provider: "openai", Model: "gpt-4"},
		&WorkflowExecution{ID: "exec-1", UserContext: UserContext{TenantID: "t1"}},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for allowed policy, got %+v", result)
	}
}

// TestMAPHITLPolicyChecker_NilResult tests that a nil policy evaluation result
// returns nil (engine returned nil).
func TestMAPHITLPolicyChecker_NilResult(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()

	dynamicPolicyEngine = &mockPolicyEngineForHITL{
		result: nil,
	}

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(
		context.Background(),
		WorkflowStep{Name: "fetch", Type: "connector-call"},
		&WorkflowExecution{ID: "exec-2"},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for nil engine result, got %+v", result)
	}
}

// TestMAPHITLPolicyChecker_BlockedNoAppliedPolicies tests a blocked result
// with no applied policies and no required actions.
func TestMAPHITLPolicyChecker_BlockedNoAppliedPolicies(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()

	dynamicPolicyEngine = &mockPolicyEngineForHITL{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{},
			RiskScore:       0.5,
			RequiredActions: []string{},
		},
	}

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(
		context.Background(),
		WorkflowStep{Name: "risky-step", Type: "llm-call"},
		&WorkflowExecution{ID: "exec-3"},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for blocked policy")
	}
	if result.Allowed {
		t.Error("expected Allowed = false")
	}
	if result.Action != "block" {
		t.Errorf("Action = %q, want %q", result.Action, "block")
	}
	if result.Reason != "Blocked by policy" {
		t.Errorf("Reason = %q, want %q", result.Reason, "Blocked by policy")
	}
	if result.PolicyName != "" {
		t.Errorf("PolicyName = %q, want empty (no applied policies)", result.PolicyName)
	}
}

// TestMAPHITLPolicyChecker_RequireApproval tests that the require_approval
// required action is correctly mapped to the result.
func TestMAPHITLPolicyChecker_RequireApproval(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()

	dynamicPolicyEngine = &mockPolicyEngineForHITL{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"high-risk-check"},
			RiskScore:       0.75,
			RequiredActions: []string{"require_approval"},
		},
	}

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(
		context.Background(),
		WorkflowStep{Name: "sensitive-op", Type: "connector-call", Provider: "db", Model: ""},
		&WorkflowExecution{ID: "exec-4", UserContext: UserContext{TenantID: "t1", Email: "user@test.com"}},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Allowed {
		t.Error("expected Allowed = false")
	}
	if result.Action != "require_approval" {
		t.Errorf("Action = %q, want %q", result.Action, "require_approval")
	}
	if result.Reason != "Policy requires human approval" {
		t.Errorf("Reason = %q, want %q", result.Reason, "Policy requires human approval")
	}
	if result.PolicyName != "high-risk-check" {
		t.Errorf("PolicyName = %q, want %q", result.PolicyName, "high-risk-check")
	}
}

// TestMAPHITLPolicyChecker_RequireApprovalAmongOtherActions tests that
// require_approval is extracted even when mixed with other required actions.
func TestMAPHITLPolicyChecker_RequireApprovalAmongOtherActions(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()

	dynamicPolicyEngine = &mockPolicyEngineForHITL{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"compliance-policy"},
			RiskScore:       0.65,
			RequiredActions: []string{"log_audit", "require_approval", "notify_admin"},
		},
	}

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(
		context.Background(),
		WorkflowStep{Name: "step-x", Type: "llm-call"},
		&WorkflowExecution{ID: "exec-5"},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Action != "require_approval" {
		t.Errorf("Action = %q, want %q", result.Action, "require_approval")
	}
}

// TestMAPHITLPolicyChecker_RiskScoreSeverityMapping tests that risk scores
// are correctly mapped to severity levels.
func TestMAPHITLPolicyChecker_RiskScoreSeverityMapping(t *testing.T) {
	tests := []struct {
		name             string
		riskScore        float64
		expectedSeverity string
	}{
		{"zero_risk", 0.0, "low"},
		{"low_risk_0.1", 0.1, "low"},
		{"low_risk_0.29", 0.29, "low"},
		{"medium_risk_0.3", 0.3, "medium"},
		{"medium_risk_0.5", 0.5, "medium"},
		{"medium_risk_0.59", 0.59, "medium"},
		{"high_risk_0.6", 0.6, "high"},
		{"high_risk_0.7", 0.7, "high"},
		{"high_risk_0.79", 0.79, "high"},
		{"critical_risk_0.8", 0.8, "critical"},
		{"critical_risk_0.9", 0.9, "critical"},
		{"critical_risk_1.0", 1.0, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origEngine := dynamicPolicyEngine
			defer func() { dynamicPolicyEngine = origEngine }()

			dynamicPolicyEngine = &mockPolicyEngineForHITL{
				result: &PolicyEvaluationResult{
					Allowed:         false,
					AppliedPolicies: []string{},
					RiskScore:       tt.riskScore,
					RequiredActions: []string{},
				},
			}

			checker := &MAPHITLPolicyChecker{}
			result, err := checker.CheckPolicy(
				context.Background(),
				WorkflowStep{Name: "test-step", Type: "llm-call"},
				&WorkflowExecution{ID: "exec-severity"},
			)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Severity != tt.expectedSeverity {
				t.Errorf("Severity = %q, want %q (riskScore=%.2f)", result.Severity, tt.expectedSeverity, tt.riskScore)
			}
		})
	}
}

// TestMAPHITLPolicyChecker_WithAppliedPolicies tests that the first applied
// policy name is correctly set in the result.
func TestMAPHITLPolicyChecker_WithAppliedPolicies(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()

	dynamicPolicyEngine = &mockPolicyEngineForHITL{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"pii-detection", "sqli-prevention", "rate-limit"},
			RiskScore:       0.85,
			RequiredActions: []string{},
		},
	}

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(
		context.Background(),
		WorkflowStep{Name: "data-step", Type: "connector-call"},
		&WorkflowExecution{ID: "exec-policies"},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// Should use first applied policy
	if result.PolicyName != "pii-detection" {
		t.Errorf("PolicyName = %q, want %q", result.PolicyName, "pii-detection")
	}
	if result.Severity != "critical" {
		t.Errorf("Severity = %q, want %q (riskScore=0.85)", result.Severity, "critical")
	}
}

// TestMAPHITLPolicyChecker_BlockedWithRequireApprovalAndPolicies tests the
// full combination: blocked, with applied policies, require_approval action, and high risk.
func TestMAPHITLPolicyChecker_BlockedWithRequireApprovalAndPolicies(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()

	dynamicPolicyEngine = &mockPolicyEngineForHITL{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"compliance-gdpr"},
			RiskScore:       0.95,
			RequiredActions: []string{"require_approval"},
		},
	}

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(
		context.Background(),
		WorkflowStep{Name: "eu-data-step", Type: "connector-call", Provider: "postgres"},
		&WorkflowExecution{
			ID: "exec-full",
			UserContext: UserContext{
				TenantID: "eu-tenant",
				Email:    "analyst@corp.eu",
				Role:     "analyst",
			},
		},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Allowed {
		t.Error("expected Allowed = false")
	}
	if result.Action != "require_approval" {
		t.Errorf("Action = %q, want %q", result.Action, "require_approval")
	}
	if result.PolicyName != "compliance-gdpr" {
		t.Errorf("PolicyName = %q, want %q", result.PolicyName, "compliance-gdpr")
	}
	if result.Reason != "Policy requires human approval" {
		t.Errorf("Reason = %q, want %q", result.Reason, "Policy requires human approval")
	}
	if result.Severity != "critical" {
		t.Errorf("Severity = %q, want %q", result.Severity, "critical")
	}
}

// TestMAPHITLPolicyChecker_BlockedWithoutRequireApproval tests a blocked result
// without the require_approval action (plain block).
func TestMAPHITLPolicyChecker_BlockedWithoutRequireApproval(t *testing.T) {
	origEngine := dynamicPolicyEngine
	defer func() { dynamicPolicyEngine = origEngine }()

	dynamicPolicyEngine = &mockPolicyEngineForHITL{
		result: &PolicyEvaluationResult{
			Allowed:         false,
			AppliedPolicies: []string{"sqli-prevention"},
			RiskScore:       0.9,
			RequiredActions: []string{"blocked: SQL injection detected"},
		},
	}

	checker := &MAPHITLPolicyChecker{}
	result, err := checker.CheckPolicy(
		context.Background(),
		WorkflowStep{Name: "query-step", Type: "connector-call"},
		&WorkflowExecution{ID: "exec-block"},
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Action != "block" {
		t.Errorf("Action = %q, want %q (no require_approval in actions)", result.Action, "block")
	}
	if result.Reason != "Blocked by policy" {
		t.Errorf("Reason = %q, want %q", result.Reason, "Blocked by policy")
	}
}
