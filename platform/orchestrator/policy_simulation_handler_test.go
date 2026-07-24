// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	"axonflow/platform/agent/license"
)

// mockLicenseCheckerForSim implements LicenseChecker for simulation tests.
type mockLicenseCheckerForSim struct {
	tier                     license.Tier
	policySimEnabled         bool
	maxSimsPerDay            int
	maxImpactInputs          int
	evidenceExportEnabled    bool
	maxEvidenceExportRecords int
	maxEvidenceWindowDays    int
	maxEvidenceExportsPerDay int
	hitlEnabled              bool
	hitlExpiryHours          int
}

func (m *mockLicenseCheckerForSim) IsEnterprise() bool              { return license.IsPaidTier(m.tier) }
func (m *mockLicenseCheckerForSim) Tier() license.Tier              { return m.tier }
func (m *mockLicenseCheckerForSim) PolicyLimit() int                { return 50 }
func (m *mockLicenseCheckerForSim) OrgPolicyLimit() int             { return 5 }
func (m *mockLicenseCheckerForSim) CustomPolicyConnectorLimit() int { return 5 }
func (m *mockLicenseCheckerForSim) AuditRetentionDays() int         { return 14 }
func (m *mockLicenseCheckerForSim) MaxLLMProviders() int            { return 3 }
func (m *mockLicenseCheckerForSim) MaxExecutionHistory() int        { return 500 }
func (m *mockLicenseCheckerForSim) MaxConcurrentExecutions() int    { return 25 }
func (m *mockLicenseCheckerForSim) MaxPlans() int                   { return 100 }
func (m *mockLicenseCheckerForSim) MaxVersionsPerPlan() int         { return 25 }
func (m *mockLicenseCheckerForSim) MaxSSEConnections() int          { return 25 }
func (m *mockLicenseCheckerForSim) MaxCostEstimatesPerDay() int     { return 100 }
func (m *mockLicenseCheckerForSim) MaxPendingApprovals() int        { return 100 }
func (m *mockLicenseCheckerForSim) MediaGovernanceEnabled() bool    { return true }
func (m *mockLicenseCheckerForSim) IsHITLApprovalEnabled() bool     { return m.hitlEnabled }
func (m *mockLicenseCheckerForSim) HITLExpiryHours() int            { return m.hitlExpiryHours }
func (m *mockLicenseCheckerForSim) IsPolicySimulationEnabled() bool { return m.policySimEnabled }
func (m *mockLicenseCheckerForSim) MaxSimulationsPerDay() int       { return m.maxSimsPerDay }
func (m *mockLicenseCheckerForSim) MaxImpactReportInputs() int      { return m.maxImpactInputs }
func (m *mockLicenseCheckerForSim) IsEvidenceExportEnabled() bool   { return m.evidenceExportEnabled }
func (m *mockLicenseCheckerForSim) MaxEvidenceExportRecords() int   { return m.maxEvidenceExportRecords }
func (m *mockLicenseCheckerForSim) MaxEvidenceWindowDays() int      { return m.maxEvidenceWindowDays }
func (m *mockLicenseCheckerForSim) MaxEvidenceExportsPerDay() int   { return m.maxEvidenceExportsPerDay }

// mockPolicyEngineForSim implements the policy engine interface for simulation tests.
type mockPolicyEngineForSim struct {
	evaluateResult *PolicyEvaluationResult
	activePolicies []DynamicPolicy
	lastReq        OrchestratorRequest
}

func (m *mockPolicyEngineForSim) EvaluateDynamicPolicies(_ context.Context, req OrchestratorRequest) *PolicyEvaluationResult {
	m.lastReq = req
	if m.evaluateResult != nil {
		return m.evaluateResult
	}
	return &PolicyEvaluationResult{
		Allowed:         true,
		AppliedPolicies: []string{"test-policy"},
		RiskScore:       0.3,
	}
}

func (m *mockPolicyEngineForSim) ListActivePolicies() []DynamicPolicy {
	return m.activePolicies
}

// TestSimulatePolicies_IgnoresBodyTenant is the mirror of
// TestTestPolicyHandlerIgnoresBodyTenant, and it exists because the two halves
// of that fix must not diverge — this one shipped unpinned once already.
//
// Simulation is a dry run but not a side-effect free one: EvaluateDynamicPolicies
// records a policy_metrics analytics row whose org_id is ALSO the
// app.current_org_id binding its INSERT is checked against, so a body-sourced
// tenant lets an authenticated caller attribute rows to any org they name with
// the RLS WITH CHECK passing by construction. This handler used to fill the
// tenant only when the BODY left it empty, i.e. the body won.
func TestSimulatePolicies_IgnoresBodyTenant(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxSimsPerDay:    300,
	}
	engine := &mockPolicyEngineForSim{activePolicies: make([]DynamicPolicy, 1)}
	handler := NewPolicySimulationHandler(engine, nil, nil, checker)
	handler.rateLimiter = &simulationRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body := []byte(`{"query":"hello","request_type":"chat","user":{"tenant_id":"victim-org"},"client":{"tenant_id":"victim-org"}}`)
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "caller-org")
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := engine.lastReq.User.TenantID; got != "caller-org" {
		t.Errorf("evaluated User.TenantID = %q, want %q — the body won, so a caller can attribute policy_metrics rows to any org they name", got, "caller-org")
	}
	// db_dynamic_policies.go prefers Client.TenantID over User.TenantID, so the
	// body must not be able to steer the scope through that field either.
	if got := engine.lastReq.Client.TenantID; got != "caller-org" {
		t.Errorf("evaluated Client.TenantID = %q, want %q — the metrics writer PREFERS this field, so leaving it body-controlled reopens the same hole", got, "caller-org")
	}
}

// TestSimulatePolicies_RequiresGatewayTenant: without a scope there is nothing
// to attribute the evaluation to, and falling back to the body would let the
// caller pick one.
func TestSimulatePolicies_RequiresGatewayTenant(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxSimsPerDay:    300,
	}
	handler := NewPolicySimulationHandler(&mockPolicyEngineForSim{}, nil, nil, checker)
	handler.rateLimiter = &simulationRateLimiter{counts: make(map[string]int), resetAt: nextUTCMidnight()}

	req := httptest.NewRequest("POST", "/api/v1/policies/simulate",
		bytes.NewReader([]byte(`{"query":"hello","user":{"tenant_id":"victim-org"}}`)))
	w := httptest.NewRecorder()
	handler.SimulatePolicies(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status without X-Tenant-ID = %d, want 401", w.Code)
	}
}

func TestSimulatePolicies_Success(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxSimsPerDay:    300,
	}
	engine := &mockPolicyEngineForSim{
		evaluateResult: &PolicyEvaluationResult{
			Allowed:          true,
			AppliedPolicies:  []string{"pii-detection", "prompt-injection"},
			RiskScore:        0.45,
			RequiredActions:  []string{"redact"},
			ProcessingTimeMs: 12,
		},
		activePolicies: make([]DynamicPolicy, 5),
	}

	handler := NewPolicySimulationHandler(engine, nil, nil, checker)
	// Reset rate limiter for test
	handler.rateLimiter = &simulationRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(SimulatePoliciesRequest{
		Query:       "What is my SSN?",
		RequestType: "chat",
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SimulatePoliciesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !resp.DryRun {
		t.Error("Expected dry_run to be true")
	}
	if resp.RiskScore != 0.45 {
		t.Errorf("Expected risk_score 0.45, got %f", resp.RiskScore)
	}
	if len(resp.AppliedPolicies) != 2 {
		t.Errorf("Expected 2 applied policies, got %d", len(resp.AppliedPolicies))
	}
	if resp.TotalPolicies != 5 {
		t.Errorf("Expected 5 total policies, got %d", resp.TotalPolicies)
	}
	if resp.DailyUsage == nil {
		t.Error("Expected daily_usage to be present")
	} else if resp.DailyUsage.Limit != 300 {
		t.Errorf("Expected limit 300, got %d", resp.DailyUsage.Limit)
	}
}

func TestSimulatePolicies_CommunityForbidden(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierCommunity,
		policySimEnabled: false,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	body, _ := json.Marshal(SimulatePoliciesRequest{Query: "test"})
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", w.Code)
	}
}

func TestSimulatePolicies_RateLimit(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxSimsPerDay:    2,
	}
	engine := &mockPolicyEngineForSim{
		evaluateResult: &PolicyEvaluationResult{Allowed: true},
	}

	handler := NewPolicySimulationHandler(engine, nil, nil, checker)
	handler.rateLimiter = &simulationRateLimiter{
		counts:  map[string]int{"test-tenant": 2}, // Already at limit
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(SimulatePoliciesRequest{Query: "test"})
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImpactReport_InputLimitExceeded(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxImpactInputs:  3,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	inputs := make([]ImpactReportInput, 5) // Over limit of 3
	for i := range inputs {
		inputs[i] = ImpactReportInput{Query: "test"}
	}
	body, _ := json.Marshal(ImpactReportRequest{
		PolicyID: "pol-1",
		Inputs:   inputs,
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/impact-report", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ImpactReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSimulatePolicies_OPTIONS(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	req := httptest.NewRequest("OPTIONS", "/api/v1/policies/simulate", nil)
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for OPTIONS, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Error("Expected empty body for OPTIONS")
	}
}

func TestSimulatePolicies_EmptyQuery(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxSimsPerDay:    100,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)
	handler.rateLimiter = &simulationRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(SimulatePoliciesRequest{Query: ""})
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for empty query, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp["message"] != "query is required" {
		t.Errorf("Expected 'query is required', got %q", errResp["message"])
	}
}

func TestSimulatePolicies_InvalidJSON(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader([]byte("{invalid json")))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestSimulatePolicies_UnlimitedTier(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEnterprise,
		policySimEnabled: true,
		maxSimsPerDay:    -1, // unlimited
	}
	engine := &mockPolicyEngineForSim{
		evaluateResult: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{"pii-detection"},
			RiskScore:       0.2,
		},
		activePolicies: make([]DynamicPolicy, 3),
	}

	handler := NewPolicySimulationHandler(engine, nil, nil, checker)
	handler.rateLimiter = &simulationRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(SimulatePoliciesRequest{
		Query:       "What is my SSN?",
		RequestType: "chat",
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SimulatePoliciesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.DailyUsage != nil {
		t.Error("Expected daily_usage to be nil for unlimited tier")
	}
	if resp.Tier != string(license.TierEnterprise) {
		t.Errorf("Expected tier %q, got %q", license.TierEnterprise, resp.Tier)
	}
}

func TestSimulatePolicies_TenantFromContext(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxSimsPerDay:    100,
	}
	engine := &mockPolicyEngineForSim{
		evaluateResult: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{"test-policy"},
			RiskScore:       0.1,
		},
		activePolicies: make([]DynamicPolicy, 2),
	}

	handler := NewPolicySimulationHandler(engine, nil, nil, checker)
	handler.rateLimiter = &simulationRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(SimulatePoliciesRequest{Query: "test query"})
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader(body))
	// No X-Tenant-ID header -- tenant comes from context
	ctx := context.WithValue(req.Context(), "tenant_id", "ctx-tenant")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImpactReport_EmptyPolicyID(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	body, _ := json.Marshal(ImpactReportRequest{
		PolicyID: "",
		Inputs:   []ImpactReportInput{{Query: "test"}},
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/impact-report", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ImpactReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for empty policy_id, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp["message"] != "policy_id is required" {
		t.Errorf("Expected 'policy_id is required', got %q", errResp["message"])
	}
}

func TestImpactReport_NoInputs(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	body, _ := json.Marshal(ImpactReportRequest{
		PolicyID: "pol-1",
		Inputs:   []ImpactReportInput{},
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/impact-report", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ImpactReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for no inputs, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp["message"] != "at least one input is required" {
		t.Errorf("Expected 'at least one input is required', got %q", errResp["message"])
	}
}

func TestImpactReport_InvalidJSON(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	req := httptest.NewRequest("POST", "/api/v1/policies/impact-report", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ImpactReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestImpactReport_OPTIONS(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	req := httptest.NewRequest("OPTIONS", "/api/v1/policies/impact-report", nil)
	w := httptest.NewRecorder()

	handler.ImpactReport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for OPTIONS, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Error("Expected empty body for OPTIONS")
	}
}

func TestWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusBadRequest, "TEST_CODE", "test message")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %q", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to decode JSON error body: %v", err)
	}
	if body["error"] != "TEST_CODE" {
		t.Errorf("Expected error 'TEST_CODE', got %q", body["error"])
	}
	if body["code"] != "TEST_CODE" {
		t.Errorf("Expected code 'TEST_CODE', got %q", body["code"])
	}
	if body["message"] != "test message" {
		t.Errorf("Expected message 'test message', got %q", body["message"])
	}
}

func TestWriteJSONError_InternalServerError(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "something went wrong")

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("Failed to decode JSON error body: %v", err)
	}
	if body["error"] != "INTERNAL_ERROR" {
		t.Errorf("Expected error 'INTERNAL_ERROR', got %q", body["error"])
	}
}

func TestSimulatePolicies_DefaultRequestType(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxSimsPerDay:    300,
	}
	engine := &mockPolicyEngineForSim{
		evaluateResult: &PolicyEvaluationResult{
			Allowed:         true,
			AppliedPolicies: []string{},
			RiskScore:       0.0,
		},
		activePolicies: make([]DynamicPolicy, 0),
	}

	handler := NewPolicySimulationHandler(engine, nil, nil, checker)
	handler.rateLimiter = &simulationRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	// No RequestType provided - should default to "simulation"
	body, _ := json.Marshal(SimulatePoliciesRequest{Query: "test query"})
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.SimulatePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp SimulatePoliciesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	if !resp.DryRun {
		t.Error("Expected dry_run true")
	}
	if !resp.Allowed {
		t.Error("Expected allowed true")
	}
}

func TestSimulationHandler_RegisterRoutes(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	var match mux.RouteMatch
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", nil)
	if !r.Match(req, &match) {
		t.Error("Expected /api/v1/policies/simulate POST to match")
	}
	req = httptest.NewRequest("POST", "/api/v1/policies/impact-report", nil)
	if !r.Match(req, &match) {
		t.Error("Expected /api/v1/policies/impact-report POST to match")
	}
	req = httptest.NewRequest("POST", "/api/v1/policies/conflicts", nil)
	if !r.Match(req, &match) {
		t.Error("Expected /api/v1/policies/conflicts POST to match")
	}
}

func TestImpactReport_CommunityForbidden(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierCommunity,
		policySimEnabled: false,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	body, _ := json.Marshal(ImpactReportRequest{PolicyID: "pol-1", Inputs: []ImpactReportInput{{Query: "test"}}})
	req := httptest.NewRequest("POST", "/api/v1/policies/impact-report", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ImpactReport(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", w.Code)
	}
}

func TestImpactReport_NilPolicyService(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxImpactInputs:  50,
	}
	handler := NewPolicySimulationHandler(nil, nil, nil, checker)

	body, _ := json.Marshal(ImpactReportRequest{
		PolicyID: "pol-1",
		Inputs:   []ImpactReportInput{{Query: "test"}},
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/impact-report", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ImpactReport(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 for nil policyService, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp["message"] != "Policy service not available" {
		t.Errorf("Expected 'Policy service not available', got %q", errResp["message"])
	}
}

func TestImpactReport_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:             license.TierEvaluation,
		policySimEnabled: true,
		maxImpactInputs:  50,
	}

	// Create a real PolicyService backed by sqlmock
	repo := NewPolicyRepository(db)
	policySvc := NewPolicyServiceWithLicense(repo, nil, checker)

	engine := &mockPolicyEngineForSim{}
	handler := NewPolicySimulationHandler(engine, policySvc, nil, checker)

	now := time.Now()

	// For each input, PolicyService.TestPolicy calls repo.GetByID which queries dynamic_policies.
	// We mock GetByID to return a policy that matches the "harmful" query but not the "safe" one.
	// The policy has a "block" action with a keyword condition for "harmful".
	conditionsJSON := `[{"field":"query","operator":"contains","value":"harmful"}]`
	actionsJSON := `[{"type":"block","config":{"message":"Blocked by policy"}}]`

	// #3039: GetByID now runs org-scoped (BEGIN + set_config + SELECT +
	// COMMIT) so RLS admits the tenant's rows under app_role.
	expectScopedGet := func() {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("test-tenant").WillReturnResult(sqlmock.NewResult(0, 0))
	}

	// Input 1: "harmful content" — should match
	expectScopedGet()
	mock.ExpectQuery("SELECT .+ FROM dynamic_policies").
		WithArgs("pol-test", "test-tenant").
		WillReturnRows(sqlmock.NewRows([]string{
			"policy_id", "name", "description", "policy_type",
			"category", "tier",
			"conditions", "actions", "tenant_id", "organization_id",
			"priority", "enabled", "version",
			"created_by", "updated_by",
			"created_at", "updated_at",
		}).AddRow(
			"pol-test", "test-policy", "A test policy", "custom",
			"safety", "tenant",
			conditionsJSON, actionsJSON, "test-tenant", "",
			10, true, 1,
			"admin", "admin",
			now, now,
		))
	mock.ExpectCommit()

	// Input 2: "safe question" — policy fetched again, won't match
	expectScopedGet()
	mock.ExpectQuery("SELECT .+ FROM dynamic_policies").
		WithArgs("pol-test", "test-tenant").
		WillReturnRows(sqlmock.NewRows([]string{
			"policy_id", "name", "description", "policy_type",
			"category", "tier",
			"conditions", "actions", "tenant_id", "organization_id",
			"priority", "enabled", "version",
			"created_by", "updated_by",
			"created_at", "updated_at",
		}).AddRow(
			"pol-test", "test-policy", "A test policy", "custom",
			"safety", "tenant",
			conditionsJSON, actionsJSON, "test-tenant", "",
			10, true, 1,
			"admin", "admin",
			now, now,
		))
	mock.ExpectCommit()

	body, _ := json.Marshal(ImpactReportRequest{
		PolicyID: "pol-test",
		Inputs: []ImpactReportInput{
			{Query: "this is harmful content"},
			{Query: "safe question about weather"},
		},
	})
	req := httptest.NewRequest("POST", "/api/v1/policies/impact-report", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ImpactReport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ImpactReportResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.PolicyID != "pol-test" {
		t.Errorf("Expected policy_id 'pol-test', got %q", resp.PolicyID)
	}
	if resp.TotalInputs != 2 {
		t.Errorf("Expected 2 total inputs, got %d", resp.TotalInputs)
	}
	if resp.Matched != 1 {
		t.Errorf("Expected 1 matched, got %d", resp.Matched)
	}
	if resp.Blocked != 1 {
		t.Errorf("Expected 1 blocked, got %d", resp.Blocked)
	}
	if resp.MatchRate != 0.5 {
		t.Errorf("Expected match_rate 0.5, got %f", resp.MatchRate)
	}
	if resp.BlockRate != 0.5 {
		t.Errorf("Expected block_rate 0.5, got %f", resp.BlockRate)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(resp.Results))
	}

	// First input should match + block
	if !resp.Results[0].Matched {
		t.Error("Expected first input to match")
	}
	if !resp.Results[0].Blocked {
		t.Error("Expected first input to be blocked")
	}

	// Second input should not match
	if resp.Results[1].Matched {
		t.Error("Expected second input to not match")
	}
	if resp.Results[1].Blocked {
		t.Error("Expected second input to not be blocked")
	}

	if resp.Tier != string(license.TierEvaluation) {
		t.Errorf("Expected tier %q, got %q", license.TierEvaluation, resp.Tier)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet sqlmock expectations: %v", err)
	}
}
