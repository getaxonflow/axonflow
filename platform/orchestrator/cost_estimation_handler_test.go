// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestEstimatePlanCostHandler_Success(t *testing.T) {
	// Save and restore globals
	origEngine := planningEngine
	origTierChecker := tierChecker
	defer func() {
		planningEngine = origEngine
		tierChecker = origTierChecker
	}()

	// Set up a planning engine with default pricing
	planningEngine = &PlanningEngine{
		pricingConfig: &mockPricingConfig{costPerStep: 0.05},
	}
	tierChecker = &DefaultLicenseChecker{}

	body := CostEstimateRequest{
		Steps: []WorkflowStep{
			{Name: "analyze", Type: "llm-call", Provider: "openai", Model: "gpt-4o"},
			{Name: "summarize", Type: "llm-call", Provider: "openai", Model: "gpt-4o"},
			{Name: "fetch-data", Type: "connector-call"},
		},
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/plans/estimate", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	estimatePlanCostHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CostEstimateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.EstimatedCostUSD != 0.10 {
		t.Errorf("expected total cost 0.10, got %f", resp.EstimatedCostUSD)
	}
	if resp.Currency != "USD" {
		t.Errorf("expected currency USD, got %s", resp.Currency)
	}
	// Community tier — no breakdown
	if resp.Breakdown != nil {
		t.Errorf("expected nil breakdown for community tier, got %d items", len(resp.Breakdown))
	}
}

func TestEstimatePlanCostHandler_EmptySteps(t *testing.T) {
	origEngine := planningEngine
	defer func() { planningEngine = origEngine }()

	planningEngine = &PlanningEngine{
		pricingConfig: &mockPricingConfig{costPerStep: 0.05},
	}

	body := CostEstimateRequest{Steps: []WorkflowStep{}}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/plans/estimate", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	estimatePlanCostHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestEstimatePlanCostHandler_NoPlanningEngine(t *testing.T) {
	origEngine := planningEngine
	defer func() { planningEngine = origEngine }()

	planningEngine = nil

	body := CostEstimateRequest{
		Steps: []WorkflowStep{{Name: "test", Type: "llm-call"}},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/plans/estimate", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	estimatePlanCostHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

func TestEstimatePlanCostHandler_DefaultProviderFromRequest(t *testing.T) {
	origEngine := planningEngine
	origTierChecker := tierChecker
	defer func() {
		planningEngine = origEngine
		tierChecker = origTierChecker
	}()

	mock := &mockPricingConfig{costPerStep: 0.02}
	planningEngine = &PlanningEngine{pricingConfig: mock}
	// Use evaluation tier to get breakdown
	tierChecker = newMockLicenseChecker("Evaluation")

	body := CostEstimateRequest{
		Provider: "anthropic",
		Model:    "claude-sonnet-4",
		Steps: []WorkflowStep{
			{Name: "step1", Type: "llm-call"},
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/plans/estimate", bytes.NewReader(bodyBytes))
	w := httptest.NewRecorder()

	estimatePlanCostHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp CostEstimateResponse
	json.NewDecoder(w.Body).Decode(&resp)

	// Evaluation tier should have breakdown
	if len(resp.Breakdown) != 1 {
		t.Fatalf("expected 1 breakdown item, got %d", len(resp.Breakdown))
	}
	if resp.Breakdown[0].Provider != "anthropic" {
		t.Errorf("expected provider anthropic, got %s", resp.Breakdown[0].Provider)
	}
	if resp.Breakdown[0].Model != "claude-sonnet-4" {
		t.Errorf("expected model claude-sonnet-4, got %s", resp.Breakdown[0].Model)
	}
}

func TestGetPlanCostHandler_NoPlanService(t *testing.T) {
	origService := planService
	origEngine := planningEngine
	defer func() {
		planService = origService
		planningEngine = origEngine
	}()

	planService = nil
	planningEngine = &PlanningEngine{pricingConfig: &mockPricingConfig{costPerStep: 0.01}}

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/cost", getPlanCostHandler).Methods("GET")

	req := httptest.NewRequest("GET", "/api/v1/plans/plan-123/cost", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when planService is nil, got %d", w.Code)
	}
}

func TestGetPlanCostHandler_NoPlanningEngine(t *testing.T) {
	origEngine := planningEngine
	defer func() { planningEngine = origEngine }()

	planningEngine = nil

	// planService can be non-nil here; handler checks planningEngine second
	origService := planService
	defer func() { planService = origService }()
	planService = nil

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/plans/{id}/cost", getPlanCostHandler).Methods("GET")

	req := httptest.NewRequest("GET", "/api/v1/plans/plan-123/cost", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when planningEngine is nil, got %d", w.Code)
	}
}

func TestEstimatePlanCostHandler_InvalidBody(t *testing.T) {
	origEngine := planningEngine
	defer func() { planningEngine = origEngine }()

	planningEngine = &PlanningEngine{pricingConfig: &mockPricingConfig{costPerStep: 0.01}}

	req := httptest.NewRequest("POST", "/api/v1/plans/estimate",
		bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	estimatePlanCostHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid body, got %d", w.Code)
	}
}

// mockPricingConfig implements PlanCostEstimator for testing.
type mockPricingConfig struct {
	costPerStep float64
}

func (m *mockPricingConfig) EstimateCost(provider, model string, tokensIn, tokensOut int) float64 {
	return m.costPerStep
}
