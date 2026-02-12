// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// CostEstimateRequest is the request body for POST /api/v1/plans/estimate.
type CostEstimateRequest struct {
	Provider string         `json:"provider,omitempty"`
	Model    string         `json:"model,omitempty"`
	Steps    []WorkflowStep `json:"steps"`
}

// CostEstimateResponse is the response for cost estimation endpoints.
type CostEstimateResponse struct {
	PlanID           string             `json:"plan_id,omitempty"`
	EstimatedCostUSD float64            `json:"estimated_cost_usd"`
	Currency         string             `json:"currency"`
	Breakdown        []StepCostEstimate `json:"breakdown,omitempty"`
}

// estimatePlanCostHandler handles POST /api/v1/plans/estimate.
// Estimates the cost of a plan without executing it.
// Community tier: returns aggregate only (no breakdown). Rate limited per tier.
func estimatePlanCostHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[EstimatePlanCost] Received cost estimation request")

	if planningEngine == nil {
		sendErrorResponse(w, "Planning engine not available", http.StatusServiceUnavailable)
		return
	}

	var req CostEstimateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Steps) == 0 {
		sendErrorResponse(w, "At least one step is required", http.StatusBadRequest)
		return
	}

	// Build a workflow from the request
	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: req.Steps,
		},
	}

	// Apply provider/model defaults from request if set
	if req.Provider != "" || req.Model != "" {
		for i := range workflow.Spec.Steps {
			if workflow.Spec.Steps[i].Provider == "" && req.Provider != "" {
				workflow.Spec.Steps[i].Provider = req.Provider
			}
			if workflow.Spec.Steps[i].Model == "" && req.Model != "" {
				workflow.Spec.Steps[i].Model = req.Model
			}
		}
	}

	result := planningEngine.EstimatePlanCost(workflow)

	resp := CostEstimateResponse{
		EstimatedCostUSD: result.EstimatedCostUSD,
		Currency:         result.Currency,
	}

	// Include breakdown only for Evaluation tier and above
	if tierChecker != nil && tierChecker.MaxCostEstimatesPerDay() > 10 || tierChecker.MaxCostEstimatesPerDay() == -1 {
		resp.Breakdown = result.Breakdown
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[EstimatePlanCost] Error encoding response: %v", err)
	}
}

// getPlanCostHandler handles GET /api/v1/plans/{id}/cost.
// Retrieves cost estimation for an existing stored plan.
func getPlanCostHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[GetPlanCost] Received get plan cost request")

	if planService == nil {
		sendErrorResponse(w, "Plan storage not available - database connection required", http.StatusServiceUnavailable)
		return
	}
	if planningEngine == nil {
		sendErrorResponse(w, "Planning engine not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	if planID == "" {
		sendErrorResponse(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	orgID := r.Header.Get("X-Org-ID")

	plan, err := planService.GetPlan(r.Context(), planID)
	if err != nil {
		log.Printf("[GetPlanCost] Failed to get plan %s: %v", planID, err)
		sendErrorResponse(w, "Plan not found: "+err.Error(), http.StatusNotFound)
		return
	}

	// Tenant isolation
	if orgID != "" && plan.OrgID != "" && plan.OrgID != orgID {
		sendErrorResponse(w, "Plan not found", http.StatusNotFound)
		return
	}

	// Parse workflow definition from the plan
	var workflow Workflow
	if err := json.Unmarshal(plan.WorkflowDefinition, &workflow); err != nil {
		log.Printf("[GetPlanCost] Failed to parse workflow for plan %s: %v", planID, err)
		sendErrorResponse(w, "Failed to parse plan workflow definition", http.StatusInternalServerError)
		return
	}

	result := planningEngine.EstimatePlanCost(&workflow)

	resp := CostEstimateResponse{
		PlanID:           planID,
		EstimatedCostUSD: result.EstimatedCostUSD,
		Currency:         result.Currency,
	}

	// Include breakdown only for Evaluation tier and above
	if tierChecker != nil && tierChecker.MaxCostEstimatesPerDay() > 10 || tierChecker.MaxCostEstimatesPerDay() == -1 {
		resp.Breakdown = result.Breakdown
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[GetPlanCost] Error encoding response: %v", err)
	}
}
