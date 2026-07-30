// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/license"
	logutil "axonflow/platform/shared/logger"
)

// costEstimateRateLimiter tracks daily cost estimation usage per tenant.
// NOTE: This is per-process in-memory state. In multi-replica deployments,
// each replica enforces its own limit independently.
type costEstimateRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int // tenant → count
	resetAt time.Time      // when to reset (start of next UTC day)
}

var costRateLimiter = &costEstimateRateLimiter{
	counts:  make(map[string]int),
	resetAt: nextUTCMidnight(),
}

func nextUTCMidnight() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
}

// tryConsume returns true if the request is within the daily limit for the given tenant.
// Returns false and the current count if the limit is exceeded.
func (rl *costEstimateRateLimiter) tryConsume(tenantID string, limit int) (bool, int) {
	if limit <= 0 { // unlimited
		return true, 0
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Reset if past midnight
	if time.Now().UTC().After(rl.resetAt) {
		rl.counts = make(map[string]int)
		rl.resetAt = nextUTCMidnight()
	}

	current := rl.counts[tenantID]
	if current >= limit {
		return false, current
	}

	rl.counts[tenantID]++
	return true, current + 1
}

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

	// Validate request body before consuming rate limit quota
	var req CostEstimateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Steps) == 0 {
		sendErrorResponse(w, "At least one step is required", http.StatusBadRequest)
		return
	}

	// Enforce daily rate limit per tenant (after validation). Fail closed on
	// missing tenant scope rather than sharing a `_default` global bucket
	// across all unauthenticated callers (#1623 retro): every legitimate
	// caller flows through the AxonFlow Agent gateway which sets X-Tenant-ID.
	tenantID := resolveTenantOrFail(w, r, "cost/estimate")
	if tenantID == "" {
		return // resolveTenantOrFail already wrote a 401
	}
	if tierChecker != nil {
		limit := tierChecker.MaxCostEstimatesPerDay()
		if ok, count := costRateLimiter.tryConsume(tenantID, limit); !ok {
			upgradeURL := "https://getaxonflow.com/evaluation-license"
			if license.IsEvaluationOrHigher(tierChecker.Tier()) {
				upgradeURL = "https://getaxonflow.com/enterprise"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"code":    "COST_ESTIMATE_LIMIT_EXCEEDED",
					"message": fmt.Sprintf("Daily cost estimation limit (%d) reached (%d used). Upgrade your license for higher limits: %s", limit, count, upgradeURL),
				},
			})
			return
		} else {
			// Add 80% warning header if approaching daily limit
			addTierWarningIfNeeded(w, "cost_estimates_per_day", count, limit)
		}
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
	if tierChecker != nil && license.IsEvaluationOrHigher(tierChecker.Tier()) {
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

	// Enforce daily rate limit per tenant (after input validation). See
	// resolveTenantOrFail rationale at the parallel call site above.
	tenantID := resolveTenantOrFail(w, r, "cost/estimate-plan")
	if tenantID == "" {
		return // resolveTenantOrFail already wrote a 401
	}
	if tierChecker != nil {
		limit := tierChecker.MaxCostEstimatesPerDay()
		if ok, count := costRateLimiter.tryConsume(tenantID, limit); !ok {
			upgradeURL := "https://getaxonflow.com/evaluation-license"
			if license.IsEvaluationOrHigher(tierChecker.Tier()) {
				upgradeURL = "https://getaxonflow.com/enterprise"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"code":    "COST_ESTIMATE_LIMIT_EXCEEDED",
					"message": fmt.Sprintf("Daily cost estimation limit (%d) reached (%d used). Upgrade your license for higher limits: %s", limit, count, upgradeURL),
				},
			})
			return
		} else {
			addTierWarningIfNeeded(w, "cost_estimates_per_day", count, limit)
		}
	}

	// #3065 (F3): tenant isolation now lives inside GetPlan, which fails
	// closed when the caller org or the plan's org is empty. The post-fetch
	// compare this handler used to run (`orgID != "" && plan.OrgID != "" &&
	// plan.OrgID != orgID`) let a caller who simply omitted X-Org-ID read any
	// tenant's plan — including its query text and workflow definition.
	plan, err := planService.GetPlan(r.Context(), planID, r.Header.Get("X-Org-ID"))
	if err != nil {
		log.Printf("[GetPlanCost] Failed to get plan %s: %v", logutil.Sanitize(planID), err)
		sendErrorResponse(w, "Plan not found", http.StatusNotFound)
		return
	}

	// Parse workflow definition from the plan
	var workflow Workflow
	if err := json.Unmarshal(plan.WorkflowDefinition, &workflow); err != nil {
		log.Printf("[GetPlanCost] Failed to parse workflow for plan %s: %v", logutil.Sanitize(planID), err)
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
	if tierChecker != nil && license.IsEvaluationOrHigher(tierChecker.Tier()) {
		resp.Breakdown = result.Breakdown
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[GetPlanCost] Error encoding response: %v", err)
	}
}
