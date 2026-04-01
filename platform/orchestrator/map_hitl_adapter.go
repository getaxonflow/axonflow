// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// MAP-HITL Adapter — Bridges MAP execution with HITL approval queue (#1076)

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	logutil "axonflow/platform/shared/logger"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// MAPHITLPolicyChecker evaluates dynamic policies for MAP plan steps
// and returns require_approval when applicable.
type MAPHITLPolicyChecker struct{}

// CheckPolicy evaluates pre-step policies using the dynamic policy engine.
func (c *MAPHITLPolicyChecker) CheckPolicy(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) (*PolicyCheckResult, error) {
	if dynamicPolicyEngine == nil {
		return nil, nil
	}

	req := OrchestratorRequest{
		RequestID:   execution.ID,
		Query:       fmt.Sprintf("MAP step: %s (%s)", step.Name, step.Type),
		RequestType: "map_step",
		User:        execution.UserContext,
		Context: map[string]interface{}{
			"step_name":    step.Name,
			"step_type":    step.Type,
			"step_provider": step.Provider,
			"step_model":   step.Model,
		},
	}

	result := dynamicPolicyEngine.EvaluateDynamicPolicies(ctx, req)
	if result == nil {
		return nil, nil
	}

	if !result.Allowed {
		action := "block"
		reason := "Blocked by policy"
		policyName := ""
		if len(result.AppliedPolicies) > 0 {
			policyName = result.AppliedPolicies[0]
		}

		// Check if require_approval is in the required actions
		for _, ra := range result.RequiredActions {
			if ra == "require_approval" {
				action = "require_approval"
				reason = "Policy requires human approval"
				break
			}
		}

		// Map risk score to severity
		severity := "low"
		if result.RiskScore >= 0.8 {
			severity = "critical"
		} else if result.RiskScore >= 0.6 {
			severity = "high"
		} else if result.RiskScore >= 0.3 {
			severity = "medium"
		}

		return &PolicyCheckResult{
			Allowed:    false,
			Action:     action,
			PolicyName: policyName,
			Reason:     reason,
			Severity:   severity,
		}, nil
	}

	return nil, nil
}

// MAPHITLApprovalAdapter provides in-memory approval tracking for MAP steps.
// In production enterprise deployments, this delegates to the HITL queue service.
type MAPHITLApprovalAdapter struct{}

// CreateApproval creates a new HITL approval request for a MAP step.
func (a *MAPHITLApprovalAdapter) CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error) {
	approvalID := uuid.New()

	log.Printf("[MAP-HITL] Created approval request %s for step %s (policy: %s)",
		approvalID, logutil.Sanitize(req.StepName), logutil.Sanitize(req.PolicyName))

	return &HITLApprovalResponse{
		ApprovalID: approvalID,
		Status:     "pending",
	}, nil
}

// GetApproval retrieves the status of an HITL approval request.
func (a *MAPHITLApprovalAdapter) GetApproval(ctx context.Context, approvalID uuid.UUID) (*HITLApprovalResponse, error) {
	// Check the execution store for the approval status
	executionStoreMutex.RLock()
	defer executionStoreMutex.RUnlock()

	for _, exec := range executionStore {
		if exec.ApprovalID == approvalID {
			return &HITLApprovalResponse{
				ApprovalID: approvalID,
				Status:     exec.ApprovalStatus,
			}, nil
		}
	}

	return nil, fmt.Errorf("approval %s not found", approvalID)
}

// mapStepApproveHandler handles POST /api/v1/plans/{id}/steps/{step_id}/approve
func mapStepApproveHandler(w http.ResponseWriter, r *http.Request) {
	if isCommunityMode() {
		sendErrorResponse(w, "MAP step approval requires Enterprise license", http.StatusForbidden)
		return
	}

	if !hitlEnabled || hitlWorkflowEngine == nil {
		sendErrorResponse(w, "HITL not enabled", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	stepID := vars["step_id"]

	if planID == "" || stepID == "" {
		sendErrorResponse(w, "Plan ID and Step ID are required", http.StatusBadRequest)
		return
	}

	log.Printf("[MAP-HITL] Step approval for plan %s, step %s", logutil.Sanitize(planID), logutil.Sanitize(stepID))

	// Find the paused execution for this plan
	executionStoreMutex.Lock()
	var targetExec *HITLWorkflowExecution
	for _, exec := range executionStore {
		if exec.Status == StatusPaused && exec.WorkflowExecution != nil {
			// Match by plan ID from execution context, workflow name, or ID prefix
			if exec.WorkflowName == "plan-"+planID ||
				exec.ID == planID ||
				(exec.Input != nil && exec.Input["plan_id"] == planID) {
				targetExec = exec
				break
			}
		}
	}
	executionStoreMutex.Unlock()

	if targetExec == nil {
		sendErrorResponse(w, "No paused execution found for this plan", http.StatusNotFound)
		return
	}

	// Update approval status and resume execution
	targetExec.ApprovalStatus = StatusApproved
	targetExec.Status = "running"

	log.Printf("[MAP-HITL] Execution %s approved and resumed for plan %s, step %s", targetExec.ID, logutil.Sanitize(planID), logutil.Sanitize(stepID))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"plan_id":      planID,
		"step_id":      stepID,
		"status":       "approved",
		"execution_id": targetExec.ID,
	}); err != nil {
		log.Printf("[MAP-HITL] Error encoding response: %v", err)
	}
}

// mapStepRejectHandler handles POST /api/v1/plans/{id}/steps/{step_id}/reject
func mapStepRejectHandler(w http.ResponseWriter, r *http.Request) {
	if isCommunityMode() {
		sendErrorResponse(w, "MAP step rejection requires Enterprise license", http.StatusForbidden)
		return
	}

	if !hitlEnabled || hitlWorkflowEngine == nil {
		sendErrorResponse(w, "HITL not enabled", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	stepID := vars["step_id"]

	if planID == "" || stepID == "" {
		sendErrorResponse(w, "Plan ID and Step ID are required", http.StatusBadRequest)
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	log.Printf("[MAP-HITL] Step rejection for plan %s, step %s: %s", logutil.Sanitize(planID), logutil.Sanitize(stepID), logutil.Sanitize(req.Reason))

	// Find the paused execution for this plan
	executionStoreMutex.Lock()
	var targetExec *HITLWorkflowExecution
	for _, exec := range executionStore {
		if exec.Status == StatusPaused && exec.WorkflowExecution != nil {
			if exec.WorkflowName == "plan-"+planID {
				targetExec = exec
				break
			}
		}
	}
	executionStoreMutex.Unlock()

	if targetExec == nil {
		sendErrorResponse(w, "No paused execution found for this plan", http.StatusNotFound)
		return
	}

	// Abort the execution
	reason := req.Reason
	if reason == "" {
		reason = "Step rejected"
	}
	_, _ = hitlWorkflowEngine.AbortExecution(r.Context(), targetExec, reason)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"plan_id":     planID,
		"step_id":     stepID,
		"status":      "rejected",
		"execution_id": targetExec.ID,
	})
}
