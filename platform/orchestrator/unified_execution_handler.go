// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/execution"
)

// UnifiedExecutionHandler handles HTTP requests for unified execution status tracking.
// This supports both MAP plans and WCP workflows through a common API.
type UnifiedExecutionHandler struct {
	repo               execution.ExecutionRepository
	mapTracker         *MAPExecutionTracker
	wcpTracker         *WCPExecutionTracker
	logger             *log.Logger
}

// NewUnifiedExecutionHandler creates a new unified execution handler.
func NewUnifiedExecutionHandler(
	repo execution.ExecutionRepository,
	mapTracker *MAPExecutionTracker,
	wcpTracker *WCPExecutionTracker,
) *UnifiedExecutionHandler {
	return &UnifiedExecutionHandler{
		repo:       repo,
		mapTracker: mapTracker,
		wcpTracker: wcpTracker,
		logger:     log.Default(),
	}
}

// RegisterRoutes registers the unified execution API routes.
// These are registered at /api/v1/unified/executions to avoid conflict with replay API.
func (h *UnifiedExecutionHandler) RegisterRoutes(r *mux.Router) {
	// Unified execution status API - separate from replay
	r.HandleFunc("/api/v1/unified/executions", h.ListExecutions).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/unified/executions/{id}", h.GetExecutionStatus).Methods("GET", "OPTIONS")
}

// ListExecutions handles GET /api/v1/unified/executions
func (h *UnifiedExecutionHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	req := execution.ListExecutionsRequest{
		Limit:  20,
		Offset: 0,
	}

	// Parse query parameters
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= 100 {
			req.Limit = l
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			req.Offset = o
		}
	}
	if execType := r.URL.Query().Get("execution_type"); execType != "" {
		t := execution.ExecutionType(execType)
		req.ExecutionType = &t
	}
	if status := r.URL.Query().Get("status"); status != "" {
		s := execution.ExecutionStatusValue(status)
		req.Status = &s
	}

	// Get tenant context from headers
	req.TenantID = r.Header.Get("X-Tenant-ID")
	req.OrgID = r.Header.Get("X-Org-ID")

	// Use the base tracker for listing
	tracker := execution.NewBaseExecutionTracker(h.repo)
	resp, err := tracker.ListExecutions(r.Context(), req)
	if err != nil {
		h.logger.Printf("[UnifiedExecution] ListExecutions error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list executions")
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// GetExecutionStatus handles GET /api/v1/unified/executions/{id}
// It attempts to find the execution by:
// 1. Direct execution ID lookup in the unified execution_history table
// 2. Workflow ID lookup for WCP workflows (checks metadata)
// 3. Plan ID lookup for MAP plans (checks metadata)
func (h *UnifiedExecutionHandler) GetExecutionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	executionID := mux.Vars(r)["id"]
	if executionID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	ctx := r.Context()

	// Strategy 1: Direct lookup by execution ID
	exec, err := h.repo.Get(ctx, executionID)
	if err == nil {
		// Found directly - calculate progress and return
		exec.ProgressPercent = exec.CalculateProgress()
		exec.Duration = exec.CalculateDuration()
		h.writeJSON(w, http.StatusOK, exec)
		return
	}

	// Strategy 2: Check if it's a WCP workflow ID
	if h.wcpTracker != nil && (strings.HasPrefix(executionID, "wf_") || strings.HasPrefix(executionID, "wcp_")) {
		exec, err = h.wcpTracker.GetWorkflowStatus(ctx, executionID)
		if err == nil {
			h.writeJSON(w, http.StatusOK, exec)
			return
		}
	}

	// Strategy 3: Check if it's a MAP plan ID
	if h.mapTracker != nil && strings.HasPrefix(executionID, "plan_") {
		exec, err = h.mapTracker.GetPlanStatus(ctx, executionID)
		if err == nil {
			h.writeJSON(w, http.StatusOK, exec)
			return
		}
	}

	// Strategy 4: Search by workflow_id or plan_id in metadata
	// Try WCP first
	if h.wcpTracker != nil {
		exec, err = h.wcpTracker.GetWorkflowStatus(ctx, executionID)
		if err == nil {
			h.writeJSON(w, http.StatusOK, exec)
			return
		}
	}

	// Try MAP
	if h.mapTracker != nil {
		exec, err = h.mapTracker.GetPlanStatus(ctx, executionID)
		if err == nil {
			h.writeJSON(w, http.StatusOK, exec)
			return
		}
	}

	// Not found anywhere
	if errors.Is(err, execution.ErrExecutionNotFound) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found: "+executionID)
		return
	}

	h.logger.Printf("[UnifiedExecution] GetExecutionStatus error for %s: %v", executionID, err)
	h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found: "+executionID)
}

// --- Helper methods ---

func (h *UnifiedExecutionHandler) handleCORS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID")
	w.WriteHeader(http.StatusNoContent)
}

func (h *UnifiedExecutionHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Printf("[UnifiedExecution] JSON encode error: %v", err)
	}
}

func (h *UnifiedExecutionHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	}
	_ = json.NewEncoder(w).Encode(resp) // Error intentionally ignored for error responses
}
