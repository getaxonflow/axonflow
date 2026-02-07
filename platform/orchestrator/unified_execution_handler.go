// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/shared/execution"
)

// UnifiedExecutionHandler handles HTTP requests for unified execution status tracking.
// This supports both MAP plans and WCP workflows through a common API.
type UnifiedExecutionHandler struct {
	repo        execution.ExecutionRepository
	mapTracker  *MAPExecutionTracker
	wcpTracker  *WCPExecutionTracker
	eventHub    *execution.EventHub
	planService *planning.Service
	logger      *log.Logger
}

// NewUnifiedExecutionHandler creates a new unified execution handler.
func NewUnifiedExecutionHandler(
	repo execution.ExecutionRepository,
	mapTracker *MAPExecutionTracker,
	wcpTracker *WCPExecutionTracker,
	eventHub *execution.EventHub,
	planService *planning.Service,
) *UnifiedExecutionHandler {
	return &UnifiedExecutionHandler{
		repo:        repo,
		mapTracker:  mapTracker,
		wcpTracker:  wcpTracker,
		eventHub:    eventHub,
		planService: planService,
		logger:      log.Default(),
	}
}

// RegisterRoutes registers the unified execution API routes.
// These are registered at /api/v1/unified/executions to avoid conflict with replay API.
func (h *UnifiedExecutionHandler) RegisterRoutes(r *mux.Router) {
	// Unified execution status API - separate from replay
	r.HandleFunc("/api/v1/unified/executions", h.ListExecutions).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/unified/executions/{id}", h.GetExecutionStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/unified/executions/{id}/cancel", h.CancelExecution).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/unified/executions/{id}/stream", h.StreamExecutionStatus).Methods("GET", "OPTIONS")
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

// CancelExecution handles POST /api/v1/unified/executions/{id}/cancel
// Propagates cancellation to the appropriate subsystem (WCP or MAP).
func (h *UnifiedExecutionHandler) CancelExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	executionID := mux.Vars(r)["id"]
	if executionID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	// Parse optional reason from body
	var req execution.CancelExecutionRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // Ignore decode errors — reason is optional
	}
	if req.Reason == "" {
		req.Reason = "cancelled via unified API"
	}

	ctx := r.Context()

	// Look up the execution
	exec, err := h.repo.Get(ctx, executionID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found: "+executionID)
			return
		}
		h.logger.Printf("[UnifiedExecution] CancelExecution lookup error for %s: %v", executionID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up execution")
		return
	}

	// Check if already terminal
	if exec.IsTerminal() {
		h.writeError(w, http.StatusConflict, "CONFLICT",
			fmt.Sprintf("Execution is already in terminal state: %s", exec.Status))
		return
	}

	// Propagate to subsystem based on execution type
	switch exec.ExecutionType {
	case execution.ExecutionTypeWCP:
		// WCP: abort the workflow
		workflowID, _ := exec.Metadata["workflow_id"].(string)
		if workflowID == "" {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Missing workflow_id in execution metadata")
			return
		}
		if h.wcpTracker == nil || h.wcpTracker.wcpService == nil {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "WCP service not available")
			return
		}
		if err := h.wcpTracker.wcpService.AbortWorkflow(ctx, workflowID, req.Reason); err != nil {
			h.logger.Printf("[UnifiedExecution] WCP AbortWorkflow error for %s: %v", workflowID, err)
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to cancel WCP workflow")
			return
		}

	case execution.ExecutionTypeMAP:
		// MAP: cancel the plan
		planID, _ := exec.Metadata["plan_id"].(string)
		if planID == "" {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Missing plan_id in execution metadata")
			return
		}
		if h.planService == nil {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Plan service not available")
			return
		}
		if err := h.planService.CancelPlan(ctx, planID, req.Reason); err != nil {
			h.logger.Printf("[UnifiedExecution] MAP CancelPlan error for %s: %v", planID, err)
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to cancel MAP plan")
			return
		}
		// Sync status to execution_history
		if h.mapTracker != nil {
			_ = h.mapTracker.SyncPlanStatus(ctx, planID, planning.PlanStatusCancelled, req.Reason)
		}

	default:
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST",
			fmt.Sprintf("Unknown execution type: %s", exec.ExecutionType))
		return
	}

	// Return updated status
	updated, err := h.repo.Get(ctx, executionID)
	if err != nil {
		// Cancel succeeded but couldn't fetch updated status — return a generic success
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"execution_id": executionID,
			"status":       "cancelled",
			"message":      "Execution cancelled successfully",
		})
		return
	}
	updated.ProgressPercent = updated.CalculateProgress()
	updated.Duration = updated.CalculateDuration()
	h.writeJSON(w, http.StatusOK, updated)
}

// StreamExecutionStatus handles GET /api/v1/unified/executions/{id}/stream
// Streams execution state changes via Server-Sent Events (SSE).
func (h *UnifiedExecutionHandler) StreamExecutionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	executionID := mux.Vars(r)["id"]
	if executionID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	// Verify execution exists
	exec, err := h.repo.Get(r.Context(), executionID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found: "+executionID)
			return
		}
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up execution")
		return
	}

	// Check SSE support
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Streaming not supported")
		return
	}

	if h.eventHub == nil {
		h.writeError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Event streaming not available")
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	// Send initial state
	h.writeSSEEvent(w, "status", exec)
	flusher.Flush()

	// If already terminal, close immediately
	if exec.IsTerminal() {
		return
	}

	// Subscribe to events
	ch := h.eventHub.Subscribe(executionID)
	defer h.eventHub.Unsubscribe(executionID, ch)

	// Heartbeat ticker to prevent proxy idle timeouts
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send SSE comment as keepalive
			if _, err := fmt.Fprintf(w, ":keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case event, ok := <-ch:
			if !ok {
				return
			}
			h.writeSSEEvent(w, event.EventType, event.Data)
			flusher.Flush()

			// Close on terminal state
			if event.Data != nil && event.Data.IsTerminal() {
				return
			}
		}
	}
}

// --- Helper methods ---

func (h *UnifiedExecutionHandler) handleCORS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

func (h *UnifiedExecutionHandler) writeSSEEvent(w http.ResponseWriter, eventType string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		h.logger.Printf("[UnifiedExecution] SSE marshal error: %v", err)
		return
	}
	if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", time.Now().UnixMilli(), eventType, jsonData); err != nil {
		h.logger.Printf("[UnifiedExecution] SSE write error: %v", err)
	}
}
