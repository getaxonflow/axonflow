// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

// Handler handles HTTP requests for the Workflow Control Plane
type Handler struct {
	service *Service
	logger  *log.Logger
}

// NewHandler creates a new workflow control handler
func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
		logger:  log.Default(),
	}
}

// NewHandlerWithLogger creates a new workflow control handler with a custom logger
func NewHandlerWithLogger(service *Service, logger *log.Logger) *Handler {
	if logger == nil {
		logger = log.Default()
	}
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers core workflow control API routes with a gorilla/mux router.
// Core routes include workflow lifecycle and step gates (available in all editions).
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Workflow lifecycle
	r.HandleFunc("/api/v1/workflows", h.CreateWorkflow).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows", h.ListWorkflows).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}", h.GetWorkflow).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/complete", h.CompleteWorkflow).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/abort", h.AbortWorkflow).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/resume", h.ResumeWorkflow).Methods("POST", "OPTIONS")

	// Step gates - the core governance endpoint
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/gate", h.StepGate).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/complete", h.MarkStepCompleted).Methods("POST", "OPTIONS")
}

// RegisterEnterpriseRoutes registers enterprise-only approval routes with a gorilla/mux router.
// Approval endpoints (approve, reject, pending) are only available in enterprise mode.
func (h *Handler) RegisterEnterpriseRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/approve", h.ApproveStep).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/reject", h.RejectStep).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/approvals/pending", h.GetPendingApprovals).Methods("GET", "OPTIONS")
}

// CreateWorkflow handles POST /api/v1/workflows
func (h *Handler) CreateWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	var req CreateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body")
		return
	}

	if req.WorkflowName == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "workflow_name is required")
		return
	}

	// Get tenant/org context from headers or auth
	tenantID := h.getTenantID(r)
	orgID := h.getOrgID(r)
	userID := h.getUserID(r)
	clientID := h.getClientID(r)

	workflow, err := h.service.CreateWorkflow(r.Context(), &req, tenantID, orgID, userID, clientID)
	if err != nil {
		if strings.Contains(err.Error(), "concurrent execution limit reached") {
			h.writeError(w, http.StatusTooManyRequests, "CONCURRENT_EXECUTION_LIMIT",
				"Maximum concurrent executions reached. Upgrade your license for higher limits: https://docs.getaxonflow.com/evaluation-license")
			return
		}
		h.logger.Printf("[WorkflowControl] CreateWorkflow error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create workflow")
		return
	}

	h.writeJSON(w, http.StatusCreated, workflow.ToCreateResponse())
}

// GetWorkflow handles GET /api/v1/workflows/{id}
func (h *Handler) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	workflow, err := h.service.GetWorkflow(r.Context(), workflowID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		h.logger.Printf("[WorkflowControl] GetWorkflow error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, workflow.ToStatusResponse())
}

// ListWorkflows handles GET /api/v1/workflows
func (h *Handler) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	opts := ListWorkflowsOptions{
		Limit:  20,
		Offset: 0,
	}

	// Parse query parameters
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			opts.Limit = l
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			opts.Offset = o
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		s := WorkflowStatus(status)
		opts.Status = &s
	}
	if source := r.URL.Query().Get("source"); source != "" {
		s := WorkflowSource(source)
		opts.Source = &s
	}

	// Get tenant/org context
	opts.TenantID = h.getTenantID(r)
	opts.OrgID = h.getOrgID(r)

	response, err := h.service.ListWorkflows(r.Context(), opts)
	if err != nil {
		h.logger.Printf("[WorkflowControl] ListWorkflows error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list workflows")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// StepGate handles POST /api/v1/workflows/{id}/steps/{step_id}/gate
// This is the core governance endpoint - called before each step in an external workflow
func (h *Handler) StepGate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	stepID := vars["step_id"]

	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}
	if stepID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Step ID is required")
		return
	}

	var req StepGateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body")
		return
	}

	if req.StepType == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "step_type is required")
		return
	}

	// Get tenant/org context
	tenantID := h.getTenantID(r)
	orgID := h.getOrgID(r)
	userID := h.getUserID(r)
	clientID := h.getClientID(r)

	response, err := h.service.StepGate(r.Context(), workflowID, stepID, &req, tenantID, orgID, userID, clientID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		if strings.Contains(err.Error(), "pending approval") {
			h.writeError(w, http.StatusConflict, "APPROVAL_PENDING", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] StepGate error for %s/%s: %v", workflowID, stepID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate step gate")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// MarkStepCompleted handles POST /api/v1/workflows/{id}/steps/{step_id}/complete
func (h *Handler) MarkStepCompleted(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	stepID := vars["step_id"]

	if workflowID == "" || stepID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID and Step ID are required")
		return
	}

	if err := h.service.MarkStepCompleted(r.Context(), workflowID, stepID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Step not found")
			return
		}
		h.logger.Printf("[WorkflowControl] MarkStepCompleted error for %s/%s: %v", workflowID, stepID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to mark step completed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CompleteWorkflow handles POST /api/v1/workflows/{id}/complete
func (h *Handler) CompleteWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	if err := h.service.CompleteWorkflow(r.Context(), workflowID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		if strings.Contains(err.Error(), "pending approval") {
			h.writeError(w, http.StatusConflict, "APPROVAL_PENDING", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] CompleteWorkflow error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to complete workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"status":      WorkflowStatusCompleted,
		"message":     "Workflow completed successfully",
	})
}

// AbortWorkflow handles POST /api/v1/workflows/{id}/abort
func (h *Handler) AbortWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	var req AbortWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body
		req.Reason = "Aborted by user"
	}
	if req.Reason == "" {
		req.Reason = "Aborted by user"
	}

	if err := h.service.AbortWorkflow(r.Context(), workflowID, req.Reason); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] AbortWorkflow error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to abort workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"status":      WorkflowStatusAborted,
		"message":     "Workflow aborted",
		"reason":      req.Reason,
	})
}

// ResumeWorkflow handles POST /api/v1/workflows/{id}/resume
func (h *Handler) ResumeWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	if err := h.service.ResumeWorkflow(r.Context(), workflowID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		if strings.Contains(err.Error(), "pending approval") {
			h.writeError(w, http.StatusConflict, "APPROVAL_PENDING", err.Error())
			return
		}
		if strings.Contains(err.Error(), "rejected") {
			h.writeError(w, http.StatusConflict, "STEP_REJECTED", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] ResumeWorkflow error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resume workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"status":      WorkflowStatusInProgress,
		"message":     "Workflow resumed",
	})
}

// ApproveStep handles POST /api/v1/workflows/{id}/steps/{step_id}/approve (Enterprise)
func (h *Handler) ApproveStep(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	stepID := vars["step_id"]

	if workflowID == "" || stepID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID and Step ID are required")
		return
	}

	// Get approver identity
	approvedBy := h.getUserID(r)
	if approvedBy == "" {
		approvedBy = "system"
	}

	if err := h.service.ApproveStep(r.Context(), workflowID, stepID, approvedBy); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Step not found")
			return
		}
		if strings.Contains(err.Error(), "does not require") {
			h.writeError(w, http.StatusConflict, "NO_APPROVAL_NEEDED", err.Error())
			return
		}
		if strings.Contains(err.Error(), "not pending") {
			h.writeError(w, http.StatusConflict, "NOT_PENDING", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] ApproveStep error for %s/%s: %v", workflowID, stepID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to approve step")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id":     workflowID,
		"step_id":         stepID,
		"approval_status": ApprovalStatusApproved,
		"approved_by":     approvedBy,
		"message":         "Step approved",
	})
}

// RejectStep handles POST /api/v1/workflows/{id}/steps/{step_id}/reject (Enterprise)
func (h *Handler) RejectStep(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	stepID := vars["step_id"]

	if workflowID == "" || stepID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID and Step ID are required")
		return
	}

	// Get rejector identity
	rejectedBy := h.getUserID(r)
	if rejectedBy == "" {
		rejectedBy = "system"
	}

	if err := h.service.RejectStep(r.Context(), workflowID, stepID, rejectedBy); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Step not found")
			return
		}
		if strings.Contains(err.Error(), "does not require") {
			h.writeError(w, http.StatusConflict, "NO_APPROVAL_NEEDED", err.Error())
			return
		}
		if strings.Contains(err.Error(), "not pending") {
			h.writeError(w, http.StatusConflict, "NOT_PENDING", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] RejectStep error for %s/%s: %v", workflowID, stepID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to reject step")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id":     workflowID,
		"step_id":         stepID,
		"approval_status": ApprovalStatusRejected,
		"rejected_by":     rejectedBy,
		"message":         "Step rejected, workflow aborted",
	})
}

// GetPendingApprovals handles GET /api/v1/workflows/approvals/pending (Enterprise)
func (h *Handler) GetPendingApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Tenant ID is required")
		return
	}

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	steps, err := h.service.GetPendingApprovals(r.Context(), tenantID, limit)
	if err != nil {
		h.logger.Printf("[WorkflowControl] GetPendingApprovals error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get pending approvals")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending_approvals": steps,
		"count":             len(steps),
	})
}

// Helper types

// ErrorResponse represents an API error
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Helper methods

// getTenantID extracts tenant ID from request
func (h *Handler) getTenantID(r *http.Request) string {
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}
	if tenantID, ok := r.Context().Value("tenant_id").(string); ok {
		return tenantID
	}
	return ""
}

// getOrgID extracts org ID from request
func (h *Handler) getOrgID(r *http.Request) string {
	if orgID := r.Header.Get("X-Org-ID"); orgID != "" {
		return orgID
	}
	if orgID, ok := r.Context().Value("org_id").(string); ok {
		return orgID
	}
	return ""
}

// getUserID extracts user ID from request
func (h *Handler) getUserID(r *http.Request) string {
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	if userID, ok := r.Context().Value("user_id").(string); ok {
		return userID
	}
	return ""
}

// getClientID extracts client ID from request
func (h *Handler) getClientID(r *http.Request) string {
	if clientID := r.Header.Get("X-Client-ID"); clientID != "" {
		return clientID
	}
	if clientID, ok := r.Context().Value("client_id").(string); ok {
		return clientID
	}
	return ""
}

// allowedOrigins for CORS
var allowedOrigins = map[string]bool{
	"https://app.getaxonflow.com":      true,
	"https://staging.getaxonflow.com":  true,
	"https://demo.getaxonflow.com":     true,
	"https://customer.getaxonflow.com": true,
	"http://localhost:3000":            true,
	"http://localhost:8080":            true,
	"http://localhost:8081":            true,
}

// handleCORS sets CORS headers for OPTIONS requests
func (h *Handler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID, X-User-ID, X-Client-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

// writeJSON writes a JSON response
func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// Set permissive CORS for non-preflight requests
	// Preflight (OPTIONS) is handled by handleCORS with origin checking
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, ErrorResponse{
		Error:   strings.ToLower(code),
		Code:    code,
		Message: message,
	})
}
