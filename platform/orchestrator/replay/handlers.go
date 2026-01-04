// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Handler handles HTTP requests for execution replay
type Handler struct {
	service *Service
	logger  *log.Logger
}

// NewHandler creates a new replay handler
func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
		logger:  log.Default(),
	}
}

// NewHandlerWithLogger creates a new replay handler with a custom logger
func NewHandlerWithLogger(service *Service, logger *log.Logger) *Handler {
	if logger == nil {
		logger = log.Default()
	}
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers replay API routes with a gorilla/mux router
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/executions", h.ListExecutions).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/executions/{id}", h.GetExecution).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/executions/{id}/steps", h.GetSteps).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/executions/{id}/steps/{stepIndex}", h.GetStep).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/executions/{id}/timeline", h.GetTimeline).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/executions/{id}/export", h.ExportExecution).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/executions/{id}", h.DeleteExecution).Methods("DELETE", "OPTIONS")
}

// ListExecutions handles GET /api/v1/executions
func (h *Handler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	opts := ListOptions{
		Limit:  50,
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
		opts.Status = status
	}
	if workflowID := r.URL.Query().Get("workflow_id"); workflowID != "" {
		opts.WorkflowID = workflowID
	}
	if startTime := r.URL.Query().Get("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			opts.StartTime = &t
		}
	}
	if endTime := r.URL.Query().Get("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			opts.EndTime = &t
		}
	}

	// Get tenant/org context
	opts.TenantID = h.getTenantID(r)
	opts.OrgID = h.getOrgID(r)

	executions, total, err := h.service.ListExecutions(r.Context(), opts)
	if err != nil {
		h.logger.Printf("[Replay] ListExecutions error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list executions")
		return
	}

	response := ListExecutionsResponse{
		Executions: executions,
		Total:      total,
		Limit:      opts.Limit,
		Offset:     opts.Offset,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// GetExecution handles GET /api/v1/executions/{id}
func (h *Handler) GetExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	requestID := mux.Vars(r)["id"]
	if requestID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	exec, err := h.service.GetExecution(r.Context(), requestID)
	if err != nil {
		if err == ErrNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found")
			return
		}
		h.logger.Printf("[Replay] GetExecution error for %s: %v", requestID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get execution")
		return
	}

	h.writeJSON(w, http.StatusOK, exec)
}

// GetSteps handles GET /api/v1/executions/{id}/steps
func (h *Handler) GetSteps(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	requestID := mux.Vars(r)["id"]
	if requestID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	steps, err := h.service.GetSteps(r.Context(), requestID)
	if err != nil {
		h.logger.Printf("[Replay] GetSteps error for %s: %v", requestID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get execution steps")
		return
	}

	h.writeJSON(w, http.StatusOK, steps)
}

// GetStep handles GET /api/v1/executions/{id}/steps/{stepIndex}
func (h *Handler) GetStep(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	vars := mux.Vars(r)
	requestID := vars["id"]
	stepIndexStr := vars["stepIndex"]

	if requestID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	stepIndex, err := strconv.Atoi(stepIndexStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid step index")
		return
	}

	step, err := h.service.GetStep(r.Context(), requestID, stepIndex)
	if err != nil {
		if err == ErrNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Step not found")
			return
		}
		h.logger.Printf("[Replay] GetStep error for %s step %d: %v", requestID, stepIndex, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get step")
		return
	}

	h.writeJSON(w, http.StatusOK, step)
}

// GetTimeline handles GET /api/v1/executions/{id}/timeline
func (h *Handler) GetTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	requestID := mux.Vars(r)["id"]
	if requestID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	timeline, err := h.service.GetTimeline(r.Context(), requestID)
	if err != nil {
		if err == ErrNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found")
			return
		}
		h.logger.Printf("[Replay] GetTimeline error for %s: %v", requestID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get timeline")
		return
	}

	h.writeJSON(w, http.StatusOK, timeline)
}

// ExportExecution handles GET /api/v1/executions/{id}/export
func (h *Handler) ExportExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	requestID := mux.Vars(r)["id"]
	if requestID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	// Parse export options from query params
	opts := ExportOptions{
		Format:          ExportFormatJSON,
		IncludeInput:    true,
		IncludeOutput:   true,
		IncludePolicies: true,
	}

	if format := r.URL.Query().Get("format"); format != "" {
		opts.Format = ExportFormat(format)
	}
	if includeInput := r.URL.Query().Get("include_input"); includeInput == "false" {
		opts.IncludeInput = false
	}
	if includeOutput := r.URL.Query().Get("include_output"); includeOutput == "false" {
		opts.IncludeOutput = false
	}
	if includePolicies := r.URL.Query().Get("include_policies"); includePolicies == "false" {
		opts.IncludePolicies = false
	}

	data, err := h.service.ExportExecution(r.Context(), requestID, opts)
	if err != nil {
		if err == ErrNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found")
			return
		}
		h.logger.Printf("[Replay] ExportExecution error for %s: %v", requestID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to export execution")
		return
	}

	// Set download headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=execution-"+requestID+".json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		h.logger.Printf("[Replay] Failed to write export response: %v", err)
	}
}

// DeleteExecution handles DELETE /api/v1/executions/{id}
func (h *Handler) DeleteExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	requestID := mux.Vars(r)["id"]
	if requestID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	err := h.service.DeleteExecution(r.Context(), requestID)
	if err != nil {
		if err == ErrNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found")
			return
		}
		h.logger.Printf("[Replay] DeleteExecution error for %s: %v", requestID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete execution")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Helper types

// ListExecutionsResponse is the response for listing executions
type ListExecutionsResponse struct {
	Executions []ExecutionSummary `json:"executions"`
	Total      int                `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
}

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
	w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

// writeJSON writes a JSON response
func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	origin := w.Header().Get("Origin")
	if origin == "" {
		// Allow all origins for read-only APIs
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
