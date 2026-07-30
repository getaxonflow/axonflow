// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AISystemRegistryHandler handles HTTP requests for AI system registry operations.
// This is an Enterprise-only feature for RBI FREE-AI compliance.
type AISystemRegistryHandler struct {
	service AISystemRegistryService
}

// NewAISystemRegistryHandler creates a new AI system registry handler.
func NewAISystemRegistryHandler(service AISystemRegistryService) *AISystemRegistryHandler {
	return &AISystemRegistryHandler{service: service}
}

// RegisterRoutes registers AI system registry routes with the provided mux.
// All routes are prefixed with /api/v1/rbi/ai-systems.
//
// Endpoints:
//   - POST   /api/v1/rbi/ai-systems         - Create a new AI system
//   - GET    /api/v1/rbi/ai-systems         - List AI systems
//   - GET    /api/v1/rbi/ai-systems/summary - Get summary statistics
//   - GET    /api/v1/rbi/ai-systems/{id}    - Get AI system by ID
//   - PATCH  /api/v1/rbi/ai-systems/{id}    - Update AI system
//   - DELETE /api/v1/rbi/ai-systems/{id}    - Delete (deprecate) AI system
//   - POST   /api/v1/rbi/ai-systems/{id}/board-approval - Process board approval
//   - POST   /api/v1/rbi/ai-systems/{id}/validation     - Schedule validation
func (h *AISystemRegistryHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/rbi/ai-systems", h.handleAISystems)
	mux.HandleFunc("/api/v1/rbi/ai-systems/", h.handleAISystemByID)
	mux.HandleFunc("/api/v1/rbi/ai-systems/summary", h.handleSummary)
}

// maxRequestBodySize limits request body to 1MB
const maxRequestBodySize = 1 << 20 // 1MB

// handleAISystems handles POST/GET /api/v1/rbi/ai-systems
func (h *AISystemRegistryHandler) handleAISystems(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createSystem(w, r)
	case http.MethodGet:
		h.listSystems(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleSummary handles GET /api/v1/rbi/ai-systems/summary
func (h *AISystemRegistryHandler) handleSummary(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getSummary(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleAISystemByID handles GET/PATCH/DELETE /api/v1/rbi/ai-systems/{id}
func (h *AISystemRegistryHandler) handleAISystemByID(w http.ResponseWriter, r *http.Request) {
	// Extract system ID and potential sub-path from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rbi/ai-systems/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_ID", "System ID is required")
		return
	}

	systemID := parts[0]

	// Check for sub-routes
	if len(parts) > 1 {
		switch parts[1] {
		case "board-approval":
			if r.Method == http.MethodPost {
				h.processBoardApproval(w, r, systemID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		case "validation":
			if r.Method == http.MethodPost {
				h.scheduleValidation(w, r, systemID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		}
	}

	// Handle main system endpoints
	switch r.Method {
	case http.MethodGet:
		h.getSystem(w, r, systemID)
	case http.MethodPatch:
		h.updateSystem(w, r, systemID)
	case http.MethodDelete:
		h.deleteSystem(w, r, systemID)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// createSystem handles POST /api/v1/rbi/ai-systems
func (h *AISystemRegistryHandler) createSystem(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req CreateAISystemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	system, err := h.service.CreateSystem(r.Context(), orgID, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusCreated, system)
}

// listSystems handles GET /api/v1/rbi/ai-systems
func (h *AISystemRegistryHandler) listSystems(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	// Parse query parameters
	params := &ListAISystemsParams{
		RiskCategory:        r.URL.Query().Get("risk_category"),
		DeploymentStatus:    r.URL.Query().Get("deployment_status"),
		BoardApprovalStatus: r.URL.Query().Get("board_approval_status"),
		OwnerDepartment:     r.URL.Query().Get("owner_department"),
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			params.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			params.Offset = offset
		}
	}
	if overdueStr := r.URL.Query().Get("validation_overdue"); overdueStr != "" {
		overdue := overdueStr == "true"
		params.ValidationOverdue = &overdue
	}

	systems, total, err := h.service.ListSystems(r.Context(), orgID, params)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := map[string]interface{}{
		"systems": systems,
		"total":   total,
		"limit":   params.Limit,
		"offset":  params.Offset,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getSystem handles GET /api/v1/rbi/ai-systems/{id}
func (h *AISystemRegistryHandler) getSystem(w http.ResponseWriter, r *http.Request, systemID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	system, err := h.service.GetSystem(r.Context(), orgID, systemID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, system)
}

// updateSystem handles PATCH /api/v1/rbi/ai-systems/{id}
func (h *AISystemRegistryHandler) updateSystem(w http.ResponseWriter, r *http.Request, systemID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req UpdateAISystemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	system, err := h.service.UpdateSystem(r.Context(), orgID, systemID, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, system)
}

// deleteSystem handles DELETE /api/v1/rbi/ai-systems/{id}
func (h *AISystemRegistryHandler) deleteSystem(w http.ResponseWriter, r *http.Request, systemID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	if err := h.service.DeleteSystem(r.Context(), orgID, systemID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// processBoardApproval handles POST /api/v1/rbi/ai-systems/{id}/board-approval
func (h *AISystemRegistryHandler) processBoardApproval(w http.ResponseWriter, r *http.Request, systemID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req BoardApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	// #3150: `approver` is persisted as rbi_ai_systems.board_approver_name,
	// the named board member recorded against an AI system's approval, and
	// the same request's `action` drives the approve/reject/revoke transition.
	actor := resolveActor(r)
	req.Approver = actor.ID

	system, err := h.service.ProcessBoardApproval(r.Context(), orgID, systemID, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, system)
}

// scheduleValidation handles POST /api/v1/rbi/ai-systems/{id}/validation
func (h *AISystemRegistryHandler) scheduleValidation(w http.ResponseWriter, r *http.Request, systemID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req struct {
		ValidationDate time.Time `json:"validation_date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	if req.ValidationDate.IsZero() {
		req.ValidationDate = time.Now().UTC()
	}

	system, err := h.service.ScheduleValidation(r.Context(), orgID, systemID, req.ValidationDate)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, system)
}

// getSummary handles GET /api/v1/rbi/ai-systems/summary
func (h *AISystemRegistryHandler) getSummary(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	summary, err := h.service.GetSystemSummary(r.Context(), orgID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, summary)
}

// handleCORS handles OPTIONS requests for CORS preflight.
func (h *AISystemRegistryHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Org-ID")
	w.WriteHeader(http.StatusNoContent)
}

// handleServiceError maps service errors to HTTP responses.
func (h *AISystemRegistryHandler) handleServiceError(w http.ResponseWriter, err error) {
	log.Printf("[RBI Registry] Error: %v", err)

	switch {
	case errors.Is(err, ErrSystemNotFound):
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "AI system not found")
	case errors.Is(err, ErrSystemAlreadyExists):
		h.writeError(w, http.StatusConflict, "ALREADY_EXISTS", "AI system with this ID already exists")
	case errors.Is(err, ErrInvalidInput):
		h.writeError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	default:
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred")
	}
}

// writeJSON writes a JSON response with the given status code.
func (h *AISystemRegistryHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[RBI Registry] Error encoding JSON response: %v", err)
	}
}

// writeError writes an error response.
func (h *AISystemRegistryHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
