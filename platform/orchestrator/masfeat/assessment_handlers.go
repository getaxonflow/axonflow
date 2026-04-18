// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"net/http"
	"strconv"
	"strings"
)

// AssessmentHandler handles HTTP requests for FEAT assessment operations.
type AssessmentHandler struct {
	service *AssessmentService
}

// NewAssessmentHandler creates a new assessment handler.
func NewAssessmentHandler(service *AssessmentService) *AssessmentHandler {
	return &AssessmentHandler{service: service}
}

// RegisterRoutes registers the assessment routes on an http.ServeMux.
func (h *AssessmentHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/masfeat/assessments", h.handleAssessments)
	mux.HandleFunc("/api/v1/masfeat/assessments/", h.handleAssessmentByID)
}

// handleAssessments handles POST (create) and GET (list) for /api/v1/masfeat/assessments.
func (h *AssessmentHandler) handleAssessments(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.createAssessment(w, r, orgID)
	case http.MethodGet:
		h.listAssessments(w, r, orgID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleAssessmentByID handles GET, PUT, and action routes for /api/v1/masfeat/assessments/{id}.
func (h *AssessmentHandler) handleAssessmentByID(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	// Parse path to extract ID and action
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/masfeat/assessments/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "Assessment ID required")
		return
	}

	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	// Handle actions
	if action != "" {
		switch action {
		case "submit":
			h.submitAssessment(w, r, orgID, id)
		case "approve":
			h.approveAssessment(w, r, orgID, id)
		case "reject":
			h.rejectAssessment(w, r, orgID, id)
		default:
			writeError(w, http.StatusNotFound, "Unknown action: "+action)
		}
		return
	}

	// Handle standard CRUD
	switch r.Method {
	case http.MethodGet:
		h.getAssessment(w, r, orgID, id)
	case http.MethodPut:
		h.updateAssessment(w, r, orgID, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// createAssessment handles POST /api/v1/masfeat/assessments.
func (h *AssessmentHandler) createAssessment(w http.ResponseWriter, r *http.Request, orgID string) {
	var req CreateAssessmentRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	assessment, err := h.service.CreateAssessment(r.Context(), orgID, &req, user)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, assessment)
}

// listAssessments handles GET /api/v1/masfeat/assessments.
func (h *AssessmentHandler) listAssessments(w http.ResponseWriter, r *http.Request, orgID string) {
	params := ListParams{
		Status:   r.URL.Query().Get("status"),
		SystemID: r.URL.Query().Get("system_id"),
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

	assessments, err := h.service.ListAssessments(r.Context(), orgID, params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if assessments == nil {
		assessments = []*FEATAssessment{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"assessments": assessments,
		"count":       len(assessments),
	})
}

// getAssessment handles GET /api/v1/masfeat/assessments/{id}.
func (h *AssessmentHandler) getAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	assessment, err := h.service.GetAssessment(r.Context(), orgID, id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// updateAssessment handles PUT /api/v1/masfeat/assessments/{id}.
func (h *AssessmentHandler) updateAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	var req UpdateAssessmentRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	assessment, err := h.service.UpdateAssessment(r.Context(), orgID, id, &req)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// submitAssessment handles POST /api/v1/masfeat/assessments/{id}/submit.
func (h *AssessmentHandler) submitAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	assessment, err := h.service.SubmitAssessment(r.Context(), orgID, id, user)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// approveAssessment handles POST /api/v1/masfeat/assessments/{id}/approve.
func (h *AssessmentHandler) approveAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	assessment, err := h.service.ApproveAssessment(r.Context(), orgID, id, user)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// rejectAssessment handles POST /api/v1/masfeat/assessments/{id}/reject.
func (h *AssessmentHandler) rejectAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	assessment, err := h.service.RejectAssessment(r.Context(), orgID, id, user, req.Reason)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}
