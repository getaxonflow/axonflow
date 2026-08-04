// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// ConformityHandler handles HTTP requests for conformity assessments.
type ConformityHandler struct {
	service *ConformityService
}

// NewConformityHandler creates a new conformity handler.
func NewConformityHandler(service *ConformityService) *ConformityHandler {
	return &ConformityHandler{service: service}
}

// RegisterRoutes registers conformity routes on the given mux.
func (h *ConformityHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/euaiact/conformity", h.handleConformity)
	mux.HandleFunc("/api/v1/euaiact/conformity/", h.handleConformityByID)
}

// handleConformity handles POST/GET /api/v1/euaiact/conformity.
func (h *ConformityHandler) handleConformity(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createAssessment(w, r)
	case http.MethodGet:
		h.listAssessments(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// createAssessment handles POST /api/v1/euaiact/conformity.
func (h *ConformityHandler) createAssessment(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	var req CreateAssessmentRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "system"
	}

	input := CreateAssessmentInput{
		OrgID:        orgID,
		SystemID:     req.SystemID,
		SystemName:   req.SystemName,
		RiskCategory: req.RiskCategory,
		Assessors:    req.Assessors,
		CreatedBy:    userID,
	}

	assessment, err := h.service.CreateAssessment(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, assessment)
}

// listAssessments handles GET /api/v1/euaiact/conformity.
func (h *ConformityHandler) listAssessments(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	status := AssessmentStatus(r.URL.Query().Get("status"))
	limit := DefaultListLimit
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= MaxListLimit {
			limit = l
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	assessments, total, err := h.service.ListAssessments(r.Context(), orgID, status, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"assessments": assessments,
		"total":       total,
		"limit":       limit,
		"offset":      offset,
	})
}

// handleConformityByID handles requests to /api/v1/euaiact/conformity/{id}.
func (h *ConformityHandler) handleConformityByID(w http.ResponseWriter, r *http.Request) {
	// Extract ID and action from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/euaiact/conformity/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Assessment ID required", http.StatusBadRequest)
		return
	}

	assessmentID := parts[0]

	// Route shape and method are resolved BEFORE the organization gate, so a
	// CORS preflight and a wrong-method request keep answering exactly as they
	// did (200 / 405) rather than turning into "header required" - the org gate
	// must not change what an unauthenticated OPTIONS or a typo'd verb sees.
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	switch action {
	case "":
		if r.Method != http.MethodGet && r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	case "submit", "approve", "reject":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	// #3241: resolve the AUTHENTICATED organization ONCE, here, before any
	// branch touches the row. Every one of these five entry points used to
	// reach the repository with an id alone, so a foreign organization could
	// read, rewrite, submit, approve and reject another company's Article 43
	// assessment. Resolving at the dispatcher rather than per-handler means a
	// sixth action cannot be added with the check accidentally omitted.
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	switch action {
	case "submit":
		h.submitAssessment(w, r, orgID, assessmentID)
	case "approve":
		h.approveAssessment(w, r, orgID, assessmentID)
	case "reject":
		h.rejectAssessment(w, r, orgID, assessmentID)
	default:
		if r.Method == http.MethodGet {
			h.getAssessment(w, r, orgID, assessmentID)
			return
		}
		h.updateAssessment(w, r, orgID, assessmentID)
	}
}

// writeAssessmentError maps a by-id conformity failure to its HTTP shape.
//
// ErrAssessmentNotFound covers BOTH "no such id" and "that id belongs to
// another organization"; both are 404, so the refusal cannot be used to probe
// which assessment ids exist elsewhere on the deployment.
func writeAssessmentError(w http.ResponseWriter, err error, fallbackStatus int) {
	if errors.Is(err, ErrAssessmentNotFound) {
		writeError(w, http.StatusNotFound, "Assessment not found")
		return
	}
	writeError(w, fallbackStatus, err.Error())
}

// getAssessment handles GET /api/v1/euaiact/conformity/{id}.
func (h *ConformityHandler) getAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	assessment, err := h.service.GetAssessment(r.Context(), orgID, id)
	if err != nil {
		writeAssessmentError(w, err, http.StatusInternalServerError)
		return
	}
	if assessment == nil {
		writeError(w, http.StatusNotFound, "Assessment not found")
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// updateAssessment handles PUT /api/v1/euaiact/conformity/{id}.
func (h *ConformityHandler) updateAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	var req UpdateAssessmentRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	input := UpdateAssessmentInput{
		SystemName:      req.SystemName,
		RiskCategory:    req.RiskCategory,
		Assessors:       req.Assessors,
		Requirements:    req.Requirements,
		Evidence:        req.Evidence,
		Findings:        req.Findings,
		RiskMitigation:  req.RiskMitigation,
		Recommendations: req.Recommendations,
	}

	assessment, err := h.service.UpdateAssessment(r.Context(), orgID, id, input)
	if err != nil {
		writeAssessmentError(w, err, http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// submitAssessment handles POST /api/v1/euaiact/conformity/{id}/submit.
func (h *ConformityHandler) submitAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "system"
	}

	assessment, err := h.service.SubmitAssessment(r.Context(), orgID, id, userID)
	if err != nil {
		writeAssessmentError(w, err, http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// approveAssessment handles POST /api/v1/euaiact/conformity/{id}/approve.
func (h *ConformityHandler) approveAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "system"
	}

	// Parse validity years from request body (optional)
	var req struct {
		ValidityYears int `json:"validity_years"`
	}
	// Ignore decode errors - validity_years is optional
	_ = decodeJSONBody(r, &req)
	if req.ValidityYears <= 0 {
		req.ValidityYears = DefaultValidityYears
	}

	assessment, err := h.service.ApproveAssessment(r.Context(), orgID, id, userID, req.ValidityYears)
	if err != nil {
		writeAssessmentError(w, err, http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}

// rejectAssessment handles POST /api/v1/euaiact/conformity/{id}/reject.
func (h *ConformityHandler) rejectAssessment(w http.ResponseWriter, r *http.Request, orgID, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "system"
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	assessment, err := h.service.RejectAssessment(r.Context(), orgID, id, userID, req.Reason)
	if err != nil {
		writeAssessmentError(w, err, http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, assessment)
}
