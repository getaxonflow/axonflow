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

// BoardReportHandler handles HTTP requests for board report operations.
type BoardReportHandler struct {
	service BoardReportService
}

// NewBoardReportHandler creates a new handler.
func NewBoardReportHandler(service BoardReportService) *BoardReportHandler {
	return &BoardReportHandler{service: service}
}

// RegisterRoutes registers board report routes with the provided mux.
// Endpoints:
//   - POST   /api/v1/rbi/reports          - Generate report
//   - GET    /api/v1/rbi/reports          - List reports
//   - GET    /api/v1/rbi/reports/pending  - List pending approval
//   - GET    /api/v1/rbi/reports/latest   - Get latest report by type
//   - GET    /api/v1/rbi/reports/{id}     - Get report
//   - DELETE /api/v1/rbi/reports/{id}     - Delete report
//   - POST   /api/v1/rbi/reports/{id}/submit   - Submit for approval
//   - POST   /api/v1/rbi/reports/{id}/approve  - Approve report
//   - POST   /api/v1/rbi/reports/{id}/reject   - Reject report
//   - POST   /api/v1/rbi/reports/{id}/actions  - Add corrective action
//   - PUT    /api/v1/rbi/reports/{id}/actions/{action_id} - Update action
func (h *BoardReportHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/rbi/reports", h.handleReports)
	mux.HandleFunc("/api/v1/rbi/reports/", h.handleReportRoutes)
}

// handleReports handles POST/GET /api/v1/rbi/reports
func (h *BoardReportHandler) handleReports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.generateReport(w, r)
	case http.MethodGet:
		h.listReports(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleReportRoutes handles requests for /api/v1/rbi/reports/...
func (h *BoardReportHandler) handleReportRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rbi/reports/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid path")
		return
	}

	// Handle special routes
	switch parts[0] {
	case "pending":
		if r.Method == http.MethodGet {
			h.getPendingApproval(w, r)
		} else if r.Method == http.MethodOptions {
			h.handleCORS(w, r)
		} else {
			h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
		return
	case "latest":
		if r.Method == http.MethodGet {
			h.getLatestReport(w, r)
		} else if r.Method == http.MethodOptions {
			h.handleCORS(w, r)
		} else {
			h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
		return
	}

	reportID := parts[0]

	// Handle sub-routes
	if len(parts) > 1 {
		switch parts[1] {
		case "submit":
			if r.Method == http.MethodPost {
				h.submitForApproval(w, r, reportID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		case "approve":
			if r.Method == http.MethodPost {
				h.approveReport(w, r, reportID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		case "reject":
			if r.Method == http.MethodPost {
				h.rejectReport(w, r, reportID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		case "actions":
			if len(parts) > 2 {
				// PUT /reports/{id}/actions/{action_id}
				if r.Method == http.MethodPut {
					h.updateCorrectiveAction(w, r, reportID, parts[2])
				} else if r.Method == http.MethodOptions {
					h.handleCORS(w, r)
				} else {
					h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
				}
			} else {
				// POST /reports/{id}/actions
				if r.Method == http.MethodPost {
					h.addCorrectiveAction(w, r, reportID)
				} else if r.Method == http.MethodOptions {
					h.handleCORS(w, r)
				} else {
					h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
				}
			}
			return
		}
	}

	// Handle basic CRUD
	switch r.Method {
	case http.MethodGet:
		h.getReport(w, r, reportID)
	case http.MethodDelete:
		h.deleteReport(w, r, reportID)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// generateReport handles POST /api/v1/rbi/reports
func (h *BoardReportHandler) generateReport(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req GenerateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	// #3150: generated_by / generated_by_email are persisted onto
	// rbi_board_reports as the author of the RBI FREE-AI board report. They
	// come from the authenticated caller, never the body.
	actor := resolveActor(r)
	req.GeneratedBy = actor.ID
	req.GeneratedByEmail = actor.Email

	report, err := h.service.GenerateReport(r.Context(), orgID, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusCreated, report)
}

// listReports handles GET /api/v1/rbi/reports
func (h *BoardReportHandler) listReports(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	params := &ListBoardReportsParams{
		ReportType:     r.URL.Query().Get("report_type"),
		Quarter:        r.URL.Query().Get("quarter"),
		ApprovalStatus: r.URL.Query().Get("approval_status"),
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
	if startStr := r.URL.Query().Get("start_date"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			params.StartDate = &t
		}
	}
	if endStr := r.URL.Query().Get("end_date"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			params.EndDate = &t
		}
	}

	reports, total, err := h.service.ListReports(r.Context(), orgID, params)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := map[string]interface{}{
		"reports": reports,
		"total":   total,
		"limit":   params.Limit,
		"offset":  params.Offset,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getReport handles GET /api/v1/rbi/reports/{id}
func (h *BoardReportHandler) getReport(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	report, err := h.service.GetReport(r.Context(), orgID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// deleteReport handles DELETE /api/v1/rbi/reports/{id}
func (h *BoardReportHandler) deleteReport(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	if err := h.service.DeleteReport(r.Context(), orgID, id); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// getPendingApproval handles GET /api/v1/rbi/reports/pending
func (h *BoardReportHandler) getPendingApproval(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	reports, err := h.service.GetPendingApproval(r.Context(), orgID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"reports": reports,
		"total":   len(reports),
	})
}

// getLatestReport handles GET /api/v1/rbi/reports/latest
func (h *BoardReportHandler) getLatestReport(w http.ResponseWriter, r *http.Request) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	reportTypeStr := r.URL.Query().Get("report_type")
	if reportTypeStr == "" {
		reportTypeStr = "quarterly"
	}
	reportType := ReportType(reportTypeStr)

	report, err := h.service.GetLatestReport(r.Context(), orgID, reportType)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// submitForApproval handles POST /api/v1/rbi/reports/{id}/submit
func (h *BoardReportHandler) submitForApproval(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req SubmitForApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	// #3150: submitted_by / submitted_by_email reach only the operational log
	// today (the BoardReport row has no submitter column), which is exactly
	// why they are bound here too: a `validate:"required"` field that writes
	// nothing is one schema change away from becoming a persisted actor.
	actor := resolveActor(r)
	req.SubmittedBy = actor.ID
	req.SubmittedByEmail = actor.Email

	report, err := h.service.SubmitForApproval(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// approveReport handles POST /api/v1/rbi/reports/{id}/approve
func (h *BoardReportHandler) approveReport(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req ApproveReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	// #3150: approved_by / approved_by_email are persisted onto
	// rbi_board_reports.approved_by(_email) and are the single most sensitive
	// actor in this module — a board approval is the artefact the regulator
	// reads. Bound to the authenticated caller.
	actor := resolveActor(r)
	req.ApprovedBy = actor.ID
	req.ApprovedByEmail = actor.Email

	report, err := h.service.ApproveReport(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// rejectReport handles POST /api/v1/rbi/reports/{id}/reject
func (h *BoardReportHandler) rejectReport(w http.ResponseWriter, r *http.Request, id string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req RejectReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	// #3150: same class as approveReport. rejected_by is log-only today; see
	// the submitForApproval note for why it is bound anyway.
	actor := resolveActor(r)
	req.RejectedBy = actor.ID
	req.RejectedByEmail = actor.Email

	report, err := h.service.RejectReport(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// addCorrectiveAction handles POST /api/v1/rbi/reports/{id}/actions
func (h *BoardReportHandler) addCorrectiveAction(w http.ResponseWriter, r *http.Request, reportID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var action CorrectiveAction
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	report, err := h.service.AddCorrectiveAction(r.Context(), orgID, reportID, &action)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// updateCorrectiveAction handles PUT /api/v1/rbi/reports/{id}/actions/{action_id}
func (h *BoardReportHandler) updateCorrectiveAction(w http.ResponseWriter, r *http.Request, reportID, actionID string) {
	orgID := resolveOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var update UpdateCorrectiveActionRequest
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	report, err := h.service.UpdateCorrectiveAction(r.Context(), orgID, reportID, actionID, &update)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// handleCORS handles OPTIONS requests.
func (h *BoardReportHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Org-ID")
	w.WriteHeader(http.StatusNoContent)
}

// handleServiceError maps service errors to HTTP responses.
func (h *BoardReportHandler) handleServiceError(w http.ResponseWriter, err error) {
	log.Printf("[RBI BoardReport] Error: %v", err)

	switch {
	case errors.Is(err, ErrBoardReportNotFound):
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Board report not found")
	case errors.Is(err, ErrInvalidInput):
		h.writeError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	default:
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred")
	}
}

// writeJSON writes a JSON response.
func (h *BoardReportHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[RBI BoardReport] Error encoding JSON: %v", err)
	}
}

// writeError writes an error response.
func (h *BoardReportHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
