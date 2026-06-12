//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// OJKAuditExportHandler handles HTTP requests for OJK compliance.
type OJKAuditExportHandler struct {
	service OJKAuditExportService
}

// NewOJKAuditExportHandler creates a new handler.
func NewOJKAuditExportHandler(service OJKAuditExportService) *OJKAuditExportHandler {
	return &OJKAuditExportHandler{service: service}
}

// RegisterRoutes registers OJK routes on a standard http.ServeMux.
func (h *OJKAuditExportHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/ojk/audit/export", h.handleExport)
	mux.HandleFunc("/api/v1/ojk/audit/export/", h.handleExportByID)
	mux.HandleFunc("/api/v1/ojk/audit/retention", h.handleRetentionStatus)
	mux.HandleFunc("/api/v1/ojk/audit/readiness", h.handleComplianceReadiness)
	mux.HandleFunc("/api/v1/ojk/breach/notify", h.handleBreachNotify)
	mux.HandleFunc("/api/v1/ojk/breach/acknowledge", h.handleBreachAcknowledge)
	mux.HandleFunc("/api/v1/ojk/breach/evaluate-deadlines", h.handleBreachEvaluateDeadlines)
	mux.HandleFunc("/api/v1/ojk/dashboard", h.handleDashboard)
}

func (h *OJKAuditExportHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.exportAuditData(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

func (h *OJKAuditExportHandler) handleExportByID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getExportStatus(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

func (h *OJKAuditExportHandler) handleExportByIDWithMux(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getExportStatusMux(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

func (h *OJKAuditExportHandler) handleRetentionStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getRetentionStatus(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

func (h *OJKAuditExportHandler) handleComplianceReadiness(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getComplianceReadiness(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

func (h *OJKAuditExportHandler) handleBreachNotify(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.submitBreachNotification(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

func (h *OJKAuditExportHandler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getDashboard(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

func (h *OJKAuditExportHandler) exportAuditData(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	var req OJKAuditExportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		h.writeError(w, "invalid_request", "Invalid request body", err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.validateExportRequest(&req); err != nil {
		h.writeError(w, "validation_error", err.Error(), "", http.StatusBadRequest)
		return
	}

	resp, err := h.service.ExportAuditData(r.Context(), tenantID, &req)
	if err != nil {
		log.Printf("OJK export error for tenant %s: %v", tenantID, err)
		h.writeError(w, "internal_error", "Export failed", err.Error(), http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *OJKAuditExportHandler) getExportStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	path := r.URL.Path
	exportID := strings.TrimPrefix(path, "/api/v1/ojk/audit/export/")
	if exportID == "" || exportID == path {
		h.writeError(w, "missing_export_id", "Export ID is required", "", http.StatusBadRequest)
		return
	}

	resp, err := h.service.GetExportStatus(r.Context(), tenantID, exportID)
	if err != nil {
		h.writeError(w, "not_found", "Export not found", err.Error(), http.StatusNotFound)
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *OJKAuditExportHandler) getExportStatusMux(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	vars := mux.Vars(r)
	exportID := vars["id"]
	if exportID == "" {
		h.writeError(w, "missing_export_id", "Export ID is required", "", http.StatusBadRequest)
		return
	}

	resp, err := h.service.GetExportStatus(r.Context(), tenantID, exportID)
	if err != nil {
		h.writeError(w, "not_found", "Export not found", err.Error(), http.StatusNotFound)
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *OJKAuditExportHandler) getRetentionStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	req := &OJKRetentionStatusRequest{}
	dataTypes := r.URL.Query().Get("data_types")
	if dataTypes != "" {
		for _, dt := range strings.Split(dataTypes, ",") {
			req.DataTypes = append(req.DataTypes, OJKAuditDataType(strings.TrimSpace(dt)))
		}
	}

	resp, err := h.service.GetRetentionStatus(r.Context(), tenantID, req)
	if err != nil {
		h.writeError(w, "internal_error", "Failed to get retention status", err.Error(), http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *OJKAuditExportHandler) getComplianceReadiness(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	resp, err := h.service.ValidateComplianceReadiness(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, "internal_error", "Failed to validate readiness", err.Error(), http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *OJKAuditExportHandler) submitBreachNotification(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	var req OJKBreachNotification
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		h.writeError(w, "invalid_request", "Invalid request body", err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.validateBreachNotification(&req); err != nil {
		h.writeError(w, "validation_error", err.Error(), "", http.StatusBadRequest)
		return
	}

	resp, err := h.service.SubmitBreachNotification(r.Context(), tenantID, &req)
	if err != nil {
		log.Printf("OJK breach notification error for tenant %s: %v", tenantID, err)
		h.writeError(w, "internal_error", "Failed to submit breach notification", err.Error(), http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, http.StatusCreated, resp)
}

func (h *OJKAuditExportHandler) getDashboard(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	resp, err := h.service.GetDashboard(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, "internal_error", "Failed to get dashboard", err.Error(), http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

func (h *OJKAuditExportHandler) handleBreachAcknowledge(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.acknowledgeBreach(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

func (h *OJKAuditExportHandler) handleBreachEvaluateDeadlines(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.evaluateBreachDeadlines(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, "method_not_allowed", "Method not allowed", "", http.StatusMethodNotAllowed)
	}
}

// acknowledgeBreach records authority receipt for a previously submitted breach.
// Maps service sentinels to client-correctable HTTP codes: 404 for an unknown
// id, 409 when the breach is not in a submittable→acknowledgeable state.
func (h *OJKAuditExportHandler) acknowledgeBreach(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		h.writeError(w, "invalid_request", "Invalid request body", err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.ID) == "" {
		h.writeError(w, "validation_error", "id is required", "", http.StatusBadRequest)
		return
	}

	resp, err := h.service.AcknowledgeBreachNotification(r.Context(), tenantID, strings.TrimSpace(body.ID))
	if err != nil {
		switch {
		case errors.Is(err, ErrBreachNotFound):
			h.writeError(w, "not_found", "Breach notification not found", err.Error(), http.StatusNotFound)
		case errors.Is(err, ErrInvalidBreachTransition):
			h.writeError(w, "invalid_transition", "Breach cannot be acknowledged from its current status", err.Error(), http.StatusConflict)
		default:
			log.Printf("OJK breach acknowledge error for tenant %s: %v", tenantID, err)
			h.writeError(w, "internal_error", "Failed to acknowledge breach notification", err.Error(), http.StatusInternalServerError)
		}
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// evaluateBreachDeadlines durably flips never-submitted lapsed drafts to overdue
// and returns how many rows changed.
func (h *OJKAuditExportHandler) evaluateBreachDeadlines(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, "missing_tenant", "Tenant ID is required", "", http.StatusBadRequest)
		return
	}

	flipped, err := h.service.EvaluateBreachDeadlines(r.Context(), tenantID)
	if err != nil {
		log.Printf("OJK breach deadline evaluation error for tenant %s: %v", tenantID, err)
		h.writeError(w, "internal_error", "Failed to evaluate breach deadlines", err.Error(), http.StatusInternalServerError)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]int{"flipped_overdue": flipped})
}

func (h *OJKAuditExportHandler) validateExportRequest(req *OJKAuditExportRequest) error {
	if req.StartDate == "" || req.EndDate == "" {
		return fmt.Errorf("start_date and end_date are required")
	}

	start, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return fmt.Errorf("invalid start_date format (expected YYYY-MM-DD)")
	}
	end, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return fmt.Errorf("invalid end_date format (expected YYYY-MM-DD)")
	}

	if end.Before(start) {
		return fmt.Errorf("end_date must be after start_date")
	}

	maxRange := 5 * 365 * 24 * time.Hour
	if end.Sub(start) > maxRange {
		return fmt.Errorf("date range cannot exceed 5 years")
	}

	if req.Format != "" {
		switch req.Format {
		case OJKFormatJSON, OJKFormatCSV, OJKFormatXML:
		default:
			return fmt.Errorf("unsupported format: %s (allowed: json, csv, xml)", req.Format)
		}
	}

	if req.Framework != "" {
		switch req.Framework {
		case OJKFrameworkAIGovernance, OJKFrameworkUUPDP, OJKFrameworkBIPJP, OJKFrameworkCombined:
		default:
			return fmt.Errorf("unsupported framework: %s", req.Framework)
		}
	}

	return nil
}

func (h *OJKAuditExportHandler) validateBreachNotification(req *OJKBreachNotification) error {
	if req.IncidentTimestamp.IsZero() {
		return fmt.Errorf("incident_timestamp is required")
	}
	if req.DiscoveryTime.IsZero() {
		return fmt.Errorf("discovery_time is required")
	}
	if req.DataSubjectsAffected <= 0 {
		return fmt.Errorf("data_subjects_affected must be positive")
	}
	if len(req.DataTypesInvolved) == 0 {
		return fmt.Errorf("data_types_involved is required (UU PDP Art. 46)")
	}
	if req.Description == "" {
		return fmt.Errorf("description is required (UU PDP Art. 46)")
	}
	if len(req.RemediationSteps) == 0 {
		return fmt.Errorf("remediation_steps is required (UU PDP Art. 46)")
	}
	return nil
}

func (h *OJKAuditExportHandler) getTenantID(r *http.Request) string {
	if id := r.Header.Get("X-Tenant-ID"); id != "" {
		return id
	}
	if id := r.Header.Get("X-Org-ID"); id != "" {
		return id
	}
	return ""
}

var allowedCORSOrigins = map[string]bool{
	"https://app.getaxonflow.com":         true,
	"https://try.getaxonflow.com":         true,
	"https://try-staging.getaxonflow.com": true,
	"http://localhost:3000":               true,
	"http://localhost:3001":               true,
}

func (h *OJKAuditExportHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedCORSOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Tenant-ID, X-Org-ID, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *OJKAuditExportHandler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *OJKAuditExportHandler) writeError(w http.ResponseWriter, code, message, details string, status int) {
	h.writeJSON(w, status, OJKAPIError{
		Code:    code,
		Message: message,
		Details: details,
	})
}
