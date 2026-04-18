// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// getOrgIDFromRequest extracts the org ID from query parameter or X-Org-ID header.
// Returns empty string if not found.
func getOrgIDFromRequest(r *http.Request) string {
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		orgID = r.Header.Get("X-Org-ID")
	}
	return orgID
}

// AuditExportHandler handles HTTP requests for audit exports.
type AuditExportHandler struct {
	service *AuditExportService
}

// NewAuditExportHandler creates a new audit export handler.
func NewAuditExportHandler(service *AuditExportService) *AuditExportHandler {
	return &AuditExportHandler{service: service}
}

// RegisterRoutes registers audit export routes with the given mux.
// Endpoints:
//   - POST   /api/v1/rbi/audit-exports          - Create export request
//   - GET    /api/v1/rbi/audit-exports          - List exports
//   - GET    /api/v1/rbi/audit-exports/{id}     - Get export
//   - DELETE /api/v1/rbi/audit-exports/{id}     - Delete export
//   - GET    /api/v1/rbi/audit-exports/{id}/download - Download export file
//   - POST   /api/v1/rbi/audit-exports/{id}/process  - Process export
func (h *AuditExportHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/rbi/audit-exports", h.handleExports)
	mux.HandleFunc("/api/v1/rbi/audit-exports/", h.handleExportRoutes)
}

// CreateAuditExportRequest is the request body for creating an audit export.
type CreateAuditExportRequest struct {
	ExportType       AuditExportType   `json:"export_type"`
	Format           AuditExportFormat `json:"format"`
	StartDate        *time.Time        `json:"start_date,omitempty"`
	EndDate          *time.Time        `json:"end_date,omitempty"`
	SystemIDs        []string          `json:"system_ids,omitempty"`
	RiskCategories   []string          `json:"risk_categories,omitempty"`
	IncludeArchived  bool              `json:"include_archived"`
	RequestedBy      string            `json:"requested_by,omitempty"`
	RequestedByEmail string            `json:"requested_by_email,omitempty"`
	Purpose          string            `json:"purpose,omitempty"`
}

// AuditExportResponse is the response for audit export operations.
type AuditExportResponse struct {
	Export *AuditExport `json:"export"`
}

// ListAuditExportsResponse is the response for listing audit exports.
type ListAuditExportsResponse struct {
	Exports []*AuditExport `json:"exports"`
	Total   int            `json:"total"`
	Limit   int            `json:"limit"`
	Offset  int            `json:"offset"`
}

// handleExports handles POST/GET /api/v1/rbi/audit-exports
func (h *AuditExportHandler) handleExports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createExport(w, r)
	case http.MethodGet:
		h.listExports(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleExportRoutes handles requests for /api/v1/rbi/audit-exports/...
func (h *AuditExportHandler) handleExportRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rbi/audit-exports/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid path")
		return
	}

	exportID := parts[0]

	// Handle sub-routes
	if len(parts) > 1 {
		switch parts[1] {
		case "download":
			if r.Method == http.MethodGet {
				h.downloadExport(w, r, exportID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		case "process":
			if r.Method == http.MethodPost {
				h.processExport(w, r, exportID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		}
	}

	// Handle base export routes
	switch r.Method {
	case http.MethodGet:
		h.getExport(w, r, exportID)
	case http.MethodDelete:
		h.deleteExport(w, r, exportID)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

func (h *AuditExportHandler) createExport(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_ORG_ID", "org_id is required")
		return
	}

	var req CreateAuditExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body: "+err.Error())
		return
	}

	export, err := h.service.CreateExport(r.Context(), &CreateExportRequest{
		OrgID:            orgID,
		ExportType:       req.ExportType,
		Format:           req.Format,
		StartDate:        req.StartDate,
		EndDate:          req.EndDate,
		SystemIDs:        req.SystemIDs,
		RiskCategories:   req.RiskCategories,
		IncludeArchived:  req.IncludeArchived,
		RequestedBy:      req.RequestedBy,
		RequestedByEmail: req.RequestedByEmail,
		Purpose:          req.Purpose,
	})
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "CREATE_FAILED", err.Error())
		return
	}

	h.writeJSON(w, http.StatusCreated, AuditExportResponse{Export: export})
}

func (h *AuditExportHandler) listExports(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_ORG_ID", "org_id is required")
		return
	}

	params := &ListAuditExportsParams{}

	// Parse query parameters
	if exportType := r.URL.Query().Get("export_type"); exportType != "" {
		params.ExportType = exportType
	}
	if status := r.URL.Query().Get("status"); status != "" {
		params.Status = status
	}
	if startDate := r.URL.Query().Get("start_date"); startDate != "" {
		if t, err := time.Parse(time.RFC3339, startDate); err == nil {
			params.StartDate = &t
		}
	}
	if endDate := r.URL.Query().Get("end_date"); endDate != "" {
		if t, err := time.Parse(time.RFC3339, endDate); err == nil {
			params.EndDate = &t
		}
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			params.Limit = l
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil {
			params.Offset = o
		}
	}

	exports, total, err := h.service.ListExports(r.Context(), orgID, params)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "LIST_FAILED", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, ListAuditExportsResponse{
		Exports: exports,
		Total:   total,
		Limit:   params.Limit,
		Offset:  params.Offset,
	})
}

func (h *AuditExportHandler) getExport(w http.ResponseWriter, r *http.Request, exportID string) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_ORG_ID", "org_id is required")
		return
	}

	export, err := h.service.GetExport(r.Context(), orgID, exportID)
	if err != nil {
		if err == ErrAuditExportNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Audit export not found")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "GET_FAILED", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, AuditExportResponse{Export: export})
}

func (h *AuditExportHandler) deleteExport(w http.ResponseWriter, r *http.Request, exportID string) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_ORG_ID", "org_id is required")
		return
	}

	err := h.service.DeleteExport(r.Context(), orgID, exportID)
	if err != nil {
		if err == ErrAuditExportNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Audit export not found")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "DELETE_FAILED", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuditExportHandler) downloadExport(w http.ResponseWriter, r *http.Request, exportID string) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_ORG_ID", "org_id is required")
		return
	}

	// Try to get a presigned URL for cloud exports
	downloadURL, err := h.service.GetExportDownloadURL(r.Context(), orgID, exportID)
	if err != nil {
		if err == ErrAuditExportNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Audit export not found")
			return
		}
		// Fall through to direct download
	}

	if downloadURL != "" {
		http.Redirect(w, r, downloadURL, http.StatusTemporaryRedirect)
		return
	}

	// Fall back to streaming the file directly
	content, filename, err := h.service.GetExportFile(r.Context(), orgID, exportID)
	if err != nil {
		if err == ErrAuditExportNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Audit export not found")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "DOWNLOAD_FAILED", err.Error())
		return
	}

	// Set content type based on file extension
	contentType := "application/octet-stream"
	if strings.HasSuffix(filename, ".json") {
		contentType = "application/json"
	} else if strings.HasSuffix(filename, ".csv") {
		contentType = "text/csv"
	} else if strings.HasSuffix(filename, ".pdf") {
		contentType = "application/pdf"
	} else if strings.HasSuffix(filename, ".xlsx") {
		contentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.Write(content)
}

func (h *AuditExportHandler) processExport(w http.ResponseWriter, r *http.Request, exportID string) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_ORG_ID", "org_id is required")
		return
	}

	export, err := h.service.GetExport(r.Context(), orgID, exportID)
	if err != nil {
		if err == ErrAuditExportNotFound {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Audit export not found")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "GET_FAILED", err.Error())
		return
	}

	if export.Status != AuditExportStatusPending {
		h.writeError(w, http.StatusBadRequest, "INVALID_STATUS",
			fmt.Sprintf("Export cannot be processed, current status: %s", export.Status))
		return
	}

	// Process synchronously for now (in production, use async processing)
	if err := h.service.ProcessExport(r.Context(), export); err != nil {
		h.writeError(w, http.StatusInternalServerError, "PROCESS_FAILED", "Failed to process export: "+err.Error())
		return
	}

	// Refetch to get updated status
	export, _ = h.service.GetExport(r.Context(), orgID, exportID)
	h.writeJSON(w, http.StatusOK, AuditExportResponse{Export: export})
}

// handleCORS handles CORS preflight requests.
func (h *AuditExportHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Org-ID")
	w.WriteHeader(http.StatusNoContent)
}

// writeJSON writes a JSON response.
func (h *AuditExportHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[RBI AuditExport] Error encoding JSON: %v", err)
	}
}

// writeError writes an error response.
func (h *AuditExportHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
