// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ExportHandler handles HTTP requests for EU AI Act exports.
type ExportHandler struct {
	service *ExportService
}

// NewExportHandler creates a new export handler.
func NewExportHandler(service *ExportService) *ExportHandler {
	return &ExportHandler{service: service}
}

// RegisterRoutes registers export routes on the given mux.
func (h *ExportHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/euaiact/export", h.handleExport)
	mux.HandleFunc("/api/v1/euaiact/export/", h.handleExportByID)
}

// handleExport handles POST/GET /api/v1/euaiact/export.
func (h *ExportHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createExport(w, r)
	case http.MethodGet:
		h.listExports(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// createExport handles POST /api/v1/euaiact/export.
func (h *ExportHandler) createExport(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	var req CreateExportRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	// Parse dates
	var dateFrom, dateTo time.Time
	if req.DateFrom != "" {
		var err error
		dateFrom, err = time.Parse(time.RFC3339, req.DateFrom)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid date_from format, use RFC3339")
			return
		}
	}
	if req.DateTo != "" {
		var err error
		dateTo, err = time.Parse(time.RFC3339, req.DateTo)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid date_to format, use RFC3339")
			return
		}
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "system"
	}

	input := CreateExportInput{
		OrgID:       orgID,
		ExportType:  req.ExportType,
		Format:      req.Format,
		DateFrom:    dateFrom,
		DateTo:      dateTo,
		ModelIDs:    req.ModelIDs,
		Filters:     req.Filters,
		RequestedBy: userID,
	}

	export, err := h.service.CreateExport(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, export)
}

// listExports handles GET /api/v1/euaiact/export.
func (h *ExportHandler) listExports(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

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

	exports, total, err := h.service.ListExports(r.Context(), orgID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"exports": exports,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// handleExportByID handles requests to /api/v1/euaiact/export/{id}.
func (h *ExportHandler) handleExportByID(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/euaiact/export/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Export ID required", http.StatusBadRequest)
		return
	}

	exportID := parts[0]

	// Check for download action
	if len(parts) > 1 && parts[1] == "download" {
		h.downloadExport(w, r, exportID)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	export, err := h.service.GetExport(r.Context(), exportID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if export == nil {
		writeError(w, http.StatusNotFound, "Export not found")
		return
	}

	writeJSON(w, http.StatusOK, export)
}

// downloadExport handles GET /api/v1/euaiact/export/{id}/download.
func (h *ExportHandler) downloadExport(w http.ResponseWriter, r *http.Request, exportID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	export, err := h.service.GetExport(r.Context(), exportID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if export == nil {
		writeError(w, http.StatusNotFound, "Export not found")
		return
	}

	if export.Status != ExportStatusCompleted {
		writeError(w, http.StatusBadRequest, "Export not yet completed")
		return
	}

	// If the export has a cloud storage key and the service has a storage backend,
	// generate a presigned URL and redirect the client.
	if export.StorageKey != "" {
		downloadURL, err := h.service.GetExportDownloadURL(r.Context(), exportID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to generate download URL: "+err.Error())
			return
		}
		if downloadURL != "" {
			http.Redirect(w, r, downloadURL, http.StatusTemporaryRedirect)
			return
		}
	}

	if export.FilePath == "" {
		writeError(w, http.StatusNotFound, "Export file not available")
		return
	}

	// Fallback: return the export metadata with file path for local storage
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":        export.ID,
		"file_path": export.FilePath,
		"file_size": export.FileSize,
		"format":    export.Format,
	})
}
