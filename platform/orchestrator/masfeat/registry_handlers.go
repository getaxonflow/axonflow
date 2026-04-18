// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"net/http"
	"strconv"
	"strings"
)

// RegistryHandler handles HTTP requests for AI system registry operations.
type RegistryHandler struct {
	service *RegistryService
}

// NewRegistryHandler creates a new registry handler.
func NewRegistryHandler(service *RegistryService) *RegistryHandler {
	return &RegistryHandler{service: service}
}

// RegisterRoutes registers the registry routes on an http.ServeMux.
func (h *RegistryHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/masfeat/registry", h.handleRegistry)
	mux.HandleFunc("/api/v1/masfeat/registry/summary", h.handleRegistrySummary)
	mux.HandleFunc("/api/v1/masfeat/registry/", h.handleRegistryByID)
}

// handleRegistry handles POST (create) and GET (list) for /api/v1/masfeat/registry.
func (h *RegistryHandler) handleRegistry(w http.ResponseWriter, r *http.Request) {
	// Handle CORS preflight
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
		h.createSystem(w, r, orgID)
	case http.MethodGet:
		h.listSystems(w, r, orgID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleRegistrySummary handles GET for /api/v1/masfeat/registry/summary.
func (h *RegistryHandler) handleRegistrySummary(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	summary, err := h.service.GetSummary(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

// handleRegistryByID handles GET, PUT, DELETE for /api/v1/masfeat/registry/{id}.
func (h *RegistryHandler) handleRegistryByID(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	// Extract ID from path
	id := extractIDFromPath(r.URL.Path, "/api/v1/masfeat/registry/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "System ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getSystem(w, r, orgID, id)
	case http.MethodPut:
		h.updateSystem(w, r, orgID, id)
	case http.MethodDelete:
		h.deleteSystem(w, r, orgID, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// createSystem handles POST /api/v1/masfeat/registry.
func (h *RegistryHandler) createSystem(w http.ResponseWriter, r *http.Request, orgID string) {
	var req CreateRegistryRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	system, err := h.service.RegisterSystem(r.Context(), orgID, &req, user)
	if err != nil {
		// Check for duplicate error
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, system)
}

// listSystems handles GET /api/v1/masfeat/registry.
func (h *RegistryHandler) listSystems(w http.ResponseWriter, r *http.Request, orgID string) {
	params := ListParams{
		Status: r.URL.Query().Get("status"),
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

	systems, err := h.service.ListSystems(r.Context(), orgID, params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if systems == nil {
		systems = []*AISystemRegistry{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"systems": systems,
		"count":   len(systems),
	})
}

// getSystem handles GET /api/v1/masfeat/registry/{id}.
func (h *RegistryHandler) getSystem(w http.ResponseWriter, r *http.Request, orgID, id string) {
	system, err := h.service.GetSystem(r.Context(), orgID, id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, system)
}

// updateSystem handles PUT /api/v1/masfeat/registry/{id}.
func (h *RegistryHandler) updateSystem(w http.ResponseWriter, r *http.Request, orgID, id string) {
	var req UpdateRegistryRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	system, err := h.service.UpdateSystem(r.Context(), orgID, id, &req, user)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, system)
}

// deleteSystem handles DELETE /api/v1/masfeat/registry/{id}.
func (h *RegistryHandler) deleteSystem(w http.ResponseWriter, r *http.Request, orgID, id string) {
	err := h.service.DeleteSystem(r.Context(), orgID, id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "System retired successfully",
		"id":      id,
	})
}

// extractIDFromPath extracts the ID from a URL path given a prefix.
func extractIDFromPath(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	id := strings.TrimPrefix(path, prefix)
	// Remove trailing slashes and any additional path segments
	if idx := strings.Index(id, "/"); idx != -1 {
		id = id[:idx]
	}
	return id
}
