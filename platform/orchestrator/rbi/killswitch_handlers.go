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
)

// KillSwitchHandler handles HTTP requests for kill switch operations.
type KillSwitchHandler struct {
	service KillSwitchService
}

// NewKillSwitchHandler creates a new handler.
func NewKillSwitchHandler(service KillSwitchService) *KillSwitchHandler {
	return &KillSwitchHandler{service: service}
}

// RegisterRoutes registers kill switch routes with the provided mux.
// Endpoints:
//   - POST   /api/v1/rbi/killswitches             - Create kill switch
//   - GET    /api/v1/rbi/killswitches             - List kill switches
//   - GET    /api/v1/rbi/killswitches/active      - List active kill switches
//   - GET    /api/v1/rbi/killswitches/check       - Check if blocked
//   - GET    /api/v1/rbi/killswitches/{id}        - Get kill switch
//   - DELETE /api/v1/rbi/killswitches/{id}        - Delete kill switch
//   - POST   /api/v1/rbi/killswitches/{id}/activate   - Activate
//   - POST   /api/v1/rbi/killswitches/{id}/deactivate - Deactivate
//   - GET    /api/v1/rbi/killswitches/{id}/history    - Get history
func (h *KillSwitchHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/rbi/killswitches", h.handleKillSwitches)
	mux.HandleFunc("/api/v1/rbi/killswitches/", h.handleKillSwitchRoutes)
}

// handleKillSwitches handles POST/GET /api/v1/rbi/killswitches
func (h *KillSwitchHandler) handleKillSwitches(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createKillSwitch(w, r)
	case http.MethodGet:
		h.listKillSwitches(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleKillSwitchRoutes handles requests for /api/v1/rbi/killswitches/...
func (h *KillSwitchHandler) handleKillSwitchRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/rbi/killswitches/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid path")
		return
	}

	// Handle special routes
	switch parts[0] {
	case "active":
		if r.Method == http.MethodGet {
			h.listActiveKillSwitches(w, r)
		} else if r.Method == http.MethodOptions {
			h.handleCORS(w, r)
		} else {
			h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
		return
	case "check":
		if r.Method == http.MethodGet {
			h.checkKillSwitch(w, r)
		} else if r.Method == http.MethodOptions {
			h.handleCORS(w, r)
		} else {
			h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
		return
	}

	killSwitchID := parts[0]

	// Handle sub-routes
	if len(parts) > 1 {
		switch parts[1] {
		case "activate":
			if r.Method == http.MethodPost {
				h.activateKillSwitch(w, r, killSwitchID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		case "deactivate":
			if r.Method == http.MethodPost {
				h.deactivateKillSwitch(w, r, killSwitchID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		case "history":
			if r.Method == http.MethodGet {
				h.getHistory(w, r, killSwitchID)
			} else if r.Method == http.MethodOptions {
				h.handleCORS(w, r)
			} else {
				h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
			}
			return
		}
	}

	// Handle basic CRUD
	switch r.Method {
	case http.MethodGet:
		h.getKillSwitch(w, r, killSwitchID)
	case http.MethodDelete:
		h.deleteKillSwitch(w, r, killSwitchID)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// createKillSwitch handles POST /api/v1/rbi/killswitches
func (h *KillSwitchHandler) createKillSwitch(w http.ResponseWriter, r *http.Request) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req CreateKillSwitchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	ks, err := h.service.CreateKillSwitch(r.Context(), orgID, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusCreated, ks)
}

// listKillSwitches handles GET /api/v1/rbi/killswitches
func (h *KillSwitchHandler) listKillSwitches(w http.ResponseWriter, r *http.Request) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	params := &ListKillSwitchParams{
		SystemID: r.URL.Query().Get("system_id"),
		Scope:    r.URL.Query().Get("scope"),
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
	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		val := activeStr == "true"
		params.IsActive = &val
	}

	switches, total, err := h.service.ListKillSwitches(r.Context(), orgID, params)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	response := map[string]interface{}{
		"kill_switches": switches,
		"total":         total,
		"limit":         params.Limit,
		"offset":        params.Offset,
	}

	h.writeJSON(w, http.StatusOK, response)
}

// listActiveKillSwitches handles GET /api/v1/rbi/killswitches/active
func (h *KillSwitchHandler) listActiveKillSwitches(w http.ResponseWriter, r *http.Request) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	switches, err := h.service.ListActiveKillSwitches(r.Context(), orgID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"kill_switches": switches,
		"total":         len(switches),
	})
}

// checkKillSwitch handles GET /api/v1/rbi/killswitches/check
func (h *KillSwitchHandler) checkKillSwitch(w http.ResponseWriter, r *http.Request) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	scopeStr := r.URL.Query().Get("scope")
	if scopeStr == "" {
		scopeStr = "system"
	}
	scope := KillSwitchScope(scopeStr)

	systemID := r.URL.Query().Get("system_id")
	targetID := r.URL.Query().Get("target_id")

	result, err := h.service.CheckKillSwitch(r.Context(), orgID, scope, systemID, targetID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// getKillSwitch handles GET /api/v1/rbi/killswitches/{id}
func (h *KillSwitchHandler) getKillSwitch(w http.ResponseWriter, r *http.Request, id string) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	ks, err := h.service.GetKillSwitch(r.Context(), orgID, id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, ks)
}

// deleteKillSwitch handles DELETE /api/v1/rbi/killswitches/{id}
func (h *KillSwitchHandler) deleteKillSwitch(w http.ResponseWriter, r *http.Request, id string) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	if err := h.service.DeleteKillSwitch(r.Context(), orgID, id); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// activateKillSwitch handles POST /api/v1/rbi/killswitches/{id}/activate
func (h *KillSwitchHandler) activateKillSwitch(w http.ResponseWriter, r *http.Request, id string) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req ActivateKillSwitchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	ks, err := h.service.Activate(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, ks)
}

// deactivateKillSwitch handles POST /api/v1/rbi/killswitches/{id}/deactivate
func (h *KillSwitchHandler) deactivateKillSwitch(w http.ResponseWriter, r *http.Request, id string) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var req DeactivateKillSwitchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON in request body")
		return
	}

	ks, err := h.service.Deactivate(r.Context(), orgID, id, &req)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, ks)
}

// getHistory handles GET /api/v1/rbi/killswitches/{id}/history
func (h *KillSwitchHandler) getHistory(w http.ResponseWriter, r *http.Request, id string) {
	orgID := h.getOrgID(r)
	if orgID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Organization ID required")
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil {
			limit = val
		}
	}

	history, err := h.service.GetHistory(r.Context(), orgID, id, limit)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"history": history,
		"total":   len(history),
	})
}

// getOrgID extracts the organization ID from the request.
func (h *KillSwitchHandler) getOrgID(r *http.Request) string {
	if orgID := r.Header.Get("X-Org-ID"); orgID != "" {
		return orgID
	}
	return r.URL.Query().Get("org_id")
}

// handleCORS handles OPTIONS requests.
func (h *KillSwitchHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Org-ID")
	w.WriteHeader(http.StatusNoContent)
}

// handleServiceError maps service errors to HTTP responses.
func (h *KillSwitchHandler) handleServiceError(w http.ResponseWriter, err error) {
	log.Printf("[RBI KillSwitch] Error: %v", err)

	switch {
	case errors.Is(err, ErrKillSwitchNotFound):
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Kill switch not found")
	case errors.Is(err, ErrSystemNotFound):
		h.writeError(w, http.StatusNotFound, "SYSTEM_NOT_FOUND", "AI system not found")
	case errors.Is(err, ErrInvalidInput):
		h.writeError(w, http.StatusBadRequest, "INVALID_INPUT", err.Error())
	default:
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred")
	}
}

// writeJSON writes a JSON response.
func (h *KillSwitchHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[RBI KillSwitch] Error encoding JSON: %v", err)
	}
}

// writeError writes an error response.
func (h *KillSwitchHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
