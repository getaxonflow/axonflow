// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"net/http"
	"strconv"
	"strings"
)

// KillSwitchHandler handles HTTP requests for kill switch operations.
type KillSwitchHandler struct {
	service *KillSwitchService
}

// NewKillSwitchHandler creates a new kill switch handler.
func NewKillSwitchHandler(service *KillSwitchService) *KillSwitchHandler {
	return &KillSwitchHandler{service: service}
}

// RegisterRoutes registers the kill switch routes on an http.ServeMux.
func (h *KillSwitchHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/masfeat/killswitch/", h.handleKillSwitchRoute)
}

// handleKillSwitchRoute routes kill switch requests.
func (h *KillSwitchHandler) handleKillSwitchRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	// Parse path: /api/v1/masfeat/killswitch/{system_id}[/action]
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/masfeat/killswitch/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "System ID required")
		return
	}

	systemID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	// Route to appropriate handler
	switch action {
	case "":
		h.handleKillSwitch(w, r)
	case "configure":
		h.handleKillSwitchConfigure(w, r)
	case "trigger":
		h.handleKillSwitchTrigger(w, r)
	case "restore":
		h.handleKillSwitchRestore(w, r)
	case "history":
		h.handleKillSwitchHistory(w, r)
	case "enable":
		h.handleKillSwitchEnable(w, r, orgID, systemID)
	case "disable":
		h.handleKillSwitchDisable(w, r, orgID, systemID)
	default:
		writeError(w, http.StatusNotFound, "Unknown action: "+action)
	}
}

// handleKillSwitch handles GET /api/v1/masfeat/killswitch/{system_id}.
func (h *KillSwitchHandler) handleKillSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	orgID := getOrgIDFromRequest(r)
	systemID := extractSystemIDFromPath(r.URL.Path)

	ks, err := h.service.GetOrCreateKillSwitch(r.Context(), orgID, systemID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ks)
}

// handleKillSwitchConfigure handles POST /api/v1/masfeat/killswitch/{system_id}/configure.
func (h *KillSwitchHandler) handleKillSwitchConfigure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	orgID := getOrgIDFromRequest(r)
	systemID := extractSystemIDFromPath(r.URL.Path)

	var req ConfigureKillSwitchRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	ks, err := h.service.ConfigureKillSwitch(r.Context(), orgID, systemID, &req, user)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ks)
}

// handleKillSwitchTrigger handles POST /api/v1/masfeat/killswitch/{system_id}/trigger.
func (h *KillSwitchHandler) handleKillSwitchTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	orgID := getOrgIDFromRequest(r)
	systemID := extractSystemIDFromPath(r.URL.Path)

	var req TriggerKillSwitchRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	ks, err := h.service.TriggerKillSwitch(r.Context(), orgID, systemID, &req, user)
	if err != nil {
		if strings.Contains(err.Error(), "already triggered") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "Kill switch triggered successfully",
		"kill_switch": ks,
	})
}

// handleKillSwitchRestore handles POST /api/v1/masfeat/killswitch/{system_id}/restore.
func (h *KillSwitchHandler) handleKillSwitchRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	orgID := getOrgIDFromRequest(r)
	systemID := extractSystemIDFromPath(r.URL.Path)

	var req RestoreKillSwitchRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	ks, err := h.service.RestoreKillSwitch(r.Context(), orgID, systemID, &req, user)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":     "Kill switch restored successfully",
		"kill_switch": ks,
	})
}

// handleKillSwitchHistory handles GET /api/v1/masfeat/killswitch/{system_id}/history.
func (h *KillSwitchHandler) handleKillSwitchHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	orgID := getOrgIDFromRequest(r)
	systemID := extractSystemIDFromPath(r.URL.Path)

	limit := DefaultListLimit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	history, err := h.service.GetHistory(r.Context(), orgID, systemID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if history == nil {
		history = []*KillSwitchHistory{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"history": history,
		"count":   len(history),
	})
}

// handleKillSwitchEnable handles POST /api/v1/masfeat/killswitch/{system_id}/enable.
func (h *KillSwitchHandler) handleKillSwitchEnable(w http.ResponseWriter, r *http.Request, orgID, systemID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	ks, err := h.service.EnableKillSwitch(r.Context(), orgID, systemID, user)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ks)
}

// handleKillSwitchDisable handles POST /api/v1/masfeat/killswitch/{system_id}/disable.
func (h *KillSwitchHandler) handleKillSwitchDisable(w http.ResponseWriter, r *http.Request, orgID, systemID string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	user := getUserFromRequest(r)
	if user == "" {
		user = "system"
	}

	ks, err := h.service.DisableKillSwitch(r.Context(), orgID, systemID, user)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ks)
}

// extractSystemIDFromPath extracts the system_id from a kill switch path.
func extractSystemIDFromPath(path string) string {
	// Path format: /api/v1/masfeat/killswitch/{system_id}[/action]
	path = strings.TrimPrefix(path, "/api/v1/masfeat/killswitch/")
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
